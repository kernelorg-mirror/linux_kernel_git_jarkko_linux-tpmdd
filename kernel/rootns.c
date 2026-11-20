// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

/**
 * DOC: Overview
 *
 * A ``rootns`` is an anonymous-inode control file descriptor (not an ``nsfs``
 * namespace) that binds a full set of detached namespaces, an initially empty
 * mount namespace, an owning user namespace, and an init process lifecycle:
 *
 * 1. ``rootns()`` allocates a detached ``rootns`` with a fresh user namespace
 *    and dedicated mount (``CLONE_EMPTY_MNTNS``), PID, UTS, IPC, network,
 *    cgroup, and time namespaces, returning its control fd.
 *
 * 2. Userspace optionally maps UIDs/GIDs via ``userns_set_idmap()`` on the
 *    ``CLONE_NEWUSER`` fd, configures superblocks via ``FSCONFIG_SET_ROOTNS``,
 *    retrieves the mount namespace fd via ``ioctl(rootns_fd, ROOTNS_GET_NSFD,
 *    CLONE_NEWNS)``, and installs ``"/"`` and relative or cloned
 *    (``MOVE_MOUNT_CLONE``) submounts via ``MOVE_MOUNT_T_MNTNS``.
 *
 * 3. ``clone3()`` with ``CLONE_INTO_ROOTNS`` spawns processes into the
 *    ``rootns``; the first call commits PID 1 while concurrent bootstrap
 *    callers wait killably.
 *
 * 4. ``pidfd_send_signal(rootns_fd, sig, NULL, 0)`` signals all member thread
 *    groups. When PID 1 exits, the PID namespace zaps and reaps all remaining
 *    tasks, ``poll()`` reports ``EPOLLHUP``, and ``waitid(P_ROOTNS, rootns_fd,
 *    &infop, WEXITED, NULL)`` reports init's exit information.
 */

#include <linux/poll.h>
#include <linux/wait.h>
#include <uapi/linux/wait.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/rootns.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/nsfs.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/time_namespace.h>
#include <linux/user_namespace.h>
#include <linux/idr.h>
#include <uapi/linux/rootns.h>

#include "exit.h"

/*
 * Get a reference to a rootns.
 */
struct rootns *get_rootns(struct rootns *c)
{
	refcount_inc(&c->usage);
	return c;
}

/*
 * Drop a reference on a rootns and clear it if it is no longer in use.
 */
void put_rootns(struct rootns *c)
{
	if (!c || !refcount_dec_and_test(&c->usage))
		return;

	if (c->ns)
		put_nsproxy(c->ns);
	if (c->init_pid)
		put_pid(c->init_pid);
	if (c->user_ns) {
		ns_ref_active_put(c->user_ns);
		put_user_ns(c->user_ns);
	}
	kfree(c);
}

/*
 * Allow the user to poll for the rootns dying.
 */
static __poll_t rootns_poll(struct file *file, poll_table *wait)
{
	struct rootns *rootns = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &rootns->waitq, wait);

	if (READ_ONCE(rootns->state) == ROOTNS_DEAD)
		mask |= EPOLLHUP;

	return mask;
}

static long rootns_get_nsfd(struct rootns *rootns, unsigned long nstype)
{
	if (nstype > UINT_MAX)
		return -EINVAL;
	if (!ns_capable(rootns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (nstype == CLONE_NEWPID) {
		if (!pidns_is_ancestor(rootns->ns->pid_ns_for_children,
				       task_active_pid_ns(current)))
			return -EXDEV;
		if (READ_ONCE(rootns->state) != ROOTNS_RUNNING)
			return -ESRCH;
	}

	return nsproxy_open_namespace(rootns->ns, rootns->user_ns, nstype);
}

/**
 * DOC: P_ROOTNS
 *
 * ``waitid(P_ROOTNS, rootns_fd, &infop, options, NULL)`` waits freezably and
 * interruptibly (unless ``WNOHANG`` is set in ``options`` or ``O_NONBLOCK`` is
 * set on ``rootns_fd``) until ``rootns_fd`` reaches ``ROOTNS_DEAD``, then writes
 * the recorded exit information of ``rootns`` init into ``infop`` without
 * consuming it.
 *
 * ``options`` must include ``WEXITED`` and may optionally include ``WNOHANG``
 * and ``WNOWAIT``; ``rusage`` must be ``NULL``.
 *
 * Returns ``0`` on success (leaving ``infop->si_signo`` and ``infop->si_pid``
 * zero when ``WNOHANG`` is set and the ``rootns`` is still running), or ``-1``
 * with ``errno`` set to ``EBADF`` if ``rootns_fd`` is not an open ``rootns``
 * file descriptor, ``EAGAIN`` if ``O_NONBLOCK`` is set without ``WNOHANG``
 * while running, ``ECHILD`` if init was never started or is not visible in the
 * caller's active PID namespace, or ``EINVAL`` for unsupported arguments.
 */
long rootns_waitid(int upid, struct waitid_info *infop, int options,
		   struct rusage *ru)
{
	struct pid_namespace *pid_ns;
	unsigned int f_flags;
	struct rootns *rootns;
	bool nonblock;
	int status;
	kuid_t uid;
	long ret;

	if (upid < 0 || ru)
		return -EINVAL;
	if (options & ~(WEXITED | WNOHANG | WNOWAIT))
		return -EINVAL;
	if (!(options & WEXITED))
		return -EINVAL;

	CLASS(fd, f)(upid);
	if (fd_empty(f) || !is_rootns_file(fd_file(f)))
		return -EBADF;

	f_flags = READ_ONCE(fd_file(f)->f_flags);
	nonblock = (options & WNOHANG) || (f_flags & O_NONBLOCK);
	rootns = fd_file(f)->private_data;
	pid_ns = task_active_pid_ns(current);

	if (!pidns_is_ancestor(rootns->ns->pid_ns_for_children, pid_ns))
		return -ECHILD;
	if (READ_ONCE(rootns->state) == ROOTNS_INIT)
		return -ECHILD;

	if (!nonblock) {
		ret = wait_event_freezable(rootns->waitq,
					   READ_ONCE(rootns->state) == ROOTNS_DEAD ||
					   READ_ONCE(rootns->state) == ROOTNS_INIT);
		if (ret)
			return ret;
	}

	scoped_guard(spinlock, &rootns->lock) {
		if (rootns->state == ROOTNS_INIT)
			return -ECHILD;
		if (rootns->state != ROOTNS_DEAD)
			return (options & WNOHANG) ? 0 : -EAGAIN;
		ret = pid_nr_ns(rootns->init_pid, pid_ns);
		if (ret <= 0)
			return -ECHILD;
		status = rootns->exit_code;
		uid = rootns->init_uid;
	}

	if ((status & 0x7f) == 0) {
		infop->cause = CLD_EXITED;
		infop->status = status >> 8;
	} else {
		infop->cause = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
		infop->status = status & 0x7f;
	}
	infop->pid = ret;
	infop->uid = from_kuid_munged(current_user_ns(), uid);
	return ret;
}

static long rootns_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rootns *rootns = file->private_data;

	switch (cmd) {
	case ROOTNS_GET_NSFD:
		return rootns_get_nsfd(rootns, arg);
	default:
		return -ENOIOCTLCMD;
	}
}

static int __rootns_kill(struct rootns *rootns, int sig, bool priv)
{
	struct pid *pid = NULL;
	int ret;

	scoped_guard(spinlock, &rootns->lock) {
		if (rootns->state == ROOTNS_RUNNING)
			pid = get_pid(rootns->init_pid);
	}
	if (!pid)
		return -ESRCH;

	ret = kill_pid(pid, sig, priv);
	put_pid(pid);
	return ret;
}

static int rootns_release(struct inode *inode, struct file *file)
{
	struct rootns *rootns = file->private_data;

	if (rootns->flags & ROOTNS_KILL_ON_CLOSE)
		__rootns_kill(rootns, SIGKILL, true);
	put_rootns(rootns);
	return 0;
}

static const struct file_operations rootns_fops = {
	.poll		= rootns_poll,
	.unlocked_ioctl	= rootns_ioctl,
	.compat_ioctl	= rootns_ioctl,
	.release	= rootns_release,
};

/*
 * Returns true if the file is a rootns.
 */
bool is_rootns_file(struct file *file)
{
	return file->f_op == &rootns_fops;
}

void copy_rootns(struct task_struct *tsk, struct pid *pid, struct rootns *c)
{
	if (likely(!c || !is_child_reaper(pid)))
		return;

	scoped_guard(spinlock, &c->lock) {
		if (c->state != ROOTNS_FORKING)
			return;
		ns_of_pid(pid)->rootns = get_rootns(c);
		WRITE_ONCE(c->init_pid, get_pid(pid));
		WRITE_ONCE(c->state, ROOTNS_RUNNING);
	}
}

void exit_rootns(struct pid_namespace *pid_ns, struct task_struct *tsk)
{
	struct rootns *c = pid_ns->rootns;
	struct task_struct *leader;
	kuid_t uid;
	int status;

	if (!c)
		return;

	leader = tsk->group_leader;
	rcu_read_lock();
	uid = task_uid(leader);
	rcu_read_unlock();
	status = (tsk->signal->flags & SIGNAL_GROUP_EXIT) ?
		 tsk->signal->group_exit_code : leader->exit_code;

	scoped_guard(spinlock, &c->lock) {
		c->exit_code = status;
		c->init_uid = uid;
		WRITE_ONCE(c->state, ROOTNS_DEAD);
	}

	pid_ns->rootns = NULL;
	__wake_up(&c->waitq, TASK_NORMAL, 0, poll_to_key(EPOLLHUP));
	put_rootns(c);
}

static struct user_namespace *create_rootns_user_ns(void)
{
	struct user_namespace *user_ns;
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return ERR_PTR(-ENOMEM);

	ret = create_user_ns(new);
	if (ret < 0) {
		abort_creds(new);
		return ERR_PTR(ret);
	}

	user_ns = get_user_ns(new->user_ns);
	abort_creds(new);
	return user_ns;
}

/*
 * Create a new rootns.
 */
static struct rootns *create_rootns(unsigned int flags)
{
	u64 clone_flags = CLONE_NEWNS | CLONE_EMPTY_MNTNS | CLONE_NEWPID |
			  CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
			  CLONE_NEWNET |
			  (IS_ENABLED(CONFIG_TIME_NS) ? CLONE_NEWTIME : 0);
	struct user_namespace *user_ns;
	struct nsproxy *ns;
	struct rootns *c;
	int ret;

	c = kzalloc_obj(*c, GFP_KERNEL);
	if (!c)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&c->waitq);
	spin_lock_init(&c->lock);
	refcount_set(&c->usage, 1);
	c->flags = flags;

	user_ns = create_rootns_user_ns();
	if (IS_ERR(user_ns)) {
		ret = PTR_ERR(user_ns);
		goto err_put;
	}
	c->user_ns = user_ns;
	ns_ref_active_get(user_ns);

	if (!ns_capable(user_ns, CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto err_put;
	}

	ns = create_new_namespaces(clone_flags, current->nsproxy, user_ns,
				   NULL);
	if (IS_ERR(ns)) {
		ret = PTR_ERR(ns);
		goto err_put;
	}

	timens_activate_nsproxy(ns);
	c->ns = ns;
	nsproxy_ns_active_get(ns);

	return c;

err_put:
	put_rootns(c);
	return ERR_PTR(ret);
}

/**
 * sys_rootns - Create a detached rootns
 * @flags: Combination of &enum rootns_flags values
 *
 * Allocate a detached rootns owning a fresh user namespace and
 * dedicated empty mount, PID, UTS, IPC, network, cgroup, and time namespaces.
 *
 * Return: Control file descriptor on success, negative error code on failure.
 */
SYSCALL_DEFINE1(rootns, unsigned int, flags)
{
	struct rootns *c;
	int fd;

	if (flags & ~ROOTNS_ALL_FLAGS)
		return -EINVAL;
	if (unlikely(!current->nsproxy))
		return -EOPNOTSUPP;

	c = create_rootns(flags);
	if (IS_ERR(c))
		return PTR_ERR(c);

	fd = anon_inode_getfd("rootns", &rootns_fops, c,
			      O_RDWR | (flags & ROOTNS_CLOSE_ON_EXEC ? O_CLOEXEC : 0));
	if (fd < 0)
		put_rootns(c);

	return fd;
}
