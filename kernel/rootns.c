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
