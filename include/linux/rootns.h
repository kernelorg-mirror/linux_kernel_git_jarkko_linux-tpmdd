/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _LINUX_ROOTNS_H
#define _LINUX_ROOTNS_H

#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct file;
struct nsproxy;
struct pid;
struct user_namespace;

enum rootns_state {
	ROOTNS_INIT	= 0,
	ROOTNS_FORKING	= 1,
	ROOTNS_RUNNING	= 2,
	ROOTNS_DEAD	= 3,
};

/*
 * The rootns object.
 */
struct rootns {
	refcount_t		usage;
	int			exit_code;	/* The exit code of 'init' */
	struct user_namespace	*user_ns;	/* Owning user namespace */
	struct nsproxy		*ns;		/* This rootns's namespaces */
	struct pid		*init_pid;	/* The 'init' task's TGID (pid ref) */
	spinlock_t		lock;		/* Guards rootns lifecycle state */
	wait_queue_head_t	waitq;		/* Someone waiting for init to exit waits here */
	unsigned int		flags;		/* Validated rootns() flags */
	enum rootns_state	state;		/* rootns lifecycle state */
};

#ifdef CONFIG_ROOTNS
struct rootns *get_rootns(struct rootns *c);
void put_rootns(struct rootns *c);
bool is_rootns_file(struct file *file);
#else
static inline struct rootns *get_rootns(struct rootns *c)
{
	return NULL;
}

static inline void put_rootns(struct rootns *c)
{
}

static inline bool is_rootns_file(struct file *file)
{
	return false;
}
#endif /* CONFIG_ROOTNS */

#endif /* _LINUX_ROOTNS_H */
