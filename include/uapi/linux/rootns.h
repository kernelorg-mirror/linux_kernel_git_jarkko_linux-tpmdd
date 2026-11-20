/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _UAPI_LINUX_ROOTNS_H
#define _UAPI_LINUX_ROOTNS_H

#include <linux/ioctl.h>

/**
 * enum rootns_flags - Flags for rootns()
 * @ROOTNS_KILL_ON_CLOSE: Send %SIGKILL to rootns init on final fd release.
 * @ROOTNS_CLOSE_ON_EXEC: Set %O_CLOEXEC on the returned control fd.
 * @ROOTNS_ALL_FLAGS: Mask of all valid flags accepted by rootns().
 *
 * Every rootns allocates a full set of detached namespaces owned
 * by a fresh user namespace.
 */
enum rootns_flags {
	ROOTNS_KILL_ON_CLOSE	= 0x00000001,
	ROOTNS_CLOSE_ON_EXEC	= 0x00000002,
	ROOTNS_ALL_FLAGS	= 0x00000003,
};

#define ROOTNS_IOCTL_MAGIC	0xB9

/**
 * DOC: ROOTNS_GET_NSFD
 *
 * ``ioctl(rootns_fd, ROOTNS_GET_NSFD, nstype)`` opens an ``nsfs`` file
 * descriptor (with ``O_CLOEXEC``) for the member namespace identified by
 * ``nstype`` (one of ``CLONE_NEWNS``, ``CLONE_NEWCGROUP``,
 * ``CLONE_NEWUTS``, ``CLONE_NEWIPC``, ``CLONE_NEWUSER``, ``CLONE_NEWPID``,
 * ``CLONE_NEWNET``, or ``CLONE_NEWTIME``).
 *
 * Requires ``CAP_SYS_ADMIN`` in the ``rootns`` user namespace. Opening
 * ``CLONE_NEWPID`` additionally requires running in an ancestor active PID
 * namespace and that ``rootns`` init is running.
 */
#define ROOTNS_GET_NSFD		_IO(ROOTNS_IOCTL_MAGIC, 0x01)

#endif /* _UAPI_LINUX_ROOTNS_H */
