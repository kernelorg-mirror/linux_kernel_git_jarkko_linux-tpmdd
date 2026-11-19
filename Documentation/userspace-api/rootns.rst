.. SPDX-License-Identifier: GPL-2.0

===========
rootns uAPI
===========

Overview
========

.. kernel-doc:: kernel/rootns.c
   :doc: Overview

Flags
=====

.. kernel-doc:: include/uapi/linux/rootns.h
   :identifiers: rootns_flags

Ioctls
======

.. kernel-doc:: include/uapi/linux/rootns.h
   :doc: ROOTNS_GET_NSFD

System calls
============

.. kernel-doc:: kernel/rootns.c
   :identifiers: sys_rootns

Process creation
================

.. kernel-doc:: kernel/rootns.c
   :doc: CLONE_INTO_ROOTNS

Process waiting
===============

.. kernel-doc:: kernel/rootns.c
   :doc: P_ROOTNS

Signal delivery
===============

.. kernel-doc:: kernel/rootns.c
   :doc: pidfd_send_signal

Filesystem configuration
========================

.. kernel-doc:: fs/fsopen.c
   :doc: FSCONFIG_SET_ROOTNS

Mount tree installation
=======================

.. kernel-doc:: fs/namespace.c
   :doc: MOVE_MOUNT_T_MNTNS

User namespace ID mapping
=========================

.. kernel-doc:: include/uapi/linux/nsfs.h
   :identifiers: userns_idmap_extent userns_idmap_flags userns_idmap

.. kernel-doc:: kernel/user_namespace.c
   :identifiers: sys_userns_set_idmap
