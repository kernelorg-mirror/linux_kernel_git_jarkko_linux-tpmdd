#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Opinsys Oy

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
import ctypes
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum, IntFlag
import errno
import json
import os
import platform
import selectors
import signal
import socket
import sys
from types import TracebackType
from typing import Any, ClassVar, Final, NoReturn

HOST_RUNTIME_ENTRIES: Final[tuple[str, ...]] = (
    "usr",
    "bin",
    "sbin",
    "lib",
    "lib32",
    "lib64",
    "libx32",
    "etc",
    "opt",
    "nix",
)


class RootnsFlag(IntFlag):
    NONE = 0
    KILL_ON_CLOSE = 0x00000001
    CLOSE_ON_EXEC = 0x00000002
    DEFAULT = KILL_ON_CLOSE | CLOSE_ON_EXEC
    ALL = KILL_ON_CLOSE | CLOSE_ON_EXEC


class CloneFlag(IntFlag):
    NONE = 0
    NEWTIME = 0x00000080
    VM = 0x00000100
    FS = 0x00000200
    FILES = 0x00000400
    SIGHAND = 0x00000800
    PIDFD = 0x00001000
    VFORK = 0x00004000
    PARENT = 0x00008000
    THREAD = 0x00010000
    NEWNS = 0x00020000
    SYSVSEM = 0x00040000
    NEWCGROUP = 0x02000000
    NEWUTS = 0x04000000
    NEWIPC = 0x08000000
    NEWUSER = 0x10000000
    NEWPID = 0x20000000
    NEWNET = 0x40000000
    CLEAR_SIGHAND = 1 << 32
    INTO_CGROUP = 1 << 33
    AUTOREAP = 1 << 34
    NNP = 1 << 35
    PIDFD_AUTOKILL = 1 << 36
    EMPTY_MNTNS = 1 << 37
    INTO_ROOTNS = 1 << 38


class AtFlag(IntFlag):
    NONE = 0
    EMPTY_PATH = 0x1000
    RECURSIVE = 0x8000


class OpenTreeFlag(IntFlag):
    CLONE = 1 << 0
    CLOEXEC = os.O_CLOEXEC
    RECURSIVE = 0x8000


class MoveMountFlag(IntFlag):
    F_EMPTY_PATH = 0x00000004
    T_EMPTY_PATH = 0x00000040
    T_MNTNS = 0x00000080
    SET_GROUP = 0x00000100
    BENEATH = 0x00000200
    CLONE = 0x00000400


class UsernsIdmapFlag(IntFlag):
    NONE = 0
    UID = 1 << 0
    GID = 1 << 1
    PROJID = 1 << 2
    SETGROUPS_DENY = 1 << 3
    ALL = 0x0F


class MountAttrFlag(IntFlag):
    NONE = 0
    RDONLY = 0x00000001
    NOSUID = 0x00000002
    NODEV = 0x00000004


class MountFlag(IntFlag):
    REC = 0x4000
    PRIVATE = 1 << 18
    SHARED = 1 << 20


class UmountFlag(IntFlag):
    NONE = 0
    DETACH = 2


class ResolveFlag(IntFlag):
    NONE = 0
    IN_ROOT = 0x10


class FsconfigCmd(IntEnum):
    SET_FLAG = 0
    SET_STRING = 1
    CMD_CREATE = 6
    SET_ROOTNS = 9


class PrctlOp(IntEnum):
    GET_DUMPABLE = 3
    SET_DUMPABLE = 4
    SET_KEEPCAPS = 8
    GET_NO_NEW_PRIVS = 39


class WaitIdType(IntEnum):
    ALL = 0
    PID = 1
    PGID = 2
    PIDFD = 3
    ROOTNS = 4


class CloneArgs(ctypes.Structure):
    SIZE_VER2: ClassVar[int] = 88
    SIZE_VER3: ClassVar[int] = 96

    flags: int
    pidfd: int
    child_tid: int
    parent_tid: int
    exit_signal: int
    stack: int
    stack_size: int
    tls: int
    set_tid: int
    set_tid_size: int
    cgroup: int
    rootns: int
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("pidfd", ctypes.c_uint64),
        ("child_tid", ctypes.c_uint64),
        ("parent_tid", ctypes.c_uint64),
        ("exit_signal", ctypes.c_uint64),
        ("stack", ctypes.c_uint64),
        ("stack_size", ctypes.c_uint64),
        ("tls", ctypes.c_uint64),
        ("set_tid", ctypes.c_uint64),
        ("set_tid_size", ctypes.c_uint64),
        ("cgroup", ctypes.c_uint64),
        ("rootns", ctypes.c_uint64),
    ]


class OpenHow(ctypes.Structure):
    flags: int
    mode: int
    resolve: int
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class UsernsIdmapExtent(ctypes.Structure):
    first: int
    lower_first: int
    count: int
    reserved: int
    _fields_ = [
        ("first", ctypes.c_uint32),
        ("lower_first", ctypes.c_uint32),
        ("count", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class CapHeader(ctypes.Structure):
    VERSION_3: ClassVar[int] = 0x20080522

    version: int
    pid: int
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int32),
    ]


class CapData(ctypes.Structure):
    effective: int
    permitted: int
    inheritable: int
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


class UsernsIdmap(ctypes.Structure):
    SIZE_VER0: ClassVar[int] = 40

    flags: int
    nr_uid_extents: int
    uid_extents: int
    nr_gid_extents: int
    nr_projid_extents: int
    gid_extents: int
    projid_extents: int
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("nr_uid_extents", ctypes.c_uint32),
        ("uid_extents", ctypes.c_uint64),
        ("nr_gid_extents", ctypes.c_uint32),
        ("nr_projid_extents", ctypes.c_uint32),
        ("gid_extents", ctypes.c_uint64),
        ("projid_extents", ctypes.c_uint64),
    ]


class Sys:
    AT_FDCWD: Final[int] = -100
    FSOPEN_CLOEXEC: Final[int] = 0x00000001
    FSMOUNT_CLOEXEC: Final[int] = 0x00000001
    CAP_SETGID: Final[int] = 6
    CAP_SETUID: Final[int] = 7
    _WIDE_IOC_ARCHS: Final[tuple[str, ...]] = (
        "ppc",
        "ppc64",
        "ppc64le",
        "powerpc",
        "sparc",
        "sparc64",
        "alpha",
    )

    @classmethod
    def _is_wide_ioc_arch(cls) -> bool:
        mach = platform.machine().lower()
        return mach in cls._WIDE_IOC_ARCHS or mach.startswith("mips")

    @classmethod
    def ioc(cls, direction: int, magic: int, nr: int, size: int) -> int:
        sizebits = 13 if cls._is_wide_ioc_arch() else 14
        typeshift = 8
        sizeshift = 16
        dirshift = sizeshift + sizebits
        return (
            (direction << dirshift)
            | (magic << typeshift)
            | nr
            | (size << sizeshift)
        )

    @classmethod
    def io(cls, magic: int, nr: int) -> int:
        none_dir = 1 if cls._is_wide_ioc_arch() else 0
        return cls.ioc(none_dir, magic, nr, 0)

    @staticmethod
    def _build_syscall_numbers() -> dict[str, int]:
        mach = platform.machine().lower()
        if mach == "alpha":
            base = 110
        elif mach.startswith("mips"):
            base = 5000 if ctypes.sizeof(ctypes.c_void_p) == 8 else 4000
        else:
            base = 0

        nums: dict[str, int] = {
            "pidfd_send_signal": base + 424,
            "open_tree": base + 428,
            "move_mount": base + 429,
            "fsopen": base + 430,
            "fsconfig": base + 431,
            "fsmount": base + 432,
            "clone3": base + 435,
            "openat2": base + 437,
            "userns_set_idmap": base + 473,
            "rootns": base + 474,
        }
        legacy: dict[str, dict[str, int]] = {
            "x86_64": {
                "pivot_root": 155,
                "umount2": 166,
                "waitid": 247,
                "execveat": 322,
            },
            "i386": {
                "pivot_root": 217,
                "umount2": 52,
                "waitid": 284,
                "execveat": 358,
            },
            "i686": {
                "pivot_root": 217,
                "umount2": 52,
                "waitid": 284,
                "execveat": 358,
            },
            "aarch64": {
                "pivot_root": 41,
                "umount2": 39,
                "waitid": 95,
                "execveat": 281,
            },
            "riscv64": {
                "pivot_root": 41,
                "umount2": 39,
                "waitid": 95,
                "execveat": 281,
            },
            "loongarch64": {
                "pivot_root": 41,
                "umount2": 39,
                "waitid": 95,
                "execveat": 281,
            },
            "s390x": {
                "pivot_root": 217,
                "umount2": 52,
                "waitid": 281,
                "execveat": 354,
            },
            "ppc64le": {
                "pivot_root": 203,
                "umount2": 52,
                "waitid": 272,
                "execveat": 362,
            },
            "ppc64": {
                "pivot_root": 203,
                "umount2": 52,
                "waitid": 272,
                "execveat": 362,
            },
            "armv7l": {
                "pivot_root": 218,
                "umount2": 52,
                "waitid": 280,
                "execveat": 387,
            },
        }
        nums.update(legacy.get(mach, legacy["x86_64"]))
        return nums

    _NR: ClassVar[dict[str, int]]
    _LIBC: ClassVar[ctypes.CDLL]

    @staticmethod
    def _os_err() -> NoReturn:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

    @staticmethod
    def _cstr(val: str | bytes) -> bytes:
        return val if isinstance(val, bytes) else os.fsencode(val)

    @classmethod
    def syscall(cls, name: str, *args: Any) -> int:
        ret: int = cls._LIBC.syscall(ctypes.c_long(cls._NR[name]), *args)
        if ret < 0:
            cls._os_err()
        return int(ret)

    @classmethod
    def ioctl(cls, fd: int, cmd: int, arg: int = 0) -> int:
        ret: int = cls._LIBC.ioctl(
            ctypes.c_int(fd), ctypes.c_ulong(int(cmd)), ctypes.c_ulong(arg)
        )
        if ret < 0:
            cls._os_err()
        return int(ret)

    @classmethod
    def fsopen(cls, fsname: str | bytes, flags: int = FSOPEN_CLOEXEC) -> int:
        return cls.syscall(
            "fsopen", ctypes.c_char_p(cls._cstr(fsname)), ctypes.c_uint(flags)
        )

    @classmethod
    def fsconfig(
        cls,
        fsfd: int,
        cmd: FsconfigCmd,
        key: str | bytes | None = None,
        value: str | bytes | None = None,
        aux: int = 0,
    ) -> None:
        k_ptr = (
            ctypes.c_char_p(cls._cstr(key))
            if key is not None
            else ctypes.c_void_p(0)
        )
        v_ptr = (
            ctypes.c_char_p(cls._cstr(value))
            if value is not None
            else ctypes.c_void_p(0)
        )
        cls.syscall(
            "fsconfig",
            ctypes.c_int(fsfd),
            ctypes.c_uint(int(cmd)),
            k_ptr,
            v_ptr,
            ctypes.c_int(aux),
        )

    @classmethod
    def fsmount(
        cls,
        fsfd: int,
        flags: int = FSMOUNT_CLOEXEC,
        attr_flags: MountAttrFlag = MountAttrFlag.NONE,
    ) -> int:
        return cls.syscall(
            "fsmount",
            ctypes.c_int(fsfd),
            ctypes.c_uint(flags),
            ctypes.c_uint(int(attr_flags)),
        )

    @classmethod
    def open_tree(
        cls, dfd: int, path: str | bytes, flags: OpenTreeFlag
    ) -> int:
        return cls.syscall(
            "open_tree",
            ctypes.c_int(dfd),
            ctypes.c_char_p(cls._cstr(path)),
            ctypes.c_uint(int(flags)),
        )

    @classmethod
    def move_mount(
        cls,
        from_dfd: int,
        from_path: str | bytes,
        to_dfd: int,
        to_path: str | bytes,
        flags: MoveMountFlag,
    ) -> None:
        cls.syscall(
            "move_mount",
            ctypes.c_int(from_dfd),
            ctypes.c_char_p(cls._cstr(from_path)),
            ctypes.c_int(to_dfd),
            ctypes.c_char_p(cls._cstr(to_path)),
            ctypes.c_uint(int(flags)),
        )

    @classmethod
    def openat2(
        cls,
        dfd: int,
        path: str | bytes,
        flags: int,
        mode: int = 0,
        resolve: ResolveFlag = ResolveFlag.NONE,
    ) -> int:
        how = OpenHow(flags=flags, mode=mode, resolve=int(resolve))
        return cls.syscall(
            "openat2",
            ctypes.c_int(dfd),
            ctypes.c_char_p(cls._cstr(path)),
            ctypes.byref(how),
            ctypes.c_size_t(ctypes.sizeof(how)),
        )

    @classmethod
    def execveat(
        cls,
        dfd: int,
        path: str | bytes,
        argv: Sequence[str],
        envp: Mapping[str, str] | Sequence[str] | None = None,
        flags: AtFlag = AtFlag.NONE,
    ) -> NoReturn:
        c_argv = (ctypes.c_char_p * (len(argv) + 1))(
            *[cls._cstr(a) for a in argv], None
        )
        if envp is None:
            env_items = [f"{k}={v}" for k, v in os.environ.items()]
        elif isinstance(envp, Mapping):
            env_items = [f"{k}={v}" for k, v in envp.items()]
        else:
            env_items = list(envp)
        c_envp = (ctypes.c_char_p * (len(env_items) + 1))(
            *[cls._cstr(e) for e in env_items], None
        )
        cls.syscall(
            "execveat",
            ctypes.c_int(dfd),
            ctypes.c_char_p(cls._cstr(path)),
            c_argv,
            c_envp,
            ctypes.c_int(int(flags)),
        )
        cls._os_err()

    @classmethod
    def pivot_root(cls, new_root: str | bytes, put_old: str | bytes) -> None:
        cls.syscall(
            "pivot_root",
            ctypes.c_char_p(cls._cstr(new_root)),
            ctypes.c_char_p(cls._cstr(put_old)),
        )

    @classmethod
    def umount2(
        cls, target: str | bytes, flags: UmountFlag = UmountFlag.NONE
    ) -> None:
        cls.syscall(
            "umount2",
            ctypes.c_char_p(cls._cstr(target)),
            ctypes.c_int(int(flags)),
        )

    @classmethod
    def set_mount_propagation(
        cls,
        target: str | bytes = "/",
        flags: MountFlag = MountFlag.REC | MountFlag.PRIVATE,
    ) -> None:
        ret: int = cls._LIBC.mount(
            ctypes.c_char_p(b"none"),
            ctypes.c_char_p(cls._cstr(target)),
            ctypes.c_void_p(0),
            ctypes.c_ulong(int(flags)),
            ctypes.c_void_p(0),
        )
        if ret < 0:
            cls._os_err()

    @classmethod
    def setns(cls, fd: int, nstype: CloneFlag | int = 0) -> None:
        if hasattr(os, "setns"):
            os.setns(fd, int(nstype))
            return
        ret: int = cls._LIBC.setns(ctypes.c_int(fd), ctypes.c_int(int(nstype)))
        if ret < 0:
            cls._os_err()

    @classmethod
    def unshare(cls, flags: CloneFlag | int) -> None:
        if hasattr(os, "unshare"):
            os.unshare(int(flags))
            return
        ret: int = cls._LIBC.unshare(ctypes.c_int(int(flags)))
        if ret < 0:
            cls._os_err()

    @classmethod
    def setgroups_empty(cls) -> None:
        ret: int = cls._LIBC.setgroups(ctypes.c_size_t(0), ctypes.c_void_p(0))
        if ret < 0:
            cls._os_err()

    @classmethod
    def drop_to_setid_helper(cls, uid: int) -> None:
        cls.prctl(PrctlOp.SET_KEEPCAPS, 1)
        try:
            cls.setgroups_empty()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        os.setresgid(uid, uid, uid)
        os.setresuid(uid, uid, uid)
        hdr = CapHeader(version=CapHeader.VERSION_3, pid=0)
        mask = (1 << cls.CAP_SETGID) | (1 << cls.CAP_SETUID)
        data = (CapData * 2)(
            CapData(effective=mask, permitted=mask, inheritable=0),
            CapData(effective=0, permitted=0, inheritable=0),
        )
        ret: int = cls._LIBC.capset(ctypes.byref(hdr), ctypes.byref(data))
        if ret < 0:
            cls._os_err()
        cls.prctl(PrctlOp.SET_DUMPABLE, 1)

    @classmethod
    def prctl(
        cls,
        option: PrctlOp,
        arg2: int = 0,
        arg3: int = 0,
        arg4: int = 0,
        arg5: int = 0,
    ) -> int:
        ret: int = cls._LIBC.prctl(
            ctypes.c_int(int(option)),
            ctypes.c_ulong(arg2),
            ctypes.c_ulong(arg3),
            ctypes.c_ulong(arg4),
            ctypes.c_ulong(arg5),
        )
        if ret < 0:
            cls._os_err()
        return int(ret)

    @classmethod
    def clone3(cls, args: CloneArgs, size: int | None = None) -> int:
        actual_size = ctypes.sizeof(args) if size is None else size
        sys.stdout.flush()
        sys.stderr.flush()
        return cls.syscall(
            "clone3", ctypes.byref(args), ctypes.c_size_t(actual_size)
        )

    @staticmethod
    def _extent_array(
        extents: Sequence[tuple[int, int, int]],
    ) -> ctypes.Array[UsernsIdmapExtent] | None:
        if not extents:
            return None
        arr_t = UsernsIdmapExtent * len(extents)
        return arr_t(
            *[
                UsernsIdmapExtent(
                    first=first, lower_first=lower, count=count, reserved=0
                )
                for first, lower, count in extents
            ]
        )

    @classmethod
    def pidfd_send_signal(
        cls,
        pidfd: int,
        sig: int,
        info_addr: int = 0,
        flags: int = 0,
    ) -> None:
        cls.syscall(
            "pidfd_send_signal",
            ctypes.c_int(pidfd),
            ctypes.c_int(sig),
            ctypes.c_void_p(info_addr),
            ctypes.c_uint(flags),
        )

    @classmethod
    def waitid_raw(
        cls,
        which: int,
        upid: int,
        infop_addr: int,
        options: int,
        ru_addr: int = 0,
    ) -> None:
        cls.syscall(
            "waitid",
            ctypes.c_int(which),
            ctypes.c_int(upid),
            ctypes.c_void_p(infop_addr),
            ctypes.c_int(options),
            ctypes.c_void_p(ru_addr),
        )

    @classmethod
    def userns_set_idmap_raw(
        cls,
        userns_fd: int,
        map_addr: int,
        size: int = UsernsIdmap.SIZE_VER0,
        flags: int = 0,
    ) -> None:
        cls.syscall(
            "userns_set_idmap",
            ctypes.c_int(userns_fd),
            ctypes.c_void_p(map_addr),
            ctypes.c_size_t(size),
            ctypes.c_uint(flags),
        )

    @classmethod
    def set_userns_idmap(
        cls,
        userns_fd: int,
        uid_extents: Sequence[tuple[int, int, int]] = (),
        gid_extents: Sequence[tuple[int, int, int]] = (),
        projid_extents: Sequence[tuple[int, int, int]] = (),
        *,
        deny_setgroups: bool = False,
        extra_flags: UsernsIdmapFlag | int = UsernsIdmapFlag.NONE,
        size: int | None = None,
        sys_flags: int = 0,
    ) -> None:
        flags = int(extra_flags)
        u_arr = cls._extent_array(uid_extents)
        g_arr = cls._extent_array(gid_extents)
        p_arr = cls._extent_array(projid_extents)
        if u_arr is not None:
            flags |= int(UsernsIdmapFlag.UID)
        if g_arr is not None:
            flags |= int(UsernsIdmapFlag.GID)
        if p_arr is not None:
            flags |= int(UsernsIdmapFlag.PROJID)
        if deny_setgroups:
            flags |= int(UsernsIdmapFlag.SETGROUPS_DENY)
        req = UsernsIdmap(
            flags=flags,
            nr_uid_extents=len(uid_extents),
            uid_extents=ctypes.addressof(u_arr) if u_arr is not None else 0,
            nr_gid_extents=len(gid_extents),
            nr_projid_extents=len(projid_extents),
            gid_extents=ctypes.addressof(g_arr) if g_arr is not None else 0,
            projid_extents=ctypes.addressof(p_arr) if p_arr is not None else 0,
        )
        cls.userns_set_idmap_raw(
            userns_fd,
            ctypes.addressof(req),
            ctypes.sizeof(req) if size is None else size,
            sys_flags,
        )


Sys._NR = Sys._build_syscall_numbers()
Sys._LIBC = ctypes.CDLL(None, use_errno=True)
Sys._LIBC.syscall.restype = ctypes.c_long


class Ioctl(IntEnum):
    ROOTNS_GET_NSFD = Sys.io(0xB9, 0x01)
    NS_GET_USERNS = Sys.io(0xB7, 0x01)
    NS_GET_PARENT = Sys.io(0xB7, 0x02)
    NS_GET_NSTYPE = Sys.io(0xB7, 0x03)


class CellState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"


class CellMode(str, Enum):
    HOST = "host"
    TMPFS = "tmpfs"


class RpcOp(str, Enum):
    PING = "ping"
    SHUTDOWN = "shutdown"
    LIST = "list"
    CREATE = "create"
    SPAWN = "spawn"
    MOUNT = "mount"
    KILL = "kill"
    WAIT = "wait"
    DESTROY = "destroy"


@dataclass(frozen=True)
class WaitResult:
    pid: int
    status: int = 0
    code: int = 0
    uid: int = 0

    @property
    def exit_code(self) -> int | None:
        if self.pid <= 0:
            return None
        if self.code == os.CLD_EXITED:
            return self.status
        if self.code in (os.CLD_KILLED, os.CLD_DUMPED):
            return -self.status
        return os.waitstatus_to_exitcode(self.status)


@dataclass(frozen=True)
class CellInfo:
    name: str
    state: CellState
    init_pid: int | None = None
    exit_code: int | None = None


@dataclass(frozen=True)
class SpawnInfo:
    pid: int
    state: CellState


class Rootns:
    fd: int

    def __init__(
        self,
        flags: RootnsFlag | int = RootnsFlag.DEFAULT,
        *,
        fd: int | None = None,
    ) -> None:
        if fd is not None:
            self.fd = fd
        else:
            self.fd = Sys.syscall("rootns", ctypes.c_uint(int(flags)))

    @classmethod
    def from_fd(cls, fd: int) -> Rootns:
        return cls(fd=fd)

    def fileno(self) -> int:
        return self.fd

    def __enter__(self) -> Rootns:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def get_nsfd(self, nstype: CloneFlag | int) -> int:
        return Sys.ioctl(self.fd, Ioctl.ROOTNS_GET_NSFD, int(nstype))

    def set_idmap(
        self,
        uid_extents: Sequence[tuple[int, int, int]] = (),
        gid_extents: Sequence[tuple[int, int, int]] = (),
        projid_extents: Sequence[tuple[int, int, int]] = (),
        *,
        deny_setgroups: bool = False,
    ) -> None:
        userns_fd = self.get_nsfd(CloneFlag.NEWUSER)
        try:
            Sys.set_userns_idmap(
                userns_fd,
                uid_extents=uid_extents,
                gid_extents=gid_extents,
                projid_extents=projid_extents,
                deny_setgroups=deny_setgroups,
            )
        finally:
            os.close(userns_fd)

    def map_self_ugid(self) -> None:
        self.set_idmap(
            uid_extents=((0, os.geteuid(), 1),),
            gid_extents=((0, os.getegid(), 1),),
            deny_setgroups=True,
        )

    def wait(self, flags: int = 0) -> WaitResult:
        res = os.waitid(int(WaitIdType.ROOTNS), self.fd, os.WEXITED | flags)
        if res is None:
            return WaitResult(pid=0)
        return WaitResult(
            pid=int(res.si_pid),
            status=int(res.si_status),
            code=int(res.si_code),
            uid=int(res.si_uid),
        )

    def kill(self, sig: signal.Signals | int) -> None:
        Sys.pidfd_send_signal(self.fd, int(sig))

    def clone_into(
        self,
        extra_flags: CloneFlag = CloneFlag.NONE,
        exit_signal: int = int(signal.SIGCHLD),
    ) -> tuple[int, int]:
        pidfd_cell = ctypes.c_int(-1)
        args = CloneArgs()
        args.flags = int(CloneFlag.INTO_ROOTNS | extra_flags)
        args.exit_signal = exit_signal
        args.rootns = self.fd & 0xFFFFFFFFFFFFFFFF
        if extra_flags & CloneFlag.PIDFD:
            args.pidfd = ctypes.addressof(pidfd_cell)
        pid = Sys.clone3(args)
        return pid, int(pidfd_cell.value)

    def run(
        self,
        fn: Callable[[], int | None],
        extra_flags: CloneFlag = CloneFlag.NONE,
    ) -> int:
        pid, _ = self.clone_into(extra_flags=extra_flags)
        if pid == 0:
            try:
                self.close()
                rc = fn()
                os._exit(0 if rc is None else int(rc))
            except BaseException:
                os._exit(126)
        return pid

    def make_mount(
        self,
        fstype: str,
        attr_flags: MountAttrFlag = MountAttrFlag.NONE,
        options: Mapping[str, str | None] | None = None,
    ) -> int:
        fsfd = Sys.fsopen(fstype)
        try:
            Sys.fsconfig(fsfd, FsconfigCmd.SET_ROOTNS, aux=self.fd)
            if options:
                for k, v in options.items():
                    if v is None:
                        Sys.fsconfig(fsfd, FsconfigCmd.SET_FLAG, key=k)
                    else:
                        Sys.fsconfig(
                            fsfd, FsconfigCmd.SET_STRING, key=k, value=str(v)
                        )
            Sys.fsconfig(fsfd, FsconfigCmd.CMD_CREATE)
            return Sys.fsmount(fsfd, attr_flags=attr_flags)
        finally:
            os.close(fsfd)


@dataclass
class Cell:
    name: str
    flags: RootnsFlag = RootnsFlag.DEFAULT
    rns: Rootns = field(init=False)
    mntns_fd: int = field(init=False, default=-1)
    root_dfd: int = field(init=False, default=-1)
    init_pid: int | None = field(init=False, default=None)
    exit_code: int | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.rns = Rootns(self.flags)
        try:
            self.mntns_fd = self.rns.get_nsfd(CloneFlag.NEWNS)
        except Exception:
            self.rns.close()
            raise

    def __enter__(self) -> Cell:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @staticmethod
    def _close_fd(fd: int) -> int:
        if fd >= 0:
            with suppress(OSError):
                os.close(fd)
        return -1

    def _move_to_mntns(self, mfd: int, target: str) -> None:
        Sys.move_mount(
            mfd,
            "",
            self.mntns_fd,
            target,
            MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
        )

    def _consume_mount(self, mfd: int, target: str) -> None:
        try:
            self._move_to_mntns(mfd, target.lstrip("/"))
        finally:
            os.close(mfd)

    def setup_rootfs(
        self,
        dirs: Sequence[str] = ("proc", "tmp", "mnt"),
        mount_procfs: bool = True,
        host_runtime: bool = False,
        map_ugid: bool = True,
    ) -> None:
        if map_ugid:
            self.rns.map_self_ugid()
        rootfd = self.rns.make_mount("tmpfs")
        bind_dirs: list[str] = []
        try:
            for d in dirs:
                os.mkdir(d, 0o755, dir_fd=rootfd)
            if host_runtime:
                for entry in HOST_RUNTIME_ENTRIES:
                    host_path = f"/{entry}"
                    if os.path.islink(host_path):
                        os.symlink(
                            os.readlink(host_path), entry, dir_fd=rootfd
                        )
                    elif os.path.isdir(host_path):
                        os.mkdir(entry, 0o755, dir_fd=rootfd)
                        bind_dirs.append(entry)
            self._move_to_mntns(rootfd, "/")
        except Exception:
            os.close(rootfd)
            raise
        self.root_dfd = rootfd
        for entry in bind_dirs:
            self.bind_mount(f"/{entry}", entry)
        if mount_procfs and "proc" in dirs:
            self.mount_fs("proc", "proc")

    def mount_fs(
        self,
        fstype: str,
        target: str,
        attr_flags: MountAttrFlag = MountAttrFlag.NONE,
        options: Mapping[str, str | None] | None = None,
    ) -> None:
        mfd = self.rns.make_mount(
            fstype, attr_flags=attr_flags, options=options
        )
        self._consume_mount(mfd, target)

    def bind_mount(self, host_src: str, target: str) -> None:
        Sys.move_mount(
            Sys.AT_FDCWD,
            host_src,
            self.mntns_fd,
            target.lstrip("/"),
            MoveMountFlag.T_MNTNS | MoveMountFlag.CLONE,
        )

    def spawn(
        self,
        argv: Sequence[str],
        env: Mapping[str, str] | None = None,
        resolve_in_root: bool = True,
    ) -> int:
        bin_fd = -1
        if resolve_in_root and self.root_dfd >= 0:
            bin_fd = Sys.openat2(
                self.root_dfd,
                argv[0],
                os.O_RDONLY | os.O_CLOEXEC,
                resolve=ResolveFlag.IN_ROOT,
            )
        try:
            pid, _ = self.rns.clone_into(
                extra_flags=CloneFlag.AUTOREAP, exit_signal=0
            )
            if pid == 0:
                try:
                    self.close()
                    if bin_fd >= 0:
                        Sys.execveat(bin_fd, "", argv, env, AtFlag.EMPTY_PATH)
                    if env is None:
                        os.execv(argv[0], list(argv))
                    else:
                        os.execve(argv[0], list(argv), dict(env))
                except BaseException:
                    os._exit(127)
            if self.init_pid is None:
                self.init_pid = pid
            return pid
        finally:
            self._close_fd(bin_fd)

    def kill(self, sig: signal.Signals | int = signal.SIGTERM) -> None:
        self.rns.kill(sig)

    def wait(self, nohang: bool = False) -> WaitResult:
        res = self.rns.wait(os.WNOHANG if nohang else 0)
        if res.pid > 0:
            self.exit_code = res.exit_code
        return res

    @property
    def state(self) -> CellState:
        if self.init_pid is None:
            return CellState.CREATED
        if self.exit_code is None:
            return CellState.RUNNING
        return CellState.EXITED

    def info(self) -> CellInfo:
        return CellInfo(
            name=self.name,
            state=self.state,
            init_pid=self.init_pid,
            exit_code=self.exit_code,
        )

    def close(self) -> None:
        self.root_dfd = self._close_fd(self.root_dfd)
        self.mntns_fd = self._close_fd(self.mntns_fd)
        self.rns.close()


class JsonLine:
    @staticmethod
    def send(sock: socket.socket, payload: Mapping[str, Any]) -> None:
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))

    @staticmethod
    def recv(sock: socket.socket) -> dict[str, Any] | None:
        with sock.makefile("r", encoding="utf-8") as reader:
            line = reader.readline()
        if not line:
            return None
        data: dict[str, Any] = json.loads(line)
        return data


class CellService:
    def __init__(self, sock_path: str) -> None:
        self.sock_path = sock_path
        self.sel = selectors.DefaultSelector()
        self.cells: dict[str, Cell] = {}
        self.running = True
        with suppress(FileNotFoundError):
            os.unlink(sock_path)
        self.srv = socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
        )
        self.srv.bind(sock_path)
        self.srv.listen(16)
        self.srv.setblocking(False)
        self.sel.register(self.srv, selectors.EVENT_READ, self._on_accept)

    def __enter__(self) -> CellService:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _safe_unregister(self, fileobj: Any) -> None:
        with suppress(KeyError, ValueError):
            self.sel.unregister(fileobj)

    def _reap_children(self) -> None:
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break

    def _on_cell_event(self, cell: Cell) -> None:
        with suppress(OSError):
            res = cell.wait(nohang=True)
            if res.pid > 0:
                self._safe_unregister(cell.rns)
        self._reap_children()

    def _on_accept(self) -> None:
        conn, _ = self.srv.accept()
        with conn:
            conn.setblocking(True)
            try:
                req = JsonLine.recv(conn)
                if req is None:
                    return
                resp: dict[str, Any] = {
                    "ok": True,
                    "result": self._dispatch(req),
                }
            except Exception as exc:
                resp = {
                    "ok": False,
                    "error": str(exc),
                    "errno": getattr(exc, "errno", None),
                }
            JsonLine.send(conn, resp)

    def _dispatch(self, req: Mapping[str, Any]) -> Any:
        op = RpcOp(req["op"])
        if op is RpcOp.PING:
            return "pong"
        if op is RpcOp.SHUTDOWN:
            self.running = False
            return "bye"
        if op is RpcOp.LIST:
            self._reap_children()
            return [asdict(c.info()) for c in self.cells.values()]

        name = str(req["name"])
        if op is RpcOp.CREATE:
            if name in self.cells:
                raise OSError(errno.EEXIST, f"cell {name} already exists")
            mode = CellMode(req.get("mode", CellMode.HOST))
            cell = Cell(name, flags=RootnsFlag.DEFAULT)
            try:
                cell.setup_rootfs(
                    mount_procfs=bool(req.get("proc", True)),
                    host_runtime=mode is CellMode.HOST,
                )
            except Exception:
                cell.close()
                raise
            self.cells[name] = cell
            self.sel.register(
                cell.rns,
                selectors.EVENT_READ,
                lambda c=cell: self._on_cell_event(c),
            )
            return asdict(cell.info())

        if name not in self.cells:
            raise OSError(errno.ENOENT, f"unknown cell {name}")
        cell = self.cells[name]

        if op is RpcOp.SPAWN:
            pid = cell.spawn(
                list(req["argv"]),
                resolve_in_root=bool(req.get("resolve_in_root", True)),
            )
            return asdict(SpawnInfo(pid=pid, state=cell.state))
        if op is RpcOp.MOUNT:
            if req.get("bind"):
                cell.bind_mount(str(req["source"]), str(req["target"]))
            else:
                cell.mount_fs(
                    str(req["source"]),
                    str(req["target"]),
                    options=req.get("options"),
                )
            return str(req["target"])
        if op is RpcOp.KILL:
            cell.kill(int(req.get("sig", int(signal.SIGTERM))))
            return name
        if op is RpcOp.WAIT:
            res = cell.wait(nohang=bool(req.get("nohang", False)))
            self._reap_children()
            return asdict(res)
        if op is RpcOp.DESTROY:
            self._safe_unregister(cell.rns)
            cell.close()
            del self.cells[name]
            self._reap_children()
            return name
        raise ValueError(f"unsupported op {op}")

    def serve_forever(self) -> None:
        try:
            while self.running:
                for key, _ in self.sel.select(timeout=0.2):
                    cb: Callable[[], None] = key.data
                    cb()
                self._reap_children()
        finally:
            self.close()

    def close(self) -> None:
        for cell in list(self.cells.values()):
            self._safe_unregister(cell.rns)
            cell.close()
        self.cells.clear()
        self._safe_unregister(self.srv)
        self.srv.close()
        self.sel.close()
        with suppress(FileNotFoundError):
            os.unlink(self.sock_path)
        self._reap_children()


@dataclass(frozen=True)
class CellClient:
    sock_path: str

    def call(self, op: RpcOp, **params: Any) -> Any:
        with socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
        ) as sock:
            sock.connect(self.sock_path)
            JsonLine.send(sock, {"op": op.value, **params})
            resp = JsonLine.recv(sock)
        if resp is None:
            raise RuntimeError("empty RPC response")
        if not resp["ok"]:
            err = resp.get("errno")
            if err is not None:
                raise OSError(int(err), str(resp["error"]))
            raise RuntimeError(str(resp["error"]))
        return resp["result"]

    @staticmethod
    def _parse_cell_info(data: Mapping[str, Any]) -> CellInfo:
        return CellInfo(
            name=str(data["name"]),
            state=CellState(data["state"]),
            init_pid=data.get("init_pid"),
            exit_code=data.get("exit_code"),
        )

    def ping(self) -> str:
        return str(self.call(RpcOp.PING))

    def shutdown(self) -> str:
        return str(self.call(RpcOp.SHUTDOWN))

    def list_cells(self) -> list[CellInfo]:
        items: list[dict[str, Any]] = self.call(RpcOp.LIST)
        return [self._parse_cell_info(item) for item in items]

    def create(
        self,
        name: str,
        mode: CellMode = CellMode.HOST,
        proc: bool = True,
    ) -> CellInfo:
        data: dict[str, Any] = self.call(
            RpcOp.CREATE,
            name=name,
            mode=mode.value,
            proc=proc,
        )
        return self._parse_cell_info(data)

    def spawn(
        self,
        name: str,
        argv: Sequence[str],
        resolve_in_root: bool = True,
    ) -> SpawnInfo:
        data: dict[str, Any] = self.call(
            RpcOp.SPAWN,
            name=name,
            argv=list(argv),
            resolve_in_root=resolve_in_root,
        )
        return SpawnInfo(pid=int(data["pid"]), state=CellState(data["state"]))

    def mount(
        self,
        name: str,
        source: str,
        target: str,
        bind: bool = False,
        options: Mapping[str, str | None] | None = None,
    ) -> str:
        return str(
            self.call(
                RpcOp.MOUNT,
                name=name,
                source=source,
                target=target,
                bind=bind,
                options=dict(options) if options is not None else None,
            )
        )

    def kill(
        self, name: str, sig: signal.Signals | int = signal.SIGTERM
    ) -> str:
        return str(self.call(RpcOp.KILL, name=name, sig=int(sig)))

    def wait(self, name: str, nohang: bool = False) -> WaitResult:
        data: dict[str, Any] = self.call(RpcOp.WAIT, name=name, nohang=nohang)
        return WaitResult(
            pid=int(data["pid"]),
            status=int(data["status"]),
            code=int(data.get("code", 0)),
            uid=int(data.get("uid", 0)),
        )

    def destroy(self, name: str) -> str:
        return str(self.call(RpcOp.DESTROY, name=name))


class CellCli:
    @staticmethod
    def build_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser()
        parser.add_argument("--sock", default="/tmp/rootns-cells.sock")
        sub = parser.add_subparsers(dest="cmd", required=True)
        sub.add_parser("daemon")
        sub.add_parser("ps")
        sub.add_parser("shutdown")

        p_create = sub.add_parser("create")
        p_create.add_argument("name")
        p_create.add_argument(
            "--mode",
            type=CellMode,
            choices=tuple(CellMode),
            default=CellMode.HOST,
        )

        for cname in ("start", "exec", "spawn"):
            p_run = sub.add_parser(cname)
            p_run.add_argument("name")
            p_run.add_argument("argv", nargs=argparse.REMAINDER)

        p_mnt = sub.add_parser("mount")
        p_mnt.add_argument("name")
        p_mnt.add_argument("source")
        p_mnt.add_argument("target")
        p_mnt.add_argument("--bind", action="store_true")

        p_kill = sub.add_parser("kill")
        p_kill.add_argument("name")
        p_kill.add_argument(
            "-s", "--sig", type=int, default=int(signal.SIGTERM)
        )

        p_wait = sub.add_parser("wait")
        p_wait.add_argument("name")

        p_rm = sub.add_parser("destroy")
        p_rm.add_argument("name")
        return parser

    @classmethod
    def main(cls, argv: Sequence[str] | None = None) -> None:
        args = cls.build_parser().parse_args(argv)
        if args.cmd == "daemon":
            with CellService(args.sock) as srv:
                srv.serve_forever()
            return

        client = CellClient(args.sock)
        if args.cmd == "ps":
            print(
                json.dumps([asdict(c) for c in client.list_cells()], indent=2)
            )
        elif args.cmd == "shutdown":
            print(json.dumps(client.shutdown()))
        elif args.cmd == "create":
            info = client.create(args.name, mode=args.mode)
            print(json.dumps(asdict(info)))
        elif args.cmd in ("start", "exec", "spawn"):
            cmd_argv = (
                args.argv[1:]
                if args.argv and args.argv[0] == "--"
                else list(args.argv)
            )
            print(json.dumps(asdict(client.spawn(args.name, cmd_argv))))
        elif args.cmd == "mount":
            print(
                json.dumps(
                    client.mount(
                        args.name, args.source, args.target, bind=args.bind
                    )
                )
            )
        elif args.cmd == "kill":
            print(json.dumps(client.kill(args.name, args.sig)))
        elif args.cmd == "wait":
            res = client.wait(args.name)
            print(json.dumps({"pid": res.pid, "exit_code": res.exit_code}))
        elif args.cmd == "destroy":
            print(json.dumps(client.destroy(args.name)))


if __name__ == "__main__":
    CellCli.main()
