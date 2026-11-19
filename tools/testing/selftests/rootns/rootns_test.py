#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2026 Opinsys Oy

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
import ctypes
from dataclasses import dataclass
import errno
import importlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import sys
import tempfile
import time
import traceback
from types import TracebackType
from typing import Any, Final, NoReturn
import unittest

from rootns_cells import (
    Cell,
    CellClient,
    CellInfo,
    CellMode,
    CellService,
    CellState,
    CloneArgs,
    CloneFlag,
    FsconfigCmd,
    Ioctl,
    MountFlag,
    MoveMountFlag,
    OpenTreeFlag,
    PrctlOp,
    Rootns,
    RootnsFlag,
    Sys,
    UmountFlag,
    UsernsIdmap,
    UsernsIdmapFlag,
    WaitIdType,
    WaitResult,
)

PYTHON_BIN: Final[str] = os.path.realpath(sys.executable)
SKIP_ERRNOS: Final[tuple[int, ...]] = (
    errno.ENOSYS,
    errno.EPERM,
    errno.EACCES,
    errno.EINVAL,
    errno.ENOSPC,
)


@dataclass(frozen=True)
class Payload:
    code: str

    def argv(self) -> list[str]:
        return [PYTHON_BIN, "-S", "-c", self.code]


WAIT_MOUNT_PAYLOAD: Final[Payload] = Payload(
    """\
import os
import sys
import time

if os.getpid() != 1:
    sys.exit(1)
deadline = time.monotonic() + 5.0
while time.monotonic() < deadline:
    if os.path.ismount("/mnt") and os.path.exists("/mnt/done"):
        with open("/mnt/done", "rb") as f:
            sys.exit(0 if f.read() == b"ok\\n" else 2)
    time.sleep(0.02)
sys.exit(3)
"""
)

WRITE_MOUNT_PAYLOAD: Final[Payload] = Payload(
    """\
import os
import sys

if not os.path.ismount("/mnt"):
    sys.exit(1)
with open("/mnt/done.tmp", "wb") as f:
    f.write(b"ok\\n")
os.replace("/mnt/done.tmp", "/mnt/done")
"""
)

PAUSE_PAYLOAD: Final[Payload] = Payload(
    """\
import signal

signal.pause()
"""
)


@dataclass(frozen=True)
class ProbeResult:
    supported: bool
    reason: str = ""


@dataclass
class SyncPipe:
    r_fd: int
    w_fd: int

    @classmethod
    def create(cls) -> SyncPipe:
        r_fd, w_fd = os.pipe2(os.O_CLOEXEC)
        return cls(r_fd=r_fd, w_fd=w_fd)

    def __enter__(self) -> SyncPipe:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close_read(self) -> None:
        if self.r_fd >= 0:
            os.close(self.r_fd)
            self.r_fd = -1

    def close_write(self) -> None:
        if self.w_fd >= 0:
            os.close(self.w_fd)
            self.w_fd = -1

    def close(self) -> None:
        self.close_read()
        self.close_write()

    def read_bytes(self, n: int = 1) -> bytes:
        return os.read(self.r_fd, n)

    def read_all(self) -> bytes:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(self.r_fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def write_bytes(self, data: bytes = b"1") -> None:
        os.write(self.w_fd, data)

    def wait_in_child(self, exit_code: int = 0) -> int:
        self.close_write()
        self.read_bytes()
        self.close_read()
        return exit_code


@dataclass(frozen=True)
class NsTypeCase:
    name: str
    nstype: CloneFlag


@dataclass(frozen=True)
class BadCloneCase:
    name: str
    flags: CloneFlag
    exit_signal: int = int(signal.SIGCHLD)
    expected_errno: int = errno.EINVAL


@dataclass(frozen=True)
class SignalCase:
    name: str
    sig: int
    expected_errno: int


NS_TYPE_CASES: Final[tuple[NsTypeCase, ...]] = (
    NsTypeCase("mnt", CloneFlag.NEWNS),
    NsTypeCase("cgroup", CloneFlag.NEWCGROUP),
    NsTypeCase("uts", CloneFlag.NEWUTS),
    NsTypeCase("ipc", CloneFlag.NEWIPC),
    NsTypeCase("user", CloneFlag.NEWUSER),
    NsTypeCase("net", CloneFlag.NEWNET),
    NsTypeCase("time", CloneFlag.NEWTIME),
)

BAD_CLONE_CASES: Final[tuple[BadCloneCase, ...]] = (
    BadCloneCase("newns", CloneFlag.NEWNS),
    BadCloneCase("newpid", CloneFlag.NEWPID),
    BadCloneCase("newuser", CloneFlag.NEWUSER),
    BadCloneCase("empty_mntns", CloneFlag.EMPTY_MNTNS),
    BadCloneCase("fs", CloneFlag.FS),
    BadCloneCase(
        "thread",
        CloneFlag.THREAD | CloneFlag.SIGHAND | CloneFlag.VM,
        exit_signal=0,
    ),
    BadCloneCase("parent", CloneFlag.PARENT, exit_signal=0),
    BadCloneCase("sysvsem", CloneFlag.SYSVSEM),
    BadCloneCase("vm", CloneFlag.VM),
    BadCloneCase("vm_vfork", CloneFlag.VM | CloneFlag.VFORK),
)

BAD_SIGNAL_CASES: Final[tuple[SignalCase, ...]] = (
    SignalCase("negative", -1, errno.EINVAL),
    SignalCase("out_of_range", 9999, errno.EINVAL),
    SignalCase("empty_rootns", 0, errno.ESRCH),
)


class RootnsTestBase(unittest.TestCase):
    @staticmethod
    @contextmanager
    def closing_fd(fd: int) -> Iterator[int]:
        try:
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def pause_forever() -> int:
        signal.pause()
        return 0

    @staticmethod
    def reap_exit_code(pid: int) -> int:
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return 128 + os.WTERMSIG(status)
        return 255

    @staticmethod
    def drop_to_uid(uid: int) -> None:
        try:
            Sys.setgroups_empty()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise
        os.setresgid(uid, uid, uid)
        os.setresuid(uid, uid, uid)
        Sys.prctl(PrctlOp.SET_DUMPABLE, 1)

    @classmethod
    def make_plain_mount(cls, fstype: str) -> int:
        with cls.closing_fd(Sys.fsopen(fstype)) as fsfd:
            Sys.fsconfig(fsfd, FsconfigCmd.CMD_CREATE)
            return Sys.fsmount(fsfd)

    @classmethod
    def probe_pre_idmap_mkdir(cls) -> ProbeResult:
        try:
            rns = Rootns()
        except OSError as exc:
            if exc.errno in SKIP_ERRNOS:
                return ProbeResult(False, f"rootns() unavailable: {exc}")
            raise
        with rns:
            try:
                rns.map_self_ugid()
                mfd = rns.make_mount("tmpfs")
            except OSError as exc:
                return ProbeResult(False, f"rootns setup unavailable: {exc}")
            with cls.closing_fd(mfd):
                os.mkdir("probe", 0o755, dir_fd=mfd)
                return ProbeResult(True)

    def run_forked(self, fn: Callable[[], None]) -> None:
        with SyncPipe.create() as pipe:
            sys.stdout.flush()
            sys.stderr.flush()
            pid = os.fork()
            if pid == 0:
                pipe.close_read()
                try:
                    fn()
                except unittest.SkipTest as exc:
                    payload = json.dumps({"kind": "skip", "msg": str(exc)})
                    pipe.write_bytes(payload.encode("utf-8"))
                    pipe.close_write()
                    os._exit(0)
                except BaseException:
                    payload = json.dumps(
                        {"kind": "fail", "msg": traceback.format_exc()}
                    )
                    pipe.write_bytes(payload.encode("utf-8"))
                    pipe.close_write()
                    os._exit(1)
                pipe.close_write()
                os._exit(0)
            pipe.close_write()
            raw = pipe.read_all()
            code = self.reap_exit_code(pid)
        if raw:
            info = json.loads(raw.decode("utf-8"))
            if info["kind"] == "skip":
                self.skipTest(str(info["msg"]))
            self.fail(str(info["msg"]))
        self.assertEqual(code, 0)

    def create_rootns_as_uid(self, uid: int) -> Rootns | None:
        s_parent, s_child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_DGRAM
        )
        sys.stdout.flush()
        sys.stderr.flush()
        pid = os.fork()
        if pid == 0:
            s_parent.close()
            try:
                self.drop_to_uid(uid)
                with Rootns() as rns:
                    socket.send_fds(s_child, [b"F"], [rns.fd])
                os._exit(0)
            except OSError as exc:
                os._exit(0 if exc.errno in SKIP_ERRNOS else 1)
            finally:
                s_child.close()
        s_child.close()
        fds: list[int] = []
        try:
            rlist, _, _ = select.select([s_parent], [], [], 5.0)
            if rlist:
                _, fds, _, _ = socket.recv_fds(s_parent, 1, 1)
        finally:
            s_parent.close()
        code = self.reap_exit_code(pid)
        if code != 0:
            for fd in fds:
                os.close(fd)
            self.fail(f"create_rootns_as_uid({uid}) failed with status {code}")
        return Rootns.from_fd(fds[0]) if fds else None


class CellServiceTest(RootnsTestBase):
    tmpdir: str
    sock_path: str
    daemon_pid: int
    client: CellClient

    def setUp(self) -> None:
        probe = self.probe_pre_idmap_mkdir()
        if not probe.supported:
            self.skipTest(probe.reason)
        self.daemon_pid = 0
        self.tmpdir = tempfile.mkdtemp(prefix="rootns-cells-")
        try:
            self.sock_path = os.path.join(self.tmpdir, "cells.sock")
            self.daemon_pid = os.fork()
            if self.daemon_pid == 0:
                try:
                    with CellService(self.sock_path) as srv:
                        srv.serve_forever()
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            self.client = CellClient(self.sock_path)
            for _ in range(50):
                if os.path.exists(self.sock_path):
                    try:
                        if self.client.ping() == "pong":
                            break
                    except OSError:
                        pass
                time.sleep(0.05)
            else:
                self.fail("CellService daemon failed to start")
        except BaseException:
            self.tearDown()
            raise

    def tearDown(self) -> None:
        daemon_pid = getattr(self, "daemon_pid", 0)
        if daemon_pid > 0:
            try:
                self.client.shutdown()
            except Exception:
                os.kill(daemon_pid, signal.SIGKILL)
            self.reap_exit_code(daemon_pid)
        tmpdir = getattr(self, "tmpdir", "")
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_cell_lifecycle_exec_and_hot_mount(self) -> None:
        info = self.client.create("alpha", mode=CellMode.HOST)
        self.assertEqual(info.state, CellState.CREATED)
        self.assertEqual(
            self.client.list_cells(),
            [CellInfo(name="alpha", state=CellState.CREATED)],
        )

        started = self.client.spawn("alpha", WAIT_MOUNT_PAYLOAD.argv())
        self.assertEqual(started.state, CellState.RUNNING)

        self.client.mount("alpha", "tmpfs", "/mnt")
        self.client.spawn("alpha", WRITE_MOUNT_PAYLOAD.argv())

        res = self.client.wait("alpha")
        self.assertGreater(res.pid, 0)
        self.assertEqual(res.exit_code, 0)

        self.client.destroy("alpha")
        self.assertEqual(self.client.list_cells(), [])

    def test_cell_broadcast_kill(self) -> None:
        self.client.create("killme", mode=CellMode.HOST)
        self.client.spawn("killme", PAUSE_PAYLOAD.argv())
        self.client.spawn("killme", PAUSE_PAYLOAD.argv())

        self.client.kill("killme", signal.SIGKILL)
        res = self.client.wait("killme")
        self.assertEqual(res.exit_code, -int(signal.SIGKILL))
        self.client.destroy("killme")


class RootnsUapiTest(RootnsTestBase):
    probe: ProbeResult
    cell: Cell | None

    def setUp(self) -> None:
        self.probe = self.probe_pre_idmap_mkdir()
        self.cell = None
        if self.probe.supported:
            cell = Cell("test")
            try:
                cell.setup_rootfs(
                    dirs=("proc", "tmp", "mnt"), mount_procfs=True
                )
            except BaseException:
                cell.close()
                raise
            self.cell = cell

    def tearDown(self) -> None:
        if self.cell is not None:
            self.cell.close()

    def _require_cell(self) -> Cell:
        if not self.probe.supported or self.cell is None:
            self.skipTest(self.probe.reason)
        return self.cell

    def test_create_flags(self) -> None:
        self._require_cell()
        with Rootns(RootnsFlag.NONE):
            pass
        with Rootns(RootnsFlag.DEFAULT):
            pass
        with self.assertRaises(OSError) as cm:
            Rootns((~int(RootnsFlag.ALL)) & 0xFFFFFFFF)
        self.assertEqual(cm.exception.errno, errno.EINVAL)

    def test_get_nsfd(self) -> None:
        try:
            rns = Rootns()
        except OSError as exc:
            if exc.errno in SKIP_ERRNOS:
                self.skipTest(f"rootns() unavailable: {exc}")
            raise
        with rns:
            for case in NS_TYPE_CASES:
                with self.subTest(ns=case.name):
                    with self.closing_fd(rns.get_nsfd(case.nstype)) as nsfd:
                        self.assertEqual(
                            Sys.ioctl(nsfd, Ioctl.NS_GET_NSTYPE),
                            int(case.nstype),
                        )

            with self.assertRaises(OSError) as cm:
                rns.get_nsfd(CloneFlag.NEWPID)
            self.assertEqual(cm.exception.errno, errno.ESRCH)

            with self.assertRaises(OSError) as cm:
                rns.get_nsfd(0)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with (
                self.closing_fd(rns.get_nsfd(CloneFlag.NEWNS)) as mntns_fd,
                self.closing_fd(rns.make_mount("tmpfs")) as rootfd,
            ):
                Sys.move_mount(
                    rootfd,
                    "",
                    mntns_fd,
                    "/",
                    MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                )

            with SyncPipe.create() as hold:
                pid = rns.run(hold.wait_in_child)
                hold.close_read()
                try:
                    with self.closing_fd(
                        rns.get_nsfd(CloneFlag.NEWPID)
                    ) as nsfd:
                        self.assertEqual(
                            Sys.ioctl(nsfd, Ioctl.NS_GET_NSTYPE),
                            int(CloneFlag.NEWPID),
                        )
                finally:
                    hold.close_write()
                    self.assertEqual(self.reap_exit_code(pid), 0)

    def test_wait_poll_and_clone_dead(self) -> None:
        cell = self._require_cell()
        rns = cell.rns

        with self.assertRaises(OSError) as cm:
            os.waitid(int(WaitIdType.ROOTNS), -1, os.WEXITED)
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        with self.assertRaises(OSError) as cm:
            os.waitid(int(WaitIdType.ROOTNS), 99999, os.WEXITED)
        self.assertEqual(cm.exception.errno, errno.EBADF)

        with self.assertRaises(OSError) as cm:
            os.waitid(int(WaitIdType.ROOTNS), cell.mntns_fd, os.WEXITED)
        self.assertEqual(cm.exception.errno, errno.EBADF)

        with self.assertRaises(OSError) as cm:
            os.waitid(int(WaitIdType.ROOTNS), rns.fd, os.WNOHANG)
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        with self.assertRaises(OSError) as cm:
            rns.wait(os.WSTOPPED)
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        ru_buf = ctypes.create_string_buffer(256)
        with self.assertRaises(OSError) as cm:
            Sys.waitid_raw(
                int(WaitIdType.ROOTNS),
                rns.fd,
                0,
                os.WEXITED | os.WNOHANG,
                ctypes.addressof(ru_buf),
            )
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        for wait_flags in (0, os.WNOHANG):
            with self.assertRaises(OSError) as cm:
                rns.wait(wait_flags)
            self.assertEqual(cm.exception.errno, errno.ECHILD)

        with SyncPipe.create() as hold:
            pid = rns.run(lambda: hold.wait_in_child(42))
            hold.close_read()

            self.assertEqual(rns.wait(os.WNOHANG), WaitResult(0))

            os.set_blocking(rns.fd, False)
            try:
                with self.assertRaises(OSError) as cm:
                    rns.wait(0)
                self.assertEqual(cm.exception.errno, errno.EAGAIN)
            finally:
                os.set_blocking(rns.fd, True)

            def check_foreign_pidns_wait() -> None:
                Sys.unshare(CloneFlag.NEWPID)

                def check_inner_wait() -> None:
                    with self.assertRaises(OSError) as cm_w:
                        rns.wait(os.WNOHANG)
                    self.assertEqual(cm_w.exception.errno, errno.ECHILD)

                self.run_forked(check_inner_wait)

            self.run_forked(check_foreign_pidns_wait)
            poller = select.poll()
            poller.register(rns, select.POLLIN)
            self.assertEqual(poller.poll(0), [])
            with select.epoll() as ep1, select.epoll() as ep2:
                ep1.register(rns, select.EPOLLIN | select.EPOLLEXCLUSIVE)
                ep2.register(rns, select.EPOLLIN | select.EPOLLEXCLUSIVE)
                self.assertEqual(ep1.poll(0), [])
                self.assertEqual(ep2.poll(0), [])

                hold.close_write()
                events = poller.poll(5000)
                self.assertTrue(any(ev & select.POLLHUP for _, ev in events))
                ep1_ev = ep1.poll(5.0)
                ep2_ev = ep2.poll(5.0)
                self.assertTrue(any(ev & select.EPOLLHUP for _, ev in ep1_ev))
                self.assertTrue(any(ev & select.EPOLLHUP for _, ev in ep2_ev))

        res = rns.wait(os.WNOHANG | os.WNOWAIT)
        self.assertEqual(res.pid, pid)
        self.assertEqual(res.code, os.CLD_EXITED)
        self.assertEqual(res.status, 42)
        self.assertEqual(res.exit_code, 42)
        self.assertEqual(res.uid, os.geteuid())
        Sys.waitid_raw(int(WaitIdType.ROOTNS), rns.fd, 0, os.WEXITED, 0)
        self.assertEqual(rns.wait(), res)
        self.assertEqual(self.reap_exit_code(pid), 42)

        with self.assertRaises(OSError) as cm:
            rns.clone_into()
        self.assertEqual(cm.exception.errno, errno.ESRCH)

    def test_send_signal_and_kill_on_close(self) -> None:
        cell = self._require_cell()
        rns = cell.rns

        with self.assertRaises(OSError) as cm:
            Sys.pidfd_send_signal(99999, 0)
        self.assertEqual(cm.exception.errno, errno.EBADF)

        with self.assertRaises(OSError) as cm:
            Sys.pidfd_send_signal(cell.mntns_fd, 0)
        self.assertEqual(cm.exception.errno, errno.EBADF)

        with self.assertRaises(OSError) as cm:
            Sys.pidfd_send_signal(rns.fd, 0, flags=1)
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        siginfo_buf = ctypes.create_string_buffer(128)
        with self.assertRaises(OSError) as cm:
            Sys.pidfd_send_signal(
                rns.fd, int(signal.SIGKILL), ctypes.addressof(siginfo_buf)
            )
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        for case in BAD_SIGNAL_CASES:
            with self.subTest(sig=case.name):
                with self.assertRaises(OSError) as cm:
                    rns.kill(case.sig)
                self.assertEqual(cm.exception.errno, case.expected_errno)

        with SyncPipe.create() as ready, SyncPipe.create() as hold:

            def init_proc() -> int:
                ready.close()
                hold.close()
                signal.pause()
                return 0

            def member_proc() -> int:
                ready.close_read()
                hold.close_read()
                os.setsid()
                gc = os.fork()
                if gc == 0:
                    ready.write_bytes(b"r")
                    ready.close_write()
                    signal.pause()
                    os._exit(0)
                ready.close_write()
                signal.pause()
                return 0

            pid1 = rns.run(init_proc)
            pid2 = rns.run(member_proc)
            ready.close_write()
            hold.close_write()

            self.assertEqual(ready.read_bytes(), b"r")
            ready.close_read()

            def check_foreign_pidns_kill() -> None:
                Sys.unshare(CloneFlag.NEWPID)

                def check_inner_kill() -> None:
                    with self.assertRaises(OSError) as cm_k:
                        rns.kill(0)
                    self.assertEqual(cm_k.exception.errno, errno.EXDEV)

                self.run_forked(check_inner_kill)

            self.run_forked(check_foreign_pidns_kill)

            rns.kill(0)
            rns.kill(signal.SIGKILL)
            self.assertEqual(hold.read_bytes(), b"")
            hold.close_read()

            self.assertEqual(
                self.reap_exit_code(pid2), 128 + int(signal.SIGKILL)
            )
            self.assertEqual(
                self.reap_exit_code(pid1), 128 + int(signal.SIGKILL)
            )

        with Cell("koc", flags=RootnsFlag.DEFAULT) as cell2:
            cell2.setup_rootfs(mount_procfs=False)
            pid_koc = cell2.rns.run(self.pause_forever)
        self.assertEqual(
            self.reap_exit_code(pid_koc), 128 + int(signal.SIGKILL)
        )

    def test_proc_submount_and_nested_namespaces(self) -> None:
        cell = self._require_cell()
        cell.mount_fs("tmpfs", "mnt")

        def inside() -> int:
            if os.getpid() != 1:
                return 1
            pids = [e for e in os.listdir("/proc") if e.isdigit()]
            if pids != ["1"]:
                return 2
            with open("/mnt/hello", "wb") as f:
                f.write(b"ok")
            Sys.unshare(
                CloneFlag.NEWUTS | CloneFlag.NEWIPC | CloneFlag.NEWNET
            )
            return 0

        pid = cell.rns.run(inside)
        res = cell.wait()
        self.assertEqual(res.pid, pid)
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(self.reap_exit_code(pid), 0)

    def test_setns_owner_vs_foreign(self) -> None:
        cell = self._require_cell()
        with SyncPipe.create() as hold:
            pid = cell.rns.run(hold.wait_in_child)
            hold.close_read()
            try:
                with self.closing_fd(
                    os.open(f"/proc/{pid}/ns/uts", os.O_RDONLY | os.O_CLOEXEC)
                ) as uts_fd:
                    self.run_forked(
                        lambda: Sys.setns(uts_fd, CloneFlag.NEWUTS)
                    )

                    if os.geteuid() == 0:

                        def check_foreign() -> None:
                            try:
                                self.drop_to_uid(1000)
                            except OSError:
                                return
                            with self.assertRaises(OSError) as cm_perm:
                                Sys.setns(uts_fd, CloneFlag.NEWUTS)
                            self.assertEqual(
                                cm_perm.exception.errno, errno.EPERM
                            )

                        self.run_forked(check_foreign)
            finally:
                hold.close_write()
                self.reap_exit_code(pid)

    def test_mount_and_fsconfig_validation(self) -> None:
        self._require_cell()
        with (
            Rootns() as rns,
            self.closing_fd(rns.get_nsfd(CloneFlag.NEWNS)) as mntns_fd,
        ):
            with self.assertRaises(OSError) as cm:
                Sys.move_mount(
                    Sys.AT_FDCWD, "/", mntns_fd, "/", MoveMountFlag.T_MNTNS
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.move_mount(
                    Sys.AT_FDCWD,
                    "/tmp",
                    Sys.AT_FDCWD,
                    "/tmp",
                    MoveMountFlag.CLONE,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.move_mount(
                    Sys.AT_FDCWD,
                    "/tmp",
                    mntns_fd,
                    "/",
                    MoveMountFlag.T_MNTNS
                    | MoveMountFlag.CLONE
                    | MoveMountFlag.SET_GROUP,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.closing_fd(rns.make_mount("tmpfs")) as m1:
                Sys.move_mount(
                    m1,
                    "",
                    mntns_fd,
                    "/",
                    MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                )

            with self.closing_fd(rns.make_mount("tmpfs")) as m2:
                for alias in ("/", "."):
                    with self.assertRaises(OSError) as cm:
                        Sys.move_mount(
                            m2,
                            "",
                            mntns_fd,
                            alias,
                            MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                        )
                    self.assertEqual(cm.exception.errno, errno.EBUSY)
                with self.assertRaises(OSError) as cm:
                    Sys.move_mount(
                        m2,
                        "",
                        mntns_fd,
                        ".",
                        MoveMountFlag.F_EMPTY_PATH
                        | MoveMountFlag.T_MNTNS
                        | MoveMountFlag.BENEATH,
                    )
                self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.closing_fd(Sys.fsopen("tmpfs")) as fsfd:
                Sys.fsconfig(fsfd, FsconfigCmd.SET_ROOTNS, aux=rns.fd)
                with self.assertRaises(OSError) as cm:
                    Sys.fsconfig(fsfd, FsconfigCmd.SET_ROOTNS, aux=rns.fd)
                self.assertEqual(cm.exception.errno, errno.EBUSY)

            with (
                Rootns() as other_rns,
                self.closing_fd(
                    other_rns.get_nsfd(CloneFlag.NEWNS)
                ) as other_mntns,
                self.closing_fd(rns.make_mount("tmpfs")) as bound_mfd,
            ):
                with self.assertRaises(OSError) as cm:
                    Sys.move_mount(
                        bound_mfd,
                        "",
                        other_mntns,
                        "/",
                        MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                    )
                self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.closing_fd(Sys.fsopen("proc")) as p_fsfd:
                Sys.fsconfig(p_fsfd, FsconfigCmd.SET_ROOTNS, aux=rns.fd)
                with self.assertRaises(OSError) as cm:
                    Sys.fsconfig(
                        p_fsfd,
                        FsconfigCmd.SET_STRING,
                        key="pidns",
                        value="/proc/self/ns/pid",
                    )
                self.assertEqual(cm.exception.errno, errno.EBUSY)

            with self.closing_fd(Sys.fsopen("proc")) as bad_proc:

                def check_nonancestor_proc() -> None:
                    Sys.unshare(CloneFlag.NEWPID)

                    def check_inner() -> None:
                        with self.assertRaises(OSError) as cm_set:
                            Sys.fsconfig(
                                bad_proc, FsconfigCmd.SET_ROOTNS, aux=rns.fd
                            )
                        self.assertEqual(cm_set.exception.errno, errno.EINVAL)
                        with self.assertRaises(OSError) as cm_create:
                            Sys.fsconfig(bad_proc, FsconfigCmd.CMD_CREATE)
                        self.assertEqual(
                            cm_create.exception.errno, errno.EBUSY
                        )

                    self.run_forked(check_inner)

                self.run_forked(check_nonancestor_proc)

            with (
                Rootns() as rns_lock,
                self.closing_fd(
                    rns_lock.get_nsfd(CloneFlag.NEWNS)
                ) as lock_mntns,
                SyncPipe.create() as prop_ready,
                SyncPipe.create() as prop_go,
            ):
                rns_lock.map_self_ugid()
                with self.closing_fd(rns_lock.make_mount("tmpfs")) as rfd:
                    os.mkdir("host_sub", 0o755, dir_fd=rfd)
                    os.mkdir("prop_mnt", 0o755, dir_fd=rfd)
                    Sys.move_mount(
                        rfd,
                        "",
                        lock_mntns,
                        "/",
                        MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                    )
                Sys.move_mount(
                    Sys.AT_FDCWD,
                    "/tmp",
                    lock_mntns,
                    "host_sub",
                    MoveMountFlag.T_MNTNS | MoveMountFlag.CLONE,
                )

                def try_umount_locked() -> int:
                    prop_ready.close_read()
                    prop_go.close_write()
                    try:
                        Sys.umount2("/host_sub", UmountFlag.DETACH)
                        return 1
                    except OSError as exc:
                        if exc.errno != errno.EINVAL:
                            return 2
                    Sys.set_mount_propagation(
                        "/", MountFlag.REC | MountFlag.SHARED
                    )
                    peer = os.fork()
                    if peer == 0:
                        Sys.unshare(CloneFlag.NEWNS)
                        prop_ready.write_bytes(b"p")
                        prop_ready.close_write()
                        if prop_go.read_bytes() != b"g":
                            os._exit(3)
                        prop_go.close_read()
                        if not os.path.ismount("/prop_mnt"):
                            os._exit(4)
                        try:
                            Sys.umount2("/prop_mnt", UmountFlag.DETACH)
                            os._exit(5)
                        except OSError as exc:
                            os._exit(0 if exc.errno == errno.EINVAL else 6)
                    prop_ready.close_write()
                    prop_go.close_read()
                    return self.reap_exit_code(peer)

                p_lock = rns_lock.run(try_umount_locked)
                prop_ready.close_write()
                prop_go.close_read()
                self.assertEqual(prop_ready.read_bytes(), b"p")
                Sys.move_mount(
                    Sys.AT_FDCWD,
                    "/tmp",
                    lock_mntns,
                    "prop_mnt",
                    MoveMountFlag.T_MNTNS | MoveMountFlag.CLONE,
                )
                prop_go.write_bytes(b"g")
                prop_go.close_write()
                self.assertEqual(self.reap_exit_code(p_lock), 0)

            if os.geteuid() == 0:
                u_rns = self.create_rootns_as_uid(1000)
                if u_rns is not None:
                    with (
                        u_rns,
                        self.closing_fd(
                            u_rns.get_nsfd(CloneFlag.NEWNS)
                        ) as u_mntns,
                    ):
                        with self.closing_fd(
                            u_rns.make_mount("tmpfs")
                        ) as m_root:
                            Sys.move_mount(
                                m_root,
                                "",
                                u_mntns,
                                "/",
                                MoveMountFlag.F_EMPTY_PATH
                                | MoveMountFlag.T_MNTNS,
                            )

                        def check_attacker() -> None:
                            try:
                                self.drop_to_uid(2000)
                            except OSError:
                                return
                            with self.closing_fd(Sys.fsopen("tmpfs")) as fsfd2:
                                with self.assertRaises(OSError) as cm_fs:
                                    Sys.fsconfig(
                                        fsfd2,
                                        FsconfigCmd.SET_ROOTNS,
                                        aux=u_rns.fd,
                                    )
                                self.assertEqual(
                                    cm_fs.exception.errno, errno.EPERM
                                )
                            with self.assertRaises(OSError) as cm_clone:
                                u_rns.clone_into()
                            self.assertEqual(
                                cm_clone.exception.errno, errno.EPERM
                            )

                        self.run_forked(check_attacker)

    def test_clone_flags_and_pidns_ancestry(self) -> None:
        cell = self._require_cell()
        rns = cell.rns

        with Rootns() as empty_rns:
            with self.assertRaises(OSError) as cm:
                empty_rns.clone_into(CloneFlag.VFORK)
            self.assertEqual(cm.exception.errno, errno.ENOENT)

            with (
                self.closing_fd(
                    empty_rns.get_nsfd(CloneFlag.NEWNS)
                ) as e_mntns,
                self.closing_fd(empty_rns.make_mount("tmpfs")) as e_root,
            ):
                Sys.move_mount(
                    e_root,
                    "",
                    e_mntns,
                    "/",
                    MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                )
            with self.assertRaises(OSError) as cm:
                empty_rns.clone_into(
                    CloneFlag.AUTOREAP, exit_signal=int(signal.SIGCHLD)
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

        args = CloneArgs(
            flags=int(CloneFlag.INTO_ROOTNS),
            exit_signal=int(signal.SIGCHLD),
            rootns=rns.fd,
        )
        with self.assertRaises(OSError) as cm:
            Sys.clone3(args, size=CloneArgs.SIZE_VER2)
        self.assertEqual(cm.exception.errno, errno.EINVAL)

        for case in BAD_CLONE_CASES:
            with self.subTest(flag=case.name):
                with self.assertRaises(OSError) as cm:
                    rns.clone_into(
                        extra_flags=case.flags,
                        exit_signal=case.exit_signal,
                    )
                self.assertEqual(cm.exception.errno, case.expected_errno)

        allowed = (
            CloneFlag.VFORK
            | CloneFlag.PIDFD
            | CloneFlag.CLEAR_SIGHAND
            | CloneFlag.NNP
        )
        old_umask = os.umask(0o077)
        try:
            Sys.prctl(PrctlOp.SET_DUMPABLE, 1)
            pid, pidfd = rns.clone_into(extra_flags=allowed)
            if pid == 0:
                cur_umask = os.umask(0o022)
                dumpable = Sys.prctl(PrctlOp.GET_DUMPABLE)
                ok = (
                    os.getpid() == 1
                    and Sys.prctl(PrctlOp.GET_NO_NEW_PRIVS) == 1
                    and cur_umask == 0o077
                    and dumpable != 1
                )
                os._exit(0 if ok else 1)
        finally:
            os.umask(old_umask)
        self.assertGreaterEqual(pidfd, 0)
        os.close(pidfd)
        self.assertEqual(self.reap_exit_code(pid), 0)

        with Cell("exdev") as cell2:
            cell2.setup_rootfs(mount_procfs=False)

            def check_exdev() -> None:
                Sys.unshare(CloneFlag.NEWPID)

                def check_inner() -> None:
                    with self.assertRaises(OSError) as cm_exdev:
                        cell2.rns.clone_into()
                    self.assertEqual(cm_exdev.exception.errno, errno.EXDEV)

                self.run_forked(check_inner)

            self.run_forked(check_exdev)

    def test_concurrent_bootstrap(self) -> None:
        cell = self._require_cell()
        rns = cell.rns
        with (
            SyncPipe.create() as start,
            SyncPipe.create() as ready,
            SyncPipe.create() as init_gate,
            SyncPipe.create() as peer_gate,
        ):
            workers: list[int] = []
            for idx in range(4):
                wpid = os.fork()
                if wpid == 0:
                    start.close_write()
                    ready.close_read()
                    init_gate.close_write()
                    peer_gate.close_write()
                    start.read_bytes()
                    start.close_read()

                    def entrant(worker_idx: int = idx) -> int:
                        my_pid = os.getpid()
                        ready.write_bytes(bytes([worker_idx, my_pid]))
                        ready.close_write()
                        gate = init_gate if my_pid == 1 else peer_gate
                        gate.read_bytes()
                        init_gate.close_read()
                        peer_gate.close_read()
                        return 0

                    cpid = rns.run(entrant)
                    ready.close_write()
                    init_gate.close_read()
                    peer_gate.close_read()
                    os._exit(0 if self.reap_exit_code(cpid) == 0 else 1)
                workers.append(wpid)

            start.close_read()
            ready.close_write()
            init_gate.close_read()
            peer_gate.close_read()
            start.close_write()

            seen_pids: set[int] = set()
            init_idx = -1
            for _ in range(4):
                msg = ready.read_bytes(2)
                self.assertEqual(len(msg), 2)
                if msg[1] == 1:
                    init_idx = msg[0]
                seen_pids.add(msg[1])
            ready.close_read()

            self.assertEqual(seen_pids, {1, 2, 3, 4})
            self.assertGreaterEqual(init_idx, 0)

            peer_gate.close_write()
            for i, wpid in enumerate(workers):
                if i != init_idx:
                    self.assertEqual(self.reap_exit_code(wpid), 0)
            init_gate.close_write()
            self.assertEqual(self.reap_exit_code(workers[init_idx]), 0)

        res = cell.wait()
        self.assertGreater(res.pid, 0)
        self.assertEqual(res.exit_code, 0)

    def test_pivot_root_and_standalone_mntns_hot_mount(self) -> None:
        cell = self._require_cell()
        with (
            SyncPipe.create() as ready,
            SyncPipe.create() as hold,
        ):

            def init_pivot() -> int:
                ready.close_read()
                hold.close_write()
                with self.closing_fd(self.make_plain_mount("tmpfs")) as mfd:
                    os.mkdir("old_root", 0o755, dir_fd=mfd)
                    os.mkdir("sub", 0o755, dir_fd=mfd)
                    with self.closing_fd(
                        os.open(
                            "pivoted",
                            os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC,
                            0o644,
                            dir_fd=mfd,
                        )
                    ):
                        pass
                    Sys.move_mount(
                        mfd,
                        "",
                        Sys.AT_FDCWD,
                        "/mnt",
                        MoveMountFlag.F_EMPTY_PATH,
                    )
                os.chdir("/mnt")
                Sys.pivot_root(".", "old_root")
                os.chdir("/")
                Sys.umount2("/old_root", UmountFlag.DETACH)
                ready.write_bytes(b"p")
                ready.close_write()
                hold.read_bytes()
                hold.close_read()
                return 0

            pid1 = cell.rns.run(init_pivot)
            ready.close_write()
            hold.close_read()
            try:
                self.assertEqual(ready.read_bytes(), b"p")
                ready.close_read()

                cell.mount_fs("tmpfs", "sub")

                pid2 = cell.rns.run(
                    lambda: (
                        0
                        if os.path.exists("/pivoted")
                        and os.path.ismount("/sub")
                        else 1
                    ),
                )
                self.assertEqual(self.reap_exit_code(pid2), 0)
            finally:
                hold.close_write()
                self.assertEqual(self.reap_exit_code(pid1), 0)

        with SyncPipe.create() as ext_ready, SyncPipe.create() as ext_hold:
            plain_pid = os.fork()
            if plain_pid == 0:
                ext_ready.close_read()
                ext_hold.close_write()
                try:
                    Sys.unshare(CloneFlag.NEWNS)
                    Sys.set_mount_propagation("/")
                    with self.closing_fd(
                        self.make_plain_mount("tmpfs")
                    ) as mfd:
                        Sys.move_mount(
                            mfd,
                            "",
                            Sys.AT_FDCWD,
                            "/tmp",
                            MoveMountFlag.F_EMPTY_PATH,
                        )
                    os.mkdir("/tmp/target", 0o755)
                    ext_ready.write_bytes(b"r")
                    ext_ready.close_write()
                    ext_hold.read_bytes()
                    ext_hold.close_read()
                    os._exit(0 if os.path.ismount("/tmp/target") else 2)
                except BaseException:
                    os._exit(1)
            ext_ready.close_write()
            ext_hold.close_read()
            try:
                self.assertEqual(ext_ready.read_bytes(), b"r")
                ext_ready.close_read()
                with (
                    self.closing_fd(
                        os.open(
                            f"/proc/{plain_pid}/ns/mnt",
                            os.O_RDONLY | os.O_CLOEXEC,
                        )
                    ) as ext_mntns,
                    self.closing_fd(self.make_plain_mount("tmpfs")) as mfd,
                ):
                    with self.assertRaises(OSError) as cm:
                        Sys.move_mount(
                            mfd,
                            "",
                            ext_mntns,
                            "tmp/..",
                            MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                        )
                    self.assertEqual(cm.exception.errno, errno.EBUSY)
                    with self.assertRaises(OSError) as cm:
                        Sys.move_mount(
                            mfd,
                            "",
                            ext_mntns,
                            "tmp/..",
                            MoveMountFlag.F_EMPTY_PATH
                            | MoveMountFlag.T_MNTNS
                            | MoveMountFlag.BENEATH,
                        )
                    self.assertEqual(cm.exception.errno, errno.EINVAL)
                    Sys.move_mount(
                        mfd,
                        "",
                        ext_mntns,
                        "tmp/target",
                        MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                    )
            finally:
                ext_hold.close_write()
            self.assertEqual(self.reap_exit_code(plain_pid), 0)

    def test_userns_set_idmap(self) -> None:
        self._require_cell()
        with (
            Rootns() as rns,
            self.closing_fd(rns.get_nsfd(CloneFlag.NEWUSER)) as userns_fd,
            self.closing_fd(rns.get_nsfd(CloneFlag.NEWNS)) as mntns_fd,
        ):
            with self.assertRaises(OSError) as cm:
                Sys.userns_set_idmap_raw(-1, 0)
            self.assertEqual(cm.exception.errno, errno.EBADF)

            with self.assertRaises(OSError) as cm:
                Sys.userns_set_idmap_raw(userns_fd, 0)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(
                    userns_fd,
                    uid_extents=((0, os.geteuid(), 1),),
                    size=UsernsIdmap.SIZE_VER0 - 1,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(
                    userns_fd,
                    uid_extents=((0, os.geteuid(), 1),),
                    sys_flags=1,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(
                    rns.fd,
                    uid_extents=((0, os.geteuid(), 1),),
                    deny_setgroups=True,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(
                    mntns_fd,
                    uid_extents=((0, os.geteuid(), 1),),
                    deny_setgroups=True,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(userns_fd)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(
                    userns_fd,
                    extra_flags=(~int(UsernsIdmapFlag.ALL)) & 0xFFFFFFFF,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            with self.assertRaises(OSError) as cm:
                Sys.set_userns_idmap(
                    userns_fd,
                    uid_extents=((0, os.geteuid(), 0),),
                    deny_setgroups=True,
                )
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            rns.map_self_ugid()
            with self.assertRaises(OSError) as cm:
                rns.map_self_ugid()
            self.assertEqual(cm.exception.errno, errno.EPERM)

            with self.closing_fd(rns.make_mount("tmpfs")) as rootfd:
                os.mkdir("proc", 0o755, dir_fd=rootfd)
                Sys.move_mount(
                    rootfd,
                    "",
                    mntns_fd,
                    "/",
                    MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                )
            with self.closing_fd(rns.make_mount("proc")) as pfd:
                Sys.move_mount(
                    pfd,
                    "",
                    mntns_fd,
                    "proc",
                    MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                )

            def verify_idmap() -> int:
                if os.geteuid() != 0 or os.getegid() != 0:
                    return 1
                with open("/proc/self/setgroups", "rb") as f:
                    if f.read() != b"deny\n":
                        return 2
                return 0

            pid = rns.run(verify_idmap)
            res = rns.wait()
            self.assertEqual(res.pid, pid)
            self.assertEqual(res.exit_code, 0)
            self.assertEqual(self.reap_exit_code(pid), 0)

    def test_userns_set_idmap_delegation(self) -> None:
        self._require_cell()
        if os.geteuid() != 0:
            self.skipTest("uidmapd delegation test requires root")

        rns1 = self.create_rootns_as_uid(1000)
        rns2 = self.create_rootns_as_uid(1000)
        if rns1 is None or rns2 is None:
            if rns1 is not None:
                rns1.close()
            if rns2 is not None:
                rns2.close()
            self.skipTest("unprivileged rootns creation unavailable")

        with rns1, rns2:
            s_main, s_alice = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_DGRAM
            )
            alice_pid = os.fork()
            if alice_pid == 0:
                s_main.close()
                try:
                    self.drop_to_uid(1000)
                    with self.closing_fd(
                        rns1.get_nsfd(CloneFlag.NEWUSER)
                    ) as ufd1:
                        socket.send_fds(s_alice, [b"A"], [ufd1])
                    os._exit(0)
                except BaseException:
                    os._exit(1)
                finally:
                    s_alice.close()
            s_alice.close()
            _, alice_fds, _, _ = socket.recv_fds(s_main, 1, 1)
            s_main.close()
            self.assertEqual(self.reap_exit_code(alice_pid), 0)

            with (
                self.closing_fd(alice_fds[0]) as alice_ufd,
                self.closing_fd(rns2.get_nsfd(CloneFlag.NEWUTS)) as uts2_fd,
            ):
                s_m1, s_m2 = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_DGRAM
                )
                mal_pid = os.fork()
                if mal_pid == 0:
                    s_m1.close()
                    try:
                        self.drop_to_uid(2000)
                        with self.closing_fd(
                            Sys.ioctl(uts2_fd, Ioctl.NS_GET_USERNS)
                        ) as bad_ufd:
                            socket.send_fds(s_m2, [b"M"], [bad_ufd])
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                    finally:
                        s_m2.close()
                s_m2.close()
                _, mal_fds, _, _ = socket.recv_fds(s_m1, 1, 1)
                s_m1.close()
                self.assertEqual(self.reap_exit_code(mal_pid), 0)

                with self.closing_fd(mal_fds[0]) as mallory_ufd:

                    def run_uidmapd() -> None:
                        try:
                            Sys.drop_to_setid_helper(990)
                        except OSError as exc:
                            if exc.errno in SKIP_ERRNOS:
                                self.skipTest(f"setid helper setup: {exc}")
                            raise

                        with self.assertRaises(OSError) as cm_bad:
                            Sys.set_userns_idmap(
                                mallory_ufd,
                                uid_extents=((0, 1000, 1),),
                                deny_setgroups=True,
                            )
                        self.assertEqual(cm_bad.exception.errno, errno.EPERM)

                        with self.assertRaises(OSError) as cm_root:
                            Sys.set_userns_idmap(
                                alice_ufd,
                                uid_extents=((0, 0, 1),),
                                deny_setgroups=True,
                            )
                        self.assertEqual(cm_root.exception.errno, errno.EPERM)

                        Sys.set_userns_idmap(
                            alice_ufd,
                            uid_extents=((0, 1000, 1), (1, 2000, 1)),
                            gid_extents=((0, 1000, 1), (1, 2000, 1)),
                            deny_setgroups=True,
                        )

                    self.run_forked(run_uidmapd)

            def verify_as_alice() -> None:
                self.drop_to_uid(1000)
                with (
                    self.closing_fd(
                        rns1.get_nsfd(CloneFlag.NEWNS)
                    ) as mntns_fd,
                    self.closing_fd(rns1.make_mount("tmpfs")) as rootfd,
                ):
                    Sys.move_mount(
                        rootfd,
                        "",
                        mntns_fd,
                        "/",
                        MoveMountFlag.F_EMPTY_PATH | MoveMountFlag.T_MNTNS,
                    )

                def switch_subuid() -> int:
                    os.setresgid(1, 1, 1)
                    os.setresuid(1, 1, 1)
                    return 0 if os.geteuid() == 1 and os.getegid() == 1 else 1

                pid = rns1.run(switch_subuid)
                res = rns1.wait()
                self.assertEqual(res.pid, pid)
                self.assertEqual(res.exit_code, 0)
                self.assertEqual(self.reap_exit_code(pid), 0)

            self.run_forked(verify_as_alice)

    def test_unprivileged_without_entering_userns(self) -> None:
        def worker() -> None:
            if os.geteuid() == 0:
                try:
                    self.drop_to_uid(1000)
                except OSError as exc:
                    if exc.errno == errno.EINVAL:
                        self.skipTest("uid 1000 unmapped in current userns")
                    raise

            try:
                tfd = Sys.fsopen("tmpfs")
            except OSError as exc:
                self.assertEqual(exc.errno, errno.EPERM)
            else:
                with self.closing_fd(tfd):
                    with self.assertRaises(OSError) as cm_create:
                        Sys.fsconfig(tfd, FsconfigCmd.CMD_CREATE)
                    self.assertEqual(cm_create.exception.errno, errno.EPERM)

            with self.assertRaises(OSError) as cm_ot:
                Sys.open_tree(
                    Sys.AT_FDCWD,
                    "/tmp",
                    OpenTreeFlag.CLONE | OpenTreeFlag.CLOEXEC,
                )
            self.assertEqual(cm_ot.exception.errno, errno.EPERM)

            try:
                cell = Cell("unpriv", flags=RootnsFlag.DEFAULT)
            except OSError as exc:
                if exc.errno in SKIP_ERRNOS:
                    self.skipTest("unprivileged rootns unavailable")
                raise

            with (
                tempfile.TemporaryDirectory(prefix="rootns-unpriv-") as hdir,
                cell,
            ):
                os.chmod(hdir, 0o755)
                with open(os.path.join(hdir, "hello"), "wb") as f:
                    f.write(b"unpriv-ok\n")
                cell.setup_rootfs(
                    dirs=("proc", "tmp", "mnt"), mount_procfs=True
                )
                cell.bind_mount(hdir, "mnt")

                def unpriv_init() -> int:
                    if (
                        os.getpid() != 1
                        or os.geteuid() != 0
                        or os.getegid() != 0
                    ):
                        return 1
                    pids = [e for e in os.listdir("/proc") if e.isdigit()]
                    if pids != ["1"]:
                        return 2
                    with open("/mnt/hello", "rb") as hf:
                        if hf.read() != b"unpriv-ok\n":
                            return 3
                    try:
                        Sys.umount2("/mnt", UmountFlag.DETACH)
                        return 4
                    except OSError as exc:
                        return 0 if exc.errno == errno.EINVAL else 5

                pid = cell.rns.run(unpriv_init)
                res = cell.wait()
                self.assertEqual(res.pid, pid)
                self.assertEqual(res.exit_code, 0)
                self.assertEqual(self.reap_exit_code(pid), 0)

        self.run_forked(worker)

class KtapTestResult(unittest.TestResult):
    def __init__(self, ksft_mod: Any) -> None:
        super().__init__()
        self._ksft = ksft_mod
        self._failed = False

    @staticmethod
    def _test_name(test: unittest.TestCase) -> str:
        return f"{type(test).__name__}.{test._testMethodName}"

    def _print_diag(self, text: str) -> None:
        for line in text.rstrip().splitlines():
            self._ksft.print_msg(line)

    def _print_err(
        self,
        test: unittest.TestCase,
        err: (
            tuple[type[BaseException], BaseException, TracebackType]
            | tuple[None, None, None]
        ),
    ) -> None:
        formatted = "".join(traceback.format_exception(*err))
        self._print_diag(f"{test.id()}:\n{formatted}")

    def startTest(self, test: unittest.TestCase) -> None:
        super().startTest(test)
        self._failed = False

    def stopTest(self, test: unittest.TestCase) -> None:
        if self._failed:
            self._ksft.test_result_fail(self._test_name(test))
        super().stopTest(test)

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self._ksft.test_result_pass(self._test_name(test))

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        name = self._test_name(test)
        if reason:
            self._print_diag(f"{name}: {reason}")
        self._ksft.test_result_skip(name)

    def addFailure(
        self,
        test: unittest.TestCase,
        err: (
            tuple[type[BaseException], BaseException, TracebackType]
            | tuple[None, None, None]
        ),
    ) -> None:
        super().addFailure(test, err)
        self._print_err(test, err)
        self._failed = True

    def addError(
        self,
        test: unittest.TestCase,
        err: (
            tuple[type[BaseException], BaseException, TracebackType]
            | tuple[None, None, None]
        ),
    ) -> None:
        super().addError(test, err)
        self._print_err(test, err)
        self._failed = True

    def addSubTest(
        self,
        test: unittest.TestCase,
        subtest: unittest.TestCase,
        err: (
            tuple[type[BaseException], BaseException, TracebackType]
            | tuple[None, None, None]
            | None
        ),
    ) -> None:
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._print_err(subtest, err)
            self._failed = True


class KtapRunner:
    @staticmethod
    def _load_ksft() -> Any:
        ksft_dir = str(Path(__file__).resolve().parents[1] / "kselftest")
        if ksft_dir not in sys.path:
            sys.path.insert(0, ksft_dir)
        return importlib.import_module("ksft")

    @classmethod
    def main(cls, argv: Sequence[str] | None = None) -> NoReturn:
        args = list(sys.argv[1:] if argv is None else argv)
        loader = unittest.TestLoader()
        module = sys.modules[__name__]
        suite = (
            loader.loadTestsFromNames(args, module)
            if args
            else loader.loadTestsFromModule(module)
        )
        ksft = cls._load_ksft()
        total = suite.countTestCases()
        ksft.print_header()
        ksft.set_plan(total)
        result = KtapTestResult(ksft)
        suite.run(result)
        ksft.print_cnts()
        sys.stdout.flush()
        counts: dict[str, int] = ksft.ksft_cnt
        if counts["fail"] > 0:
            code = int(ksft.KSFT_FAIL)
        elif total == 0 or (counts["pass"] == 0 and counts["skip"] > 0):
            code = int(ksft.KSFT_SKIP)
        else:
            code = int(ksft.KSFT_PASS)
        sys.exit(code)


if __name__ == "__main__":
    KtapRunner.main()
