"""使用内存中的假设备验证权限恢复，实际进程只执行受控测试命令。"""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "capture_permissions_macos.py"
SPEC = importlib.util.spec_from_file_location("capture_permissions_macos", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)


class FakeDevices:
    def __init__(self, count=2):
        self.devices = {}
        for index in range(count):
            self.devices["/dev/bpf" + str(index)] = types.SimpleNamespace(
                st_mode=stat.S_IFCHR | 0o640, st_dev=20, st_ino=100 + index,
                st_rdev=200 + index, st_uid=0, st_gid=7)
        self.calls = []
        self.fail_grant = None
        self.fail_restore = None

    def paths(self):
        return sorted(self.devices)

    def lstat(self, path):
        return types.SimpleNamespace(**vars(self.devices[path]))

    def chown(self, path, uid, gid):
        self.calls.append(("chown", path, uid, gid))
        if path == self.fail_grant and uid != 0:
            raise PermissionError("模拟授权失败")
        if path == self.fail_restore and uid == 0:
            raise PermissionError("模拟恢复失败")
        self.devices[path].st_uid = uid
        self.devices[path].st_gid = gid

    def chmod(self, path, mode):
        self.calls.append(("chmod", path, mode))
        self.devices[path].st_mode = stat.S_IFMT(self.devices[path].st_mode) | mode


class FinishedChild:
    pid = 99999999

    def __init__(self, code=0):
        self.code = code

    def wait(self, timeout=None):
        return self.code

    def poll(self):
        return self.code


class CapturePermissionTests(unittest.TestCase):
    def setUp(self):
        self.devices = FakeDevices()
        self.user = guard.LoginUser(501, 20, "student", "/Users/student")
        self.output = io.StringIO()

    def run_guard(self, spawn, command=None, grace=0.2, timeout=0):
        return guard.run_session(command or ["/fake/CourseSniffer"], self.user,
                                 self.devices, spawn=spawn, output=self.output,
                                 grace=grace, timeout=timeout)

    def assert_restored(self):
        for info in self.devices.devices.values():
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 7, 0o640))

    def test_normal_exit_restores_and_supplies_user_identity(self):
        captured = {}

        def spawn(command, **options):
            captured.update(options)
            for info in self.devices.devices.values():
                self.assertEqual(info.st_uid, 501)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o440)
            return FinishedChild(7)

        self.assertEqual(self.run_guard(spawn), 7)
        self.assert_restored()
        self.assertEqual(captured["user"], 501)
        self.assertEqual(captured["group"], 20)
        self.assertEqual(captured["extra_groups"], [])
        self.assertEqual(captured["env"]["HOME"], "/Users/student")
        self.assertEqual(captured["env"]["USER"], "student")
        self.assertEqual(captured["env"]["LOGNAME"], "student")
        self.assertEqual(captured["cwd"], os.getcwd())
        self.assertTrue(captured["start_new_session"])
        self.assertTrue(captured["close_fds"])

    def test_partial_grant_failure_restores_all_touched_devices(self):
        self.devices.fail_grant = "/dev/bpf1"
        spawn = mock.Mock()
        self.assertEqual(self.run_guard(spawn), 1)
        spawn.assert_not_called()
        self.assert_restored()
        self.assertIn("模拟授权失败", self.output.getvalue())

    def test_mode_failure_after_owner_change_restores_original(self):
        original_chmod = self.devices.chmod

        def fail_first_grant(path, mode):
            if path == "/dev/bpf1" and mode == 0o440:
                raise PermissionError("模拟权限设置失败")
            original_chmod(path, mode)

        self.devices.chmod = fail_first_grant
        self.assertEqual(self.run_guard(mock.Mock()), 1)
        self.assert_restored()

    def test_spawn_failure_restores(self):
        def spawn(_command, **_options):
            raise FileNotFoundError("模拟应用不存在")

        self.assertEqual(self.run_guard(spawn), 1)
        self.assert_restored()
        self.assertIn("模拟应用不存在", self.output.getvalue())

    def test_signal_during_grant_restores_without_starting_child(self):
        original_chmod = self.devices.chmod

        def interrupt_grant(path, mode):
            original_chmod(path, mode)
            if path == "/dev/bpf0" and mode == 0o440:
                os.kill(os.getpid(), signal.SIGTERM)

        self.devices.chmod = interrupt_grant
        spawn = mock.Mock()
        self.assertEqual(self.run_guard(spawn), 128 + signal.SIGTERM)
        spawn.assert_not_called()
        self.assert_restored()

    def test_restore_failure_reports_guarded_exact_commands(self):
        self.devices.fail_restore = "/dev/bpf0"
        self.assertEqual(self.run_guard(lambda *_args, **_kwargs: FinishedChild()), 1)
        message = self.output.getvalue()
        self.assertIn("sudo /usr/sbin/chown -h 0:7 /dev/bpf0", message)
        self.assertIn("sudo /bin/chmod -h 0640 /dev/bpf0", message)
        self.assertIn("20:100:200", message)
        self.assertIn("test ! -L /dev/bpf0", message)
        self.assertEqual(self.devices.devices["/dev/bpf1"].st_uid, 0)

    def test_changed_device_identity_is_not_modified_during_restore(self):
        def spawn(_command, **_options):
            self.devices.devices["/dev/bpf0"].st_ino += 1
            return FinishedChild()

        self.assertEqual(self.run_guard(spawn), 1)
        owner_restores = [item for item in self.devices.calls
                          if item[:3] == ("chown", "/dev/bpf0", 0)]
        self.assertEqual(owner_restores, [])
        self.assertIn("设备身份发生变化", self.output.getvalue())

    def test_symbolic_link_is_rejected(self):
        self.devices.devices["/dev/bpf0"].st_mode = stat.S_IFLNK | 0o777
        spawn = mock.Mock()
        self.assertEqual(self.run_guard(spawn), 1)
        spawn.assert_not_called()
        self.assertEqual(self.devices.calls, [])

    def test_unrelated_device_path_is_rejected(self):
        self.devices.devices["/dev/bpf0-other"] = self.devices.devices.pop("/dev/bpf0")
        self.assertEqual(self.run_guard(mock.Mock()), 1)
        self.assertEqual(self.devices.calls, [])

    def test_non_darwin_refuses_before_privilege_or_device_operations(self):
        with mock.patch.object(guard.sys, "platform", "linux"), \
                mock.patch.object(guard.os, "geteuid") as geteuid, \
                mock.patch.object(guard, "BpfOperations") as operations, \
                contextlib.redirect_stderr(self.output):
            self.assertEqual(guard.main(["--", "/fake/CourseSniffer"]), 2)
        geteuid.assert_not_called()
        operations.assert_not_called()

    def test_normal_controlled_process_exit(self):
        def spawn(command, **options):
            return subprocess.Popen(command, start_new_session=True, close_fds=True,
                                    cwd=options["cwd"], env=dict(os.environ),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self.assertEqual(self.run_guard(spawn, [sys.executable, "-c", "raise SystemExit(4)"]), 4)
        self.assert_restored()

    def test_timeout_stops_controlled_process_and_restores(self):
        children = []

        def spawn(command, **options):
            child = subprocess.Popen(command, start_new_session=True, close_fds=True,
                                     cwd=options["cwd"], env=dict(os.environ),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(child)
            return child

        code = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)"
        start = time.monotonic()
        self.assertEqual(self.run_guard(spawn, [sys.executable, "-c", code], timeout=0.15), 124)
        self.assertLess(time.monotonic() - start, 5)
        self.assertIsNotNone(children[0].poll())
        self.assert_restored()
        self.assertIn("运行时间上限", self.output.getvalue())

    def test_invalid_timeout_refuses_before_authorization(self):
        for timeout in ("-1", "nan", "inf", "abc"):
            with self.subTest(timeout=timeout), \
                    mock.patch.object(guard.sys, "platform", "darwin"), \
                    mock.patch.object(guard.os, "geteuid") as geteuid, \
                    contextlib.redirect_stderr(self.output):
                self.assertEqual(guard.main(["--timeout", timeout, "--", "/fake/CourseSniffer"]), 2)
                geteuid.assert_not_called()

    def test_interrupt_signals_cleanup_controlled_process(self):
        for requested_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGQUIT):
            with self.subTest(signal=requested_signal):
                self.devices = FakeDevices()
                old_handler = signal.getsignal(requested_signal)

                def spawn(command, **options):
                    return subprocess.Popen(command, start_new_session=True, close_fds=True,
                                            cwd=options["cwd"], env=dict(os.environ),
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # 子进程主动通知本测试会话，并忽略清理信号以验证有界终止。
                code = ("import os,signal,time; "
                        "signal.signal(signal.SIGINT,signal.SIG_IGN); "
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                        "signal.signal(signal.SIGQUIT,signal.SIG_IGN); "
                        "os.kill(os.getppid(),{}); time.sleep(30)").format(int(requested_signal))
                start = time.monotonic()
                self.assertEqual(self.run_guard(spawn, [sys.executable, "-c", code]),
                                 128 + int(requested_signal))
                self.assertLess(time.monotonic() - start, 5)
                self.assert_restored()
                self.assertEqual(signal.getsignal(requested_signal), old_handler)

    def test_descendants_are_terminated_when_group_leader_exits(self):
        for leader_exits in (True, False):
            with self.subTest(leader_exits=leader_exits):
                self.devices = FakeDevices()
                children = []
                group_exited = False

                def spawn(command, **options):
                    child = subprocess.Popen(command, start_new_session=True, close_fds=True,
                                             cwd=options["cwd"], env=dict(os.environ),
                                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    children.append(child)
                    readable, _, _ = select.select([child.stdout], [], [], 3)
                    self.assertTrue(readable, "受控后代进程没有报告就绪状态")
                    self.assertEqual(os.read(child.stdout.fileno(), 6), b"ready\n")
                    return child

                code = (
                    "import os,signal,time\n"
                    "if os.fork() == 0:\n"
                    "    signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                    "    os.write(1,b'ready\\n')\n"
                    "    time.sleep(30)\n"
                    "    os._exit(0)\n"
                    + ("os._exit(9)\n" if leader_exits else "time.sleep(30)\n")
                )
                started = time.monotonic()
                try:
                    result = self.run_guard(spawn, [sys.executable, "-c", code],
                                            grace=0.1, timeout=0 if leader_exits else 0.15)
                    self.assertEqual(result, 9 if leader_exits else 124)
                    self.assertLess(time.monotonic() - started, 5)
                    self.assert_restored()
                    self.assertIsNotNone(children[0].poll())
                    # EOF 证明后代关闭了最后的写入端，僵尸进程不会阻止这一检查。
                    readable, _, _ = select.select([children[0].stdout], [], [], 1)
                    self.assertTrue(readable, "会话结束后受控后代仍然持有管道")
                    self.assertEqual(os.read(children[0].stdout.fileno(), 1), b"")
                    group_exited = True
                finally:
                    for child in children:
                        try:
                            if not group_exited:
                                try:
                                    os.killpg(child.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            child.wait(timeout=2)
                        finally:
                            child.stdout.close()


if __name__ == "__main__":
    unittest.main()
