#!/usr/bin/env python3
"""临时授予当前用户 BPF 读取权限，并以该用户身份运行指定程序。"""

import errno
import fcntl
import math
import os
from pathlib import Path
import pwd
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass


DEVICE_PATTERN = re.compile(r"/dev/bpf[0-9]+\Z")
LOCK_PATH = "/var/run/coursesniffer-bpf.lock"


@dataclass(frozen=True)
class LoginUser:
    uid: int
    gid: int
    name: str
    home: str


@dataclass(frozen=True)
class DeviceState:
    path: str
    device: int
    inode: int
    special_device: int
    uid: int
    gid: int
    mode: int


class BpfOperations:
    """设备操作只接受经过检查的 BPF 字符设备。"""

    def paths(self):
        return sorted(
            ("/dev/" + name for name in os.listdir("/dev")
             if re.fullmatch(r"bpf[0-9]+", name)),
            key=lambda path: int(path[8:]),
        )

    @staticmethod
    def lstat(path):
        return os.lstat(path)

    @staticmethod
    def chown(path, uid, gid):
        os.chown(path, uid, gid, follow_symlinks=False)

    @staticmethod
    def chmod(path, mode):
        os.chmod(path, mode, follow_symlinks=False)


def read_device(path, operations):
    if not DEVICE_PATTERN.fullmatch(path):
        raise RuntimeError("设备路径必须采用 /dev/bpf 后接数字编号的形式：" + path)
    info = operations.lstat(path)
    if not stat.S_ISCHR(info.st_mode):
        raise RuntimeError("目标需要保持为 BPF 字符设备：" + path)
    return DeviceState(path, info.st_dev, info.st_ino, info.st_rdev,
                       info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))


def verify_device(original, operations):
    current = read_device(original.path, operations)
    if (current.device, current.inode, current.special_device) != (
            original.device, original.inode, original.special_device):
        raise RuntimeError("设备身份发生变化：" + original.path)


def restoration_command(original):
    path = shlex.quote(original.path)
    identity = shlex.quote("{}:{}:{}".format(
        original.device, original.inode, original.special_device))
    return (
        'test ! -L {path} && test -c {path} && '
        'test "$(/usr/bin/stat -f \'%d:%i:%r\' {path})" = {identity} && '
        'sudo /usr/sbin/chown -h {uid}:{gid} {path} && '
        'sudo /bin/chmod -h {mode:04o} {path}'
    ).format(path=path, identity=identity, uid=original.uid,
             gid=original.gid, mode=original.mode)


def restore_devices(states, operations, output):
    success = True
    for original in reversed(states):
        errors = []
        try:
            verify_device(original, operations)
        except (OSError, RuntimeError) as error:
            errors.append(str(error))
        else:
            try:
                operations.chown(original.path, original.uid, original.gid)
            except OSError as error:
                errors.append(str(error))
            try:
                verify_device(original, operations)
                operations.chmod(original.path, original.mode)
            except (OSError, RuntimeError) as error:
                errors.append(str(error))
        if errors:
            success = False
            print("设备属性恢复失败：{}；{}".format(original.path, "；".join(errors)), file=output)
            print("确认设备身份后执行以下恢复命令：", file=output)
            print(restoration_command(original), file=output)
    return success


def login_user(environment):
    try:
        uid = int(environment["SUDO_UID"])
        gid = int(environment["SUDO_GID"])
        name = environment["SUDO_USER"]
        account = pwd.getpwuid(uid)
    except (KeyError, TypeError, ValueError) as error:
        raise RuntimeError("请由普通用户启动脚本，并通过系统 sudo 完成授权。") from error
    if uid <= 0 or gid < 0 or account.pw_name != name or account.pw_gid != gid:
        raise RuntimeError("sudo 用户信息与本机用户记录不一致。")
    return LoginUser(uid, gid, name, account.pw_dir)


def acquire_lock(path=LOCK_PATH):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
            raise RuntimeError("权限会话锁必须为 root 专属的普通文件：" + path)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise RuntimeError("另一个 CourseSniffer 权限会话正在运行。") from error
            raise
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def finish_child(child, requested_signal, grace, output):
    if child is None:
        return True
    try:
        try:
            os.killpg(child.pid, requested_signal)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while True:
            child.poll()
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            time.sleep(min(0.05, remaining))
        # 后代退出后可能暂时保持僵尸状态，SIGKILL 之后仅等待并回收直接子进程。
        child.wait(timeout=grace)
        return True
    except OSError as error:
        print("无法结束会话进程组：" + str(error), file=output)
        return False
    except subprocess.TimeoutExpired:
        print("子进程在规定时间内未能结束。", file=output)
        return False


def run_session(command, user, operations, spawn=subprocess.Popen, output=None, grace=2.0, timeout=0):
    """原设备属性保存在本次进程内存，正常退出与可处理信号执行恢复。"""
    output = output if output is not None else sys.stderr
    states = []
    child = None
    received_signal = 0
    result = 1
    previous_handlers = {}

    def receive_signal(number, _frame):
        nonlocal received_signal
        if not received_signal:
            received_signal = number

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        previous_handlers[number] = signal.signal(number, receive_signal)
    try:
        paths = operations.paths()
        if not paths:
            raise RuntimeError("当前系统没有可授权的 /dev/bpf 数字编号设备。")
        for path in paths:
            if received_signal:
                break
            original = read_device(path, operations)
            states.append(original)
            verify_device(original, operations)
            operations.chown(path, user.uid, original.gid)
            verify_device(original, operations)
            operations.chmod(path, (original.mode & 0o077) | 0o400)
        if received_signal:
            result = 128 + received_signal
        else:
            environment = dict(os.environ)
            environment.update(HOME=user.home, USER=user.name, LOGNAME=user.name)
            # 子进程使用用户的主组，并清空从特权进程继承的补充组。
            child = spawn(command, cwd=os.getcwd(), env=environment, close_fds=True,
                          start_new_session=True, user=user.uid, group=user.gid,
                          extra_groups=[])
            deadline = time.monotonic() + timeout if timeout else None
            while not received_signal:
                remaining = deadline - time.monotonic() if deadline is not None else None
                if remaining is not None and remaining <= 0:
                    print("程序达到运行时间上限，正在结束本次权限会话。", file=output)
                    result = 124
                    break
                try:
                    status = child.wait(timeout=min(0.1, remaining) if remaining is not None else 0.1)
                    result = status if status >= 0 else 128 - status
                    break
                except subprocess.TimeoutExpired:
                    pass
            if received_signal:
                result = 128 + received_signal
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print("权限会话执行失败：" + str(error), file=output)
        result = 1
    finally:
        if not finish_child(child, received_signal or signal.SIGTERM, grace, output):
            result = 1
        if not restore_devices(states, operations, output):
            result = 1
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    return result


def main(arguments=None):
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if sys.platform != "darwin":
        print("此权限脚本仅支持 macOS。", file=sys.stderr)
        return 2
    forwarded_arguments = list(arguments)
    timeout = 0.0
    if arguments and arguments[0] == "--timeout":
        try:
            timeout = float(arguments[1])
            if not math.isfinite(timeout) or timeout < 0:
                raise ValueError()
        except (IndexError, ValueError):
            print("运行时间上限必须为零或有限的正数。", file=sys.stderr)
            return 2
        arguments = arguments[2:]
    if len(arguments) < 2 or arguments[0] != "--" or not arguments[1]:
        print("用法：python3 capture_permissions_macos.py [--timeout 秒数] -- <command> [args...]", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        try:
            os.execv("/usr/bin/sudo", ["sudo", "--", sys.executable,
                     str(Path(__file__).resolve()), *forwarded_arguments])
        except OSError as error:
            print("无法启动系统授权：" + str(error), file=sys.stderr)
            return 1
    descriptor = None
    try:
        user = login_user(os.environ)
        descriptor = acquire_lock()
        return run_session(arguments[1:], user, BpfOperations(), timeout=timeout)
    except (OSError, RuntimeError) as error:
        print("权限会话无法启动：" + str(error), file=sys.stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)


if __name__ == "__main__":
    sys.exit(main())
