#!/usr/bin/env python3
"""在九十秒期限内执行本机抓包测试，并结束超时进程组。"""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys


def stop_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main():
    parser = argparse.ArgumentParser(description="执行本机抓包测试")
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        parser.error(f"测试程序不可执行：{executable}")
    command = [str(executable), "idleLiveCaptureStop", "liveLoopbackTraffic", "-o", "-,txt"]
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait(timeout=90)
    except subprocess.TimeoutExpired:
        print("本机抓包测试超过九十秒，正在终止测试进程。", file=sys.stderr, flush=True)
        stop_process_group(process)
        return 124
    except KeyboardInterrupt:
        stop_process_group(process)
        return 130


if __name__ == "__main__":
    sys.exit(main())
