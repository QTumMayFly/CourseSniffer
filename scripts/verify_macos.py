#!/usr/bin/env python3
"""构建 Mac 应用并保存真实抓包、窗口截图和结构化验证记录。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1]


def command_output(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        return (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error)


def main():
    parser = argparse.ArgumentParser(description="完成 macOS 构建、抓包测试和实际窗口验证")
    parser.add_argument("--install-deps", action="store_true", help="使用 Homebrew 安装 qtbase、cmake 和 ninja")
    parser.add_argument("--interface", default="en0", help="验证混杂模式请求的非回环接口，默认 en0")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("此脚本需要在目标 macOS 设备上运行。")
    if os.geteuid() == 0:
        parser.error("请以普通用户运行此脚本；所需管理员操作由脚本单独请求。")
    if not shutil.which("brew"):
        parser.error("Homebrew 不可用，请安装 Homebrew 后运行此命令。")
    results = PROJECT / "local-validation"
    results.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    proof_directory = results / ("live_gui_" + stamp)
    record = {
        "application_version": "1.1.0",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": "macOS",
        "system_version": command_output(["sw_vers"]),
        "architecture": platform.machine(),
        "physical_interface": args.interface,
        "steps": [],
        "overall_passed": False,
        "proof_directory": str(proof_directory),
    }
    environment = dict(os.environ)
    environment["COURSESNIFFER_INTERFACE"] = args.interface
    environment["COURSESNIFFER_PYTHON"] = sys.executable

    def run_step(name, command):
        print(f"正在执行：{name}", flush=True)
        try:
            result = subprocess.run(command, cwd=PROJECT, env=environment, check=False)
            code = result.returncode
        except OSError as error:
            print(error, file=sys.stderr)
            code = 127
        record["steps"].append({"name": name, "exit_code": code})
        if code:
            raise RuntimeError(f"验证步骤未通过：{name}，退出状态 {code}")

    try:
        if args.install_deps:
            run_step("安装构建依赖", ["brew", "install", "qtbase", "cmake", "ninja"])
        run_step("构建应用并执行 CTest", ["bash", "scripts/build_macos.sh"])
        record["tool_versions"] = {
            "clang": command_output(["clang++", "--version"]),
            "cmake": command_output(["cmake", "--version"]),
            "homebrew_packages": command_output(["brew", "list", "--versions", "qtbase", "cmake", "ninja"]),
            "macos_sdk": command_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"]),
        }
        run_step("实际抓包与接口模式测试", ["bash", "scripts/validate_capture_macos.sh"])
        executable = PROJECT / "build/CourseSniffer.app/Contents/MacOS/CourseSniffer"
        run_step("普通用户运行实际图形界面", [sys.executable,
            str(PROJECT / "scripts/capture_permissions_macos.py"), "--timeout", "90", "--", str(executable),
            "--capture-proof", str(proof_directory), "--demo-script", str(PROJECT / "demo/run_demo.py")])
        proof = json.loads((proof_directory / "capture_proof.json").read_text(encoding="utf-8"))
        record["live_gui_proof"] = proof
        if proof.get("data_source") != "live-libpcap" or proof.get("passed") is not True:
            raise RuntimeError("实际图形界面的抓包检查未通过。")
        if proof.get("effective_uid") != os.getuid():
            raise RuntimeError("图形界面的运行身份与当前普通用户不一致。")
        record["overall_passed"] = True
    except (OSError, ValueError, RuntimeError) as error:
        record["error"] = str(error)
        print(error, file=sys.stderr)
    except KeyboardInterrupt:
        record["error"] = "本机验证由用户终止。"
        print(record["error"], file=sys.stderr)
    finally:
        proof_path = proof_directory / "capture_proof.json"
        if "live_gui_proof" not in record and proof_path.is_file():
            try:
                record["live_gui_proof"] = json.loads(proof_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                record["proof_read_error"] = str(error)
        output = json.dumps(record, ensure_ascii=False, indent=2) + "\n"
        (results / "verification.json").write_text(output, encoding="utf-8")
        (results / ("verification_" + stamp + ".json")).write_text(output, encoding="utf-8")
        lines = ["# Mac 本机验证记录", "", f"记录时间：{record['recorded_at_utc']}", "",
                 f"总体结果：{'通过' if record['overall_passed'] else '未通过'}", "",
                 "| 检查步骤 | 退出状态 |", "| --- | --- |"]
        lines += [f"| {step['name']} | {step['exit_code']} |" for step in record["steps"]]
        lines += ["", f"实际界面资料目录：{proof_directory}", ""]
        if record.get("error"):
            lines += [f"检查说明：{record['error']}", ""]
        (results / "verification.md").write_text("\n".join(lines), encoding="utf-8")
        print(f"验证记录：{results / 'verification.json'}")
    if record["overall_passed"]:
        print("Mac 构建、实际捕获和普通用户界面验证全部通过。")
        print("报告追加本机结果：python3 scripts/render_report.py --validation local-validation/verification.json")
    return 0 if record["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
