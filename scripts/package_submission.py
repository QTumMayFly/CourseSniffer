#!/usr/bin/env python3
"""按课程约定检查并生成最终提交包。"""
import argparse
from pathlib import Path
import zipfile

def main():
    parser = argparse.ArgumentParser(description="生成实验 1A 提交 ZIP")
    parser.add_argument("--video", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    for path, suffix in [(args.video, ".mp4"), (args.report, ".pdf")]:
        if not path.is_file() or path.suffix.lower() != suffix or path.stat().st_size == 0:
            parser.error(f"文件不可用：{path}")
    if not args.report.read_bytes().startswith(b"%PDF-"):
        parser.error("报告文件缺少 PDF 文件签名。")
    with args.video.open("rb") as handle:
        header = handle.read(32)
    if b"ftyp" not in header:
        parser.error("视频文件缺少 MP4 文件签名。")
    base = "仲泓宇_202618013229068"
    top = base + "_EX1A"
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / (top + ".zip")
    if destination.exists():
        parser.error(f"目标文件已经存在，请选择其他输出目录：{destination}")
    excluded = {".git", "build", "local-validation", "__pycache__"}
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if not path.is_file() or any(p in excluded or p.startswith("build-") for p in relative.parts):
                continue
            if path.suffix in {".zip", ".bundle", ".pyc"} or path.name == ".DS_Store":
                continue
            if path.resolve() in {args.video.resolve(), args.report.resolve(), destination.resolve()}:
                continue
            archive.write(path, f"{top}/{base}_ex1A_src/{relative.as_posix()}")
        archive.write(args.video, f"{top}/{base}_ex1A_play.mp4")
        archive.write(args.report, f"{top}/{base}_ex1A_report.pdf")
    with zipfile.ZipFile(destination) as archive:
        error = archive.testzip()
        if error:
            raise RuntimeError(f"ZIP 校验失败：{error}")
    print(f"文件签名及 ZIP 完整性检查通过：{destination}")
    print("请打开报告并完整播放视频，确认内容、画面和声音符合提交要求。")

if __name__ == "__main__":
    main()
