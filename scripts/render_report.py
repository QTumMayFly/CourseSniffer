#!/usr/bin/env python3
"""将可编辑 Markdown 报告渲染为 PDF。

依赖：ReportLab。
用法：python3 scripts/render_report.py --font /absolute/path/chinese_font.ttf
本机记录：python3 scripts/render_report.py --validation local-validation/verification.json
省略 --font 时查找常用中文字体，随后使用 STSong-Light。
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import html
import json
from pathlib import Path
import re
import sys

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate, Flowable, Frame, Image, KeepTogether, PageBreak,
        PageTemplate, Paragraph, Spacer, Table, TableStyle,
    )
except ImportError as exc:
    raise SystemExit("缺少 ReportLab，请在 Python 虚拟环境中安装 reportlab。") from exc


PROJECT = Path(__file__).resolve().parents[1]
APPLICATION_VERSION = "1.1.0"
PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN_X = 45
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN_X
INK = colors.HexColor("#1E334B")
MUTED = colors.HexColor("#596E83")
BLUE = colors.HexColor("#25658D")
PALE = colors.HexColor("#F1F5F9")
LINE = colors.HexColor("#D8E2EC")


def load_font(requested: str | None) -> str:
    candidates = []
    if requested:
        candidates.append(Path(requested).expanduser())
    candidates.extend([
        Path("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"),
        Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
        Path("/Library/Fonts/Arial Unicode.ttf"),
    ])
    for path in candidates:
        if not path.is_file():
            continue
        try:
            pdfmetrics.registerFont(TTFont("ReportChinese", str(path), subfontIndex=0))
            pdfmetrics.registerFontFamily("ReportChinese", normal="ReportChinese", bold="ReportChinese", italic="ReportChinese", boldItalic="ReportChinese")
            return "ReportChinese"
        except Exception as error:
            print(f"字体读取失败：{path}；{error}", file=sys.stderr)
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    pdfmetrics.registerFontFamily("STSong-Light", normal="STSong-Light", bold="STSong-Light", italic="STSong-Light", boldItalic="STSong-Light")
    return "STSong-Light"


def inline(text: str) -> str:
    """转换报告使用的行内 Markdown，保留代码标识符和可点击链接。"""
    tokens: list[str] = []

    def hold(value: str) -> str:
        tokens.append(value)
        return f"@@TOKEN{len(tokens) - 1}@@"

    text = re.sub(r"`([^`]+)`", lambda m: hold(f'<font color="#245C7F">{html.escape(m.group(1))}</font>'), text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", lambda m: hold(f'<link href="{html.escape(m.group(2), quote=True)}" color="#25658D"><u>{html.escape(m.group(1))}</u></link>'), text)
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r'<font color="#1E334B">\1</font>', text)
    for index, token in enumerate(tokens):
        text = text.replace(f"@@TOKEN{index}@@", token)
    return text


class CodeBlock(Flowable):
    def __init__(self, lines: list[str], font: str):
        super().__init__()
        self.lines = lines
        self.font = font
        self.width = CONTENT_WIDTH
        self.font_size = 8.0
        self.leading = 12.0
        self.height = len(lines) * self.leading + 17
        self.spaceBefore = 2
        self.spaceAfter = 8

    def wrap(self, available_width: float, available_height: float):
        self.width = min(CONTENT_WIDTH, available_width)
        largest = max((pdfmetrics.stringWidth(line, self.font, self.font_size) for line in self.lines), default=1)
        if largest > self.width - 22:
            self.font_size = max(6.2, self.font_size * (self.width - 22) / largest)
        return self.width, self.height

    def draw(self):
        canvas = self.canv
        canvas.setFillColor(PALE)
        canvas.roundRect(0, 0, self.width, self.height, 5, stroke=0, fill=1)
        canvas.setFillColor(BLUE)
        canvas.rect(0, 0, 3, self.height, stroke=0, fill=1)
        canvas.setFont(self.font, self.font_size)
        canvas.setFillColor(INK)
        for number, line in enumerate(self.lines):
            canvas.drawString(11, self.height - 13 - number * self.leading, line)


def make_styles(font: str) -> dict[str, ParagraphStyle]:
    base = dict(fontName=font, textColor=INK, wordWrap="CJK", alignment=TA_LEFT, allowWidows=0, allowOrphans=0)
    return {
        "title": ParagraphStyle("title", fontSize=21, leading=29, spaceAfter=13, keepWithNext=True, **base),
        "h2": ParagraphStyle("h2", fontSize=12.3, leading=18, spaceBefore=8, spaceAfter=6, keepWithNext=True, **base),
        "body": ParagraphStyle("body", fontSize=9.5, leading=15.1, spaceAfter=7.5, **base),
        "cell": ParagraphStyle("cell", fontSize=8.5, leading=12.7, **base),
        "headcell": ParagraphStyle("headcell", fontSize=8.6, leading=12.7, **base),
        "caption": ParagraphStyle("caption", fontSize=8.1, leading=12.4, spaceBefore=5, spaceAfter=9, textColor=MUTED, **{k: v for k, v in base.items() if k != "textColor"}),
    }


def table_widths(rows: list[list[str]]) -> list[float]:
    count = len(rows[0])
    if count == 2:
        first = rows[0][0]
        ratio = 0.27
        if first in {"项目", "层次或协议"}:
            ratio = 0.25
        if first == "检查项目":
            ratio = 0.22
        if first == "文件或目录":
            ratio = 0.38
        return [CONTENT_WIDTH * ratio, CONTENT_WIDTH * (1 - ratio)]
    return [CONTENT_WIDTH / count] * count


def report_table(rows, styles, widths=None):
    data = [[Paragraph(inline(str(cell)).replace("\n", "<br/>"),
             styles["headcell" if number == 0 else "cell"])
             for cell in row] for number, row in enumerate(rows)]
    table = Table(data, colWidths=widths or table_widths(rows), repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5EEF5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5.2),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, LINE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, LINE),
    ]))
    return table


def require_field(record, key, expected, location):
    if key not in record or type(record[key]) is not expected:
        raise ValueError(f"验证记录字段类型不正确：{location}.{key}")
    return record[key]


def check_utc(value, location):
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise ValueError(f"验证记录时间格式不正确：{location}") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"验证记录时间需要包含 UTC 时区：{location}")


def string_list(value, location):
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError(f"验证记录需要字符串列表：{location}")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"验证记录包含重复字段：{key}")
        result[key] = value
    return result


def load_validation(path):
    """校验本机记录，保留失败和缺失证据，不从演示资源补充截图。"""
    if not path.is_file():
        raise ValueError(f"验证记录不存在：{path}")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("验证记录超过 2 MiB，无法作为本报告的结构化记录读取。")
    record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    if type(record) is not dict:
        raise ValueError("验证记录的顶层需要为 JSON 对象。")
    for key in ("application_version", "recorded_at_utc", "platform", "system_version", "architecture", "proof_directory"):
        require_field(record, key, str, "record")
    check_utc(record["recorded_at_utc"], "record.recorded_at_utc")
    if record["platform"].lower() not in {"macos", "darwin"}:
        raise ValueError("本机验证记录的 platform 需要标明 macOS 或 Darwin。")
    require_field(record, "overall_passed", bool, "record")
    steps = require_field(record, "steps", list, "record")
    for index, step in enumerate(steps):
        if type(step) is not dict:
            raise ValueError(f"验证步骤需要为对象：steps[{index}]")
        require_field(step, "name", str, f"steps[{index}]")
        require_field(step, "exit_code", int, f"steps[{index}]")
    for key in ("error", "proof_read_error"):
        if key in record:
            require_field(record, key, str, "record")
    proof_directory = Path(record["proof_directory"])
    if not proof_directory.is_absolute():
        raise ValueError("proof_directory 需要使用绝对目录路径。")
    proof = record.get("live_gui_proof")
    if proof is not None:
        if type(proof) is not dict:
            raise ValueError("live_gui_proof 需要为对象，缺失时可省略该字段。")
        for key in ("application_version", "created_utc", "platform", "interface_name", "capture_mode", "data_source"):
            require_field(proof, key, str, "live_gui_proof")
        check_utc(proof["created_utc"], "live_gui_proof.created_utc")
        for key in ("passed", "promiscuous_requested", "ordinary_fallback"):
            require_field(proof, key, bool, "live_gui_proof")
        for key in ("packet_count", "effective_uid"):
            value = require_field(proof, key, int, "live_gui_proof")
            if value < 0:
                raise ValueError(f"验证记录需要非负整数：live_gui_proof.{key}")
        counts = require_field(proof, "protocol_counts", dict, "live_gui_proof")
        if any(type(key) is not str or type(value) is not int or value < 0 for key, value in counts.items()):
            raise ValueError("protocol_counts 需要使用协议名称及非负整数。")
        for key in ("api_results", "warnings", "failures"):
            string_list(require_field(proof, key, list, "live_gui_proof"), f"live_gui_proof.{key}")
        if "capture_activated" in proof:
            require_field(proof, "capture_activated", bool, "live_gui_proof")

    issues = []
    if record["application_version"] != APPLICATION_VERSION:
        issues.append(f"记录版本为 {record['application_version']}，本报告描述 {APPLICATION_VERSION}；此记录保留其原有版本范围。")
    if not steps:
        issues.append("验证步骤记录缺失。")
    elif any(step["exit_code"] != 0 for step in steps):
        issues.append("部分验证步骤返回失败状态。")
    for key in ("error", "proof_read_error"):
        if record.get(key):
            issues.append(record[key])
    if not proof:
        issues.append("实际图形界面证据缺失。")
    else:
        if proof["application_version"] != record["application_version"]:
            issues.append("图形界面记录版本与本次验证记录版本不一致。")
        if proof["data_source"] != "live-libpcap":
            issues.append("图形界面数据来源未确认为 live-libpcap。")
        if not proof["passed"]:
            issues.append("图形界面验证记录为未通过。")
        if proof["effective_uid"] == 0:
            issues.append("图形界面记录的有效用户编号为零，普通用户运行条件未得到确认。")
        if not any(name in proof["platform"].lower() for name in ("macos", "mac os", "darwin")):
            issues.append("图形界面的平台字段未标明 macOS。")
        if proof["packet_count"] == 0:
            issues.append("图形界面记录没有已捕获数据包。")
        if proof.get("capture_activated") is False:
            issues.append("实际捕获接口未成功激活。")
        issues.extend(proof["failures"])

    images = []
    for filename, title in (("main_window_live.png", "实际抓包主窗口"), ("tcp_stream_live.png", "实际 TCP 双向内容")):
        item = {"path": proof_directory / filename, "title": title, "usable": False}
        if proof is None:
            item["status"] = "缺少对应图形界面记录"
        elif proof["data_source"] != "live-libpcap":
            item["status"] = "数据来源未确认为实际捕获"
        elif not item["path"].is_file():
            item["status"] = "截图文件缺失"
            issues.append(f"截图文件缺失：{filename}。")
        else:
            try:
                width, height = ImageReader(str(item["path"])).getSize()
                if width <= 0 or height <= 0:
                    raise ValueError("图片尺寸无效")
                item["usable"] = True
                item["status"] = "实际验证目录中的图片可读取"
            except Exception as error:
                item["status"] = "图片无法读取"
                issues.append(f"图片无法读取：{filename}；{error}")
        images.append(item)
    if record["overall_passed"] and issues:
        issues.insert(0, "原始记录的总体结果为通过；材料核对仍存在以下状态，请结合证据范围阅读。")
    return {"record": record, "source": path.resolve(), "issues": list(dict.fromkeys(issues)), "images": images}


def validation_pages(validation, styles):
    record = validation["record"]
    proof = record.get("live_gui_proof")
    story = [PageBreak(), Paragraph("Mac 本机验证记录", styles["title"])]
    story.append(Paragraph("以下内容来自指定 JSON 记录，保留原始步骤状态及证据范围。记录版本、平台、数据来源和图片可用性在导入时核对。", styles["body"]))
    metadata = [
        ["记录项目", "内容"],
        ["来源文件", str(validation["source"])],
        ["应用版本", record["application_version"]],
        ["记录时间 UTC", record["recorded_at_utc"]],
        ["系统与架构", record["system_version"] + "\n" + record["architecture"]],
        ["总体结果（原始记录）", "通过" if record["overall_passed"] else "未通过"],
    ]
    story.extend([report_table(metadata, styles), Spacer(1, 8)])
    story.append(Paragraph("验证步骤", styles["h2"]))
    steps = [["检查步骤", "退出状态"]]
    steps.extend([[step["name"], "通过，退出状态 0" if step["exit_code"] == 0 else f"未通过，退出状态 {step['exit_code']}"] for step in record["steps"]])
    if len(steps) == 1:
        steps.append(["步骤记录", "缺失"])
    story.extend([report_table(steps, styles, [CONTENT_WIDTH * 0.55, CONTENT_WIDTH * 0.45]), Spacer(1, 8)])
    story.append(Paragraph("证据核对状态", styles["h2"]))
    if validation["issues"]:
        for issue in validation["issues"]:
            story.append(Paragraph(inline(issue), styles["body"]))
    else:
        story.append(Paragraph("现有记录字段、实际数据来源和两张截图相互对应。本文按导入记录所列环境及版本报告结果。", styles["body"]))
    image_rows = [["截图文件", "读取状态"]]
    image_rows.extend([[item["path"].name, item["status"]] for item in validation["images"]])
    story.extend([report_table(image_rows, styles, [CONTENT_WIDTH * 0.43, CONTENT_WIDTH * 0.57]), Spacer(1, 8)])

    if proof is not None:
        story.extend([PageBreak(), Paragraph("Mac 实际界面捕获记录", styles["title"])])
        rows = [
            ["记录项目", "实际记录"],
            ["界面验证状态", "通过" if proof["passed"] else "未通过"],
            ["记录时间 UTC", proof["created_utc"]],
            ["平台与应用版本", proof["platform"] + "；" + proof["application_version"]],
            ["数据来源与有效用户", proof["data_source"] + "；UID " + str(proof["effective_uid"])],
            ["接口与捕获模式", proof["interface_name"] + "；" + proof["capture_mode"]],
            ["混杂模式请求", "请求" if proof["promiscuous_requested"] else "普通模式请求"],
            ["普通模式回退", "发生回退" if proof["ordinary_fallback"] else "未发生回退"],
            ["已捕获数据包", str(proof["packet_count"])],
            ["协议计数", "；".join(f"{key}：{value}" for key, value in proof["protocol_counts"].items()) or "记录为空"],
        ]
        story.extend([report_table(rows, styles), Spacer(1, 8)])
        for key, title in (("api_results", "API 调用记录"), ("warnings", "警告记录"), ("failures", "失败记录")):
            story.append(Paragraph(title, styles["h2"]))
            values = proof[key]
            if values:
                for value in values:
                    story.append(Paragraph(inline(value), styles["body"]))
            else:
                story.append(Paragraph("记录列表为空。", styles["body"]))

    for item in validation["images"]:
        if not item["usable"]:
            continue
        story.extend([PageBreak(), Paragraph(item["title"], styles["title"])])
        status = "通过" if proof["passed"] else "未通过"
        caption = (f"用户导入的实际抓包过程记录。应用版本 {proof['application_version']}，"
                   f"接口 {proof['interface_name']}，GUI 验证状态：{status}。")
        story.append(Paragraph(inline(caption), styles["body"]))
        picture = Image(str(item["path"]))
        scale = min(CONTENT_WIDTH / picture.imageWidth, 585 / picture.imageHeight)
        picture.drawWidth = picture.imageWidth * scale
        picture.drawHeight = picture.imageHeight * scale
        picture.hAlign = "CENTER"
        story.extend([picture, Paragraph(inline(str(item["path"])), styles["caption"])])
    return story


def parse_markdown(source: Path, styles: dict[str, ParagraphStyle], font: str):
    lines = source.read_text(encoding="utf-8").splitlines()
    story = []
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line:
            index += 1
            continue
        if line == "<!-- pagebreak -->":
            story.append(PageBreak())
            index += 1
            continue
        if line.startswith("```"):
            code = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code.append(lines[index])
                index += 1
            if index == len(lines):
                raise ValueError("Markdown 代码区块缺少结束标记。")
            story.append(CodeBlock(code, font))
            index += 1
            continue
        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), styles["title"]))
            index += 1
            continue
        if line.startswith("## "):
            story.append(Paragraph(inline(line[3:]), styles["h2"]))
            index += 1
            continue
        picture = re.fullmatch(r"!\[([^\]]*)\]\(([^)]+)\)", line)
        if picture:
            image_path = source.parent / picture.group(2)
            if not image_path.is_file():
                raise FileNotFoundError(f"缺少报告图片：{image_path}")
            asset = Image(str(image_path))
            width = CONTENT_WIDTH
            asset.drawHeight = asset.imageHeight * width / asset.imageWidth
            asset.drawWidth = width
            asset.hAlign = "CENTER"
            story.append(KeepTogether([asset, Paragraph(inline(picture.group(1)), styles["caption"])]))
            index += 1
            continue
        if line.startswith("|"):
            rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                row = [cell.strip() for cell in lines[index].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", cell) for cell in row):
                    rows.append(row)
                index += 1
            story.extend([report_table(rows, styles), Spacer(1, 8)])
            continue
        paragraph = []
        while index < len(lines):
            current = lines[index].strip()
            if not current or current.startswith(("#", "```", "|", "![", "<!-- pagebreak -->")):
                break
            paragraph.append(inline(current))
            if lines[index].endswith("  "):
                paragraph.append("<br/>")
            index += 1
        story.append(Paragraph(" ".join(paragraph), styles["body"]))
    return story


def create_pdf(source: Path, destination: Path, font: str, validation=None):
    styles = make_styles(font)
    document = BaseDocTemplate(str(destination), pagesize=A4,
        leftMargin=MARGIN_X, rightMargin=MARGIN_X, topMargin=57, bottomMargin=43,
        title="实验 1A 网络嗅探器实现与验证报告", author="CourseSniffer",
        subject="本机操作、实现范围、测试证据与课程提交说明")

    def decorate(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BLUE)
        canvas.rect(MARGIN_X, PAGE_HEIGHT - 32, 27, 3, fill=1, stroke=0)
        canvas.setFont(font, 8.1)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN_X + 36, PAGE_HEIGHT - 33, "CourseSniffer  /  软件与系统安全")
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.45)
        canvas.line(MARGIN_X, 34, PAGE_WIDTH - MARGIN_X, 34)
        canvas.setFont(font, 7.8)
        canvas.drawString(MARGIN_X, 21, "实验 1A  ·  实现与验证报告")
        canvas.drawRightString(PAGE_WIDTH - MARGIN_X, 21, f"{doc.page:02d}")
        canvas.restoreState()

    frame = Frame(MARGIN_X, 43, CONTENT_WIDTH, PAGE_HEIGHT - 100,
                  leftPadding=0, bottomPadding=0, rightPadding=0, topPadding=0)
    document.addPageTemplates(PageTemplate(id="report", frames=[frame], onPage=decorate))
    story = parse_markdown(source, styles, font)
    if validation is not None:
        story.extend(validation_pages(validation, styles))
    document.build(story)


def main():
    parser = argparse.ArgumentParser(description="渲染 CourseSniffer 实现与验证报告")
    parser.add_argument("--source", type=Path, default=PROJECT / "docs/implementation_and_validation.md")
    parser.add_argument("--output", type=Path, default=PROJECT / "docs/implementation_and_validation.pdf")
    parser.add_argument("--font", help="中文 TTF 或 TTC 字体的绝对路径")
    parser.add_argument("--validation", type=Path, help="verify_macos.py 生成的实际验证 JSON 记录")
    args = parser.parse_args()
    if not args.source.is_file():
        parser.error(f"报告源文件不存在：{args.source}")
    validation = None
    if args.validation is not None:
        try:
            validation = load_validation(args.validation)
        except (OSError, ValueError) as error:
            parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    create_pdf(args.source.resolve(), args.output.resolve(), load_font(args.font), validation)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
