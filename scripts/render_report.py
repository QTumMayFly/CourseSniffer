#!/usr/bin/env python3
"""将可编辑 Markdown 报告渲染为 PDF。

依赖：ReportLab。
用法：python3 scripts/render_report.py --font /absolute/path/chinese_font.ttf
省略 --font 时查找常用中文字体，随后使用 STSong-Light。
"""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import re
import sys

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
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
        return [CONTENT_WIDTH * ratio, CONTENT_WIDTH * (1 - ratio)]
    return [CONTENT_WIDTH / count] * count


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
            widths = table_widths(rows)
            data = [[Paragraph(inline(cell), styles["headcell" if number == 0 else "cell"]) for cell in row] for number, row in enumerate(rows)]
            table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
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
            story.extend([table, Spacer(1, 8)])
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


def create_pdf(source: Path, destination: Path, font: str):
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
    document.build(parse_markdown(source, styles, font))


def main():
    parser = argparse.ArgumentParser(description="渲染 CourseSniffer 实现与验证报告")
    parser.add_argument("--source", type=Path, default=PROJECT / "docs/implementation_and_validation.md")
    parser.add_argument("--output", type=Path, default=PROJECT / "docs/implementation_and_validation.pdf")
    parser.add_argument("--font", help="中文 TTF 或 TTC 字体的绝对路径")
    args = parser.parse_args()
    if not args.source.is_file():
        parser.error(f"报告源文件不存在：{args.source}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    create_pdf(args.source.resolve(), args.output.resolve(), load_font(args.font))
    print(args.output.resolve())


if __name__ == "__main__":
    main()
