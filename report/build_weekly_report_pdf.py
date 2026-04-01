from __future__ import annotations

import argparse
import html
import re
from pathlib import Path

import yaml
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)


FONT_REGULAR = "MalgunGothic"
FONT_BOLD = "MalgunGothic-Bold"
FONT_DIR = Path(r"C:\Windows\Fonts")


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont(FONT_REGULAR, str(FONT_DIR / "malgun.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(FONT_DIR / "malgunbd.ttf")))


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(page_count)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count: int):
        self.setFont(FONT_REGULAR, 9)
        self.setFillColor(HexColor("#444444"))
        self.drawCentredString(A4[0] / 2, 11 * mm, f"{self._pageNumber} / {page_count}")


def parse_markdown(md_path: Path) -> tuple[dict, str]:
    text = md_path.read_text(encoding="utf-8")
    if text.startswith("---"):
        _, front_matter, body = text.split("---", 2)
        metadata = yaml.safe_load(front_matter) or {}
        return metadata, body.strip()
    return {}, text


def build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontName=FONT_BOLD,
            fontSize=19,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=6,
            textColor=HexColor("#111111"),
        ),
        "meta": ParagraphStyle(
            "Meta",
            parent=base["Normal"],
            fontName=FONT_REGULAR,
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            spaceAfter=12,
            textColor=HexColor("#333333"),
        ),
        "h1": ParagraphStyle(
            "Heading1",
            parent=base["Heading1"],
            fontName=FONT_BOLD,
            fontSize=14,
            leading=18,
            alignment=TA_LEFT,
            spaceBefore=4,
            spaceAfter=8,
            textColor=HexColor("#111111"),
        ),
        "h2": ParagraphStyle(
            "Heading2",
            parent=base["Heading2"],
            fontName=FONT_BOLD,
            fontSize=12,
            leading=16,
            spaceBefore=8,
            spaceAfter=6,
            textColor=HexColor("#111111"),
        ),
        "h3": ParagraphStyle(
            "Heading3",
            parent=base["Heading3"],
            fontName=FONT_BOLD,
            fontSize=11,
            leading=15,
            spaceBefore=6,
            spaceAfter=4,
            textColor=HexColor("#222222"),
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontName=FONT_REGULAR,
            fontSize=10.5,
            leading=16,
            spaceAfter=6,
            textColor=HexColor("#222222"),
        ),
        "list": ParagraphStyle(
            "List",
            parent=base["Normal"],
            fontName=FONT_REGULAR,
            fontSize=10.5,
            leading=15,
            leftIndent=0,
            textColor=HexColor("#222222"),
        ),
    }


def escape_text(text: str) -> str:
    return html.escape(text).replace("\n", "<br/>")


def collect_block(lines: list[str], start: int, pattern: re.Pattern[str]) -> tuple[list[str], int]:
    items = []
    i = start
    current = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            if current:
                items.append(" ".join(current).strip())
                current = []
            i += 1
            continue
        if re.match(r"^(#{1,3})\s+", stripped) or stripped == "<!--PAGEBREAK-->":
            break
        if pattern.match(stripped):
            if current:
                items.append(" ".join(current).strip())
            current = [pattern.sub("", stripped, count=1).strip()]
        else:
            if current:
                current.append(stripped)
            else:
                current = [stripped]
        i += 1

    if current:
        items.append(" ".join(current).strip())
    return items, i


def markdown_blocks(body: str):
    lines = body.splitlines()
    blocks = []
    paragraph = []
    i = 0

    def flush_paragraph():
        nonlocal paragraph
        if paragraph:
            blocks.append(("paragraph", " ".join(paragraph).strip()))
            paragraph = []

    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        if stripped == "<!--PAGEBREAK-->":
            flush_paragraph()
            blocks.append(("pagebreak", ""))
            i += 1
            continue

        if not stripped:
            flush_paragraph()
            i += 1
            continue

        heading = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if heading:
            flush_paragraph()
            blocks.append(("heading", len(heading.group(1)), heading.group(2).strip()))
            i += 1
            continue

        if re.match(r"^-\s+", stripped):
            flush_paragraph()
            items, i = collect_block(lines, i, re.compile(r"^-\s+"))
            blocks.append(("bullets", items))
            continue

        if re.match(r"^\d+[.)]\s+", stripped):
            flush_paragraph()
            items, i = collect_block(lines, i, re.compile(r"^\d+[.)]\s+"))
            blocks.append(("numbered", items))
            continue

        paragraph.append(stripped)
        i += 1

    flush_paragraph()
    return blocks


def list_flowable(items: list[str], style: ParagraphStyle, ordered: bool):
    flow_items = [
        ListItem(Paragraph(escape_text(item), style), leftIndent=10)
        for item in items
        if item
    ]
    return ListFlowable(
        flow_items,
        bulletType="1" if ordered else "bullet",
        start="1",
        leftIndent=14,
        bulletFontName=FONT_REGULAR,
        bulletFontSize=10.5,
    )


def build_story(metadata: dict, body: str):
    styles = build_styles()
    story = []

    title = metadata.get("title", "주간 미팅 보고서")
    project_name = metadata.get("project_name", "[프로젝트명]")
    date = metadata.get("date", "[작성일]")
    week_label = metadata.get("week_label", "[주차]")

    story.append(Paragraph(escape_text(title), styles["title"]))
    meta_line = f"프로젝트명: {project_name} | 작성일: {date} | {week_label}"
    story.append(Paragraph(escape_text(meta_line), styles["meta"]))

    for kind, *payload in markdown_blocks(body):
        if kind == "pagebreak":
            story.append(PageBreak())
            continue

        if kind == "heading":
            level, text = payload
            style_name = {1: "h1", 2: "h2", 3: "h3"}.get(level, "body")
            story.append(Paragraph(escape_text(text), styles[style_name]))
            continue

        if kind == "paragraph":
            story.append(Paragraph(escape_text(payload[0]), styles["body"]))
            continue

        if kind == "bullets":
            story.append(list_flowable(payload[0], styles["list"], ordered=False))
            story.append(Spacer(1, 3))
            continue

        if kind == "numbered":
            story.append(list_flowable(payload[0], styles["list"], ordered=True))
            story.append(Spacer(1, 3))

    return story


def render_pdf(md_path: Path, pdf_path: Path) -> None:
    register_fonts()
    metadata, body = parse_markdown(md_path)
    story = build_story(metadata, body)

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=metadata.get("title", "주간 미팅 보고서"),
        author="Codex",
    )
    doc.build(story, canvasmaker=NumberedCanvas)


def main():
    parser = argparse.ArgumentParser(description="Render weekly report markdown to PDF.")
    parser.add_argument(
        "--input",
        default=str(Path(__file__).with_name("weekly-report-template.md")),
        help="input markdown path",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).with_name("weekly-report-template.pdf")),
        help="output PDF path",
    )
    args = parser.parse_args()

    md_path = Path(args.input).resolve()
    pdf_path = Path(args.output).resolve()
    render_pdf(md_path, pdf_path)
    print(pdf_path)


if __name__ == "__main__":
    main()
