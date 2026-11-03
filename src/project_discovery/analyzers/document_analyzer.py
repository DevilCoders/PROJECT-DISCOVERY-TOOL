"""Structural extraction for HTML, reStructuredText, text, PDF and DOCX files."""
from __future__ import annotations

import importlib
import re
from html.parser import HTMLParser
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.headings: list[str] = []
        self.links: list[str] = []
        self._capture: str | None = None
        self._capture_depth = 0
        self._skip_depth = 0
        self._current: list[str] = []
        self.text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = dict(attrs)
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        if tag == "title":
            self._capture = "title"
            self._capture_depth = 1
            self._current = []
        elif re.fullmatch(r"h[1-6]", tag):
            self._capture = "heading"
            self._capture_depth = 1
            self._current = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._capture == "title" and tag == "title":
            value = " ".join(" ".join(self._current).split())
            if value:
                self.title_parts.append(value)
            self._capture = None
        elif self._capture == "heading" and re.fullmatch(r"h[1-6]", tag):
            value = " ".join(" ".join(self._current).split())
            if value:
                self.headings.append(value)
            self._capture = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        clean = data.strip()
        if clean:
            self.text_parts.append(clean)
            if self._capture:
                self._current.append(clean)


def _word_count(text: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", text))


def _rst_headings(text: str) -> list[str]:
    lines = text.splitlines()
    headings: list[str] = []
    for index in range(1, len(lines)):
        title = lines[index - 1].strip()
        underline = lines[index].strip()
        if (
            title and len(underline) >= len(title)
            and len(set(underline)) == 1
            and underline[0] in "=-~^\"'#*+"
        ):
            headings.append(title)
    return headings


class DocumentAnalyzer(Analyzer):
    """Extract document structure and text metrics without asserting implementation."""

    name = "document-formats"
    _extensions = {".html", ".htm", ".rst", ".txt", ".adoc", ".asciidoc", ".tex", ".pdf", ".docx"}

    def supports(self, record: FileRecord) -> bool:
        return record.extension in self._extensions and record.error is None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        extension = record.extension
        try:
            if extension in {".html", ".htm"}:
                parser = _HTMLTextExtractor()
                parser.feed(path.read_text(encoding="utf-8"))
                parser.close()
                text = " ".join(parser.text_parts)
                title = parser.title_parts[0] if parser.title_parts else Path(record.path).stem
                details = (
                    f"HTML title: {title}; headings: {len(parser.headings)}; "
                    f"links: {len(parser.links)}; approximately {_word_count(text)} words."
                )
            elif extension == ".rst":
                content = path.read_text(encoding="utf-8")
                headings = _rst_headings(content)
                title = headings[0] if headings else Path(record.path).stem
                details = (
                    f"reStructuredText headings: {len(headings)}; "
                    f"approximately {_word_count(content)} words."
                )
            elif extension in {".txt", ".adoc", ".asciidoc", ".tex"}:
                content = path.read_text(encoding="utf-8")
                title = Path(record.path).stem
                details = (
                    f"Text document; lines: {len(content.splitlines())}; "
                    f"approximately {_word_count(content)} words."
                )
            elif extension == ".pdf":
                pypdf = importlib.import_module("pypdf")
                reader = pypdf.PdfReader(str(path), strict=False)
                page_text = [page.extract_text() or "" for page in reader.pages]
                content = "\n".join(page_text)
                metadata = reader.metadata
                title = str(metadata.title) if metadata and metadata.title else Path(record.path).stem
                details = (
                    f"PDF pages: {len(reader.pages)}; pages with extractable text: "
                    f"{sum(bool(value.strip()) for value in page_text)}; "
                    f"approximately {_word_count(content)} words."
                )
            else:
                docx = importlib.import_module("docx")
                document = docx.Document(str(path))
                paragraphs = [paragraph.text for paragraph in document.paragraphs if paragraph.text]
                table_cells = [
                    cell.text for table in document.tables
                    for row in table.rows for cell in row.cells
                ]
                content = "\n".join(paragraphs + table_cells)
                title = next(
                    (paragraph.text for paragraph in document.paragraphs
                     if paragraph.style and paragraph.style.name == "Title" and paragraph.text),
                    Path(record.path).stem,
                )
                details = (
                    f"DOCX paragraphs: {len(paragraphs)}; tables: {len(document.tables)}; "
                    f"approximately {_word_count(content)} words."
                )
        except ImportError as exc:
            optional = "pypdf" if extension == ".pdf" else "python-docx"
            return [Finding(
                "documentation",
                f"Optional document parser unavailable: {record.path}",
                f"Install the '{optional}' document extra to inspect this format. "
                "The file remains inventoried; no document contents were extracted.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]
        except Exception as exc:
            return [Finding(
                "documentation",
                f"Document parse error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        return [Finding(
            "documentation",
            f"Document: {title}",
            details + " Document content is descriptive evidence, not proof of implemented features.",
            confidence="CONFIRMED",
            evidence=[record.path],
            analyzer=self.name,
        )]
