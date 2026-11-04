"""Structural extraction for HTML, reStructuredText, text, PDF and DOCX files."""
from __future__ import annotations

import importlib
import io
import re
import zipfile
from html.parser import HTMLParser
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding
from ..source_utils import SourceBudgetExceeded, read_bytes_bounded, read_text_bounded


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


_MAX_TEXT_DOCUMENT_BYTES = 32 * 1024 * 1024
_MAX_BINARY_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_PDF_PAGES = 5000
_MAX_DOCUMENT_TEXT_CHARS = 16 * 1024 * 1024
_MAX_DOCX_ENTRIES = 10_000
_MAX_DOCX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024


class DocumentAnalyzer(Analyzer):
    """Extract document structure and text metrics without asserting implementation."""

    name = "document-formats"
    domains = ("documentation",)
    _extensions = {".html", ".htm", ".rst", ".txt", ".adoc", ".asciidoc", ".tex", ".pdf", ".docx"}

    def supports(self, record: FileRecord) -> bool:
        return record.extension in self._extensions and record.error is None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        extension = record.extension
        binary_document = extension in {".pdf", ".docx"}
        max_bytes = _MAX_BINARY_DOCUMENT_BYTES if binary_document else _MAX_TEXT_DOCUMENT_BYTES

        def budget_finding(detail: str) -> list[Finding]:
            return [Finding(
                "documentation",
                f"Document analysis resource limit: {record.path}",
                detail,
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]

        if record.size_bytes > max_bytes:
            return budget_finding(
                f"File size {record.size_bytes:,} bytes exceeds the document analyzer's "
                f"{max_bytes:,}-byte input budget."
            )

        try:
            if extension in {".html", ".htm"}:
                parser = _HTMLTextExtractor()
                parser.feed(read_text_bounded(
                    path, _MAX_TEXT_DOCUMENT_BYTES,
                    expected_identity=record.analysis_identity,
                ))
                parser.close()
                text = " ".join(parser.text_parts)
                title = parser.title_parts[0] if parser.title_parts else Path(record.path).stem
                details = (
                    f"HTML title: {title}; headings: {len(parser.headings)}; "
                    f"links: {len(parser.links)}; approximately {_word_count(text)} words."
                )
            elif extension == ".rst":
                content = read_text_bounded(
                    path, _MAX_TEXT_DOCUMENT_BYTES,
                    expected_identity=record.analysis_identity,
                )
                headings = _rst_headings(content)
                title = headings[0] if headings else Path(record.path).stem
                details = (
                    f"reStructuredText headings: {len(headings)}; "
                    f"approximately {_word_count(content)} words."
                )
            elif extension in {".txt", ".adoc", ".asciidoc", ".tex"}:
                content = read_text_bounded(
                    path, _MAX_TEXT_DOCUMENT_BYTES,
                    expected_identity=record.analysis_identity,
                )
                title = Path(record.path).stem
                details = (
                    f"Text document; lines: {len(content.splitlines())}; "
                    f"approximately {_word_count(content)} words."
                )
            elif extension == ".pdf":
                raw_document = read_bytes_bounded(
                    path, _MAX_BINARY_DOCUMENT_BYTES,
                    expected_identity=record.analysis_identity,
                )
                pypdf = importlib.import_module("pypdf")
                reader = pypdf.PdfReader(io.BytesIO(raw_document), strict=False)
                page_count = len(reader.pages)
                if page_count > _MAX_PDF_PAGES:
                    return budget_finding(
                        f"PDF contains {page_count:,} pages; the configured page budget is "
                        f"{_MAX_PDF_PAGES:,}. No page text was extracted."
                    )
                page_text: list[str] = []
                text_chars = 0
                for page in reader.pages:
                    value = page.extract_text() or ""
                    text_chars += len(value)
                    if text_chars > _MAX_DOCUMENT_TEXT_CHARS:
                        return budget_finding(
                            f"PDF extracted text exceeded {_MAX_DOCUMENT_TEXT_CHARS:,} characters. "
                            "Text extraction stopped and the document result is UNKNOWN."
                        )
                    page_text.append(value)
                content = "\n".join(page_text)
                metadata = reader.metadata
                title = str(metadata.title) if metadata and metadata.title else Path(record.path).stem
                details = (
                    f"PDF pages: {page_count}; pages with extractable text: "
                    f"{sum(bool(value.strip()) for value in page_text)}; "
                    f"approximately {_word_count(content)} words."
                )
            else:
                raw_document = read_bytes_bounded(
                    path, _MAX_BINARY_DOCUMENT_BYTES,
                    expected_identity=record.analysis_identity,
                )
                with zipfile.ZipFile(io.BytesIO(raw_document)) as package:
                    members = package.infolist()
                    if len(members) > _MAX_DOCX_ENTRIES:
                        return budget_finding(
                            f"DOCX package contains {len(members):,} entries; "
                            f"entry budget is {_MAX_DOCX_ENTRIES:,}."
                        )
                    uncompressed_bytes = sum(item.file_size for item in members)
                    if uncompressed_bytes > _MAX_DOCX_UNCOMPRESSED_BYTES:
                        return budget_finding(
                            f"DOCX package declares {uncompressed_bytes:,} uncompressed bytes; "
                            f"package budget is {_MAX_DOCX_UNCOMPRESSED_BYTES:,} bytes."
                        )
                    if any(
                        item.compress_size > 0 and
                        item.file_size / item.compress_size > 1000
                        for item in members
                    ):
                        return budget_finding(
                            "DOCX package contains a member with a compression ratio above "
                            "the 1000:1 document safety threshold."
                        )
                docx = importlib.import_module("docx")
                document = docx.Document(io.BytesIO(raw_document))
                paragraphs: list[str] = []
                table_cells: list[str] = []
                text_chars = 0
                title = Path(record.path).stem
                for paragraph in document.paragraphs:
                    if paragraph.text:
                        text_chars += len(paragraph.text)
                        if text_chars > _MAX_DOCUMENT_TEXT_CHARS:
                            return budget_finding(
                                f"DOCX extracted text exceeded {_MAX_DOCUMENT_TEXT_CHARS:,} "
                                "characters; extraction stopped."
                            )
                        paragraphs.append(paragraph.text)
                        if (
                            title == Path(record.path).stem
                            and paragraph.style
                            and paragraph.style.name == "Title"
                        ):
                            title = paragraph.text
                for table in document.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            if cell.text:
                                text_chars += len(cell.text)
                                if text_chars > _MAX_DOCUMENT_TEXT_CHARS:
                                    return budget_finding(
                                        f"DOCX extracted text exceeded {_MAX_DOCUMENT_TEXT_CHARS:,} "
                                        "characters; extraction stopped."
                                    )
                                table_cells.append(cell.text)
                content = "\n".join(paragraphs + table_cells)
                details = (
                    f"DOCX paragraphs: {len(paragraphs)}; tables: {len(document.tables)}; "
                    f"approximately {_word_count(content)} words."
                )
        except SourceBudgetExceeded as exc:
            return budget_finding(str(exc))
        except ImportError:
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
