"""Markdown structural analysis."""
import re
from pathlib import Path

from ...core.source_utils import SourceBudgetExceeded, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_MAX_MARKDOWN_BYTES = 32 * 1024 * 1024
# Linear forms: the closing "#" sequence is stripped in Python (a lazy title followed by
# \s*#*\s*$ was quadratic on long whitespace runs), and link text/targets stop at the
# next bracket so unclosed "[](" runs are scanned once instead of once per bracket.
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+)$")
LINK = re.compile(r"!?\[[^\]\[]*\]\(([^)\[\]]+)\)")


def _heading_title(raw: str) -> str:
    """Strip an ATX closing sequence, which must follow whitespace ("# C#" keeps its "#")."""
    title = raw.rstrip()
    without_closing = title.rstrip("#")
    if without_closing != title and (not without_closing or without_closing[-1].isspace()):
        title = without_closing.rstrip()
    return title

class MarkdownAnalyzer(Analyzer):
    name = "markdown"
    domains = ("documentation",)
    def supports(self, record: FileRecord) -> bool:
        return record.extension == ".md" and record.error is None
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > _MAX_MARKDOWN_BYTES:
            return [Finding(
                "documentation", f"Markdown resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the Markdown analyzer's "
                f"{_MAX_MARKDOWN_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            text = read_text_bounded(
                path, _MAX_MARKDOWN_BYTES, expected_identity=record.analysis_identity,
            )
        except SourceBudgetExceeded as exc:
            return [Finding(
                "documentation", f"Markdown resource limit: {record.path}", str(exc),
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "documentation", "Markdown read error", str(exc),
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
            )]
        headings = [
            _heading_title(m.group(2)) for line in text.splitlines() if (m := HEADING.match(line))
        ]
        links = LINK.findall(text)
        words = len(re.findall(r"\b[\w'-]+\b",text))
        title = next((heading for heading in headings if heading), Path(record.path).stem)
        return [Finding("documentation",f"Document: {title}",
            f"{len(headings)} headings; {len(links)} links; approximately {words} words.",
            evidence=[record.path],analyzer=self.name)]
