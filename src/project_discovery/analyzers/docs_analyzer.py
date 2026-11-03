"""Markdown structural analysis."""
import re
from pathlib import Path
from .base import Analyzer
from ..models import FileRecord, Finding
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
LINK = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")

class MarkdownAnalyzer(Analyzer):
    name = "markdown"
    def supports(self, record: FileRecord) -> bool:
        return record.extension == ".md" and record.error is None
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError,UnicodeDecodeError) as exc:
            return [Finding("documentation","Markdown read error",str(exc),evidence=[record.path],analyzer=self.name)]
        headings = [m.group(2) for line in text.splitlines() if (m := HEADING.match(line))]
        links = LINK.findall(text)
        words = len(re.findall(r"\b[\w'-]+\b",text))
        title = headings[0] if headings else Path(record.path).stem
        return [Finding("documentation",f"Document: {title}",
            f"{len(headings)} headings; {len(links)} links; approximately {words} words.",
            evidence=[record.path],analyzer=self.name)]
