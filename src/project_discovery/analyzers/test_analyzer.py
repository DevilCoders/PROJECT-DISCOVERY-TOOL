"""Static test-suite discovery across common language ecosystems."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


_QUOTE = r"""['"\x60]"""
_PATTERNS = {
    ".py": re.compile(r"(?m)^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)\s*\("),
    ".js": re.compile(r"(?m)\b(?:it|test)\s*\(\s*" + _QUOTE + r"([^'\"\x60]+)" + _QUOTE),
    ".jsx": re.compile(r"(?m)\b(?:it|test)\s*\(\s*" + _QUOTE + r"([^'\"\x60]+)" + _QUOTE),
    ".ts": re.compile(r"(?m)\b(?:it|test)\s*\(\s*" + _QUOTE + r"([^'\"\x60]+)" + _QUOTE),
    ".tsx": re.compile(r"(?m)\b(?:it|test)\s*\(\s*" + _QUOTE + r"([^'\"\x60]+)" + _QUOTE),
    ".rs": re.compile(r"(?m)#\s*\[\s*(?:tokio::)?test\s*\]"),
    ".go": re.compile(r"(?m)^\s*func\s+(Test[A-Za-z0-9_]+)\s*\("),
    ".java": re.compile(r"(?m)^\s*@(?:Test|ParameterizedTest|RepeatedTest)\b"),
    ".kt": re.compile(r"(?m)^\s*@(?:Test|ParameterizedTest)\b"),
    ".cs": re.compile(r"(?m)^\s*\[(?:Test|Fact|Theory|TestCase)\b"),
    ".cpp": re.compile(r"(?m)\bTEST(?:_F|_P)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)"),
    ".cc": re.compile(r"(?m)\bTEST(?:_F|_P)?\s*\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)"),
    ".php": re.compile(r"(?m)^\s*public\s+function\s+(test[A-Za-z0-9_]+)\s*\("),
    ".rb": re.compile(r"(?m)\b(?:it|specify)\s*\(?\s*" + _QUOTE + r"([^'\"\x60]+)" + _QUOTE),
    ".swift": re.compile(r"(?m)^\s*func\s+test[A-Za-z0-9_]+\s*\("),
}
_TEST_FILENAMES = (
    re.compile(r"(^|/)test_[^/]+\.py$", re.I),
    re.compile(r"(^|/)[^/]+_test\.(?:go|rs|js|jsx|ts|tsx|java|kt|cs|cpp|cc)$", re.I),
    re.compile(r"(^|/)[^/]+\.(?:test|spec)\.(?:js|jsx|ts|tsx)$", re.I),
    re.compile(r"(^|/)[^/]+_spec\.rb$", re.I),
)


class TestDiscoveryAnalyzer(Analyzer):
    """Find test files and statically recognizable test declarations."""

    name = "test-discovery"

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and any(
            pattern.search(record.path) for pattern in _TEST_FILENAMES
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        pattern = _PATTERNS.get(record.extension)
        if pattern is None:
            return [Finding(
                "testing",
                f"Test candidate: {record.path}",
                "The path follows a common test-file naming convention; this language's "
                "test declarations are not yet extracted by the built-in patterns.",
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
            )]
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "testing",
                f"Test file read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]
        matches = list(pattern.finditer(content))
        if not matches:
            return [Finding(
                "testing",
                f"Test candidate without recognized cases: {record.path}",
                "File naming suggests a test file, but no supported test declaration pattern was found.",
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
            )]
        evidence = [
            f"{record.path}:{content.count(chr(10), 0, match.start()) + 1}"
            for match in matches[:100]
        ]
        names = [
            " ".join(group for group in match.groups() if group)
            for match in matches[:30]
        ]
        return [Finding(
            "testing",
            f"Test suite: {record.path}",
            f"Detected {len(matches)} test declarations. Sample names: "
            + (", ".join(names) if names else "annotation/attribute-based test cases")
            + ("; remaining names omitted." if len(matches) > 30 else "."),
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer=self.name,
        )]
