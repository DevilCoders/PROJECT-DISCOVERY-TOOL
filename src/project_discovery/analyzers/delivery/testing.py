"""Static test-suite discovery across polyglot repositories."""
from __future__ import annotations

import re
from pathlib import Path

from ...catalog.languages import is_source_path, source_extensions, source_language_names
from ...core.source_utils import read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_QUOTE = r"""['"\x60]"""
_STRING_CASE = lambda names: re.compile(
    r"(?m)\b(?:" + names + r")\s*\(\s*" + _QUOTE + r"([^'\"\x60]+)" + _QUOTE
)
_PATTERNS = {
    ".py": re.compile(r"(?m)^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)\s*\("),
    ".js": _STRING_CASE("it|test"),
    ".jsx": _STRING_CASE("it|test"),
    ".mjs": _STRING_CASE("it|test"),
    ".cjs": _STRING_CASE("it|test"),
    ".ts": _STRING_CASE("it|test"),
    ".tsx": _STRING_CASE("it|test"),
    ".rs": re.compile(r"(?m)#\s*\[\s*(?:tokio::)?test\s*\]"),
    ".go": re.compile(r"(?m)^\s*func\s+(Test[A-Za-z0-9_]+)\s*\("),
    ".java": re.compile(r"(?m)^\s*@(?:Test|ParameterizedTest|RepeatedTest|TestFactory)\b"),
    ".kt": re.compile(r"(?m)^\s*@(?:Test|ParameterizedTest)\b"),
    ".cs": re.compile(r"(?m)^\s*\[(?:Test|Fact|Theory|TestCase|TestMethod)\b"),
    ".fs": re.compile(r"(?m)^\s*\[<\s*(?:Fact|Theory|Test)\s*>\]"),
    ".vb": re.compile(r"(?im)^\s*<(?:Test|Fact|TestMethod)\s*>"),
    ".cpp": re.compile(r"(?m)\b(?:TEST(?:_F|_P)?|TEST_CASE)\s*\(\s*([A-Za-z0-9_]+)"),
    ".cc": re.compile(r"(?m)\b(?:TEST(?:_F|_P)?|TEST_CASE)\s*\(\s*([A-Za-z0-9_]+)"),
    ".cxx": re.compile(r"(?m)\b(?:TEST(?:_F|_P)?|TEST_CASE)\s*\(\s*([A-Za-z0-9_]+)"),
    ".c": re.compile(r"(?m)\b(?:START_TEST|TEST_CASE)\s*\(\s*([A-Za-z0-9_]+)"),
    ".php": re.compile(r"(?m)^\s*public\s+function\s+(test[A-Za-z0-9_]+)\s*\("),
    ".rb": _STRING_CASE("it|specify"),
    ".swift": re.compile(r"(?m)^\s*func\s+(test[A-Za-z0-9_]+)\s*\("),
    ".dart": _STRING_CASE("test|group"),
    ".exs": re.compile(r'(?m)\btest\s+["\']([^"\']+)["\']'),
    ".r": re.compile(r'(?m)\btest_that\s*\(\s*["\']([^"\']+)["\']'),
    ".jl": re.compile(r'(?m)@testset\s+["\']([^"\']+)["\']'),
    ".scala": _STRING_CASE("test|it"),
    ".clj": re.compile(r"(?m)\(deftest\s+([A-Za-z0-9_!?-]+)"),
    ".lua": _STRING_CASE("describe|it|test"),
    ".pl": re.compile(r"(?m)^\s*(?:ok|is|isnt|subtest)\s*\("),
    ".t": re.compile(r"(?m)^\s*(?:ok|is|isnt|subtest)\s*\("),
    ".bats": re.compile(r'(?m)^\s*@test\s+["\']([^"\']+)["\']'),
    ".ps1": re.compile(r'(?mi)^\s*(?:Describe|Context|It)\s+["\']([^"\']+)["\']'),
    ".sol": re.compile(r"(?m)^\s*function\s+(test[A-Za-z0-9_]*)\s*\("),
    ".nim": re.compile(r'(?mi)^\s*(?:test|suite)\s+["\']([^"\']+)["\']'),
    ".hs": re.compile(r'(?m)\b(?:describe|it)\s+["\']([^"\']+)["\']'),
    ".groovy": re.compile(r"(?m)^\s*def\s+(?:'([^']+)'|([A-Za-z0-9_]+))\s*\("),
    ".m": re.compile(r"(?m)^\s*-\s*\(void\)\s*(test[A-Za-z0-9_]+)"),
    ".f90": re.compile(r"(?im)^\s*subroutine\s+(test_[A-Za-z0-9_]+)"),
    ".v": re.compile(r"(?m)^\s*module\s+(tb_[A-Za-z0-9_]+)"),
    ".sv": re.compile(r"(?m)^\s*module\s+(tb_[A-Za-z0-9_]+)"),
    ".vhd": re.compile(r"(?im)^\s*entity\s+(tb_[A-Za-z0-9_]+)\s+is"),
    ".vhdl": re.compile(r"(?im)^\s*entity\s+(tb_[A-Za-z0-9_]+)\s+is"),
    ".zig": re.compile(r'(?m)\btest\s+["\']([^"\']+)["\']'),
}
_SUPPORTED_EXTENSIONS = set(_PATTERNS) | source_extensions() | {".bats"}
_TEST_DIRS = {"test", "tests", "testing", "__tests__", "spec", "specs"}
_TEST_FILENAMES = (
    re.compile(r"(^|/)(?:test_[^/]+|[^/]+_test)\.py$", re.I),
    re.compile(r"(^|/)(?:test_[^/]+|[^/]+_test)\.(?:go|rs|js|jsx|mjs|cjs|ts|tsx|java|kt|cs|cpp|cc|cxx|c)$", re.I),
    re.compile(r"(^|/)[^/]+\.(?:test|spec)\.(?:js|jsx|mjs|cjs|ts|tsx)$", re.I),
    re.compile(r"(^|/)[^/]+_spec\.rb$", re.I),
    re.compile(r"(^|/)[^/]+_tests?\.(?:java|kt|cs|fs|vb|swift|dart|exs|r|jl|scala|clj|lua|pl|ps1|sol|nim|hs|groovy|m|f90|cpp|cc|cxx)$", re.I),
    re.compile(r"(^|/)runtests\.jl$", re.I),
    re.compile(r"(^|/)test[^/]*\.bats$", re.I),
    re.compile(r"(^|/)Test[^/]*\.t\.sol$", re.I),
    re.compile(r"(^|/)[^/]+\.t$", re.I),
    re.compile(r"(^|/)Spec\.hs$", re.I),
    re.compile(r"(^|/)(?:test_[^/]+|[^/]+_(?:test|tests|spec))\.(?:dart|exs|r|jl|scala|clj|lua|ps1|sol|sv|bats)$", re.I),
    re.compile(r"(^|/)[^/]+Tests?\.(?:java|kt|cs|fs|vb|swift|dart|groovy|m|ps1)$", re.I),
    re.compile(r"(^|/)[^/]+(?:Spec|Suite)\.(?:scala|hs)$", re.I),
    re.compile(r"(^|/)[^/]+\.t\.sol$", re.I),
    re.compile(r"(^|/)tb_[^/]+\.(?:v|sv|vhd|vhdl)$", re.I),
    re.compile(r"(^|/)[^/]+\.bats$", re.I),
)


def is_test_path(path: str) -> bool:
    """Whether a project-relative path follows a test directory or file naming convention."""
    normalized = path.replace("\\", "/")
    parts = {part.lower() for part in Path(normalized).parts[:-1]}
    stem = Path(Path(normalized).name.lower()).stem
    generic_test_name = (
        stem.startswith(("test_", "test-"))
        or stem.endswith(("_test", "_tests", "_spec", "_specs", ".test", ".spec"))
    )
    return (
        bool(parts & _TEST_DIRS)
        or generic_test_name
        or any(pattern.search(normalized) for pattern in _TEST_FILENAMES)
    )


class TestDiscoveryAnalyzer(Analyzer):
    """Find test files and recognizable test declarations across language ecosystems."""

    name = "test-discovery"
    domains = ("tests",)
    languages = source_language_names() + ("Bats",)

    def supports(self, record: FileRecord) -> bool:
        if record.error or (record.extension not in _SUPPORTED_EXTENSIONS and not is_source_path(record.path)):
            return False
        return is_test_path(record.path)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        pattern = _PATTERNS.get(record.extension)
        if pattern is None:
            return [Finding(
                "testing",
                f"Test candidate: {record.path}",
                "The path follows a test-directory or naming convention; this format's "
                "test declarations are not extracted by the built-in patterns.",
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
            )]
        try:
            content = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
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
