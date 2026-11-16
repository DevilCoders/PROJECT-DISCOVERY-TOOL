"""Stable public analyzer plugin contract."""
from abc import ABC, abstractmethod
from pathlib import Path

from ..core.limits import AnalyzerLimits
from ..models import FileRecord, Finding


def oversize_finding(analyzer: "Analyzer", record: FileRecord, category: str, subject: str,
                     limit: int) -> Finding:
    """The UNKNOWN finding for a file past an analyzer's byte budget, which it did not analyze.

    Record the limit first (``core.limits.over_limit``), so the budget metrics count it too.
    """
    return Finding(
        category, f"{subject} resource limit: {record.path}",
        f"File size {record.size_bytes:,} bytes exceeds the {analyzer.name} analyzer's {limit:,}-byte "
        "content budget, so the file was not analyzed. This is not a clean result.",
        confidence="UNKNOWN", evidence=[record.path], analyzer=analyzer.name, severity="LOW",
    )


class Analyzer(ABC):
    """Base class for local, read-only project analyzers.

    By default PDT runs third-party plugins in sandboxed host processes (see
    docs/guides/PLUGIN_SDK.md): ``analyze`` receives a private copy of one file, and the plugin
    cannot write files, open network connections or start processes. Implementations
    must not mutate target files, execute target code, or perform network access during
    analysis. Analyzer instances may be called concurrently for different files.
    In-process plugins with shared mutable state must set ``concurrent_safe = False``.
    """

    api_version = 1
    name = "unnamed"
    version = "0.1.0"
    description = ""
    domains: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    concurrent_safe = True
    # The per-file content limits the analyzer applies: the most of a file it reads, how it
    # reads, and its other caps (core.limits.AnalyzerLimits). Reports list them with what
    # each call read and the limits it reached; every built-in analyzer declares them.
    limits: AnalyzerLimits | None = None

    @abstractmethod
    def supports(self, record: FileRecord) -> bool:
        """Return whether this analyzer can inspect the inventoried record."""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        """Return evidence-backed findings without modifying the target file."""
        raise NotImplementedError
