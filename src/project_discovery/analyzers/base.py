"""Stable public analyzer plugin contract."""
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import FileRecord, Finding


class Analyzer(ABC):
    """Base class for local, read-only project analyzers.

    By default PDT runs third-party plugins in sandboxed host processes (see
    docs/PLUGIN_SDK.md): ``analyze`` receives a private copy of one file, and the plugin
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

    @abstractmethod
    def supports(self, record: FileRecord) -> bool:
        """Return whether this analyzer can inspect the inventoried record."""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        """Return evidence-backed findings without modifying the target file."""
        raise NotImplementedError
