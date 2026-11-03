"""Shared, serialization-friendly project inventory and finding models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Confidence = Literal["CONFIRMED", "INFERRED", "UNKNOWN"]
Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(slots=True)
class CodeEvidence:
    """One redacted source line associated with a finding."""

    line_number: int
    code: str
    vulnerable: bool = True

    def __post_init__(self) -> None:
        # Enforce redaction at the model boundary so custom analyzers cannot
        # accidentally serialize secrets or direct identifiers in report excerpts.
        from .source_utils import redact_source_excerpt
        self.code = redact_source_excerpt(self.code)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    detail: str
    confidence: Confidence = "CONFIRMED"
    evidence: list[str] = field(default_factory=list)
    analyzer: str = "core"
    severity: Severity = "INFO"
    code_evidence: list[CodeEvidence] = field(default_factory=list)
    impact: str | None = None
    recommendation: str | None = None

    def __post_init__(self) -> None:
        if self.severity == "INFO" and self.category in {
            "security", "supply_chain", "migration", "privacy",
        }:
            self.severity = "MEDIUM"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FileRecord:
    path: str
    size_bytes: int
    extension: str
    language: str
    sha256: str | None = None
    analyzed: bool = False
    error: str | None = None
    file_type: str = "unknown"
    size_bucket: str = "unknown"
    is_hidden: bool = False
    permissions: int | None = None
    mtime_ns: int | None = None
    content_skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DirectoryRecord:
    path: str
    depth: int
    direct_child_count: int = 0
    file_count: int = 0
    total_bytes: int = 0
    is_hidden: bool = False
    permissions: int | None = None
    development_marker: str | None = None
    pruned: bool = False
    prune_reason: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SymlinkRecord:
    path: str
    target: str
    target_scope: str
    target_state: str = "unverified"
    is_hidden: bool = False
    permissions: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SpecialEntryRecord:
    path: str
    entry_type: str
    is_hidden: bool = False
    permissions: int | None = None
    size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    root: str
    started_at: str
    finished_at: str
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    analyzer_names: list[str] = field(default_factory=list)
    directories: list[DirectoryRecord] = field(default_factory=list)
    symlinks: list[SymlinkRecord] = field(default_factory=list)
    special_entries: list[SpecialEntryRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.3",
            "root": self.root,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "files": [item.to_dict() for item in self.files],
            "directories": [item.to_dict() for item in self.directories],
            "symlinks": [item.to_dict() for item in self.symlinks],
            "special_entries": [item.to_dict() for item in self.special_entries],
            "findings": [item.to_dict() for item in self.findings],
            "metrics": self.metrics,
            "errors": self.errors,
            "analyzers": self.analyzer_names,
        }
