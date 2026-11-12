"""Shared, serialization-friendly project inventory and finding models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Sequence

# Report schema: minor versions are additive, so any 1.x reader can load 1.y reports.
# 1.7 added the top-level "scan" summary (mode, source, network access, remote source and
# vulnerability sources) and the online advisory provenance under
# metrics.vulnerability_intelligence.
REPORT_SCHEMA_VERSION = "1.7"

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
        # accidentally serialize secrets or direct identifiers in report excerpts, and so
        # escape sequences in scanned code never reach a terminal or report.
        from .core.source_utils import neutralize_controls, redact_source_excerpt
        self.code = neutralize_controls(redact_source_excerpt(self.code))

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
        # Titles and evidence carry scanned text (file names, values, source fragments):
        # terminal control characters in them are neutralized for every output surface.
        from .core.source_utils import neutralize_controls

        self.title = neutralize_controls(self.title)
        self.detail = neutralize_controls(self.detail)
        self.evidence = [neutralize_controls(item) for item in self.evidence]
        if self.impact is not None:
            self.impact = neutralize_controls(self.impact)
        if self.recommendation is not None:
            self.recommendation = neutralize_controls(self.recommendation)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        """Restore a finding from its JSON-compatible persisted representation."""
        data = dict(value)
        data["code_evidence"] = [
            item if isinstance(item, CodeEvidence) else CodeEvidence(**item)
            for item in data.get("code_evidence", [])
        ]
        return cls(**data)


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
    # Private scan-time identity used to pin analyzer reads. It is excluded from
    # public reports but retained by the private SQLite inventory store.
    analysis_identity: tuple[int | None, int | None, int | None, int | None, int | None] | None = field(
        default=None, repr=False, compare=False,
    )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("analysis_identity", None)
        return value

    def to_storage_dict(self) -> dict[str, Any]:
        """Serialize internal metadata for the private inventory database."""
        value = self.to_dict()
        if self.analysis_identity is not None:
            value["analysis_identity"] = list(self.analysis_identity)
        return value

    @classmethod
    def from_storage_dict(cls, value: dict[str, Any]) -> "FileRecord":
        """Reconstruct a file record persisted by InventoryStore."""
        data = dict(value)
        identity = data.get("analysis_identity")
        if identity is not None:
            if (
                not isinstance(identity, (list, tuple))
                or len(identity) != 5
                or any(
                    item is not None and (
                        isinstance(item, bool) or not isinstance(item, int)
                    )
                    for item in identity
                )
            ):
                raise ValueError("stored analysis_identity must contain five integers or nulls")
            data["analysis_identity"] = tuple(identity)
        return cls(**data)


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
    files: Sequence[FileRecord] = field(default_factory=list)
    findings: Sequence[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    errors: Sequence[str] = field(default_factory=list)
    analyzer_names: list[str] = field(default_factory=list)
    directories: Sequence[DirectoryRecord] = field(default_factory=list)
    symlinks: Sequence[SymlinkRecord] = field(default_factory=list)
    special_entries: Sequence[SpecialEntryRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from .reporting.writers import scan_summary  # the writers import this module

        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            # Schema 1.7 added this block; the serializer now writes what it stamps.
            "scan": scan_summary(self.metrics),
            "root": self.root,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "files": [item.to_dict() for item in self.files],
            "directories": [item.to_dict() for item in self.directories],
            "symlinks": [item.to_dict() for item in self.symlinks],
            "special_entries": [item.to_dict() for item in self.special_entries],
            "findings": [item.to_dict() for item in self.findings],
            "metrics": self.metrics,
            "errors": list(self.errors),
            "analyzers": self.analyzer_names,
        }
