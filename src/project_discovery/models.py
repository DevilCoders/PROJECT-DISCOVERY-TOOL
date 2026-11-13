"""Shared, serialization-friendly project inventory and finding models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Sequence

# Report schema: minor versions are additive, so any 1.x reader can load 1.y reports.
# 1.7 added the top-level "scan" summary (mode, source, network access, remote source and
# vulnerability sources) and the online advisory provenance under
# metrics.vulnerability_intelligence. 1.8 added uid, gid, attributes and security to every
# file, directory, symlink and special-entry record, and metrics.entry_attributes and
# metrics.security_metadata. 1.9 added mtime_ns and reparse_tag to directory, symlink and
# special-entry records (reparse_tag to file records), device_major and device_minor to
# special entries, and metrics.reparse_tags. 1.10 resolves every symlink against the
# inventory: target_state is resolved, broken, loop, external, unknown or unreadable, with
# resolved_path, resolved_type and target_detail, and metrics.symlink_states. 1.11 added
# metrics.inventory_aggregates (empty directories, fan-out, hard links, owners, groups and
# file timestamps). 1.12 added type_source, signature, type_detail, mime_type, name_type and
# type_mismatch to file records (file_type is the verified signature, text, binary/unknown or
# empty, from the name only when the content was not read), and metrics.type_sources,
# metrics.mime_types, metrics.type_mismatches and metrics.git_lfs_pointer_count. 1.13 added
# marker_category, marker_ecosystem, marker_confidence and marker_evidence to directory
# records (development_marker is the marker catalog's key), metrics.development_categories,
# metrics.development_confidence and metrics.pruned_by_profile. 1.14 added contents_recorded
# to directory records (false inside a --development-trees directory-only tree) and
# metrics.development_trees. 1.15 added metrics.analysis_budgets: the per-analyzer time and
# memory budgets, the per-domain overrides, what each analyzer used and the calls a budget stopped.
REPORT_SCHEMA_VERSION = "1.15"

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
    # POSIX owner and group IDs (None on Windows), the platform attribute names (Windows
    # FILE_ATTRIBUTE_* bits or macOS file flags) and, with --security-metadata, the owner,
    # group and DACL (Windows) or POSIX ACLs (Linux). The other records carry the same four.
    uid: int | None = None
    gid: int | None = None
    attributes: list[str] = field(default_factory=list)
    security: dict[str, Any] | None = None
    # The Windows reparse tag name of a reparse point that is not a link ("cloud", "dedup").
    reparse_tag: str | None = None
    # How file_type was determined: "signature" (the leading bytes match a catalogued
    # format), "content" (the sample is text, binary without a known signature, or empty) or
    # "name" (the content was not read, as in --inventory-only scans). signature is the
    # verified format (text formats such as scripts too), type_detail what its header says,
    # mime_type the content's MIME type, and name_type what the name suggests, kept apart;
    # type_mismatch is set when the name and the content disagree.
    type_source: str | None = None
    signature: str | None = None
    type_detail: str | None = None
    mime_type: str | None = None
    name_type: str | None = None
    type_mismatch: bool = False
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
    uid: int | None = None
    gid: int | None = None
    attributes: list[str] = field(default_factory=list)
    security: dict[str, Any] | None = None
    mtime_ns: int | None = None
    reparse_tag: str | None = None
    # A development, dependency, build or cache tree (inventory.markers): its category
    # (dependencies, build, cache, vcs, ide, ...), ecosystem, and how sure that is
    # (confirmed by marker_evidence, the entry found inside or beside it; name, a
    # distinctive name; possible, a common name nothing confirmed).
    marker_category: str | None = None
    marker_ecosystem: str | None = None
    marker_confidence: str | None = None
    marker_evidence: str | None = None
    # False inside a --development-trees directory-only tree: the directory's files, links
    # and special entries are counted in its totals but have no records of their own.
    contents_recorded: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SymlinkRecord:
    path: str
    target: str
    target_scope: str
    # resolved, broken, loop, external, unknown or unreadable: the target resolved against
    # the inventory (inventory.links), never the filesystem; "unverified" until it is.
    target_state: str = "unverified"
    is_hidden: bool = False
    permissions: int | None = None
    uid: int | None = None
    gid: int | None = None
    attributes: list[str] = field(default_factory=list)
    security: dict[str, Any] | None = None
    mtime_ns: int | None = None
    # Windows: "symlink", "mount_point" (a junction or volume mount point), "lx_symlink", ...
    reparse_tag: str | None = None
    # The root-relative path the chain reaches (resolved) or names (broken), the type of the
    # entry it reaches, and why it is broken, a loop, external or unknown.
    resolved_path: str | None = None
    resolved_type: str | None = None
    target_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SpecialEntryRecord:
    path: str
    entry_type: str
    is_hidden: bool = False
    permissions: int | None = None
    size_bytes: int = 0
    uid: int | None = None
    gid: int | None = None
    attributes: list[str] = field(default_factory=list)
    security: dict[str, Any] | None = None
    mtime_ns: int | None = None
    # Block and character devices: the device's major and minor numbers (POSIX).
    device_major: int | None = None
    device_minor: int | None = None
    # Windows: "af_unix", "lx_fifo", "lx_chr" or "lx_blk" for the reparse points recorded here.
    reparse_tag: str | None = None

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
