"""Offline dependency lockfile inventory."""
from __future__ import annotations

from pathlib import Path

from .base import Analyzer
from ..lockfiles import (
    LOCKFILE_ECOSYSTEMS,
    LOCKFILE_NAMES,
    MAX_LOCKFILE_BYTES,
    MAX_LOCKFILE_PACKAGE_ENTRIES,
    LockfileEntryBudgetExceeded,
    parse_lockfile,
)
from ..models import FileRecord, Finding
from ..source_utils import SourceBudgetExceeded, read_text_bounded, redact_source_excerpt

_MAX_LOCKFILE_INVENTORY_BYTES = MAX_LOCKFILE_BYTES
_MAX_LOCKFILE_PACKAGE_ENTRIES = MAX_LOCKFILE_PACKAGE_ENTRIES
_LOCK_NAMES = LOCKFILE_NAMES
_MAX_INVENTORY_EVIDENCE = 200


class LockfileAnalyzer(Analyzer):
    """Extract pinned/resolved package versions from common lockfile formats."""

    name = "dependency-lockfiles"
    domains = ("dependency_resolution", "supply_chain")
    languages = tuple(sorted(set(LOCKFILE_ECOSYSTEMS.values())))

    def supports(self, record: FileRecord) -> bool:
        return (
            record.error is None
            and record.content_skipped_reason is None
            and Path(record.path).name.lower() in _LOCK_NAMES
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > _MAX_LOCKFILE_INVENTORY_BYTES:
            return [Finding(
                "dependency",
                f"Lockfile inventory resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the lockfile inventory "
                f"{_MAX_LOCKFILE_INVENTORY_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            content = read_text_bounded(
                path, _MAX_LOCKFILE_INVENTORY_BYTES,
                expected_identity=record.analysis_identity,
            )
            packages = parse_lockfile(
                Path(record.path).name, content, max_entries=_MAX_LOCKFILE_PACKAGE_ENTRIES,
            )
        except (SourceBudgetExceeded, LockfileEntryBudgetExceeded) as exc:
            return [Finding(
                "dependency", f"Lockfile inventory resource limit: {record.path}",
                redact_source_excerpt(str(exc)), confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, ValueError, RecursionError, MemoryError) as exc:
            return [Finding(
                "dependency",
                f"Lockfile parse error: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]

        ecosystem = LOCKFILE_ECOSYSTEMS[Path(record.path).name.lower()]
        omitted = max(0, len(packages) - _MAX_INVENTORY_EVIDENCE)
        detail = (
            f"Extracted {len(packages)} package/version entries from a {ecosystem} lockfile. "
            "This records declared resolution state; it does not prove packages are installed "
            "or that the lockfile is current."
        )
        if omitted:
            detail += f" Evidence lists the first {_MAX_INVENTORY_EVIDENCE}; {omitted} more are omitted."
        return [Finding(
            "dependency",
            f"Resolved dependency inventory: {record.path}",
            detail,
            confidence="CONFIRMED",
            evidence=[
                f"{item.name}=={item.version}" for item in packages[:_MAX_INVENTORY_EVIDENCE]
            ] or [record.path],
            analyzer=self.name,
        )]
