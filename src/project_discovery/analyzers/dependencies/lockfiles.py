"""Offline dependency lockfile inventory."""
from __future__ import annotations

from pathlib import Path

from ...core.source_utils import SourceBudgetExceeded, describe_error, read_text_bounded, redact_source_excerpt
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer
from .lockfile_parsers import (
    LOCKFILE_ECOSYSTEMS,
    LOCKFILE_NAMES,
    MAX_LOCKFILE_BYTES,
    MAX_LOCKFILE_PACKAGE_ENTRIES,
    LockfileEntryBudgetExceeded,
    parse_lockfile,
)

_MAX_LOCKFILE_INVENTORY_BYTES = MAX_LOCKFILE_BYTES
_MAX_LOCKFILE_PACKAGE_ENTRIES = MAX_LOCKFILE_PACKAGE_ENTRIES
_LOCK_NAMES = LOCKFILE_NAMES
_MAX_INVENTORY_EVIDENCE = 200
# Resolved packages recorded per lockfile for `pdt compare` (code_index.dependencies); the
# finding's evidence keeps a readable sample only. Below the per-file fact ceiling.
MAX_RESOLVED_FACTS = 4_000


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
                describe_error(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]

        ecosystem = LOCKFILE_ECOSYSTEMS[Path(record.path).name.lower()]
        for item in packages[:MAX_RESOLVED_FACTS]:
            code_facts.emit_fact("resolved_package", item.name, version=item.version, ecosystem=ecosystem)
        if len(packages) > MAX_RESOLVED_FACTS:
            code_facts.emit_fact("resolved_packages_truncated", ecosystem, omitted=len(packages) - MAX_RESOLVED_FACTS)
        omitted = max(0, len(packages) - _MAX_INVENTORY_EVIDENCE)
        detail = (
            f"Extracted {len(packages)} package/version entries from a {ecosystem} lockfile. "
            "This records declared resolution state; it does not prove packages are installed "
            "or that the lockfile is current."
        )
        if omitted:
            detail += f" Evidence lists the first {_MAX_INVENTORY_EVIDENCE}; {omitted} more are omitted."
        findings = [Finding(
            "dependency",
            f"Resolved dependency inventory: {record.path}",
            detail,
            confidence="CONFIRMED",
            evidence=[
                f"{item.name}=={item.version}" for item in packages[:_MAX_INVENTORY_EVIDENCE]
            ] or [record.path],
            analyzer=self.name,
        )]
        local = getattr(packages, "local", [])
        if local:
            findings.append(Finding(
                "dependency",
                f"Local and workspace packages: {record.path}",
                f"{len(local)} entries are the project's own code (the root project, workspace "
                "members, path or linked packages). They are not registry releases, so they are "
                "neither looked up online nor matched against registry advisories.",
                confidence="CONFIRMED",
                evidence=[record.path, *local[:_MAX_INVENTORY_EVIDENCE]],
                analyzer=self.name,
            ))
        non_registry = getattr(packages, "non_registry", [])
        if non_registry:
            # Their specifiers (git URLs) can hold credentials: only names are listed.
            findings.append(Finding(
                "dependency",
                f"Dependencies outside a package registry: {record.path}",
                f"{len(non_registry)} third-party dependencies come from git or a URL instead of "
                "a registry release. They have no registry version, so they are not matched "
                "against vulnerability advisories.",
                confidence="UNKNOWN",
                evidence=[record.path, *non_registry[:_MAX_INVENTORY_EVIDENCE]],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
