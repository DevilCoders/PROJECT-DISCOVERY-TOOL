"""Metadata-only archive inspection. Archive members are never extracted."""
from __future__ import annotations

import re
import stat
import tarfile
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from .base import Analyzer
from ..models import FileRecord, Finding


_ARCHIVE_EXTENSIONS = {
    ".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".whl", ".egg",
    ".nupkg", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar",
    ".cab", ".iso", ".deb", ".rpm",
}
_MAX_ARCHIVE_ENTRIES = 200_000
_MAX_EVIDENCE = 100
_PATH_DRIVE = re.compile(r"^[A-Za-z]:")


def _unsafe_member_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        normalized.startswith("/")
        or _PATH_DRIVE.match(normalized) is not None
        or ".." in path.parts
    )


def _mode_risks(mode: int) -> list[str]:
    risks = []
    if mode & stat.S_ISUID:
        risks.append("setuid")
    if mode & stat.S_ISGID:
        risks.append("setgid")
    if mode & stat.S_IWOTH:
        risks.append("world-writable")
    return risks


class ArchiveIntelligenceAnalyzer(Analyzer):
    """Inspect archive indexes and metadata under entry-count and evidence limits."""

    name = "archive-intelligence"
    domains = ("archives", "filesystem_inventory", "supply_chain")
    languages = ("ZIP", "TAR", "GZIP", "BZIP2", "XZ", "7z", "RAR", "CAB", "ISO")

    def supports(self, record: FileRecord) -> bool:
        return (
            record.error is None
            and record.content_skipped_reason is None
            and (
                record.file_type.startswith("archive/")
                or record.extension in _ARCHIVE_EXTENSIONS
            )
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if zipfile.is_zipfile(path):
            return self._zip(path, record)
        try:
            if tarfile.is_tarfile(path):
                return self._tar(path, record)
        except (OSError, tarfile.TarError):
            pass
        return [Finding(
            "archive",
            f"Archive/container detected: {record.path}",
            f"Recognized as {record.file_type} or by archive extension. This format does not "
            "have a built-in metadata index reader in this installation; no extraction or "
            "decompression was attempted.",
            confidence="CONFIRMED",
            evidence=[record.path, f"{record.size_bytes} bytes"],
            analyzer=self.name,
        )]

    def _zip(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            with zipfile.ZipFile(path, "r") as archive:
                infos = archive.infolist()
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
            return [Finding(
                "archive",
                f"ZIP metadata read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        total = len(infos)
        counts: Counter[str] = Counter()
        unsafe_paths: list[str] = []
        symlinks: list[str] = []
        encrypted = 0
        risky_modes: list[str] = []
        high_ratios: list[str] = []
        duplicates = [name for name, count in Counter(item.filename for item in infos).items() if count > 1]
        for info in infos[:_MAX_ARCHIVE_ENTRIES]:
            mode = (info.external_attr >> 16) & 0xFFFF
            if info.is_dir():
                kind = "directory"
            elif stat.S_ISLNK(mode):
                kind = "symlink"
                symlinks.append(info.filename)
            else:
                kind = "file"
            counts[kind] += 1
            if _unsafe_member_path(info.filename):
                unsafe_paths.append(info.filename)
            if info.flag_bits & 0x1:
                encrypted += 1
            for risk in _mode_risks(mode):
                risky_modes.append(f"{info.filename} ({risk})")
            if info.file_size > 0 and (
                info.compress_size == 0 or info.file_size / max(info.compress_size, 1) > 1000
            ):
                high_ratios.append(info.filename)

        evidence = [
            f"{counts['file']} regular file(s)",
            f"{counts['directory']} directory entry(ies)",
            f"{counts['symlink']} symlink entry(ies)",
            f"{encrypted} encrypted entry(ies)",
            f"{len(duplicates)} duplicate member name(s)",
        ]
        findings = [Finding(
            "archive",
            f"ZIP archive inventory: {record.path}",
            f"Indexed {min(total, _MAX_ARCHIVE_ENTRIES)} of {total} member(s); "
            f"compressed file size {record.size_bytes:,} bytes. Member payloads were not "
            "opened or extracted.",
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer=self.name,
        )]
        if total > _MAX_ARCHIVE_ENTRIES:
            findings.append(Finding(
                "archive",
                f"ZIP entry limit reached: {record.path}",
                f"Archive contains {total} entries; metadata analysis was limited to "
                f"{_MAX_ARCHIVE_ENTRIES}.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        findings.extend(self._risk_findings(
            record, unsafe_paths, symlinks, risky_modes, high_ratios, duplicates, encrypted
        ))
        return findings

    def _tar(self, path: Path, record: FileRecord) -> list[Finding]:
        counts: Counter[str] = Counter()
        unsafe_paths: list[str] = []
        symlinks: list[str] = []
        hardlinks: list[str] = []
        risky_modes: list[str] = []
        special_entries: list[str] = []
        total = 0
        try:
            with tarfile.open(path, mode="r:*") as archive:
                for member in archive:
                    total += 1
                    if total > _MAX_ARCHIVE_ENTRIES:
                        break
                    if member.isdir():
                        kind = "directory"
                    elif member.issym():
                        kind = "symlink"
                        symlinks.append(member.name)
                    elif member.islnk():
                        kind = "hardlink"
                        hardlinks.append(member.name)
                    elif member.isreg():
                        kind = "file"
                    else:
                        kind = "special"
                        special_entries.append(member.name)
                    counts[kind] += 1
                    if _unsafe_member_path(member.name) or (
                        member.issym() and _unsafe_member_path(member.linkname)
                    ) or (
                        member.islnk() and _unsafe_member_path(member.linkname)
                    ):
                        unsafe_paths.append(member.name)
                    for risk in _mode_risks(member.mode):
                        risky_modes.append(f"{member.name} ({risk})")
        except (OSError, tarfile.TarError, EOFError) as exc:
            return [Finding(
                "archive",
                f"TAR metadata read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        findings = [Finding(
            "archive",
            f"TAR archive inventory: {record.path}",
            f"Indexed {total} member(s); {counts['file']} regular file(s), "
            f"{counts['directory']} directory(ies), {counts['symlink']} symlink(s), "
            f"{counts['hardlink']} hardlink(s), {counts['special']} special entry(ies). "
            "Member payloads were not extracted.",
            confidence="CONFIRMED",
            evidence=[record.path],
            analyzer=self.name,
        )]
        if total > _MAX_ARCHIVE_ENTRIES:
            findings.append(Finding(
                "archive",
                f"TAR entry limit reached: {record.path}",
                f"Metadata traversal stopped after {_MAX_ARCHIVE_ENTRIES} members.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        findings.extend(self._risk_findings(
            record, unsafe_paths, symlinks, risky_modes, [], [], 0
        ))
        if hardlinks:
            findings.append(Finding(
                "archive",
                f"Archive hardlink entries: {record.path}",
                f"Detected {len(hardlinks)} hardlink member(s). Link targets were not followed.",
                confidence="CONFIRMED",
                evidence=[f"{record.path}::{name}" for name in hardlinks[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        if special_entries:
            findings.append(Finding(
                "security",
                f"Special filesystem entries inside archive: {record.path}",
                f"Detected {len(special_entries)} device/FIFO/socket-like member(s).",
                confidence="CONFIRMED",
                evidence=[f"{record.path}::{name}" for name in special_entries[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="HIGH",
            ))
        return findings

    def _risk_findings(
        self,
        record: FileRecord,
        unsafe_paths: list[str],
        symlinks: list[str],
        risky_modes: list[str],
        high_ratios: list[str],
        duplicates: list[str],
        encrypted: int,
    ) -> list[Finding]:
        findings = []
        if unsafe_paths:
            findings.append(Finding(
                "security",
                f"Archive path traversal indicators: {record.path}",
                f"Detected {len(unsafe_paths)} absolute, drive-prefixed or parent-traversal "
                "member path/link target(s). Entries were not extracted.",
                confidence="CONFIRMED",
                evidence=[f"{record.path}::{name}" for name in unsafe_paths[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="CRITICAL",
            ))
        if symlinks:
            findings.append(Finding(
                "archive",
                f"Archive symlink entries: {record.path}",
                f"Detected {len(symlinks)} symbolic link member(s). Link targets were not followed.",
                confidence="CONFIRMED",
                evidence=[f"{record.path}::{name}" for name in symlinks[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        if risky_modes:
            findings.append(Finding(
                "security",
                f"Risky archive permissions: {record.path}",
                f"Detected {len(risky_modes)} member(s) with setuid, setgid or world-writable mode bits.",
                confidence="INFERRED",
                evidence=[f"{record.path}::{name}" for name in risky_modes[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="HIGH",
            ))
        if high_ratios:
            findings.append(Finding(
                "security",
                f"High compression-ratio archive entries: {record.path}",
                f"Detected {len(high_ratios)} member(s) with compression ratio above 1000:1 "
                "or a zero compressed size. Review for archive-bomb risk; contents were not decompressed.",
                confidence="INFERRED",
                evidence=[f"{record.path}::{name}" for name in high_ratios[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="HIGH",
            ))
        if duplicates:
            findings.append(Finding(
                "archive",
                f"Duplicate archive member names: {record.path}",
                f"Detected {len(duplicates)} duplicated member path(s), which may be interpreted "
                "differently by extraction tools.",
                confidence="INFERRED",
                evidence=[f"{record.path}::{name}" for name in duplicates[:_MAX_EVIDENCE]],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        if encrypted:
            findings.append(Finding(
                "archive",
                f"Encrypted archive entries: {record.path}",
                f"Detected {encrypted} encrypted member(s); content inspection is unavailable.",
                confidence="CONFIRMED",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
