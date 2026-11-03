"""Metadata-only archive inspection. Archive members are never extracted."""
from __future__ import annotations

import re
import stat
import struct
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
_MAX_ARCHIVE_INDEX_BYTES = 64 * 1024 * 1024


def _zip_index_hint(path: Path) -> tuple[int, int] | None:
    """Read ZIP/ZIP64 central-directory size/count without materializing entries."""
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            tail_size = min(size, 65_557)
            stream.seek(size - tail_size)
            tail = stream.read(tail_size)
            eocd = tail.rfind(b"PK\x05\x06")
            if eocd < 0 or eocd + 22 > len(tail):
                return None
            entry_count = struct.unpack_from("<H", tail, eocd + 10)[0]
            directory_size = struct.unpack_from("<I", tail, eocd + 12)[0]
            if entry_count == 0xFFFF or directory_size == 0xFFFFFFFF:
                locator = eocd - 20
                if locator < 0 or tail[locator:locator + 4] != b"PK\x06\x07":
                    return None
                zip64_offset = struct.unpack_from("<Q", tail, locator + 8)[0]
                stream.seek(zip64_offset)
                zip64 = stream.read(56)
                if len(zip64) < 56 or zip64[:4] != b"PK\x06\x06":
                    return None
                entry_count = struct.unpack_from("<Q", zip64, 32)[0]
                directory_size = struct.unpack_from("<Q", zip64, 40)[0]
            return int(entry_count), int(directory_size)
    except (OSError, ValueError, struct.error):
        return None


_MAX_MEMBER_SCAN_BYTES = 1024 * 1024
_MAX_ARCHIVE_SCAN_BYTES = 32 * 1024 * 1024
_MEMBER_SCAN_CHUNK = 64 * 1024
_CONTENT_RULES = (
    (
        "credential-like assignment",
        re.compile(
            r"""(?im)\b(?:password|passwd|passphrase|api[_-]?key|client[_-]?secret|"""
            r"""access[_-]?token|refresh[_-]?token|secret)\b\s*["']?\s*[:=]\s*["']?"""
            r"""[^\s,"']{4,}"""
        ),
        "secrets",
    ),
    (
        "private-key marker",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "secrets",
    ),
    (
        "cloud access-key identifier",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "secrets",
    ),
    (
        "email-shaped value",
        re.compile(
            r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
            r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b"
        ),
        "privacy",
    ),
)


def _read_member_sample(stream, budget_remaining: int) -> tuple[bytes, int, bool]:
    """Read a bounded in-memory sample from a member stream; never write it to disk."""
    limit = min(_MAX_MEMBER_SCAN_BYTES, max(0, budget_remaining))
    if limit <= 0:
        return b"", 0, True
    sample = bytearray()
    while len(sample) <= limit:
        chunk = stream.read(min(_MEMBER_SCAN_CHUNK, limit + 1 - len(sample)))
        if not chunk:
            break
        sample.extend(chunk)
    truncated = len(sample) > limit
    if truncated:
        del sample[limit:]
    return bytes(sample), len(sample), truncated


def _member_content_findings(
    archive_path: str, member_name: str, sample: bytes,
) -> list[Finding]:
    """Return path/line-only indicators; matched values are deliberately discarded."""
    if not sample:
        return []
    text = sample.decode("utf-8", errors="replace")
    hits: dict[tuple[str, str], set[int]] = {}
    for label, pattern, category in _CONTENT_RULES:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.setdefault((category, label), set()).add(line)
    findings: list[Finding] = []
    for (category, label), lines in sorted(hits.items()):
        findings.append(Finding(
            category,
            f"{label.title()} inside archive member: {archive_path}",
            f"Detected {len(lines)} line(s) with {label} in an archive member. "
            "Matched values are not retained. This bounded scan is not a complete DLP or malware scan.",
            confidence="INFERRED",
            evidence=[
                f"{archive_path}::{member_name}:{line} ({label}; value redacted)"
                for line in sorted(lines)[:_MAX_EVIDENCE]
            ],
            analyzer="archive-intelligence",
            severity="HIGH" if category == "secrets" else "MEDIUM",
        ))
    return findings
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
        index_hint = _zip_index_hint(path)
        if index_hint is not None:
            entry_count, index_bytes = index_hint
            if entry_count > _MAX_ARCHIVE_ENTRIES or index_bytes > _MAX_ARCHIVE_INDEX_BYTES:
                return [Finding(
                    "archive",
                    f"ZIP central-directory budget exceeded: {record.path}",
                    "The archive index was not materialized because its declared entry count "
                    "or central-directory byte size exceeds the configured safety budget. "
                    "No members were extracted or decompressed.",
                    confidence="UNKNOWN",
                    evidence=[
                        f"declared entries: {entry_count:,}",
                        f"central-directory bytes: {index_bytes:,}",
                        f"entry limit: {_MAX_ARCHIVE_ENTRIES:,}",
                        f"index-byte limit: {_MAX_ARCHIVE_INDEX_BYTES:,}",
                    ],
                    analyzer=self.name,
                    severity="MEDIUM",
                )]
        counts: Counter[str] = Counter()
        unsafe_paths: list[str] = []
        symlinks: list[str] = []
        encrypted = 0
        risky_modes: list[str] = []
        high_ratios: list[str] = []
        content_findings: list[Finding] = []
        content_bytes = 0
        content_truncated = 0
        try:
            with zipfile.ZipFile(path, "r") as archive:
                infos = archive.infolist()
                total = len(infos)
                duplicates = [
                    name for name, count in Counter(
                        item.filename for item in infos
                    ).items() if count > 1
                ]
                for info in infos[:_MAX_ARCHIVE_ENTRIES]:
                    mode = (info.external_attr >> 16) & 0xFFFF
                    encrypted_member = bool(info.flag_bits & 0x1)
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
                    if encrypted_member:
                        encrypted += 1
                    for risk in _mode_risks(mode):
                        risky_modes.append(f"{info.filename} ({risk})")
                    if info.file_size > 0 and (
                        info.compress_size == 0
                        or info.file_size / max(info.compress_size, 1) > 1000
                    ):
                        high_ratios.append(info.filename)

                    if encrypted_member or kind not in {"file", "symlink"}:
                        continue
                    remaining = _MAX_ARCHIVE_SCAN_BYTES - content_bytes
                    if remaining <= 0:
                        content_truncated += 1
                        continue
                    try:
                        with archive.open(info, "r") as member_stream:
                            sample, consumed, truncated = _read_member_sample(
                                member_stream, remaining
                            )
                        content_bytes += consumed
                        if truncated or info.file_size > consumed:
                            content_truncated += 1
                        if kind == "symlink":
                            target = sample.decode("utf-8", errors="replace").strip("\x00")
                            if target and _unsafe_member_path(target):
                                unsafe_paths.append(f"{info.filename} -> {target}")
                        else:
                            content_findings.extend(
                                _member_content_findings(record.path, info.filename, sample)
                            )
                    except (
                        OSError, RuntimeError, NotImplementedError,
                        zipfile.BadZipFile, EOFError,
                    ):
                        content_truncated += 1

        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
            return [Finding(
                "archive",
                f"ZIP metadata read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        evidence = [
            f"{counts['file']} regular file(s)",
            f"{counts['directory']} directory entry(ies)",
            f"{counts['symlink']} symlink entry(ies)",
            f"{encrypted} encrypted entry(ies)",
            f"{len(duplicates)} duplicate member name(s)",
            f"{content_bytes:,} member bytes inspected in memory",
            f"{content_truncated} member(s) not fully inspected",
        ]
        findings = [Finding(
            "archive",
            f"ZIP archive inventory: {record.path}",
            f"Indexed {min(total, _MAX_ARCHIVE_ENTRIES)} of {total} member(s); "
            f"compressed file size {record.size_bytes:,} bytes. Member bytes were inspected "
            "only through bounded in-memory streams; no member was written to disk.",
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
        findings.extend(content_findings)
        if content_truncated:
            findings.append(Finding(
                "archive",
                f"ZIP member content budget reached: {record.path}",
                f"Content inspection was limited to {_MAX_ARCHIVE_SCAN_BYTES:,} total "
                f"in-memory bytes and {_MAX_MEMBER_SCAN_BYTES:,} bytes per member. "
                f"{content_truncated} member(s) were not fully inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

    def _tar(self, path: Path, record: FileRecord) -> list[Finding]:
        counts: Counter[str] = Counter()
        unsafe_paths: list[str] = []
        symlinks: list[str] = []
        hardlinks: list[str] = []
        risky_modes: list[str] = []
        special_entries: list[str] = []
        content_findings: list[Finding] = []
        content_bytes = 0
        content_truncated = 0
        total = 0
        try:
            with tarfile.open(path, mode="r|*") as archive:
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

                    if kind == "file":
                        remaining = _MAX_ARCHIVE_SCAN_BYTES - content_bytes
                        if remaining <= 0:
                            content_truncated += 1
                            break
                        member_stream = None
                        try:
                            member_stream = archive.extractfile(member)
                            if member_stream is not None:
                                sample, consumed, truncated = _read_member_sample(
                                    member_stream, remaining
                                )
                                content_bytes += consumed
                                member_incomplete = truncated or member.size > consumed
                                if member_incomplete:
                                    content_truncated += 1
                                content_findings.extend(
                                    _member_content_findings(record.path, member.name, sample)
                                )
                                if member_incomplete:
                                    break
                        except (OSError, tarfile.TarError, EOFError):
                            content_truncated += 1
                            break
                        finally:
                            if member_stream is not None:
                                member_stream.close()

        except (OSError, tarfile.TarError, EOFError) as exc:
            return [Finding(
                "archive",
                f"TAR metadata read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        indexed = min(total, _MAX_ARCHIVE_ENTRIES)
        findings = [Finding(
            "archive",
            f"TAR archive inventory: {record.path}",
            f"Indexed {indexed} member(s); {counts['file']} regular file(s), "
            f"{counts['directory']} directory(ies), {counts['symlink']} symlink(s), "
            f"{counts['hardlink']} hardlink(s), {counts['special']} special entry(ies). "
            f"{content_bytes:,} member bytes were inspected through bounded in-memory streams; "
            "no member was written to disk.",
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
        findings.extend(content_findings)
        if content_truncated:
            findings.append(Finding(
                "archive",
                f"TAR member content budget reached: {record.path}",
                f"Content inspection was limited to {_MAX_ARCHIVE_SCAN_BYTES:,} total "
                f"in-memory bytes and {_MAX_MEMBER_SCAN_BYTES:,} bytes per member. "
                f"{content_truncated} member(s) were not fully inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
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
