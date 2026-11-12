"""Metadata-only archive inspection. Archive members are never extracted."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import stat
import struct
import tarfile
import time
import unicodedata
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from ...core.secret_patterns import ANY_TOKEN, PRIVATE_KEY_MARKER
from ...core.source_utils import describe_error, open_verified_binary, redact_source_excerpt
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer

_ARCHIVE_EXTENSIONS = {
    ".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".whl", ".egg",
    ".nupkg", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar",
    ".cab", ".iso", ".deb", ".rpm",
}
_MAX_ARCHIVE_ENTRIES = 200_000
_MAX_ARCHIVE_INDEX_BYTES = 64 * 1024 * 1024


def _zip_index_hint(
    path: Path,
    expected_identity: tuple[int | None, int | None, int | None, int | None, int | None] | None = None,
) -> tuple[int, int] | None:
    """Read ZIP/ZIP64 bounds through a verified no-follow descriptor."""
    try:
        with open_verified_binary(path, expected_identity) as stream:
            stream.seek(0, 2)
            size = stream.tell()
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
_MAX_ARCHIVE_WALL_SECONDS = 8.0
# Compressed TAR streams must be decompressed to reach later headers; this bounds the
# decompression work independently of the wall-time budget.
_MAX_TAR_DECOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
_MEMBER_SCAN_CHUNK = 64 * 1024


class _ArchiveBudgetExceeded(Exception):
    """Raised from inside archive reads when a time or decompression budget is spent."""


class _BudgetedReader(io.RawIOBase):
    """Read-through wrapper that enforces a deadline and byte budget on every read."""

    def __init__(self, stream, deadline: float, max_bytes: int) -> None:
        self._stream = stream
        self._deadline = deadline
        self._remaining = max_bytes
        self.consumed = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        if time.monotonic() >= self._deadline:
            raise _ArchiveBudgetExceeded("wall-time budget reached")
        if self._remaining <= 0:
            raise _ArchiveBudgetExceeded("decompressed-byte budget reached")
        view = memoryview(buffer)
        size = min(len(view), self._remaining, _MEMBER_SCAN_CHUNK * 16)
        data = self._stream.read(size)
        view[:len(data)] = data
        self._remaining -= len(data)
        self.consumed += len(data)
        return len(data)


def _tar_decompressor(stream):
    """Return a decompressing file object for gzip/bzip2/xz TAR streams, or None if plain."""
    head = stream.peek(6)[:6]
    if head.startswith(b"\x1f\x8b"):
        return gzip.GzipFile(fileobj=stream, mode="rb")
    if head.startswith(b"BZh"):
        return bz2.BZ2File(stream)
    if head.startswith(b"\xfd7zXZ\x00"):
        return lzma.LZMAFile(stream)
    return None


def _colliding_names(names) -> list[str]:
    """Member names that collide on case-insensitive or Unicode-normalizing filesystems."""
    seen: dict[str, set[str]] = {}
    for name in names:
        key = unicodedata.normalize("NFC", name.replace("\\", "/")).casefold()
        seen.setdefault(key, set()).add(name)
    return sorted(
        " / ".join(sorted(variants)) for variants in seen.values() if len(variants) > 1
    )
_CONTENT_RULES = (
    (
        "credential-like assignment",
        re.compile(
            # Possessive, same-line separators: two adjacent \s* runs backtracked
            # quadratically on long whitespace after a keyword.
            r"""(?im)\b(?:password|passwd|passphrase|api[_-]?key|client[_-]?secret|"""
            r"""access[_-]?token|refresh[_-]?token|secret)\b[ \t]*+["']?[ \t]*+[:=][ \t]*+["']?"""
            r"""[^\s,"']{4,}"""
        ),
        "secrets",
    ),
    ("private-key marker", PRIVATE_KEY_MARKER, "secrets"),
    # The same provider-token registry as the source secret scanner.
    ("provider credential token", ANY_TOKEN, "secrets"),
    (
        "email-shaped value",
        re.compile(
            r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_{|}~-]{1,64}@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
            r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b"
        ),
        "privacy",
    ),
)


def _read_member_sample(
    stream,
    budget_remaining: int,
    deadline: float | None = None,
) -> tuple[bytes, int, bool]:
    """Read a bounded in-memory sample; stop on byte or wall-time budget."""
    limit = min(_MAX_MEMBER_SCAN_BYTES, max(0, budget_remaining))
    if limit <= 0:
        return b"", 0, True
    sample = bytearray()
    timed_out = False
    while len(sample) <= limit:
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            break
        chunk = stream.read(min(_MEMBER_SCAN_CHUNK, limit + 1 - len(sample)))
        if not chunk:
            break
        sample.extend(chunk)
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            break
    truncated = timed_out or len(sample) > limit
    if len(sample) > limit:
        del sample[limit:]
    return bytes(sample), len(sample), truncated


def _member_content_findings(
    archive_path: str,
    member_name: str,
    sample: bytes,
    deadline: float | None = None,
) -> tuple[list[Finding], bool]:
    """Return bounded redacted member findings and whether matching hit the deadline."""
    if not sample:
        return [], False
    text = sample.decode("utf-8", errors="replace")
    hits: dict[tuple[str, str], set[int]] = {}
    excerpts: dict[tuple[str, str, int], str] = {}
    excerpt_counts: Counter[tuple[str, str]] = Counter()
    timed_out = False

    for label, pattern, category in _CONTENT_RULES:
        line_number = 1
        position_cursor = 0
        for match in pattern.finditer(text):
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break

            # Each pattern yields ordered matches. Count only the not-yet-visited
            # segment so repeated matches do not rescan the start of a large sample.
            line_number += text.count("\n", position_cursor, match.start())
            position_cursor = match.start()
            key = (category, label)
            hits.setdefault(key, set()).add(line_number)
            evidence_key = (category, label, line_number)
            if evidence_key not in excerpts and excerpt_counts[key] < 20:
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end < 0:
                    line_end = len(text)
                excerpts[evidence_key] = redact_source_excerpt(text[line_start:line_end])
                excerpt_counts[key] += 1

        if timed_out or (
            deadline is not None and time.monotonic() >= deadline
        ):
            timed_out = True
            break

    findings: list[Finding] = []
    for (category, label), lines in sorted(hits.items()):
        if category == "secrets":
            impact = (
                "If the archived value is a valid active credential, an attacker who obtains "
                "the archive may access the linked API, cloud account or database, read or alter "
                "data, invoke privileged operations or pivot to connected services."
            )
            recommendation = (
                "Revoke and rotate any live credential, remove it from archived source/configuration "
                "where appropriate, replace it with secret-manager or protected runtime injection, "
                "and audit repository/artifact access."
            )
        else:
            impact = (
                "If the address is real, exposing it in a repository artifact may reveal a contact "
                "identity for unsolicited contact, phishing or account correlation."
            )
            recommendation = (
                "Replace real addresses in fixtures and examples with reserved example addresses; "
                "remove exposed personal data from tracked files and published artifacts."
            )
        selected_lines = sorted(lines)
        findings.append(Finding(
            category,
            f"{label.title()} inside archive member: {archive_path}",
            f"Detected {len(lines)} line(s) with {label} in an archive member. "
            "Matched values are not retained. This bounded scan is not a complete DLP or malware scan.",
            confidence="INFERRED",
            evidence=[
                f"{archive_path}::{member_name}:{line} ({label}; value redacted)"
                for line in selected_lines[:_MAX_EVIDENCE]
            ],
            analyzer="archive-intelligence",
            severity="HIGH" if category == "secrets" else "MEDIUM",
            code_evidence=[
                CodeEvidence(
                    line_number=line,
                    code=excerpts[(category, label, line)],
                )
                for line in selected_lines[:20]
                if (category, label, line) in excerpts
            ],
            impact=impact,
            recommendation=recommendation,
        ))
    return findings, timed_out

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
        suffix = record.path.lower()
        if record.file_type == "archive/zip" or suffix.endswith((
            ".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".whl", ".egg", ".nupkg",
        )):
            return self._zip(path, record)
        if record.file_type in {"archive/tar", "archive/tar-or-compressed-tar"} or suffix.endswith((
            ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
        )):
            return self._tar(path, record)
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
        index_hint = _zip_index_hint(path, record.analysis_identity)
        if index_hint is None:
            return [Finding(
                "archive",
                f"ZIP central-directory bounds unavailable: {record.path}",
                "The archive index could not be safely bounded from its ZIP/ZIP64 trailer. "
                "The central directory was not materialized and no members were inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            )]
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
        deadline = time.monotonic() + _MAX_ARCHIVE_WALL_SECONDS
        time_budget_reached = False
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
            with open_verified_binary(path, record.analysis_identity) as archive_stream, zipfile.ZipFile(archive_stream, "r") as archive:
                infos = archive.infolist()
                total = len(infos)
                duplicates = [
                    name for name, count in Counter(
                        item.filename for item in infos
                    ).items() if count > 1
                ]
                collisions = _colliding_names({item.filename for item in infos})
                for info in infos[:_MAX_ARCHIVE_ENTRIES]:
                    if time.monotonic() >= deadline:
                        time_budget_reached = True
                        break
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
                                member_stream, remaining, deadline
                            )
                        content_bytes += consumed
                        if time.monotonic() >= deadline:
                            time_budget_reached = True
                        if truncated or info.file_size > consumed:
                            content_truncated += 1
                        if kind == "symlink":
                            target = sample.decode("utf-8", errors="replace").strip("\x00")
                            if target and _unsafe_member_path(target):
                                unsafe_paths.append(f"{info.filename} -> {target}")
                        else:
                            member_findings, member_timed_out = _member_content_findings(
                                record.path, info.filename, sample, deadline
                            )
                            content_findings.extend(member_findings)
                            if member_timed_out:
                                time_budget_reached = True
                    except (
                        OSError, RuntimeError, NotImplementedError,
                        zipfile.BadZipFile, EOFError,
                    ):
                        content_truncated += 1
                    if time_budget_reached:
                        break

        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
            return [Finding(
                "archive",
                f"ZIP metadata read error: {record.path}",
                describe_error(exc),
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
        if collisions:
            findings.append(self._collision_finding(record, collisions))
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
        if time_budget_reached:
            findings.append(Finding(
                "archive",
                f"ZIP wall-time budget reached: {record.path}",
                f"Archive inspection stopped after the {_MAX_ARCHIVE_WALL_SECONDS:g}-second "
                "wall-time budget. Findings already collected are partial; remaining entries "
                "were not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

    def _tar(self, path: Path, record: FileRecord) -> list[Finding]:
        """Traverse every TAR header under budgets; content sampling never ends traversal.

        Stopping at the first large member would hide later traversal, link and setuid
        entries, so sampling limits only skip sampling. Compressed streams are read through
        a budgeted reader that enforces wall time and decompressed bytes inside each read.
        """
        deadline = time.monotonic() + _MAX_ARCHIVE_WALL_SECONDS
        time_budget_reached = False
        stop_reason: str | None = None
        counts: Counter[str] = Counter()
        names: list[str] = []
        unsafe_paths: list[str] = []
        symlinks: list[str] = []
        hardlinks: list[str] = []
        risky_modes: list[str] = []
        special_entries: list[str] = []
        content_findings: list[Finding] = []
        content_bytes = 0
        content_truncated = 0
        total = 0
        compressed = False
        try:
            with open_verified_binary(path, record.analysis_identity) as archive_stream:
                decompressor = _tar_decompressor(archive_stream)
                if decompressor is None:
                    # Plain TAR on a seekable descriptor: headers are reached by seeking.
                    archive = tarfile.open(fileobj=archive_stream, mode="r:")
                else:
                    compressed = True
                    archive = tarfile.open(
                        fileobj=_BudgetedReader(decompressor, deadline, _MAX_TAR_DECOMPRESSED_BYTES),
                        mode="r|",
                    )
                with archive:
                    try:
                        for member in archive:
                            if time.monotonic() >= deadline:
                                time_budget_reached = True
                                break
                            total += 1
                            if total > _MAX_ARCHIVE_ENTRIES:
                                break
                            names.append(member.name)
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
                                (member.issym() or member.islnk())
                                and _unsafe_member_path(member.linkname)
                            ):
                                unsafe_paths.append(member.name)
                            for risk in _mode_risks(member.mode):
                                risky_modes.append(f"{member.name} ({risk})")

                            if kind != "file":
                                continue
                            remaining = _MAX_ARCHIVE_SCAN_BYTES - content_bytes
                            if remaining <= 0:
                                content_truncated += 1
                                continue
                            member_stream = archive.extractfile(member)
                            if member_stream is None:
                                continue
                            with member_stream:
                                sample, consumed, truncated = _read_member_sample(
                                    member_stream, remaining, deadline
                                )
                            content_bytes += consumed
                            if truncated or member.size > consumed:
                                content_truncated += 1
                            member_findings, member_timed_out = _member_content_findings(
                                record.path, member.name, sample, deadline
                            )
                            content_findings.extend(member_findings)
                            if member_timed_out or time.monotonic() >= deadline:
                                time_budget_reached = True
                                break
                    except _ArchiveBudgetExceeded as exc:
                        stop_reason = str(exc)
                        time_budget_reached = "wall-time" in stop_reason
        except (OSError, tarfile.TarError, EOFError, lzma.LZMAError) as exc:
            return [Finding(
                "archive",
                f"TAR metadata read error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        indexed = min(total, _MAX_ARCHIVE_ENTRIES)
        traversal_complete = not (time_budget_reached or stop_reason or total > _MAX_ARCHIVE_ENTRIES)
        findings = [Finding(
            "archive",
            f"TAR archive inventory: {record.path}",
            f"Indexed {indexed} member(s){'' if traversal_complete else ' before a budget stopped traversal'}; "
            f"{counts['file']} regular file(s), "
            f"{counts['directory']} directory(ies), {counts['symlink']} symlink(s), "
            f"{counts['hardlink']} hardlink(s), {counts['special']} special entry(ies)"
            f"{' in a compressed stream' if compressed else ''}. "
            f"{content_bytes:,} member bytes were inspected through bounded in-memory streams; "
            "no member was written to disk.",
            confidence="CONFIRMED",
            evidence=[record.path],
            analyzer=self.name,
        )]
        if stop_reason and not time_budget_reached:
            findings.append(Finding(
                "archive",
                f"TAR decompression budget reached: {record.path}",
                f"Traversal stopped after {_MAX_TAR_DECOMPRESSED_BYTES:,} decompressed bytes. "
                "Members after that point were not indexed; this is not a clean result.",
                confidence="UNKNOWN",
                evidence=[record.path, f"members_indexed: {indexed:,}"],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        collisions = _colliding_names(names)
        if collisions:
            findings.append(self._collision_finding(record, collisions))
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
        if time_budget_reached:
            findings.append(Finding(
                "archive",
                f"TAR wall-time budget reached: {record.path}",
                f"Archive inspection stopped after the {_MAX_ARCHIVE_WALL_SECONDS:g}-second "
                "wall-time budget. Findings already collected are partial; remaining entries "
                "were not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

    def _collision_finding(self, record: FileRecord, collisions: list[str]) -> Finding:
        return Finding(
            "archive",
            f"Case- or Unicode-colliding archive member names: {record.path}",
            f"Detected {len(collisions)} group(s) of distinct member names that map to the same "
            "path on case-insensitive or Unicode-normalizing filesystems (Windows, macOS). "
            "Extraction there may overwrite one member with another.",
            confidence="CONFIRMED",
            evidence=[f"{record.path}::{group}" for group in collisions[:_MAX_EVIDENCE]],
            analyzer=self.name,
            severity="MEDIUM",
        )

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
