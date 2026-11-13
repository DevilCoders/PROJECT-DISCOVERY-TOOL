"""Metadata-only archive inspection. Archive members are never extracted."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import math
import re
import stat
import struct
import tarfile
import time
import unicodedata
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, limit_overrides, limit_reached, over_limit
from ...core.source_utils import LineIndex, describe_error, open_verified_binary, redact_source_excerpt
from ...intelligence.facts import MAX_ARCHIVE_MEMBERS_PER_FILE, current_facts, emit_archive, emit_archive_member
from ...inventory.signatures import family_of, is_archive
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer
from ..security.privacy import personal_email_matches
from ..security.secrets import credential_matches

_MAX_ARCHIVE_ENTRIES = 200_000
_MAX_ARCHIVE_INDEX_BYTES = 64 * 1024 * 1024


def _zip_index_hint(
    path: Path,
    expected_identity: tuple[int | None, int | None, int | None, int | None, int | None] | None = None,
    data: bytes | None = None,
) -> tuple[int, int] | None:
    """Read ZIP/ZIP64 bounds through a verified no-follow descriptor, or from a nested archive's bytes."""
    try:
        with (open_verified_binary(path, expected_identity) if data is None else io.BytesIO(data)) as stream:
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
            saturated = entry_count == 0xFFFF or directory_size == 0xFFFFFFFF
            # zipfile applies a ZIP64 record whenever its locator precedes the EOCD, and reads
            # the record just before the locator (not at the locator's offset). An archive
            # whose classic EOCD declares one entry but whose ZIP64 record declares millions
            # passed this preflight and infolist() built them all, so the record is read the
            # way zipfile reads it, saturated fields or not.
            locator = eocd - 20
            if locator >= 0 and tail[locator:locator + 4] == b"PK\x06\x07":
                record_start = size - tail_size + locator - 56
                if record_start < 0:
                    return None
                stream.seek(record_start)
                zip64 = stream.read(56)
                if len(zip64) == 56 and zip64[:4] == b"PK\x06\x06":
                    entry_count = struct.unpack_from("<Q", zip64, 32)[0]
                    directory_size = struct.unpack_from("<Q", zip64, 40)[0]
                elif saturated:
                    return None
            elif saturated:
                return None
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
# Members declaring more uncompressed bytes in total than this suggest an archive bomb.
_MAX_DECLARED_UNCOMPRESSED_BYTES = 16 * 1024 * 1024 * 1024
_MAX_NESTED_DEPTH = 1  # archives inside an archive are inspected one level down
_MAX_NESTED_BYTES = 64 * 1024 * 1024  # nested archives one archive may buffer in memory, in total
_HIGH_COMPRESSION_RATIO = 1000.0  # a member compressed more than this is flagged "high-ratio"
_MIB = 1024 * 1024
# `pdt scan --archive-limit NAME=VALUE`: option name -> (limit, unit in bytes or 1, whole number)
ARCHIVE_LIMIT_OPTIONS = {
    "entries": ("entries", 1, True),
    "index_mb": ("index_bytes", _MIB, True),
    "member_sample_mb": ("member_sample_bytes", _MIB, True),
    "sample_mb": ("archive_sample_bytes", _MIB, True),
    "wall_seconds": ("wall_seconds", 1, False),
    "decompressed_mb": ("tar_decompressed_bytes", _MIB, True),
    "uncompressed_mb": ("uncompressed_bytes", _MIB, True),
    "ratio": ("compression_ratio", 1, False),
    "nested_depth": ("nested_depth", 1, True),
    "nested_mb": ("nested_bytes", _MIB, True),
}



def parse_archive_limits(values) -> dict[str, float]:
    """``--archive-limit NAME=VALUE`` values as {name: number}; a later value for a name wins.

    Byte limits are in MiB. ``sample_mb`` and ``member_sample_mb`` may be 0 (no content
    sampling); the other whole-number limits are at least 1, ``wall_seconds`` is above 0 and
    ``ratio`` above 1.
    """
    limits: dict[str, float] = {}
    for raw in values or ():
        name, equals, value = str(raw).partition("=")
        name = name.strip().lower()
        if not equals or name not in ARCHIVE_LIMIT_OPTIONS:
            raise ValueError(f"--archive-limit {raw}: expected NAME=VALUE, NAME one of {', '.join(ARCHIVE_LIMIT_OPTIONS)}")
        try:
            number = float(value)
        except ValueError:
            raise ValueError(f"--archive-limit {raw}: {name} must be a number") from None
        whole = ARCHIVE_LIMIT_OPTIONS[name][2]
        if whole:
            minimum = 0 if name in {"sample_mb", "member_sample_mb", "nested_depth", "nested_mb"} else 1
            if not math.isfinite(number) or number != int(number) or number < minimum:
                raise ValueError(f"--archive-limit {raw}: {name} must be a whole number of at least {minimum}")
            limits[name] = int(number)
        else:
            floor = 1 if name == "ratio" else 0
            if not math.isfinite(number) or number <= floor:
                raise ValueError(f"--archive-limit {raw}: {name} must be a number above {floor}")
            limits[name] = number
    return limits

class _Limits:
    """One call's archive limits: the module defaults with the scan's --archive-limit values."""

    __slots__ = ("entries", "index_bytes", "member_sample_bytes", "archive_sample_bytes", "wall_seconds",
                 "tar_decompressed_bytes", "uncompressed_bytes", "compression_ratio", "nested_depth",
                 "nested_bytes")

    def __init__(self) -> None:
        # Read when a call starts, so the defaults are the module's current values.
        self.entries = _MAX_ARCHIVE_ENTRIES
        self.index_bytes = _MAX_ARCHIVE_INDEX_BYTES
        self.member_sample_bytes = _MAX_MEMBER_SCAN_BYTES
        self.archive_sample_bytes = _MAX_ARCHIVE_SCAN_BYTES
        self.wall_seconds = _MAX_ARCHIVE_WALL_SECONDS
        self.tar_decompressed_bytes = _MAX_TAR_DECOMPRESSED_BYTES
        self.uncompressed_bytes = _MAX_DECLARED_UNCOMPRESSED_BYTES
        self.compression_ratio = _HIGH_COMPRESSION_RATIO
        self.nested_depth = _MAX_NESTED_DEPTH
        self.nested_bytes = _MAX_NESTED_BYTES
        for name, value in limit_overrides("archive-intelligence").items():
            attribute, unit, whole = ARCHIVE_LIMIT_OPTIONS[name]
            setattr(self, attribute, int(value * unit) if whole else float(value))


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
# Members get the file scanners' own rules (credential assignments with keyed names and
# placeholder filtering, credential URLs, provider tokens, private keys, and personal
# addresses), so a secret in a .env file is reported the same whether or not it is zipped.
_SECRET_LABELS = {
    "private_key": "private-key marker",
    "credential_assignment": "credential-like assignment",
    "credential_url": "credential URL",
}


def _member_matches(text: str, member_name: str):
    """(label, category, match) for every secret and personal address in a member sample."""
    for pattern_name, match in credential_matches(text, member_name):
        yield _SECRET_LABELS.get(pattern_name, "provider credential token"), "secrets", match
    for match in personal_email_matches(text):
        yield "email-shaped value", "privacy", match


def _read_member_sample(
    stream,
    budget_remaining: int,
    deadline: float | None = None,
    member_limit: int | None = None,
) -> tuple[bytes, int, bool]:
    """Read a bounded in-memory sample; stop on byte or wall-time budget."""
    limit = min(_MAX_MEMBER_SCAN_BYTES if member_limit is None else member_limit, max(0, budget_remaining))
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

    lines = LineIndex(text)
    for label, category, match in _member_matches(text, member_name):
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            break
        line_number = lines.line(match.start())
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


# Limits that stop the metadata traversal (the archive is budget-stopped) and limits that only
# leave member content partly read (sample-truncated).
_TRAVERSAL_LIMITS = frozenset({"entries", "index_bytes", "wall_seconds", "tar_decompressed_bytes",
                               "analyzer_time", "analyzer_memory", "analyzer_cpu", "analyzer_read"})


def _zip_time(date_time) -> str | None:
    """A ZIP member's DOS timestamp: local time without a zone, at two-second resolution."""
    try:
        year, month, day, hour, minute, second = date_time
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}T{int(hour):02d}:{int(minute):02d}:{int(second):02d}"
    except (TypeError, ValueError):
        return None


def _tar_time(mtime) -> str | None:
    """A TAR member's modification time (seconds since the epoch, UTC)."""
    try:
        return datetime.fromtimestamp(float(mtime), timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def _pct(part: int, whole: int | None) -> float | None:
    if whole is None:
        return None
    return 100.0 if whole == 0 else round(100 * min(part, whole) / whole, 1)


def _archive_format(record: FileRecord) -> str:
    """The archive format a record names: its signature's family, or its extension."""
    if record.file_type.startswith("archive/"):
        return record.file_type.split("/", 1)[1]
    return family_of(record.file_type) or record.extension.lstrip(".") or "unknown"



_LOCAL_HEADER = struct.Struct("<4s5H3L2H")  # signature, version, flags, method, time, date, CRC, sizes, name/extra


def _zip_structure_issues(stream, infos, start_dir: int, size: int, deadline: float) -> tuple[dict[int, list[str]], bool]:
    """Check each member's local header and data descriptor against the central directory.

    Returns ({member index: issues}, whether the wall-time budget stopped the check). The issues
    are "header-mismatch" (the local header names another file, method, CRC or size: tools
    that read local headers see another archive), "descriptor-mismatch" (a data descriptor
    disagrees with the directory), "out-of-bounds" (the member's data runs past the central
    directory or the end of the file: a truncated or corrupt archive) and "overlapping" (its
    data overlaps another member's, the construction of non-recursive zip bombs).
    """
    issues: dict[int, list[str]] = {}
    spans: list[tuple[int, int, int]] = []
    for index, info in enumerate(infos):
        if index % 1024 == 0 and time.monotonic() >= deadline:
            return issues, True
        found: list[str] = []
        stream.seek(info.header_offset)
        header = stream.read(_LOCAL_HEADER.size)
        if len(header) < _LOCAL_HEADER.size or header[:4] != b"PK\x03\x04":
            issues[index] = ["out-of-bounds" if info.header_offset + _LOCAL_HEADER.size > size else "header-mismatch"]
            continue
        _, _, flags, method, _, _, crc, compressed, uncompressed, name_length, extra_length = _LOCAL_HEADER.unpack(header)
        name = stream.read(name_length)
        try:
            expected = info.orig_filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
        except UnicodeEncodeError:
            expected = name
        if name != expected or method != info.compress_type:
            found.append("header-mismatch")
        data_start = info.header_offset + _LOCAL_HEADER.size + name_length + extra_length
        data_end = data_start + info.compress_size
        if flags & 0x08:
            # Sizes and CRC follow the data: optional signature, then 4- or 8-byte (ZIP64) sizes.
            stream.seek(data_end)
            tail = stream.read(24)
            body = tail[4:] if tail[:4] == b"PK\x07\x08" else tail
            short = struct.unpack_from("<3L", body) if len(body) >= 12 else None
            wide = struct.unpack_from("<L2Q", body) if len(body) >= 20 else None
            declared = (info.CRC, info.compress_size, info.file_size)
            if declared not in (short, wide):
                found.append("descriptor-mismatch")
            data_end += (len(tail) - len(body)) + (20 if wide == declared and short != declared else 12)
        elif 0xFFFFFFFF not in (compressed, uncompressed) and (crc, compressed, uncompressed) != (
                info.CRC, info.compress_size, info.file_size):
            found.append("header-mismatch")
        if data_end > min(start_dir, size):
            found.append("out-of-bounds")
        spans.append((info.header_offset, data_end, index))
        if found:
            issues[index] = found
    spans.sort()
    reach, holder = -1, -1
    for start, end, index in spans:
        if start < reach:
            for member in (index, holder):
                if "overlapping" not in issues.setdefault(member, []):
                    issues[member].append("overlapping")
        if end > reach:
            reach, holder = end, index
    return issues, False

class _Nested:
    """The bytes of nested archives one top-level archive may still buffer in memory."""

    __slots__ = ("remaining",)

    def __init__(self, budget: int) -> None:
        self.remaining = budget


_NESTED_ZIP_SUFFIXES = (".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".whl", ".egg", ".nupkg")
_NESTED_TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


def _nested_kind(name: str) -> str | None:
    """"zip" or "tar" for a member named like an archive these readers inspect, else None."""
    lowered = name.lower()
    if lowered.endswith(_NESTED_ZIP_SUFFIXES):
        return "zip"
    if lowered.endswith(_NESTED_TAR_SUFFIXES):
        return "tar"
    return None


class _Inspection:
    """How far one archive's inspection got: its states, member counts and coverage, and
    every limit that stopped deeper inspection, recorded with ``emit_archive`` at the end."""

    def __init__(self, record: FileRecord, archive_format: str, limits: _Limits) -> None:
        self.record, self.format, self.limits_in_force = record, archive_format, limits
        self.path = record.path  # a nested archive's record carries "outer.zip::inner.jar"
        self.declared: int | None = None  # members the archive's index declares
        self.index_read = False
        self.indexed = 0
        self.regular = 0  # indexed regular-file members and their uncompressed bytes
        self.regular_bytes = 0
        self.compressed_bytes: int | None = None
        self.sampled = 0  # members whose content was read, in part or in full
        self.fully_sampled = 0
        self.sample_bytes = 0
        self.regular_sample_bytes = 0
        self.truncated = 0  # members eligible for sampling that were not read in full
        self.encrypted = 0
        self.records = 0
        self.malformed: str | None = None
        self.unsupported = False
        self.limits: dict[str, dict] = {}
        self.extra: dict = {}  # format-specific record fields (ZIP structure issues)
        facts = current_facts()
        self._first_record = len(facts.archive_members) if facts is not None else 0

    def flag_duplicates(self, names) -> None:
        """Add the "duplicate" flag to the recorded members whose name occurs more than once."""
        repeated = {name for name, count in Counter(names).items() if count > 1}
        facts = current_facts()
        if not repeated or facts is None:
            return
        records = facts.archive_members
        for index in range(self._first_record, len(records)):
            item = records[index]
            # Only this archive's records: a nested archive's follow them in the same list.
            if item[0] == self.path and item[2] in repeated:
                records[index] = (*item[:8], ",".join(filter(None, (item[8], "duplicate"))), *item[9:])

    def limit(self, name: str, value, used=None, members: int | None = None) -> None:
        entry = self.limits.setdefault(name, {"limit": name, "value": value})
        if used is not None:
            entry["used"] = used
        if members is not None:
            entry["members"] = entry.get("members", 0) + members

    def member(self, ordinal: int, name: str, kind: str, size, compressed, mode, mtime, flags,
               link_target=None, uid=None, gid=None, owner=None, group=None) -> None:
        self.indexed += 1
        if kind == "file":
            self.regular += 1
            self.regular_bytes += max(0, int(size or 0))
        # Permission bits only: the type is the record's own field (a ZIP mode carries both).
        permissions = stat.S_IMODE(mode) if mode else None
        if emit_archive_member(self.path, ordinal, name, kind, size, compressed, permissions, mtime, flags,
                               link_target, uid, gid, owner, group):
            self.records += 1

    def sample(self, kind: str, size: int, consumed: int, truncated: bool, remaining: int) -> None:
        """One member's content sample; a sample short of the member names the limit."""
        self.sampled += 1
        self.sample_bytes += consumed
        if kind == "file":
            self.regular_sample_bytes += consumed
        if not truncated and size <= consumed:
            self.fully_sampled += 1
            return
        self.truncated += 1
        if consumed >= remaining:
            self.limit("archive_sample_bytes", self.limits_in_force.archive_sample_bytes, members=1)
        elif consumed >= self.limits_in_force.member_sample_bytes:
            self.limit("member_sample_bytes", self.limits_in_force.member_sample_bytes, members=1)

    def skipped_sample(self) -> None:
        """A member that the spent archive sample budget left unread."""
        self.truncated += 1
        self.limit("archive_sample_bytes", self.limits_in_force.archive_sample_bytes, members=1)

    def emit(self) -> None:
        if self.records < self.indexed:
            self.limit("member_records", MAX_ARCHIVE_MEMBERS_PER_FILE, members=self.indexed - self.records)
        stopped = bool(_TRAVERSAL_LIMITS & set(self.limits))
        complete = self.index_read and not stopped and self.malformed is None
        states = ["detected"] + [name for name, applies in (
            ("unsupported", self.unsupported), ("index-read", self.index_read), ("metadata-complete", complete),
            ("sample-read", self.sampled > 0), ("sample-truncated", self.truncated > 0),
            ("encrypted", self.encrypted > 0), ("malformed", self.malformed is not None), ("budget-stopped", stopped),
        ) if applies]
        state = ("malformed" if self.malformed is not None else "unsupported" if self.unsupported
                 else "budget-stopped" if stopped else "metadata-complete" if complete
                 else "index-read" if self.index_read else "detected")
        detail = {
            "archive_bytes": self.record.size_bytes, "compressed_bytes": self.compressed_bytes,
            "members_declared": self.declared, "members_indexed": self.indexed,
            "member_coverage_pct": _pct(self.indexed, self.declared),
            "regular_members": self.regular, "member_bytes": self.regular_bytes,
            "members_sampled": self.sampled, "members_fully_sampled": self.fully_sampled,
            "members_not_fully_sampled": self.truncated, "member_bytes_sampled": self.sample_bytes,
            "content_coverage_pct": _pct(self.regular_sample_bytes, self.regular_bytes) if self.index_read else None,
            "encrypted_members": self.encrypted, "member_records": self.records,
            "limits": [self.limits[name] for name in sorted(self.limits)],
        }
        detail.update(self.extra)
        if self.malformed is not None:
            detail["error"] = self.malformed
        emit_archive(self.path, self.format, state, states, **detail)


class ArchiveIntelligenceAnalyzer(Analyzer):
    """Inspect archive indexes and metadata under entry-count and evidence limits."""

    name = "archive-intelligence"
    limits = AnalyzerLimits(
        None,
        "sampled",
        {"entries": _MAX_ARCHIVE_ENTRIES, "index_bytes": _MAX_ARCHIVE_INDEX_BYTES, "member_sample_bytes": _MAX_MEMBER_SCAN_BYTES, "archive_sample_bytes": _MAX_ARCHIVE_SCAN_BYTES, "wall_seconds": _MAX_ARCHIVE_WALL_SECONDS, "tar_decompressed_bytes": _MAX_TAR_DECOMPRESSED_BYTES, "uncompressed_bytes": _MAX_DECLARED_UNCOMPRESSED_BYTES, "compression_ratio": int(_HIGH_COMPRESSION_RATIO), "nested_depth": _MAX_NESTED_DEPTH, "nested_bytes": _MAX_NESTED_BYTES},
        outcome="UNKNOWN or partial finding at an index, entry, sample, decompression or wall-time limit",
    )
    domains = ("archives", "filesystem_inventory", "supply_chain")
    languages = ("ZIP", "TAR", "GZIP", "BZIP2", "XZ", "7z", "RAR", "CAB", "ISO")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and is_archive(record)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        suffix = record.path.lower()
        if family_of(record.file_type) == "zip" or suffix.endswith((
            ".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".whl", ".egg", ".nupkg",
        )):
            return self._zip(path, record, _Limits())
        if record.file_type == "archive/tar" or suffix.endswith((
            ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
        )):
            return self._tar(path, record, _Limits())
        inspection = _Inspection(record, _archive_format(record), _Limits())
        inspection.unsupported = True
        inspection.emit()
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

    def budget_stopped(self, record: FileRecord, stop) -> None:
        """The engine stopped this analyzer on the file: record the archive as budget-stopped."""
        inspection = _Inspection(record, _archive_format(record), _Limits())
        inspection.limit(f"analyzer_{stop.kind}", stop.limit, round(stop.used, 3))
        inspection.emit()

    def _zip(self, path: Path, record: FileRecord, limits: _Limits | None = None, *, data: bytes | None = None,
             depth: int = 0, nested: _Nested | None = None, deadline: float | None = None) -> list[Finding]:
        limits = limits or _Limits()
        nested = nested or _Nested(limits.nested_bytes)
        inspection = _Inspection(record, "zip", limits)
        index_hint = _zip_index_hint(path, record.analysis_identity, data)
        if index_hint is None:
            inspection.malformed = "the central directory could not be bounded from its ZIP/ZIP64 trailer"
            inspection.emit()
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
        entry_count, index_bytes = index_hint
        if (over_limit(entry_count, limits.entries, "entries")
                or over_limit(index_bytes, limits.index_bytes)):
            inspection.declared = entry_count
            if entry_count > limits.entries:
                inspection.limit("entries", limits.entries, entry_count)
            if index_bytes > limits.index_bytes:
                inspection.limit("index_bytes", limits.index_bytes, index_bytes)
            inspection.emit()
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
                    f"entry limit: {limits.entries:,}",
                    f"index-byte limit: {limits.index_bytes:,}",
                ],
                analyzer=self.name,
                severity="MEDIUM",
            )]
        deadline = deadline if deadline is not None else time.monotonic() + limits.wall_seconds
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
            source = open_verified_binary(path, record.analysis_identity) if data is None else io.BytesIO(data)
            with source as archive_stream, zipfile.ZipFile(archive_stream, "r") as archive:
                infos = archive.infolist()
                total = len(infos)
                inspection.index_read, inspection.declared, inspection.compressed_bytes = True, total, 0
                duplicates = [
                    name for name, count in Counter(
                        item.filename for item in infos
                    ).items() if count > 1
                ]
                collisions = _colliding_names({item.filename for item in infos})
                archive_stream.seek(0, 2)
                structure, structure_stopped = _zip_structure_issues(
                    archive_stream, infos[:limits.entries], archive.start_dir, archive_stream.tell(), deadline,
                )
                if structure_stopped:
                    time_budget_reached = True
                for ordinal, info in enumerate(infos[:limits.entries]):
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
                    # A FIFO, socket or device node among the members is read as a file, as
                    # before, but its record names it.
                    file_type = stat.S_IFMT(mode)
                    record_kind = "special" if kind == "file" and file_type and file_type != stat.S_IFREG else kind
                    flags = ["encrypted"] if encrypted_member else []
                    if _unsafe_member_path(info.filename):
                        unsafe_paths.append(info.filename)
                        flags.append("unsafe-path")
                    if encrypted_member:
                        encrypted += 1
                    for risk in _mode_risks(mode):
                        risky_modes.append(f"{info.filename} ({risk})")
                        flags.append(risk)
                    if info.file_size > 0 and (
                        info.compress_size == 0
                        or info.file_size / max(info.compress_size, 1) > limits.compression_ratio
                    ):
                        high_ratios.append(info.filename)
                        flags.append("high-ratio")
                    inspection.compressed_bytes += info.compress_size
                    flags.extend(structure.get(ordinal, ()))
                    link_target = None

                    # An overlapping member is reported already; opening it re-reads another's data, and
                    # zipfile warns (or, in some versions, refuses): it is not read at all.
                    overlapped = "overlapping" in structure.get(ordinal, ())
                    readable = not encrypted_member and not overlapped
                    if overlapped and kind in {"file", "symlink"}:
                        content_truncated += 1
                        inspection.truncated += 1
                    nested_kind = _nested_kind(info.filename) if kind == "file" and readable else None
                    inspect_nested = False
                    if nested_kind is not None:
                        flags.append("nested-archive")
                        if depth >= limits.nested_depth:
                            inspection.limit("nested_depth", limits.nested_depth, members=1)
                        elif info.file_size > nested.remaining:
                            inspection.limit("nested_bytes", limits.nested_bytes, members=1)
                        else:
                            inspect_nested = True
                    if inspect_nested:
                        # Read whole (it fits the nested budget) and inspected like a file, in memory.
                        try:
                            with archive.open(info, "r") as member_stream:
                                inner = member_stream.read(info.file_size + 1)
                            nested.remaining -= len(inner)
                            content_findings.extend(self._nested(
                                inner, f"{record.path}::{info.filename}", nested_kind, limits, depth + 1, nested, deadline,
                            ))
                            if time.monotonic() >= deadline:
                                time_budget_reached = True
                        except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError):
                            content_truncated += 1
                            inspection.truncated += 1
                    elif readable and kind in {"file", "symlink"}:
                        remaining = limits.archive_sample_bytes - content_bytes
                        if remaining <= 0:
                            content_truncated += 1
                            inspection.skipped_sample()
                        else:
                            try:
                                with archive.open(info, "r") as member_stream:
                                    sample, consumed, truncated = _read_member_sample(
                                        member_stream, remaining, deadline, limits.member_sample_bytes
                                    )
                                content_bytes += consumed
                                inspection.sample(kind, info.file_size, consumed, truncated, remaining)
                                if time.monotonic() >= deadline:
                                    time_budget_reached = True
                                if truncated or info.file_size > consumed:
                                    content_truncated += 1
                                if kind == "symlink":
                                    target = sample.decode("utf-8", errors="replace").strip("\x00")
                                    link_target = target or None
                                    if target and _unsafe_member_path(target):
                                        unsafe_paths.append(f"{info.filename} -> {target}")
                                        if "unsafe-path" not in flags:
                                            flags.append("unsafe-path")
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
                                inspection.truncated += 1
                    inspection.member(ordinal, info.filename, record_kind, info.file_size, info.compress_size,
                                      mode, _zip_time(info.date_time), flags, link_target)
                    if time_budget_reached:
                        break

        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
            inspection.malformed = describe_error(exc)
            inspection.encrypted = encrypted
            inspection.emit()
            return [Finding(
                "archive",
                f"ZIP metadata read error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
                evidence=[record.path],
                analyzer=self.name,
            )]

        inspection.encrypted = encrypted
        structure_counts = Counter(issue for found in structure.values() for issue in found)
        if structure_counts:
            inspection.extra["structure_issues"] = {
                name.replace("-", "_"): structure_counts[name]
                for name in ("header-mismatch", "descriptor-mismatch", "out-of-bounds", "overlapping")
            }
        if structure_counts["out-of-bounds"]:
            inspection.malformed = (f"{structure_counts['out-of-bounds']:,} member(s) extend past the central "
                                    "directory or the end of the file")
        if entry_count != total:
            # zipfile reads the directory by its size, not its declared count: a count that disagrees
            # marks a truncated or rewritten directory.
            inspection.declared = max(entry_count, total)
            inspection.extra["declared_entries"] = entry_count
        declared_bytes = sum(item.file_size for item in infos)
        if declared_bytes > limits.uncompressed_bytes:
            inspection.limit("uncompressed_bytes", limits.uncompressed_bytes, declared_bytes)
        if duplicates:
            inspection.flag_duplicates(item.filename for item in infos)
        if time_budget_reached:
            inspection.limit("wall_seconds", limits.wall_seconds)
        if total > limits.entries:
            inspection.limit("entries", limits.entries, total)
        inspection.emit()
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
            f"Indexed {min(total, limits.entries)} of {total} member(s); "
            f"compressed file size {record.size_bytes:,} bytes. Member bytes were inspected "
            "only through bounded in-memory streams; no member was written to disk.",
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer=self.name,
        )]
        if over_limit(total, limits.entries, "entries"):
            findings.append(Finding(
                "archive",
                f"ZIP entry limit reached: {record.path}",
                f"Archive contains {total} entries; metadata analysis was limited to "
                f"{limits.entries}.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        findings.extend(self._risk_findings(
            record, unsafe_paths, symlinks, risky_modes, high_ratios, duplicates, encrypted
        ))
        if declared_bytes > limits.uncompressed_bytes:
            findings.append(self._bomb_finding(record, declared_bytes, limits))
        findings.extend(self._structure_findings(record, infos, structure, structure_counts, entry_count, total))
        if collisions:
            findings.append(self._collision_finding(record, collisions))
        findings.extend(content_findings)
        if content_truncated:
            limit_reached("bytes", limits.archive_sample_bytes)
            findings.append(Finding(
                "archive",
                f"ZIP member content budget reached: {record.path}",
                f"Content inspection was limited to {limits.archive_sample_bytes:,} total "
                f"in-memory bytes and {limits.member_sample_bytes:,} bytes per member. "
                f"{content_truncated} member(s) were not fully inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        if time_budget_reached:
            limit_reached("wall_time", limits.wall_seconds)
            findings.append(Finding(
                "archive",
                f"ZIP wall-time budget reached: {record.path}",
                f"Archive inspection stopped after the {limits.wall_seconds:g}-second "
                "wall-time budget. Findings already collected are partial; remaining entries "
                "were not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

    def _tar(self, path: Path, record: FileRecord, limits: _Limits | None = None, *, data: bytes | None = None,
             depth: int = 0, nested: _Nested | None = None, deadline: float | None = None) -> list[Finding]:
        """Traverse every TAR header under budgets; content sampling never ends traversal.

        Stopping at the first large member would hide later traversal, link and setuid
        entries, so sampling limits only skip sampling. Compressed streams are read through
        a budgeted reader that enforces wall time and decompressed bytes inside each read.
        """
        limits = limits or _Limits()
        nested = nested or _Nested(limits.nested_bytes)
        inspection = _Inspection(record, "tar", limits)
        deadline = deadline if deadline is not None else time.monotonic() + limits.wall_seconds
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
        declared_bytes = 0
        compressed = False
        try:
            source = (open_verified_binary(path, record.analysis_identity) if data is None
                      else io.BufferedReader(io.BytesIO(data)))  # buffered: the decompressor peeks
            with source as archive_stream:
                decompressor = _tar_decompressor(archive_stream)
                if decompressor is None:
                    # Plain TAR on a seekable descriptor: headers are reached by seeking.
                    archive = tarfile.open(fileobj=archive_stream, mode="r:")
                else:
                    compressed = True
                    inspection.format = "tar+" + (
                        "gzip" if isinstance(decompressor, gzip.GzipFile)
                        else "bzip2" if isinstance(decompressor, bz2.BZ2File) else "xz"
                    )
                    archive = tarfile.open(
                        fileobj=_BudgetedReader(decompressor, deadline, limits.tar_decompressed_bytes),
                        mode="r|",
                    )
                with archive:
                    inspection.index_read = True
                    try:
                        for member in archive:
                            if time.monotonic() >= deadline:
                                time_budget_reached = True
                                break
                            total += 1
                            if total > limits.entries:  # recorded with the finding below
                                break
                            names.append(member.name)
                            declared_bytes += max(0, member.size)
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
                            linked = member.issym() or member.islnk()
                            flags = []
                            if _unsafe_member_path(member.name) or (
                                linked
                                and _unsafe_member_path(member.linkname)
                            ):
                                unsafe_paths.append(member.name)
                                flags.append("unsafe-path")
                            for risk in _mode_risks(member.mode):
                                risky_modes.append(f"{member.name} ({risk})")
                                flags.append(risk)
                            nested_kind = _nested_kind(member.name) if kind == "file" else None
                            if nested_kind is not None:
                                flags.append("nested-archive")
                            inspection.member(
                                total - 1, member.name, kind, member.size, None, member.mode,
                                _tar_time(member.mtime), flags, member.linkname if linked else None,
                                member.uid, member.gid, member.uname or None, member.gname or None,
                            )

                            if kind != "file":
                                continue
                            if nested_kind is not None:
                                if depth >= limits.nested_depth:
                                    inspection.limit("nested_depth", limits.nested_depth, members=1)
                                elif member.size > nested.remaining:
                                    inspection.limit("nested_bytes", limits.nested_bytes, members=1)
                                else:
                                    member_stream = archive.extractfile(member)
                                    if member_stream is not None:
                                        with member_stream:
                                            inner = member_stream.read(member.size + 1)
                                        nested.remaining -= len(inner)
                                        content_findings.extend(self._nested(
                                            inner, f"{record.path}::{member.name}", nested_kind, limits,
                                            depth + 1, nested, deadline,
                                        ))
                                        if time.monotonic() >= deadline:
                                            time_budget_reached = True
                                            break
                                    continue
                            remaining = limits.archive_sample_bytes - content_bytes
                            if remaining <= 0:
                                content_truncated += 1
                                inspection.skipped_sample()
                                continue
                            member_stream = archive.extractfile(member)
                            if member_stream is None:
                                continue
                            with member_stream:
                                sample, consumed, truncated = _read_member_sample(
                                    member_stream, remaining, deadline, limits.member_sample_bytes
                                )
                            content_bytes += consumed
                            inspection.sample(kind, member.size, consumed, truncated, remaining)
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
            inspection.malformed = describe_error(exc)
            inspection.emit()
            return [Finding(
                "archive",
                f"TAR metadata read error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
                evidence=[record.path],
                analyzer=self.name,
            )]

        indexed = min(total, limits.entries)
        traversal_complete = not (time_budget_reached or stop_reason or total > limits.entries)
        inspection.flag_duplicates(names)
        if traversal_complete:
            inspection.declared = indexed  # every header was read: the archive holds no more
        if compressed:
            inspection.compressed_bytes = record.size_bytes
        if time_budget_reached:
            inspection.limit("wall_seconds", limits.wall_seconds)
        if stop_reason and not time_budget_reached:
            inspection.limit("tar_decompressed_bytes", limits.tar_decompressed_bytes)
        if total > limits.entries:
            inspection.limit("entries", limits.entries)
        if declared_bytes > limits.uncompressed_bytes:
            inspection.limit("uncompressed_bytes", limits.uncompressed_bytes, declared_bytes)
        inspection.emit()
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
            limit_reached("bytes", limits.tar_decompressed_bytes)
            findings.append(Finding(
                "archive",
                f"TAR decompression budget reached: {record.path}",
                f"Traversal stopped after {limits.tar_decompressed_bytes:,} decompressed bytes. "
                "Members after that point were not indexed; this is not a clean result.",
                confidence="UNKNOWN",
                evidence=[record.path, f"members_indexed: {indexed:,}"],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        collisions = _colliding_names(names)
        if collisions:
            findings.append(self._collision_finding(record, collisions))
        if over_limit(total, limits.entries, "entries"):
            findings.append(Finding(
                "archive",
                f"TAR entry limit reached: {record.path}",
                f"Metadata traversal stopped after {limits.entries} members.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        findings.extend(self._risk_findings(
            record, unsafe_paths, symlinks, risky_modes, [], [], 0
        ))
        if declared_bytes > limits.uncompressed_bytes:
            findings.append(self._bomb_finding(record, declared_bytes, limits))
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
            limit_reached("bytes", limits.archive_sample_bytes)
            findings.append(Finding(
                "archive",
                f"TAR member content budget reached: {record.path}",
                f"Content inspection was limited to {limits.archive_sample_bytes:,} total "
                f"in-memory bytes and {limits.member_sample_bytes:,} bytes per member. "
                f"{content_truncated} member(s) were not fully inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        if time_budget_reached:
            limit_reached("wall_time", limits.wall_seconds)
            findings.append(Finding(
                "archive",
                f"TAR wall-time budget reached: {record.path}",
                f"Archive inspection stopped after the {limits.wall_seconds:g}-second "
                "wall-time budget. Findings already collected are partial; remaining entries "
                "were not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

    def _nested(self, data: bytes, display: str, kind: str, limits: _Limits, depth: int, nested: _Nested,
                deadline: float) -> list[Finding]:
        """Inspect a member that is itself an archive, from its bytes in memory; its archive and
        member records and findings name it "outer.zip::inner.jar"."""
        name = display.rsplit("::", 1)[-1]
        record = FileRecord(display, len(data), PurePosixPath(name).suffix.lower(), "Archive",
                            file_type="archive/zip" if kind == "zip" else "archive/tar")
        inspect = self._zip if kind == "zip" else self._tar
        return inspect(Path(name), record, limits, data=data, depth=depth, nested=nested, deadline=deadline)

    def _structure_findings(self, record: FileRecord, infos, structure: dict[int, list[str]],
                            counts: Counter, declared: int, total: int) -> list[Finding]:
        """Findings for overlapping members, headers that disagree, truncation and a wrong entry count."""
        def named(issue: str) -> list[str]:
            return [f"{record.path}::{infos[index].filename}" for index, found in sorted(structure.items())
                    if issue in found][:_MAX_EVIDENCE]

        findings = []
        if counts["overlapping"]:
            findings.append(Finding(
                "security", f"Overlapping ZIP members: {record.path}",
                f"{counts['overlapping']:,} member(s) share or overlap their compressed data, the construction "
                "of non-recursive zip bombs: extracting them writes far more data than the archive holds.",
                confidence="CONFIRMED", evidence=named("overlapping"), analyzer=self.name, severity="HIGH",
            ))
        mismatched = counts["header-mismatch"] + counts["descriptor-mismatch"]
        if mismatched:
            findings.append(Finding(
                "security", f"ZIP local headers disagree with the central directory: {record.path}",
                f"{mismatched:,} member(s) have a local header or data descriptor that names another file, "
                "method, CRC or size than the central directory. Tools that read local headers (streaming "
                "extractors, some scanners) see a different archive from tools that read the directory.",
                confidence="CONFIRMED", evidence=named("header-mismatch") + named("descriptor-mismatch"),
                analyzer=self.name, severity="MEDIUM",
            ))
        if counts["out-of-bounds"]:
            findings.append(Finding(
                "archive", f"Truncated or corrupt ZIP members: {record.path}",
                f"{counts['out-of-bounds']:,} member(s) extend past the central directory or the end of the "
                "file, so their data is incomplete; their contents were not fully inspected.",
                confidence="UNKNOWN", evidence=named("out-of-bounds"), analyzer=self.name, severity="MEDIUM",
            ))
        if declared != total:
            findings.append(Finding(
                "archive", f"ZIP entry count disagrees with its central directory: {record.path}",
                f"The end-of-directory record declares {declared:,} entries; the central directory holds "
                f"{total:,}. The directory is truncated or was rewritten.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name, severity="MEDIUM",
            ))
        return findings

    def _bomb_finding(self, record: FileRecord, declared_bytes: int, limits: _Limits) -> Finding:
        return Finding(
            "security",
            f"Archive declares more uncompressed data than its budget: {record.path}",
            f"Its members declare {declared_bytes:,} uncompressed bytes, more than the "
            f"{limits.uncompressed_bytes:,}-byte budget (--archive-limit uncompressed_mb). Extracting it "
            "could exhaust disk or memory (an archive bomb); PDT decompressed no more than its bounded samples.",
            confidence="INFERRED",
            evidence=[record.path, f"declared uncompressed bytes: {declared_bytes:,}"],
            analyzer=self.name,
            severity="HIGH",
        )

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
