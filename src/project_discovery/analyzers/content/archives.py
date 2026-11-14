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
from collections import Counter, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ...core.limits import AnalyzerLimits, limit_overrides, limit_reached, over_limit
from ...core.source_utils import (
    LineIndex,
    describe_error,
    open_verified_binary,
    redact_source_excerpt,
)
from ...intelligence.facts import (
    MAX_ARCHIVE_MEMBERS_PER_FILE,
    current_facts,
    emit_archive,
    emit_archive_member,
)
from ...inventory.signatures import ARCHIVE_FAMILIES, family_of, is_archive
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer
from ..security.privacy import personal_email_matches
from ..security.secrets import credential_matches
from .archive_formats import (
    ZSTD_ERRORS,
    ZSTD_UNAVAILABLE,
    ArchiveFormatError,
    ArchiveLimitError,
    ArchiveUnsupportedError,
    read_7z,
    read_ar,
    read_cab,
    read_compressed,
    read_iso,
    read_rar,
    read_rpm,
    zstd_reader,
)
from .packages import MANIFEST_BYTES, Packages

_MAX_ARCHIVE_ENTRIES = 200_000
_MAX_ARCHIVE_INDEX_BYTES = 64 * 1024 * 1024


def _zip_index_hint(
    path: Path,
    expected_identity: tuple[int | None, int | None, int | None, int | None, int | None] | None = None,
    data=None,
) -> tuple[int, int] | None:
    """Read ZIP/ZIP64 bounds through a verified no-follow descriptor, or from a nested archive's
    bytes or slice."""
    try:
        with (open_verified_binary(path, expected_identity) if data is None else _open_data(data)) as stream:
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
_ZSTD_MAX_WINDOW = 1 << 27  # libzstd's default decoder window limit, which both decompressors keep
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


class _Unsupported(Exception):
    """This installation cannot read the archive (a decompressor it does not have)."""


def _decompressor(stream, codec: str | None = None):
    """(codec, decompressing file object) for a gzip, bzip2, xz or Zstandard stream by its
    signature, or for LZMA (which has none) when ``codec`` says so; (None, None) for anything
    else. Raises _Unsupported for Zstandard without a decompressor."""
    head = stream.peek(6)[:6]
    if head.startswith(b"\x1f\x8b"):
        return "gzip", gzip.GzipFile(fileobj=stream, mode="rb")
    if head.startswith(b"BZh"):
        return "bzip2", bz2.BZ2File(stream)
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz", lzma.LZMAFile(stream)
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        reader = zstd_reader(stream)
        if reader is None:
            raise _Unsupported(ZSTD_UNAVAILABLE)
        return "zstd", reader
    if codec == "lzma" and not _tar_header(stream.peek(512)[:512]):
        return "lzma", lzma.LZMAFile(stream, format=lzma.FORMAT_ALONE)
    return None, None


def _tar_header(block: bytes) -> bool:
    """Whether ``block`` starts with a TAR header (its checksum is valid)."""
    if len(block) < 512:
        return False
    try:
        stored = int(block[148:156].strip(b" \x00") or b"-1", 8)
    except ValueError:
        return False
    return stored == sum(block[:148]) + 8 * 32 + sum(block[156:512])


@dataclass(frozen=True, slots=True)
class _Slice:
    """``length`` bytes at ``offset`` of an open seekable stream: a member stored as is (an ar
    member), inspected in place instead of buffered in memory."""

    stream: Any
    offset: int
    length: int


class _Window(io.RawIOBase):
    """A read-only, seekable view of a slice; closing it leaves the stream open."""

    def __init__(self, part: _Slice) -> None:
        self._part, self._position = part, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, position: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._position, io.SEEK_END: self._part.length}[whence]
        self._position = max(0, base + position)
        return self._position

    def readinto(self, buffer) -> int:
        count = min(len(buffer), self._part.length - self._position)
        if count <= 0:
            return 0
        self._part.stream.seek(self._part.offset + self._position)
        data = self._part.stream.read(count)
        memoryview(buffer)[:len(data)] = data
        self._position += len(data)
        return len(data)


def _open_data(data: bytes | _Slice, buffered: bool = False):
    """A stream over a nested archive's bytes, or over a slice of its container."""
    if isinstance(data, _Slice):
        return io.BufferedReader(_Window(data))
    return io.BufferedReader(io.BytesIO(data)) if buffered else io.BytesIO(data)


def _data_size(data: bytes | _Slice) -> int:
    return data.length if isinstance(data, _Slice) else len(data)


class _Recorder(io.RawIOBase):
    """Passes reads through and keeps the last bytes read, so the block tarfile stopped at can be
    looked at in a stream that cannot seek back."""

    _KEEP = 64 * 1024

    def __init__(self, inner) -> None:
        self._inner, self._tail, self._tail_start = inner, bytearray(), 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        data = self._inner.read(len(buffer))
        memoryview(buffer)[:len(data)] = data
        self._tail += data
        if len(self._tail) > 2 * self._KEEP:
            drop = len(self._tail) - self._KEEP
            del self._tail[:drop]
            self._tail_start += drop
        return len(data)

    def block(self, offset: int) -> bytes | None:
        start = offset - self._tail_start
        if start < 0 or start + 512 > len(self._tail):
            return None
        return bytes(self._tail[start:start + 512])


class _Chain(io.RawIOBase):
    """``first``, then the rest of a stream."""

    def __init__(self, first: bytes, rest) -> None:
        self._first, self._rest = memoryview(first), rest

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        if self._first:
            count = min(len(buffer), len(self._first))
            memoryview(buffer)[:count] = self._first[:count]
            self._first = self._first[count:]
            return count
        data = self._rest.read(len(buffer))
        memoryview(buffer)[:len(data)] = data
        return len(data)


def _read_block(stream) -> bytes:
    """Up to 512 bytes, read until the stream ends."""
    data = b""
    while len(data) < 512:
        chunk = stream.read(512 - len(data))
        if not chunk:
            break
        data += chunk
    return data


_TRAILING_SCAN = 1 << 20  # bytes after the end-of-archive blocks looked at for data


class _TarSegments:
    """A TAR stream's members, read on where Python's tarfile stops but GNU tar does not.

    tarfile ends a listing at the first header that fails its checksum and at the first zero
    block; GNU tar skips a bad header to the next valid one ("Skipping to next header") and
    reads on past a lone zero block, extracting what follows. A crafted checksum can so hide
    members from tools built on tarfile (or 7-Zip) but not from extraction: this listing
    resumes where GNU tar would, and records each corrupt header, lone zero block and the
    data after the end-of-archive blocks.
    """

    def __init__(self, archive, stream, size: int | None, recorder: _Recorder | None, deadline: float) -> None:
        self.first, self.stream, self.size, self.recorder, self.deadline = archive, stream, size, recorder, deadline
        self.corrupt: list[int] = []  # offsets of headers that fail their checksum
        self.lone_zero: list[int] = []
        self.trailing = 0  # non-zero bytes after the end-of-archive blocks (in the first MiB)
        self.resumed = 0  # members listed after a corrupt header or a lone zero block
        self.opened: list = []

    def __iter__(self):
        segment, base, recorder = self.first, 0, self.recorder
        while segment is not None:
            for member in segment:
                if base:
                    self.resumed += 1
                yield segment, member
            segment, base, recorder = self._resume(segment, base, recorder)

    def close(self) -> None:
        for segment in self.opened:
            segment.close()

    def _resume(self, segment, base: int, recorder: _Recorder | None):
        try:
            return self._next_segment(segment, base, recorder)
        except (OSError, EOFError, lzma.LZMAError, tarfile.TarError, *ZSTD_ERRORS):
            # What follows the stop does not decompress or parse (a compressed stream's
            # trailing bytes): the listing ends there, as it would have.
            return None, 0, None

    def _next_segment(self, segment, base: int, recorder: _Recorder | None):
        stop = base + segment.offset  # where tarfile stopped: a zero block, a bad header or the end
        if recorder is None:  # the first segment of a plain TAR, on a seekable stream
            rest = io.BufferedReader(_Window(_Slice(self.stream, stop, max(0, self.size - stop))))
            block = _read_block(rest)
        else:  # a stream: tarfile has read the block; the recorder kept it
            block = recorder.block(segment.offset)
            rest = segment.fileobj
            if block is None:
                return None, 0, None
        if len(block) < 512:
            return None, 0, None  # the end of the data (a short tail is tarfile's to report)
        position = stop + 512
        if not block.strip(b"\x00"):
            candidate = _read_block(rest)
            if not candidate.strip(b"\x00"):  # two zero blocks: the end of the archive
                tail = rest.read(_TRAILING_SCAN)
                self.trailing = len(tail) - tail.count(0)
                return None, 0, None
            self.lone_zero.append(stop)
        else:
            self.corrupt.append(stop)
            candidate = _read_block(rest)
        while len(candidate) == 512 and not _tar_header(candidate):  # GNU tar: skip to the next header
            if position % (1 << 20) == 0 and time.monotonic() >= self.deadline:
                raise _ArchiveBudgetExceeded("wall-time budget reached")
            position += 512
            candidate = _read_block(rest)
        if len(candidate) < 512:
            return None, 0, None
        recorder = _Recorder(_Chain(candidate, rest))
        following = tarfile.open(fileobj=recorder, mode="r|")
        self.opened.append(following)
        return following, position, recorder


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


_MAX_LINK_HOPS = 40  # links followed in one resolution, as Linux allows before ELOOP


def _archive_path(name: str) -> str:
    """A member name as a path inside the archive: forward slashes, no "./" or trailing "/"."""
    parts = [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")]
    return "/".join(parts)


def _resolve(path: str, links: dict[str, str]) -> str | None:
    """Where an archive path leads through the archive's own symlinks: None, "escape" (out of
    the archive's root, or to an absolute path) or "loop" (more links than Linux follows)."""
    pending = deque(part for part in path.split("/") if part not in ("", "."))
    resolved: list[str] = []
    hops = 0
    while pending:
        part = pending.popleft()
        if part == "..":
            if not resolved:
                return "escape"
            resolved.pop()
            continue
        target = links.get("/".join(resolved + [part]))
        if target is None:
            resolved.append(part)
            continue
        hops += 1
        if hops > _MAX_LINK_HOPS:
            return "loop"
        normalized = target.replace("\\", "/")
        if normalized.startswith("/") or _PATH_DRIVE.match(normalized):
            return "escape"
        pending.extendleft(reversed([item for item in normalized.split("/") if item not in ("", ".")]))
    return None


def _link_issues(members, links: dict[str, str], hardlinks: dict[str, str] | None = None,
                 check_escapes: bool = True) -> dict[str, str]:
    """Members whose resolution through the archive's symlinks loops ("symlink-loop") or, for
    a member written through a symlinked directory or a link resolving through one, leaves the
    archive ("unsafe-path"): what an extractor following the links would do.

    ``members`` are member names, ``links`` {symlink: target} and ``hardlinks``
    {hard link: target member}; a package payload's links point anywhere by design, so
    ``check_escapes`` False looks for loops only."""
    if not links:
        return {}
    table = {_archive_path(name): target for name, target in links.items()}
    issues: dict[str, str] = {}
    for name, target in links.items():
        key = _archive_path(name)
        parent = key.rpartition("/")[0]
        normalized = target.replace("\\", "/")
        if normalized.startswith("/") or _PATH_DRIVE.match(normalized):
            outcome = "escape"  # an absolute target, wherever the link sits
        else:
            outcome = _resolve(f"{parent}/{normalized}" if parent else normalized, table)
        if outcome == "loop":
            issues[name] = "symlink-loop"
        elif outcome == "escape" and check_escapes:
            issues[name] = "unsafe-path"
    for name, target in (hardlinks or {}).items():
        outcome = _resolve(_archive_path(target), table)
        if outcome == "loop" or (outcome == "escape" and check_escapes):
            issues[name] = "symlink-loop" if outcome == "loop" else "unsafe-path"
    for name in members:
        key = _archive_path(name)
        if name in issues or key in table or "/" not in key:
            continue
        prefix, through = "", False
        for part in key.split("/")[:-1]:
            prefix = f"{prefix}/{part}" if prefix else part
            if prefix in table:
                through = True
                break
        if not through:
            continue
        outcome = _resolve(key.rpartition("/")[0], table)
        if outcome == "loop" or (outcome == "escape" and check_escapes):
            issues[name] = "symlink-loop" if outcome == "loop" else "unsafe-path"
    return issues


def _unsafe_package_path(name: str) -> bool:
    """A package path that escapes its root (absolute paths are where a package installs)."""
    normalized = name.replace("\\", "/")
    return _PATH_DRIVE.match(normalized) is not None or ".." in PurePosixPath(normalized).parts


def _package_text(package: dict) -> str:
    """"name version (ecosystem)" of a language package found in an archive."""
    name = " ".join(str(part) for part in (package.get("name"), package.get("version")) if part)
    return f"{name or 'unnamed'} ({package['ecosystem']})"


def _package_part(archive: str, member: str) -> bool:
    """Whether a nested archive belongs to its container's package: a conda package's info tarball."""
    return archive.lower().endswith(".conda") and PurePosixPath(member.replace("\\", "/")).name.startswith("info-")


def _package_label(metadata: dict) -> str | None:
    """"name version (architecture)" of a DEB or RPM package, from its reader's metadata."""
    deb, rpm = metadata.get("deb") or {}, metadata.get("rpm") or {}
    if deb.get("package"):
        name, version, arch = deb["package"], deb.get("version"), deb.get("architecture")
    elif rpm.get("name"):
        name, arch = rpm["name"], rpm.get("arch")
        version = "-".join(str(part) for part in (rpm.get("version"), rpm.get("release")) if part)
    else:
        return None
    return " ".join(part for part in (name, version, f"({arch})" if arch else None) if part)


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
        return datetime.fromtimestamp(float(mtime), UTC).isoformat().replace("+00:00", "Z")
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


_NESTED_ZIP_SUFFIXES = (".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".whl", ".egg", ".nupkg", ".conda",
                        ".vsix")
_NESTED_TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tzst",
                        ".tar.lzma", ".tlz", ".gem", ".crate")
_TAR_SUFFIXES = _NESTED_TAR_SUFFIXES
_STREAM_SUFFIXES = (".gz", ".bz2", ".xz", ".lzma", ".zst")
# Member names these readers inspect as archives, most specific first (.tar.gz before .gz).
_NESTED_KINDS = (
    (_NESTED_ZIP_SUFFIXES, "zip"), (_NESTED_TAR_SUFFIXES, "tar"), ((".deb", ".udeb"), "ar"), ((".rpm",), "rpm"),
    ((".cab",), "cab"), ((".iso",), "iso"), ((".7z",), "7z"), ((".rar",), "rar"), (_STREAM_SUFFIXES, "stream"),
)
_NESTED_TYPES = {"zip": "archive/zip", "tar": "archive/tar", "ar": "archive/deb", "rpm": "archive/rpm",
                 "cab": "archive/cab", "iso": "disk-image/iso9660", "7z": "archive/7z", "rar": "archive/rar",
                 "stream": "archive/compressed"}
# The readers by content family, then by name: a name decides unless the content is another
# archive format (a .zip holding a RAR archive). Compressed content is a TAR stream under a TAR
# name (.tgz, .tar.zst, .ipk) and otherwise a single compressed file, whose content may still
# turn out to be TAR. Content whose start is no archive (a .jar behind a launcher script, a
# self-extracting .zip) is read by name, as ZIP readers find the directory from the end.
_READER_FAMILIES = {"zip": "zip", "tar": "tar", "ar": "ar", "cab": "cab", "rpm": "rpm", "iso9660": "iso",
                    "udf": "iso", "7z": "7z", "rar": "rar"}
_COMPRESSION_FAMILIES = frozenset({"gzip", "bzip2", "xz", "lzma", "zstandard"})
_READER_SUFFIXES = (
    (_NESTED_ZIP_SUFFIXES, "zip"), (_TAR_SUFFIXES + (".ipk",), "tar"), ((".deb", ".udeb"), "ar"),
    ((".cab",), "cab"), ((".rpm",), "rpm"), ((".iso",), "iso"), ((".7z",), "7z"), ((".rar",), "rar"),
    (_STREAM_SUFFIXES, "stream"),
)
_CODEC_FAMILIES = {"gzip": "gzip", "bzip2": "bzip2", "xz": "xz", "lzma": "lzma", "zstandard": "zstd"}
_CODEC_SUFFIXES = (
    ((".gz", ".tgz", ".svgz"), "gzip"), ((".bz2", ".tbz2", ".tbz"), "bzip2"), ((".xz", ".txz"), "xz"),
    ((".lzma", ".tlz"), "lzma"), ((".zst", ".tzst"), "zstd"),
)
# What a compressed file's member is called when its header names none: its name without the suffix.
_UNCOMPRESSED_SUFFIXES = {".tgz": ".tar", ".tbz2": ".tar", ".tbz": ".tar", ".txz": ".tar", ".tzst": ".tar",
                          ".tlz": ".tar", ".svgz": ".svg"}


def _reader(record: FileRecord) -> str | None:
    """The reader for an archive record ("zip", "tar", "ar", "cab", "rpm", "iso", "7z", "rar" or "stream"),
    or None."""
    family = family_of(record.file_type)
    if family in _READER_FAMILIES:
        return _READER_FAMILIES[family]
    lowered = record.path.lower()
    if family in _COMPRESSION_FAMILIES:
        return "tar" if lowered.endswith(_TAR_SUFFIXES + (".ipk",)) else "stream"
    for suffixes, reader in _READER_SUFFIXES:
        if lowered.endswith(suffixes):
            if record.file_type.startswith("archive/") or family in ARCHIVE_FAMILIES:
                return None
            return reader
    return None


def _codec(name: str, file_type: str = "") -> str | None:
    """The compression of a single compressed file, by its content family, else by its name."""
    family = family_of(file_type)
    if family in _CODEC_FAMILIES:
        return _CODEC_FAMILIES[family]
    lowered = name.lower()
    for suffixes, codec in _CODEC_SUFFIXES:
        if lowered.endswith(suffixes):
            return codec
    return None


def _uncompressed_name(name: str) -> str:
    """A compressed file's name without its compression suffix (app.log.gz: app.log)."""
    base = PurePosixPath(name.replace("\\", "/")).name
    suffix = PurePosixPath(base).suffix.lower()
    if suffix in _UNCOMPRESSED_SUFFIXES:
        return base[:-len(suffix)] + _UNCOMPRESSED_SUFFIXES[suffix]
    return base[:-len(suffix)] if suffix in _STREAM_SUFFIXES and len(base) > len(suffix) else base


def _nested_kind(name: str) -> str | None:
    """The reader for a member named like an archive these readers inspect, else None."""
    lowered = name.lower()
    for suffixes, kind in _NESTED_KINDS:
        if lowered.endswith(suffixes):
            return kind
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
        self.unsized = 0  # regular members whose size the format does not say (a bzip2 stream)
        self.compressed_bytes: int | None = None
        self.sampled = 0  # members whose content was read, in part or in full
        self.fully_sampled = 0
        self.sample_bytes = 0
        self.regular_sample_bytes = 0
        self.truncated = 0  # members eligible for sampling that were not read in full
        self.encrypted = 0
        self.headers_encrypted = False  # the index itself is encrypted: no member can be listed
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

    def add_flags(self, flags: dict[str, str]) -> None:
        """Add one flag to each named member's recorded entries (a finding made after the listing)."""
        facts = current_facts()
        if not flags or facts is None:
            return
        records = facts.archive_members
        for index in range(self._first_record, len(records)):
            item = records[index]
            flag = flags.get(item[2]) if item[0] == self.path else None
            if flag and flag not in (item[8] or "").split(","):
                records[index] = (*item[:8], ",".join(filter(None, (item[8], flag))), *item[9:])

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
            self.unsized += size is None
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
        encrypted = self.encrypted > 0 or self.headers_encrypted
        states = ["detected"] + [name for name, applies in (
            ("unsupported", self.unsupported), ("index-read", self.index_read), ("metadata-complete", complete),
            ("sample-read", self.sampled > 0), ("sample-truncated", self.truncated > 0),
            ("encrypted", encrypted), ("malformed", self.malformed is not None), ("budget-stopped", stopped),
        ) if applies]
        state = ("malformed" if self.malformed is not None else "unsupported" if self.unsupported
                 else "encrypted" if self.headers_encrypted else "budget-stopped" if stopped
                 else "metadata-complete" if complete else "index-read" if self.index_read else "detected")
        detail = {
            "archive_bytes": self.record.size_bytes, "compressed_bytes": self.compressed_bytes,
            "members_declared": self.declared, "members_indexed": self.indexed,
            "member_coverage_pct": _pct(self.indexed, self.declared),
            "regular_members": self.regular, "member_bytes": self.regular_bytes,
            "members_sampled": self.sampled, "members_fully_sampled": self.fully_sampled,
            "members_not_fully_sampled": self.truncated, "member_bytes_sampled": self.sample_bytes,
            # Unknown when a member's size is: the share of an undeclared size is not a number.
            "content_coverage_pct": (_pct(self.regular_sample_bytes, self.regular_bytes)
                                     if self.index_read and not self.unsized else None),
            "encrypted_members": self.encrypted, "member_records": self.records,
            "limits": [self.limits[name] for name in sorted(self.limits)],
        }
        if self.unsized:
            detail["members_unsized"] = self.unsized
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
    languages = ("ZIP", "TAR", "GZIP", "BZIP2", "XZ", "LZMA", "Zstandard", "AR", "DEB", "RPM", "CAB", "ISO", "7z", "RAR")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and is_archive(record)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        reader = _reader(record)
        if reader == "zip":
            return self._zip(path, record, _Limits())
        if reader == "tar":
            return self._tar(path, record, _Limits(), codec=_codec(record.path, record.file_type))
        if reader == "stream":
            return self._stream(path, record, _Limits(), _codec(record.path, record.file_type))
        if reader is not None:
            return self._listed(path, record, _Limits(), reader)
        return self._unsupported(_Inspection(record, _archive_format(record), _Limits()))

    def _unsupported(self, inspection: _Inspection, reason: str | None = None) -> list[Finding]:
        """Record an archive this installation has no reader for, or cannot decompress."""
        record = inspection.record
        inspection.unsupported = True
        if reason is not None:
            inspection.extra["unsupported_reason"] = reason
        inspection.emit()
        return [Finding(
            "archive",
            f"Archive/container detected: {record.path}",
            f"Recognized as {record.file_type} or by archive extension. "
            + ("This format does not have a built-in metadata index reader in this installation"
               if reason is None else reason)
            + "; no extraction or decompression was attempted.",
            confidence="CONFIRMED",
            evidence=[record.path, f"{record.size_bytes} bytes"],
            analyzer=self.name,
        )]

    def budget_stopped(self, record: FileRecord, stop) -> None:
        """The engine stopped this analyzer on the file: record the archive as budget-stopped."""
        inspection = _Inspection(record, _archive_format(record), _Limits())
        inspection.limit(f"analyzer_{stop.kind}", stop.limit, round(stop.used, 3))
        inspection.emit()

    def _zip(self, path: Path, record: FileRecord, limits: _Limits | None = None, *,
             data: bytes | _Slice | None = None, depth: int = 0, nested: _Nested | None = None,
             deadline: float | None = None, packages: Packages | None = None) -> list[Finding]:
        limits = limits or _Limits()
        nested = nested or _Nested(limits.nested_bytes)
        own_packages = packages is None  # a conda info tarball reports to its package
        packages = packages or Packages(record.path)
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
        zip_links: dict[str, str] = {}
        crc_mismatches: list[str] = []
        try:
            source = open_verified_binary(path, record.analysis_identity) if data is None else _open_data(data)
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
                # Package manifests first, before the samples spend the wall time: a ZIP can be read
                # in any order, and a wheel's METADATA comes last.
                for ordinal, info in enumerate(infos[:limits.entries]):
                    manifest = packages.wants(info.filename, info.file_size)
                    if (manifest is None or info.is_dir() or info.flag_bits & 0x1
                            or stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF)
                            or "overlapping" in structure.get(ordinal, ())):
                        continue
                    try:
                        with archive.open(info, "r") as manifest_stream:
                            packages.add(manifest, info.filename, manifest_stream.read(MANIFEST_BYTES + 1))
                    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, EOFError):
                        pass
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
                    for risk in _mode_risks(mode) if kind != "symlink" else ():  # a link's own bits are unused
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
                                packages=packages if _package_part(record.path, info.filename) else None,
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
                                    if target:
                                        zip_links[info.filename] = target
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
                            except zipfile.BadZipFile as exc:
                                content_truncated += 1
                                inspection.truncated += 1
                                if "CRC" in str(exc):  # read to its end, the data is not what was written
                                    crc_mismatches.append(info.filename)
                                    flags.append("crc-mismatch")
                            except (OSError, RuntimeError, NotImplementedError, EOFError):
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
        link_issues = _link_issues([info.filename for info in infos[:limits.entries]], zip_links)
        link_loops = self._apply_link_issues(inspection, link_issues, unsafe_paths)
        structure_counts = Counter(issue for found in structure.values() for issue in found)
        if structure_counts or crc_mismatches or link_loops:
            inspection.extra["structure_issues"] = {
                name.replace("-", "_"): structure_counts[name]
                for name in ("header-mismatch", "descriptor-mismatch", "out-of-bounds", "overlapping")
            } | {"crc_mismatches": len(crc_mismatches), "symlink_loops": len(link_loops)}
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
        found_package = packages.result() if own_packages else None
        if found_package:
            inspection.extra["package"] = found_package
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
            evidence=([f"package: {_package_text(found_package)}"] if found_package else []) + evidence,
            analyzer=self.name,
        )]
        findings.extend(self._package_findings(record, found_package))
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
        findings.extend(self._integrity_findings(record, link_loops, crc_mismatches))
        if collisions:
            findings.append(self._collision_finding(record, collisions))
        findings.extend(content_findings)
        findings.extend(self._budget_findings(record, "ZIP", limits, content_truncated, time_budget_reached))
        return findings

    def _tar(self, path: Path, record: FileRecord, limits: _Limits | None = None, *,
             data: bytes | _Slice | None = None, depth: int = 0, nested: _Nested | None = None,
             deadline: float | None = None, package: bool = False, codec: str | None = None,
             packages: Packages | None = None) -> list[Finding]:
        """Traverse every TAR header under budgets; content sampling never ends traversal.

        Stopping at the first large member would hide later traversal, link and setuid
        entries, so sampling limits only skip sampling. Compressed streams are read through
        a budgeted reader that enforces wall time and decompressed bytes inside each read;
        ``codec`` "lzma" names an LZMA stream, which has no signature to find it by.
        A package payload (a DEB's tarballs) has links the package manager installs as links,
        to anywhere: only its member paths are checked for traversal, not its link targets.
        """
        limits = limits or _Limits()
        nested = nested or _Nested(limits.nested_bytes)
        inspection = _Inspection(record, "tar", limits)
        own_packages = packages is None
        packages = packages or Packages(record.path)
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
        tar_links: dict[str, str] = {}
        tar_hardlinks: dict[str, str] = {}
        sparse_members: list[tuple[str, int, int]] = []  # (name, declared size, stored bytes)
        try:
            source = (open_verified_binary(path, record.analysis_identity) if data is None
                      else _open_data(data, buffered=True))  # buffered: the decompressor peeks
            with source as archive_stream:
                codec, decompressor = _decompressor(archive_stream, codec)
                recorder, stream_size = None, None
                if decompressor is None:
                    # Plain TAR on a seekable descriptor: headers are reached by seeking.
                    stream_size = archive_stream.seek(0, io.SEEK_END)
                    archive_stream.seek(0)
                    archive = tarfile.open(fileobj=archive_stream, mode="r:")
                else:
                    compressed = True
                    inspection.format = f"tar+{codec}"
                    recorder = _Recorder(_BudgetedReader(decompressor, deadline, limits.tar_decompressed_bytes))
                    archive = tarfile.open(fileobj=recorder, mode="r|")
                segments = _TarSegments(archive, archive_stream, stream_size, recorder, deadline)
                with archive:
                    inspection.index_read = True
                    try:
                        for segment, member in segments:
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
                                tar_links[member.name] = member.linkname
                            elif member.islnk():
                                kind = "hardlink"
                                hardlinks.append(member.name)
                                tar_hardlinks[member.name] = member.linkname
                            elif member.isreg():
                                kind = "file"
                            else:
                                kind = "special"
                                special_entries.append(member.name)
                            counts[kind] += 1
                            linked = member.issym() or member.islnk()
                            flags = []
                            if _unsafe_member_path(member.name) or (
                                linked and not package
                                and _unsafe_member_path(member.linkname)
                            ):
                                unsafe_paths.append(member.name)
                                flags.append("unsafe-path")
                            for risk in _mode_risks(member.mode) if kind != "symlink" else ():  # unused bits
                                risky_modes.append(f"{member.name} ({risk})")
                                flags.append(risk)
                            if segment is not archive:
                                flags.append("past-corrupt-header")  # tools that stop there miss it
                            if member.issparse():
                                # Extracting it without sparse-file support writes its full size.
                                flags.append("sparse")
                                sparse_members.append((member.name, member.size,
                                                       sum(size for _, size in member.sparse or ())))
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
                            # A streamed member is read once: a manifest's bytes also serve its sample.
                            manifest_data = None
                            manifest = packages.wants(member.name, member.size)
                            if manifest is not None:
                                handle = segment.extractfile(member)
                                if handle is not None:
                                    with handle:
                                        manifest_data = handle.read(MANIFEST_BYTES + 1)
                                    packages.add(manifest, member.name, manifest_data)
                            if nested_kind is not None:
                                if depth >= limits.nested_depth:
                                    inspection.limit("nested_depth", limits.nested_depth, members=1)
                                elif member.size > nested.remaining:
                                    inspection.limit("nested_bytes", limits.nested_bytes, members=1)
                                else:
                                    member_stream = (io.BytesIO(manifest_data) if manifest_data is not None
                                                     else segment.extractfile(member))
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
                            member_stream = (io.BytesIO(manifest_data) if manifest_data is not None
                                             else segment.extractfile(member))
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
                    finally:
                        segments.close()
        except _Unsupported as exc:
            inspection.format = "tar+zstd"
            return self._unsupported(inspection, str(exc))
        except (OSError, tarfile.TarError, EOFError, lzma.LZMAError, *ZSTD_ERRORS) as exc:
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
        found_package = packages.result() if own_packages else None
        if found_package:
            inspection.extra["package"] = found_package
        link_issues = _link_issues(names, tar_links, tar_hardlinks, check_escapes=not package)
        link_loops = self._apply_link_issues(inspection, link_issues, unsafe_paths)
        issues = {"corrupt_headers": len(segments.corrupt), "lone_zero_blocks": len(segments.lone_zero),
                  "trailing_bytes": segments.trailing, "symlink_loops": len(link_loops),
                  "sparse_members": len(sparse_members)}
        if any(issues.values()):
            inspection.extra["structure_issues"] = {name: value for name, value in issues.items() if value}
        if segments.corrupt:
            inspection.malformed = f"{len(segments.corrupt):,} TAR header(s) fail their checksum"
            inspection.extra["corrupt_header_offsets"] = segments.corrupt[:20]
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
            evidence=[record.path] + ([f"package: {_package_text(found_package)}"] if found_package else []),
            analyzer=self.name,
        )]
        findings.extend(self._package_findings(record, found_package))
        findings.extend(self._tar_structure_findings(record, segments))
        findings.extend(self._integrity_findings(record, link_loops, []))
        if sparse_members:
            findings.append(self._sparse_finding(record, sparse_members, limits))
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
        findings.extend(self._link_findings(record, hardlinks, special_entries))
        findings.extend(content_findings)
        findings.extend(self._budget_findings(record, "TAR", limits, content_truncated, time_budget_reached))
        return findings

    def _listed(self, path: Path, record: FileRecord, limits: _Limits | None = None, reader: str = "ar", *,
                data: bytes | _Slice | None = None, depth: int = 0, nested: _Nested | None = None,
                deadline: float | None = None) -> list[Finding]:
        """Inspect an ar (DEB package, static library), Cabinet, RPM or ISO 9660 archive from its
        own headers.

        ar and ISO members are stored as is: each is sampled in place like a TAR member, and
        those named like archives (a DEB's control and data tarballs, the packages on an
        install image) are inspected as nested archives without being buffered. Cabinet and
        RPM member data is compressed and is not read: their records come from the cabinet's
        file table and the RPM header.
        """
        limits = limits or _Limits()
        nested = nested or _Nested(limits.nested_bytes)
        inspection = _Inspection(record, reader, limits)
        deadline = deadline if deadline is not None else time.monotonic() + limits.wall_seconds
        time_budget_reached = False
        counts: Counter[str] = Counter()
        names: list[str] = []
        unsafe_paths: list[str] = []
        symlinks: list[str] = []
        hardlinks: list[str] = []
        risky_modes: list[str] = []
        special_entries: list[str] = []
        high_ratios: list[str] = []
        content_findings: list[Finding] = []
        content_bytes = content_truncated = 0
        try:
            source = open_verified_binary(path, record.analysis_identity) if data is None else _open_data(data)
            with source as stream:
                stream.seek(0, 2)
                size = stream.tell()
                if reader == "ar":
                    listing = read_ar(stream, size, limits.entries, limits.index_bytes, deadline)
                elif reader == "cab":
                    listing = read_cab(stream, size, limits.entries, limits.index_bytes)
                elif reader == "iso":
                    listing = read_iso(stream, size, limits.entries, limits.index_bytes, deadline)
                elif reader == "7z":
                    listing = read_7z(stream, size, limits.entries, limits.index_bytes)
                elif reader == "rar":
                    listing = read_rar(stream, size, limits.entries, deadline)
                else:
                    listing = read_rpm(stream, size, limits.entries, limits.index_bytes)
                deb = "deb" in listing.metadata
                if deb:
                    inspection.format = "deb"
                info = listing.metadata.get(reader, {})
                # An encrypted index (7z -mhe, RAR -hp) lists no member at all.
                inspection.headers_encrypted = bool(info.get("headers_encrypted"))
                inspection.index_read = not inspection.headers_encrypted
                inspection.extra.update(listing.metadata)
                # A solid archive compresses its members together, so a member's own packed size
                # says nothing of its ratio.
                member_ratios = reader in ("7z", "rar") and not info.get("solid")
                encrypted = 0
                # An RPM installs its paths from /: absolute paths are its design, a parent
                # traversal is not, and its links, like any package's, may point anywhere. An
                # image's and a RAR archive's links are checked like a TAR's (7z keeps a link's
                # target in its compressed data).
                unsafe = _unsafe_package_path if reader == "rpm" else _unsafe_member_path
                for ordinal, entry in enumerate(listing.entries):
                    if ordinal % 256 == 0 and time.monotonic() >= deadline:
                        time_budget_reached = True
                        break
                    names.append(entry.name)
                    counts[entry.kind] += 1
                    flags = []
                    if unsafe(entry.name) or (reader in ("iso", "rar") and entry.kind in ("symlink", "hardlink")
                                              and entry.link_target and _unsafe_member_path(entry.link_target)):
                        unsafe_paths.append(entry.name)
                        flags.append("unsafe-path")
                    flags.extend(entry.flags)
                    if entry.kind == "symlink":
                        symlinks.append(entry.name)
                    elif entry.kind == "hardlink":
                        hardlinks.append(entry.name)
                    elif entry.kind == "special":
                        special_entries.append(entry.name)
                    if entry.mode is not None and entry.kind != "symlink":
                        for risk in _mode_risks(entry.mode):
                            risky_modes.append(f"{entry.name} ({risk})")
                            flags.append(risk)
                    if entry.encrypted:
                        encrypted += 1
                        flags.append("encrypted")
                    if (member_ratios and entry.kind == "file" and entry.size and entry.compressed_size is not None
                            and (entry.compressed_size == 0
                                 or entry.size / entry.compressed_size > limits.compression_ratio)):
                        high_ratios.append(entry.name)
                        flags.append("high-ratio")
                    stored = (entry.kind == "file" and entry.offset is not None and entry.size is not None
                              and not entry.encrypted)
                    nested_kind = _nested_kind(entry.name) if stored else None
                    if nested_kind is not None:
                        flags.append("nested-archive")
                    inspection.member(ordinal, entry.name, entry.kind, entry.size, entry.compressed_size,
                                      entry.mode, entry.mtime, flags, entry.link_target, entry.uid, entry.gid,
                                      entry.owner, entry.group)
                    if not stored:
                        continue
                    part = _Slice(stream, entry.offset, entry.size)
                    if nested_kind is not None:
                        if depth >= limits.nested_depth:
                            inspection.limit("nested_depth", limits.nested_depth, members=1)
                        else:
                            # Read in place, so no nested-byte budget applies: a DEB's data
                            # tarball holds the package's files.
                            content_findings.extend(self._nested(
                                part, f"{record.path}::{entry.name}", nested_kind, limits, depth + 1, nested,
                                deadline, package=deb,
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
                    sample, consumed, truncated = _read_member_sample(
                        _Window(part), remaining, deadline, limits.member_sample_bytes
                    )
                    content_bytes += consumed
                    inspection.sample("file", entry.size, consumed, truncated, remaining)
                    if truncated or entry.size > consumed:
                        content_truncated += 1
                    member_findings, member_timed_out = _member_content_findings(
                        record.path, entry.name, sample, deadline
                    )
                    content_findings.extend(member_findings)
                    if member_timed_out or time.monotonic() >= deadline:
                        time_budget_reached = True
                        break
        except ArchiveLimitError as exc:
            limit = getattr(limits, exc.limit)
            limit_reached("bytes", limit, exc.used)
            inspection.limit(exc.limit, limit, exc.used)
            inspection.emit()
            return [Finding(
                "archive",
                f"{inspection.format.upper()} index budget exceeded: {record.path}",
                f"The archive index was not read: {exc}, more than the {limit:,}-byte budget "
                "(--archive-limit index_mb). No members were inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            )]
        except ArchiveUnsupportedError as exc:
            inspection.format = "udf"
            return self._unsupported(inspection, str(exc))
        except (OSError, ArchiveFormatError, EOFError, struct.error) as exc:
            inspection.malformed = describe_error(exc)
            inspection.emit()
            return [Finding(
                "archive",
                f"{inspection.format.upper()} metadata read error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
                evidence=[record.path],
                analyzer=self.name,
            )]

        label = inspection.format.upper()
        declared = listing.declared if listing.declared is not None else (
            len(listing.entries) if listing.complete else None)
        inspection.declared = declared
        member_bytes = sum(max(0, entry.size or 0) for entry in listing.entries if entry.kind == "file")
        # Cabinet folders and an RPM payload compress every member together, so the ratio is the
        # archive's; an ISO image stores its files as is, so files that declare more than the
        # image holds share their data.
        compressed = {"cab": size, "rpm": listing.metadata.get("rpm", {}).get("payload_bytes"),
                      "7z": listing.metadata.get("7z", {}).get("packed_bytes"),
                      "rar": sum(entry.compressed_size or 0 for entry in listing.entries)}.get(reader)
        inspection.encrypted = encrypted
        inspection.compressed_bytes = compressed
        base = size if reader == "iso" else compressed
        ratio = member_bytes / base if base else None
        if ratio is not None:
            inspection.extra["expansion_ratio" if reader == "iso" else "compression_ratio"] = round(ratio, 1)
        out_of_bounds = [entry.name for entry in listing.entries if "out-of-bounds" in entry.flags]
        if out_of_bounds:
            inspection.malformed = f"{len(out_of_bounds):,} member(s) extend past the end of the file"
        if listing.stopped == "wall_seconds":
            time_budget_reached = True
        if time_budget_reached:
            inspection.limit("wall_seconds", limits.wall_seconds)
        if listing.stopped == "entries":
            limit_reached("entries", limits.entries, listing.declared)
            inspection.limit("entries", limits.entries, listing.declared)
        if member_bytes > limits.uncompressed_bytes:
            inspection.limit("uncompressed_bytes", limits.uncompressed_bytes, member_bytes)
        duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
        if duplicates:
            inspection.flag_duplicates(names)
        listed = listing.entries[:inspection.indexed]
        link_issues = _link_issues(
            [entry.name for entry in listed],
            {entry.name: entry.link_target for entry in listed if entry.kind == "symlink" and entry.link_target},
            {entry.name: entry.link_target for entry in listed if entry.kind == "hardlink" and entry.link_target},
            check_escapes=reader in ("iso", "rar"),  # an RPM installs its links as links
        )
        link_loops = self._apply_link_issues(inspection, link_issues, unsafe_paths)
        if link_loops:
            inspection.extra.setdefault("structure_issues", {})["symlink_loops"] = len(link_loops)
        inspection.emit()

        indexed = f"{inspection.indexed:,}" + ("" if declared is None else f" of {declared:,}")
        if reader == "cab":
            cab = listing.metadata["cab"]
            source_note = (f"the cabinet's file table; the members are compressed in {cab['folders']:,} folder(s) "
                           f"({', '.join(cab['compression']) or 'none'}) and were not decompressed")
        elif reader == "rpm":
            compressor = listing.metadata["rpm"].get("payload_compressor") or "compressed"
            source_note = f"the package header; the {compressor} payload was not decompressed"
        elif reader in ("7z", "rar"):
            info = listing.metadata[reader]
            methods = ", ".join(info.get("methods", ())) or None
            index_name = "the 7z header" if reader == "7z" else f"the RAR {info['version']} block headers"
            source_note = (index_name + (" (encrypted: no member could be listed)" if inspection.headers_encrypted
                                         else "")
                           + f"; {content_bytes:,} bytes of stored members were inspected in memory and compressed "
                           + "members were not decompressed" + (f" ({methods})" if methods else ""))
        else:
            headers = ("the ar member headers" if reader == "ar"
                       else f"the image's {listing.metadata['iso']['tree']} ISO 9660 directory tree")
            source_note = (f"{headers}; {content_bytes:,} member bytes were inspected through bounded "
                           "in-memory streams and no member was written to disk")
        evidence = [
            f"{counts['file']:,} regular file(s)", f"{counts['directory']:,} directory(ies)",
            f"{counts['symlink']:,} symlink(s)", f"{counts['hardlink']:,} hardlink(s)",
            f"{counts['special']:,} special entry(ies)", f"{len(duplicates):,} duplicate member name(s)",
        ]
        package = _package_label(listing.metadata)
        if package:
            evidence.insert(0, f"package: {package}")
        findings = [Finding(
            "archive",
            f"{label} archive inventory: {record.path}",
            f"Indexed {indexed} member(s) from {source_note}.",
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer=self.name,
        )]
        if listing.stopped == "entries":
            findings.append(Finding(
                "archive",
                f"{label} entry limit reached: {record.path}",
                f"Metadata listing stopped after {limits.entries:,} members.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="MEDIUM",
            ))
        findings.extend(self._risk_findings(record, unsafe_paths, symlinks, risky_modes, high_ratios, duplicates,
                                            encrypted))
        if inspection.headers_encrypted:
            findings.append(Finding(
                "archive", f"Encrypted archive index: {record.path}",
                "The archive encrypts its index (file names included), so no member could be listed or "
                "inspected without the password.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name, severity="MEDIUM",
            ))
        if member_bytes > limits.uncompressed_bytes:
            findings.append(self._bomb_finding(record, member_bytes, limits))
        if ratio is not None and member_bytes and ratio > limits.compression_ratio:
            if reader == "iso":
                title = f"ISO image files declare far more data than it holds: {record.path}"
                detail = (f"Its files declare {member_bytes:,} bytes, {ratio:,.0f} times the image's {base:,} bytes "
                          f"(over {limits.compression_ratio:g}:1): they share their data, so extracting them "
                          "writes far more than the image holds, like an overlapping-member zip bomb.")
            else:
                title = f"High compression-ratio archive: {record.path}"
                detail = (f"Its members declare {member_bytes:,} bytes, {ratio:,.0f} times its {base:,} compressed "
                          f"bytes (over {limits.compression_ratio:g}:1). Review for archive-bomb risk; contents "
                          "were not decompressed.")
            findings.append(Finding(
                "security", title, detail, confidence="INFERRED",
                evidence=[record.path, f"declared member bytes: {member_bytes:,}", f"archive bytes: {base:,}"],
                analyzer=self.name, severity="HIGH",
            ))
        if reader == "iso":
            findings.extend(self._iso_findings(record, listing.metadata["iso"], out_of_bounds))
        findings.extend(self._link_findings(record, hardlinks, special_entries))
        findings.extend(self._integrity_findings(record, link_loops, []))
        collisions = _colliding_names(names)
        if collisions:
            findings.append(self._collision_finding(record, collisions))
        findings.extend(content_findings)
        findings.extend(self._budget_findings(record, label, limits, content_truncated, time_budget_reached))
        return findings

    def _iso_findings(self, record: FileRecord, iso: dict, out_of_bounds: list[str]) -> list[Finding]:
        """Findings for an ISO image's directory loops, both-endian disagreements, corrupt or
        truncated directories and a UDF tree that was not read."""
        issues = iso.get("structure_issues", {})
        findings = []
        if issues.get("directory-loop"):
            findings.append(Finding(
                "security", f"ISO directory loop: {record.path}",
                f"{issues['directory-loop']:,} directory record(s) point back to a directory already listed. "
                "Tools that follow them recurse without end; PDT listed each directory once.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name, severity="MEDIUM",
            ))
        if issues.get("both-endian-mismatch"):
            findings.append(Finding(
                "security", f"ISO directory records disagree with themselves: {record.path}",
                f"{issues['both-endian-mismatch']:,} directory record(s) hold different little- and big-endian "
                "extents or sizes. Systems that read the other half see other files; PDT read the little-endian "
                "half.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name, severity="MEDIUM",
            ))
        corrupt = sum(issues.get(name, 0) for name in ("corrupt-record", "directory-out-of-bounds",
                                                         "continuation-out-of-bounds"))
        if corrupt or out_of_bounds or iso.get("missing_bytes"):
            evidence = [f"{record.path}::{name}" for name in out_of_bounds[:_MAX_EVIDENCE]] or [record.path]
            findings.append(Finding(
                "archive", f"Truncated or corrupt ISO image: {record.path}",
                f"{corrupt:,} directory record(s) or area(s) could not be read and {len(out_of_bounds):,} file(s) "
                f"extend past the end of the image"
                + (f", which is {iso['missing_bytes']:,} bytes shorter than its volume" if iso.get("missing_bytes")
                   else "") + ". The listing may be incomplete.",
                confidence="UNKNOWN", evidence=evidence, analyzer=self.name, severity="MEDIUM",
            ))
        if "udf" in iso.get("extensions", ()):
            findings.append(Finding(
                "archive", f"UDF file system not read: {record.path}",
                "The image also holds a UDF file system, which has no built-in reader. Hybrid images (Windows "
                "install media) may list only a few files in their ISO 9660 tree; files only in the UDF tree "
                "were not inspected.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW",
            ))
        return findings

    def _nested(self, data: bytes | _Slice, display: str, kind: str, limits: _Limits, depth: int,
                nested: _Nested, deadline: float, package: bool = False,
                packages: Packages | None = None) -> list[Finding]:
        """Inspect a member that is itself an archive, from its bytes in memory or in place; its
        archive and member records and findings name it "outer.zip::inner.jar"."""
        name = display.rsplit("::", 1)[-1]
        record = FileRecord(display, _data_size(data), PurePosixPath(name).suffix.lower(), "Archive",
                            file_type=_NESTED_TYPES[kind])
        options = {"data": data, "depth": depth, "nested": nested, "deadline": deadline}
        if kind == "zip":
            return self._zip(Path(name), record, limits, packages=packages, **options)
        if kind == "tar":
            return self._tar(Path(name), record, limits, package=package, codec=_codec(name), packages=packages,
                             **options)
        if kind == "stream":
            return self._stream(Path(name), record, limits, _codec(name), **options)
        return self._listed(Path(name), record, limits, kind, **options)

    def _stream(self, path: Path, record: FileRecord, limits: _Limits | None = None, codec: str | None = None, *,
                data: bytes | _Slice | None = None, depth: int = 0, nested: _Nested | None = None,
                deadline: float | None = None) -> list[Finding]:
        """Inspect a single compressed file (gzip, bzip2, xz, LZMA, Zstandard) as an archive of one
        member: its header's metadata (an original name, a time, the declared size) and a
        bounded sample of its content. Content that is a TAR stream is inspected as TAR."""
        limits = limits or _Limits()
        nested = nested or _Nested(limits.nested_bytes)
        codec = codec or "gzip"
        deadline = deadline if deadline is not None else time.monotonic() + limits.wall_seconds
        inspection = _Inspection(record, codec, limits)
        scan_limit = min(limits.member_sample_bytes, limits.archive_sample_bytes)
        head, eof, timed_out = b"", False, False
        unreadable = unsupported = None
        try:
            source = (open_verified_binary(path, record.analysis_identity) if data is None
                      else _open_data(data, buffered=True))
            with source as stream:
                stream.seek(0, 2)
                size = stream.tell()
                info = read_compressed(stream, size, codec, limits.index_bytes, deadline)
                window = info.get("window_bytes") or 0
                if codec == "zstd" and info.get("dictionaries"):
                    unreadable = "its Zstandard frames need a dictionary"
                elif codec == "zstd" and window > _ZSTD_MAX_WINDOW:
                    unreadable = (f"its Zstandard window of {window:,} bytes is over the decompressors' "
                                  f"{_ZSTD_MAX_WINDOW:,}-byte limit")
                else:
                    stream.seek(0)
                    try:
                        _, reader = _decompressor(stream, codec)
                    except _Unsupported as exc:
                        unsupported, reader = str(exc), None
                    if reader is None and unsupported is None:
                        raise ArchiveFormatError(f"no {codec} stream signature")
                    if reader is not None:
                        # Enough to tell a TAR stream (512 bytes) and to sample the content.
                        sniff = max(512, scan_limit)
                        try:
                            head, _, more = _read_member_sample(
                                _BudgetedReader(reader, deadline, limits.tar_decompressed_bytes), sniff, deadline, sniff)
                        except _ArchiveBudgetExceeded:
                            timed_out = True
                        else:
                            timed_out = time.monotonic() >= deadline
                            eof = not more and not timed_out
        except ArchiveLimitError as exc:
            limit = getattr(limits, exc.limit)
            limit_reached("bytes", limit, exc.used)
            inspection.limit(exc.limit, limit, exc.used)
            inspection.emit()
            return [Finding(
                "archive", f"{codec.upper()} index budget exceeded: {record.path}",
                f"The compressed file's index was not read: {exc}, more than the {limit:,}-byte budget "
                "(--archive-limit index_mb).",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="MEDIUM",
            )]
        except (OSError, ArchiveFormatError, EOFError, lzma.LZMAError, struct.error, *ZSTD_ERRORS) as exc:
            inspection.malformed = describe_error(exc)
            inspection.emit()
            return [Finding(
                "archive", f"{codec.upper()} read error: {record.path}", describe_error(exc),
                confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name,
            )]
        if _tar_header(head[:512]):
            return self._tar(path, record, limits, data=data, depth=depth, nested=nested, deadline=deadline,
                             codec=codec)

        label = codec.upper()
        name = info.get("original_name") or _uncompressed_name(record.path.rsplit("::", 1)[-1])
        # An xz index and Zstandard frame sizes are exact (Python's xz reader also stops at stream
        # padding); a gzip trailer and an LZMA header may not be, so a content read to its end wins.
        exact = info.get("content_bytes") if codec in ("xz", "zstd") else None
        member_size = exact if exact is not None else len(head) if eof else info.get("content_bytes")
        flags: list[str] = []
        unsafe_paths = [name] if _unsafe_member_path(name) else []
        if unsafe_paths:
            flags.append("unsafe-path")  # gunzip -N restores the name the header gives
        high_ratios = []
        if member_size and member_size / max(size, 1) > limits.compression_ratio:
            high_ratios.append(name)
            flags.append("high-ratio")
        nested_kind = _nested_kind(name)
        if nested_kind == "tar":
            nested_kind = None  # its content was no TAR stream
        if nested_kind is not None:
            flags.append("nested-archive")
        inspection.index_read, inspection.declared, inspection.compressed_bytes = True, 1, size
        inspection.extra["stream"] = info
        inspection.member(0, name, "file", member_size, size, None, info.get("mtime"), flags)
        content_findings: list[Finding] = []
        sampled = truncated = 0
        timed_out = timed_out or info.get("complete") is False  # the index or frame walk ran out of time
        inspected_nested = False
        if unsupported is not None:
            inspection.unsupported = True
            inspection.extra["unsupported_reason"] = unsupported
        elif unreadable is not None:
            inspection.extra["stream"]["unreadable"] = unreadable
            inspection.truncated += 1
            truncated = 1
        elif nested_kind is not None and not timed_out:
            if depth >= limits.nested_depth:
                inspection.limit("nested_depth", limits.nested_depth, members=1)
            else:
                inner = head if eof else self._decompressed(path, record, data, codec, nested.remaining, deadline,
                                                            limits)
                if inner is None or len(inner) > nested.remaining:
                    inspection.limit("nested_bytes", limits.nested_bytes, members=1)
                else:
                    nested.remaining -= len(inner)
                    inspected_nested = True
                    content_findings.extend(self._nested(
                        inner, f"{record.path}::{name}", nested_kind, limits, depth + 1, nested, deadline))
        if unsupported is None and unreadable is None and not inspected_nested:
            # Sampled like any member, also when it is an archive left uninspected by a limit.
            sample = head[:scan_limit]
            short = timed_out or not eof or len(head) > scan_limit
            sampled = len(sample)
            inspection.sample("file", member_size if member_size is not None else sampled + int(short), sampled,
                              short, limits.archive_sample_bytes)
            truncated = int(short)
            findings_found, member_timed_out = _member_content_findings(record.path, name, sample, deadline)
            content_findings.extend(findings_found)
            timed_out = timed_out or member_timed_out
        if member_size is not None and member_size > limits.uncompressed_bytes:
            inspection.limit("uncompressed_bytes", limits.uncompressed_bytes, member_size)
        if timed_out:
            inspection.limit("wall_seconds", limits.wall_seconds)
        inspection.emit()

        evidence = [f"member: {name}", f"compressed bytes: {size:,}",
                    f"uncompressed bytes: {member_size:,}" if member_size is not None
                    else "uncompressed size: not declared"]
        if codec == "xz" and info.get("streams"):
            evidence.append(f"{info['streams']:,} xz stream(s), {info['blocks']:,} block(s)")
        elif codec == "zstd" and info.get("frames"):
            evidence.append(f"{info['frames']:,} Zstandard frame(s)")
        reason = unsupported or unreadable
        detail = (f"A single compressed member, {name}; "
                  + (f"its content was not decompressed: {reason}." if reason else
                     f"{sampled:,} decompressed bytes were inspected through bounded in-memory streams and "
                     "nothing was written to disk."))
        findings = [Finding("archive", f"{label} compressed file inventory: {record.path}", detail,
                            confidence="CONFIRMED", evidence=evidence, analyzer=self.name)]
        findings.extend(self._risk_findings(record, unsafe_paths, [], [], high_ratios, [], 0))
        if member_size is not None and member_size > limits.uncompressed_bytes:
            findings.append(self._bomb_finding(record, member_size, limits))
        findings.extend(content_findings)
        findings.extend(self._budget_findings(record, label, limits, truncated, timed_out))
        return findings

    def _decompressed(self, path: Path, record: FileRecord, data: bytes | _Slice | None, codec: str, limit: int,
                      deadline: float, limits: _Limits) -> bytes | None:
        """A compressed file's whole content, or None when it is larger than ``limit`` or the
        wall-time budget ends first."""
        try:
            source = (open_verified_binary(path, record.analysis_identity) if data is None
                      else _open_data(data, buffered=True))
            with source as stream:
                _, reader = _decompressor(stream, codec)
                if reader is None:
                    return None
                content, _, more = _read_member_sample(
                    _BudgetedReader(reader, deadline, limits.tar_decompressed_bytes), limit, deadline, limit)
        except (_ArchiveBudgetExceeded, _Unsupported, OSError, EOFError, lzma.LZMAError, *ZSTD_ERRORS):
            return None
        return None if more else content

    def _apply_link_issues(self, inspection: _Inspection, issues: dict[str, str], unsafe_paths: list[str]) -> list[str]:
        """Flag the members a link resolution found; returns the looping ones. A member that
        leaves the archive through a link joins the traversal evidence."""
        inspection.add_flags(issues)
        reported = {item.split(" ", 1)[0] for item in unsafe_paths}
        for name, issue in issues.items():
            if issue == "unsafe-path" and name not in reported:
                unsafe_paths.append(f"{name} (through a symlink)")
        return sorted(name for name, issue in issues.items() if issue == "symlink-loop")

    def _integrity_findings(self, record: FileRecord, loops: list[str], crc_mismatches: list[str]) -> list[Finding]:
        findings = []
        if loops:
            findings.append(Finding(
                "security", f"Archive symlink loops: {record.path}",
                f"{len(loops):,} member(s) resolve through the archive's own symlinks in a circle (more than "
                f"{_MAX_LINK_HOPS} links): extractors and scanners that follow them loop or fail. Links were "
                "resolved by name only; nothing was followed on disk.",
                confidence="CONFIRMED", evidence=[f"{record.path}::{name}" for name in loops[:_MAX_EVIDENCE]],
                analyzer=self.name, severity="MEDIUM",
            ))
        if crc_mismatches:
            findings.append(Finding(
                "security", f"ZIP members fail their CRC: {record.path}",
                f"{len(crc_mismatches):,} member(s) read to their end do not match their CRC-32: the data "
                "was altered or corrupted after the archive was written. Tools that check CRCs refuse them; "
                "others extract the altered data.",
                confidence="CONFIRMED", evidence=[f"{record.path}::{name}" for name in crc_mismatches[:_MAX_EVIDENCE]],
                analyzer=self.name, severity="MEDIUM",
            ))
        return findings

    def _sparse_finding(self, record: FileRecord, members: list[tuple[str, int, int]], limits: _Limits) -> Finding:
        declared, stored = sum(item[1] for item in members), sum(item[2] for item in members)
        expanding = [item for item in members if item[1] > max(item[2], 1) * limits.compression_ratio]
        return Finding(
            "security" if expanding else "archive", f"Sparse TAR members: {record.path}",
            f"{len(members):,} sparse member(s) declare {declared:,} bytes from {stored:,} stored bytes"
            + (f"; {len(expanding):,} expand more than {limits.compression_ratio:g} times. Extracting them on a "
               "filesystem without sparse files writes their full size (a disk-filling archive)."
               if expanding else ". Extracting them where sparse files are not supported writes their full size."),
            confidence="CONFIRMED",
            evidence=[f"{record.path}::{name} ({size:,} bytes from {data:,} stored)"
                      for name, size, data in (expanding or members)[:_MAX_EVIDENCE]],
            analyzer=self.name, severity="HIGH" if expanding else "LOW",
        )

    def _tar_structure_findings(self, record: FileRecord, segments: _TarSegments) -> list[Finding]:
        """Headers that fail their checksum and lone zero blocks, where Python's tarfile and 7-Zip
        stop listing but GNU tar reads on, and data after the end-of-archive blocks."""
        findings = []
        resumed = f" PDT read on as GNU tar does and listed {segments.resumed:,} member(s) after them."
        if segments.corrupt:
            findings.append(Finding(
                "security", f"TAR headers fail their checksum: {record.path}",
                f"{len(segments.corrupt):,} header(s) fail their checksum. Python's tarfile and 7-Zip stop listing "
                "at the first one; GNU tar skips to the next valid header and extracts what follows, so members "
                "can hide from tools that stop." + resumed,
                confidence="CONFIRMED", analyzer=self.name, severity="MEDIUM",
                evidence=[f"{record.path} (header at offset {offset:,})" for offset in segments.corrupt[:20]],
            ))
        if segments.lone_zero:
            findings.append(Finding(
                "security", f"Lone zero blocks inside a TAR archive: {record.path}",
                f"{len(segments.lone_zero):,} single zero block(s) sit between members. Python's tarfile ends a "
                "listing at one; GNU tar reads on and extracts the members after it." + resumed,
                confidence="CONFIRMED", analyzer=self.name, severity="MEDIUM",
                evidence=[f"{record.path} (zero block at offset {offset:,})" for offset in segments.lone_zero[:20]],
            ))
        if segments.trailing:
            findings.append(Finding(
                "archive", f"Data after the end of a TAR archive: {record.path}",
                f"{segments.trailing:,} non-zero byte(s) follow the end-of-archive blocks (within the first MiB "
                "after them). GNU tar ignores them unless run with --ignore-zeros; they may hold a further archive.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW",
            ))
        return findings

    def _package_findings(self, record: FileRecord, package: dict | None) -> list[Finding]:
        """A package that runs code when it is installed: npm install scripts, Python startup
        hooks (.pth files), NuGet install scripts."""
        code = (package or {}).get("install_code")
        if not code:
            return []
        return [Finding(
            "supply_chain",
            f"Package runs code when installed: {record.path}",
            f"The {package['ecosystem']} package {_package_text(package)} declares {len(code):,} piece(s) of code "
            "that run when it is installed, before anything imports it (npm install scripts, Python .pth startup "
            "hooks, NuGet install scripts). Review them before installing the package.",
            confidence="INFERRED",
            evidence=[f"{record.path}::{redact_source_excerpt(item)}" for item in code[:_MAX_EVIDENCE]],
            analyzer=self.name,
            severity="MEDIUM",
        )]

    def _link_findings(self, record: FileRecord, hardlinks: list[str], special_entries: list[str]) -> list[Finding]:
        findings = []
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

    def _budget_findings(self, record: FileRecord, label: str, limits: _Limits, content_truncated: int,
                         time_budget_reached: bool) -> list[Finding]:
        findings = []
        if content_truncated:
            limit_reached("bytes", limits.archive_sample_bytes)
            findings.append(Finding(
                "archive",
                f"{label} member content budget reached: {record.path}",
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
                f"{label} wall-time budget reached: {record.path}",
                f"Archive inspection stopped after the {limits.wall_seconds:g}-second "
                "wall-time budget. Findings already collected are partial; remaining entries "
                "were not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

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
