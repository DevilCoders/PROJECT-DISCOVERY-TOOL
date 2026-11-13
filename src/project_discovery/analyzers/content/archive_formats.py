"""Metadata readers for archive formats beyond ZIP and TAR: ar (Debian packages and static
libraries), Microsoft Cabinet, RPM and ISO 9660 images; the metadata of single compressed
files (gzip, bzip2, xz, LZMA, Zstandard); and the Zstandard decompressor the TAR reader uses.

Each archive reader parses the format's own headers from a seekable binary stream, returns at
most ``max_entries`` member entries and decompresses no member data; a DEB's control tarball,
a few KiB, is the one exception, read for its package fields under a decompressed-byte cap.
Malformed input raises ``ArchiveFormatError``, an index larger than its budget
``ArchiveLimitError`` and a format variant without a reader ``ArchiveUnsupportedError``. The
standard library suffices, except for Zstandard before Python 3.14, which needs the optional
``zstandard`` package (``pip install "project-discovery-tool[archives]"``).
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import stat
import struct
import tarfile
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, BinaryIO


class ArchiveFormatError(ValueError):
    """The stream does not hold a well-formed archive of the format."""


class ArchiveLimitError(Exception):
    """An archive index is larger than its budget; nothing past the budget was read."""

    def __init__(self, limit: str, used: int, message: str) -> None:
        super().__init__(message)
        self.limit, self.used = limit, used


class ArchiveUnsupportedError(Exception):
    """A variant of the format that has no built-in reader (a UDF-only disc image)."""


@dataclass(slots=True)
class Entry:
    name: str
    kind: str  # file, directory, symlink, hardlink or special
    size: int | None
    compressed_size: int | None = None
    mode: int | None = None  # with its file-type bits when the format records them
    mtime: str | None = None
    link_target: str | None = None
    uid: int | None = None
    gid: int | None = None
    owner: str | None = None
    group: str | None = None
    encrypted: bool = False
    offset: int | None = None  # where the member's bytes start, in formats that store them as is (ar, ISO)
    flags: tuple[str, ...] = ()  # structure flags the reader found ("out-of-bounds")


@dataclass(slots=True)
class Listing:
    """What a reader found: the entries it read, how many the archive declares (None when the
    format does not say), whether it read them all, and format-specific metadata."""

    entries: list[Entry] = field(default_factory=list)
    declared: int | None = None
    complete: bool = True
    stopped: str | None = None  # the limit that ended the listing early: "entries" or "wall_seconds"
    metadata: dict[str, Any] = field(default_factory=dict)

    def full(self, max_entries: int) -> bool:
        """Whether the entry limit is reached; the listing is then incomplete."""
        if len(self.entries) < max_entries:
            return False
        self.complete, self.stopped = False, "entries"
        return True


def _utc(seconds) -> str | None:
    try:
        return datetime.fromtimestamp(float(seconds), UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def _dos_time(date: int, time_of_day: int) -> str | None:
    """A DOS date and time: local time without a zone, at two-second resolution."""
    year, month, day = 1980 + (date >> 9), (date >> 5) & 0xF, date & 0x1F
    hour, minute, second = time_of_day >> 11, (time_of_day >> 5) & 0x3F, (time_of_day & 0x1F) * 2
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"


def _kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode) or not stat.S_IFMT(mode):
        return "file"
    return "special"


def _text(value, limit: int = 512):
    return value[:limit] if isinstance(value, str) else value


# ---------------------------------------------------------------------------------------
# Zstandard: compression.zstd (Python 3.14) or the optional zstandard package

def _zstd_module():
    try:
        from compression import zstd  # Python 3.14
        return zstd
    except ImportError:
        pass
    try:
        import zstandard  # pip install "project-discovery-tool[archives]"
        return zstandard
    except ImportError:
        return None


_ZSTD = _zstd_module()
ZSTD_ERRORS: tuple[type[BaseException], ...] = () if _ZSTD is None else (_ZSTD.ZstdError,)
ZSTD_UNAVAILABLE = ("Zstandard decompression needs Python 3.14 (compression.zstd) or the optional zstandard "
                    'package (pip install "project-discovery-tool[archives]")')


def zstd_decompressor() -> str | None:
    """The Zstandard decompressor this Python offers, by module name, or None."""
    return None if _ZSTD is None else _ZSTD.__name__


def zstd_reader(stream: BinaryIO):
    """A file object decompressing the Zstandard stream ``stream`` (closing it leaves
    ``stream`` open), or None when this Python has no Zstandard decompressor. Both
    decompressors refuse frames whose window exceeds libzstd's default limit (128 MiB)."""
    if _ZSTD is None:
        return None
    if _ZSTD.__name__ == "compression.zstd":
        return _ZSTD.ZstdFile(stream)
    return _ZSTD.ZstdDecompressor().stream_reader(stream, read_across_frames=True, closefd=False)


class _Capped(io.RawIOBase):
    """Reads at most ``limit`` bytes of ``stream``, then fails, so a small compressed member
    cannot expand without bound."""

    def __init__(self, stream, limit: int) -> None:
        self._stream, self._remaining = stream, limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        if self._remaining <= 0:
            raise ArchiveFormatError("the member decompresses past its cap")
        data = self._stream.read(min(len(buffer), self._remaining))
        memoryview(buffer)[:len(data)] = data
        self._remaining -= len(data)
        return len(data)


def _decompressed(name: str, data: bytes):
    """A reader of the bytes of member ``name`` by its compression suffix; None for Zstandard
    without a decompressor."""
    raw = io.BytesIO(data)
    if name.endswith(".gz"):
        return gzip.GzipFile(fileobj=raw)
    if name.endswith(".xz"):
        return lzma.LZMAFile(raw)
    if name.endswith(".bz2"):
        return bz2.BZ2File(raw)
    if name.endswith(".zst"):
        return zstd_reader(raw)
    return raw


# ---------------------------------------------------------------------------------------
# ar: Debian packages and static libraries

_AR_MAGIC, _AR_THIN = b"!<arch>\n", b"!<thin>\n"
_AR_SYMBOL_TABLES = frozenset({"/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64",
                               "__.SYMDEF_64 SORTED"})
_DEB_CONTROL_BYTES = 4 * 1024 * 1024  # a DEB control tarball read for its package fields
_DEB_CONTROL_EXPANDED = 16 * 1024 * 1024  # and what it may decompress to
_CONTROL_FIELDS = frozenset({"Package", "Source", "Version", "Architecture", "Maintainer", "Installed-Size",
                             "Depends", "Pre-Depends", "Section", "Priority", "Homepage", "Description"})


def _control_fields(text: str) -> dict[str, Any]:
    """Fields of a Debian control file (the Description field's synopsis line only)."""
    fields: dict[str, Any] = {}
    for line in text.splitlines():
        if line[:1] in (" ", "\t"):
            continue  # a continuation line
        key, separator, value = line.partition(":")
        if separator and key in _CONTROL_FIELDS:
            fields[key.lower().replace("-", "_")] = value.strip()[:512]
    return fields


def _deb_control(data: bytes, name: str) -> dict[str, Any]:
    """The package fields of a DEB's control file, read from its control tarball's bytes."""
    source = _decompressed(name, data)
    if source is None:
        return {"control_error": f"{name}: {ZSTD_UNAVAILABLE}"}
    try:
        with tarfile.open(fileobj=_Capped(source, _DEB_CONTROL_EXPANDED), mode="r|") as archive:
            for member in archive:
                if member.isfile() and member.name.removeprefix("./") == "control":
                    handle = archive.extractfile(member)
                    text = b"" if handle is None else handle.read(256 * 1024)
                    return _control_fields(text.decode("utf-8", "replace"))
    except (OSError, EOFError, lzma.LZMAError, tarfile.TarError, ValueError, *ZSTD_ERRORS) as exc:
        return {"control_error": f"{name}: {type(exc).__name__}: {exc}"[:300]}
    return {"control_error": f"{name}: no control file"}


def _ar_number(field_bytes: bytes, base: int, position: int) -> int:
    try:
        value = int(field_bytes.strip() or b"0", base)
    except ValueError:
        raise ArchiveFormatError(f"a non-numeric field in the ar member header at offset {position}") from None
    if value < 0:
        raise ArchiveFormatError(f"a negative field in the ar member header at offset {position}")
    return value


def read_ar(stream: BinaryIO, size: int, max_entries: int, max_index_bytes: int,
            deadline: float | None = None) -> Listing:
    """An ar archive's members: common, GNU (long-name table, thin archives) and BSD (#1/
    names) variants. A Debian package's fields come from its control tarball; the symbol
    table and the long-name table are not members (``ar t`` does not list them)."""
    stream.seek(0)
    magic = stream.read(8)
    if magic not in (_AR_MAGIC, _AR_THIN):
        raise ArchiveFormatError("not an ar archive (no !<arch> signature)")
    thin = magic == _AR_THIN
    info: dict[str, Any] = {"variant": "common", "thin": thin, "symbol_table": False}
    listing = Listing(metadata={"ar": info})
    names_table = b""
    position, headers = 8, 0
    while position < size:
        headers += 1
        if deadline is not None and headers % 1024 == 0 and time.monotonic() >= deadline:
            listing.complete, listing.stopped = False, "wall_seconds"
            break
        stream.seek(position)
        header = stream.read(60)
        if len(header) < 60:
            if not header.strip(b"\n"):
                break  # padding after the last member
            raise ArchiveFormatError(f"a truncated ar member header at offset {position}")
        if header[58:60] != b"`\n":
            raise ArchiveFormatError(f"a corrupt ar member header at offset {position}")
        raw_name = header[:16].rstrip(b" ")
        mtime = _ar_number(header[16:28], 10, position)
        uid = _ar_number(header[28:34], 10, position)
        gid = _ar_number(header[34:40], 10, position)
        mode = _ar_number(header[40:48], 8, position)
        length = _ar_number(header[48:58], 10, position)
        data_start = position + 60
        # A thin archive stores its symbol and name tables; its members are files beside it.
        stored = not thin or raw_name in (b"/", b"//", b"/SYM64/")
        next_position = data_start + (length + (length & 1) if stored else 0)
        if stored and data_start + length > size:
            raise ArchiveFormatError(f"the ar member at offset {position} runs past the end of the file")
        if raw_name == b"//":  # GNU: the long-name table
            if length > max_index_bytes:
                raise ArchiveLimitError("index_bytes", length, f"the ar long-name table holds {length:,} bytes")
            stream.seek(data_start)
            names_table = stream.read(length)
            info["variant"], position = "gnu", next_position
            continue
        if raw_name in (b"/", b"/SYM64/"):  # GNU: the symbol table
            info["symbol_table"], info["variant"], position = True, "gnu", next_position
            continue
        if raw_name.startswith(b"#1/"):  # BSD: the name precedes the member's data
            name_length = _ar_number(raw_name[3:], 10, position)
            if name_length > length:
                raise ArchiveFormatError(f"the BSD ar name at offset {position} is longer than its member")
            stream.seek(data_start)
            raw_name = stream.read(name_length).rstrip(b"\x00")
            data_start, length = data_start + name_length, length - name_length
            info["variant"] = "bsd"
        elif raw_name[:1] == b"/" and raw_name[1:].isdigit():  # GNU: an offset into the name table
            offset = int(raw_name[1:])
            if offset >= len(names_table):
                raise ArchiveFormatError(f"the ar long-name offset {offset} is past the name table")
            ends = [end for end in (names_table.find(b"\n", offset), names_table.find(b"\x00", offset)) if end >= 0]
            raw_name = names_table[offset:min(ends) if ends else len(names_table)].rstrip(b"/")
        elif raw_name.endswith(b"/"):  # GNU: a short name ends in "/"
            raw_name = raw_name[:-1]
        name = raw_name.decode("utf-8", "replace")
        if name in _AR_SYMBOL_TABLES:  # BSD symbol tables
            info["symbol_table"], position = True, next_position
            continue
        if listing.full(max_entries):
            break
        listing.entries.append(Entry(name, "file", length, mode=mode or None, mtime=_utc(mtime), uid=uid, gid=gid,
                                     offset=data_start if stored else None))
        if stored and len(listing.entries) == 1 and name == "debian-binary":
            stream.seek(data_start)
            version = stream.read(min(length, 16)).decode("ascii", "replace").strip()
            listing.metadata = {"deb": {"format_version": version}}
        elif stored and name.startswith("control.tar") and "deb" in listing.metadata:
            deb = listing.metadata["deb"]
            if length > _DEB_CONTROL_BYTES:
                deb["control_error"] = f"{name}: {length:,} bytes, over the {_DEB_CONTROL_BYTES:,}-byte cap"
            elif "package" not in deb:
                stream.seek(data_start)
                deb.update(_deb_control(stream.read(length), name))
        position = next_position
    return listing


# ---------------------------------------------------------------------------------------
# Microsoft Cabinet

_CAB_HEADER = struct.Struct("<4sLLLLLBBHHHHH")
_CAB_FOLDER = struct.Struct("<LHH")
_CAB_FILE = struct.Struct("<LLHHHH")
_CAB_COMPRESSION = {0: "none", 1: "mszip", 2: "quantum", 3: "lzx"}
_CAB_NAME_BYTES = 256  # the format's longest member name, without its terminator


def read_cab(stream: BinaryIO, size: int, max_entries: int, max_index_bytes: int) -> Listing:
    """A cabinet's files (its CFFILE records): names, sizes, DOS times; the folders' compression."""
    stream.seek(0)
    header = stream.read(_CAB_HEADER.size)
    if len(header) < _CAB_HEADER.size or header[:4] != b"MSCF":
        raise ArchiveFormatError("not a cabinet (no MSCF signature)")
    (_, _, cabinet_bytes, _, files_offset, _, minor, major, folders, files, flags, set_id,
     cabinet_index) = _CAB_HEADER.unpack(header)
    if cabinet_bytes > size or files_offset > size:
        raise ArchiveFormatError(f"the cabinet header declares {cabinet_bytes:,} bytes and a file table at "
                                 f"offset {files_offset:,}; the file holds {size:,} bytes")
    position, folder_reserve = _CAB_HEADER.size, 0
    if flags & 0x0004:  # reserved areas in the header, folders and data blocks
        stream.seek(position)
        reserved = stream.read(4)
        if len(reserved) < 4:
            raise ArchiveFormatError("truncated cabinet reserve fields")
        header_reserve, folder_reserve = struct.unpack_from("<HB", reserved)
        position += 4 + header_reserve
    for _ in range((2 if flags & 0x0001 else 0) + (2 if flags & 0x0002 else 0)):  # adjacent cabinet and disk names
        stream.seek(position)
        end = stream.read(_CAB_NAME_BYTES + 1).find(b"\x00")
        if end < 0:
            raise ArchiveFormatError("an unterminated cabinet set name")
        position += end + 1
    folder_size = _CAB_FOLDER.size + folder_reserve
    stream.seek(position)
    table = stream.read(folders * folder_size)
    if len(table) < folders * folder_size:
        raise ArchiveFormatError("a truncated cabinet folder table")
    methods, data_start = set(), size
    for folder in range(folders):
        start, _, compression = _CAB_FOLDER.unpack_from(table, folder * folder_size)
        methods.add(_CAB_COMPRESSION.get(compression & 0x000F, "unknown"))
        if files_offset < start < data_start:
            data_start = start  # the file table ends where the first data block starts
    table_bytes = min(data_start - files_offset, files * (_CAB_FILE.size + _CAB_NAME_BYTES + 1))
    if table_bytes > max_index_bytes:
        raise ArchiveLimitError("index_bytes", table_bytes, f"the cabinet file table spans {table_bytes:,} bytes")
    stream.seek(files_offset)
    table = stream.read(table_bytes)
    listing = Listing(declared=files, metadata={"cab": {
        "version": f"{major}.{minor}", "folders": folders, "compression": sorted(methods), "set_id": set_id,
        "cabinet_index": cabinet_index, "cabinet_bytes": cabinet_bytes, "spans_cabinets": bool(flags & 0x0003),
    }})
    cursor = 0
    for _ in range(files):
        if listing.full(max_entries):
            break
        if cursor + _CAB_FILE.size > len(table):
            raise ArchiveFormatError("a truncated cabinet file table")
        length, _, _, date, time_of_day, attributes = _CAB_FILE.unpack_from(table, cursor)
        end = table.find(b"\x00", cursor + _CAB_FILE.size)
        if end < 0:
            raise ArchiveFormatError("an unterminated name in the cabinet file table")
        raw = table[cursor + _CAB_FILE.size:end]
        cursor = end + 1
        # Names are in the OEM code page unless the UTF-8 attribute (0x80) is set.
        name = raw.decode("utf-8" if attributes & 0x80 else "cp437", "replace").replace("\\", "/")
        listing.entries.append(Entry(name, "file", length, mtime=_dos_time(date, time_of_day)))
    return listing


# ---------------------------------------------------------------------------------------
# RPM

_RPM_LEAD, _RPM_HEADER = b"\xed\xab\xee\xdb", b"\x8e\xad\xe8\x01"
_RPM_STRINGS = frozenset({6, 8, 9})  # STRING, STRING_ARRAY, I18NSTRING
_RPM_INTEGERS = {2: (1, "B"), 3: (2, "H"), 4: (4, "L"), 5: (8, "Q")}  # INT8 to INT64
_RPM_MAX_TAGS = 65536
_RPM_PACKAGE = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1004: "summary", 1014: "license",
                1020: "url", 1022: "arch", 1044: "source_rpm", 1124: "payload_format", 1125: "payload_compressor"}
_RPM_FILES = {1027: "old_file_names", 1028: "sizes", 1030: "modes", 1034: "mtimes", 1036: "link_targets",
              1039: "owners", 1040: "groups", 1095: "devices", 1096: "inodes", 1116: "dir_indexes",
              1117: "base_names", 1118: "dir_names", 5008: "long_sizes"}
_RPM_WANTED = frozenset(_RPM_PACKAGE) | frozenset(_RPM_FILES)


def _rpm_header(stream: BinaryIO, position: int, size: int, max_bytes: int, wanted: frozenset,
                max_items: int) -> tuple[dict[int, Any], dict[int, int], int]:
    """One RPM header structure: ({tag: value} for the wanted tags, their first ``max_items``
    items, {tag: declared item count}, the offset just past the structure)."""
    stream.seek(position)
    intro = stream.read(16)
    if len(intro) < 16 or intro[:4] != _RPM_HEADER:
        raise ArchiveFormatError(f"no RPM header structure at offset {position}")
    count, data_size = struct.unpack_from(">LL", intro, 8)
    total = 16 * count + data_size
    if total > max_bytes:
        raise ArchiveLimitError("index_bytes", total, f"an RPM header holds {total:,} bytes")
    if count > _RPM_MAX_TAGS:
        raise ArchiveFormatError(f"an RPM header with {count:,} tags")
    if position + 16 + total > size:
        raise ArchiveFormatError("an RPM header runs past the end of the file")
    index = stream.read(16 * count)
    data = stream.read(data_size)
    values: dict[int, Any] = {}
    counts: dict[int, int] = {}
    for item in range(count):
        tag, kind, offset, items = struct.unpack_from(">4L", index, 16 * item)
        if tag not in wanted:
            continue
        if offset > data_size:
            raise ArchiveFormatError(f"RPM tag {tag} points past its header")
        counts[tag] = items
        if kind in _RPM_STRINGS:
            if items > data_size - offset + 1:
                raise ArchiveFormatError(f"RPM tag {tag} declares more strings than its header holds")
            strings, cursor = [], offset
            for _ in range(1 if kind == 6 else min(items, max_items)):
                end = data.find(b"\x00", cursor)
                if end < 0:
                    raise ArchiveFormatError(f"an unterminated string in RPM tag {tag}")
                strings.append(data[cursor:end].decode("utf-8", "replace"))
                cursor = end + 1
            values[tag] = strings[0] if kind == 6 else strings
        elif kind in _RPM_INTEGERS:
            width, code = _RPM_INTEGERS[kind]
            if offset + width * items > data_size:
                raise ArchiveFormatError(f"RPM tag {tag} runs past its header")
            values[tag] = list(struct.unpack_from(f">{min(items, max_items)}{code}", data, offset))
    return values, counts, position + 16 + total


def read_rpm(stream: BinaryIO, size: int, max_entries: int, max_header_bytes: int) -> Listing:
    """An RPM's package fields and file list, from its header; the payload is not decompressed."""
    stream.seek(0)
    lead = stream.read(96)
    if len(lead) < 96 or lead[:4] != _RPM_LEAD:
        raise ArchiveFormatError("not an RPM package (no lead signature)")
    source_package = struct.unpack_from(">H", lead, 6)[0] == 1
    _, _, signature_end = _rpm_header(stream, 96, size, max_header_bytes, frozenset(), max_entries)
    header, counts, payload = _rpm_header(stream, signature_end + (-signature_end % 8), size, max_header_bytes,
                                          _RPM_WANTED, max_entries)
    files = {label: header.get(tag, []) for tag, label in _RPM_FILES.items()}
    if 1117 in header:  # base names with directory indexes, or the old full names
        directories, indexes = files["dir_names"], files["dir_indexes"]
        paths = [(directories[indexes[item]] if item < len(indexes) and indexes[item] < len(directories) else "")
                 + name for item, name in enumerate(files["base_names"])]
        declared = counts[1117]
    else:
        paths, declared = files["old_file_names"], counts.get(1027, 0)
    sizes = files["long_sizes"] or files["sizes"]
    package = {}
    for tag, label in _RPM_PACKAGE.items():
        value = header.get(tag)
        package[label] = _text(value[0] if isinstance(value, list) and value else value or None)
    package.update(source_package=source_package, payload_bytes=max(0, size - payload))
    listing = Listing(declared=declared, metadata={"rpm": package})
    first_link: dict[tuple[int, int], str] = {}
    for item, path in enumerate(paths[:max_entries]):
        mode = files["modes"][item] if item < len(files["modes"]) else 0
        kind, target = _kind(mode), None
        if kind == "symlink" and item < len(files["link_targets"]):
            target = files["link_targets"][item] or None
        elif kind == "file" and item < min(len(files["inodes"]), len(files["devices"])) and files["inodes"][item]:
            # Regular files that share a device and inode are hard links to the first of them.
            key = (files["devices"][item], files["inodes"][item])
            if key in first_link:
                kind, target = "hardlink", first_link[key]
            else:
                first_link[key] = path
        listing.entries.append(Entry(
            path, kind, sizes[item] if item < len(sizes) else None, mode=mode or None,
            mtime=_utc(files["mtimes"][item]) if item < len(files["mtimes"]) else None, link_target=target,
            owner=files["owners"][item] if item < len(files["owners"]) else None,
            group=files["groups"][item] if item < len(files["groups"]) else None,
        ))
    if declared > len(listing.entries):
        listing.complete, listing.stopped = False, "entries"
    return listing


# ---------------------------------------------------------------------------------------
# ISO 9660, with Rock Ridge and Joliet

_ISO_SECTOR = 2048  # directory records never cross a 2048-byte logical sector
_ISO_DESCRIPTORS = 16 * _ISO_SECTOR  # the volume descriptor set starts at sector 16
_ISO_MAX_DESCRIPTORS = 64
_ISO_RECORD = struct.Struct("<BBL4sL4s7sBBBH2xB")  # a directory record's fixed 33 bytes
_JOLIET = (b"%/@", b"%/C", b"%/E")  # the UCS-2 escape sequences of a Joliet descriptor
_UDF_DESCRIPTORS = (b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2", b"CDW02")
_ISO_MAX_CONTINUATIONS = 16  # Rock Ridge continuation areas followed per directory record


def _iso_time(raw: bytes) -> str | None:
    """A directory record's time: years since 1900, month, day, hours, minutes, seconds and
    the offset from UTC in 15-minute steps."""
    if len(raw) < 7 or not any(raw[:6]):
        return None
    try:
        moment = datetime(1900 + raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], tzinfo=UTC)
    except ValueError:
        return None
    offset = struct.unpack("b", raw[6:7])[0]
    return (moment - timedelta(minutes=15 * offset)).isoformat().replace("+00:00", "Z")


def _iso_volume_time(raw: bytes) -> str | None:
    """A volume descriptor's time: 16 ASCII digits (to hundredths) and the UTC offset byte."""
    digits = raw[:14]
    if len(raw) < 17 or not digits.isdigit() or not digits.strip(b"0"):
        return None
    try:
        moment = datetime(int(digits[:4]), int(digits[4:6]), int(digits[6:8]), int(digits[8:10]),
                          int(digits[10:12]), int(digits[12:14]), tzinfo=UTC)
    except ValueError:
        return None
    offset = struct.unpack("b", raw[16:17])[0]
    return (moment - timedelta(minutes=15 * offset)).isoformat().replace("+00:00", "Z")


def _iso_text(raw: bytes) -> str | None:
    return raw.decode("latin-1").strip(" \x00") or None


def _susp(area: bytes) -> list[tuple[bytes, bytes]]:
    """The System Use Sharing Protocol entries of a system use area, as (signature, data)."""
    entries, cursor = [], 0
    while cursor + 4 <= len(area):
        signature, length = area[cursor:cursor + 2], area[cursor + 2]
        if length < 4 or cursor + length > len(area):
            break
        entries.append((signature, area[cursor + 4:cursor + length]))
        if signature == b"ST":
            break
        cursor += length
    return entries


def _symlink_target(components: list[tuple[int, bytes]]) -> str:
    """A Rock Ridge symlink's target from its SL component records (flags: 1 the component
    continues in the next record, 2 ".", 4 "..", 8 the root)."""
    parts: list[str] = []
    joined = False
    for flags, content in components:
        text = ("." if flags & 0x02 else ".." if flags & 0x04 else "" if flags & 0x08
                else content.decode("utf-8", "replace"))
        if joined and parts:
            parts[-1] += text
        else:
            parts.append(text)
        joined = bool(flags & 0x01)
    return "/".join(parts) or "/"


def _system_use_area(record: bytes, name_length: int) -> bytes:
    """A directory record's system use area: after the name and its padding byte (present
    when the name's length is even)."""
    return record[_ISO_RECORD.size + name_length + (0 if name_length % 2 else 1):]


class _IsoTree:
    """One ISO 9660 directory tree, walked breadth first under the entry, index-byte and
    time budgets; a directory reached a second time (a loop) is not walked again."""

    def __init__(self, stream: BinaryIO, size: int, block_size: int, joliet: bool, skip: int | None,
                 max_entries: int, max_index_bytes: int, deadline: float | None, listing: Listing) -> None:
        self.stream, self.size, self.block_size, self.joliet = stream, size, block_size, joliet
        self.rock_ridge, self.skip = skip is not None, skip or 0
        self.max_entries, self.max_index_bytes, self.deadline = max_entries, max_index_bytes, deadline
        self.listing = listing
        self.index_bytes = 0
        self.issues: Counter[str] = Counter()

    def _read(self, offset: int, length: int) -> bytes:
        self.index_bytes += length
        if self.index_bytes > self.max_index_bytes:
            raise ArchiveLimitError("index_bytes", self.index_bytes,
                                    f"the ISO 9660 directories hold more than {self.max_index_bytes:,} bytes")
        self.stream.seek(offset)
        return self.stream.read(length)

    def _system_use(self, area: bytes) -> list[tuple[bytes, bytes]]:
        entries = _susp(area[self.skip:])
        for _ in range(_ISO_MAX_CONTINUATIONS):
            continuation = next((data for signature, data in entries if signature == b"CE" and len(data) >= 20),
                                None)
            if continuation is None:
                break
            block, offset, length = (struct.unpack_from("<L", continuation, start)[0] for start in (0, 8, 16))
            if block * self.block_size + offset + length > self.size:
                self.issues["continuation-out-of-bounds"] += 1
                break
            entries = [item for item in entries if item[0] != b"CE"]
            entries += _susp(self._read(block * self.block_size + offset, length))
        return entries

    def records(self, extent: int, length: int):
        """A directory's records: (fixed fields, name bytes, system use area)."""
        start = extent * self.block_size
        if start + length > self.size:
            self.issues["directory-out-of-bounds"] += 1
            length = max(0, self.size - start)
        data = self._read(start, length)
        cursor = 0
        while cursor < len(data):
            record_length = data[cursor]
            if record_length == 0:  # the rest of the sector is padding
                cursor = (cursor // _ISO_SECTOR + 1) * _ISO_SECTOR
                continue
            if record_length < _ISO_RECORD.size or cursor + record_length > len(data):
                self.issues["corrupt-record"] += 1
                return
            record = data[cursor:cursor + record_length]
            cursor += record_length
            fields = _ISO_RECORD.unpack_from(record)
            if _ISO_RECORD.size + fields[-1] > record_length:
                self.issues["corrupt-record"] += 1
                return
            yield fields, record[_ISO_RECORD.size:_ISO_RECORD.size + fields[-1]], _system_use_area(record, fields[-1])

    def walk(self, root_extent: int, root_length: int) -> None:
        listing = self.listing
        visited: set[int] = set()
        queue: deque[tuple[int, int, str]] = deque([(root_extent, root_length, "")])
        steps = 0
        while queue:
            extent, length, prefix = queue.popleft()
            if extent in visited:
                self.issues["directory-loop"] += 1
                continue
            visited.add(extent)
            previous: Entry | None = None
            for fields, raw_name, area in self.records(extent, length):
                steps += 1
                if self.deadline is not None and steps % 1024 == 0 and time.monotonic() >= self.deadline:
                    listing.complete, listing.stopped = False, "wall_seconds"
                    return
                _, attribute_blocks, extent_le, extent_be, size_le, size_be, recorded, flags = fields[:8]
                if struct.unpack(">L", extent_be)[0] != extent_le or struct.unpack(">L", size_be)[0] != size_le:
                    self.issues["both-endian-mismatch"] += 1
                if raw_name in (b"\x00", b"\x01"):  # "." and ".."
                    continue
                system = self._system_use(area) if self.rock_ridge else []
                entry, directory, relocated = self._entry(prefix, raw_name, extent_le, attribute_blocks, size_le,
                                                          recorded, flags, system)
                if relocated:  # a directory Rock Ridge moved for depth: listed where its CL record is
                    continue
                if previous is not None and previous.name == entry.name:
                    # A multi-extent file: one entry, the sizes of its extents summed.
                    contiguous = (previous.offset is not None and entry.offset is not None
                                  and previous.offset + (previous.size or 0) == entry.offset)
                    previous.size = (previous.size or 0) + (entry.size or 0)
                    previous.offset = previous.offset if contiguous else None
                    previous.flags = tuple(dict.fromkeys(previous.flags + entry.flags))
                    previous = previous if flags & 0x80 else None
                    continue
                if listing.full(self.max_entries):
                    return
                listing.entries.append(entry)
                previous = entry if flags & 0x80 and directory is None else None
                if directory is not None:
                    queue.append((directory[0], directory[1], entry.name + "/"))

    def _entry(self, prefix: str, raw_name: bytes, extent: int, attribute_blocks: int, size: int, recorded: bytes,
               flags: int, system: list[tuple[bytes, bytes]]) -> tuple[Entry, tuple[int, int] | None, bool]:
        name = raw_name.decode("utf-16-be" if self.joliet else "latin-1", "replace")
        if not flags & 0x02:
            name = name.split(";", 1)[0]  # the file version
            if not self.joliet and name.endswith("."):
                name = name[:-1]  # a name without an extension
        mode = uid = gid = None
        mtime = _iso_time(recorded)
        special = compressed = relocated = False
        child: int | None = None
        alternate = b""
        components: list[tuple[int, bytes]] = []
        for signature, data in system:
            if signature == b"NM" and data:
                if not data[0] & 0x06:  # not "." or ".."
                    alternate += data[1:]
            elif signature == b"PX" and len(data) >= 32:
                mode, uid, gid = (struct.unpack_from("<L", data, start)[0] for start in (0, 16, 24))
            elif signature == b"SL" and data:
                cursor = 1
                while cursor + 2 <= len(data):
                    length = data[cursor + 1]
                    components.append((data[cursor], data[cursor + 2:cursor + 2 + length]))
                    cursor += 2 + length
            elif signature == b"PN":
                special = True
            elif signature == b"TF" and data:
                mtime = _tf_mtime(data) or mtime
            elif signature == b"ZF":
                compressed = True  # zisofs: the data is compressed on the image
            elif signature == b"CL" and len(data) >= 4:
                child = struct.unpack_from("<L", data, 0)[0]
            elif signature == b"RE":
                relocated = True
        if alternate:
            name = alternate.decode("utf-8", "replace")
        directory: tuple[int, int] | None = None
        if flags & 0x02:
            kind, directory = "directory", (extent, size)
        elif child is not None:
            kind, directory = "directory", (child, self._directory_length(child))
        else:
            kind = "file" if mode is None else _kind(mode)
        if special and kind == "file":
            kind = "special"
        offset: int | None = (extent + attribute_blocks) * self.block_size
        entry_flags: tuple[str, ...] = ()
        if kind == "file" and offset + size > self.size:
            entry_flags, offset = ("out-of-bounds",), None
        stored = kind == "file" and not compressed
        target = _symlink_target(components) if kind == "symlink" and components else None
        return (Entry(prefix + name, kind, None if kind == "directory" else size, mode=mode, mtime=mtime,
                      link_target=target, uid=uid, gid=gid, offset=offset if stored else None, flags=entry_flags),
                directory, relocated)

    def _directory_length(self, extent: int) -> int:
        """A relocated directory's length, from its own "." record."""
        for fields, name, _ in self.records(extent, _ISO_SECTOR):
            return fields[4] if name == b"\x00" else _ISO_SECTOR
        return _ISO_SECTOR


def _tf_mtime(data: bytes) -> str | None:
    """The modification time of a Rock Ridge TF entry (the stamp after the optional creation stamp)."""
    flags, width = data[0], 17 if data[0] & 0x80 else 7
    if not flags & 0x02:
        return None
    start = 1 + (width if flags & 0x01 else 0)
    raw = data[start:start + width]
    return _iso_volume_time(raw) if width == 17 else _iso_time(raw)


def _rock_ridge_skip(stream: BinaryIO, size: int, block_size: int, primary: bytes) -> int | None:
    """The SUSP skip length when the primary tree uses Rock Ridge (its root's "." record holds
    an SP entry), else None."""
    root = _ISO_RECORD.unpack_from(primary, 156)
    start = root[2] * block_size
    if start + _ISO_RECORD.size + 1 > size:
        return None
    stream.seek(start)
    sector = stream.read(min(max(root[4], _ISO_RECORD.size + 1), _ISO_SECTOR))
    length = sector[0] if sector else 0
    if length < _ISO_RECORD.size + 1 or length > len(sector):
        return None
    sp = next((data for signature, data in _susp(_system_use_area(sector[:length], sector[32]))
               if signature == b"SP"), None)
    if sp is None or sp[:2] != b"\xbe\xef":
        return None
    return sp[2] if len(sp) > 2 else 0


def read_iso(stream: BinaryIO, size: int, max_entries: int, max_index_bytes: int,
             deadline: float | None = None) -> Listing:
    """An ISO 9660 image's files: the Rock Ridge tree (POSIX names, modes, owners, links) when
    the image has one, else the Joliet tree (Unicode names), else the primary tree. Files are
    stored as is, so each entry has its data offset. A UDF tree, which hybrid images such as
    Windows install media carry beside a minimal ISO 9660 one, is detected, not read."""
    primary = joliet = None
    boot = udf = False
    for index in range(_ISO_MAX_DESCRIPTORS):
        stream.seek(_ISO_DESCRIPTORS + index * _ISO_SECTOR)
        block = stream.read(_ISO_SECTOR)
        if len(block) < _ISO_SECTOR:
            break
        kind, identifier = block[0], block[1:6]
        if identifier == b"CD001":
            if kind == 1 and primary is None:
                primary = block
            elif kind == 2 and block[88:91] in _JOLIET and joliet is None:
                joliet = block
            elif kind == 0 and block[7:30] == b"EL TORITO SPECIFICATION":
                boot = True
        elif identifier in _UDF_DESCRIPTORS:
            udf = udf or identifier in (b"NSR02", b"NSR03")
            if identifier == b"TEA01":
                break
        else:
            break
    if primary is None:
        if udf:
            raise ArchiveUnsupportedError("a UDF image without an ISO 9660 tree; UDF has no built-in reader")
        raise ArchiveFormatError("no ISO 9660 primary volume descriptor at sector 16")
    block_size = struct.unpack_from("<H", primary, 128)[0]
    if block_size not in (512, 1024, 2048):
        raise ArchiveFormatError(f"an ISO 9660 logical block size of {block_size}")
    volume_bytes = struct.unpack_from("<L", primary, 80)[0] * block_size
    info: dict[str, Any] = {
        "volume_id": _iso_text(primary[40:72]), "system_id": _iso_text(primary[8:40]),
        "publisher": _iso_text(primary[318:446]), "preparer": _iso_text(primary[446:574]),
        "application": _iso_text(primary[574:702]), "created": _iso_volume_time(primary[813:830]),
        "modified": _iso_volume_time(primary[830:847]), "block_size": block_size, "volume_bytes": volume_bytes,
    }
    listing = Listing(metadata={"iso": info})
    skip = _rock_ridge_skip(stream, size, block_size, primary)
    use_joliet = joliet is not None and skip is None  # Rock Ridge has modes and links, Joliet only names
    tree = _IsoTree(stream, size, block_size, use_joliet, skip, max_entries, max_index_bytes, deadline, listing)
    root = _ISO_RECORD.unpack_from(joliet if use_joliet else primary, 156)
    tree.walk(root[2], root[4])
    info["tree"] = "rock-ridge" if skip is not None else "joliet" if use_joliet else "primary"
    info["extensions"] = [name for name, present in (("rock-ridge", skip is not None), ("joliet", joliet is not None),
                                                     ("el-torito", boot), ("udf", udf)) if present]
    if tree.issues:
        info["structure_issues"] = dict(sorted(tree.issues.items()))
    if volume_bytes > size:
        info["missing_bytes"] = volume_bytes - size  # a truncated image
    return listing


# ---------------------------------------------------------------------------------------
# Single compressed files: gzip, bzip2, xz, LZMA and Zstandard

STREAM_CODECS = ("gzip", "bzip2", "xz", "lzma", "zstd")
_DEFLATE_MAX_RATIO = 1032  # deflate cannot expand data by more than this
_XZ_FOOTER = 12  # the size of an xz stream's header and of its footer
_GZIP_SYSTEMS = {0: "FAT", 1: "Amiga", 2: "VMS", 3: "Unix", 4: "VM/CMS", 5: "Atari TOS", 6: "HPFS", 7: "Macintosh",
                 8: "Z-System", 9: "CP/M", 10: "TOPS-20", 11: "NTFS", 12: "QDOS", 13: "Acorn RISCOS", 255: "unknown"}


def _zero_terminated(stream: BinaryIO, limit: int) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = stream.read(1)
        if not chunk:
            raise ArchiveFormatError("a truncated gzip header")
        if chunk == b"\x00":
            return bytes(data)
        data += chunk
    raise ArchiveFormatError(f"a gzip header field longer than {limit:,} bytes")


def _gzip(stream: BinaryIO, size: int) -> dict[str, Any]:
    head = stream.read(10)
    if len(head) < 10 or head[:2] != b"\x1f\x8b":
        raise ArchiveFormatError("not a gzip stream")
    method, flags, mtime, system = head[2], head[3], struct.unpack_from("<L", head, 4)[0], head[9]
    if method != 8:
        raise ArchiveFormatError(f"gzip compression method {method}, not deflate")
    if flags & 0xE0:
        raise ArchiveFormatError("reserved gzip header flags are set")
    if flags & 0x04:  # FEXTRA
        extra = stream.read(2)
        if len(extra) < 2:
            raise ArchiveFormatError("a truncated gzip header")
        stream.seek(struct.unpack("<H", extra)[0], io.SEEK_CUR)
    name = _zero_terminated(stream, 4096).decode("latin-1") if flags & 0x08 else None
    comment = _zero_terminated(stream, 65536) if flags & 0x10 else None
    if size < 18:
        raise ArchiveFormatError("a gzip stream shorter than its header and trailer")
    stream.seek(size - 4)
    trailer = struct.unpack("<L", stream.read(4))[0]
    return {
        "original_name": name, "mtime": _utc(mtime) if mtime else None,
        "system": _GZIP_SYSTEMS.get(system, str(system)), "has_comment": comment is not None,
        "trailer_size": trailer,
        # The trailer holds the size modulo 4 GiB, so it is the size only for a file too small to
        # expand past 4 GiB (and, in a file of several gzip members, only the last member's).
        "content_bytes": trailer if size * _DEFLATE_MAX_RATIO < 1 << 32 else None,
    }


def _xz_vint(data: bytes, cursor: int) -> tuple[int, int]:
    """An xz multibyte integer: 7 bits a byte, little-endian, at most 9 bytes."""
    value = 0
    for shift in range(0, 63, 7):
        if cursor >= len(data):
            raise ArchiveFormatError("a truncated xz index")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
    raise ArchiveFormatError("an xz index integer longer than 9 bytes")


def _padding_start(stream: BinaryIO, end: int, deadline: float | None) -> int | None:
    """Where the zero bytes that end at ``end`` start (None when the deadline passes first)."""
    position = end
    while position > 0:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        start = max(0, position - 65536)
        stream.seek(start)
        stripped = stream.read(position - start).rstrip(b"\0")
        if stripped:
            return start + len(stripped)
        position = start
    return 0


def _xz(stream: BinaryIO, size: int, max_index_bytes: int, deadline: float | None) -> dict[str, Any]:
    """An xz file's streams and blocks and its uncompressed size, from each stream's index,
    walked from the end of the file; no block is decompressed."""
    streams = blocks = total = index_bytes = 0
    end = size
    while end > 0:
        if deadline is not None and time.monotonic() >= deadline:
            return {"streams": streams, "blocks": blocks, "content_bytes": None, "complete": False}
        if end >= 4:
            stream.seek(end - 4)
            if stream.read(4) == b"\0\0\0\0":  # stream padding, in multiples of four bytes
                start = _padding_start(stream, end, deadline)
                if start is None:
                    return {"streams": streams, "blocks": blocks, "content_bytes": None, "complete": False}
                if (end - start) % 4:
                    raise ArchiveFormatError("xz stream padding that is not a multiple of four bytes")
                end = start
                continue
        if end < 2 * _XZ_FOOTER:
            raise ArchiveFormatError("an xz stream shorter than its header and footer")
        stream.seek(end - _XZ_FOOTER)
        footer = stream.read(_XZ_FOOTER)
        if footer[10:12] != b"YZ":
            raise ArchiveFormatError("no xz stream footer")
        backward = (struct.unpack_from("<L", footer, 4)[0] + 1) * 4
        index_bytes += backward
        if index_bytes > max_index_bytes:
            raise ArchiveLimitError("index_bytes", index_bytes, f"the xz indexes hold {index_bytes:,} bytes")
        index_start = end - _XZ_FOOTER - backward
        if index_start < _XZ_FOOTER:
            raise ArchiveFormatError("an xz index that starts before its stream")
        stream.seek(index_start)
        index = stream.read(backward)
        if index[:1] != b"\0":
            raise ArchiveFormatError("no xz index indicator")
        records, cursor = _xz_vint(index, 1)
        if records > backward:
            raise ArchiveFormatError("an xz index declaring more records than it holds")
        packed = 0
        for _ in range(records):
            unpadded, cursor = _xz_vint(index, cursor)
            uncompressed, cursor = _xz_vint(index, cursor)
            packed += unpadded + (-unpadded % 4)
            total += uncompressed
        blocks += records
        streams += 1
        end = index_start - packed - _XZ_FOOTER
        if end < 0:
            raise ArchiveFormatError("xz blocks that start before the file")
        stream.seek(end)
        if stream.read(6) != b"\xfd7zXZ\x00":
            raise ArchiveFormatError(f"no xz stream header at offset {end}")
    if not streams:
        raise ArchiveFormatError("no xz stream")
    return {"streams": streams, "blocks": blocks, "content_bytes": total, "complete": True}


def _zstd(stream: BinaryIO, size: int, deadline: float | None) -> dict[str, Any]:
    """A Zstandard file's frames, walked through their block headers without decompressing:
    their declared content sizes (exact for raw and RLE blocks), window and dictionaries."""
    frames = skippable = checksums = steps = known = window = 0
    exact, dictionaries, position = True, set(), 0
    result: dict[str, Any] = {}
    while position < size:
        steps += 1
        if deadline is not None and steps % 4096 == 0 and time.monotonic() >= deadline:
            result["complete"], exact = False, False
            break
        stream.seek(position)
        head = stream.read(18)
        magic = struct.unpack_from("<L", head)[0] if len(head) >= 4 else None
        if magic is not None and 0x184D2A50 <= magic <= 0x184D2A5F and len(head) >= 8:
            skippable += 1
            position += 8 + struct.unpack_from("<L", head, 4)[0]
            continue
        if magic != 0xFD2FB528 or len(head) < 6:
            raise ArchiveFormatError(f"no Zstandard frame at offset {position}")
        descriptor = head[4]
        size_flag, single, checksum, dictionary_flag = descriptor >> 6, descriptor & 0x20, descriptor & 0x04, descriptor & 3
        if descriptor & 0x08:
            raise ArchiveFormatError("a reserved Zstandard frame header bit is set")
        cursor = 5
        if not single:
            exponent, mantissa = head[cursor] >> 3, head[cursor] & 7
            base = 1 << (10 + exponent)
            window = max(window, base + base // 8 * mantissa)
            cursor += 1
        dictionary_bytes = (0, 1, 2, 4)[dictionary_flag]
        if dictionary_bytes:
            dictionaries.add(int.from_bytes(head[cursor:cursor + dictionary_bytes], "little"))
        cursor += dictionary_bytes
        content_bytes = (1 if single else 0, 2, 4, 8)[size_flag]
        content = None
        if content_bytes:
            content = int.from_bytes(head[cursor:cursor + content_bytes], "little") + (256 if content_bytes == 2 else 0)
            if single:
                window = max(window, content)
        position += cursor + content_bytes
        regenerated, blocks_exact = 0, True
        while True:
            steps += 1
            if deadline is not None and steps % 4096 == 0 and time.monotonic() >= deadline:
                result["complete"] = False
                exact = False
                break
            stream.seek(position)
            block = stream.read(3)
            if len(block) < 3:
                raise ArchiveFormatError("a truncated Zstandard block header")
            header = int.from_bytes(block, "little")
            last, kind, block_size = header & 1, (header >> 1) & 3, header >> 3
            if kind == 3:
                raise ArchiveFormatError("a reserved Zstandard block type")
            if kind == 2:
                blocks_exact = False  # a compressed block regenerates up to 128 KiB
            regenerated += block_size if kind in (0, 1) else 128 * 1024
            position += 3 + (1 if kind == 1 else block_size)
            if position > size:
                raise ArchiveFormatError("a Zstandard block runs past the end of the file")
            if last:
                break
        if result.get("complete") is False:
            break
        if checksum:
            checksums += 1
            position += 4
        frames += 1
        if content is not None:
            known += content
        elif blocks_exact:
            known += regenerated
        else:
            exact = False
    result.setdefault("complete", True)
    result.update(frames=frames, skippable_frames=skippable, checksummed_frames=checksums,
                  window_bytes=window or None, dictionaries=sorted(dictionaries),
                  content_bytes=known if exact else None)
    return result


def read_compressed(stream: BinaryIO, size: int, codec: str, max_index_bytes: int,
                    deadline: float | None = None) -> dict[str, Any]:
    """The metadata of a single compressed file's header (and, for xz and Zstandard, of its
    index or frames), with ``content_bytes`` when the format says how large the content is."""
    stream.seek(0)
    if codec == "gzip":
        return _gzip(stream, size)
    if codec == "xz":
        return _xz(stream, size, max_index_bytes, deadline)
    if codec == "zstd":
        return _zstd(stream, size, deadline)
    head = stream.read(13)
    if codec == "bzip2":
        if len(head) < 4 or head[:3] != b"BZh" or head[3] not in b"123456789":
            raise ArchiveFormatError("not a bzip2 stream")
        return {"block_size_kb": 100 * (head[3] - 0x30), "content_bytes": None}
    if codec == "lzma":
        if len(head) < 13 or head[0] >= 9 * 5 * 5:
            raise ArchiveFormatError("not an LZMA stream")
        dictionary, declared = struct.unpack_from("<LQ", head, 1)
        return {"dictionary_bytes": dictionary, "content_bytes": None if declared == (1 << 64) - 1 else declared}
    raise ValueError(f"unknown codec {codec!r}")
