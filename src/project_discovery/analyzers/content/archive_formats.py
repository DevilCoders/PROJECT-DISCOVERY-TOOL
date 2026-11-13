"""Metadata readers for archive formats beyond ZIP and TAR: ar (Debian packages and static
libraries), Microsoft Cabinet and RPM, and the Zstandard decompressor the TAR reader uses.

Each reader parses the format's own headers from a seekable binary stream, returns at most
``max_entries`` member entries and decompresses no member data; a DEB's control tarball, a
few KiB, is the one exception, read for its package fields under a decompressed-byte cap.
Malformed input raises ``ArchiveFormatError``, an index larger than its budget
``ArchiveLimitError``. The standard library suffices, except for Zstandard before Python
3.14, which needs the optional ``zstandard`` package (``pip install
"project-discovery-tool[archives]"``).
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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, BinaryIO


class ArchiveFormatError(ValueError):
    """The stream does not hold a well-formed archive of the format."""


class ArchiveLimitError(Exception):
    """An archive index is larger than its budget; nothing past the budget was read."""

    def __init__(self, limit: str, used: int, message: str) -> None:
        super().__init__(message)
        self.limit, self.used = limit, used


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
    offset: int | None = None  # where the member's bytes start, in formats that store them as is (ar)


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
