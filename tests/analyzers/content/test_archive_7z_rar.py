"""7z and RAR (4 and 5) inspection, with archives built byte by byte to each format's layout."""
from __future__ import annotations

import io
import lzma
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from project_discovery.analyzers.content import archives
from test_archive_formats import _analyze, _titles

_SECRET = ("aws_access_key_id = " + "AKIA" + "ABCDEFGHIJKLMNOP\n").encode()
_FILETIME = (1_700_000_000 + 11_644_473_600) * 10_000_000  # 2023-11-14T22:13:20Z
_WHEN = "2023-11-14T22:13:20Z"
_DOS_TIME = (((2024 - 1980) << 9 | 5 << 5 | 6) << 16) | (7 << 11 | 8 << 5 | 5)  # 2024-05-06 07:08:10


def _inspect(tmp_path: Path, name: str, data: bytes, file_type: str):
    path = tmp_path / name
    path.write_bytes(data)
    summaries, members, findings = _analyze(path, file_type)
    return path, summaries, members, findings


def _tar_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("../escape.sh")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"run"))
    return buffer.getvalue()


# ---------------------------------------------------------------------------------------
# 7z


def _number(value: int) -> bytes:
    """A 7z number: leading 1 bits in the first byte say how many bytes follow."""
    for extra in range(8):
        if value < 1 << (7 * (extra + 1)):
            first = ((0xFF00 >> extra) & 0xFF) | (value >> (8 * extra))
            return bytes([first]) + (value & ((1 << (8 * extra)) - 1)).to_bytes(extra, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _bits(values) -> bytes:
    out = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            out[index // 8] |= 0x80 >> (index % 8)
    return bytes(out)


_LZMA2 = {"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}  # property byte 16
_AES = (b"\x06\xf1\x07\x01", b"\x01\x02")


def _coder(method: bytes, properties: bytes = b"") -> bytes:
    return bytes([len(method) | (0x20 if properties else 0)]) + method + (
        _number(len(properties)) + properties if properties else b"")


def _streams(pack_sizes, folders, folder_sizes, substreams=None, pack_position: int = 0) -> bytes:
    """A StreamsInfo block: folders are coder byte strings, one coder each."""
    out = b"\x06" + _number(pack_position) + _number(len(pack_sizes)) + b"\x09"
    out += b"".join(_number(item) for item in pack_sizes) + b"\x00"
    out += b"\x07\x0b" + _number(len(folders)) + b"\x00"
    out += b"".join(b"\x01" + coder for coder in folders)
    out += b"\x0c" + b"".join(_number(item) for item in folder_sizes) + b"\x00"
    if substreams is not None:
        counts, sizes = substreams
        out += b"\x08\x0d" + b"".join(_number(item) for item in counts)
        if sizes:
            out += b"\x09" + b"".join(_number(item) for item in sizes)
        out += b"\x00"
    return out + b"\x00"


def _files(names, empty_stream=None, empty_file=None, mtimes=True, attributes=None) -> bytes:
    count = len(names)
    out = b"\x05" + _number(count)
    if empty_stream is not None:
        vector = _bits(empty_stream)
        out += b"\x0e" + _number(len(vector)) + vector
        vector = _bits(empty_file)
        out += b"\x0f" + _number(len(vector)) + vector
    text = b"\x00" + b"".join(name.encode("utf-16-le") + b"\x00\x00" for name in names)
    out += b"\x11" + _number(len(text)) + text
    if mtimes:
        times = b"\x01\x00" + b"".join(struct.pack("<Q", _FILETIME) for _ in names)
        out += b"\x14" + _number(len(times)) + times
    if attributes is not None:
        values = b"\x01\x00" + b"".join(struct.pack("<L", item) for item in attributes)
        out += b"\x15" + _number(len(values)) + values
    return out + b"\x00"


def _seven(packed: bytes, header: bytes, *, encode: bool = False, encrypt_header: bool = False) -> bytes:
    """A 7z archive: the packed streams, then the header, plain or packed with LZMA as 7-Zip writes it."""
    if encode:
        filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}]
        body = lzma.compress(header, format=lzma.FORMAT_RAW, filters=filters)
        coder = _AES if encrypt_header else (b"\x03\x01\x01", bytes([93]) + struct.pack("<L", 1 << 16))
        position = len(packed)
        packed += body
        header = b"\x17" + _streams([len(body)], [_coder(*coder)], [len(header)], pack_position=position)
    start = struct.pack("<QQL", len(packed), len(header), zlib.crc32(header))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<L", zlib.crc32(start)) + start + packed + header


def _stored_seven() -> bytes:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("../escape.txt", "x")
    files = [(b"hello\n", "docs/readme.txt"), (_SECRET, "secret.env"), (inner.getvalue(), "lib/inner.zip")]
    packed = b"".join(data for data, _ in files)
    names = ["docs", "docs/readme.txt", "secret.env", "lib/inner.zip", "empty.txt"]
    header = (b"\x01\x04" + _streams([len(data) for data, _ in files], [_coder(b"\x00")] * 3,
                                     [len(data) for data, _ in files])
              + _files(names, [True, False, False, False, True], [False, True], attributes=[0x10, 0x20, 0x20, 0x20, 0x20])
              + b"\x00")
    return _seven(packed, header)


def test_a_7z_header_lists_files_directories_sizes_and_times_and_stored_members_are_read(tmp_path: Path):
    path, summaries, members, findings = _inspect(tmp_path, "bundle.7z", _stored_seven(), "archive/7z")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("7z", "metadata-complete")
    assert summary["7z"] == {"version": "0.4", "encoded_header": False, "headers_encrypted": False, "folders": 3,
                             "methods": ["copy"], "solid": False, "packed_bytes": summary["7z"]["packed_bytes"]}
    listed = members[path.name]
    assert list(listed) == ["docs", "docs/readme.txt", "secret.env", "lib/inner.zip", "empty.txt"]
    assert listed["docs"]["type"] == "directory" and listed["empty.txt"] == {**listed["empty.txt"], "type": "file",
                                                                             "size": 0}
    assert listed["docs/readme.txt"] == {**listed["docs/readme.txt"], "size": 6, "compressed_size": 6, "mtime": _WHEN}
    # Stored (copy) members are their bytes: sampled in place, and an archive in one inspected.
    assert any(item.title == f"Provider Credential Token inside archive member: {path.name}" for item in findings)
    assert summaries[f"{path.name}::lib/inner.zip"]["state"] == "metadata-complete"
    assert "Archive path traversal indicators" in _titles(findings)


def test_a_packed_header_and_a_solid_folder_give_each_files_size(tmp_path: Path):
    contents = [b"a" * 1000, b"b" * 2000, b"c" * 3000]
    body = lzma.compress(b"".join(contents), format=lzma.FORMAT_RAW, filters=[_LZMA2])
    header = (b"\x01\x04" + _streams([len(body)], [_coder(b"\x21", bytes([16]))], [6000],
                                     substreams=([3], [1000, 2000]))
              + _files(["a.txt", "b.txt", "c.txt"]) + b"\x00")
    path, summaries, members, _ = _inspect(tmp_path, "solid.7z", _seven(body, header, encode=True), "archive/7z")
    info = summaries[path.name]["7z"]
    assert (info["encoded_header"], info["solid"], info["methods"]) == (True, True, ["lzma2"])
    assert [(item["size"], item["compressed_size"]) for item in members[path.name].values()] == [
        (1000, None), (2000, None), (3000, None)]  # a solid folder has no per-member packed size
    assert summaries[path.name]["members_sampled"] == 0


def test_unix_modes_in_7z_attributes_give_links_and_permission_flags(tmp_path: Path):
    unix = 0x8000
    header = (b"\x01\x04" + _streams([5, 9], [_coder(b"\x00")] * 2, [5, 9])
              + _files(["tool", "link"], attributes=[unix | (0o104755 << 16), unix | (0o120777 << 16)]) + b"\x00")
    path, _, members, findings = _inspect(tmp_path, "modes.7z", _seven(b"\x7fELF\x00../target", header), "archive/7z")
    assert members[path.name]["tool"]["flags"] == ["setuid"] and members[path.name]["tool"]["mode"] == 0o4755
    assert members[path.name]["link"]["type"] == "symlink" and members[path.name]["link"]["flags"] == []
    assert "Risky archive permissions" in _titles(findings)


def test_encrypted_7z_folders_and_headers_are_reported(tmp_path: Path):
    header = b"\x01\x04" + _streams([32], [_coder(*_AES)], [20]) + _files(["locked.bin"]) + b"\x00"
    path, summaries, members, findings = _inspect(tmp_path, "locked.7z", _seven(bytes(32), header), "archive/7z")
    assert members[path.name]["locked.bin"]["flags"] == ["encrypted"]
    assert summaries[path.name]["encrypted_members"] == 1 and "encrypted" in summaries[path.name]["states"]
    assert summaries[path.name]["7z"]["methods"] == ["aes"]
    assert "Encrypted archive entries" in _titles(findings)
    hidden = _seven(b"", b"\x01" + _files(["secret-name.txt"]) + b"\x00", encode=True, encrypt_header=True)
    path, summaries, members, findings = _inspect(tmp_path, "hidden.7z", hidden, "archive/7z")
    assert summaries[path.name]["state"] == "encrypted" and path.name not in members
    assert summaries[path.name]["7z"]["headers_encrypted"] is True
    assert "Encrypted archive index" in _titles(findings)


def test_a_7z_member_compressed_past_the_ratio_is_flagged(tmp_path: Path):
    body = lzma.compress(bytes(8 << 20), format=lzma.FORMAT_RAW, filters=[_LZMA2])
    header = b"\x01\x04" + _streams([len(body)], [_coder(b"\x21", bytes([16]))], [8 << 20]) + _files(["zeros"]) + b"\x00"
    path, summaries, members, findings = _inspect(tmp_path, "zeros.7z", _seven(body, header), "archive/7z")
    assert members[path.name]["zeros"]["flags"] == ["high-ratio"]
    assert summaries[path.name]["compression_ratio"] > 1000
    titles = _titles(findings)
    assert "High compression-ratio archive entries" in titles and "High compression-ratio archive" in titles


def test_an_empty_7z_archive_is_complete(tmp_path: Path):
    start = struct.pack("<QQL", 0, 0, 0)
    data = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<L", zlib.crc32(start)) + start
    path, summaries, members, _ = _inspect(tmp_path, "empty.7z", data, "archive/7z")
    assert (summaries[path.name]["state"], summaries[path.name]["members_declared"]) == ("metadata-complete", 0)


@pytest.mark.parametrize(("mutate", "error"), [
    (lambda data: data[:8] + b"\0\0\0\0" + data[12:], "start header's CRC does not match"),
    (lambda data: data[:-1] + bytes([data[-1] ^ 1]), "header's CRC does not match"),
    (lambda data: data[:-5], "past the end of the file"),
    (lambda data: b"7z\xbc\xaf\x27\x1c" + b"\0" * 10, "not a 7z archive"),
])
def test_corrupt_7z_archives_are_malformed(tmp_path: Path, mutate, error):
    path, summaries, _, _ = _inspect(tmp_path, "bad.7z", mutate(_stored_seven()), "archive/7z")
    assert summaries[path.name]["state"] == "malformed" and error in summaries[path.name]["error"]


def test_a_7z_header_over_the_index_budget_is_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_INDEX_BYTES", 64)
    path, summaries, _, findings = _inspect(tmp_path, "big.7z", _stored_seven(), "archive/7z")
    assert summaries[path.name]["state"] == "budget-stopped" and findings[0].title.startswith("7Z index budget")


# ---------------------------------------------------------------------------------------
# RAR 4


def _rar4_block(kind: int, flags: int, body: bytes, data: bytes = b"") -> bytes:
    header = struct.pack("<BHH", kind, flags, 7 + len(body)) + body
    return struct.pack("<H", zlib.crc32(header) & 0xFFFF) + header + data


def _rar4_unicode(name: str) -> bytes:
    """RAR 4's compressed UTF-16 name: here every character in two bytes (mode 2)."""
    out, chars = bytearray([0]), [ord(char) for char in name]
    for start in range(0, len(chars), 4):
        group = chars[start:start + 4]
        out.append(sum(0b10 << (6 - 2 * index) for index in range(len(group))))
        for char in group:
            out += char.to_bytes(2, "little")
    return bytes(out)


def _rar4_file(name: str, data: bytes, *, unpacked: int | None = None, method: int = 0x30, host: int = 2,
               attribute: int = 0x20, flags: int = 0, unicode: bool = False) -> bytes:
    raw = name.encode("ascii", "replace") + (b"\0" + _rar4_unicode(name) if unicode else b"")
    body = struct.pack("<LLBLLBBHL", len(data), len(data) if unpacked is None else unpacked, host, zlib.crc32(data),
                       _DOS_TIME, 29, method, len(raw), attribute) + raw
    return _rar4_block(0x74, 0x8000 | flags | (0x0200 if unicode else 0), body, data)


def _rar4(*files: bytes, archive_flags: int = 0) -> bytes:
    return (b"Rar!\x1a\x07\x00" + _rar4_block(0x73, archive_flags, bytes(6)) + b"".join(files)
            + _rar4_block(0x7B, 0x4000, b""))


def test_rar4_headers_list_names_sizes_times_and_stored_members_are_read(tmp_path: Path):
    data = _rar4(
        _rar4_file("docs", b"", flags=0x00E0, attribute=0x10),
        _rar4_file("docs\\readme.txt", b"hello\n"),
        _rar4_file("secret.env", _SECRET),
        _rar4_file("naïve.txt", b"x", unicode=True),
        _rar4_file("locked.bin", bytes(16), method=0x33, flags=0x0004),
        _rar4_file("tool", b"\x7fELF", host=3, attribute=0o104755),
        _rar4_file("zeros.bin", bytes(64), unpacked=10 << 20, method=0x35),
        _rar4_file("pack.tar", _tar_bytes()),
    )
    path, summaries, members, findings = _inspect(tmp_path, "bundle.rar", data, "archive/rar")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("rar", "metadata-complete")
    assert summary["rar"] == {"version": 4, "headers_encrypted": False, "volume": False, "solid": False,
                              "locked": False, "recovery_record": False, "comment": False}
    listed = members[path.name]
    assert list(listed) == ["docs", "docs/readme.txt", "secret.env", "naïve.txt", "locked.bin", "tool", "zeros.bin",
                            "pack.tar"]
    assert listed["docs"]["type"] == "directory"
    assert listed["docs/readme.txt"] == {**listed["docs/readme.txt"], "size": 6, "mtime": "2024-05-06T07:08:10"}
    assert listed["locked.bin"]["flags"] == ["encrypted"]
    assert listed["tool"] == {**listed["tool"], "mode": 0o4755, "flags": ["setuid"]}
    assert listed["zeros.bin"]["flags"] == ["high-ratio"]
    assert listed["pack.tar"]["flags"] == ["nested-archive"]
    assert members[f"{path.name}::pack.tar"]["../escape.sh"]["flags"] == ["unsafe-path"]
    titles = _titles(findings)
    for title in ("Provider Credential Token inside archive member", "Encrypted archive entries",
                  "Risky archive permissions", "High compression-ratio archive entries"):
        assert title in titles


def test_rar4_encrypted_headers_and_corrupt_blocks(tmp_path: Path):
    path, summaries, _, findings = _inspect(tmp_path, "hidden.rar", _rar4(archive_flags=0x0080)[:20] + bytes(40),
                                            "archive/rar")
    assert summaries[path.name]["state"] == "encrypted" and "Encrypted archive index" in _titles(findings)
    data = bytearray(_rar4(_rar4_file("a.txt", b"abc")))
    data[7 + 13 + 7 + 25] ^= 0x01  # the file name's first byte: the header's CRC no longer matches
    path, summaries, _, _ = _inspect(tmp_path, "bad.rar", bytes(data), "archive/rar")
    assert summaries[path.name]["state"] == "malformed" and "fails its CRC" in summaries[path.name]["error"]


def test_a_solid_rar_does_not_judge_members_by_their_packed_size(tmp_path: Path):
    data = _rar4(_rar4_file("a.bin", bytes(10), unpacked=10 << 20, method=0x35, flags=0x0010), archive_flags=0x0008)
    path, summaries, members, _ = _inspect(tmp_path, "solid.rar", data, "archive/rar")
    assert summaries[path.name]["rar"]["solid"] is True and members[path.name]["a.bin"]["flags"] == []


# ---------------------------------------------------------------------------------------
# RAR 5


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _rar5_block(kind: int, fields: bytes, *, flags: int = 0, extra: bytes = b"", data: bytes = b"") -> bytes:
    body = _vint(kind) + _vint(flags | (0x0001 if extra else 0) | (0x0002 if data else 0))
    body += (_vint(len(extra)) if extra else b"") + (_vint(len(data)) if data else b"") + fields + extra
    sized = _vint(len(body)) + body
    return struct.pack("<L", zlib.crc32(sized)) + sized + data


def _record(kind: int, data: bytes) -> bytes:
    payload = _vint(kind) + data
    return _vint(len(payload)) + payload


def _rar5_file(name: str, data: bytes, *, unpacked: int | None = None, directory: bool = False, method: int = 0,
               host: int = 1, attribute: int = 0o100644, extra: bytes = b"") -> bytes:
    fields = (_vint(0x0001 if directory else 0x0002) + _vint(len(data) if unpacked is None else unpacked)
              + _vint(attribute) + (b"" if directory else struct.pack("<L", 1_700_000_000))
              + _vint(method << 7) + _vint(host) + _vint(len(name.encode())) + name.encode())
    return _rar5_block(2, fields, extra=extra, data=data)


def _rar5(*files: bytes, archive_flags: int = 0) -> bytes:
    return (b"Rar!\x1a\x07\x01\x00" + _rar5_block(1, _vint(archive_flags)) + b"".join(files)
            + _rar5_block(5, _vint(0)))


def test_rar5_headers_list_files_links_owners_and_encryption(tmp_path: Path):
    owner = _record(6, _vint(0x3) + _vint(4) + b"root" + _vint(5) + b"wheel")
    link = _record(5, _vint(1) + _vint(0) + _vint(13) + b"../etc/passwd")
    hard = _record(5, _vint(4) + _vint(0) + _vint(7) + b"tool.sh")
    encryption = _record(1, _vint(0) + _vint(0) + bytes([15]) + bytes(32))
    data = _rar5(
        _rar5_file("dir", b"", directory=True, attribute=0o40755),
        _rar5_file("tool.sh", b"#!/bin/sh\n", attribute=0o104755, extra=owner),
        _rar5_file("passwd-link", b"", attribute=0o120777, extra=link),
        _rar5_file("tool-copy.sh", b"", extra=hard),
        _rar5_file("secret.env", _SECRET),
        _rar5_file("locked.bin", bytes(16), method=3, extra=encryption),
    )
    path, summaries, members, findings = _inspect(tmp_path, "bundle.rar", data, "archive/rar")
    summary = summaries[path.name]
    assert summary["rar"] == {"version": 5, "headers_encrypted": False, "volume": False, "solid": False,
                              "recovery_record": False, "locked": False}
    listed = members[path.name]
    assert listed["dir"]["type"] == "directory"
    assert listed["tool.sh"] == {**listed["tool.sh"], "owner": "root", "group": "wheel", "mode": 0o4755,
                                 "mtime": _WHEN, "flags": ["setuid"]}
    assert listed["passwd-link"] == {**listed["passwd-link"], "type": "symlink", "link_target": "../etc/passwd",
                                     "flags": ["unsafe-path"]}
    assert listed["tool-copy.sh"] == {**listed["tool-copy.sh"], "type": "hardlink", "link_target": "tool.sh"}
    assert listed["locked.bin"]["flags"] == ["encrypted"]
    titles = _titles(findings)
    for title in ("Provider Credential Token inside archive member", "Archive path traversal indicators",
                  "Archive hardlink entries", "Archive symlink entries", "Encrypted archive entries"):
        assert title in titles


def test_rar5_archive_encryption_hides_the_index(tmp_path: Path):
    data = b"Rar!\x1a\x07\x01\x00" + _rar5_block(4, _vint(0) + _vint(0) + bytes([15]) + bytes(16)) + bytes(64)
    path, summaries, members, findings = _inspect(tmp_path, "hidden.rar", data, "archive/rar")
    assert summaries[path.name]["state"] == "encrypted" and path.name not in members
    assert "Encrypted archive index" in _titles(findings)


@pytest.mark.parametrize(("data", "error"), [
    (b"Rar!\x1a\x07\x01\x00" + b"\0\0\0\0\x01", "RAR 5 header of 1 bytes"),
    (_rar5(_rar5_file("a.txt", b"abc"))[:-12], "truncated RAR 5 block"),
    (b"Rar!\x1a\x07\x02" + bytes(8), "not a RAR archive"),
])
def test_malformed_rar5_archives(tmp_path: Path, data, error):
    path, summaries, _, _ = _inspect(tmp_path, "bad.rar", data, "archive/rar")
    assert summaries[path.name]["state"] == "malformed" and error in summaries[path.name]["error"]


def test_the_rar_entry_limit_stops_the_listing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_ENTRIES", 2)
    data = _rar5(*(_rar5_file(f"f{index}.txt", b"x") for index in range(4)))
    path, summaries, members, _ = _inspect(tmp_path, "many.rar", data, "archive/rar")
    assert summaries[path.name]["state"] == "budget-stopped" and len(members[path.name]) == 2
