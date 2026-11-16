"""ISO 9660 images (Rock Ridge, Joliet, UDF detection) and single compressed files (gzip,
bzip2, xz, LZMA, Zstandard), with fixtures built byte by byte."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from project_discovery.analyzers.content import archive_formats, archives
from test_archive_formats import _analyze, _ar, _titles, _zstd_frame

_SECTOR = 2048
_WHEN = bytes([124, 5, 6, 7, 8, 10, 0])  # 2024-05-06 07:08:10 UTC
_WHEN_TEXT = "2024-05-06T07:08:10Z"
_SECRET = ("aws_access_key_id = " + "AKIA" + "ABCDEFGHIJKLMNOP\n").encode()


# ---------------------------------------------------------------------------------------
# ISO 9660 fixtures


def _both32(value: int) -> bytes:
    return struct.pack("<L", value) + struct.pack(">L", value)


def _record(name: bytes, extent: int, size: int, flags: int = 0, system_use: bytes = b"",
            big_endian_extent: int | None = None) -> bytes:
    """A directory record; flags 2 marks a directory, 0x80 an extent that more follow."""
    padding = b"" if len(name) % 2 else b"\0"
    body = (struct.pack("<L", extent) + struct.pack(">L", extent if big_endian_extent is None else big_endian_extent)
            + _both32(size) + _WHEN + bytes([flags, 0, 0]) + struct.pack("<H", 1) + struct.pack(">H", 1)
            + bytes([len(name)]) + name + padding + system_use)
    if len(body) % 2:
        body += b"\0"
    return bytes([2 + len(body), 0]) + body


def _directory(extent: int, parent: int, children, dot_use: bytes = b"") -> bytes:
    """A directory's records, "." and ".." first, none crossing a sector, padded to a sector."""
    data = b""
    for record in [_record(b"\0", extent, _SECTOR, 2, dot_use), _record(b"\1", parent, _SECTOR, 2)] + list(children):
        if len(data) // _SECTOR != (len(data) + len(record) - 1) // _SECTOR:
            data += b"\0" * (-len(data) % _SECTOR)
        data += record
    return data + b"\0" * (-len(data) % _SECTOR)


def _descriptor(kind: int, root_extent: int = 0, volume_blocks: int = 64, escape: bytes = b"") -> bytes:
    block = bytearray(_SECTOR)
    block[0], block[1:6], block[6] = kind, b"CD001", 1
    if kind in (1, 2):
        block[8:40] = b"LINUX".ljust(32)
        block[40:72] = b"PDT_TEST".ljust(32)
        block[80:88] = _both32(volume_blocks)
        block[88:88 + len(escape)] = escape
        block[128:132] = struct.pack("<H", _SECTOR) + struct.pack(">H", _SECTOR)
        block[156:190] = _record(b"\0", root_extent, _SECTOR, 2)
        block[318:446] = b"PDT TESTS".ljust(128)
        block[813:830] = b"2024050607081000\0"
    return bytes(block)


def _image(sectors: dict[int, bytes], volume_blocks: int | None = None) -> bytes:
    count = max(index + -(-len(data) // _SECTOR) for index, data in sectors.items())
    out = bytearray(_SECTOR * count)
    for index, data in sectors.items():
        out[index * _SECTOR:index * _SECTOR + len(data)] = data
    return bytes(out)


def _su(signature: bytes, data: bytes) -> bytes:
    return signature + bytes([4 + len(data), 1]) + data


def _px(mode: int, uid: int = 0, gid: int = 0) -> bytes:
    return _su(b"PX", _both32(mode) + _both32(1) + _both32(uid) + _both32(gid))


def _nm(name: str) -> bytes:
    return _su(b"NM", b"\0" + name.encode())


def _sl(*components: tuple[int, bytes]) -> bytes:
    return _su(b"SL", b"\0" + b"".join(bytes([flags, len(text)]) + text for flags, text in components))


_SP = _su(b"SP", b"\xbe\xef\0")


def _rock_ridge_image(extra_root=(), joliet: bool = False) -> bytes:
    root = _directory(20, 20, [
        _record(b"README.TXT;1", 30, 6, 0, _nm("ReadMe.txt") + _px(0o100644)),
        _record(b"DOCS", 21, _SECTOR, 2, _nm("docs") + _px(0o40755)),
        _record(b"TOOL.;1", 31, 3, 0, _nm("tool") + _px(0o104755, 0, 0)),
        _record(b"LINK.;1", 0, 0, 0, _nm("link") + _px(0o120777)
                + _sl((0x04, b""), (0, b"etc"), (0, b"passwd"))),
        *extra_root,
    ], _SP + _px(0o40755))
    docs = _directory(21, 20, [_record(b"NOTES.ENV;1", 32, len(_SECRET), 0, _nm("notes.env") + _px(0o100600, 1000, 1000))])
    sectors = {16: _descriptor(1, 20), 17: _descriptor(255), 20: root, 21: docs,
               30: b"hello\n", 31: b"ELF", 32: _SECRET}
    if joliet:
        sectors[17] = _descriptor(2, 24, escape=b"%/E")
        sectors[18] = _descriptor(255)
        sectors[24] = _directory(24, 24, [_record("Joliet.txt;1".encode("utf-16-be"), 30, 6)])
    return _image(sectors)


def _iso(tmp_path: Path, data: bytes, name: str = "image.iso"):
    path = tmp_path / name
    path.write_bytes(data)
    return path, *_analyze(path, "disk-image/iso9660")


def test_a_primary_tree_lists_files_with_names_sizes_times_and_samples_them_in_place(tmp_path: Path):
    root = _directory(20, 20, [_record(b"README.TXT;1", 30, 6), _record(b"DOCS", 21, _SECTOR, 2),
                               _record(b"NOEXT.;1", 31, 1)])
    docs = _directory(21, 20, [_record(b"NOTES.TXT;1", 32, len(_SECRET))])
    path, summaries, members, findings = _iso(tmp_path, _image({
        16: _descriptor(1, 20), 17: _descriptor(255), 20: root, 21: docs, 30: b"hello\n", 31: b"x", 32: _SECRET}))
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("iso", "metadata-complete")
    assert summary["iso"] == {
        "volume_id": "PDT_TEST", "system_id": "LINUX", "publisher": "PDT TESTS", "preparer": None,
        "application": None, "created": "2024-05-06T07:08:10Z", "modified": None, "block_size": 2048,
        "volume_bytes": 64 * 2048, "tree": "primary", "extensions": [], "missing_bytes": 64 * 2048 - path.stat().st_size,
    }
    listed = members[path.name]
    assert list(listed) == ["README.TXT", "DOCS", "NOEXT", "DOCS/NOTES.TXT"]
    assert listed["README.TXT"] == {**listed["README.TXT"], "type": "file", "size": 6, "mtime": _WHEN_TEXT, "flags": []}
    assert listed["DOCS"]["type"] == "directory" and listed["DOCS"]["size"] is None
    assert (summary["members_declared"], summary["members_fully_sampled"], summary["content_coverage_pct"]) == (4, 3, 100.0)
    assert any(item.title == f"Provider Credential Token inside archive member: {path.name}" for item in findings)
    inventory = next(item for item in findings if item.title.startswith("ISO archive inventory"))
    assert "primary ISO 9660 directory tree" in inventory.detail
    # The volume declares more blocks than the file holds: a truncated image.
    assert "Truncated or corrupt ISO image" in _titles(findings)


def test_rock_ridge_gives_posix_names_modes_owners_and_links(tmp_path: Path):
    path, summaries, members, findings = _iso(tmp_path, _rock_ridge_image(joliet=True))
    summary = summaries[path.name]
    assert summary["iso"]["tree"] == "rock-ridge"  # preferred to Joliet, which only has names
    assert summary["iso"]["extensions"] == ["rock-ridge", "joliet"]
    listed = members[path.name]
    assert list(listed) == ["ReadMe.txt", "docs", "tool", "link", "docs/notes.env"]
    assert listed["ReadMe.txt"]["mode"] == 0o644
    assert listed["docs"] == {**listed["docs"], "type": "directory", "mode": 0o755}
    assert listed["tool"]["flags"] == ["setuid"]
    assert listed["link"] == {**listed["link"], "type": "symlink", "link_target": "../etc/passwd",
                              "flags": ["unsafe-path"]}
    assert listed["docs/notes.env"] == {**listed["docs/notes.env"], "mode": 0o600, "uid": 1000, "gid": 1000}
    titles = _titles(findings)
    for title in ("Archive path traversal indicators", "Archive symlink entries", "Risky archive permissions",
                  "Provider Credential Token inside archive member"):
        assert title in titles


def test_a_joliet_tree_gives_unicode_names(tmp_path: Path):
    root = _directory(20, 20, [_record(b"LONGFI~1.TXT;1", 30, 6)])
    joliet = _directory(24, 24, [_record("A long file name ünïcode.txt;1".encode("utf-16-be"), 30, 6)])
    path, summaries, members, _ = _iso(tmp_path, _image({
        16: _descriptor(1, 20), 17: _descriptor(2, 24, escape=b"%/E"), 18: _descriptor(255), 20: root, 24: joliet,
        30: b"hello\n"}))
    assert summaries[path.name]["iso"]["tree"] == "joliet"
    assert list(members[path.name]) == ["A long file name ünïcode.txt"]


def test_a_rock_ridge_relocated_directory_is_listed_where_it_belongs(tmp_path: Path):
    root = _directory(20, 20, [
        _record(b"A", 21, _SECTOR, 2, _nm("a")),
        _record(b"RR_MOVED", 22, _SECTOR, 2, _nm("rr_moved")),
    ], _SP)
    a = _directory(21, 20, [_record(b"DEEP.;1", 0, 0, 0, _nm("deep") + _su(b"CL", _both32(23)))])
    moved = _directory(22, 20, [_record(b"DEEP", 23, _SECTOR, 2, _nm("deep") + _su(b"RE", b""))])
    deep = _directory(23, 21, [_record(b"FILE.TXT;1", 30, 2, 0, _nm("file.txt"))])
    path, _, members, _ = _iso(tmp_path, _image({16: _descriptor(1, 20), 17: _descriptor(255), 20: root, 21: a,
                                                 22: moved, 23: deep, 30: b"ok"}))
    assert list(members[path.name]) == ["a", "rr_moved", "a/deep", "a/deep/file.txt"]
    assert members[path.name]["a/deep"]["type"] == "directory"


def test_a_multi_extent_file_is_one_member(tmp_path: Path):
    root = _directory(20, 20, [_record(b"BIG.BIN;1", 30, _SECTOR, 0x80), _record(b"BIG.BIN;1", 31, 100)])
    path, _, members, _ = _iso(tmp_path, _image({16: _descriptor(1, 20), 17: _descriptor(255), 20: root,
                                                 30: b"a" * _SECTOR, 31: b"b" * 100}))
    assert members[path.name]["BIG.BIN"]["size"] == _SECTOR + 100


def test_directory_loops_and_both_endian_disagreements_are_reported(tmp_path: Path):
    root = _directory(20, 20, [_record(b"LOOP", 20, _SECTOR, 2), _record(b"ODD.TXT;1", 30, 2, 0, b"", 99)])
    path, summaries, members, findings = _iso(tmp_path, _image({16: _descriptor(1, 20), 17: _descriptor(255), 20: root,
                                                                30: b"ok"}))
    issues = summaries[path.name]["iso"]["structure_issues"]
    assert issues == {"both-endian-mismatch": 1, "directory-loop": 1}
    assert list(members[path.name]) == ["LOOP", "ODD.TXT"]
    titles = _titles(findings)
    assert "ISO directory loop" in titles and "ISO directory records disagree with themselves" in titles


def test_files_past_the_end_of_the_image_mark_it_malformed(tmp_path: Path):
    root = _directory(20, 20, [_record(b"CUT.BIN;1", 30, 10 * _SECTOR)])
    path, summaries, members, findings = _iso(tmp_path, _image({16: _descriptor(1, 20), 17: _descriptor(255), 20: root,
                                                                30: b"partial"}))
    assert summaries[path.name]["state"] == "malformed"
    assert members[path.name]["CUT.BIN"]["flags"] == ["out-of-bounds"]
    assert "Truncated or corrupt ISO image" in _titles(findings)


def test_files_that_share_one_extent_are_an_expansion_bomb(tmp_path: Path):
    shared = [_record(f"F{index:03d}.BIN;1".encode(), 30, 1 << 30) for index in range(20)]
    path, summaries, _, findings = _iso(tmp_path, _image({16: _descriptor(1, 20), 17: _descriptor(255),
                                                          20: _directory(20, 20, shared), 30: b"\0" * _SECTOR}))
    assert summaries[path.name]["expansion_ratio"] > 1000
    titles = _titles(findings)
    assert "ISO image files declare far more data than it holds" in titles
    assert "Archive declares more uncompressed data than its budget" in titles


def test_udf_images_are_detected_and_named(tmp_path: Path):
    def descriptor(identifier: bytes) -> bytes:
        return (b"\0" + identifier + b"\1").ljust(_SECTOR, b"\0")
    udf_only = _image({16: descriptor(b"BEA01"), 17: descriptor(b"NSR02"), 18: descriptor(b"TEA01")})
    path, summaries, _, findings = _iso(tmp_path, udf_only, "dvd.iso")
    assert summaries[path.name]["state"] == "unsupported" and summaries[path.name]["format"] == "udf"
    assert "UDF has no built-in reader" in summaries[path.name]["unsupported_reason"]
    hybrid = _image({16: _descriptor(1, 20), 17: _descriptor(255), 18: descriptor(b"BEA01"), 19: descriptor(b"NSR03"),
                     20: _directory(20, 20, [_record(b"README.TXT;1", 30, 6)]), 30: b"hello\n"})
    path, summaries, _, findings = _iso(tmp_path, hybrid, "hybrid.iso")
    assert summaries[path.name]["iso"]["extensions"] == ["udf"]
    assert "UDF file system not read" in _titles(findings)


def test_packages_on_an_image_are_inspected_in_place(tmp_path: Path):
    deb = _ar([(b"debian-binary", b"2.0\n", 0o100644)])
    root = _directory(20, 20, [_record(b"TOOL.DEB;1", 30, len(deb))])
    path, summaries, members, _ = _iso(tmp_path, _image({16: _descriptor(1, 20), 17: _descriptor(255), 20: root,
                                                         30: deb}))
    assert members[path.name]["TOOL.DEB"]["flags"] == ["nested-archive"]
    assert summaries[f"{path.name}::TOOL.DEB"]["format"] == "deb"


def test_iso_directories_over_the_index_budget_are_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_INDEX_BYTES", 1024)
    path, summaries, _, findings = _iso(tmp_path, _rock_ridge_image())
    assert summaries[path.name]["state"] == "budget-stopped"
    assert summaries[path.name]["limits"][0]["limit"] == "index_bytes"
    assert [item.title for item in findings] == [f"ISO index budget exceeded: {path.name}"]


@pytest.mark.parametrize(("data", "error"), [
    (b"\0" * (17 * _SECTOR), "no ISO 9660 primary volume descriptor"),
    (_image({16: _descriptor(1, 20)[:128] + struct.pack("<H", 4096) + _descriptor(1, 20)[130:]}),
     "logical block size of 4096"),
])
def test_malformed_images_are_recorded_malformed(tmp_path: Path, data, error):
    path, summaries, _, _ = _iso(tmp_path, data)
    assert summaries[path.name]["state"] == "malformed" and error in summaries[path.name]["error"]


# ---------------------------------------------------------------------------------------
# Single compressed files


def _stream(tmp_path: Path, name: str, data: bytes, file_type: str):
    path = tmp_path / name
    path.write_bytes(data)
    summaries, members, findings = _analyze(path, file_type)
    return path, summaries[path.name], members.get(path.name, {}), findings


def _gzip(payload: bytes, name: bytes | None = None, mtime: int = 1_700_000_000) -> bytes:
    """A gzip member written by hand, so its FNAME field may hold any name."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = compressor.compress(payload) + compressor.flush()
    header = b"\x1f\x8b\x08" + bytes([0x08 if name else 0]) + struct.pack("<L", mtime) + b"\0\x03"
    return header + (name + b"\0" if name else b"") + body + struct.pack("<LL", zlib.crc32(payload), len(payload))


def test_a_gzip_file_records_its_original_name_time_size_and_content(tmp_path: Path):
    path, summary, members, findings = _stream(tmp_path, "settings.gz", _gzip(_SECRET, b"settings.env"), "archive/gzip")
    assert (summary["format"], summary["state"]) == ("gzip", "metadata-complete")
    assert summary["stream"] == {"original_name": "settings.env", "mtime": "2023-11-14T22:13:20Z", "system": "Unix",
                                 "has_comment": False, "trailer_size": len(_SECRET), "content_bytes": len(_SECRET)}
    member = members["settings.env"]
    assert (member["size"], member["compressed_size"], member["mtime"]) == (len(_SECRET), path.stat().st_size,
                                                                          "2023-11-14T22:13:20Z")
    assert summary["content_coverage_pct"] == 100.0
    assert findings[0].title == f"GZIP compressed file inventory: {path.name}"
    assert any(item.title == f"Provider Credential Token inside archive member: {path.name}" for item in findings)


def test_a_gzip_name_that_escapes_is_reported(tmp_path: Path):
    _, _, members, findings = _stream(tmp_path, "x.gz", _gzip(b"data", b"../../etc/cron.d/evil"), "archive/gzip")
    assert members["../../etc/cron.d/evil"]["flags"] == ["unsafe-path"]
    assert "Archive path traversal indicators" in _titles(findings)


def test_a_compressed_file_holding_tar_is_inspected_as_tar(tmp_path: Path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("app/run.sh")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"run"))
    path, summary, members, findings = _stream(tmp_path, "backup.gz", gzip.compress(buffer.getvalue()), "archive/gzip")
    assert summary["format"] == "tar+gzip" and list(members) == ["app/run.sh"]
    assert "TAR archive inventory" in _titles(findings)
    path, summary, members, _ = _stream(tmp_path, "backup.lzma", lzma.compress(buffer.getvalue(),
                                                                            format=lzma.FORMAT_ALONE), "archive/lzma")
    assert summary["format"] == "tar+lzma" and list(members) == ["app/run.sh"]


def test_xz_sizes_come_from_the_stream_indexes(tmp_path: Path):
    data = lzma.compress(b"a" * 5000) + b"\0" * 8 + lzma.compress(b"b" * 3000)
    _, summary, members, _ = _stream(tmp_path, "parts.xz", data, "archive/xz")
    assert summary["stream"] == {"streams": 2, "blocks": 2, "content_bytes": 8000, "complete": True}
    assert members["parts"]["size"] == 8000


def test_bzip2_and_lzma_files_are_sampled(tmp_path: Path):
    _, summary, members, _ = _stream(tmp_path, "notes.txt.bz2", bz2.compress(b"plain notes\n"), "archive/bzip2")
    assert summary["stream"] == {"block_size_kb": 900, "content_bytes": None}
    assert members["notes.txt"]["size"] == 12 and summary["members_fully_sampled"] == 1
    _, summary, members, _ = _stream(tmp_path, "notes.lzma", lzma.compress(b"x" * 10, format=lzma.FORMAT_ALONE),
                                     "archive/lzma")
    assert members["notes"]["size"] == 10


def test_a_member_of_unknown_size_has_no_coverage_figure(tmp_path: Path):
    # bzip2 declares no size, and the content is longer than the sample.
    _, summary, members, _ = _stream(tmp_path, "big.txt.bz2", bz2.compress(b"line of text\n" * 100_000),
                                     "archive/bzip2")
    assert members["big.txt"]["size"] is None
    assert summary["members_unsized"] == 1 and summary["content_coverage_pct"] is None
    assert summary["limits"] == [{"limit": "member_sample_bytes", "value": archives._MAX_MEMBER_SCAN_BYTES,
                                  "members": 1}]


def test_scan_metrics_leave_members_of_unknown_size_out_of_the_coverage(tmp_path: Path):
    from project_discovery.cli import run_scan

    project = tmp_path / "project"
    project.mkdir()
    (project / "big.txt.bz2").write_bytes(bz2.compress(b"line of text\n" * 100_000))
    with zipfile.ZipFile(project / "small.zip", "w") as archive:
        archive.writestr("a.txt", "hello")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, quiet=True, executor="thread") == 0
    import json

    metrics = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["archives"]
    assert metrics["by_format"] == {"bzip2": 1, "zip": 1}
    assert metrics["members_unsized"] == 1 and metrics["content_coverage_pct"] == 100.0


def test_a_zstandard_file_reports_its_frames_and_reads_with_a_decompressor(tmp_path: Path):
    data = _zstd_frame(b"zstd content\n")
    _, summary, members, findings = _stream(tmp_path, "log.zst", data, "archive/zstandard")
    assert summary["stream"]["frames"] == 1 and summary["stream"]["content_bytes"] == 13
    assert members["log"]["size"] == 13
    if archive_formats.zstd_decompressor() is None:
        assert summary["state"] == "unsupported" and summary["unsupported_reason"] == archive_formats.ZSTD_UNAVAILABLE
    else:
        assert summary["state"] == "metadata-complete" and summary["members_fully_sampled"] == 1


def test_zstandard_rle_blocks_that_expand_past_the_budget_are_a_bomb(tmp_path: Path):
    blocks = 132_000  # 128 KiB each: just over 16 GiB from about 528 KB
    rle = (((128 * 1024) << 3) | (1 << 1)).to_bytes(3, "little") + b"\0"
    last = (((128 * 1024) << 3) | (1 << 1) | 1).to_bytes(3, "little") + b"\0"
    data = b"\x28\xb5\x2f\xfd" + bytes([0x00, 7 << 3]) + rle * (blocks - 1) + last
    _, summary, members, findings = _stream(tmp_path, "bomb.zst", data, "archive/zstandard")
    assert summary["stream"]["content_bytes"] == blocks * 128 * 1024 and summary["stream"]["window_bytes"] == 128 * 1024
    assert members["bomb"]["flags"] == ["high-ratio"]
    titles = _titles(findings)
    assert "High compression-ratio archive entries" in titles
    assert "Archive declares more uncompressed data than its budget" in titles


def test_zstandard_frames_a_decompressor_cannot_read_are_named(tmp_path: Path):
    # Single segment, dictionary 7, a one-byte content size of 0 and one empty raw block.
    with_dictionary = b"\x28\xb5\x2f\xfd" + bytes([0x21, 7, 0]) + (1).to_bytes(3, "little")
    _, summary, _, findings = _stream(tmp_path, "dict.zst", with_dictionary, "archive/zstandard")
    assert summary["stream"]["dictionaries"] == [7] and summary["stream"]["unreadable"].startswith("its Zstandard")
    assert summary["state"] == "metadata-complete" and "sample-truncated" in summary["states"]
    huge_window = b"\x28\xb5\x2f\xfd" + bytes([0x00, 20 << 3]) + (1).to_bytes(3, "little")
    _, summary, _, _ = _stream(tmp_path, "window.zst", huge_window, "archive/zstandard")
    assert "window" in summary["stream"]["unreadable"]


def test_an_archive_inside_a_compressed_file_is_inspected(tmp_path: Path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("../escape.txt", "x")
    path, _, members, findings = _stream(tmp_path, "bundle.zip.gz", gzip.compress(inner.getvalue()), "archive/gzip")
    assert members["bundle.zip"]["flags"] == ["nested-archive"]
    assert any(item.title == f"Archive path traversal indicators: {path.name}::bundle.zip" for item in findings)


@pytest.mark.parametrize(("name", "data", "file_type", "error"), [
    ("bad.gz", b"\x1f\x8b\x09" + b"\0" * 20, "archive/gzip", "gzip compression method 9"),
    ("cut.gz", _gzip(random.Random(1).randbytes(100_000))[:200], "archive/gzip", "EOFError"),
    ("bad.xz", b"\xfd7zXZ\0" + b"\1" * 30, "archive/xz", "no xz stream footer"),
    ("pad.xz", b"\xfd7zXZ\0" + b"\1" * 30 + b"\0" * 6, "archive/xz", "padding that is not a multiple of four"),
    ("bad.zst", b"\x28\xb5\x2f\xfd\x00\x38" + b"\x07\0\0", "archive/zstandard", "reserved Zstandard block type"),
    ("cut.zst", b"\x28\xb5\x2f\xfd\x00\x38" + b"\x07\0", "archive/zstandard", "truncated Zstandard block header"),
    ("bad.bz2", b"BZx", "archive/bzip2", "not a bzip2 stream"),
])
def test_malformed_compressed_files_are_recorded_malformed(tmp_path: Path, name, data, file_type, error):
    _, summary, _, _ = _stream(tmp_path, name, data, file_type)
    assert summary["state"] == "malformed" and error in summary["error"]


def test_an_xz_index_over_the_budget_is_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_INDEX_BYTES", 4)
    _, summary, _, findings = _stream(tmp_path, "data.xz", lzma.compress(b"x"), "archive/xz")
    assert summary["state"] == "budget-stopped" and summary["limits"][0]["limit"] == "index_bytes"
    assert findings[0].title.startswith("XZ index budget exceeded")
