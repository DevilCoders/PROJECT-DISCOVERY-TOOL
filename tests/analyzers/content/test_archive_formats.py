"""ar (DEB packages, static libraries), Cabinet, RPM and Zstandard-compressed TAR inspection.

Every fixture is built byte by byte, so the readers are checked against the formats' own
layouts rather than against another library's writer.
"""
from __future__ import annotations

import gzip
import io
import json
import lzma
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.content import archive_formats, archives
from project_discovery.analyzers.content.archives import ArchiveIntelligenceAnalyzer, _reader
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord

_MEMBER_FIELDS = ("archive", "ordinal", "path", "type", "size", "compressed_size", "mode", "mtime", "flags", "link_target",
                  "uid", "gid", "owner", "group")
_MTIME = 1_700_000_000
_MTIME_TEXT = "2023-11-14T22:13:20Z"


def _analyze(path: Path, file_type: str):
    """({archive: summary}, {archive: {member path: record}}, findings) for one archive."""
    record = FileRecord(path.name, path.stat().st_size, "".join(path.suffixes).lower(), "Archive", file_type=file_type)
    with collecting_facts() as facts:
        findings = ArchiveIntelligenceAnalyzer().analyze(path, record)
    summaries = {archive: {"format": archive_format, "state": state, "states": states.split(","), **json.loads(detail)}
                 for archive, archive_format, state, states, detail in facts.archives}
    members: dict = {}
    for row in facts.archive_members:
        item = dict(zip(_MEMBER_FIELDS, row, strict=True))
        item["flags"] = item["flags"].split(",") if item["flags"] else []
        members.setdefault(item["archive"], {})[item["path"]] = item
    return summaries, members, findings


def _titles(findings) -> list[str]:
    return [finding.title.split(":", 1)[0] for finding in findings]


def _tar(members, compress=None) -> bytes:
    """A TAR stream of (name, payload, mode, kind, link target) members."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload, mode, kind, target in members:
            info = tarfile.TarInfo(name)
            info.mode, info.mtime, info.type = mode, _MTIME, kind
            info.linkname = target or ""
            info.size = len(payload) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(payload) if kind == tarfile.REGTYPE else None)
    data = buffer.getvalue()
    if compress == "gz":
        return gzip.compress(data, mtime=0)
    if compress == "xz":
        return lzma.compress(data)
    if compress == "zst":
        return _zstd_frame(data)
    return data


def _zstd_frame(data: bytes) -> bytes:
    """A Zstandard frame of raw (stored) blocks: single segment, 8-byte content size."""
    frame = b"\x28\xb5\x2f\xfd" + bytes([0xE0]) + struct.pack("<Q", len(data))
    blocks = [data[start:start + 128 * 1024] for start in range(0, len(data), 128 * 1024)] or [b""]
    for index, block in enumerate(blocks):
        frame += ((len(block) << 3) | int(index == len(blocks) - 1)).to_bytes(3, "little") + block
    return frame


def _ar_header(name: bytes, size: int, mode: int = 0o100644) -> bytes:
    header = (name.ljust(16) + str(_MTIME).encode().ljust(12) + b"1000".ljust(6) + b"1000".ljust(6)
              + format(mode, "o").encode().ljust(8) + str(size).encode().ljust(10) + b"`\n")
    assert len(header) == 60
    return header


def _ar(members, magic: bytes = b"!<arch>\n") -> bytes:
    """An ar archive of (raw header name, data, mode) members; data None stores nothing (thin)."""
    out = bytearray(magic)
    for name, data, mode, *declared in members:
        size = declared[0] if declared else len(data or b"")
        out += _ar_header(name, size, mode)
        if data is not None:
            out += data + (b"\n" if len(data) & 1 else b"")
    return bytes(out)


_CONTROL = (b"Package: tool\nVersion: 1.2-3\nArchitecture: amd64\nMaintainer: Example <pkg@example.invalid>\n"
            b"Depends: libc6 (>= 2.34)\nDescription: a tool\n long description line\n")


def _deb(data_compress="xz", control_compress="gz", data_members=None) -> bytes:
    data_members = data_members or [
        ("./usr/", b"", 0o755, tarfile.DIRTYPE, None),
        ("./usr/bin/tool", b"#!/bin/sh\necho tool\n", 0o4755, tarfile.REGTYPE, None),
        ("./usr/bin/tool-alt", b"", 0o777, tarfile.SYMTYPE, "/etc/alternatives/tool"),
        ("./usr/share/doc/tool/copyright", b"MIT\n", 0o644, tarfile.REGTYPE, None),
    ]
    control = _tar([("./control", _CONTROL, 0o644, tarfile.REGTYPE, None),
                    ("./postinst", b"#!/bin/sh\nexit 0\n", 0o755, tarfile.REGTYPE, None)], control_compress)
    return _ar([
        (b"debian-binary", b"2.0\n", 0o100644),
        (b"control.tar." + control_compress.encode(), control, 0o100644),
        (b"data.tar." + data_compress.encode(), _tar(data_members, data_compress), 0o100644),
    ])


# ---------------------------------------------------------------------------------------
# Dispatch


@pytest.mark.parametrize(("name", "file_type", "reader"), [
    ("pkg.deb", "archive/deb", "ar"), ("libz.a", "library/static", "ar"), ("x.ar", "archive/ar", "ar"),
    ("setup.cab", "archive/cab", "cab"), ("tool.rpm", "archive/rpm", "rpm"),
    ("disk.iso", "disk-image/iso9660", "iso"), ("disk.img", "disk-image/iso9660", "iso"), ("dvd.iso", "disk-image/udf", "iso"),
    ("app.tar.zst", "archive/zstandard", "tar"), ("app.tgz", "archive/gzip", "tar"), ("pkg.ipk", "archive/gzip", "tar"),
    ("app.tlz", "archive/lzma", "tar"),
    # Compressed content under any other name is a single compressed file (which may hold TAR).
    ("data.zst", "archive/zstandard", "stream"), ("app.log.gz", "archive/gzip", "stream"),
    ("pkg.deb", "archive/gzip", "stream"), ("blob", "archive/xz", "stream"), ("notes.lzma", "archive/lzma", "stream"),
    # A name decides when the content is no archive: a launcher script before a JAR, a corrupt .deb.
    ("app.jar", "text", "zip"), ("broken.deb", "binary/unknown", "ar"), ("broken.cab", "unknown", "cab"),
    ("broken.gz", "binary/unknown", "stream"), ("broken.iso", "unknown", "iso"),
    # ... but not when the content is another archive format.
    ("misnamed.zip", "archive/rar", None), ("setup.cab", "archive/installshield-cab", None),
    ("backup.gz", "archive/7z", None),
])
def test_archives_are_dispatched_by_content_family_then_by_name(name, file_type, reader):
    assert _reader(FileRecord(name, 10, Path(name).suffix, "Archive", file_type=file_type)) == reader


# ---------------------------------------------------------------------------------------
# Debian packages


def test_a_deb_records_its_package_fields_and_inspects_its_tarballs_in_place(tmp_path: Path):
    path = tmp_path / "tool_1.2-3_amd64.deb"
    path.write_bytes(_deb())
    summaries, members, findings = _analyze(path, "archive/deb")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("deb", "metadata-complete")
    assert summary["deb"] == {
        "format_version": "2.0", "package": "tool", "version": "1.2-3", "architecture": "amd64",
        "maintainer": "Example <pkg@example.invalid>", "depends": "libc6 (>= 2.34)", "description": "a tool",
    }
    assert (summary["members_declared"], summary["members_indexed"], summary["member_coverage_pct"]) == (3, 3, 100.0)
    outer = members[path.name]
    assert list(outer) == ["debian-binary", "control.tar.gz", "data.tar.xz"]
    assert outer["debian-binary"] == {**outer["debian-binary"], "type": "file", "size": 4, "mode": 0o644,
                                      "mtime": _MTIME_TEXT, "uid": 1000, "gid": 1000, "flags": []}
    assert outer["data.tar.xz"]["flags"] == ["nested-archive"]
    # The data tarball is read in place from the package (no nested-byte budget is spent).
    data = summaries[f"{path.name}::data.tar.xz"]
    assert (data["format"], data["state"]) == ("tar+xz", "metadata-complete")
    files = members[f"{path.name}::data.tar.xz"]
    assert files["./usr/bin/tool"]["flags"] == ["setuid"]
    # A package's links are installed as links: an absolute target is not a traversal.
    assert files["./usr/bin/tool-alt"] == {**files["./usr/bin/tool-alt"], "type": "symlink", "flags": [],
                                           "link_target": "/etc/alternatives/tool"}
    assert set(members[f"{path.name}::control.tar.gz"]) == {"./control", "./postinst"}
    inventory = next(item for item in findings if item.title.startswith("DEB archive inventory"))
    assert inventory.evidence[0] == "package: tool 1.2-3 (amd64)"
    assert "Archive path traversal indicators" not in _titles(findings)
    assert "Risky archive permissions" in _titles(findings)


def test_a_deb_data_tarball_that_escapes_its_root_is_reported(tmp_path: Path):
    path = tmp_path / "evil.deb"
    path.write_bytes(_deb(data_compress="gz", data_members=[
        ("./../../etc/cron.d/evil", b"* * * * * root id\n", 0o644, tarfile.REGTYPE, None),
    ]))
    summaries, members, findings = _analyze(path, "archive/deb")
    assert members[f"{path.name}::data.tar.gz"]["./../../etc/cron.d/evil"]["flags"] == ["unsafe-path"]
    assert "Archive path traversal indicators" in _titles(findings)


def test_deb_tarballs_beyond_the_nested_depth_are_listed_but_not_opened(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_NESTED_DEPTH", 0)
    path = tmp_path / "tool.deb"
    path.write_bytes(_deb())
    summaries, members, _ = _analyze(path, "archive/deb")
    assert list(summaries) == [path.name]
    assert summaries[path.name]["limits"] == [{"limit": "nested_depth", "value": 0, "members": 2}]
    assert summaries[path.name]["deb"]["package"] == "tool"  # the control fields are read regardless


def test_zstandard_deb_tarballs_are_read_with_a_decompressor_or_reported_unsupported(tmp_path: Path):
    path = tmp_path / "tool.deb"
    path.write_bytes(_deb(data_compress="zst", control_compress="zst"))
    summaries, members, findings = _analyze(path, "archive/deb")
    data = summaries[f"{path.name}::data.tar.zst"]
    if archive_formats.zstd_decompressor() is None:
        assert data["state"] == "unsupported" and "zstandard" in data["unsupported_reason"]
        assert summaries[path.name]["deb"]["control_error"].startswith("control.tar.zst: Zstandard decompression")
    else:
        assert (data["format"], data["state"]) == ("tar+zstd", "metadata-complete")
        assert members[f"{path.name}::data.tar.zst"]["./usr/bin/tool"]["flags"] == ["setuid"]
        assert summaries[path.name]["deb"]["package"] == "tool"


def test_a_deb_control_tarball_that_expands_past_its_cap_is_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archive_formats, "_DEB_CONTROL_EXPANDED", 4096)
    path = tmp_path / "bomb.deb"
    control = _tar([("./padding", b"\0" * 64 * 1024, 0o644, tarfile.REGTYPE, None),
                    ("./control", _CONTROL, 0o644, tarfile.REGTYPE, None)], "gz")
    path.write_bytes(_ar([(b"debian-binary", b"2.0\n", 0o100644), (b"control.tar.gz", control, 0o100644)]))
    summaries, _, _ = _analyze(path, "archive/deb")
    deb = summaries[path.name]["deb"]
    assert "package" not in deb and "past its cap" in deb["control_error"]


# ---------------------------------------------------------------------------------------
# Static libraries and other ar archives


def test_gnu_long_names_and_the_symbol_table_and_member_sampling(tmp_path: Path):
    long_name = b"a_rather_long_object_file_name.o"
    table = long_name + b"/\n"
    secret = ("aws_access_key_id = " + "AKIA" + "ABCDEFGHIJKLMNOP\n").encode()
    path = tmp_path / "libtool.a"
    path.write_bytes(_ar([
        (b"/", b"\0\0\0\0", 0o100644),
        (b"//", table, 0o100644),
        (b"/0", b"\x7fELF object", 0o100644),
        (b"short.o/", secret, 0o100666),
    ]))
    summaries, members, findings = _analyze(path, "library/static")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("ar", "metadata-complete")
    assert summary["ar"] == {"variant": "gnu", "thin": False, "symbol_table": True}
    assert list(members[path.name]) == [long_name.decode(), "short.o"]
    assert members[path.name]["short.o"]["flags"] == ["world-writable"]
    assert summary["members_fully_sampled"] == 2 and summary["content_coverage_pct"] == 100.0
    assert any(item.title == f"Provider Credential Token inside archive member: {path.name}" for item in findings)


def test_bsd_names_and_symbol_tables(tmp_path: Path):
    name = b"a_long_bsd_member_name.o"
    path = tmp_path / "libbsd.a"
    path.write_bytes(_ar([
        (b"#1/20", b"__.SYMDEF SORTED\0\0\0\0" + b"syms", 0o100644),
        (b"#1/" + str(len(name)).encode(), name + b"data", 0o100644),
    ]))
    summaries, members, _ = _analyze(path, "library/static")
    assert summaries[path.name]["ar"] == {"variant": "bsd", "thin": False, "symbol_table": True}
    assert members[path.name][name.decode()]["size"] == 4


def test_a_thin_archive_lists_members_it_does_not_store(tmp_path: Path):
    path = tmp_path / "libthin.a"
    table = b"obj/one.o/\nobj/two.o/\n"
    path.write_bytes(_ar([(b"//", table, 0o100644), (b"/0", None, 0o100644, 1234), (b"/11", None, 0o100644, 99)],
                         magic=b"!<thin>\n"))
    summaries, members, _ = _analyze(path, "library/static")
    summary = summaries[path.name]
    assert summary["ar"]["thin"] is True and summary["state"] == "metadata-complete"
    assert [(item["path"], item["size"]) for item in members[path.name].values()] == [("obj/one.o", 1234),
                                                                                    ("obj/two.o", 99)]
    assert summary["members_sampled"] == 0


def test_an_archive_stored_in_an_ar_archive_is_inspected_in_place(tmp_path: Path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr("../escape.class", "x")
    path = tmp_path / "bundle.ar"
    path.write_bytes(_ar([(b"plugin.jar/", inner.getvalue(), 0o100644)]))
    summaries, members, findings = _analyze(path, "archive/ar")
    assert summaries[f"{path.name}::plugin.jar"]["state"] == "metadata-complete"
    assert members[f"{path.name}::plugin.jar"]["../escape.class"]["flags"] == ["unsafe-path"]
    assert any(item.title == f"Archive path traversal indicators: {path.name}::plugin.jar" for item in findings)


@pytest.mark.parametrize(("data", "error"), [
    (b"!<arch>\n" + b"x" * 30, "truncated ar member header"),
    (_ar([(b"one.o/", b"data", 0o100644)]).replace(b"`\n", b"!!"), "corrupt ar member header"),
    (_ar([(b"one.o/", b"data", 0o100644, 4096)]), "runs past the end of the file"),
    (_ar([(b"/7", b"data", 0o100644)]), "long-name offset 7 is past the name table"),
    (b"!<arch>\n" + b"one.o/".ljust(16) + b"x" * 42 + b"`\n", "non-numeric field"),
])
def test_malformed_ar_archives_are_recorded_malformed(tmp_path: Path, data, error):
    path = tmp_path / "broken.a"
    path.write_bytes(data)
    summaries, _, findings = _analyze(path, "library/static")
    assert summaries[path.name]["state"] == "malformed" and error in summaries[path.name]["error"]
    assert [item.title for item in findings] == [f"AR metadata read error: {path.name}"]


def test_the_ar_entry_limit_stops_the_listing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_ENTRIES", 2)
    path = tmp_path / "many.a"
    path.write_bytes(_ar([(f"m{index}.o/".encode(), b"x", 0o100644) for index in range(5)]))
    summaries, members, findings = _analyze(path, "library/static")
    summary = summaries[path.name]
    assert summary["state"] == "budget-stopped" and summary["members_declared"] is None
    assert summary["limits"] == [{"limit": "entries", "value": 2}]
    assert len(members[path.name]) == 2 and "AR entry limit reached" in _titles(findings)


# ---------------------------------------------------------------------------------------
# Cabinets


def _cab(files, *, data_bytes: bytes = b"CK" + b"\0" * 30, compression: int = 1) -> bytes:
    """A cabinet with one folder and (name, size, attributes) files; DOS time 2024-05-06 07:08:10."""
    date, time_of_day = ((2024 - 1980) << 9) | (5 << 5) | 6, (7 << 11) | (8 << 5) | 5
    table = b"".join(struct.pack("<LLHHHH", size, 0, 0, date, time_of_day, attributes) + name + b"\0"
                     for name, size, attributes in files)
    files_offset = 36 + 8
    data_offset = files_offset + len(table)
    total = data_offset + 8 + len(data_bytes)
    header = struct.pack("<4sLLLLLBBHHHHH", b"MSCF", 0, total, 0, files_offset, 0, 3, 1, 1, len(files), 0, 77, 0)
    folder = struct.pack("<LHH", data_offset, 1, compression)
    block = struct.pack("<LHH", 0, len(data_bytes), 100)
    return header + folder + table + block + data_bytes


def test_a_cabinet_lists_its_files_from_the_file_table(tmp_path: Path):
    path = tmp_path / "setup.cab"
    path.write_bytes(_cab([(b"app\\main.exe", 4096, 0x20), ("naïve.txt".encode(), 12, 0xA0),
                           (b"..\\..\\Windows\\evil.dll", 10, 0x20)]))
    summaries, members, findings = _analyze(path, "archive/cab")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("cab", "metadata-complete")
    assert summary["cab"] == {"version": "1.3", "folders": 1, "compression": ["mszip"], "set_id": 77,
                              "cabinet_index": 0, "cabinet_bytes": path.stat().st_size, "spans_cabinets": False}
    assert (summary["members_declared"], summary["members_indexed"]) == (3, 3)
    assert summary["compressed_bytes"] == path.stat().st_size and summary["members_sampled"] == 0
    listed = members[path.name]
    assert listed["app/main.exe"] == {**listed["app/main.exe"], "type": "file", "size": 4096,
                                      "mtime": "2024-05-06T07:08:10", "mode": None, "flags": []}
    assert "naïve.txt" in listed  # the UTF-8 attribute names the encoding
    assert listed["../../Windows/evil.dll"]["flags"] == ["unsafe-path"]
    assert "Archive path traversal indicators" in _titles(findings)


def test_a_cabinet_declaring_far_more_than_it_holds_is_a_bomb(tmp_path: Path):
    path = tmp_path / "bomb.cab"
    path.write_bytes(_cab([(f"zero{index}.bin".encode(), 0xFFFFFFFF, 0x20) for index in range(5)]))
    summaries, _, findings = _analyze(path, "archive/cab")
    summary = summaries[path.name]
    assert summary["compression_ratio"] > 1000
    assert summary["limits"] == [{"limit": "uncompressed_bytes", "value": archives._MAX_DECLARED_UNCOMPRESSED_BYTES,
                                  "used": 5 * 0xFFFFFFFF}]
    titles = _titles(findings)
    assert "High compression-ratio archive" in titles
    assert "Archive declares more uncompressed data than its budget" in titles


@pytest.mark.parametrize(("data", "error"), [
    (b"MSCF" + b"\0" * 20, "not a cabinet"),
    (_cab([(b"a.txt", 1, 0)])[:60], "the cabinet header declares"),
    (_cab([(b"a.txt", 1, 0)]).replace(b"a.txt\0", b"a.txtx"), "unterminated name in the cabinet file table"),
    (_cab([(b"a.txt", 1, 0)])[:28] + struct.pack("<H", 2) + _cab([(b"a.txt", 1, 0)])[30:],
     "truncated cabinet file table"),
])
def test_malformed_cabinets_are_recorded_malformed(tmp_path: Path, data, error):
    path = tmp_path / "broken.cab"
    path.write_bytes(data)
    summaries, _, _ = _analyze(path, "archive/cab")
    assert summaries[path.name]["state"] == "malformed" and error in summaries[path.name]["error"]


# ---------------------------------------------------------------------------------------
# RPM packages


def _rpm_structure(tags) -> bytes:
    """An RPM header structure of (tag, type, data, count) entries, data aligned for its type."""
    index, data = b"", b""
    for tag, kind, payload, count in tags:
        data += b"\0" * (-len(data) % {3: 2, 4: 4, 5: 8}.get(kind, 1))
        index += struct.pack(">4L", tag, kind, len(data), count)
        data += payload
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">LL", len(tags), len(data)) + index + data


def _strings(*values: str) -> bytes:
    return b"".join(value.encode() + b"\0" for value in values)


def _ints(code: str, *values: int) -> bytes:
    return struct.pack(f">{len(values)}{code}", *values)


_RPM_DIRS = ("/usr/", "/usr/bin/", "/usr/lib/", "/usr/../etc/", "/dev/")
_RPM_FILES = (  # base name, directory index, mode, size, inode, link target, group
    ("bin", 0, 0o40755, 4096, 1, "", "root"),
    ("tool", 1, 0o104755, 1000, 2, "", "root"),
    ("tool-link", 1, 0o120777, 4, 3, "tool", "root"),
    ("a.so", 2, 0o100644, 5000, 7, "", "root"),
    ("b.so", 2, 0o100644, 5000, 7, "", "root"),
    ("evil", 3, 0o100644, 10, 8, "", "root"),
    ("console", 4, 0o20620, 0, 9, "", "tty"),
)


def _rpm(files=_RPM_FILES, payload: bytes = b"\x28\xb5\x2f\xfd" + bytes(96), source: bool = False) -> bytes:
    lead = (b"\xed\xab\xee\xdb\x03\x00" + struct.pack(">HH", int(source), 1) + b"tool-1.2-3".ljust(66, b"\0")
            + struct.pack(">HH", 1, 5) + bytes(16))
    assert len(lead) == 96
    signature = _rpm_structure([])
    count = len(files)
    header = _rpm_structure([
        (1000, 6, _strings("tool"), 1), (1001, 6, _strings("1.2"), 1), (1002, 6, _strings("3.el9"), 1),
        (1004, 9, _strings("A tool"), 1), (1014, 6, _strings("MIT"), 1), (1022, 6, _strings("x86_64"), 1),
        (1028, 4, _ints("L", *(item[3] for item in files)), count),
        (1030, 3, _ints("H", *(item[2] for item in files)), count),
        (1034, 4, _ints("L", *(_MTIME for _ in files)), count),
        (1036, 8, _strings(*(item[5] for item in files)), count),
        (1039, 8, _strings(*("root" for _ in files)), count),
        (1040, 8, _strings(*(item[6] for item in files)), count),
        (1095, 4, _ints("L", *(1 for _ in files)), count),
        (1096, 4, _ints("L", *(item[4] for item in files)), count),
        (1116, 4, _ints("L", *(item[1] for item in files)), count),
        (1117, 8, _strings(*(item[0] for item in files)), count),
        (1118, 8, _strings(*_RPM_DIRS), len(_RPM_DIRS)),
        (1124, 6, _strings("cpio"), 1), (1125, 6, _strings("zstd"), 1),
    ])
    return lead + signature + header + payload


def test_an_rpm_lists_its_files_and_package_fields_from_its_header(tmp_path: Path):
    path = tmp_path / "tool-1.2-3.el9.x86_64.rpm"
    path.write_bytes(_rpm())
    summaries, members, findings = _analyze(path, "archive/rpm")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("rpm", "metadata-complete")
    assert summary["rpm"] == {
        "name": "tool", "version": "1.2", "release": "3.el9", "epoch": None, "summary": "A tool", "license": "MIT",
        "url": None, "arch": "x86_64", "source_rpm": None, "payload_format": "cpio", "payload_compressor": "zstd",
        "source_package": False, "payload_bytes": 100,
    }
    assert (summary["members_declared"], summary["members_indexed"], summary["compressed_bytes"]) == (7, 7, 100)
    listed = members[path.name]
    assert listed["/usr/bin"]["type"] == "directory"
    assert listed["/usr/bin/tool"] == {**listed["/usr/bin/tool"], "type": "file", "size": 1000, "mode": 0o4755,
                                       "mtime": _MTIME_TEXT, "owner": "root", "group": "root", "flags": ["setuid"]}
    # A symlink's own mode bits are unused: 0777 is not "world-writable".
    assert listed["/usr/bin/tool-link"] == {**listed["/usr/bin/tool-link"], "type": "symlink", "link_target": "tool",
                                            "flags": []}
    assert listed["/usr/lib/b.so"] == {**listed["/usr/lib/b.so"], "type": "hardlink", "link_target": "/usr/lib/a.so"}
    assert listed["/dev/console"] == {**listed["/dev/console"], "type": "special", "group": "tty"}
    # Absolute paths are where a package installs; only the parent traversal is unsafe.
    assert [item["path"] for item in listed.values() if "unsafe-path" in item["flags"]] == ["/usr/../etc/evil"]
    inventory = next(item for item in findings if item.title.startswith("RPM archive inventory"))
    assert inventory.evidence[0] == "package: tool 1.2-3.el9 (x86_64)"
    assert "the zstd payload was not decompressed" in inventory.detail
    titles = _titles(findings)
    for title in ("Archive path traversal indicators", "Risky archive permissions", "Archive hardlink entries",
                  "Special filesystem entries inside archive", "Archive symlink entries"):
        assert title in titles


def test_an_rpm_header_over_the_index_budget_is_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_INDEX_BYTES", 256)
    path = tmp_path / "tool.rpm"
    path.write_bytes(_rpm())
    summaries, members, findings = _analyze(path, "archive/rpm")
    summary = summaries[path.name]
    assert summary["state"] == "budget-stopped" and summary["limits"][0]["limit"] == "index_bytes"
    assert summary["limits"][0]["used"] > 256 and path.name not in members
    assert [item.title for item in findings] == [f"RPM index budget exceeded: {path.name}"]


def test_the_rpm_entry_limit_keeps_the_declared_count(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_ENTRIES", 3)
    path = tmp_path / "tool.rpm"
    path.write_bytes(_rpm())
    summaries, members, findings = _analyze(path, "archive/rpm")
    summary = summaries[path.name]
    assert (summary["state"], summary["members_declared"], summary["members_indexed"]) == ("budget-stopped", 7, 3)
    assert summary["member_coverage_pct"] == pytest.approx(42.9)
    assert summary["limits"] == [{"limit": "entries", "value": 3, "used": 7}]
    assert "RPM entry limit reached" in _titles(findings)


@pytest.mark.parametrize(("mutate", "error"), [
    (lambda data: b"\0" + data[1:], "not an RPM package"),
    (lambda data: data[:200], "runs past the end of the file"),
    (lambda data: data[:112] + b"XXXX" + data[116:], "no RPM header structure at offset 112"),
])
def test_malformed_rpms_are_recorded_malformed(tmp_path: Path, mutate, error):
    path = tmp_path / "broken.rpm"
    path.write_bytes(mutate(_rpm()))
    summaries, _, _ = _analyze(path, "archive/rpm")
    assert summaries[path.name]["state"] == "malformed" and error in summaries[path.name]["error"]


# ---------------------------------------------------------------------------------------
# Zstandard-compressed TAR and symlink modes


def test_a_tar_zst_is_read_with_a_decompressor_or_reported_unsupported(tmp_path: Path, monkeypatch):
    path = tmp_path / "app.tar.zst"
    path.write_bytes(_tar([("app/run.sh", b"#!/bin/sh\n", 0o755, tarfile.REGTYPE, None)], "zst"))
    if archive_formats.zstd_decompressor() is not None:
        summaries, members, findings = _analyze(path, "archive/zstandard")
        assert (summaries[path.name]["format"], summaries[path.name]["state"]) == ("tar+zstd", "metadata-complete")
        assert members[path.name]["app/run.sh"]["size"] == 10
        assert "TAR archive inventory" in _titles(findings)
    monkeypatch.setattr(archives, "zstd_reader", lambda stream: None)
    summaries, members, findings = _analyze(path, "archive/zstandard")
    summary = summaries[path.name]
    assert (summary["format"], summary["state"]) == ("tar+zstd", "unsupported")
    assert summary["unsupported_reason"] == archive_formats.ZSTD_UNAVAILABLE and path.name not in members
    assert archive_formats.ZSTD_UNAVAILABLE in findings[0].detail


def test_symlink_mode_bits_are_not_reported_as_world_writable(tmp_path: Path):
    path = tmp_path / "links.tar"
    path.write_bytes(_tar([("current", b"", 0o777, tarfile.SYMTYPE, "releases/1"),
                           ("shared.txt", b"x", 0o666, tarfile.REGTYPE, None)]))
    _, members, findings = _analyze(path, "archive/tar")
    assert members[path.name]["current"]["flags"] == []
    assert members[path.name]["shared.txt"]["flags"] == ["world-writable"]
    risky = next(item for item in findings if item.title.startswith("Risky archive permissions"))
    assert risky.evidence == [f"{path.name}::shared.txt (world-writable)"]
    zipped = tmp_path / "links.zip"
    with zipfile.ZipFile(zipped, "w") as archive:
        link = zipfile.ZipInfo("current")
        link.create_system, link.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "releases/1")
    _, members, findings = _analyze(zipped, "archive/zip")
    assert members[zipped.name]["current"]["flags"] == []
    assert "Risky archive permissions" not in _titles(findings)
