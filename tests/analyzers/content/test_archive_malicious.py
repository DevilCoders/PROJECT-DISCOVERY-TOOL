"""The malicious archive fixture set: each construction used against extractors and scanners,
and what PDT reports for it (the archive's state, its members' flags and the findings).

Every fixture is built here, byte by byte where the standard library cannot write it, so the
set needs no binary files: archive bombs (deflate, overlapping members, declared sizes, sparse
members, Zstandard RLE), nested bombs (deep and wide), malformed headers in every format,
encrypted members and indexes, path traversal, absolute paths, hard links, symlink loops and
writes through symlinks, huge entry counts and corrupt checksums.
"""
from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.content import archives
from test_archive_7z_rar import _rar4, _rar4_file, _rar5_block, _seven, _stored_seven, _vint
from test_archive_formats import _analyze, _ar, _cab, _rpm, _titles


def _inspect(tmp_path: Path, name: str, data: bytes, file_type: str):
    path = tmp_path / name
    path.write_bytes(data)
    summaries, members, findings = _analyze(path, file_type)
    return summaries, members, findings


def _zip(members, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _zip_link(name: str, target: str) -> tuple[zipfile.ZipInfo, str]:
    info = zipfile.ZipInfo(name)
    info.create_system, info.external_attr = 3, (0o120777 << 16)
    return info, target


def _tar(members) -> bytes:
    """A TAR of (name, data or None, type, link target)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data, kind, target in members:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, target or ""
            info.size = len(data or b"")
            archive.addfile(info, io.BytesIO(data) if data else None)
    return buffer.getvalue()


def _number(value: int, width: int = 12) -> bytes:
    """A TAR number field: octal, or GNU base-256 when octal does not fit."""
    if value < 8 ** (width - 1):
        return b"%0*o\0" % (width - 1, value)
    return b"\x80" + value.to_bytes(width - 1, "big")


def _sparse_member(name: str, data: bytes, real_size: int) -> bytes:
    """An old-GNU sparse member: ``data`` at offset 0, holes up to ``real_size``."""
    info = tarfile.TarInfo(name)
    info.size, info.type = len(data), tarfile.GNUTYPE_SPARSE
    header = bytearray(info.tobuf(tarfile.GNU_FORMAT))
    header[386:410] = _number(0) + _number(len(data))
    header[482] = 0
    header[483:495] = _number(real_size)
    header[148:156] = b" " * 8
    header[148:156] = b"%06o\0 " % sum(header)
    return bytes(header) + data + bytes(-len(data) % 512)


# ---------------------------------------------------------------------------------------
# Archive bombs and high-ratio entries


def test_a_deflate_bomb_member_is_high_ratio(tmp_path: Path):
    summaries, members, findings = _inspect(tmp_path, "bomb.zip", _zip([("zeros.bin", bytes(32 << 20))]), "archive/zip")
    assert members["bomb.zip"]["zeros.bin"]["flags"] == ["high-ratio"]
    assert "High compression-ratio archive entries" in _titles(findings)


def test_overlapping_zip_members_are_a_non_recursive_bomb_and_are_not_opened(tmp_path: Path):
    data = _zip([("kernel.bin", bytes(1 << 20))])
    eocd = data.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<L", data, eocd + 16)[0]
    entry = data[directory:eocd]
    copies = [entry.replace(b"kernel.bin", f"c{index:05d}.bin".encode()) for index in range(50)]
    table = b"".join(copies)
    end = b"PK\x05\x06" + struct.pack("<HHHHLLH", 0, 0, len(copies), len(copies), len(table), directory, 0)
    summaries, members, findings = _inspect(tmp_path, "overlap.zip", data[:directory] + table + end, "archive/zip")
    summary = summaries["overlap.zip"]
    assert summary["structure_issues"]["overlapping"] == 50
    assert all("overlapping" in item["flags"] for item in members["overlap.zip"].values())
    assert summary["members_sampled"] == 0  # none is opened: each would re-read the same data
    assert "Overlapping ZIP members" in _titles(findings)


def test_a_sparse_tar_member_that_declares_a_terabyte_is_a_bomb(tmp_path: Path):
    data = _sparse_member("disk.img", b"boot", 1 << 40) + bytes(1024)
    summaries, members, findings = _inspect(tmp_path, "sparse.tar", data, "archive/tar")
    member = members["sparse.tar"]["disk.img"]
    assert (member["size"], member["flags"]) == (1 << 40, ["sparse"])
    assert summaries["sparse.tar"]["structure_issues"]["sparse_members"] == 1
    titles = _titles(findings)
    assert "Sparse TAR members" in titles and "Archive declares more uncompressed data than its budget" in titles
    sparse = next(item for item in findings if item.title.startswith("Sparse TAR members"))
    assert sparse.severity == "HIGH"


def test_a_zstandard_rle_bomb_is_found_without_decompressing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_DECLARED_UNCOMPRESSED_BYTES", 64 << 20)
    rle = (((128 * 1024) << 3) | (1 << 1)).to_bytes(3, "little") + b"\0"
    last = (((128 * 1024) << 3) | (1 << 1) | 1).to_bytes(3, "little") + b"\0"
    data = b"\x28\xb5\x2f\xfd" + bytes([0x00, 7 << 3]) + rle * 999 + last  # 125 MiB from 4 KB
    summaries, members, findings = _inspect(tmp_path, "rle.zst", data, "archive/zstandard")
    assert members["rle.zst"]["rle"]["flags"] == ["high-ratio"]
    assert "Archive declares more uncompressed data than its budget" in _titles(findings)


# ---------------------------------------------------------------------------------------
# Nested bombs


def _nest(levels: int, payload: bytes) -> bytes:
    data = _zip([("payload.bin", payload)])
    for level in range(levels - 1, 0, -1):
        data = _zip([(f"level{level}.zip", data)], zipfile.ZIP_STORED)
    return data


def test_a_deep_nested_bomb_stops_at_the_nesting_depth(tmp_path: Path):
    summaries, _, _ = _inspect(tmp_path, "deep.zip", _nest(4, bytes(1 << 20)), "archive/zip")
    assert set(summaries) == {"deep.zip", "deep.zip::level1.zip"}
    assert summaries["deep.zip::level1.zip"]["limits"] == [{"limit": "nested_depth", "value": 1, "members": 1}]


def test_a_deep_nested_bomb_within_a_raised_depth_is_inspected_to_its_payload(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_NESTED_DEPTH", 3)
    summaries, members, _ = _inspect(tmp_path, "deep.zip", _nest(4, bytes(32 << 20)), "archive/zip")
    innermost = "deep.zip::level1.zip::level2.zip::level3.zip"
    assert innermost in summaries
    assert members[innermost]["payload.bin"]["flags"] == ["high-ratio"]


def test_a_wide_nested_bomb_stops_at_the_nested_byte_budget(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_NESTED_BYTES", 3 << 20)
    inner = _zip([("data.bin", bytes(64 << 10) + bytes(range(256)) * 4096)], zipfile.ZIP_STORED)  # about 1.1 MiB
    data = _zip([(f"copy{index}.zip", inner) for index in range(10)], zipfile.ZIP_STORED)
    summaries, _, _ = _inspect(tmp_path, "wide.zip", data, "archive/zip")
    nested = [name for name in summaries if "::" in name]
    assert len(nested) == 2
    # The eight left uninspected are sampled like any member (and are longer than a sample).
    assert {"limit": "nested_bytes", "members": 8, "value": 3 << 20} in summaries["wide.zip"]["limits"]


# ---------------------------------------------------------------------------------------
# Malformed headers


_TAR_ONE = _tar([("a.txt", b"data", tarfile.REGTYPE, None)])


@pytest.mark.parametrize(("name", "data", "file_type"), [
    ("cut.zip", _zip([("a.txt", b"x" * 100)])[:-30], "archive/zip"),
    ("bad-first.tar", bytes([_TAR_ONE[0] ^ 1]) + _TAR_ONE[1:], "archive/tar"),
    ("bad.7z", _stored_seven()[:8] + b"\0\0\0\0" + _stored_seven()[12:], "archive/7z"),
    ("bad.rar", b"Rar!\x1a\x07\x01\x00" + b"\0\0\0\0\x01", "archive/rar"),
    ("bad.a", _ar([(b"one.o/", b"data", 0o100644)]).replace(b"`\n", b"!!"), "library/static"),
    ("cut.cab", _cab([(b"a.txt", 1, 0)])[:60], "archive/cab"),
    ("bad.rpm", b"\0" + _rpm()[1:], "archive/rpm"),
    ("bad.gz", b"\x1f\x8b\x09" + bytes(20), "archive/gzip"),
    ("bad.iso", bytes(17 * 2048), "disk-image/iso9660"),
])
def test_malformed_headers_leave_the_archive_malformed_with_its_error(tmp_path: Path, name, data, file_type):
    summaries, members, findings = _inspect(tmp_path, name, data, file_type)
    summary = summaries[name]
    assert summary["state"] == "malformed" and summary["error"]
    assert findings and findings[0].confidence == "UNKNOWN"


# ---------------------------------------------------------------------------------------
# Encrypted archives


def test_encrypted_zip_members_are_flagged_and_not_read(tmp_path: Path):
    data = bytearray(_zip([("secret.txt", "classified\n")], zipfile.ZIP_STORED))
    data[6] |= 0x01  # the local header's encryption flag
    directory = data.rfind(b"PK\x01\x02")
    data[directory + 8] |= 0x01  # and the central directory's
    summaries, members, findings = _inspect(tmp_path, "locked.zip", bytes(data), "archive/zip")
    assert members["locked.zip"]["secret.txt"]["flags"] == ["encrypted"]
    assert summaries["locked.zip"]["members_sampled"] == 0 and "encrypted" in summaries["locked.zip"]["states"]
    assert "Encrypted archive entries" in _titles(findings)


def test_archives_with_encrypted_indexes_are_encrypted(tmp_path: Path):
    hidden_7z = _seven(b"", b"\x01\x05\x01\x11\x05\x00a\x00\x00\x00\x00\x00", encode=True, encrypt_header=True)
    hidden_rar = b"Rar!\x1a\x07\x01\x00" + _rar5_block(4, _vint(0) + _vint(0) + bytes([15]) + bytes(16)) + bytes(64)
    for name, data, file_type in (("hidden.7z", hidden_7z, "archive/7z"), ("hidden.rar", hidden_rar, "archive/rar")):
        summaries, members, findings = _inspect(tmp_path, name, data, file_type)
        assert summaries[name]["state"] == "encrypted" and name not in members
        assert "Encrypted archive index" in _titles(findings)


# ---------------------------------------------------------------------------------------
# Path traversal and absolute paths


@pytest.mark.parametrize("member", [
    "../../etc/cron.d/evil", "..\\..\\Windows\\evil.dll", "safe/../../escape.sh", "/etc/passwd",
    "C:\\Windows\\System32\\evil.dll", "C:relative.txt",
])
def test_traversal_and_absolute_member_paths_are_critical(tmp_path: Path, member):
    summaries, members, findings = _inspect(tmp_path, "evil.zip", _zip([(member, "x")]), "archive/zip")
    # zipfile writes os.sep as "/", so on Windows a backslash name is stored with slashes.
    [recorded] = members["evil.zip"].values()
    assert "unsafe-path" in recorded["flags"]
    traversal = next(item for item in findings if item.title.startswith("Archive path traversal indicators"))
    assert traversal.severity == "CRITICAL"


def test_a_traversal_inside_a_nested_archive_is_reported_on_the_nested_archive(tmp_path: Path):
    data = _zip([("lib/inner.zip", _zip([("../../escape.sh", "x")]))], zipfile.ZIP_STORED)
    summaries, members, findings = _inspect(tmp_path, "outer.zip", data, "archive/zip")
    assert members["outer.zip::lib/inner.zip"]["../../escape.sh"]["flags"] == ["unsafe-path"]
    assert any(item.title == "Archive path traversal indicators: outer.zip::lib/inner.zip" for item in findings)


# ---------------------------------------------------------------------------------------
# Hard links, symlink loops and writes through symlinks


def test_hard_links_to_absolute_paths_and_through_symlinks_are_traversal(tmp_path: Path):
    data = _tar([
        ("shadow", None, tarfile.LNKTYPE, "/etc/shadow"),
        ("etc", None, tarfile.SYMTYPE, "/etc"),
        ("sudoers", None, tarfile.LNKTYPE, "etc/sudoers"),
    ])
    summaries, members, findings = _inspect(tmp_path, "links.tar", data, "archive/tar")
    listed = members["links.tar"]
    assert listed["shadow"]["flags"] == ["unsafe-path"]
    assert listed["sudoers"]["flags"] == ["unsafe-path"]  # its target resolves through the "etc" symlink
    traversal = next(item for item in findings if item.title.startswith("Archive path traversal indicators"))
    assert "links.tar::sudoers (through a symlink)" in traversal.evidence
    assert "Archive hardlink entries" in _titles(findings)


def test_a_member_written_through_a_symlinked_directory_is_traversal(tmp_path: Path):
    data = _tar([("root", None, tarfile.SYMTYPE, "/"), ("root/etc/cron.d/evil", b"* * * * * root id\n",
                                                          tarfile.REGTYPE, None)])
    summaries, members, findings = _inspect(tmp_path, "through.tar", data, "archive/tar")
    assert members["through.tar"]["root/etc/cron.d/evil"]["flags"] == ["unsafe-path"]
    traversal = next(item for item in findings if item.title.startswith("Archive path traversal indicators"))
    assert "through.tar::root/etc/cron.d/evil (through a symlink)" in traversal.evidence


def test_symlink_loops_are_reported_in_tar_and_zip(tmp_path: Path):
    data = _tar([("a", None, tarfile.SYMTYPE, "b"), ("b", None, tarfile.SYMTYPE, "a"),
                 ("self", None, tarfile.SYMTYPE, "self"), ("dir/x", None, tarfile.SYMTYPE, "../dir/x/y"),
                 ("fine", None, tarfile.SYMTYPE, "a-file"), ("a-file", b"x", tarfile.REGTYPE, None)])
    summaries, members, findings = _inspect(tmp_path, "loops.tar", data, "archive/tar")
    listed = members["loops.tar"]
    assert [name for name, items in listed.items() if "symlink-loop" in items["flags"]] == ["a", "b", "self", "dir/x"]
    assert summaries["loops.tar"]["structure_issues"]["symlink_loops"] == 4
    assert "Archive symlink loops" in _titles(findings)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, target in (("a", "b"), ("b", "a")):
            archive.writestr(*_zip_link(name, target))
    summaries, members, findings = _inspect(tmp_path, "loops.zip", buffer.getvalue(), "archive/zip")
    assert all("symlink-loop" in items["flags"] for items in members["loops.zip"].values())
    assert "Archive symlink loops" in _titles(findings)


def test_a_package_payloads_links_are_only_checked_for_loops(tmp_path: Path):
    tarball = gzip.compress(_tar([("./etc/alternatives", None, tarfile.SYMTYPE, "/var/lib/alternatives"),
                                  ("./etc/alternatives/java", None, tarfile.SYMTYPE, "/usr/lib/jvm/java"),
                                  ("./loop", None, tarfile.SYMTYPE, "loop")]))
    data = _ar([(b"debian-binary", b"2.0\n", 0o100644), (b"data.tar.gz", tarball, 0o100644)])
    summaries, members, _ = _inspect(tmp_path, "tool.deb", data, "archive/deb")
    payload = members["tool.deb::data.tar.gz"]
    assert payload["./etc/alternatives/java"]["flags"] == []  # dpkg installs links as links
    assert payload["./loop"]["flags"] == ["symlink-loop"]


# ---------------------------------------------------------------------------------------
# Huge entry counts


def test_huge_entry_counts_stop_at_the_entry_limit(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_ENTRIES", 100)
    names = [f"f{index:04d}" for index in range(150)]
    summaries, members, findings = _inspect(tmp_path, "many.zip", _zip([(name, b"") for name in names]), "archive/zip")
    assert summaries["many.zip"]["state"] == "budget-stopped" and "many.zip" not in members
    assert "ZIP central-directory budget exceeded" in _titles(findings)
    data = _tar([(name, b"", tarfile.REGTYPE, None) for name in names])
    summaries, members, findings = _inspect(tmp_path, "many.tar", data, "archive/tar")
    assert summaries["many.tar"]["state"] == "budget-stopped" and len(members["many.tar"]) == 100
    assert "TAR entry limit reached" in _titles(findings)


# ---------------------------------------------------------------------------------------
# Corrupt checksums


def _corrupt_tar(compress: bool = False) -> bytes:
    data = bytearray(_tar([(name, b"data", tarfile.REGTYPE, None) for name in ("first.txt", "second.txt",
                                                                                "third.txt")]))
    data[1024 + 148] ^= 0x01  # the second header's checksum field
    return gzip.compress(bytes(data)) if compress else bytes(data)


@pytest.mark.parametrize("compress", [False, True])
def test_a_tar_header_that_fails_its_checksum_does_not_hide_the_members_after_it(tmp_path: Path, compress):
    # Python's tarfile and 7-Zip stop at the bad header; GNU tar skips to the next one.
    name = "corrupt.tar.gz" if compress else "corrupt.tar"
    summaries, members, findings = _inspect(tmp_path, name, _corrupt_tar(compress), "archive/tar")
    summary = summaries[name]
    assert summary["state"] == "malformed" and summary["corrupt_header_offsets"] == [1024]
    assert {path: items["flags"] for path, items in members[name].items()} == {
        "first.txt": [], "third.txt": ["past-corrupt-header"]}
    corrupt = next(item for item in findings if item.title.startswith("TAR headers fail their checksum"))
    assert corrupt.severity == "MEDIUM" and "listed 1 member(s) after them" in corrupt.detail


def test_a_lone_zero_block_does_not_hide_the_members_after_it(tmp_path: Path):
    first = _tar([("a.txt", b"data", tarfile.REGTYPE, None)])[:1024]
    data = first + bytes(512) + _tar([("hidden.txt", b"data", tarfile.REGTYPE, None)])
    summaries, members, findings = _inspect(tmp_path, "lone.tar", data, "archive/tar")
    assert summaries["lone.tar"]["structure_issues"] == {"lone_zero_blocks": 1}
    assert members["lone.tar"]["hidden.txt"]["flags"] == ["past-corrupt-header"]
    assert "Lone zero blocks inside a TAR archive" in _titles(findings)


def test_data_after_the_end_of_a_tar_archive_is_noted(tmp_path: Path):
    summaries, _, findings = _inspect(tmp_path, "tail.tar", _TAR_ONE + b"appended payload", "archive/tar")
    assert summaries["tail.tar"]["structure_issues"] == {"trailing_bytes": 16}
    assert "Data after the end of a TAR archive" in _titles(findings)


def test_a_zip_member_that_fails_its_crc_is_flagged(tmp_path: Path):
    data = bytearray(_zip([("data.txt", "hello world, all is well\n")], zipfile.ZIP_STORED))
    data[30 + len("data.txt") + 3] ^= 0x20  # one byte of the stored data
    summaries, members, findings = _inspect(tmp_path, "crc.zip", bytes(data), "archive/zip")
    assert members["crc.zip"]["data.txt"]["flags"] == ["crc-mismatch"]
    assert summaries["crc.zip"]["structure_issues"]["crc_mismatches"] == 1
    assert "ZIP members fail their CRC" in _titles(findings)


def test_7z_and_rar_header_checksums_are_checked(tmp_path: Path):
    seven = bytearray(_stored_seven())
    seven[-1] ^= 1
    rar = bytearray(_rar4(_rar4_file("a.txt", b"abc")))
    rar[7 + 13 + 7 + 25] ^= 0x01
    for name, data, file_type, error in (("crc.7z", seven, "archive/7z", "CRC does not match"),
                                         ("crc.rar", rar, "archive/rar", "fails its CRC")):
        summaries, _, _ = _inspect(tmp_path, name, bytes(data), file_type)
        assert summaries[name]["state"] == "malformed" and error in summaries[name]["error"]
