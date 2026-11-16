"""Ownership, platform attributes and --security-metadata on every inventory record."""
from __future__ import annotations

import errno
import os
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from project_discovery.inventory import entry_metadata, scanner
from project_discovery.inventory.entry_metadata import attribute_names, has_explicit_acl, parse_posix_acl
from project_discovery.inventory.scanner import discover_inventory
from project_discovery.models import DirectoryRecord, FileRecord, SpecialEntryRecord, SymlinkRecord


def _walkers(monkeypatch):
    """Yield once per inventory backend: the native walker (if built), then the fallback."""
    yield "native"
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    yield "python"


def _records(inventory) -> dict:
    files, directories, links, special, _ = inventory
    return {record.path: record for record in (*files, *directories, *links, *special)}


def _acl(*entries: tuple[int, int, int]) -> bytes:
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def test_attribute_names_decode_windows_bits_and_macos_flags():
    assert attribute_names(0x21, "win32") == ["readonly", "archive"]
    # DIRECTORY and NORMAL repeat what the record type says; an unnamed bit keeps its value.
    assert attribute_names(0x10 | 0x80, "win32") == []
    assert attribute_names(0x400 | 0x4 | 0x800000, "win32") == ["system", "reparse_point", "0x00800000"]
    assert attribute_names(0x8000 | 0x2 | 0x20000, "darwin") == ["uf_immutable", "uf_hidden", "sf_immutable"]
    assert attribute_names(0x21, "linux") == []
    assert attribute_names(None) == attribute_names(0) == []
    # Each call returns its own list, so one record's list never aliases another's.
    assert attribute_names(0x1, "win32") is not attribute_names(0x1, "win32")


def test_posix_acl_values_are_decoded_like_getfacl():
    value = _acl((0x01, 6, 0xFFFFFFFF), (0x02, 4, 1000), (0x04, 5, 0xFFFFFFFF), (0x08, 7, 27),
                 (0x10, 5, 0xFFFFFFFF), (0x20, 0, 0xFFFFFFFF))
    assert parse_posix_acl(value) == [
        "user::rw-", "user:1000:r--", "group::r-x", "group:27:rwx", "mask::r-x", "other::---",
    ]
    for malformed, message in (
        (value[:-1], "malformed POSIX ACL"), (b"\x02\x00", "malformed POSIX ACL"),
        (struct.pack("<I", 1) + value[4:], "unsupported POSIX ACL version 1"),
        (_acl((0x40, 4, 0)), "unknown POSIX ACL entry tag 0x40"),
    ):
        with pytest.raises(ValueError, match=message):
            parse_posix_acl(malformed)


def test_linux_acl_reads_separate_absent_acls_from_failures(monkeypatch):
    calls = []
    no_data = getattr(errno, "ENODATA", errno.EOPNOTSUPP)

    def getxattr(path, name, *, follow_symlinks=True):
        calls.append((path, name, follow_symlinks))
        if name == "system.posix_acl_default":
            raise OSError(errno.EOPNOTSUPP, "Operation not supported")
        if path == "/plain":
            raise OSError(no_data, "No data available")
        return _acl((0x01, 6, 0), (0x02, 4, 1000), (0x04, 4, 0), (0x10, 4, 0), (0x20, 4, 0))

    monkeypatch.setattr(entry_metadata.os, "getxattr", getxattr, raising=False)
    assert entry_metadata._linux_security("/shared", "directory") == {
        "posix_acl": ["user::rw-", "user:1000:r--", "group::r--", "mask::r--", "other::r--"],
        "posix_default_acl": None,
    }
    assert entry_metadata._linux_security("/plain", "fifo") == {"posix_acl": None}
    assert all(follow is False for *_, follow in calls)
    calls.clear()
    assert entry_metadata._linux_security("/link", "symlink") == {"posix_acl": None}
    assert calls == []  # Linux keeps no ACL on a link

    def denied(path, name, *, follow_symlinks=True):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(entry_metadata.os, "getxattr", denied, raising=False)
    with pytest.raises(PermissionError):
        entry_metadata._linux_security("/secret", "file")


def test_security_read_failures_are_recorded_as_errors(monkeypatch):
    if not entry_metadata.security_supported():
        pytest.skip("security metadata is read on Windows and Linux")

    def denied(*_args):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(entry_metadata, "_windows_security", denied)
    monkeypatch.setattr(entry_metadata, "_linux_security", denied)
    assert entry_metadata.read_security("/secret", "file") == {"error": "PermissionError: [Errno 13] Permission denied"}


def test_explicit_acl_detection():
    assert has_explicit_acl({"dacl": {"protected": False, "explicit_entries": [{"type": "allow"}]}})
    assert not has_explicit_acl({"owner_sid": "S-1-5-18", "dacl": {"explicit_entries": [], "inherited_entry_count": 3}})
    assert not has_explicit_acl({"dacl": None})  # no DACL: everyone has access, but no rule of its own
    assert has_explicit_acl({"posix_acl": None, "posix_default_acl": ["user::rwx"]})
    assert not has_explicit_acl({"posix_acl": None})
    assert not has_explicit_acl({"error": "PermissionError: denied"})
    assert not has_explicit_acl(None)


def test_native_walker_ownership_fields_reach_every_record(tmp_path: Path, monkeypatch):
    # Owner, group and attribute bits come from fields 13-15 of the walker tuple; a tuple
    # of 12 (a build from older sources) leaves them unknown instead of failing.
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f.txt").write_text("abc", encoding="utf-8")
    (tmp_path / "old.txt").write_text("a", encoding="utf-8")
    entries = [
        ("d", "directory", 0, 0o755, 0, False, "", None, 1, None, None, None, 501, 20, 0x21),
        ("d/f.txt", "file", 3, 0o644, 0, False, "", None, 2, None, None, None, 501, 20, 0x1),
        ("l", "symlink", 0, 0o777, 0, False, "d", None, 1, None, None, None, 501, 20, None),
        ("p", "fifo", 0, 0o600, 0, False, "", None, 1, None, None, None, 0, 0, None),
        ("old.txt", "file", 1, 0o644, 0, False, "", None, 1, None, None, None),
    ]
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: iter(entries))
    inventory = discover_inventory(tmp_path)
    records = _records(inventory)
    owners = {path: (record.uid, record.gid, record.attributes) for path, record in records.items() if path != "."}
    assert owners == {
        "d": (501, 20, attribute_names(0x21)), "d/f.txt": (501, 20, attribute_names(0x1)),
        "l": (501, 20, []), "p": (0, 0, []), "old.txt": (None, None, []),
    }
    assert all(record.security is None for record in records.values())
    stats = inventory[4]
    expected = Counter(attribute_names(0x21) + attribute_names(0x1) + records["."].attributes)
    assert {key[10:]: value for key, value in stats.items() if key.startswith("attribute:")} == expected


def test_unreadable_security_metadata_is_counted_not_fatal(tmp_path: Path, monkeypatch):
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(scanner, "security_supported", lambda: True)
    monkeypatch.setattr(scanner, "read_security", lambda path, kind: {"error": "PermissionError: denied"})
    for walker in _walkers(monkeypatch):
        inventory = discover_inventory(tmp_path, security_metadata=True)
        records = _records(inventory)
        assert {path: record.security for path, record in records.items()} == {
            ".": {"error": "PermissionError: denied"}, "a.txt": {"error": "PermissionError: denied"},
        }, walker
        stats = inventory[4]
        assert (stats["security_metadata_entries"], stats["security_metadata_errors"]) == (2, 2), walker
    monkeypatch.setattr(scanner, "security_supported", lambda: False)
    with pytest.raises(ValueError, match="Windows security descriptors and Linux POSIX ACLs only"):
        discover_inventory(tmp_path, security_metadata=True)


def test_ownership_and_security_survive_the_inventory_store(tmp_path: Path):
    from project_discovery.inventory.store import InventoryStore, StoredRecordSequence

    security = {"owner_sid": "S-1-5-32-544", "group_sid": "S-1-5-18",
                "dacl": {"protected": True, "explicit_entries": [], "inherited_entry_count": 0}}
    records = {
        "file": FileRecord("a.txt", 1, ".txt", "Text", uid=1000, gid=100, attributes=["readonly"], security=security),
        "directory": DirectoryRecord("d", 1, uid=0, gid=0, attributes=["system"], security={"posix_acl": None}),
        "symlink": SymlinkRecord("l", "d", "internal", attributes=["reparse_point"]),
        "special": SpecialEntryRecord("p", "fifo", uid=1000, gid=100),
    }
    database = tmp_path / "ownership.sqlite3"
    with InventoryStore(database, batch_size=1) as store:
        for kind, record in records.items():
            store.append(kind, record)
        store.flush()
        assert store.iter_file_records().__next__() == records["file"]
        for kind, record in records.items():
            if kind != "file":
                assert StoredRecordSequence(database, kind, type(record))[0] == record


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX ACLs are read on Linux")
def test_linux_records_carry_owner_group_and_posix_acls(tmp_path: Path, monkeypatch):
    if shutil.which("setfacl") is None:
        pytest.skip("setfacl is not installed")
    (tmp_path / "acl.txt").write_text("x", encoding="utf-8")
    (tmp_path / "shared").mkdir()
    os.symlink("acl.txt", tmp_path / "link")
    os.mkfifo(tmp_path / "pipe")
    uid = os.getuid()
    for command in (
        ["setfacl", "-m", f"u:{uid}:r", str(tmp_path / "acl.txt")],
        ["setfacl", "-d", "-m", f"u:{uid}:rx", str(tmp_path / "shared")],  # a default ACL
    ):
        if subprocess.run(command, capture_output=True).returncode:
            pytest.skip("this filesystem does not support POSIX ACLs")
    seen = []
    for walker in _walkers(monkeypatch):
        records = _records(discover_inventory(tmp_path, security_metadata=True))
        for path, record in records.items():
            info = os.lstat(tmp_path / path)
            assert (record.uid, record.gid, record.attributes) == (info.st_uid, info.st_gid, []), (walker, path)
        assert f"user:{uid}:r--" in records["acl.txt"].security["posix_acl"], walker
        assert records["shared"].security["posix_acl"] is None
        assert f"user:{uid}:r-x" in records["shared"].security["posix_default_acl"], walker
        assert records["link"].security == {"posix_acl": None}
        assert records["pipe"].security == {"posix_acl": None}
        assert records["."].security == {"posix_acl": None, "posix_default_acl": None}
        seen.append(sorted((path, record.uid, record.gid, repr(record.security)) for path, record in records.items()))
    assert seen[0] == seen[1]  # both backends record the same metadata
    # Without the option nothing is read; ownership is recorded either way.
    records = _records(discover_inventory(tmp_path))
    assert all(record.security is None and record.uid == os.lstat(tmp_path / path).st_uid
               for path, record in records.items())


def _set_windows_attributes(path: Path, attributes: int) -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileAttributesW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
    kernel32.SetFileAttributesW.restype = ctypes.c_int
    if not kernel32.SetFileAttributesW(str(path), attributes):
        raise ctypes.WinError(ctypes.get_last_error())


@pytest.mark.skipif(os.name != "nt", reason="Windows attributes and security descriptors")
def test_windows_records_carry_attributes_and_security_descriptors(tmp_path: Path, monkeypatch):
    for name in ("readonly.txt", "system.txt", "granted.txt", "sealed.txt"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    (tmp_path / "folder").mkdir()
    _set_windows_attributes(tmp_path / "readonly.txt", 0x1)
    _set_windows_attributes(tmp_path / "system.txt", 0x4 | 0x2)
    junction = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tmp_path / "junction"), str(tmp_path / "folder")], capture_output=True,
    ).returncode == 0
    for command in (
        ["icacls", str(tmp_path / "granted.txt"), "/grant", "*S-1-5-32-545:(R)"],  # BUILTIN\Users
        ["icacls", str(tmp_path / "sealed.txt"), "/inheritance:d"],  # copy inherited entries, stop inheriting
    ):
        if subprocess.run(command, capture_output=True).returncode:
            pytest.skip("icacls could not change the test files' ACLs")
    try:
        seen = []
        for walker in _walkers(monkeypatch):
            inventory = discover_inventory(tmp_path, security_metadata=True)
            records = _records(inventory)
            assert "readonly" in records["readonly.txt"].attributes, walker
            assert {"system", "hidden"} <= set(records["system.txt"].attributes), walker
            assert records["system.txt"].is_hidden
            assert "readonly" not in records["granted.txt"].attributes
            if junction:
                assert "reparse_point" in records["junction"].attributes, walker
            for path, record in records.items():
                assert (record.uid, record.gid) == (None, None), (walker, path)
                assert record.security["owner_sid"].startswith("S-1-"), (walker, path)
                assert record.security["group_sid"].startswith("S-1-"), (walker, path)
            granted = records["granted.txt"].security["dacl"]
            users = [entry for entry in granted["explicit_entries"] if entry["sid"] == "S-1-5-32-545"]
            assert users and users[0]["type"] == "allow" and users[0]["access_mask"] & 0x1, walker  # FILE_READ_DATA
            assert granted["protected"] is False and granted["inherited_entry_count"] >= 1
            sealed = records["sealed.txt"].security["dacl"]
            assert sealed["protected"] is True and sealed["inherited_entry_count"] == 0, walker
            assert sealed["explicit_entries"], walker
            assert records["readonly.txt"].security["dacl"]["explicit_entries"] == []
            stats = inventory[4]
            # Python 3.13+ gives pytest's 0o700 temporary root an explicit DACL of its own.
            own = 2 + has_explicit_acl(records["."].security)
            assert stats["security_explicit_acl_entries"] == own and not stats.get("security_metadata_errors"), walker
            assert stats["attribute:readonly"] >= 1 and stats["attribute:system"] == 1, walker
            seen.append(sorted((path, tuple(record.attributes), repr(record.security)) for path, record in records.items()))
        assert seen[0] == seen[1]  # both backends record the same metadata
    finally:
        for name in ("readonly.txt", "system.txt"):
            _set_windows_attributes(tmp_path / name, 0x80)
