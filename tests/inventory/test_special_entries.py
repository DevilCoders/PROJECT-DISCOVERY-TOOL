"""Full records for special entries, links and Windows reparse points."""
from __future__ import annotations

import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest

from project_discovery.inventory import scanner
from project_discovery.inventory.entry_metadata import device_numbers, reparse_tag_name
from project_discovery.inventory.scanner import discover_inventory


def _walkers(monkeypatch):
    """Yield once per inventory backend: the native walker (if built), then the fallback."""
    yield "native"
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    yield "python"


def _records(inventory) -> dict:
    files, directories, links, special, _ = inventory
    return {record.path: record for record in (*files, *directories, *links, *special)}


class _Entry:
    """A directory entry with a chosen stat result, for types a test cannot create."""

    def __init__(self, directory: Path, name: str, info: os.stat_result):
        self.name, self.path, self._info = name, os.path.join(directory, name), info

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        return self._info


class _Listing:
    def __init__(self, entries):
        self._entries = iter(entries)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._entries)

    def close(self) -> None:
        pass


def _fake_root_listing(monkeypatch, root: Path, entries) -> None:
    real, root = os.scandir, root.resolve()

    def scandir(path):
        return _Listing(entries) if Path(path).resolve() == root else real(path)

    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(scanner.os, "scandir", scandir)


def _info(mode: int, **extra) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, 0, 0, 0, 0, 0, 0), {"st_mtime_ns": 1_700_000_000_000_000_000, **extra})


def test_reparse_tag_names():
    assert reparse_tag_name(0xA0000003) == "mount_point"  # a junction or volume mount point
    assert reparse_tag_name(0xA000000C) == "symlink"
    assert reparse_tag_name(0x9000001A) == reparse_tag_name(0x9000F01A) == "cloud"
    assert reparse_tag_name(0x80000023) == "af_unix"
    assert reparse_tag_name(0x12345678) == "0x12345678"
    assert reparse_tag_name(0) is None and reparse_tag_name(None) is None


@pytest.mark.skipif(not hasattr(os, "makedev"), reason="POSIX device numbers")
def test_device_numbers_use_the_platform_encoding():
    assert device_numbers(os.makedev(8, 17)) == (8, 17)
    assert device_numbers(os.makedev(259, 70000)) == (259, 70000)
    assert device_numbers(None) == (None, None)


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFOs, sockets and device nodes")
def test_posix_special_entries_have_full_records(tmp_path: Path, monkeypatch):
    os.mkfifo(tmp_path / "pipe")
    monkeypatch.chdir(tmp_path)  # a relative name keeps the socket path within sun_path's limit
    server = socket.socket(socket.AF_UNIX)
    server.bind("sock")
    expected = {"pipe": "fifo", "sock": "socket"}
    try:
        # Linux 5.8+ lets an unprivileged user create the 0:0 character device (an overlayfs whiteout).
        os.mknod(tmp_path / "whiteout", stat.S_IFCHR | 0o600, 0)
        expected["whiteout"] = "character_device"
    except OSError:
        pass
    os.symlink("pipe", tmp_path / "link")
    (tmp_path / "dir").mkdir()
    try:
        for walker in _walkers(monkeypatch):
            inventory = discover_inventory(tmp_path)
            records = _records(inventory)
            for name, kind in expected.items():
                record, info = records[name], os.lstat(tmp_path / name)
                assert record.entry_type == kind, (walker, name)
                assert (record.uid, record.gid, record.permissions, record.mtime_ns, record.size_bytes) == (
                    info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_size,
                ), (walker, name)
                assert record.reparse_tag is None
            if "whiteout" in expected:
                assert (records["whiteout"].device_major, records["whiteout"].device_minor) == (0, 0), walker
            assert records["pipe"].device_major is None and records["sock"].device_minor is None
            for name in ("link", "dir"):
                assert records[name].mtime_ns == os.lstat(tmp_path / name).st_mtime_ns, (walker, name)
            assert records["."].mtime_ns == os.stat(tmp_path).st_mtime_ns
            stats = inventory[4]
            assert (stats["special_type:fifo"], stats["special_type:socket"]) == (1, 1), walker
    finally:
        server.close()


@pytest.mark.skipif(not hasattr(os, "makedev"), reason="POSIX device numbers")
def test_block_devices_and_unknown_types_have_full_records(tmp_path: Path, monkeypatch):
    # Neither can be created without privileges: the walker's entries are given instead.
    entries = [
        ("disk", "block_device", 0, 0o660, 5, False, "", None, 1, None, None, None, 0, 6, None, os.makedev(8, 1)),
        ("door", "unknown_special", 0, 0o644, 7, False, "", None, 1, None, None, None, 0, 0, None, None),
        # 15 fields: a walker built before device numbers were reported.
        ("tty", "character_device", 0, 0o620, 9, False, "", None, 1, None, None, None, 0, 5, None),
    ]
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: iter(entries))
    records = _records(discover_inventory(tmp_path))
    disk, door, tty = records["disk"], records["door"], records["tty"]
    assert (disk.entry_type, disk.device_major, disk.device_minor, disk.mtime_ns, disk.gid) == ("block_device", 8, 1, 5, 6)
    assert (door.entry_type, door.device_major, door.mtime_ns) == ("unknown_special", None, 7)
    assert (tty.entry_type, tty.device_major, tty.mtime_ns, tty.gid) == ("character_device", None, 9, 5)
    # The fallback walker reads the same from lstat.
    _fake_root_listing(monkeypatch, tmp_path, [
        _Entry(tmp_path, "disk", _info(stat.S_IFBLK | 0o660, st_rdev=os.makedev(8, 1))),
        _Entry(tmp_path, "door", _info(0o150000 | 0o644)),  # a Solaris door: no S_IS* test matches
    ])
    records = _records(discover_inventory(tmp_path))
    assert (records["disk"].entry_type, records["disk"].device_major, records["disk"].device_minor) == ("block_device", 8, 1)
    assert records["disk"].mtime_ns == 1_700_000_000_000_000_000
    assert (records["door"].entry_type, records["door"].device_major) == ("unknown_special", None)


def _windows_unix_socket(path: Path) -> bool:
    """Create a Windows AF_UNIX socket file; Python's socket module has no AF_UNIX here."""
    import ctypes

    ws2 = ctypes.WinDLL("ws2_32", use_last_error=True)
    ws2.socket.restype = ctypes.c_size_t
    ws2.socket.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
    ws2.bind.argtypes = (ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int)
    ws2.closesocket.argtypes = (ctypes.c_size_t,)

    class WsaData(ctypes.Structure):
        _fields_ = (("version", ctypes.c_ushort), ("high_version", ctypes.c_ushort), ("rest", ctypes.c_byte * 512))

    class SockaddrUn(ctypes.Structure):
        _fields_ = (("sun_family", ctypes.c_ushort), ("sun_path", ctypes.c_char * 108))

    if ws2.WSAStartup(0x0202, ctypes.byref(WsaData())):
        return False
    descriptor = ws2.socket(1, 1, 0)  # AF_UNIX, SOCK_STREAM
    if descriptor == ctypes.c_size_t(-1).value:
        return False
    try:
        address = SockaddrUn(1, os.fsencode(path))
        return ws2.bind(descriptor, ctypes.byref(address), ctypes.sizeof(address)) == 0
    finally:
        ws2.closesocket(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse points")
def test_windows_sockets_junctions_and_reparse_tags(tmp_path: Path, monkeypatch):
    # Regression: an AF_UNIX socket (a reparse point) was inventoried as a regular file.
    (tmp_path / "target").mkdir()
    (tmp_path / "plain.txt").write_text("x", encoding="utf-8")
    if not _windows_unix_socket(tmp_path / "s.sock"):
        pytest.skip("AF_UNIX sockets are not available")
    junction = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tmp_path / "junction"), str(tmp_path / "target")], capture_output=True,
    ).returncode == 0
    for walker in _walkers(monkeypatch):
        inventory = discover_inventory(tmp_path)
        records = _records(inventory)
        sock = records["s.sock"]
        assert (sock.entry_type, sock.reparse_tag) == ("socket", "af_unix"), walker
        assert "reparse_point" in sock.attributes and sock.mtime_ns == os.lstat(tmp_path / "s.sock").st_mtime_ns
        assert [record.path for record in inventory[0]] == ["plain.txt"], walker
        assert records["plain.txt"].reparse_tag is None and records["target"].reparse_tag is None
        if junction:
            link = records["junction"]
            assert link.reparse_tag == "mount_point", walker
            assert link.mtime_ns == os.lstat(tmp_path / "junction").st_mtime_ns, walker
        stats = inventory[4]
        assert stats["reparse_tag:af_unix"] == 1 and stats["special_type:socket"] == 1, walker


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse points")
def test_wsl_fifos_and_device_nodes_are_special_entries(tmp_path: Path, monkeypatch):
    # WSL stores FIFOs and device nodes on NTFS as reparse points that read as regular files.
    tags = {"fifo": 0x80000024, "chr": 0x80000025, "blk": 0x80000026, "cloud.txt": 0x9000701A}
    for name in tags:
        (tmp_path / name).write_text("x", encoding="utf-8")
    entries = [
        (name, "file", 1, None, 3, False, "", None, 1, None, None, None, None, None, 0x420, None)
        for name in tags
    ]
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: iter(entries))
    monkeypatch.setattr(scanner, "_lstat_reparse_tag", lambda path: tags[os.path.basename(path)])
    expected = {"fifo": ("fifo", "lx_fifo"), "chr": ("character_device", "lx_chr"), "blk": ("block_device", "lx_blk")}
    native = _records(discover_inventory(tmp_path))
    _fake_root_listing(monkeypatch, tmp_path, [
        _Entry(tmp_path, name, _info(stat.S_IFREG | 0o666, st_file_attributes=0x420, st_reparse_tag=tag))
        for name, tag in tags.items()
    ])
    fallback = _records(discover_inventory(tmp_path))
    for walker, records in (("native", native), ("python", fallback)):
        for name, (kind, tag) in expected.items():
            assert (records[name].entry_type, records[name].reparse_tag) == (kind, tag), (walker, name)
        # A cloud placeholder stays a file; its tag says what it is.
        assert (type(records["cloud.txt"]).__name__, records["cloud.txt"].reparse_tag) == ("FileRecord", "cloud"), walker
