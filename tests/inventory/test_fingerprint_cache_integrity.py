"""The fingerprint cache sees every content change and survives a damaged database."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from project_discovery.cli import run_scan
from project_discovery.inventory.cache import ScanCache
from project_discovery.inventory.entry_metadata import change_time_ns


def _digests(project: Path, output: Path) -> tuple[dict[str, str], list[str]]:
    assert run_scan(project, output, {"json"}, 128, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    return {item["path"]: item["sha256"] for item in report["files"]}, report["errors"]


def test_a_same_size_rewrite_with_its_old_mtime_restored_is_rehashed(tmp_path: Path):
    # On Windows st_ctime is the creation time: the cache compares the NTFS ChangeTime.
    project = tmp_path / "project"
    project.mkdir()
    target = project / "data.txt"
    target.write_bytes(b"alpha-1\n")
    output = tmp_path / "out"
    first, _ = _digests(project, output)
    before = target.stat()
    changed_before = change_time_ns(target, before)
    target.write_bytes(b"alpha-2\n")  # the same size
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))  # and the first version's mtime
    after = target.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    assert change_time_ns(target, after) != changed_before
    second, _ = _digests(project, output)
    assert first["data.txt"] == hashlib.sha256(b"alpha-1\n").hexdigest()
    assert second["data.txt"] == hashlib.sha256(b"alpha-2\n").hexdigest()


def test_a_cache_damaged_after_its_header_is_bypassed_then_rebuilt(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    for index in range(3):
        (project / f"file{index}.txt").write_bytes(f"content {index}\n".encode())
    output = tmp_path / "out"
    expected, _ = _digests(project, output)
    cache_path = output / ".pdt-cache" / "fingerprints.sqlite3"
    with ScanCache(cache_path) as cache:  # rows on more pages than the first
        for index in range(3000):
            cache.put("/elsewhere", f"row{index}", 1, 1, 1, 1, "0" * 64)
    data = bytearray(cache_path.read_bytes())
    data[4096:] = b"\xff" * (len(data) - 4096)  # page 1 (header and schema) intact, data pages not
    cache_path.write_bytes(bytes(data))
    digests, errors = _digests(project, output)
    assert digests == expected  # every file hashed without the cache
    assert any("fingerprint cache unreadable" in error for error in errors)
    assert list(cache_path.parent.glob("fingerprints.sqlite3.corrupt-*"))  # set aside when the scan ended
    rebuilt, errors = _digests(project, output)
    assert rebuilt == expected and not any("fingerprint cache" in error for error in errors)
    assert cache_path.exists()
