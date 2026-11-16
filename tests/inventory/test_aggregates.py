"""Inventory aggregates: empty directories, fan-out, hard links, owners and timestamps."""
from __future__ import annotations

import json
import os
from pathlib import Path

from project_discovery.cli import run_scan
from project_discovery.inventory.aggregates import inventory_aggregates
from project_discovery.inventory.store import InventoryStore
from project_discovery.models import DirectoryRecord, FileRecord, SpecialEntryRecord, SymlinkRecord

NOW = 1_800_000_000 * 10**9  # 2027-01-15


def _file(path, *, identity=None, uid=None, mtime=None, security=None):
    record = FileRecord(path, 1, "", "Text", uid=uid, gid=None if uid is None else uid + 1, mtime_ns=mtime,
                        security=security)
    record.analysis_identity = identity
    return record


def test_aggregates_from_the_stored_inventory(tmp_path: Path):
    with InventoryStore(tmp_path / "inventory.sqlite3", batch_size=7) as store:
        for record in (
            DirectoryRecord(".", 0), DirectoryRecord("wide", 1), DirectoryRecord("empty", 1),
            DirectoryRecord("node_modules", 1, pruned=True, prune_reason="explicit --exclude-dir name: node_modules"),
            DirectoryRecord("locked", 1, error="PermissionError: denied"),
        ):
            store.append("directory", record)
        store.adjust_directory(".", direct_child_delta=7)
        store.adjust_directory("wide", direct_child_delta=120)
        for record in (
            _file("wide/a", identity=(5, 42, 1, 1, 1), uid=1000, mtime=NOW - 10**9),
            _file("wide/b", identity=(5, 42, 1, 1, 1), uid=1000, mtime=315_000_000 * 10**9),  # 1979
            _file("wide/c", identity=(5, 43, 1, 1, 1), uid=0, mtime=NOW + 2 * 86_400 * 10**9),  # future
            _file("wide/d", identity=(6, 42, 1, 1, 1), uid=0),  # same inode, other device
            _file("wide/e", security={"owner_sid": "S-1-5-32-544"}),
        ):
            store.append("file", record)
        store.append("symlink", SymlinkRecord("link", "wide/a", "internal", uid=1000, gid=1001))
        store.append("special", SpecialEntryRecord("pipe", "fifo", uid=7, gid=8))
        result = inventory_aggregates(store, scan_started_ns=NOW)
    assert result["empty_directory_count"] == 1  # the pruned and unreadable ones were not listed
    assert result["fan_out"] == {
        "directories": 3, "max": 120, "max_path": "wide", "mean": 42.33,
        "buckets": {"0": 1, "1-9": 1, "100-999": 1},
    }
    assert result["hard_links"] == {
        "supported": True, "files_with_identity": 4, "distinct_inodes": 3, "hard_linked_files": 2, "groups": 1,
    }
    assert result["owners"] == {"1000": 3, "0": 2, "7": 1}
    assert result["groups"] == {"1001": 3, "1": 2, "8": 1}
    assert result["owner_sids"] == {"S-1-5-32-544": 1}
    timestamps = result["file_timestamps"]
    assert timestamps["files"] == 3
    assert timestamps["oldest"] == {"mtime_ns": 315_000_000 * 10**9, "path": "wide/b"}
    assert timestamps["newest"]["path"] == "wide/c"
    assert timestamps["by_year"] == {"1979": 1, "2027": 2}
    assert (timestamps["future_count"], timestamps["before_1980_count"]) == (1, 1)


def test_owners_beyond_the_listed_ones_are_summed(tmp_path: Path):
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        store.append("directory", DirectoryRecord(".", 0))
        for index in range(60):
            for copy in range(2 if index < 50 else 1):
                store.append("file", _file(f"f{index}-{copy}", uid=index))
        result = inventory_aggregates(store, scan_started_ns=NOW)
    assert len(result["owners"]) == 51 and result["owners"]["other"] == 10
    assert result["hard_links"]["supported"] is False  # no identities: nothing to compare
    assert result["empty_directory_count"] == 1 and result["file_timestamps"]["oldest"] is None


def test_scans_report_empty_directories_hard_links_and_unusual_times(tmp_path: Path):
    project = tmp_path / "project"
    (project / "empty").mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "a.txt").write_text("x", encoding="utf-8")
    os.link(project / "src" / "a.txt", project / "src" / "b.txt")
    (project / "old.txt").write_text("x", encoding="utf-8")
    os.utime(project / "old.txt", ns=(315_000_000 * 10**9, 315_000_000 * 10**9))
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown"}, 128, quiet=True) == 0
    aggregates = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["inventory_aggregates"]
    assert aggregates["empty_directory_count"] == 1
    assert (aggregates["hard_links"]["hard_linked_files"], aggregates["hard_links"]["groups"]) == (2, 1)
    assert aggregates["file_timestamps"]["oldest"]["path"] == "old.txt"
    assert aggregates["file_timestamps"]["before_1980_count"] == 1
    if os.name != "nt":
        assert aggregates["owners"] == {str(os.getuid()): 6}  # the root, two directories, three files
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Empty directories: 1" in markdown
    assert "- Hard-linked files: 2 in 1 group(s)" in markdown
    assert "- File modification times: oldest 1979-12-25 (old.txt), newest " in markdown
    assert "; 1 before 1980" in markdown
