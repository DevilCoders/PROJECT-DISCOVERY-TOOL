"""--development-trees: deep, inventory and directory-only scans of confirmed development trees."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from project_discovery.inventory import scanner
from project_discovery.inventory.scanner import discover_inventory


def _walkers(monkeypatch):
    yield "native"
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    yield "python"


def _project(root: Path) -> Path:
    for directory in ("node_modules/left-pad/lib", "build", "src"):
        (root / directory).mkdir(parents=True)
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / "node_modules" / ".package-lock.json").write_text("{}\n", encoding="utf-8")
    (root / "node_modules" / "left-pad" / "index.js").write_text("module.exports = 'padded';\n", encoding="utf-8")
    (root / "node_modules" / "left-pad" / "lib" / "pad.js").write_text("x" * 100, encoding="utf-8")
    (root / "build" / "out.txt").write_text("a project directory named build\n", encoding="utf-8")
    (root / "src" / "app.js").write_text("require('left-pad');\n", encoding="utf-8")
    return root


def _tree_bytes(project: Path) -> int:
    """The bytes of the regular files in the tree (a link is not a file, and is not followed)."""
    return sum(
        path.lstat().st_size for path in (project / "node_modules").rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def _link(source: Path, target: str, directory: bool = False) -> bool:
    try:
        source.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        return False
    return True


def test_directory_only_trees_keep_directories_and_totals_but_no_file_records(tmp_path: Path, monkeypatch):
    project = _project(tmp_path / "project")
    linked = _link(project / "node_modules" / "left-pad" / "alias.js", "index.js")
    outside = _link(project / "src" / "pad.js", "../node_modules/left-pad/index.js")
    for walker in _walkers(monkeypatch):
        files, directories, symlinks, _, stats = discover_inventory(project, development_trees="directory-only")
        paths = {item.path for item in files}
        assert paths == {"package.json", "build/out.txt", "src/app.js"}, walker
        records = {item.path: item for item in directories}
        assert {path for path, item in records.items() if not item.contents_recorded} == {
            "node_modules", "node_modules/left-pad", "node_modules/left-pad/lib",
        }, walker
        tree = records["node_modules"]
        assert (tree.file_count, tree.total_bytes) == (3, _tree_bytes(project)), walker
        assert records["node_modules/left-pad"].direct_child_count == (3 if linked else 2), walker
        # A possible marker (a project directory named build) keeps its full contents.
        assert records["build"].contents_recorded and records["build"].marker_confidence == "possible"
        assert stats["development_tree_count"] == 1 and stats["development_tree_unrecorded_files"] == 3
        assert stats.get("development_tree_unrecorded_entries", 0) == (1 if linked else 0)
        assert records["."].total_bytes == stats["total_bytes"], walker
        if outside:
            link = next(item for item in symlinks if item.path == "src/pad.js")
            assert link.target_state == "unknown", walker
            assert link.target_detail == ("node_modules/left-pad is a directory-only development tree: "
                                          "its files are not recorded")


def test_inventory_trees_record_every_entry_but_read_no_content(tmp_path: Path, monkeypatch):
    project = _project(tmp_path / "project")
    real_sample = scanner._read_verified_sample

    def no_tree_reads(path, *args, **kwargs):
        assert "node_modules" not in Path(path).parts, f"read inside an inventory-mode tree: {path}"
        return real_sample(path, *args, **kwargs)

    monkeypatch.setattr(scanner, "_read_verified_sample", no_tree_reads)
    for walker in _walkers(monkeypatch):
        files, directories, *_, stats = discover_inventory(project, development_trees="inventory")
        records = {item.path: item for item in files}
        tree_file = records["node_modules/left-pad/index.js"]
        assert (tree_file.type_source, tree_file.file_type) == ("name", "source"), walker
        assert tree_file.content_skipped_reason == (
            "--development-trees inventory: inside the dependencies tree node_modules (node_modules, confirmed)"
        )
        assert records["src/app.js"].type_source == "content" and records["src/app.js"].content_skipped_reason is None
        assert all(item.contents_recorded for item in directories)
        assert stats["development_tree_unread_files"] == 3 and stats["development_tree_count"] == 1


def test_development_trees_reach_reports_analysis_and_resume(tmp_path: Path, capsys):
    from project_discovery.cli import main, run_scan

    project = _project(tmp_path / "project")
    (project / "node_modules" / "left-pad" / "secret.js").write_text(
        "const key = 'AKIA" + "ABCDEFGHIJKLMNOP';\n", encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown"}, 128, quiet=True, development_trees="inventory") == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    trees = report["metrics"]["development_trees"]
    assert trees == {
        "mode": "inventory", "trees": 1, "files_not_read": 4, "files_not_recorded": 0, "bytes_not_recorded": 0,
        "links_and_special_entries_not_recorded": 0,
    }
    # Nothing inside the tree was analyzed: the key planted there is found only in a deep scan.
    def tree_secrets(scan: dict) -> list[dict]:
        return [item for item in scan["findings"]
                if item["analyzer"] == "secret-patterns" and "node_modules/" in " ".join(item["evidence"])]

    assert tree_secrets(report) == []
    deep = tmp_path / "deep"
    assert run_scan(project, deep, {"json"}, 128, quiet=True) == 0
    assert tree_secrets(json.loads((deep / "discovery-report.json").read_text(encoding="utf-8")))
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Development trees: inventory: 1 tree(s), 4 files recorded but not read" in markdown

    directory_only = tmp_path / "directory-only"
    assert run_scan(project, directory_only, {"markdown"}, 128, quiet=True, development_trees="directory-only") == 0
    markdown = (directory_only / "discovery-report.md").read_text(encoding="utf-8")
    assert (f"- Development trees: directory-only: 1 tree(s), 4 files ({_tree_bytes(project):,} bytes) and 0 links "
            "or special entries counted, not recorded") in markdown
    # --resume continues only an inventory made with the same mode.
    argv = sys.argv
    try:
        sys.argv = ["pdt", "scan", str(project), "--output", str(output), "--resume", "--quiet"]
        with pytest.raises(SystemExit) as exit_info:
            main()
        assert exit_info.value.code == 2
        assert "--development-trees: stored inventory, now deep" in " ".join(capsys.readouterr().err.split())
    finally:
        sys.argv = argv


def test_the_default_deep_mode_changes_nothing(tmp_path: Path):
    project = _project(tmp_path / "project")
    files, directories, *_, stats = discover_inventory(project)
    assert {"node_modules/left-pad/index.js", "node_modules/left-pad/lib/pad.js"} <= {item.path for item in files}
    assert all(item.contents_recorded for item in directories)
    assert not stats.get("development_tree_count")
    with pytest.raises(ValueError, match="--development-trees shallow: choose from deep, inventory, directory-only"):
        discover_inventory(project, development_trees="shallow")


@pytest.mark.skipif(os.name == "nt", reason="special entries need a POSIX FIFO")
def test_directory_only_trees_count_special_entries_without_records(tmp_path: Path):
    project = _project(tmp_path / "project")
    os.mkfifo(project / "node_modules" / "left-pad" / "pipe")
    _, _, _, special, stats = discover_inventory(project, development_trees="directory-only")
    assert special == [] and stats["development_tree_unrecorded_entries"] == 1
