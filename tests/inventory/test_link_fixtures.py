"""Broken, self, cyclic, dangling-relative and external links: recorded, never followed."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from project_discovery.inventory import scanner
from project_discovery.inventory.scanner import discover_inventory


def _walkers(monkeypatch):
    """Yield once per inventory backend: the native walker (if built), then the fallback."""
    yield "native"
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    yield "python"


def _link(path: Path, target: str, *, directory: bool = False) -> None:
    try:
        os.symlink(target, path, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:  # Windows without the symlink privilege
        pytest.skip(f"symbolic links cannot be created here: {exc}")


def test_broken_self_cyclic_dangling_and_external_links_are_recorded_not_followed(tmp_path: Path, monkeypatch):
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "sub").mkdir(parents=True)
    outside.mkdir()
    (root / "file.txt").write_text("x", encoding="utf-8")
    (outside / "secret.txt").write_text("not part of the scan", encoding="utf-8")
    gone = os.path.join("..", "gone", "file.txt")
    links = {
        "broken": ("missing.txt", False),                      # the target does not exist
        "self": ("self", False),                               # the link names itself
        "cycle_a": ("cycle_b", False),                         # two links naming each other
        "cycle_b": ("cycle_a", False),
        "sub/dangling": (gone, False),                         # relative, up a level, missing
        "sub/up": ("..", True),                                # a directory loop for followers
        "chain": (os.path.join("sub", "up"), True),            # a link to a link to the root
        "external": (str(outside / "secret.txt"), False),      # absolute, outside the root
        "external_relative": (os.path.join("..", "outside"), True),
        "absolute_internal": (str(root / "file.txt"), False),
    }
    for path, (target, directory) in links.items():
        _link(root / path, target, directory=directory)
    expected_scope = {
        "broken": "internal", "self": "internal", "cycle_a": "internal", "cycle_b": "internal",
        "sub/dangling": "internal", "sub/up": "internal", "chain": "internal",
        "external": "external", "external_relative": "external", "absolute_internal": "internal",
    }
    # Resolved against the inventory: (state, resolved type, resolved path).
    expected_state = {
        "broken": ("broken", None, "missing.txt"), "self": ("loop", None, None),
        "cycle_a": ("loop", None, None), "cycle_b": ("loop", None, None),
        "sub/dangling": ("broken", None, "gone/file.txt"), "sub/up": ("resolved", "directory", "."),
        "chain": ("resolved", "directory", "."), "external": ("external", None, None),
        "external_relative": ("external", None, None), "absolute_internal": ("resolved", "file", "file.txt"),
    }
    seen = []
    for walker in _walkers(monkeypatch):
        files, directories, symlinks, special, stats = discover_inventory(root)
        assert [record.path for record in files] == ["file.txt"], walker
        assert sorted(record.path for record in directories) == [".", "sub"], walker
        assert list(special) == [], walker
        by_path = {link.path: link for link in symlinks}
        assert {path: link.target for path, link in by_path.items()} == {
            path: target for path, (target, _) in links.items()
        }, walker
        assert {path: link.target_scope for path, link in by_path.items()} == expected_scope, walker
        assert {
            path: (link.target_state, link.resolved_type, link.resolved_path) for path, link in by_path.items()
        } == expected_state, walker
        assert by_path["self"].target_detail == "the chain returns to self"
        assert by_path["sub/dangling"].target_detail == "gone does not exist"
        assert stats["symlink_state:loop"] == 3 and stats["symlink_state:resolved"] == 3
        assert stats.get("walk_errors", 0) == 0 and stats.get("entry_errors", 0) == 0, walker
        assert stats["symlink_count"] == len(links)
        seen.append(sorted((link.path, link.target, link.target_scope, link.target_state) for link in symlinks))
    assert seen[0] == seen[1]  # both backends record the same links


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions are Windows-specific")
def test_broken_and_external_junctions_are_recorded_not_followed(tmp_path: Path, monkeypatch):
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "gone").mkdir(parents=True)
    (outside / "data").mkdir(parents=True)
    (outside / "data" / "secret.txt").write_text("not part of the scan", encoding="utf-8")
    for link, target in (("broken", root / "gone"), ("external", outside / "data")):
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / link), str(target)], capture_output=True)
        if made.returncode:
            pytest.skip("junction creation unavailable")
    shutil.rmtree(root / "gone")  # the junction now names a missing directory
    for walker in _walkers(monkeypatch):
        files, directories, symlinks, _, stats = discover_inventory(root)
        assert list(files) == [] and [record.path for record in directories] == ["."], walker
        by_path = {link.path: link for link in symlinks}
        assert set(by_path) == {"broken", "external"}, walker
        assert (by_path["broken"].target_scope, by_path["external"].target_scope) == ("internal", "external"), walker
        assert (by_path["broken"].target_state, by_path["broken"].resolved_path) == ("broken", "gone"), walker
        assert by_path["external"].target_state == "external", walker
        assert all(link.reparse_tag == "mount_point" for link in symlinks), walker
        assert not by_path["broken"].target.startswith("\\\\?\\")
        assert stats.get("walk_errors", 0) == 0, walker


def test_links_into_pruned_and_unreadable_directories_are_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.inventory.store import InventoryStore

    root = tmp_path / "root"
    for name in ("node_modules", "locked", "real"):
        (root / name).mkdir(parents=True)
    (root / "node_modules" / "pkg.js").write_text("x", encoding="utf-8")
    (root / "real" / "a.txt").write_text("x", encoding="utf-8")
    _link(root / "into_pruned", os.path.join("node_modules", "pkg.js"))
    _link(root / "into_locked", os.path.join("locked", "inner.txt"))
    _link(root / "alias", "real", directory=True)
    _link(root / "via_alias", os.path.join("alias", "a.txt"))
    locked = os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0
    if locked:
        os.chmod(root / "locked", 0)
    try:
        for walker in _walkers(monkeypatch):
            for store in (None, InventoryStore(tmp_path / f"{walker}.sqlite3")):
                inventory = discover_inventory(root, ignores={"node_modules"}, store=store)
                by_path = {link.path: link for link in inventory[2]}
                assert by_path["into_pruned"].target_state == "unknown", walker
                assert by_path["into_pruned"].target_detail == "it passes through the pruned directory node_modules"
                if locked:
                    assert by_path["into_locked"].target_state == "unknown", walker
                    assert by_path["into_locked"].target_detail == "it passes through the unreadable directory locked"
                else:
                    assert by_path["into_locked"].target_state == "broken", walker
                assert (by_path["via_alias"].target_state, by_path["via_alias"].resolved_path) == (
                    "resolved", "real/a.txt",
                ), walker
                if store is not None:
                    store.close()
    finally:
        if locked:
            os.chmod(root / "locked", 0o700)


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions are Windows-specific")
def test_junction_targets_match_inventory_names_without_regard_to_case(tmp_path: Path, monkeypatch):
    from project_discovery.inventory.store import InventoryStore

    root = tmp_path / "root"
    (root / "Data").mkdir(parents=True)
    (root / "Data" / "Report.txt").write_text("x", encoding="utf-8")
    target = os.path.join(str(root).upper(), "DATA")  # NTFS matches names without regard to case
    if subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "shortcut"), target], capture_output=True).returncode:
        pytest.skip("junction creation unavailable")
    for walker in _walkers(monkeypatch):
        for store in (None, InventoryStore(tmp_path / f"{walker}.sqlite3")):
            links = list(discover_inventory(root, store=store)[2])
            assert [(link.target_state, link.resolved_type, link.resolved_path) for link in links] == [
                ("resolved", "directory", "Data"),
            ], (walker, store)
            if store is not None:
                store.close()
