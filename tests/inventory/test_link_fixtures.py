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
        assert all(link.reparse_tag == "mount_point" for link in symlinks), walker
        assert not by_path["broken"].target.startswith("\\\\?\\")
        assert stats.get("walk_errors", 0) == 0, walker
