"""Link targets resolved against an inventory snapshot, with POSIX and Windows rules."""
from __future__ import annotations

from collections import Counter

import pytest

from project_discovery.inventory.links import (
    Flavor, classify_links, memory_lookup, root_components,
)
from project_discovery.models import DirectoryRecord, FileRecord, SpecialEntryRecord, SymlinkRecord

POSIX = Flavor(windows=False)
WINDOWS = Flavor(windows=True, fold=str.casefold)


def _inventory(*, directories=(), files=(), links=None, special=()):
    """Records for a snapshot: directory and file paths, {link path: target}, special entries."""
    records = [("directory", DirectoryRecord(".", 0))]
    for item in directories:
        path, extra = (item, {}) if isinstance(item, str) else item
        records.append(("directory", DirectoryRecord(path, path.count("/") + 1, **extra)))
    records += [("file", FileRecord(path, 1, "", "Text")) for path in files]
    records += [("special", SpecialEntryRecord(path, kind)) for path, kind in special]
    link_records = []
    for path, target in (links or {}).items():
        state = "unreadable" if target is None else "unverified"
        link_records.append(SymlinkRecord(path, target or "", "internal", target_state=state))
    records += [("symlink", record) for record in link_records]
    return records, link_records


def _resolve(flavor=POSIX, root="/srv/project", **inventory):
    records, links = _inventory(**inventory)
    stats = Counter()
    classify_links(links, memory_lookup(records, flavor.fold), flavor, root_components(root, flavor), stats)
    return {link.path: (link.target_state, link.resolved_type, link.resolved_path) for link in links}, \
        {link.path: link.target_detail for link in links}, stats


def test_posix_resolves_dot_dot_after_replacing_each_link():
    # x -> a/b, so x/../f is a/f on POSIX (physical ".."); Windows collapses ".." first: f.
    tree = {"directories": ["a", "a/b"], "files": ["a/f"], "links": {"x": "a/b", "l": "x/../f"}}
    states, _, _ = _resolve(**tree)
    assert states["l"] == ("resolved", "file", "a/f")
    states, details, _ = _resolve(WINDOWS, root="C:\\srv\\project", **tree)
    assert states["l"] == ("broken", None, "f")
    assert details["l"] == "f does not exist"


def test_windows_names_match_without_regard_to_case_and_posix_names_exactly():
    tree = {"directories": ["Sub"], "files": ["Sub/File.txt"], "links": {"l": "sub\\FILE.txt"}}
    states, _, _ = _resolve(WINDOWS, root="C:\\Work\\Project", **tree)
    assert states["l"] == ("resolved", "file", "Sub/File.txt")
    states, _, _ = _resolve(directories=["Sub"], files=["Sub/File.txt"], links={"l": "sub/File.txt"})
    assert states["l"] == ("broken", None, "sub/File.txt")


def test_loops_are_cycles_or_chains_longer_than_the_platform_allows():
    chain = {f"l{index}": f"l{index + 1}" for index in range(45)}
    chain["l45"] = "file"
    states, details, stats = _resolve(files=["file"], links={"self": "self", "a": "b", "b": "a", **chain})
    assert states["self"] == states["a"] == states["b"] == ("loop", None, None)
    assert details["a"] == "the chain returns to a"
    assert states["l0"] == ("loop", None, None) and details["l0"] == "more than 40 links"
    assert states["l5"] == ("loop", None, None)  # 41 links: one more than Linux follows
    assert states["l6"] == ("resolved", "file", "file")  # exactly 40 links
    # Windows allows 63 reparse points.
    states, _, _ = _resolve(WINDOWS, root="C:\\p", files=["file"], links=chain)
    assert states["l0"] == ("resolved", "file", "file")
    assert stats["symlink_state:loop"] == 3 + 6  # the cycles, and l0-l5


def test_a_link_to_its_own_directory_is_not_a_loop():
    states, _, _ = _resolve(files=["file"], links={"d": ".", "l": "d/d/d/file", "up": "d/.."})
    assert states["l"] == ("resolved", "file", "file")
    assert states["d"] == ("resolved", "directory", ".")


def test_targets_behind_pruned_or_unreadable_entries_are_unknown():
    tree = {
        "directories": [("node_modules", {"pruned": True}), ("secret", {"error": "PermissionError: denied"})],
        "links": {"p": "node_modules/x", "s": "secret/x", "s_dir": "secret", "u": None, "via_u": "u/x"},
    }
    states, details, _ = _resolve(**tree)
    assert states["p"][0] == states["s"][0] == states["via_u"][0] == "unknown"
    assert details["p"] == "it passes through the pruned directory node_modules"
    assert details["s"] == "it passes through the unreadable directory secret"
    assert details["via_u"] == "the link u could not be read"
    assert states["s_dir"] == ("resolved", "directory", "secret")  # the directory itself is known
    assert states["u"] == ("unreadable", None, None)


def test_files_special_entries_and_the_root_are_resolution_targets():
    tree = {
        "directories": ["a"], "files": ["f"], "special": [("pipe", "fifo")],
        "links": {"to_pipe": "pipe", "into_file": "f/x", "root": ".", "a/up": "..", "a/root": "../a/.."},
    }
    states, details, _ = _resolve(**tree)
    assert states["to_pipe"] == ("resolved", "fifo", "pipe")
    assert states["into_file"] == ("broken", None, "f/x") and details["into_file"] == "f is not a directory"
    assert states["root"] == states["a/up"] == states["a/root"] == ("resolved", "directory", ".")


def test_absolute_and_upward_targets_are_inside_only_along_the_roots_own_path():
    tree = {
        "directories": ["a"], "files": ["a/f"],
        "links": {
            "abs": "/srv/project/a/f", "around": "/srv/project/../project/a/f", "up_and_back": "../project/a/f",
            "out": "/etc/passwd", "sibling": "../other/a/f", "above": "../../..",
        },
    }
    states, _, _ = _resolve(**tree)
    assert states["abs"] == states["around"] == states["up_and_back"] == ("resolved", "file", "a/f")
    assert states["out"][0] == states["sibling"][0] == states["above"][0] == "external"


def test_windows_drives_unc_paths_and_rooted_targets():
    tree = {
        "directories": ["a"], "files": ["a/f"],
        "links": {
            "same_drive": "c:\\Work\\Project\\a\\f", "verbatim": "\\\\?\\C:\\Work\\Project\\a\\f",
            "rooted": "\\Work\\Project\\a\\f", "other_drive": "D:\\Work\\Project\\a\\f",
            "unc": "\\\\server\\share\\a\\f", "drive_relative": "C:a\\f",
        },
    }
    states, details, _ = _resolve(WINDOWS, root="C:\\Work\\Project", **tree)
    assert states["same_drive"] == states["verbatim"] == states["rooted"] == ("resolved", "file", "a/f")
    assert states["other_drive"][0] == states["unc"][0] == "external"
    assert states["drive_relative"][0] == "unknown" and details["drive_relative"] == "a drive-relative target"


def test_a_tree_without_a_filesystem_root_has_no_outside():
    # A repository listing (no-download mode): absolute targets and ".." above the top leave it.
    tree = {"directories": ["a"], "files": ["a/f"], "links": {"in": "a/f", "abs": "/etc/passwd", "up": "../x"}}
    states, details, _ = _resolve(root=None, **tree)
    assert states["in"] == ("resolved", "file", "a/f")
    assert states["abs"][0] == states["up"][0] == "external"
    assert details["up"] == "it leaves the repository tree"


def test_links_through_other_links_reuse_their_resolution():
    tree = {"directories": ["real"], "files": ["real/f"], "links": {"alias": "real", "z": "alias/f", "x": "z"}}
    states, _, stats = _resolve(**tree)
    assert states == {
        "alias": ("resolved", "directory", "real"), "z": ("resolved", "file", "real/f"),
        "x": ("resolved", "file", "real/f"),
    }
    assert stats == Counter({"symlink_state:resolved": 3})


def test_root_components_need_an_absolute_root():
    assert root_components("/srv/project", POSIX) == ["srv", "project"]
    assert root_components("C:\\Work\\Project", WINDOWS) == ["C:", "Work", "Project"]
    assert root_components(None, POSIX) is None
    with pytest.raises(ValueError, match="must be absolute"):
        root_components("relative/path", POSIX)
