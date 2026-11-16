"""Classify symbolic-link targets against the inventory snapshot, never the filesystem.

The walk records each link's target text without following it. Once the walk is complete,
every link is resolved here by looking its target up in the inventory itself: a link that
names a missing entry is ``broken``, a chain that repeats itself (or exceeds the platform's
link limit) is a ``loop``, a target that leaves the scanned tree is ``external`` and is not
examined, a target behind a pruned or unreadable directory, an unreadable link, or inside a
directory-only development tree (whose files are not recorded) is ``unknown``, and anything
else is ``resolved`` to the inventoried entry it reaches. Nothing
is opened, stat-ed or followed, so the result has no races: it describes the inventory.

Resolution follows the platform's rules. POSIX resolves ``..`` physically, after each
link in the path has been replaced by its target; Windows resolves a relative target's
``..`` lexically against the link's (already resolved) directory. Windows, and macOS on
case-insensitive volumes, match names without regard to case.
"""
from __future__ import annotations

import ntpath
import os
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from ..models import SymlinkRecord

# Linux stops after 40 links (MAXSYMLINKS); Windows after 63 reparse points.
POSIX_LINK_LIMIT, WINDOWS_LINK_LIMIT = 40, 63


@dataclass(frozen=True, slots=True)
class Resolution:
    state: str
    path: str | None = None
    kind: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class Flavor:
    """Path rules for one inventory: separators, drive letters, ``..`` and case."""

    windows: bool
    fold: Callable[[str], str] | None = None  # case-insensitive name matching

    @property
    def link_limit(self) -> int:
        return WINDOWS_LINK_LIMIT if self.windows else POSIX_LINK_LIMIT


def local_flavor(root: str) -> Flavor:
    """The rules of the filesystem holding ``root``."""
    if os.name == "nt":
        return Flavor(windows=True, fold=str.casefold)
    fold = None
    if sys.platform == "darwin":
        try:  # APFS and HFS+ are case-insensitive unless formatted otherwise
            if os.pathconf(root, "PC_CASE_SENSITIVE") == 0:
                fold = str.casefold
        except (OSError, ValueError):
            fold = str.casefold
    return Flavor(windows=False, fold=fold)


class _Lookup:
    """Inventoried entries by root-relative path: an in-memory index or the SQLite store."""

    def __init__(self, find: Callable[[str, bool], tuple[str, str, dict[str, Any]] | None], fold):
        self._find, self._fold = find, fold
        self._cache: dict[tuple[str, bool], Any] = {}

    def get(self, path: str) -> tuple[str, str, dict[str, Any]] | None:
        """(kind, stored path, record fields) of the entry at ``path``, or None."""
        found = self._cached(path, False)
        if found is None and self._fold is not None:
            found = self._cached(path, True)
        return found

    def _cached(self, path: str, folded: bool):
        key = (path, folded)
        if key not in self._cache:
            if len(self._cache) >= 65536:
                self._cache.clear()
            self._cache[key] = self._find(path, folded)
        return self._cache[key]


def memory_lookup(records: Iterable[tuple[str, Any]], fold) -> _Lookup:
    """A lookup over in-memory records, given as (kind, record) pairs."""
    exact: dict[str, tuple[str, str, dict[str, Any]]] = {}
    folded: dict[str, str] = {}
    for kind, record in records:
        fields = {
            "target": getattr(record, "target", None), "target_state": getattr(record, "target_state", None),
            "pruned": getattr(record, "pruned", False), "error": getattr(record, "error", None),
            "entry_type": getattr(record, "entry_type", None),
            "contents_recorded": getattr(record, "contents_recorded", True),
        }
        exact[record.path] = (kind, record.path, fields)
        if fold is not None:
            folded.setdefault(fold(record.path), record.path)

    def find(path: str, use_fold: bool):
        if not use_fold:
            return exact.get(path)
        stored = folded.get(fold(path))
        return None if stored is None else exact[stored]

    return _Lookup(find, fold)


def store_lookup(store, fold) -> _Lookup:
    """A lookup through the inventory store's indexes."""
    def find(path: str, use_fold: bool):
        return store.lookup(path, folded=use_fold)

    return _Lookup(find, fold)


def _split(text: str, flavor: Flavor) -> list[str]:
    if flavor.windows:
        text = text.replace("\\", "/")
    return [part for part in text.split("/") if part not in ("", ".")]


def _absolute_parts(target: str, flavor: Flavor, root_parts: list[str] | None) -> list[str] | None:
    """The components of an absolute target, a drive (Windows) first; None if not absolute."""
    if flavor.windows:
        if target.startswith(("\\\\?\\UNC\\", "\\??\\UNC\\")):
            target = "\\\\" + target[8:]
        elif target.startswith(("\\\\?\\", "\\??\\")):
            target = target[4:]
        drive, rest = ntpath.splitdrive(target)
        if drive and rest[:1] in ("\\", "/"):
            return [drive.replace("/", "\\").rstrip("\\")] + _split(rest, flavor)
        if not drive and rest[:1] in ("\\", "/") and root_parts:
            return [root_parts[0]] + _split(rest, flavor)  # rooted on the link's own drive
        return None
    if target.startswith("/"):
        return _split(target, flavor)
    return None


def root_components(root: str | None, flavor: Flavor) -> list[str] | None:
    """The scan root's absolute components, or None for an inventory without a filesystem."""
    if root is None:
        return None
    parts = _absolute_parts(str(root), flavor, None)
    if parts is None:
        raise ValueError(f"the scan root must be absolute: {root}")
    return parts


class _Resolver:
    def __init__(self, lookup: _Lookup, flavor: Flavor, root_parts: list[str] | None):
        self.lookup, self.flavor = lookup, flavor
        # Without a filesystem (an API inventory) the tree has no outside: "/" is external.
        self.root_parts = root_parts if root_parts is not None else []
        self.has_root = root_parts is not None
        self.done: dict[str, Resolution] = {}

    def _same(self, left: str, right: str) -> bool:
        fold = str.casefold if self.flavor.windows else self.flavor.fold
        return left == right if fold is None else fold(left) == fold(right)

    def _relative(self, current: list[str]) -> str:
        return "/".join(current[len(self.root_parts):]) or "."

    def resolve(self, path: str, target: str) -> Resolution:
        if path in self.done:
            return self.done[path]
        result = self._resolve(path, target)
        self.done[path] = result
        return result

    def _splice(self, link_parts: list[str], target: str, remaining: list[str]):
        """(current, remaining) after replacing the link at ``link_parts`` by its target, or
        the Resolution when the target cannot be followed within the inventory."""
        parent = link_parts[:-1]
        absolute = _absolute_parts(target, self.flavor, self.root_parts if self.has_root else None)
        if absolute is not None:
            if not self.has_root:  # a repository listing: an absolute path is outside it
                return Resolution("external", detail="an absolute target points outside the repository")
            return [], absolute + remaining
        if self.flavor.windows and target[1:2] == ":":
            return Resolution("unknown", detail="a drive-relative target")
        parts = _split(target, self.flavor)
        if not self.flavor.windows:
            return parent, parts + remaining  # ".." is resolved physically as the walk goes
        combined = list(parent)
        for part in parts:  # Windows collapses ".." lexically against the link's directory
            if part == "..":
                if len(combined) > 1:
                    combined.pop()
            else:
                combined.append(part)
        return [], combined + remaining

    def _resolve(self, path: str, target: str) -> Resolution:
        root_parts = self.root_parts
        link_parts = root_parts + path.split("/")
        spliced = self._splice(link_parts, target, [])
        if isinstance(spliced, Resolution):
            return spliced
        current, remaining = spliced
        seen = {(path, ())}
        hops = 1
        while remaining:
            name = remaining.pop(0)
            if name == "..":
                # Above the root is outside the tree, but on the root's own path; "/.." is "/".
                if current:
                    current.pop()
                elif not self.has_root:
                    return Resolution("external", detail="it leaves the repository tree")
                continue
            if len(current) < len(root_parts):
                # Outside the scanned tree, on the root's ancestry: only the root's own path leads back in.
                if self._same(name, root_parts[len(current)]):
                    current.append(root_parts[len(current)])
                    continue
                return Resolution("external", detail="the target is outside the scanned tree")
            relative = "/".join(current[len(root_parts):] + [name])
            found = self.lookup.get(relative)
            if found is None:
                # Inside a --development-trees directory-only tree, files and links have no records.
                holder = self.lookup.get("/".join(current[len(root_parts):]) or ".")
                if holder is not None and holder[2].get("contents_recorded") is False:
                    return Resolution(
                        "unknown", detail=f"{holder[1]} is a directory-only development tree: its files are not recorded",
                    )
                missing = "/".join([relative, *remaining])
                return Resolution("broken", path=missing, detail=f"{relative} does not exist")
            kind, stored, fields = found
            entry_parts = root_parts + stored.split("/")
            if kind == "symlink":
                if fields.get("target_state") == "unreadable" or not fields.get("target"):
                    return Resolution("unknown", detail=f"the link {stored} could not be read")
                key = (stored, tuple(remaining))
                hops += 1
                if key in seen:
                    return Resolution("loop", detail=f"the chain returns to {stored}")
                if hops > self.flavor.link_limit:
                    return Resolution("loop", detail=f"more than {self.flavor.link_limit} links")
                seen.add(key)
                known = self.done.get(stored)
                if known is not None and known.state == "resolved" and (known.kind == "directory" or not remaining):
                    if not remaining:
                        return known
                    current = root_parts + ([] if known.path == "." else known.path.split("/"))
                    continue
                if known is not None and known.state in {"external", "loop", "unknown"}:
                    return Resolution(known.state, detail=f"through {stored}: {known.detail}")
                spliced = self._splice(entry_parts, fields["target"], remaining)
                if isinstance(spliced, Resolution):
                    return Resolution(spliced.state, detail=f"through {stored}: {spliced.detail}")
                current, remaining = spliced
                continue
            if not remaining:
                return Resolution("resolved", path=stored, kind=fields.get("entry_type") or kind)
            if kind != "directory":
                missing = "/".join([stored, *remaining])
                return Resolution("broken", path=missing, detail=f"{stored} is not a directory")
            if fields.get("pruned"):
                return Resolution("unknown", detail=f"it passes through the pruned directory {stored}")
            if fields.get("error"):
                return Resolution("unknown", detail=f"it passes through the unreadable directory {stored}")
            current = entry_parts
        if len(current) < len(root_parts):
            return Resolution("external", detail="the target is outside the scanned tree")
        return Resolution("resolved", path=self._relative(current), kind="directory")


def apply(record: SymlinkRecord, resolution: Resolution) -> None:
    record.target_state = resolution.state
    record.resolved_path = resolution.path
    record.resolved_type = resolution.kind
    record.target_detail = resolution.detail


def classify_links(
    links: Iterable[SymlinkRecord], lookup: _Lookup, flavor: Flavor, root_parts: list[str] | None,
    stats: Counter[str], save: Callable[[SymlinkRecord], None] | None = None,
) -> None:
    """Resolve every link's target against the inventory and record the outcome.

    ``save`` persists an updated record (the inventory store); in-memory records are
    updated in place. Links whose target could not be read keep ``unreadable``.
    """
    resolver = _Resolver(lookup, flavor, root_parts)
    for record in links:
        if record.target_state != "unreadable" and record.target:
            apply(record, resolver.resolve(record.path, record.target))
            if save is not None:
                save(record)
        stats[f"symlink_state:{record.target_state}"] += 1


def stored_links(store) -> Iterator[SymlinkRecord]:
    for payload in store.iter_records("symlink"):
        yield SymlinkRecord(**payload)


__all__ = [
    "Flavor", "Resolution", "classify_links", "local_flavor", "memory_lookup", "root_components",
    "store_lookup", "stored_links",
]
