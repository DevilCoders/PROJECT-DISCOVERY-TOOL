"""Structured code facts that built-in analyzers record for cross-file analysis.

Per-file analyzers see one file at a time, but a symbol index, a call graph or a
component graph needs every file. While the analysis engine runs a file's analyzers,
it collects the facts they emit; the coordinator stores them in the scan's SQLite
inventory in the same transaction as the file's findings, and the cross-file passes in
``code_index`` read them back with bounded memory. Third-party plugins cannot emit
facts: isolated plugins run in another process, where :func:`emit` has no collector.
"""
from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

# Per-file ceilings keep one generated or minified file from flooding the index.
MAX_SYMBOLS_PER_FILE = 5_000
MAX_CALLS_PER_FILE = 20_000
MAX_REFERENCES_PER_FILE = 10_000
MAX_FACTS_PER_FILE = 5_000
# An archive's member records: as many as its readers index (their entry limit).
MAX_ARCHIVE_MEMBERS_PER_FILE = 200_000


@dataclass(slots=True)
class FileFacts:
    """Facts collected for one file; tuples keep worker-to-coordinator pickling small."""

    # (language, kind, name, qualified, line, end_line, exported)
    symbols: list[tuple] = field(default_factory=list)
    # (caller, callee, target, line); target is a resolved qualified name or ""
    calls: list[tuple] = field(default_factory=list)
    # identifiers the file references, deduplicated
    references: set[str] = field(default_factory=set)
    # (kind, name, detail_json) for other domains (imports, components, HDL modules...)
    facts: list[tuple] = field(default_factory=list)
    # The archive inspection of the file: (format, state, states_csv, detail_json)
    archives: list[tuple] = field(default_factory=list)
    # (ordinal, path, type, size, compressed_size, mode, mtime, flags_csv, link_target,
    #  uid, gid, owner, group) per archive member, in archive order
    archive_members: list[tuple] = field(default_factory=list)
    truncated: set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.symbols or self.calls or self.references or self.facts or self.archives
                    or self.archive_members)


_collector = threading.local()


@contextmanager
def collecting_facts() -> Iterator[FileFacts]:
    """Collect the facts analyzers emit on this thread while analyzing one file."""
    previous = getattr(_collector, "facts", None)
    facts = FileFacts()
    _collector.facts = facts
    try:
        yield facts
    finally:
        _collector.facts = previous


def _current() -> FileFacts | None:
    return getattr(_collector, "facts", None)


def current_facts() -> FileFacts | None:
    """The facts being collected on this thread, or None."""
    return _current()


def collecting() -> bool:
    """Whether a collector is active; analyzers skip fact extraction otherwise."""
    return _current() is not None


def emit_symbol(language: str, kind: str, name: str, qualified: str, line: int,
                end_line: int, exported: bool) -> None:
    facts = _current()
    if facts is None:
        return
    if len(facts.symbols) >= MAX_SYMBOLS_PER_FILE:
        facts.truncated.add("symbols")
        return
    facts.symbols.append((language, kind, name[:200], qualified[:400], line, end_line, int(exported)))


def emit_call(caller: str, callee: str, target: str, line: int) -> None:
    facts = _current()
    if facts is None:
        return
    if len(facts.calls) >= MAX_CALLS_PER_FILE:
        facts.truncated.add("calls")
        return
    facts.calls.append((caller[:400], callee[:200], target[:400], line))


def emit_references(names) -> None:
    facts = _current()
    if facts is None:
        return
    for name in names:
        if len(facts.references) >= MAX_REFERENCES_PER_FILE:
            facts.truncated.add("references")
            return
        if 0 < len(name) <= 200:
            facts.references.add(name)


def emit_fact(kind: str, name: str, /, **detail) -> None:
    """Record a domain fact, for example ``emit_fact("component", "App", line=3)``.

    ``kind`` and ``name`` are positional-only, so details may use those keys too.
    """
    facts = _current()
    if facts is None:
        return
    if len(facts.facts) >= MAX_FACTS_PER_FILE:
        facts.truncated.add(kind)
        return
    # ASCII escapes keep lone surrogates from undecodable file names storable in SQLite.
    facts.facts.append((
        kind, name[:400], json.dumps(detail, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    ))


def emit_archive(format: str, state: str, states: list[str], /, **detail) -> None:
    """Record how an archive was inspected: its primary ``state``, every state that applies
    and the counts, coverage and limits in ``detail`` (one record per archive file)."""
    facts = _current()
    if facts is None:
        return
    facts.archives[:] = [(format, state, ",".join(states),
                          json.dumps(detail, ensure_ascii=True, sort_keys=True, separators=(",", ":")))]


def emit_archive_member(ordinal: int, path: str, kind: str, size: int | None, compressed_size: int | None,
                        mode: int | None, mtime: str | None, flags: list[str], link_target: str | None = None,
                        uid: int | None = None, gid: int | None = None, owner: str | None = None,
                        group: str | None = None) -> bool:
    """Record one archive member's metadata; False once the per-file record limit is reached."""
    facts = _current()
    if facts is None:
        return False
    if len(facts.archive_members) >= MAX_ARCHIVE_MEMBERS_PER_FILE:
        facts.truncated.add("archive_members")
        return False
    # Member names come from the archive, as bytes decoded by the reader: keep them storable.
    facts.archive_members.append((
        ordinal, _storable(path)[:4096], kind, size, compressed_size, mode, mtime, ",".join(flags),
        None if link_target is None else _storable(link_target)[:4096], uid, gid,
        None if owner is None else _storable(owner)[:256], None if group is None else _storable(group)[:256],
    ))
    return True


def _storable(text: str) -> str:
    """Text SQLite can store: lone surrogates (undecodable bytes) become backslash escapes."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")
