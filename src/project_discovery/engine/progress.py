"""Scan progress by phase: what the live display shows and metrics.performance.phases records.

A scan has six phases. The inventory walks the tree. Hashing, the analyzer domains and
archive inspection share one pass over the files (a worker reads each file once, hashes it
and runs the analyzers on it), so they run at the same time. Correlation (online
advisories, the Python dependency graph, the architecture layout and the code index) and
reporting follow. The coordinator counts what each phase has done as results arrive; the
live display reads the counts from its own refresh thread, so updates and reads hold a lock.
"""
from __future__ import annotations

import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from typing import Any

PHASES = ("inventory", "hashing", "analysis", "archives", "correlation", "reporting")
LABELS = {
    "inventory": "Inventory",
    "hashing": "Hashing",
    "analysis": "Analyzer domains",
    "archives": "Archive inspection",
    "correlation": "Correlation",
    "reporting": "Reporting",
}
UNITS = {
    "inventory": "entries", "hashing": "files", "analysis": "files",
    "archives": "archives", "correlation": "steps", "reporting": "reports",
}
OTHER_DOMAIN = "other"  # an analyzer (a plugin) that declares no domain


class _Phase:
    __slots__ = ("state", "started", "finished", "done", "total", "bytes", "reused", "work_seconds",
                 "note", "calls", "seconds", "step", "step_started", "extra")

    def __init__(self) -> None:
        self.state = "waiting"  # waiting, running, done or skipped
        self.started: float | None = None
        self.finished: float | None = None
        self.done = 0
        self.total: int | None = None
        self.bytes = 0
        self.reused = 0  # hashing: digests the fingerprint cache supplied
        self.work_seconds = 0.0  # time the workers spent on it, summed over the workers
        self.note: str | None = None  # why a phase was skipped
        self.calls: Counter = Counter()  # analysis: analyzer calls per domain
        self.seconds: Counter = Counter()  # analysis: per domain; correlation and reporting: per step
        self.step: str | None = None
        self.step_started: float | None = None
        self.extra: dict[str, Any] = {}


class ScanProgress:
    """The six phases of one scan and what each has done."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._phases = {key: _Phase() for key in PHASES}
        self._walk: Mapping[str, int] | None = None
        self._domains: dict[str, tuple[str, ...]] = {}

    # -- transitions -------------------------------------------------------------------
    def begin(self, key: str, *, total: int | None = None) -> None:
        with self._lock:
            phase = self._phases[key]
            phase.state, phase.started, phase.total = "running", self._clock(), total

    def finish(self, key: str, *, total: int | None = None) -> None:
        """End a running phase; ``total`` replaces one that was not known when it began."""
        with self._lock:
            phase = self._phases[key]
            if total is not None:
                phase.total = total
            if phase.state == "running":
                now = self._clock()
                self._close_step(phase, now)
                phase.state, phase.finished = "done", now

    def annotate(self, key: str, **values: Any) -> None:
        """Values a phase reports as they are (the formats being written)."""
        with self._lock:
            self._phases[key].extra.update(values)

    def skip(self, key: str, note: str) -> None:
        with self._lock:
            phase = self._phases[key]
            phase.state, phase.note = "skipped", note

    def step(self, key: str, name: str | None) -> None:
        """Start a named step of a phase (correlation, reporting), ending the one before."""
        with self._lock:
            phase = self._phases[key]
            now = self._clock()
            self._close_step(phase, now)
            if name is not None:
                phase.step, phase.step_started = name, now

    @staticmethod
    def _close_step(phase: _Phase, now: float) -> None:
        if phase.step is not None and phase.step_started is not None:
            phase.seconds[phase.step] += now - phase.step_started
            phase.done += 1
        phase.step = phase.step_started = None

    # -- counters ----------------------------------------------------------------------
    def watch_walk(self, counters: Mapping[str, int] | None) -> None:
        """Show the inventory walk's own counters (entry_count, total_bytes) while it runs."""
        with self._lock:
            self._walk = counters

    def walked(self, entries: int, files: int, total_bytes: int) -> None:
        """The inventory's final counts."""
        with self._lock:
            phase = self._phases["inventory"]
            phase.done, phase.bytes, phase.extra["files"] = entries, total_bytes, files
            self._walk = None

    def advance(self, key: str, done: int = 1, *, size: int = 0, reused: int = 0,
                work_seconds: float = 0.0) -> None:
        with self._lock:
            phase = self._phases[key]
            phase.done += done
            phase.bytes += size
            phase.reused += reused
            phase.work_seconds += work_seconds

    def set_analyzer_domains(self, analyzers: Iterable[Any]) -> None:
        """The domains of each analyzer, by name, to count its calls per domain."""
        with self._lock:
            self._domains = {
                analyzer.name: tuple(getattr(analyzer, "domains", ()) or ()) or (OTHER_DOMAIN,)
                for analyzer in analyzers
            }

    def analyzer_calls(self, usage: Iterable[tuple]) -> None:
        """Count (analyzer, seconds, ...) calls for each of the analyzer's domains."""
        with self._lock:
            phase = self._phases["analysis"]
            for name, seconds, *_ in usage:
                for domain in self._domains.get(name, (OTHER_DOMAIN,)):
                    phase.calls[domain] += 1
                    phase.seconds[domain] += seconds

    # -- reading -----------------------------------------------------------------------
    def snapshot(self) -> list[dict[str, Any]]:
        """Every phase as it stands, with elapsed times: what the live display draws."""
        now = self._clock()
        with self._lock:
            items = [self._describe(key, phase, now) for key, phase in self._phases.items()]
            walk = self._walk
            if walk is not None and self._phases["inventory"].state == "running":
                items[0]["done"] = int(walk.get("entry_count", 0))
                items[0]["bytes"] = int(walk.get("total_bytes", 0))
            for item, phase in zip(items, self._phases.values(), strict=True):
                if phase.state == "running" and phase.started is not None:
                    item["elapsed"] = now - phase.started
                    item["current_step"] = phase.step
        return items

    def describe(self) -> list[dict[str, Any]]:
        """metrics.performance.phases: a phase's seconds are its wall time once it is done."""
        now = self._clock()
        with self._lock:
            return [self._describe(key, phase, now) for key, phase in self._phases.items()]

    def _describe(self, key: str, phase: _Phase, now: float) -> dict[str, Any]:
        seconds = None
        if phase.state == "done" and phase.started is not None and phase.finished is not None:
            seconds = round(phase.finished - phase.started, 3)
        item: dict[str, Any] = {
            "phase": key, "label": LABELS[key], "state": phase.state, "seconds": seconds,
            "done": phase.done, "total": phase.total, "unit": UNITS[key],
        }
        if key in {"inventory", "hashing"}:
            item["bytes"] = phase.bytes
        if key == "hashing":
            item["reused"] = phase.reused
        if key in {"hashing", "archives"}:
            item["work_seconds"] = round(phase.work_seconds, 3)
        if key == "analysis":
            item["domains"] = {
                domain: {"calls": phase.calls[domain], "seconds": round(phase.seconds[domain], 3)}
                for domain in sorted(phase.calls, key=lambda name: (-phase.calls[name], name))
            }
        if key in {"correlation", "reporting"}:
            item["steps"] = {name: round(value, 3) for name, value in phase.seconds.items()}
        if phase.note:
            item["note"] = phase.note
        item.update(phase.extra)
        return item
