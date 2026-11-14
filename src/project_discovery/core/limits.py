"""The per-file content limits analyzers declare, and the accounting of one analyzer call.

Every built-in analyzer declares its limits in a ``limits`` class attribute: the most of a
file it reads, how it reads (``READS``) and its other per-file caps (lines, entries,
findings). The declaration references the module constants the analyzer applies, so each
value is defined once. The engine reports the declarations of the loaded analyzers.

While the engine runs one analyzer call on one file, ``accounting()`` collects what the
call read through the verified readers (``core.source_utils``) and every limit it reached:
a bounded read past its budget is recorded by the reader, a size check by ``over_limit``,
and other caps by the analyzer calling ``limit_reached``. Outside a call, the functions
do nothing.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

# How an analyzer reads a file it supports, as the reports and the budget table describe it.
READS = {
    "whole": "Reads the whole file within its budget; a larger file is not analyzed",
    "stream": "Streams the file up to its budget; the rest is not analyzed",
    "prefix": "Reads a fixed prefix by design",
    "sampled": "Reads bounded samples, tables and members, never the whole file",
    "model": "Uses the shared code model (one bounded read per file and worker)",
    "none": "Reads no file content",
}

# Kinds of limit a call can reach (``limit_reached``): what the limit counts.
LIMIT_KINDS = ("bytes", "chars", "lines", "entries", "findings", "indicators", "pages", "steps", "wall_time")


@dataclass(frozen=True, slots=True)
class AnalyzerLimits:
    """The per-file content limits of one analyzer."""

    file_bytes: int | None  # the most of one file the analyzer reads; None: no read limit of its own
    reads: str  # a key of READS
    caps: dict[str, int | float] = field(default_factory=dict)  # other per-file limits by name
    outcome: str = ""  # what a file past a limit gets

    def __post_init__(self) -> None:
        if self.reads not in READS:
            raise ValueError(f"reads must be one of: {', '.join(READS)}")
        if self.file_bytes is not None and self.file_bytes < 1:
            raise ValueError("file_bytes must be positive or None")

    def describe(self) -> dict:
        return {"file_bytes": self.file_bytes, "reads": self.reads, "caps": dict(self.caps)}


class AnalyzerBudgetExceeded(BaseException):
    """Raised inside an analyzer call that ran past its budget; not an Exception on purpose.

    The engine's watchdog raises it for the time and memory budgets; the verified readers
    raise it with ``stop = ("read", limit bytes, bytes read)`` for the read budget.
    """

    def __init__(self, stop: tuple[str, int, int] | None = None) -> None:
        super().__init__(stop)
        self.stop = stop


class CallAccount:
    """What one analyzer call read and which limits it reached."""

    __slots__ = ("bytes_read", "limits", "read_limit")

    def __init__(self, read_limit: int | None = None) -> None:
        self.bytes_read = 0
        self.read_limit = read_limit  # the call's read budget in bytes, or None
        self.limits: list[tuple[str, float, float | None]] = []  # (kind, limit, used or None)


_local = threading.local()
MAX_LIMITS_PER_CALL = 32  # a call that reaches more keeps the first ones


def current_account() -> CallAccount | None:
    return getattr(_local, "account", None)


@contextmanager
def accounting(read_limit: int | None = None) -> Iterator[CallAccount]:
    """Account the reads and limits of one analyzer call on this thread."""
    previous = getattr(_local, "account", None)
    account = _local.account = CallAccount(read_limit)
    try:
        yield account
    finally:
        _local.account = previous


def count_read(size: int) -> None:
    account = getattr(_local, "account", None)
    if account is not None and size > 0:
        account.bytes_read += size
        if account.read_limit is not None and account.bytes_read > account.read_limit:
            limit, account.read_limit = account.read_limit, None  # stop once
            raise AnalyzerBudgetExceeded(("read", limit, account.bytes_read))


def limit_reached(kind: str, limit: float, used: float | None = None) -> None:
    """Record that the running analyzer call reached a limit (``used``, when known, past it)."""
    account = getattr(_local, "account", None)
    if account is not None and len(account.limits) < MAX_LIMITS_PER_CALL:
        account.limits.append((kind, float(limit), None if used is None else float(used)))


def over_limit(size: int, limit: int, kind: str = "bytes") -> bool:
    """Whether ``size`` exceeds ``limit``; records the limit when it does."""
    if size > limit:
        limit_reached(kind, limit, size)
        return True
    return False


# ---------------------------------------------------------------------------------------
# Content limits a scan configures (``pdt scan --archive-limit``), by analyzer name. The
# engine sets them with its budget policy in every process that runs analyzers; an analyzer
# reads its own when a call starts and keeps its module defaults for the rest.
_OVERRIDES: dict[str, dict[str, float]] = {}


def configure_limits(overrides: Mapping[str, Mapping[str, float]] | None) -> None:
    """Replace the configured content-limit overrides ({analyzer name: {limit: value}})."""
    _OVERRIDES.clear()
    for name, values in (overrides or {}).items():
        if values:
            _OVERRIDES[name] = dict(values)


def limit_overrides(analyzer: str) -> Mapping[str, float]:
    """The content-limit values the scan configured for one analyzer (empty: its defaults)."""
    return _OVERRIDES.get(analyzer, {})
