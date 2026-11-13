"""Per-analyzer time and memory budgets for each file, enforced by the engine.

Every built-in and in-process plugin analyzer call on a file runs under a budget: a
wall-clock limit and a limit on how much the process's resident memory may grow during the
call. A watchdog thread checks the running calls every 50 ms. When one exceeds its budget,
the watchdog raises ``AnalyzerBudgetExceeded`` in the analyzing thread at its next Python
bytecode. It is a BaseException, so an analyzer's ``except Exception`` cannot swallow it: the
call is abandoned, its findings and code facts are discarded and an UNKNOWN finding names
the budget that stopped it. A single long C call (one regular-expression search over an
already bounded buffer) finishes before the stop takes effect.

Memory is the growth of the resident set since the call started, as the watchdog samples
it: a spike shorter than a sample, or memory released before one, is not seen. The thread
executor's analyzers share one process, so there the growth includes concurrent calls; the
process executor (the default for large scans) runs one call per worker. Where the resident
set cannot be read, only the time budget applies (``memory_enforced`` is false). Isolated
plugins keep their own ``--plugin-timeout`` and ``--plugin-memory-mb`` limits.

Budgets are set per analyzer and file by ``--analyzer-timeout`` and ``--analyzer-memory-mb``,
and overridden per analyzer domain with ``--domain-budget``.
"""
from __future__ import annotations

import ctypes
import math
import os
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_MEMORY_MB = 2048
SAMPLE_SECONDS = 0.05
_MIB = 1024 * 1024


class AnalyzerBudgetExceeded(BaseException):
    """Raised inside an analyzer call that ran past its budget; not an Exception on purpose."""


@dataclass(frozen=True, slots=True)
class AnalyzerBudget:
    """Limits for one analyzer call on one file; None means no limit."""

    timeout_seconds: float | None = DEFAULT_TIMEOUT_SECONDS
    memory_mb: int | None = DEFAULT_MEMORY_MB

    @property
    def limited(self) -> bool:
        return bool(self.timeout_seconds) or bool(self.memory_mb and memory_supported())


@dataclass(frozen=True, slots=True)
class BudgetStop:
    kind: str  # "time" or "memory"
    limit: float  # seconds or MiB
    used: float  # seconds or MiB when the watchdog stopped the call


@dataclass(slots=True)
class BudgetRun:
    """How one analyzer call went: its result, its stop, and what it used."""

    result: Any
    stop: BudgetStop | None
    seconds: float
    peak_mb: float | None  # the largest sampled resident-memory growth, when sampled


def _most_permissive(values: list[float | None]) -> float | None:
    return None if any(not value for value in values) else max(values)  # type: ignore[type-var]


@dataclass(slots=True)
class BudgetPolicy:
    """The default budget and per-domain overrides ({domain: {"timeout_seconds": ..}})."""

    timeout_seconds: float | None = DEFAULT_TIMEOUT_SECONDS
    memory_mb: int | None = DEFAULT_MEMORY_MB
    overrides: dict[str, dict[str, float | None]] = field(default_factory=dict)
    _cache: dict[tuple[str, tuple[str, ...]], AnalyzerBudget] = field(default_factory=dict, repr=False)

    def for_analyzer(self, analyzer) -> AnalyzerBudget:
        """The analyzer's budget: an override of one of its domains, or the default.

        When several of its domains override the same limit, the most permissive applies.
        """
        domains = tuple(getattr(analyzer, "domains", ()) or ())
        key = (getattr(analyzer, "name", ""), domains)
        budget = self._cache.get(key)
        if budget is None:
            timeout, memory = self.timeout_seconds, self.memory_mb
            timeouts = [self.overrides[d]["timeout_seconds"] for d in domains
                        if "timeout_seconds" in self.overrides.get(d, {})]
            memories = [self.overrides[d]["memory_mb"] for d in domains if "memory_mb" in self.overrides.get(d, {})]
            if timeouts:
                timeout = _most_permissive(timeouts)
            if memories:
                memory = _most_permissive(memories)
            budget = self._cache[key] = AnalyzerBudget(timeout or None, int(memory) if memory else None)
        return budget

    def describe(self) -> dict[str, Any]:
        """The configured budgets, for metrics.analysis_budgets."""
        return {
            "timeout_seconds": self.timeout_seconds or None,
            "memory_mb": self.memory_mb or None,
            "memory_enforced": bool(self.memory_mb) and memory_supported(),
            "domain_overrides": {domain: dict(values) for domain, values in sorted(self.overrides.items())},
        }


def parse_domain_budgets(values: Iterable[str], known_domains: Iterable[str]) -> dict[str, dict[str, float | None]]:
    """--domain-budget DOMAIN:timeout=SECONDS,memory=MB values (0 means no limit)."""
    known = set(known_domains)
    overrides: dict[str, dict[str, float | None]] = {}
    for raw in values or ():
        domain, separator, settings = str(raw).partition(":")
        domain = domain.strip()
        if not separator or not settings.strip():
            raise ValueError(f"--domain-budget {raw}: expected DOMAIN:timeout=SECONDS,memory=MB")
        if domain not in known:
            import difflib

            close = difflib.get_close_matches(domain, sorted(known), n=3, cutoff=0.5)
            hint = f"; did you mean {', '.join(close)}?" if close else "; pdt capabilities --json lists each analyzer's domains"
            raise ValueError(f"--domain-budget {raw}: unknown analyzer domain {domain!r}{hint}")
        entry = overrides.setdefault(domain, {})
        for setting in settings.split(","):
            name, equals, value = setting.partition("=")
            name = name.strip().lower()
            if not equals or name not in {"timeout", "memory"}:
                raise ValueError(f"--domain-budget {raw}: settings are timeout=SECONDS and memory=MB")
            try:
                number = float(value)
            except ValueError:
                raise ValueError(f"--domain-budget {raw}: {name} must be a number") from None
            # NaN would never trip a deadline, and infinity is spelled 0 here.
            if not math.isfinite(number) or number < 0 or (name == "memory" and number != int(number)):
                raise ValueError(f"--domain-budget {raw}: {name} must be 0 (no limit) or a positive "
                                 f"{'integer' if name == 'memory' else 'number'}")
            if name == "timeout":
                entry["timeout_seconds"] = number or None
            else:
                entry["memory_mb"] = int(number) or None
    return overrides


# ---------------------------------------------------------------------------------------
# Resident memory

def _rss_reader() -> Callable[[], int | None] | None:
    """A function returning this process's resident set in bytes, or None where unsupported."""
    try:
        if sys.platform.startswith("linux"):
            page = os.sysconf("SC_PAGE_SIZE")
            # /proc/self resolves when opened: a forked worker reopens it for its own pid.
            opened: list[tuple[int, int]] = []

            def read_linux() -> int | None:
                pid = os.getpid()
                if not opened or opened[0][0] != pid:
                    opened[:] = [(pid, os.open("/proc/self/statm", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)))]
                return int(os.pread(opened[0][1], 128, 0).split()[1]) * page

            reader = read_linux
        elif os.name == "nt":
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel32.K32GetProcessMemoryInfo
            query.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
            query.restype = wintypes.BOOL
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            process = kernel32.GetCurrentProcess()

            def read_windows() -> int | None:
                counters = Counters()
                counters.cb = ctypes.sizeof(Counters)
                return int(counters.WorkingSetSize) if query(process, ctypes.byref(counters), counters.cb) else None

            reader = read_windows
        elif sys.platform == "darwin":
            class TimeValue(ctypes.Structure):
                _fields_ = [("seconds", ctypes.c_int), ("microseconds", ctypes.c_int)]

            class TaskInfo(ctypes.Structure):  # mach_task_basic_info
                _fields_ = [
                    ("virtual_size", ctypes.c_uint64), ("resident_size", ctypes.c_uint64),
                    ("resident_size_max", ctypes.c_uint64), ("user_time", TimeValue),
                    ("system_time", TimeValue), ("policy", ctypes.c_int), ("suspend_count", ctypes.c_int),
                ]

            system = ctypes.CDLL("/usr/lib/libSystem.dylib")
            task = ctypes.c_uint.in_dll(system, "mach_task_self_").value
            system.task_info.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint))
            system.task_info.restype = ctypes.c_int

            def read_macos() -> int | None:
                info = TaskInfo()
                count = ctypes.c_uint(ctypes.sizeof(TaskInfo) // 4)
                if system.task_info(task, 20, ctypes.byref(info), ctypes.byref(count)):  # MACH_TASK_BASIC_INFO
                    return None
                return int(info.resident_size)

            reader = read_macos
        else:
            return None
        sample = reader()
    except Exception:
        return None
    # A reader that returns nonsense is not used: no memory budget beats a wrong one.
    return reader if sample is not None and _MIB <= sample < (1 << 44) else None


_RSS = _rss_reader()


def memory_supported() -> bool:
    """Whether this platform's resident set can be read, so memory budgets apply."""
    return _RSS is not None


def resident_bytes() -> int | None:
    if _RSS is None:
        return None
    try:
        return _RSS()
    except Exception:
        return None


# ---------------------------------------------------------------------------------------
# The watchdog

_SET_ASYNC_EXC = ctypes.pythonapi.PyThreadState_SetAsyncExc
_SET_ASYNC_EXC.argtypes = (ctypes.c_ulong, ctypes.py_object)
_SET_ASYNC_EXC.restype = ctypes.c_int


def _raise_in(thread: int, exception: type[BaseException] | None) -> None:
    # A NULL exception clears one that is pending and not yet delivered.
    _SET_ASYNC_EXC(ctypes.c_ulong(thread), ctypes.py_object() if exception is None else ctypes.py_object(exception))


class _Call:
    __slots__ = ("thread", "budget", "started", "deadline", "memory_limit", "baseline", "peak", "samples", "running",
                 "stop")

    def __init__(self, budget: AnalyzerBudget, baseline: int | None) -> None:
        self.thread = threading.get_ident()
        self.budget = budget
        self.started = time.monotonic()
        self.deadline = self.started + budget.timeout_seconds if budget.timeout_seconds else None
        self.memory_limit = budget.memory_mb * _MIB if budget.memory_mb and baseline is not None else None
        self.baseline = baseline
        self.peak = 0
        self.samples = 0  # resident-memory samples taken while the call ran
        self.running = True
        self.stop: BudgetStop | None = None


class _Watchdog:
    def __init__(self) -> None:
        self._reset()
        if hasattr(os, "register_at_fork"):
            # A child must not inherit a lock the watchdog held, nor calls of the parent.
            os.register_at_fork(after_in_child=self._reset)

    def _reset(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[int, _Call] = {}
        self._thread: threading.Thread | None = None
        self._sample: tuple[float, int | None] = (0.0, None)

    def _rss(self) -> int | None:
        stamp, value = self._sample
        now = time.monotonic()
        if now - stamp > 2 * SAMPLE_SECONDS:
            value = resident_bytes()
            self._sample = (now, value)
        return value

    def arm(self, budget: AnalyzerBudget) -> _Call:
        call = _Call(budget, self._rss() if budget.memory_mb else None)
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._watch, name="pdt-analyzer-budgets", daemon=True)
                self._thread.start()
            self._calls[id(call)] = call
        return call

    def disarm(self, call: _Call) -> BudgetStop | None:
        """End a call; returns its stop if the watchdog fired, and clears an undelivered one."""
        with self._lock:
            if call.running:
                call.running = False
                self._calls.pop(id(call), None)
                if call.stop is not None:
                    _raise_in(call.thread, None)
            return call.stop

    def _watch(self) -> None:
        while True:
            time.sleep(SAMPLE_SECONDS)
            with self._lock:
                calls = list(self._calls.values())
            if not calls:
                continue
            rss = None
            if any(call.memory_limit for call in calls):
                rss = resident_bytes()
                self._sample = (time.monotonic(), rss)
            now = time.monotonic()
            with self._lock:
                for call in calls:
                    if not call.running or call.stop is not None:
                        continue
                    if call.memory_limit is not None and rss is not None:
                        growth = rss - call.baseline
                        call.peak = max(call.peak, growth)
                        call.samples += 1
                        if growth > call.memory_limit:
                            call.stop = BudgetStop("memory", float(call.budget.memory_mb), growth / _MIB)
                    if call.stop is None and call.deadline is not None and now >= call.deadline:
                        call.stop = BudgetStop("time", float(call.budget.timeout_seconds), now - call.started)
                    if call.stop is not None:
                        _raise_in(call.thread, AnalyzerBudgetExceeded)


_WATCHDOG = _Watchdog()


def _peak(call: _Call) -> float | None:
    """The sampled peak growth in MiB; None when no sample fell inside the call."""
    return call.peak / _MIB if call.memory_limit and call.samples else None


def run_with_budget(budget: AnalyzerBudget | None, function: Callable[[], Any]) -> BudgetRun:
    """Run one analyzer call under its budget (no budget: just run it and time it)."""
    started = time.perf_counter()
    if budget is None or not budget.limited:
        result = function()
        return BudgetRun(result, None, time.perf_counter() - started, None)
    call = _WATCHDOG.arm(budget)
    try:
        try:
            result = function()
        finally:
            stop = _WATCHDOG.disarm(call)
    except AnalyzerBudgetExceeded:
        # Delivered after the call or inside disarm(): end the call (idempotent) first.
        stop = _WATCHDOG.disarm(call) or call.stop
        if stop is None:
            raise
        return BudgetRun(None, stop, time.perf_counter() - started, _peak(call))
    peak = _peak(call)
    # Finished, but past its budget: the watchdog stopped it at the same moment.
    return BudgetRun(None if stop else result, stop, time.perf_counter() - started, peak)


_policy = BudgetPolicy()


def set_policy(policy: BudgetPolicy | None) -> None:
    """The budget policy analyzer calls in this process run under (workers set it at start)."""
    global _policy
    _policy = policy or BudgetPolicy()


def current_policy() -> BudgetPolicy:
    return _policy
