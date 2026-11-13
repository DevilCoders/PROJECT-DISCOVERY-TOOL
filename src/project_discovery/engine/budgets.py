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

``--max-memory-mb`` budgets the whole scan instead (``ScanMemoryBudget``): the coordinator
holds back new work while the resident memory of its own process and its worker processes
is over the budget, and no call's own memory budget exceeds it.
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
SCAN_SAMPLE_SECONDS = 0.05  # how stale the scan's memory may be when work is queued
SCAN_CALIBRATION_SECONDS = 10.0  # Linux: how often shared pages are measured (at least)
SCAN_MIN_MEMORY_MB = 256  # below this, the coordinator alone would be over the budget
_MIB = 1024 * 1024


from ..core.limits import AnalyzerBudgetExceeded  # noqa: E402  (the readers raise it too)


@dataclass(frozen=True, slots=True)
class AnalyzerBudget:
    """Limits for one analyzer call on one file; None means no limit."""

    timeout_seconds: float | None = DEFAULT_TIMEOUT_SECONDS
    memory_mb: int | None = DEFAULT_MEMORY_MB
    read_mb: int | None = None  # bytes read through the verified readers, in MiB
    cpu_seconds: float | None = None  # CPU time of the analyzing thread

    @property
    def limited(self) -> bool:
        return (bool(self.timeout_seconds) or bool(self.memory_mb and memory_supported()) or bool(self.read_mb)
                or bool(self.cpu_seconds and cpu_supported()))


@dataclass(frozen=True, slots=True)
class BudgetStop:
    kind: str  # "time", "memory", "read" or "cpu"
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
    read_mb: int | None = None
    cpu_seconds: float | None = None
    # --max-memory-mb: a call growing past the whole scan's budget would take the scan over
    # it, so it caps every call's memory budget (also an override's, and "no limit").
    scan_memory_mb: int | None = None
    _cache: dict[tuple[str, tuple[str, ...]], AnalyzerBudget] = field(default_factory=dict, repr=False)

    def _capped(self, memory: float | None) -> float | None:
        if not self.scan_memory_mb:
            return memory
        return min(memory, self.scan_memory_mb) if memory else self.scan_memory_mb

    def for_analyzer(self, analyzer) -> AnalyzerBudget:
        """The analyzer's budget: an override of one of its domains, or the default.

        When several of its domains override the same limit, the most permissive applies.
        """
        domains = tuple(getattr(analyzer, "domains", ()) or ())
        key = (getattr(analyzer, "name", ""), domains)
        budget = self._cache.get(key)
        if budget is None:
            timeout, memory, read = self.timeout_seconds, self.memory_mb, self.read_mb
            timeouts = [self.overrides[d]["timeout_seconds"] for d in domains
                        if "timeout_seconds" in self.overrides.get(d, {})]
            memories = [self.overrides[d]["memory_mb"] for d in domains if "memory_mb" in self.overrides.get(d, {})]
            reads = [self.overrides[d]["read_mb"] for d in domains if "read_mb" in self.overrides.get(d, {})]
            cpus = [self.overrides[d]["cpu_seconds"] for d in domains if "cpu_seconds" in self.overrides.get(d, {})]
            cpu = _most_permissive(cpus) if cpus else self.cpu_seconds
            if timeouts:
                timeout = _most_permissive(timeouts)
            if memories:
                memory = _most_permissive(memories)
            if reads:
                read = _most_permissive(reads)
            memory = self._capped(memory)
            budget = self._cache[key] = AnalyzerBudget(timeout or None, int(memory) if memory else None,
                                                       int(read) if read else None, cpu or None)
        return budget

    def describe(self) -> dict[str, Any]:
        """The budgets in force, for metrics.analysis_budgets (memory capped by the scan's)."""
        memory = self._capped(self.memory_mb)
        return {
            "timeout_seconds": self.timeout_seconds or None,
            "memory_mb": int(memory) if memory else None,
            "memory_enforced": bool(memory) and memory_supported(),
            "read_mb": self.read_mb or None,
            "cpu_seconds": self.cpu_seconds or None,
            "cpu_enforced": bool(self.cpu_seconds) and cpu_supported(),
            "scan_memory_mb": self.scan_memory_mb or None,
            "domain_overrides": {
                domain: {name: (int(self._capped(value)) if name == "memory_mb" and self._capped(value) else value)
                         for name, value in values.items()}
                for domain, values in sorted(self.overrides.items())
            },
        }


def parse_domain_budgets(values: Iterable[str], known_domains: Iterable[str]) -> dict[str, dict[str, float | None]]:
    """--domain-budget DOMAIN:timeout=SECONDS,memory=MB,read=MB,cpu=SECONDS values (0: no limit)."""
    known = set(known_domains)
    overrides: dict[str, dict[str, float | None]] = {}
    for raw in values or ():
        domain, separator, settings = str(raw).partition(":")
        domain = domain.strip()
        if not separator or not settings.strip():
            raise ValueError(f"--domain-budget {raw}: expected DOMAIN:timeout=SECONDS,memory=MB,read=MB,cpu=SECONDS")
        if domain not in known:
            import difflib

            close = difflib.get_close_matches(domain, sorted(known), n=3, cutoff=0.5)
            hint = f"; did you mean {', '.join(close)}?" if close else "; pdt capabilities --json lists each analyzer's domains"
            raise ValueError(f"--domain-budget {raw}: unknown analyzer domain {domain!r}{hint}")
        entry = overrides.setdefault(domain, {})
        for setting in settings.split(","):
            name, equals, value = setting.partition("=")
            name = name.strip().lower()
            if not equals or name not in {"timeout", "memory", "read", "cpu"}:
                raise ValueError(f"--domain-budget {raw}: settings are timeout=SECONDS, memory=MB, read=MB "
                                 "and cpu=SECONDS")
            try:
                number = float(value)
            except ValueError:
                raise ValueError(f"--domain-budget {raw}: {name} must be a number") from None
            # NaN would never trip a deadline, and infinity is spelled 0 here.
            whole = name in {"memory", "read"}
            if not math.isfinite(number) or number < 0 or (whole and number != int(number)):
                raise ValueError(f"--domain-budget {raw}: {name} must be 0 (no limit) or a positive "
                                 f"{'integer' if whole else 'number'}")
            if name == "timeout":
                entry["timeout_seconds"] = number or None
            elif name == "cpu":
                entry["cpu_seconds"] = number or None
            elif name == "memory":
                entry["memory_mb"] = int(number) or None
            else:
                entry["read_mb"] = int(number) or None
    return overrides


# ---------------------------------------------------------------------------------------
# Resident memory

def _windows_working_set():
    """(working_set(process handle) -> bytes or None, a kernel32 of its own): GetProcessMemoryInfo."""
    from ctypes import wintypes

    class Counters(ctypes.Structure):  # PROCESS_MEMORY_COUNTERS
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

    def working_set(handle) -> int | None:
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        return int(counters.WorkingSetSize) if query(handle, ctypes.byref(counters), counters.cb) else None

    return working_set, kernel32


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

            working_set, kernel32 = _windows_working_set()
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            process = kernel32.GetCurrentProcess()

            def read_windows() -> int | None:
                return working_set(process)

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


def _process_rss_reader() -> Callable[[int], int | None] | None:
    """A function returning another process's resident set in bytes (None once it has exited).

    It reads the scan's worker processes: /proc/PID/statm on Linux, GetProcessMemoryInfo on
    Windows, proc_pidinfo on macOS. A reader whose reading of this process disagrees with
    the current-process reader by more than a factor of four is not used.
    """
    try:
        if sys.platform.startswith("linux"):
            page = os.sysconf("SC_PAGE_SIZE")

            def read_linux(pid: int) -> int | None:
                try:
                    with open(f"/proc/{int(pid)}/statm", "rb", buffering=0) as handle:
                        return int(handle.read(128).split()[1]) * page
                except (OSError, ValueError, IndexError):
                    return None

            reader = read_linux
        elif os.name == "nt":
            from ctypes import wintypes

            working_set, kernel32 = _windows_working_set()
            open_process = kernel32.OpenProcess
            open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            open_process.restype = wintypes.HANDLE
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)

            def read_windows(pid: int) -> int | None:
                # PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ, as the query requires.
                handle = open_process(0x1000 | 0x0010, False, int(pid))
                if not handle:
                    return None
                try:
                    return working_set(handle)
                finally:
                    close_handle(handle)

            reader = read_windows
        elif sys.platform == "darwin":
            class TaskInfo(ctypes.Structure):  # struct proc_taskinfo
                _fields_ = [
                    ("virtual_size", ctypes.c_uint64), ("resident_size", ctypes.c_uint64),
                    ("total_user", ctypes.c_uint64), ("total_system", ctypes.c_uint64),
                    ("threads_user", ctypes.c_uint64), ("threads_system", ctypes.c_uint64),
                    *((name, ctypes.c_int32) for name in (
                        "policy", "faults", "pageins", "cow_faults", "messages_sent", "messages_received",
                        "syscalls_mach", "syscalls_unix", "csw", "threadnum", "numrunning", "priority",
                    )),
                ]

            system = ctypes.CDLL("/usr/lib/libSystem.dylib")
            pidinfo = system.proc_pidinfo
            pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
            pidinfo.restype = ctypes.c_int

            def read_macos(pid: int) -> int | None:
                info = TaskInfo()
                size = ctypes.sizeof(TaskInfo)
                if pidinfo(int(pid), 4, 0, ctypes.byref(info), size) != size:  # PROC_PIDTASKINFO
                    return None
                return int(info.resident_size)

            reader = read_macos
        else:
            return None
        sample = reader(os.getpid())
        own = _RSS() if _RSS is not None else None
    except Exception:
        return None
    if sample is None or not _MIB <= sample < (1 << 44):
        return None
    return reader if own is None or own / 4 <= sample <= own * 4 else None


_PROCESS_RSS = _process_rss_reader()


def _proportional_reader() -> Callable[[int], int | None] | None:
    """Linux: a process's proportional set size, its shared pages split among their sharers.

    Reading it walks the process's page tables (/proc/PID/smaps_rollup, Linux 4.14 and
    later): about 13 ms per GiB resident, so the scan budget calibrates with it rarely.
    """
    if not sys.platform.startswith("linux"):
        return None

    def read(pid: int) -> int | None:
        try:
            with open(f"/proc/{int(pid)}/smaps_rollup", "rb") as handle:
                for line in handle:
                    if line.startswith(b"Pss:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
        return None

    return read if read(os.getpid()) else None


_PSS = _proportional_reader()


def _thread_cpu_reader():
    """(open, read, close) for one thread's CPU time in seconds, or None where unsupported.

    open() runs in the analyzing thread and returns a clock the watchdog thread can read:
    the thread's CPU clock id (POSIX), or a thread handle (Windows, GetThreadTimes).
    """
    try:
        if hasattr(time, "pthread_getcpuclockid") and hasattr(time, "clock_gettime"):
            def open_posix():
                return time.pthread_getcpuclockid(threading.get_ident())

            reader = (open_posix, time.clock_gettime, lambda clock: None)
        elif os.name == "nt":
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_thread = kernel32.OpenThread
            open_thread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            open_thread.restype = wintypes.HANDLE
            thread_times = kernel32.GetThreadTimes
            thread_times.argtypes = (wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4))
            thread_times.restype = wintypes.BOOL
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)

            def open_windows():
                handle = open_thread(0x0800, False, threading.get_native_id())  # QUERY_LIMITED_INFORMATION
                if not handle:
                    raise OSError("OpenThread failed")
                return handle

            def read_windows(handle) -> float:
                times = [wintypes.FILETIME() for _ in range(4)]
                if not thread_times(handle, *(ctypes.byref(item) for item in times)):
                    raise OSError("GetThreadTimes failed")
                kernel, user = ((item.dwHighDateTime << 32 | item.dwLowDateTime) for item in times[2:])
                return (kernel + user) / 10_000_000

            reader = (open_windows, read_windows, close_handle)
        else:
            return None
        clock = reader[0]()
        try:
            reader[1](clock)
        finally:
            reader[2](clock)
        return reader
    except (OSError, ValueError, OverflowError, AttributeError):
        return None


_CPU = _thread_cpu_reader()


def cpu_supported() -> bool:
    """Whether a thread's CPU time can be read here, so CPU budgets apply (not on macOS)."""
    return _CPU is not None


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


def process_memory_supported() -> bool:
    """Whether other processes' resident sets can be read, so worker processes are measured."""
    return _PROCESS_RSS is not None


def process_resident_bytes(pid: int) -> int | None:
    """Another process's resident set in bytes; None once it has exited, or where unsupported."""
    if _PROCESS_RSS is None:
        return None
    try:
        return _PROCESS_RSS(pid)
    except Exception:
        return None


# ---------------------------------------------------------------------------------------
# The scan's memory budget

class ScanMemoryBudget:
    """``--max-memory-mb``: back-pressure that keeps the scan's resident memory under a budget.

    The scan's memory is this process's resident set plus each analysis worker process's
    (``worker_pids``). On Linux, pages several of them share (what a forked worker inherited
    copy-on-write, shared libraries) count once: the proportional set size splits them, but
    reading it walks the page tables, so it calibrates the cheap resident-set reads at most
    every ``SCAN_CALIBRATION_SECONDS`` (and never more than about 1% of the time). Elsewhere
    every process's resident set counts in full, which errs high by the shared library pages.

    The coordinator calls ``make_room`` before it queues work. While the scan is at or over
    its budget, queued work is collected first, oldest first, so fewer calls run at once;
    with nothing left in flight the work is queued anyway and counted, so a scan over its
    budget runs one batch at a time and never stalls. A running call is not stopped by the
    scan budget, but no call's own memory budget exceeds it (``BudgetPolicy.scan_memory_mb``).
    """

    def __init__(self, limit_mb: int | None = None, worker_pids: Callable[[], Iterable[int]] | None = None) -> None:
        self.limit = int(limit_mb) * _MIB if limit_mb else None
        self._worker_pids = worker_pids
        self.peak: int | None = None
        self.samples = 0
        self.processes = 0  # the most processes one sample measured
        self.waits = 0  # queued batches collected before more work was queued
        self.held_seconds = 0.0
        self.over_budget_submissions = 0  # work queued over the budget with nothing in flight
        self.calibrations = 0
        self._shared: dict[int, int] = {}  # pid -> resident bytes it shares with other processes
        self._calibrated: set[int] = set()  # the processes the last calibration read
        self._calibrate_after = 0.0  # when the shared pages are measured again
        self._sampled_at = -math.inf
        self._total: int | None = None

    @property
    def enforced(self) -> bool:
        return self.limit is not None and memory_supported()

    def total_bytes(self, *, fresh: bool = False) -> int | None:
        """The scan's resident memory: sampled at most every SCAN_SAMPLE_SECONDS unless fresh."""
        now = time.monotonic()
        if not fresh and now - self._sampled_at < SCAN_SAMPLE_SECONDS:
            return self._total
        self._sampled_at = now
        own = resident_bytes()
        if own is None:
            self._total = None
            return None
        readings = {os.getpid(): own}
        for pid in self._worker_pids() if self._worker_pids is not None else ():
            value = process_resident_bytes(pid)
            if value is not None:  # None: the worker has exited
                readings[pid] = value
        # Workers start after the first sample (a pool replaced after a crash brings new ones),
        # and a forked one also changes what the coordinator shares: new processes are measured
        # at once. They are young and small, and a pool starts its workers only once.
        if _PSS is not None and (now >= self._calibrate_after or not self._calibrated.issuperset(readings)):
            self._calibrate(readings)
        total = sum(value - min(value, self._shared.get(pid, 0)) for pid, value in readings.items())
        self.samples += 1
        self.processes = max(self.processes, len(readings))
        self.peak = total if self.peak is None else max(self.peak, total)
        self._total = total
        return total

    def _calibrate(self, readings: dict[int, int]) -> None:
        started = time.monotonic()
        shared = {}
        for pid, resident in readings.items():
            proportional = _PSS(pid) if _PSS is not None else None
            if proportional is not None:
                shared[pid] = max(0, resident - proportional)
        self._shared = shared
        self._calibrated = set(readings)
        self.calibrations += 1
        # Reading the proportional set walks page tables: at most about 1% of the coordinator's time.
        self._calibrate_after = started + max(SCAN_CALIBRATION_SECONDS, 100 * (time.monotonic() - started))

    def over_budget(self, *, fresh: bool = False) -> bool:
        if not self.enforced:
            return False
        total = self.total_bytes(fresh=fresh)
        return total is not None and total >= self.limit  # type: ignore[operator]

    def make_room(self, in_flight: Callable[[], int], collect_oldest: Callable[[], Any]) -> None:
        """Call before queueing work: while the scan is over its budget, collect queued work first."""
        if not self.over_budget():
            return
        started = time.monotonic()
        try:
            checked = False
            while in_flight():
                collect_oldest()
                self.waits += 1
                checked = True
                if not self.over_budget(fresh=True):
                    return
            if checked or self.over_budget(fresh=True):
                self.over_budget_submissions += 1
        finally:
            self.held_seconds += time.monotonic() - started

    def describe(self) -> dict[str, Any]:
        """metrics.analysis_budgets.scan_memory."""
        return {
            "limit_mb": self.limit // _MIB if self.limit else None,
            "enforced": self.enforced,
            "processes_measured": self.processes,
            "shared_pages": "proportional" if self.calibrations else "per_process",
            "peak_mb": None if self.peak is None else round(self.peak / _MIB, 1),
            "samples": self.samples,
            "waits": self.waits,
            "held_seconds": round(self.held_seconds, 3),
            "over_budget_submissions": self.over_budget_submissions,
        }


# ---------------------------------------------------------------------------------------
# The watchdog

_SET_ASYNC_EXC = ctypes.pythonapi.PyThreadState_SetAsyncExc
_SET_ASYNC_EXC.argtypes = (ctypes.c_ulong, ctypes.py_object)
_SET_ASYNC_EXC.restype = ctypes.c_int


def _raise_in(thread: int, exception: type[BaseException]) -> None:
    # Never called with NULL to clear a pending exception: on Python 3.11 that still raises
    # the interpreter's asynchronous-exception flag, which then never clears, and a traced
    # process (coverage) spins at every function entry. A pending stop is delivered instead.
    _SET_ASYNC_EXC(ctypes.c_ulong(thread), ctypes.py_object(exception))


class _Call:
    __slots__ = ("thread", "budget", "started", "deadline", "memory_limit", "baseline", "peak", "samples", "running",
                 "stop", "cpu_clock", "cpu_start", "cpu_limit")

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
        self.cpu_clock = None
        self.cpu_start = 0.0
        self.cpu_limit = budget.cpu_seconds if budget.cpu_seconds and _CPU is not None else None
        if self.cpu_limit is not None:
            try:  # in the analyzing thread: its own clock
                self.cpu_clock = _CPU[0]()
                self.cpu_start = _CPU[1](self.cpu_clock)
            except (OSError, ValueError, OverflowError):
                self.cpu_clock = self.cpu_limit = None


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
        """End a call; returns its stop if the watchdog fired."""
        with self._lock:
            if call.running:
                call.running = False
                if call.cpu_clock is not None:  # under the lock the watchdog reads it with
                    _CPU[2](call.cpu_clock)
                    call.cpu_clock = None
                self._calls.pop(id(call), None)
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
                    if call.stop is None and call.cpu_clock is not None:
                        try:
                            used = _CPU[1](call.cpu_clock) - call.cpu_start
                        except (OSError, ValueError, OverflowError):
                            used = 0.0
                        if used > call.cpu_limit:
                            call.stop = BudgetStop("cpu", float(call.cpu_limit), used)
                    if call.stop is None and call.deadline is not None and now >= call.deadline:
                        call.stop = BudgetStop("time", float(call.budget.timeout_seconds), now - call.started)
                    if call.stop is not None:
                        _raise_in(call.thread, AnalyzerBudgetExceeded)


_WATCHDOG = _Watchdog()


def _peak(call: _Call) -> float | None:
    """The sampled peak growth in MiB; None when no sample fell inside the call."""
    return call.peak / _MIB if call.memory_limit and call.samples else None


def _deliver_pending_stop() -> None:
    """Take here a stop the watchdog raised just as the call returned.

    The interpreter delivers an asynchronous exception at its next periodic check: loop
    back-edges are such checks on every supported version, so a stop still pending
    surfaces in this loop, inside the guarded region, never in the caller's code.
    """
    for _ in range(4):
        pass


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
            if stop is not None:
                _deliver_pending_stop()  # raises it if the call did not receive it
    except AnalyzerBudgetExceeded as exc:
        # Delivered in the call, inside disarm() or by _deliver_pending_stop(): end the call
        # (idempotent) first. The readers raise it themselves for the read budget.
        stop = _WATCHDOG.disarm(call) or call.stop
        if stop is None and exc.stop is not None:
            kind, limit, used = exc.stop
            stop = BudgetStop(kind, limit / _MIB, used / _MIB)
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
