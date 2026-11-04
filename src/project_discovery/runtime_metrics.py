"""Process resource telemetry for scan reports and benchmarks (no third-party deps)."""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from typing import Iterator


def peak_rss_bytes() -> int | None:
    """Peak resident set size of this process, or None when the platform cannot say."""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            # The pseudo-handle (-1) is truncated unless the HANDLE types are declared.
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            get_info = kernel32.K32GetProcessMemoryInfo
            get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            get_info.restype = wintypes.BOOL
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            if get_info(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return int(counters.PeakWorkingSetSize)
        except (OSError, AttributeError):
            return None
        return None
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS and the BSDs report bytes.
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


class PhaseTimer:
    """Accumulate wall-clock seconds per named scan phase."""

    def __init__(self) -> None:
        self.started = time.perf_counter()
        self._last_lap = self.started
        self.phases: dict[str, float] = {}

    def lap(self, name: str) -> float:
        """Record the time since the previous lap (or start) under ``name``."""
        now = time.perf_counter()
        seconds = round(now - self._last_lap, 3)
        self.phases[name] = round(self.phases.get(name, 0.0) + seconds, 3)
        self._last_lap = now
        return seconds

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.phases[name] = round(self.phases.get(name, 0.0) + time.perf_counter() - start, 3)

    def elapsed(self) -> float:
        return round(time.perf_counter() - self.started, 3)
