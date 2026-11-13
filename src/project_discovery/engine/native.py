"""Portable Python interface to PDT's optional C, Assembly, C++, Rust and GPU backends."""
from __future__ import annotations

from typing import Any

try:
    from .. import _native
except ImportError:
    _native = None

try:
    from .. import _native_cpp
except ImportError:
    _native_cpp = None

try:
    from .. import _walker
except ImportError:
    _walker = None

# A walker build that yields fewer fields than the scanner records (an extension built from
# older sources) is not used: the Python fallback reports every field.
WALKER_ENTRY_FIELDS = 15


def _walker_current() -> bool:
    return _walker is not None and getattr(_walker, "ENTRY_FIELDS", 12) >= WALKER_ENTRY_FIELDS


def count_byte(data: bytes | bytearray | memoryview, needle: int) -> int:
    """Count a byte using automatic large-buffer GPU dispatch or CPU fallback."""
    if not isinstance(needle, int) or isinstance(needle, bool) or not 0 <= needle <= 255:
        raise ValueError("needle must be an integer between 0 and 255")
    if _native is not None:
        return int(_native.count_byte(data, needle))
    return memoryview(data).tobytes().count(bytes((needle,)))


def capabilities() -> dict[str, Any]:
    """Report CPU, GPU and optional native backends available on this machine."""
    if _native is not None:
        info = dict(_native.capabilities())
    else:
        import os
        import platform
        info = {
            "architecture": platform.machine().lower() or "unknown",
            "backend": "python-fallback",
            "hardware_threads": os.cpu_count() or 1,
            "assembly_compiled": False,
            "gpu_available": False,
            "opencl_available": False,
            "gpu_backend": "none",
            "gpu_name": "",
            "gpu_vendor": "",
            "gpu_compute_units": 0,
            "gpu_global_memory_bytes": 0,
            "gpu_max_allocation_bytes": 0,
            "gpu_threshold_bytes": 8 * 1024 * 1024,
            "gpu_dispatches": 0,
            "gpu_fallbacks": 0,
        }
    info["cpp_signature_classifier"] = _native_cpp is not None
    info["rust_filesystem_walker"] = _walker_current()
    info["rust_filesystem_walker_outdated"] = _walker is not None and not _walker_current()
    info["gpu_status"] = "online" if info.get("gpu_available") else "cpu-fallback"
    return info


def native_available() -> bool:
    return _native is not None


def detect_signature(data: bytes | bytearray | memoryview) -> str | None:
    """Classify a bounded byte sample with the optional C++ signature engine."""
    if _native_cpp is None:
        return None
    result = _native_cpp.detect_signature(data)
    return str(result) if result is not None else None


def signature_backend_available() -> bool:
    """Return whether the compiled C++ signature classifier is loaded."""
    return _native_cpp is not None


def rust_walker_available() -> bool:
    """Return whether the compiled Rust filesystem walker is loaded and current."""
    return _walker_current()


def create_walker(root, excluded_names, excluded_paths):
    """Create the Rust no-follow walker, or return None for the Python fallback.

    The caller decides exclusions (with full Unicode case folding) and calls
    skip_directory(); the walker's own to_lowercase() matching would disagree, so it gets
    no exclusions of its own.
    """
    if not _walker_current():
        return None
    return _walker.Walker(str(root), [], [])
