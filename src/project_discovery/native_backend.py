"""Portable Python interface to PDT's optional C/Assembly backend."""
from __future__ import annotations

from typing import Any

try:
    from . import _native
except ImportError:
    _native = None

try:
    from . import _native_cpp
except ImportError:
    _native_cpp = None

try:
    from . import _walker
except ImportError:
    _walker = None


def count_byte(data: bytes | bytearray | memoryview, needle: int) -> int:
    """Count a byte using SIMD/C if built, otherwise use the portable fallback."""
    if not isinstance(needle, int) or isinstance(needle, bool) or not 0 <= needle <= 255:
        raise ValueError("needle must be an integer between 0 and 255")
    if _native is not None:
        return int(_native.count_byte(data, needle))
    return memoryview(data).tobytes().count(bytes((needle,)))


def capabilities() -> dict[str, Any]:
    """Report the native backend selected on this machine."""
    if _native is not None:
        return dict(_native.capabilities())
    import os
    import platform

    return {
        "architecture": platform.machine().lower() or "unknown",
        "backend": "python-fallback",
        "hardware_threads": os.cpu_count() or 1,
        "assembly_compiled": False,
    }


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
    """Return whether the compiled Rust filesystem walker is loaded."""
    return _walker is not None


def create_walker(root, excluded_names, excluded_paths):
    """Create the Rust no-follow walker, or return None for the Python fallback."""
    if _walker is None:
        return None
    return _walker.Walker(str(root), sorted(excluded_names), sorted(excluded_paths))
