"""Portable Python interface to PDT's optional C/Assembly backend."""
from __future__ import annotations

from typing import Any

try:
    from . import _native
except ImportError:
    _native = None


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
