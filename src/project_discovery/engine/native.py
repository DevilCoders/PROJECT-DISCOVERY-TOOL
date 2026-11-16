"""Portable Python interface to PDT's optional C, Assembly, C++, Rust and GPU backends."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
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
WALKER_ENTRY_FIELDS = 16


def _walker_current() -> bool:
    return _walker is not None and getattr(_walker, "ENTRY_FIELDS", 12) >= WALKER_ENTRY_FIELDS


def count_byte(data: bytes | bytearray | memoryview, needle: int) -> int:
    """Count a byte using automatic large-buffer GPU dispatch or CPU fallback."""
    if not isinstance(needle, int) or isinstance(needle, bool) or not 0 <= needle <= 255:
        raise ValueError("needle must be an integer between 0 and 255")
    if _native is not None:
        return int(_native.count_byte(data, needle))
    return memoryview(data).tobytes().count(bytes((needle,)))


# Why a large immutable buffer was counted on the CPU instead of the GPU (the extension's
# names): no OpenCL loader or symbol, no usable device, context creation, kernel build,
# device memory limit, host allocation, or a failed dispatch.
GPU_FALLBACK_REASONS = ("loader", "device", "context", "kernel_build", "memory_limit", "host_memory",
                        "dispatch")
# The smallest immutable buffer counted on the GPU when GPU counting is enabled (--gpu).
GPU_DEFAULT_THRESHOLD_BYTES = 8 * 1024 * 1024


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
            # Without the C extension nothing is dispatched or falls back: Python counts.
            "gpu_unavailable_reason": "native_extension",
            "gpu_fallback_reasons": {},
            "gpu_enabled": False,
        }
    info["cpp_signature_classifier"] = signature_backend_available()
    # Loaded, but compiled from another signature catalog: the Python matcher is used.
    info["cpp_signature_classifier_outdated"] = _native_cpp is not None and not signature_backend_available()
    info["rust_filesystem_walker"] = _walker_current()
    info["rust_filesystem_walker_outdated"] = _walker is not None and not _walker_current()
    # online: enabled with a usable device; disabled: GPU counting is off (the default), and
    # OpenCL was not loaded; cpu-fallback: enabled, but no usable device (or no extension).
    if info.get("gpu_available") and info.get("gpu_enabled", True):
        info["gpu_status"] = "online"
    elif info.get("gpu_unavailable_reason") == "disabled":
        info["gpu_status"] = "disabled"
    else:
        info["gpu_status"] = "cpu-fallback"
    # An extension built from older sources reports no reasons.
    info.setdefault("gpu_unavailable_reason", "" if info.get("gpu_available") else "not_reported")
    info["gpu_fallback_reasons"] = {str(name): int(count) for name, count in
                                    (info.get("gpu_fallback_reasons") or {}).items()}
    return info


def configure_gpu(enabled: bool, threshold_bytes: int = GPU_DEFAULT_THRESHOLD_BYTES) -> None:
    """Enable GPU byte counting (off by default) for immutable buffers of threshold_bytes or more.

    Off by default because, for buffers in host memory, the copy to the device costs more than
    counting on the CPU (docs/architecture/NATIVE_ENGINE.md has the measurements).
    """
    if threshold_bytes < 1024 * 1024:
        raise ValueError("the GPU threshold must be at least 1 MiB")
    setter = getattr(_native, "configure_gpu", None)
    if setter is not None:
        setter(bool(enabled), int(threshold_bytes))


def gpu_settings() -> tuple[bool, int]:
    """(enabled, threshold bytes) of GPU byte counting in this process."""
    info = capabilities()
    return bool(info.get("gpu_enabled")), int(info.get("gpu_threshold_bytes") or GPU_DEFAULT_THRESHOLD_BYTES)


@contextmanager
def gpu_configuration(enabled: bool, threshold_bytes: int = GPU_DEFAULT_THRESHOLD_BYTES) -> Iterator[None]:
    """GPU byte counting set for a block (one scan), restored afterwards."""
    previous = gpu_settings()
    configure_gpu(enabled, threshold_bytes)
    try:
        yield
    finally:
        configure_gpu(*previous)


def probe_gpu() -> dict[str, Any]:
    """capabilities() with the GPU probed, for `pdt capabilities`: whether this host has a usable
    device. A usable device that scans leave off (no --gpu) has the status "available"."""
    previous = gpu_settings()
    configure_gpu(True, previous[1])
    try:
        info = capabilities()
    finally:
        configure_gpu(*previous)
    info["gpu_enabled"] = previous[0]
    if info.get("gpu_available") and not previous[0]:
        info["gpu_status"] = "available"
    return info


def set_gpu_test_fault(reason: str | None) -> bool:
    """Tests only: count every eligible buffer on the CPU with this fallback reason.

    Returns False when the C extension (or this hook in it) is not available.
    """
    hook = getattr(_native, "_set_gpu_test_fault", None)
    if hook is None:
        return False
    hook(reason)
    return True


def native_available() -> bool:
    return _native is not None


def detect_signature(data: bytes | bytearray | memoryview) -> str | None:
    """The candidate label of the first catalog rule whose magic bytes the sample matches.

    First pass only: inventory.signatures validates the header and reads the subtype.
    """
    if _native_cpp is None:
        return None
    result = _native_cpp.detect_signature(data)
    return str(result) if result is not None else None


def signature_rules_digest() -> str | None:
    """The digest of the rule table the C++ classifier was compiled from."""
    return None if _native_cpp is None else getattr(_native_cpp, "RULES_DIGEST", None)


def match_signature_rule(data: bytes | bytearray | memoryview, start: int = 0) -> int | None:
    """The index of the first rule from ``start`` that the sample matches (C++)."""
    result = _native_cpp.match_rule(data, start)
    return None if result is None else int(result)


def signature_backend_available() -> bool:
    """Whether the compiled C++ signature classifier is loaded and holds the current catalog."""
    if _native_cpp is None:
        return False
    from ..inventory.signatures import cpp_rules_current

    return cpp_rules_current()


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
