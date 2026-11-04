from project_discovery import native_backend


def test_count_byte_matches_python_for_all_buffer_shapes():
    payload = bytes(range(256)) * 257 + b"\n\n\x00"
    for value in (0, 1, 10, 127, 255):
        expected = payload.count(bytes([value]))
        assert native_backend.count_byte(payload, value) == expected
        assert native_backend.count_byte(bytearray(payload), value) == expected
        assert native_backend.count_byte(memoryview(payload), value) == expected


def test_count_byte_handles_empty_and_unaligned_buffers():
    assert native_backend.count_byte(b"", 0) == 0
    payload = b"x" * 31 + b"!" + b"x" * 7
    assert native_backend.count_byte(payload, ord("!")) == 1


def test_count_byte_rejects_invalid_needle():
    import pytest

    for value in (-1, 256, True, 1.5):
        with pytest.raises(ValueError):
            native_backend.count_byte(b"sample", value)


def test_native_capability_report_is_machine_readable():
    import platform
    import sys

    info = native_backend.capabilities()
    assert info["architecture"]
    assert info["backend"] in {
        "x86_64-sse2-popcnt-asm", "portable-c", "python-fallback",
    }
    assert info["hardware_threads"] >= 1
    assert isinstance(info["assembly_compiled"], bool)
    if info["backend"] == "x86_64-sse2-popcnt-asm":
        assert info["assembly_compiled"] is True
    if sys.platform.startswith("linux") and platform.machine().lower() in {"x86_64", "amd64"}:
        assert native_backend.native_available()
        assert info["assembly_compiled"] is True

def test_cpp_signature_classifier_is_compiled_and_recognizes_binary_formats():
    assert native_backend.signature_backend_available()
    assert native_backend.detect_signature(b"\x7fELF" + b"0" * 32) == "executable/elf"
    assert native_backend.detect_signature(b"PK\x03\x04" + b"0" * 32) == "archive/zip"
    assert native_backend.detect_signature(b"\xfd7zXZ\x00") == "archive/xz"
    assert native_backend.detect_signature(b"SQLite format 3\x00") == "database/sqlite"
    assert native_backend.detect_signature(b"not a recognized signature") is None

def test_rust_filesystem_walker_is_built_and_available():
    assert native_backend.rust_walker_available()


def test_gpu_capability_fields_are_available_with_or_without_hardware():
    info = native_backend.capabilities()
    assert isinstance(info["gpu_available"], bool)
    assert info["gpu_status"] in {"online", "cpu-fallback"}
    assert isinstance(info["gpu_threshold_bytes"], int)
    assert info["gpu_threshold_bytes"] >= 1024 * 1024
    assert isinstance(info["gpu_dispatches"], int)
    assert isinstance(info["gpu_fallbacks"], int)
    if info["gpu_available"]:
        assert info["gpu_backend"] == "opencl"
        assert info["gpu_name"]
        assert info["gpu_compute_units"] >= 1
    else:
        assert info["gpu_backend"] == "none"


def test_large_buffer_automatic_backend_matches_python_reference():
    payload = bytes(range(256)) * 32768 + b"\n\x00"
    assert len(payload) >= 8 * 1024 * 1024
    for value in (0, 10, 127, 255):
        assert native_backend.count_byte(payload, value) == payload.count(bytes([value]))


def test_native_byte_counter_is_safe_under_concurrent_calls():
    from concurrent.futures import ThreadPoolExecutor

    payload = bytes(range(256)) * 32768
    values = [0, 10, 127, 255] * 8
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(
            lambda value: native_backend.count_byte(payload, value), values
        ))
    assert results == [payload.count(bytes([value])) for value in values]

def test_large_mutable_buffers_use_safe_cpu_path():
    payload = bytearray(bytes(range(256)) * 32768)
    before = native_backend.capabilities()["gpu_dispatches"]
    expected = payload.count(bytes([10]))
    assert native_backend.count_byte(payload, 10) == expected
    assert native_backend.count_byte(memoryview(payload), 10) == expected
    after = native_backend.capabilities()["gpu_dispatches"]
    assert after == before


def test_opencl_loader_never_resolves_libraries_from_the_working_directory():
    # Regression: LoadLibraryA("OpenCL.dll") and dlopen("OpenCL.framework/OpenCL")
    # could load a library planted in the scanned repository.
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "native" / "pdt_native.c").read_text(encoding="utf-8")
    assert 'LoadLibraryExA("OpenCL.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)' in source
    assert 'LoadLibraryA("OpenCL.dll")' not in source
    assert 'dlopen("OpenCL.framework/OpenCL"' not in source


def test_gpu_and_cpu_byte_counts_agree_when_a_gpu_is_present():
    import pytest

    capabilities = native_backend.capabilities()
    if not capabilities.get("gpu_available"):
        pytest.skip("no OpenCL GPU on this machine")
    payload = (bytes(range(256)) * (48 * 1024 * 1024 // 256)) + b"\n" * 4093
    before = native_backend.capabilities()["gpu_dispatches"]
    for needle in (0, 10, 255):
        assert native_backend.count_byte(payload, needle) == payload.count(bytes((needle,)))
    assert native_backend.capabilities()["gpu_dispatches"] > before
