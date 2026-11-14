import json

from project_discovery.engine import native as native_backend


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
    assert native_backend.capabilities()["cpp_signature_classifier_outdated"] is False


def test_the_cpp_rule_table_is_generated_from_the_python_catalog():
    from pathlib import Path

    from project_discovery.inventory.signatures import RULES, RULES_DIGEST, render_cpp_rules

    header = Path(__file__).resolve().parents[2] / "native" / "cpp" / "pdt_signature_rules.h"
    assert header.read_bytes().decode("utf-8") == render_cpp_rules(), (
        "native/cpp/pdt_signature_rules.h is stale: run python tools/signature_rules.py --write"
    )
    from project_discovery import _native_cpp

    assert (_native_cpp.RULES_DIGEST, _native_cpp.RULE_COUNT) == (RULES_DIGEST, len(RULES))


def test_a_cpp_build_from_another_catalog_falls_back_to_python(monkeypatch):
    # A C++ classifier compiled from an older table would return other rule indexes; the
    # Python matcher is used instead, and capabilities say why.
    from types import SimpleNamespace

    from project_discovery.inventory import signatures

    monkeypatch.setattr(native_backend, "_native_cpp", SimpleNamespace(RULES_DIGEST="stale", match_rule=None))
    monkeypatch.setattr(signatures, "_CPP_CURRENT", False)
    info = native_backend.capabilities()
    assert info["cpp_signature_classifier"] is False and info["cpp_signature_classifier_outdated"] is True
    assert signatures.detect(b"\x7fELF\x02\x01\x01" + b"\0" * 60).label == "executable/elf"

def test_rust_filesystem_walker_is_built_and_available():
    assert native_backend.rust_walker_available()
    assert native_backend.capabilities()["rust_filesystem_walker_outdated"] is False


def test_an_outdated_walker_build_falls_back_to_python(monkeypatch):
    # A walker built from older sources yields fewer fields than the scanner records; the
    # Python fallback is used instead, and capabilities say why.
    from types import SimpleNamespace

    def walker(*_args):
        raise AssertionError("an outdated walker build was used")

    monkeypatch.setattr(native_backend, "_walker", SimpleNamespace(Walker=walker))
    assert native_backend.create_walker(".", set(), set()) is None
    assert native_backend.rust_walker_available() is False
    info = native_backend.capabilities()
    assert (info["rust_filesystem_walker"], info["rust_filesystem_walker_outdated"]) == (False, True)


def test_gpu_capability_fields_are_available_with_or_without_hardware():
    info = native_backend.capabilities()
    assert isinstance(info["gpu_available"], bool) and isinstance(info["gpu_enabled"], bool)
    assert info["gpu_status"] in {"online", "cpu-fallback", "disabled"}
    assert isinstance(info["gpu_threshold_bytes"], int)
    assert info["gpu_threshold_bytes"] >= 1024 * 1024
    assert isinstance(info["gpu_dispatches"], int)
    assert isinstance(info["gpu_fallbacks"], int)
    with native_backend.gpu_configuration(True):
        info = native_backend.capabilities()
    if info["gpu_available"]:
        assert info["gpu_backend"] == "opencl"
        assert info["gpu_name"]
        assert info["gpu_compute_units"] >= 1
    else:
        assert info["gpu_backend"] == "none"


def test_gpu_counting_is_off_by_default_and_never_loads_opencl():
    # Measured slower than the CPU, so scans leave it off; and a disabled path loads no driver.
    import subprocess
    import sys

    probe = (
        "import ctypes, json, os, sys\n"
        "from project_discovery.engine import native\n"
        "payload = bytes(range(256)) * 32768 + b'\\n'\n"
        "assert native.count_byte(payload, 10) == payload.count(b'\\n')\n"
        "info = native.capabilities()\n"
        "if os.name == 'nt':\n"
        "    ctypes.windll.kernel32.GetModuleHandleW.restype = ctypes.c_void_p\n"
        "    loaded = bool(ctypes.windll.kernel32.GetModuleHandleW('OpenCL.dll'))\n"
        "elif sys.platform.startswith('linux'):\n"
        "    loaded = 'libOpenCL' in open('/proc/self/maps').read()\n"
        "else:\n"
        "    loaded = False\n"
        "print(json.dumps({'loaded': loaded, **{key: info[key] for key in (\n"
        "    'gpu_status', 'gpu_enabled', 'gpu_unavailable_reason', 'gpu_dispatches', 'gpu_fallbacks')}}))\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120, check=True)
    info = json.loads(result.stdout)
    assert info["loaded"] is False
    assert (info["gpu_dispatches"], info["gpu_fallbacks"], info["gpu_enabled"]) == (0, 0, False)
    if native_backend.native_available():
        assert (info["gpu_status"], info["gpu_unavailable_reason"]) == ("disabled", "disabled")


def test_gpu_settings_are_scoped_and_validated():
    import pytest

    assert native_backend.gpu_settings() == (False, native_backend.GPU_DEFAULT_THRESHOLD_BYTES)
    with native_backend.gpu_configuration(True, 16 * 1024 * 1024):
        expected = (True, 16 * 1024 * 1024) if native_backend.native_available() else (False, 8 * 1024 * 1024)
        assert native_backend.gpu_settings() == expected
    assert native_backend.gpu_settings() == (False, native_backend.GPU_DEFAULT_THRESHOLD_BYTES)
    with pytest.raises(ValueError, match="at least 1 MiB"):
        native_backend.configure_gpu(True, 1000)
    probed = native_backend.probe_gpu()
    assert probed["gpu_enabled"] is False and native_backend.gpu_settings()[0] is False
    assert probed["gpu_status"] in {"available", "cpu-fallback"}  # a usable device scans leave off, or none


def test_gpu_fallback_reasons_are_reported_with_or_without_hardware():
    with native_backend.gpu_configuration(True):
        info = native_backend.capabilities()
    reasons = info["gpu_fallback_reasons"]
    if not native_backend.native_available():
        assert (info["gpu_unavailable_reason"], reasons) == ("native_extension", {})
        return
    if info["gpu_available"]:
        assert info["gpu_unavailable_reason"] == ""
    else:
        assert info["gpu_unavailable_reason"] in native_backend.GPU_FALLBACK_REASONS
    assert set(reasons) == set(native_backend.GPU_FALLBACK_REASONS)
    assert sum(reasons.values()) == info["gpu_fallbacks"]


def test_every_gpu_fallback_is_counted_under_its_reason():
    import pytest

    if not native_backend.native_available():
        pytest.skip("the C extension is not built")
    payload = bytes(range(256)) * 32768 + b"\n"  # past the 8 MiB GPU threshold
    expected = payload.count(b"\n")
    with native_backend.gpu_configuration(True):
        for reason in native_backend.GPU_FALLBACK_REASONS:
            assert native_backend.set_gpu_test_fault(reason)
            try:
                before = native_backend.capabilities()
                assert native_backend.count_byte(payload, 10) == expected
                after = native_backend.capabilities()
            finally:
                native_backend.set_gpu_test_fault(None)
            assert after["gpu_fallbacks"] == before["gpu_fallbacks"] + 1
            assert after["gpu_dispatches"] == before["gpu_dispatches"]
            assert after["gpu_fallback_reasons"][reason] == before["gpu_fallback_reasons"][reason] + 1
        # Small and mutable buffers never reach the GPU path, so they are no fallback.
        before = native_backend.capabilities()["gpu_fallbacks"]
        native_backend.count_byte(b"\n" * 1024, 10)
        native_backend.count_byte(bytearray(payload), 10)
        assert native_backend.capabilities()["gpu_fallbacks"] == before
    # Below a raised threshold the buffer stays on the CPU without counting as a fallback.
    with native_backend.gpu_configuration(True, 16 * 1024 * 1024):
        native_backend.set_gpu_test_fault("dispatch")
        try:
            before = native_backend.capabilities()["gpu_fallbacks"]
            native_backend.count_byte(payload, 10)  # 8 MiB: under 16 MiB
            assert native_backend.capabilities()["gpu_fallbacks"] == before
            native_backend.count_byte(payload * 2, 10)  # 16 MiB and two bytes
            assert native_backend.capabilities()["gpu_fallbacks"] == before + 1
        finally:
            native_backend.set_gpu_test_fault(None)
    # GPU counting off (the default): no buffer is a GPU candidate, so none falls back.
    before = native_backend.capabilities()["gpu_fallbacks"]
    native_backend.count_byte(payload, 10)
    assert native_backend.capabilities()["gpu_fallbacks"] == before
    with pytest.raises(ValueError, match="unknown GPU fallback reason"):
        native_backend.set_gpu_test_fault("everything")


def test_without_a_usable_gpu_large_buffers_fall_back_under_the_unavailable_reason():
    import pytest

    with native_backend.gpu_configuration(True):
        info = native_backend.capabilities()
        if info["gpu_available"] or not native_backend.native_available():
            pytest.skip("this machine has a usable OpenCL GPU, or no C extension")
        reason = info["gpu_unavailable_reason"]
        payload = bytes(range(256)) * 32768 + b"\n"
        native_backend.count_byte(payload, 0)
        after = native_backend.capabilities()
    assert after["gpu_fallback_reasons"][reason] == info["gpu_fallback_reasons"][reason] + 1
    assert after["gpu_fallbacks"] == info["gpu_fallbacks"] + 1


def test_scans_use_the_gpu_only_with_the_option_also_in_worker_processes(tmp_path):
    import pytest

    from project_discovery.cli import run_scan

    if not native_backend.native_available():
        pytest.skip("the C extension is not built")
    project = tmp_path / "project"
    project.mkdir()
    # The secret scanner counts the newlines of 8 MiB chunks with count_byte.
    (project / "notes.txt").write_bytes(b"x" * 1023 + b"\n" + b"y" * (9 * 1024 * 1024))
    counted = {}
    for gpu in (False, True):
        output = tmp_path / f"out-{gpu}"
        assert run_scan(project, output, {"json"}, 128, quiet=True, executor="process", jobs=2, gpu=gpu) == 0
        native = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["native_backend"]
        counted[gpu] = (native["gpu_enabled"], native["gpu_dispatches"] + native["gpu_fallbacks"])
    # The worker processes received --gpu: their large buffers went to the GPU path, or fell back.
    assert counted[False] == (False, 0) and counted[True][0] is True and counted[True][1] >= 1
    assert native_backend.gpu_settings()[0] is False  # the scan's setting does not outlive it


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

    source = (Path(__file__).resolve().parents[2] / "native" / "c" / "pdt_native.c").read_text(encoding="utf-8")
    assert 'LoadLibraryExA("OpenCL.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)' in source
    assert 'LoadLibraryA("OpenCL.dll")' not in source
    assert 'dlopen("OpenCL.framework/OpenCL"' not in source


def test_gpu_and_cpu_byte_counts_agree_when_a_gpu_is_present():
    import pytest

    with native_backend.gpu_configuration(True):
        capabilities = native_backend.capabilities()
        if not capabilities.get("gpu_available"):
            pytest.skip("no OpenCL GPU on this machine")
        payload = (bytes(range(256)) * (48 * 1024 * 1024 // 256)) + b"\n" * 4093
        before = native_backend.capabilities()
        for needle in (0, 10, 255):
            assert native_backend.count_byte(payload, needle) == payload.count(bytes((needle,)))
        after = native_backend.capabilities()
    assert after["gpu_dispatches"] == before["gpu_dispatches"] + 3
    assert after["gpu_fallbacks"] == before["gpu_fallbacks"]
