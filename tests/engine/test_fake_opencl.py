"""The native extension's OpenCL paths against a fake OpenCL loader (Linux).

On Linux the extension loads libOpenCL.so.1 through the dynamic linker's search path, so a
fake library on LD_LIBRARY_PATH stands in for the vendor's ICD loader. Each mode of
fake_opencl.c fails one initialization or dispatch step, or provides a working device whose
kernel runs on the host, so every GPU path is tested without GPU hardware.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from project_discovery.engine import native as native_backend

FAKE = Path(__file__).with_name("fake_opencl.c")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
SOURCE_ROOT = Path(native_backend.__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.skipif(not sys.platform.startswith("linux"),
                       reason="only Linux resolves libOpenCL.so.1 through LD_LIBRARY_PATH"),
    pytest.mark.skipif(COMPILER is None, reason="no C compiler for the fake OpenCL library"),
    pytest.mark.skipif(not native_backend.native_available(), reason="the C extension is not built"),
]

PROBE = r"""
import json, os
from project_discovery.engine import native
native.configure_gpu(os.environ['PDT_PROBE_GPU'] == '1', int(os.environ['PDT_PROBE_THRESHOLD']))
small = bytes(range(256)) * (9 * 4096) + b"\n"   # 9 MiB and a byte: past the 8 MiB threshold
large = bytes(range(256)) * (20 * 4096)          # 20 MiB
correct = [native.count_byte(small, 10) == small.count(b"\n"), native.count_byte(large, 0) == large.count(b"\0")]
info = native.capabilities()
loaded = 'libOpenCL' in open('/proc/self/maps').read()
print(json.dumps({"correct": correct, "loaded": loaded, **{key: info[key] for key in (
    "gpu_available", "gpu_name", "gpu_vendor", "gpu_compute_units", "gpu_unavailable_reason",
    "gpu_dispatches", "gpu_fallbacks", "gpu_fallback_reasons")}}))
"""


@pytest.fixture(scope="module")
def fake_libraries(tmp_path_factory):
    root = tmp_path_factory.mktemp("fake-opencl")
    libraries = {}
    for variant, flags in (("complete", []), ("incomplete", ["-DPDT_FAKE_MISSING_SYMBOL"])):
        directory = root / variant
        directory.mkdir()
        subprocess.run([COMPILER, "-shared", "-fPIC", "-O1", *flags, "-o", str(directory / "libOpenCL.so.1"),
                        str(FAKE)], check=True, timeout=120)
        libraries[variant] = directory
    return libraries


def _probe(directory: Path, mode: str, *, gpu: bool = True, threshold: int = 8 << 20) -> dict:
    env = {**os.environ, "LD_LIBRARY_PATH": str(directory), "PDT_FAKE_OPENCL": mode,
           "PDT_PROBE_GPU": "1" if gpu else "0", "PDT_PROBE_THRESHOLD": str(threshold),
           "PYTHONPATH": os.pathsep.join(filter(None, [str(SOURCE_ROOT), os.environ.get("PYTHONPATH")]))}
    result = subprocess.run([sys.executable, "-c", PROBE], env=env, capture_output=True, text=True,
                            timeout=120, check=True)
    return json.loads(result.stdout)


def test_a_working_device_counts_on_the_gpu(fake_libraries):
    info = _probe(fake_libraries["complete"], "ok")
    assert info["correct"] == [True, True]
    assert (info["gpu_available"], info["gpu_name"], info["gpu_vendor"], info["gpu_compute_units"]) == (
        True, "PDT Fake GPU", "PDT tests", 4)
    assert (info["gpu_dispatches"], info["gpu_fallbacks"], info["gpu_unavailable_reason"]) == (2, 0, "")
    assert info["loaded"] is True


def test_with_gpu_counting_off_the_opencl_library_is_never_loaded(fake_libraries):
    info = _probe(fake_libraries["complete"], "ok", gpu=False)
    assert info["correct"] == [True, True] and info["loaded"] is False
    assert (info["gpu_available"], info["gpu_unavailable_reason"]) == (False, "disabled")
    assert (info["gpu_dispatches"], info["gpu_fallbacks"]) == (0, 0)


def test_buffers_under_the_threshold_stay_on_the_cpu_without_a_fallback(fake_libraries):
    info = _probe(fake_libraries["complete"], "ok", threshold=10 << 20)  # 9 MiB stays, 20 MiB goes
    assert info["correct"] == [True, True]
    assert (info["gpu_dispatches"], info["gpu_fallbacks"]) == (1, 0)


def test_a_buffer_past_the_device_allocation_limit_falls_back_on_memory_limit(fake_libraries):
    info = _probe(fake_libraries["complete"], "small_memory")
    assert info["correct"] == [True, True]
    # 9 MiB fits the 16 MiB allocation limit and a quarter of the 64 MiB memory; 20 MiB does not.
    assert (info["gpu_dispatches"], info["gpu_fallbacks"], info["gpu_fallback_reasons"]["memory_limit"]) == (1, 1, 1)


@pytest.mark.parametrize(("variant", "mode", "reason"), [
    ("incomplete", "ok", "loader"),
    ("complete", "no_platform", "device"),
    ("complete", "no_device", "device"),
    ("complete", "no_limits", "device"),
    ("complete", "context", "context"),
    ("complete", "build", "kernel_build"),
])
def test_an_initialization_failure_names_its_step_and_counts_every_fallback(fake_libraries, variant, mode, reason):
    info = _probe(fake_libraries[variant], mode)
    assert info["correct"] == [True, True]
    assert (info["gpu_available"], info["gpu_unavailable_reason"]) == (False, reason)
    assert (info["gpu_dispatches"], info["gpu_fallbacks"], info["gpu_fallback_reasons"][reason]) == (0, 2, 2)


@pytest.mark.parametrize("mode", ["dispatch", "buffer"])
def test_a_failed_dispatch_falls_back_and_keeps_the_device_online(fake_libraries, mode):
    info = _probe(fake_libraries["complete"], mode)
    assert info["correct"] == [True, True]
    assert (info["gpu_available"], info["gpu_unavailable_reason"]) == (True, "")
    assert (info["gpu_dispatches"], info["gpu_fallbacks"], info["gpu_fallback_reasons"]["dispatch"]) == (0, 2, 2)
