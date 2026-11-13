"""Time GPU against CPU byte counting on this machine, to decide whether --gpu pays off here.

    python tools/gpu_benchmark.py                 # 8 MiB to 512 MiB
    python tools/gpu_benchmark.py --sizes 16 64   # chosen sizes in MiB

Counts one byte value in immutable buffers through the native extension twice per size: on
the OpenCL GPU path (what `pdt scan --gpu` uses) and on the CPU path (the GPU path forced to
fall back with the extension's test hook). The median of several rounds is reported. GPU
counting stays off by default because on the hardware measured so far (see
docs/architecture/NATIVE_ENGINE.md) copying the buffer to the device costs more than
counting it on the CPU.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import project_discovery  # noqa: F401
except ImportError:  # a checkout without an installed package
    sys.path.insert(0, str(ROOT / "src"))

from project_discovery.engine import native  # noqa: E402

MIB = 1024 * 1024


def _median_seconds(payload: bytes, rounds: int) -> float:
    samples = []
    for _ in range(rounds):
        started = time.perf_counter()
        native.count_byte(payload, 10)
        samples.append(time.perf_counter() - started)
    return statistics.median(samples)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sizes", type=int, nargs="+", default=[8, 16, 32, 64, 128, 256, 512], metavar="MIB")
    args = parser.parse_args()
    if not native.native_available():
        print("The C extension is not built: there is no GPU path to measure.")
        return 1
    with native.gpu_configuration(True, MIB):
        info = native.capabilities()
        if not info["gpu_available"]:
            print(f"No usable OpenCL GPU ({info['gpu_unavailable_reason']}): nothing to compare.")
            return 1
        print(f"GPU {info['gpu_name']} ({info['gpu_vendor']}), {info['gpu_compute_units']} compute units, "
              f"{info['gpu_global_memory_bytes'] / 2**30:.1f} GiB; CPU backend {info['backend']}")
        native.count_byte(bytes(range(256)) * 4096, 10)  # the first dispatch builds the command objects
        print("| Buffer | GPU | CPU | GPU / CPU |")
        print("|---:|---:|---:|---:|")
        for size in args.sizes:
            payload = bytes(range(256)) * (size * MIB // 256)
            rounds = 7 if size <= 64 else 3
            gpu = _median_seconds(payload, rounds)
            native.set_gpu_test_fault("dispatch")
            try:
                cpu = _median_seconds(payload, rounds)
            finally:
                native.set_gpu_test_fault(None)
            print(f"| {size} MiB | {gpu * 1000:.1f} ms ({size / 1024 / gpu:.2f} GiB/s) | "
                  f"{cpu * 1000:.1f} ms ({size / 1024 / cpu:.2f} GiB/s) | {gpu / cpu:.2f} |", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
