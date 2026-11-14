"""Measure what a large file's repeated reads cost next to its analysis.

    python tools/read_pass_benchmark.py              # a 64 MiB text file
    python tools/read_pass_benchmark.py --mib 256

Files up to 4 MiB are read once and shared by every analyzer. A larger file is hashed in one
streaming pass, and each analyzer then reads its own bounded window, which the operating
system's page cache serves after the first pass. This tool times the hash pass, one verified
read and one UTF-8 decode of the file, scans it, and compares the re-reads and decodes of
the analyzers that read it in full (metrics.analysis_budgets) with their analysis time.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import project_discovery  # noqa: F401
except ImportError:  # a checkout without an installed package
    sys.path.insert(0, str(ROOT / "src"))

from project_discovery.cli import run_scan  # noqa: E402
from project_discovery.core.source_utils import open_verified_binary  # noqa: E402
from project_discovery.inventory.scanner import sha256_file  # noqa: E402

MIB = 1024 * 1024


def _timed(action) -> float:
    started = time.perf_counter()
    action()
    return time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mib", type=int, default=64, help="size of the text file to measure (default: 64)")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        path = project / "big.txt"
        line = b"value = token_" + b"a" * 200 + b"\n"
        with path.open("wb") as stream:
            for _ in range(args.mib * MIB // len(line)):
                stream.write(line)
        size = path.stat().st_size
        sha256_file(path)  # the first read: from disk into the page cache
        hashing = _timed(lambda: sha256_file(path))

        def read_once() -> None:
            with open_verified_binary(path) as stream:
                while stream.read(8 * MIB):
                    pass

        reading = _timed(read_once)
        payload = path.read_bytes()  # read before the decode is timed
        decoding = _timed(partial(bytes.decode, payload, "utf-8"))
        payload = b""
        output = Path(directory) / "out"
        total = _timed(lambda: run_scan(project, output, {"json"}, 128, quiet=True, executor="thread"))
        budgets = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["analysis_budgets"]
    readers = {name: entry["bytes_read"] for name, entry in budgets["analyzers"].items() if entry["bytes_read"] >= MIB}
    analysis = sum(entry["seconds"] for entry in budgets["analyzers"].values())
    rereads = sum(readers.values()) / size * reading
    decodes = len(readers) * decoding
    print(f"{size / MIB:.0f} MiB text file: hash pass {hashing * 1000:.0f} ms, one verified read "
          f"{reading * 1000:.0f} ms, one UTF-8 decode {decoding * 1000:.0f} ms")
    print(f"{len(readers)} analyzers read it: " + ", ".join(f"{name} {value / MIB:.0f} MiB" for name, value in readers.items()))
    print(f"analysis {analysis:.2f} s of a {total:.2f} s scan; their re-reads cost about {rereads * 1000:.0f} ms "
          f"({rereads / analysis * 100:.1f}%) and their decodes about {decodes * 1000:.0f} ms "
          f"({decodes / analysis * 100:.1f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
