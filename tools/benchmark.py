"""Generate synthetic corpora and benchmark `pdt scan` on any corpus.

    python tools/benchmark.py generate CORPUS --files 20000 --size-gb 1
    python tools/benchmark.py run CORPUS --output REPORTS [--jobs N] [--executor process]

`run` executes the installed PDT as a subprocess, then appends one JSON line with wall time,
per-phase seconds, throughput and peak memory to --results (default: benchmark-results.jsonl).
It works on any directory, including operator-provided 2GB-100GB+ datasets.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import subprocess
import sys
import time
from pathlib import Path

_SOURCE_SNIPPETS = {
    ".py": "import os\nimport json\n\nclass Service:\n    def handle(self, request):\n"
           "        url = 'https://api.example.org/v1/items'\n        return json.dumps({'u': url})\n",
    ".js": "const express = require('express');\nconst app = express();\n"
           "app.get('/users/:id', (req, res) => res.json({ id: req.params.id }));\n",
    ".go": "package main\n\nimport \"net/http\"\n\nfunc handler(w http.ResponseWriter, r *http.Request) {}\n",
    ".java": "public class Service {\n    public String handle(String input) { return input; }\n}\n",
    ".md": "# Notes\n\nSee https://docs.example.org for details.\n",
    ".yaml": "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - '8080:80'\n",
    ".json": '{"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}}\n',
}
_BINARY_EXTENSIONS = (".bin", ".dat", ".png")


def generate(root: Path, files: int, size_bytes: int, seed: int) -> dict:
    """Write a deterministic mixed corpus of roughly ``files`` files and ``size_bytes``."""
    rng = random.Random(seed)
    root.mkdir(parents=True, exist_ok=True)
    extensions = list(_SOURCE_SNIPPETS) + list(_BINARY_EXTENSIONS)
    # Log-normal sizes with a median near the per-file average, as in real repositories.
    average = max(256, size_bytes // max(1, files))
    written = 0
    for index in range(files):
        depth = rng.randint(1, 6)
        directory = root.joinpath(*(f"d{rng.randint(0, 40)}" for _ in range(depth)))
        directory.mkdir(parents=True, exist_ok=True)
        extension = rng.choice(extensions)
        # lognormvariate(-0.5, 1) has mean 1 (mu = -sigma^2/2), so the corpus totals about
        # --size-gb; (0, 1) has mean e^0.5 and made corpora 65% larger than requested.
        target = int(min(average * 50, max(64, rng.lognormvariate(-0.5, 1.0) * average)))
        path = directory / f"f{index}{extension}"
        with path.open("wb") as stream:
            if extension in _BINARY_EXTENSIONS:
                remaining = target
                while remaining > 0:
                    chunk = min(remaining, 1024 * 1024)
                    stream.write(rng.randbytes(chunk))
                    remaining -= chunk
            else:
                snippet = _SOURCE_SNIPPETS[extension].encode()
                copies = max(1, target // len(snippet))
                block = snippet * max(1, (1024 * 1024) // len(snippet))
                per_block = len(block) // len(snippet)
                while copies > 0:  # in chunks, as binary files are written
                    count = min(copies, per_block)
                    stream.write(block if count == per_block else snippet * count)
                    copies -= count
        written += path.stat().st_size
    return {"root": str(root), "files": files, "bytes": written, "seed": seed}


def _largest_child_rss() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


# Exit codes of a scan that wrote its report: clean, a --fail-on hit, and incomplete (--strict).
_REPORTED_EXIT_CODES = {0, 1, 3}


def run(corpus: Path, output: Path, extra: list[str], results: Path, label: str | None) -> dict:
    command = [
        sys.executable, "-m", "project_discovery", "scan", str(corpus),
        "--output", str(output), "--format", "json", "--quiet", *extra,
    ]
    report_path = output / "discovery-report.json"
    # A report left by an earlier run must never be read as this run's result.
    report_path.unlink(missing_ok=True)
    started = time.perf_counter()
    completed = subprocess.run(command, check=False)
    wall = time.perf_counter() - started
    base = {
        "label": label,
        "corpus": str(corpus),
        "exit_code": completed.returncode,
        "arguments": extra,
        "host": {"system": platform.system(), "machine": platform.machine(), "cpus": os.cpu_count()},
        "wall_seconds": round(wall, 2),
    }
    if completed.returncode not in _REPORTED_EXIT_CODES or not report_path.is_file():
        # No throughput figures for a run that produced no report: they would be invented.
        result = {**base, "failed": True, "reason": (
            f"pdt scan exited {completed.returncode}" if report_path.is_file()
            else f"pdt scan exited {completed.returncode} without writing {report_path.name}"
        )}
        with results.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(result, sort_keys=True) + "\n")
        return result
    report = json.loads(report_path.read_text(encoding="utf-8"))
    metrics = report["metrics"]
    performance = metrics.get("performance", {})
    result = {
        **base,
        "failed": False,
        "files": metrics.get("file_count"),
        "bytes": metrics.get("total_bytes"),
        "findings": metrics.get("finding_persistence", {}).get("record_count"),
        "errors": len(report.get("errors", [])),
        "executor": metrics.get("execution", {}).get("executor"),
        "workers": metrics.get("execution", {}).get("worker_count"),
        "phase_seconds": performance.get("phase_seconds"),
        "files_per_second": round((metrics.get("file_count") or 0) / max(wall, 1e-9), 1),
        "megabytes_per_second": round((metrics.get("total_bytes") or 0) / 1e6 / max(wall, 1e-9), 2),
        "coordinator_peak_rss_bytes": performance.get("peak_rss_bytes"),
        "largest_process_peak_rss_bytes": _largest_child_rss(),
    }
    with results.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(result, sort_keys=True) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="Create a deterministic synthetic corpus")
    gen.add_argument("root", type=Path)
    gen.add_argument("--files", type=int, default=10_000)
    gen.add_argument("--size-gb", type=float, default=0.25)
    gen.add_argument("--seed", type=int, default=1)
    bench = sub.add_parser("run", help="Scan a corpus and record performance")
    bench.add_argument("corpus", type=Path)
    bench.add_argument("--output", type=Path, required=True)
    bench.add_argument("--results", type=Path, default=Path("benchmark-results.jsonl"))
    bench.add_argument("--label", default=None)
    args, extra = parser.parse_known_args()
    if args.command == "generate":
        print(json.dumps(generate(args.root, args.files, int(args.size_gb * 1024**3), args.seed), indent=2))
        return
    result = run(args.corpus, args.output, extra, args.results, args.label)
    print(json.dumps(result, indent=2))
    if result["failed"]:
        # A scripted campaign must see the failure, not a normal-looking line.
        raise SystemExit(result["exit_code"] or 1)


if __name__ == "__main__":
    main()
