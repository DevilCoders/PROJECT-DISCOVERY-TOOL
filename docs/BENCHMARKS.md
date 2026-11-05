# Benchmarks

`tools/benchmark.py` measures `pdt scan` on synthetic or real corpora and records the results
as JSON lines.

```bash
# Optional: build a deterministic synthetic corpus
python tools/benchmark.py generate /data/corpus-10g --files 400000 --size-gb 10 --seed 1

# Scan any corpus (synthetic or real) and append the measurements to results.jsonl
python tools/benchmark.py run /data/corpus-10g --output /reports/corpus-10g \
    --results results.jsonl --label "10g process" --executor process --jobs 0
```

Arguments after the known options are passed through to `pdt scan`, for example `--jobs`,
`--executor`, `--inventory-only` and `--skip --max-file-mb N`. Each result records the host,
file and byte counts, findings, errors, executor, worker count, wall seconds, per-phase seconds,
files/s, MB/s, coordinator peak RSS and, on POSIX, the largest process's peak RSS.

## Measured results

These are small-scale engineering measurements on one development workstation (Windows 10,
Python 3.12, 16 hardware threads, NVIDIA RTX 3060). They are **not** the 2 GB–100 GB+ release
benchmarks, which remain open until representative corpora are scanned.

| Corpus | Configuration | Wall time | Throughput |
|---|---|---|---|
| 3,000 small source/config files, 11 MB | 0.1.0 engine, threads | 112 s | 27 files/s |
| same | 0.2.0, threads (`--executor thread --jobs 8`) | 98 s | 31 files/s |
| same | 0.2.0, processes (`--executor process --jobs 16`) | 15 s | 197 files/s |
| 2,000 mixed files, 115 MB, warm cache | 0.2.0 processes, before analyzer tuning | 64 s | 1.8 MB/s |
| same | 0.2.0 processes, final | 39 s | 2.9 MB/s |

Findings were identical across executors and before and after tuning.

Plugin isolation cost was measured on 2,000 small text files with 4 workers, using a sandboxed
plugin that reads every file:

| Host | Threads | Processes |
|---|---|---|
| Ubuntu 26.04, 4 cores, Py 3.14 (Landlock + seccomp) | +1.13 ms per file | +0.32 ms per file |
| Windows 10, 16 threads, Py 3.12 (job + untrusted integrity) | +0.64 ms per file | +0.77 ms per file |

The cost covers staging a verified copy and one JSON round trip per supported file, plus one
batched `supports()` round trip per 32 files and host start-up.

Code intelligence cost (2026-11-06, same workstation) on 4,684 real third-party files (65 MB,
2,061 of them modelled source files, mostly Python), measured per analyzer in one process:

| Measure | Result |
|---|---|
| Analysis time, the 35 earlier analyzers | 113.4 s |
| Analysis time, the 12 code-intelligence and domain analyzers | 21.7 s (+19%) |
| Costliest new analyzers per file | code index 2.1 ms (includes building the code model), performance 2.0 ms, data flow 1.8 ms |
| Full `pdt scan` (8 workers, processes) | about 30 s, 156 files/s; `code_index` phase 1.0 s |
| Code index storage | 293,632 rows, 41.6 MB (about 20 KiB per modelled source file) |

## Large-corpus release gate (open)

Planned runs at 2 GB, 10 GB, 50 GB and 100 GB+ on operator-provided data should record, for
each corpus: wall time, files/s, MB/s, peak RSS (coordinator and largest process), report size,
and errors/UNKNOWN counts. Scan each corpus twice so first-access antivirus costs can be
separated from PDT's own cost (see [OPERATIONS.md](OPERATIONS.md)).
