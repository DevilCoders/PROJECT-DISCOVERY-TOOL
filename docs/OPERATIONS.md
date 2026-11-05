# Operations Guide

How to run PDT on real repositories, including multi-gigabyte and 100 GB+ trees, and how to
read its exit codes and performance data.

## Before a large scan

1. **Check the installation:** `pdt capabilities` lists the native backends (C/SIMD, OpenCL GPU,
   C++ signatures, Rust walker), optional parsers and every analyzer. Use `--json` to keep the
   output with your scan records.
2. **Place the output outside the target.** PDT refuses an output directory inside the scanned
   tree. Use a fast local disk with free space of roughly 1–2% of the scanned size for the
   inventory database and reports, plus up to about 5 GB for the code index of a very large
   source tree (see [Code index and `pdt query`](#code-index-and-pdt-query)).
3. **Antivirus on Windows.** Microsoft Defender scans each file the first time it is opened.
   On a freshly copied corpus the inventory phase was measured 18× slower on the first run
   than on the second (23 s vs 1.3 s for 2,000 files). Consider a Defender exclusion for the
   scan target and output directories on dedicated scan hosts.
4. **Optional Tree-sitter grammars must be provisioned explicitly.** PDT never downloads
   grammars. With `tree-sitter-language-pack` 1.23+, download the grammars you need in a
   separate, deliberate step, for example
   `python -c "import tree_sitter_language_pack as t; t.download(['python', 'rust'])"`.
   Unprovisioned grammars are reported as `UNKNOWN`.

## Scan modes

| Goal | Command |
|---|---|
| Full analysis | `pdt scan /src --output /reports/src` |
| Fast metadata inventory (no content reads) | `pdt scan /src --output /reports/src --inventory-only` |
| Continue an interrupted scan | rerun the same command with `--resume` |
| Skip content of huge files | `--skip --max-file-mb 512` (skipped files stay inventoried) |
| Prune directories explicitly | `--exclude-dir node_modules --exclude-dir build/cache` |
| CI gate | `pdt scan . --output ../pdt --fail-on HIGH --strict --quiet --no-color` |

### Parallelism

`--executor auto` (the default) uses worker processes for inventories of 1,000 files or more
and threads for smaller ones. Analyzers are CPU-bound Python, so threads share one interpreter
lock and processes give real parallelism. `--jobs N` sets the worker count (`0` = automatic,
at most 8); on hosts with many cores, try `--jobs` equal to the number of physical cores.
Worker processes never write to the scan databases: they return results, and the coordinator
persists them in deterministic order. If a worker dies (a native fault or an OOM kill), the
pool is restarted and the affected batch is re-run file by file, so only the culprit file is
reported as an error.

### Resuming

Ctrl-C (or SIGINT to the PDT process) stops the scan with exit code 130. Worker processes
are terminated immediately rather than finishing their batches, and everything already
persisted is kept.

`--resume` reuses the stored inventory and findings in `OUTPUT/.pdt-cache/inventory.sqlite3`
when that inventory finished traversal for the same root. Files already hashed and analyzed are
skipped; the rest are analyzed, then the import graph, architecture layout and reports are
rebuilt. Files added or removed after the original traversal are not picked up: run a fresh
scan for a current view. When no resumable inventory exists, PDT warns and starts a fresh scan.

## Code index and `pdt query`

During analysis, PDT stores code facts (symbols, call sites, referenced names, imports and
domain facts) in `OUTPUT/.pdt-cache/inventory.sqlite3`, in the same transaction as each
file's findings, so `--resume` keeps them consistent. After analysis, the `code_index` phase
builds the call graph, module graph and domain summaries from them
(`metrics.code_index` in the JSON report). `--inventory-only` scans skip it.

Storage is bounded so a 100 GB+ repository cannot exhaust the disk or the index phase:

| Bound | Limit |
|---|---|
| Per file | 5,000 symbols, 20,000 call sites, 10,000 referenced names, 5,000 domain facts |
| Per table | 5 million symbols, 10 million call sites, 20 million references, 5 million facts |
| Call graph | 500,000 resolved edges for cycle detection |
| Modelled file size | 4 MiB (larger files are reported as `UNKNOWN`) |

A bound that is reached produces an `UNKNOWN` "Code index truncated" finding. Results that
depend on the index (call graph, unreferenced functions, test links) are then incomplete,
while per-file findings are unaffected.

Measured on 4,684 real third-party files (2,061 modelled sources, 65 MB): the index held
293,632 rows in 41.6 MB, about 20 KiB per modelled source file, and the `code_index` phase
took 1.0 s of a 30 s scan. At the table ceilings the index stops growing at roughly 5 GB, so
reserve that much on top of the inventory for very large source trees.

Look up the index of a finished scan:

```bash
pdt query /reports/src --symbol Engine.run          # definitions
pdt query /reports/src --callers parse_config       # call sites of a function
pdt query /reports/src --callees Engine.run --limit 50
pdt query /reports/src --references TOKEN_TTL --json
```

## Third-party plugins

Installed analyzer plugins run in sandboxed host processes (`--plugin-isolation sandbox`, the
default). At start-up, PDT prints one line per plugin naming the sandbox mechanisms in use and a
warning for any restriction the platform cannot enforce. `pdt capabilities` shows the same
information without running a scan.

- A plugin that hangs is stopped after `--plugin-timeout` seconds (default 60) per request. That
  file gets an `UNKNOWN` coverage finding, and the next file uses a new host.
- After 3 consecutive host failures, PDT disables the plugin for the rest of the scan and says so
  in a coverage finding. `--strict` then exits with status 3.
- `--plugin-memory-mb` (default 4096, `0` = no limit) caps each host on Linux and Windows.
- Each file a plugin analyzes is copied to `OUTPUT/.pdt-cache/plugins/`, one file at a time per
  host. Files over 1 GiB are not handed to plugins. The directory is removed when the scan ends.
- On Linux, `sandbox` mode needs Landlock (Linux 5.13+, with `landlock` in the active LSM list).
  Without it, plugins are refused with a diagnostic. `--plugin-isolation process` runs them out of
  process without OS restrictions, and `off` runs them inside PDT. Use either only for plugins you
  trust.
- On Windows, the sandbox cannot restrict file reads or network access. Prefer Linux or macOS for
  plugins you do not fully trust.

Isolation adds about 0.3–1.1 ms per file that a plugin handles (2,000 files, 4 workers, on Linux
and Windows).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed (findings may exist) |
| 1 | `--fail-on`: a CONFIRMED or INFERRED finding at or above the given severity |
| 2 | Invalid usage or a fatal error (message on stderr) |
| 3 | `--strict`: file, analyzer or traversal errors left the scan incomplete |
| 130 | Interrupted (Ctrl-C) |

`UNKNOWN` findings describe coverage gaps such as budgets, parse failures and missing parsers.
They never trigger `--fail-on`; use `--strict` to gate on completeness.

## Performance data

Every JSON report contains `metrics.performance`:

- `phase_seconds`: inventory, analysis, cache maintenance, python_graph, code_index and
  architecture.
- `files_per_second` and `bytes_per_second` up to report writing.
- `peak_rss_bytes`: the coordinator process's peak resident memory. Worker processes are
  separate; see `tools/benchmark.py` for the largest-process figure on POSIX.

The terminal summary also prints phase timings, including report writing.
`tools/benchmark.py run` appends these figures to a JSON-lines file for comparison across runs
(see [BENCHMARKS.md](BENCHMARKS.md)).

## Local vulnerability database

```bash
pdt vuln-db import /data/osv/all.zip --db ~/.pdt/advisories.sqlite3   # OSV bundle, offline
pdt vuln-db status --db ~/.pdt/advisories.sqlite3
pdt scan /src --output /reports/src --vuln-db ~/.pdt/advisories.sqlite3
```

The database is opened read-only during scans. Refresh it by importing a newer snapshot;
`status` reports the snapshot age. Databases created by 0.1.0 are migrated to indexed lookups
the first time they are opened for import or status.
