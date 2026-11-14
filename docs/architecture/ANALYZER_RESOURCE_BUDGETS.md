# Analyzer resource budgets

These are per-analyzer safety limits and one scan-wide memory budget, not a scan-size policy. Every analyzer call on a file has time, memory, CPU and read budgets, configurable per scan and per analyzer domain; `--max-memory-mb` budgets the whole scan's memory; the byte, line and entry limits each analyzer declares are fixed in code.

## Time and memory budgets

| Budget | Default | Option | Applies to |
|---|---:|---|---|
| Time per analyzer and file | 120 s | `--analyzer-timeout SECONDS` (`0`: none) | Every built-in and in-process plugin analyzer call |
| Resident-memory growth per analyzer and file | 2048 MiB | `--analyzer-memory-mb MB` (`0`: none) | The same calls, on Linux, Windows and macOS |
| CPU time per analyzer and file | none | `--analyzer-cpu-seconds SECONDS` (`0`: none) | The same calls: the analyzing thread's CPU clock, sampled every 50 ms (Linux and Windows) |
| Bytes read per analyzer and file | none | `--analyzer-read-mb MB` (`0`: none) | The same calls: the bytes they read through the verified readers, counted as they are read |
| Per-domain override | none | `--domain-budget DOMAIN:timeout=S,memory=MB,read=MB,cpu=S` | The analyzers of that domain; the most permissive override of an analyzer's domains applies |
| Resident memory of the whole scan | none | `--max-memory-mb MB` (`0`: none; at least 256) | The coordinator and its analysis worker processes: back-pressure on new work, and a cap on every call's memory budget ([below](#scan-memory-budget)) |
| Isolated plugin hosts | 60 s per request, 4096 MiB per host (Linux and Windows) | `--plugin-timeout`, `--plugin-memory-mb` | Sandboxed and process-isolated plugins |

A watchdog thread samples the running calls every 50 ms (`engine/budgets.py`). A call past a budget receives `AnalyzerBudgetExceeded`, a `BaseException`, at its next Python bytecode, so an analyzer's `except Exception` cannot swallow it. The engine discards the call's findings and code facts for the file and records an `UNKNOWN` `analysis_coverage` finding naming the analyzer, the file, the budget and what was used; the other analyzers still run. Memory is the growth of the process's resident set (Linux `/proc/self/statm`, Windows working set, macOS `task_info`) since the call started. `metrics.analysis_budgets` records the configuration, every stop and each analyzer's time and sampled memory; the terminal, Markdown and HTML reports show them.

A single long C call (one regular-expression search, a blocking read) finishes before the stop takes effect, and a memory spike between two samples is not seen. With the thread executor the analyzers share one process, so memory growth includes concurrent calls.

## Scan memory budget

`--max-memory-mb MB` budgets the whole scan (`ScanMemoryBudget` in `engine/budgets.py`). The scan's memory is the coordinator's resident set plus each analysis worker process's, read when the coordinator is about to queue work, at most every 50 ms: Linux `/proc/PID/statm`, Windows `GetProcessMemoryInfo`, macOS `proc_pidinfo`, about 5 to 13 µs a process. On Linux, pages several of these processes share (what a forked worker inherited copy-on-write, shared libraries) count once: the proportional set size (`/proc/PID/smaps_rollup`) calibrates those reads whenever workers start and every 10 s. It walks page tables, about 13 ms per GiB resident, so it is read for at most about 1% of the coordinator's time. On Windows and macOS every process's resident set counts in full, so the total errs high by the shared library pages.

- While the scan is at or over the budget, the coordinator collects queued batches, oldest first, before it queues another, so fewer calls run at once. Results keep their order.
- Over the budget with nothing in flight, it queues the batch anyway and counts it: the scan runs one batch at a time and never stalls, and the terminal warns that the budget was not met.
- A running call is not stopped by the scan budget, but no call's own memory budget (`--analyzer-memory-mb`, a domain's `memory=`, `0` included) exceeds it, since one call growing past it takes the whole scan over.
- It applies to local scans and remote checkouts (file analysis and Python import parsing) and to `--no-download` scans (fetching and analysis).

`metrics.analysis_budgets.scan_memory` reports the limit, `enforced`, `processes_measured`, `shared_pages` (`proportional` or `per_process`), the largest sampled total (`peak_mb`), the `samples`, the `waits` (batches collected early), `held_seconds` and `over_budget_submissions`; the terminal summary, the Markdown report and the HTML report show them.

Outside the budget: memory between two samples; the coordinator's passes after the analysis (the dependency graph, the code index and the reports, which read store-backed records); and sandboxed plugin hosts, which `--plugin-memory-mb` limits one by one. Idle workers are not replaced to give memory back: measured on 2026-11-13, a process keeps 2 to 32 MiB after analyzing an 11 to 33 MiB file (Windows and Linux), so a replacement would release little.

Measured on Linux (2026-11-13, Python 3.14, 6 workers, 1,200 files): the plain sum of the resident sets was 298 MiB with the fork start method (the default before Python 3.14) and 290 MiB with forkserver; the calibrated totals were 106 MiB and 146 MiB.

## Per-analyzer content limits

Each built-in analyzer declares the limits it applies to one file in its `limits` attribute (`core/limits.py`): the most of a file it reads, how it reads, its other caps and what a file past a limit gets. The declaration references the constants the analyzer applies, and the table below is generated from it. During a scan the engine records, for every analyzer call, the bytes it read through the verified readers and each limit it reached: a bounded read past its budget, a size check, or a cap the analyzer reports. `metrics.analysis_budgets` lists them per analyzer with the declarations (`analyzer_limits`), and the terminal, Markdown and HTML reports show them.

<!-- BEGIN GENERATED LIMITS: python tools/analyzer_limits.py --write -->

| Analyzer | Reads | Per-file budget | Other limits | At the limit |
|---|---|---:|---|---|
| `accessibility-markup` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `ai-ml-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `api-clients` | whole | 16 MiB | head_bytes 8 KiB; operations 2,000 | no finding past the budget: the generator's mark is not read |
| `api-contracts` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth, read or parse failure |
| `api-endpoints` | stream | 32 MiB | python_ast_bytes 4 MiB; line_chars 262,144; facts 500; handler_text_chars 8,388,608 | UNKNOWN or partial finding at the byte, Python AST or fact limit |
| `api-graphql` | whole | 16 MiB | evidence_lines 100 | UNKNOWN finding for a GraphQL file past the budget |
| `api-policies` | whole | 16 MiB | evidence_lines 100 | no finding past the budget |
| `api-protocols` | whole | 16 MiB | head_bytes 8 KiB; evidence_lines 100 | UNKNOWN finding for a contract past the budget |
| `api-rpc` | whole | 16 MiB | evidence_lines 100 | UNKNOWN finding for an IDL file past the budget |
| `api-type-classifier` | stream | 32 MiB | line_bytes 256 KiB; evidence_per_style 20 | UNKNOWN or partial finding at the byte limit |
| `archive-intelligence` | sampled | — | entries 200,000; index_bytes 64 MiB; member_sample_bytes 1 MiB; archive_sample_bytes 32 MiB; wall_seconds 8; tar_decompressed_bytes 4 GiB; uncompressed_bytes 16 GiB; compression_ratio 1,000; nested_depth 1; nested_bytes 64 MiB | UNKNOWN or partial finding at an index, entry, sample, decompression or wall-time limit |
| `build-manifests` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth, read or parse failure |
| `code-index` | model | 4 MiB | — | UNKNOWN finding for a file past the code model budget |
| `concurrency` | model | 4 MiB | — | Files past the code model budget are not modelled; code-index reports them |
| `configuration-intelligence` | whole | 16 MiB | keys 100,000; risk_lines 100 | UNKNOWN finding on oversize, growth or read failure |
| `coverage-artifacts` | whole | 64 MiB | — | UNKNOWN finding on oversize, growth, read or parse failure |
| `data-exposure-indicators` | stream | 64 MiB | line_bytes 256 KiB; evidence_lines 100; code_excerpts 20 | UNKNOWN or partial finding at the byte limit |
| `dataflow` | model | 4 MiB | exported_facts 500; outgoing_facts 500 | A "Data-flow analysis truncated" UNKNOWN finding when a cap cuts the analysis |
| `dependency-lockfiles` | whole | 128 MiB | package_entries 250,000 | UNKNOWN finding at the byte or entry limit |
| `dependency-manifests` | whole | 32 MiB | — | UNKNOWN finding on oversize, growth, read or parse failure |
| `deployment-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `document-formats` | whole | 32 MiB | binary_document_bytes 16 MiB; pdf_pages 5,000; extracted_chars 16,777,216; docx_entries 10,000; docx_uncompressed_bytes 32 MiB | UNKNOWN finding at an input, page, text, entry or uncompressed-byte limit |
| `embedded` | whole | 4 MiB | — | UNKNOWN finding for a file past the budget |
| `firmware` | sampled | 64 MiB | header_sample_bytes 1 MiB; table_bytes 4 MiB; string_scan_bytes 8 MiB; uf2_blocks 65,536 | Partial header results; UNKNOWN finding for an over-budget build file |
| `frontend` | whole | 2 MiB | — | UNKNOWN finding for a file past the budget |
| `game-engine-intelligence` | whole | 64 MiB | project_file_bytes 16 MiB | UNKNOWN finding on oversize, growth or read failure |
| `hdl` | whole | 8 MiB | design_units 2,000 | UNKNOWN finding for a file past the budget |
| `identity-intelligence` | whole | 16 MiB | evidence_lines 100 | UNKNOWN finding on oversize, growth, read or AST resource failure |
| `integration-points` | whole | 2 MiB | facts 400 | UNKNOWN finding for an over-budget manifest; facts past the cap are not recorded |
| `license-intelligence` | prefix | 8 MiB | header_window_bytes 64 KiB | Source and license files are checked within the header window; an unparsable manifest is an UNKNOWN finding |
| `local-vulnerability-intelligence` | whole | 128 MiB | package_entries 250,000 | UNKNOWN finding at the byte or entry limit |
| `localization-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `markdown` | whole | 32 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `messaging-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `migration-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `mobile-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `network-indicators` | stream | 64 MiB | line_bytes 256 KiB; indicators 25,000; evidence_lines 100 | UNKNOWN or partial finding at the byte, line or indicator limit |
| `network-sockets` | model | 4 MiB | call_sites 1,000; evidence_lines 100 | Files past the code model budget are not modelled (code-index reports them; an oversized Ruby file is an UNKNOWN finding); call sites past the per-file limit are an UNKNOWN finding |
| `nosql-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `observability-intelligence` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `operating-system-intelligence` | stream | — | chars 67,108,864; line_chars 262,144; evidence_lines 20 | UNKNOWN finding when the character budget is reached |
| `performance-hotspots` | model | 4 MiB | — | Files past the code model budget are not modelled; code-index reports them |
| `prisma-schema` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `python-ast` | whole | 4 MiB | syntax_tree_lines 100,000; symbol_evidence 200 | UNKNOWN finding on oversize or parse failure |
| `resource-management` | model | 4 MiB | — | Files past the code model budget are not modelled; code-index reports them |
| `ros-intelligence` | whole | 16 MiB | interface_bytes 4 MiB | UNKNOWN finding on oversize, growth or read failure |
| `secret-patterns` | stream | 64 MiB | chunk_bytes 8 MiB; overlap_chars 4,096; findings 10,000 | UNKNOWN or partial finding at the byte or finding limit |
| `secure-code-patterns` | whole | 16 MiB | rule_locations 100; excerpts_per_finding 20 | UNKNOWN finding on oversize, growth, read or AST resource failure |
| `shaders` | whole | 4 MiB | spirv_words 2,000,000 | UNKNOWN finding for a file past the budget |
| `sql-schema` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `test-discovery` | whole | 16 MiB | — | UNKNOWN finding on oversize, growth or read failure |
| `tree-sitter-polyglot` | whole | 16 MiB | error_locations 10,000 | UNKNOWN finding on oversize, growth, read or parser failure |
| `type-systems` | whole | 2 MiB | — | UNKNOWN finding for a file past the budget |
| `vcs-hosting-intelligence` | whole | 2 MiB | wc_db_bytes 256 MiB; sqlite_steps 50,000,000; sqlite_value_bytes 16 MiB; hg_index_bytes 64 MiB; hg_inline_index_bytes 8 MiB; jj_checkout_bytes 64 KiB; listed_entries 100,000 | An unreadable or over-budget file contributes no signals; the limit reached is recorded |

Read modes:

- `whole`: Reads the whole file within its budget; a larger file is not analyzed.
- `stream`: Streams the file up to its budget; the rest is not analyzed.
- `prefix`: Reads a fixed prefix by design.
- `sampled`: Reads bounded samples, tables and members, never the whole file.
- `model`: Uses the shared code model (one bounded read per file and worker).
- `none`: Reads no file content.

<!-- END GENERATED LIMITS -->

How the analyzers read:

- Reads go through a verified descriptor (no symlinks, identity checked against the inventory) and take at most the budget plus one byte, so a file that grew during the read is detected.
- Python sources are decoded by their PEP 263 declaration. Every Python syntax tree shares one budget, because a tree costs 100-200 times its source in memory.
- `secret-patterns` scans binary chunks with an overlap, so a secret split across two chunks is found.
- `archive-intelligence` checks the ZIP end-of-central-directory records before `ZipFile.infolist()` materializes the index, samples members in memory without extracting them, and checks its wall-time and TAR decompression limits cooperatively, between operations and inside its reads.
- `document-formats` checks DOCX package metadata and compression before python-docx opens it.
- `firmware` reads headers and tables through a verified binary stream with seeks, never the whole file.
- Lockfiles are parsed from one bounded buffer; the entry cap limits the retained packages, not the parser's object graph.

## Shared subsystems

| Subsystem | Limit | Input strategy | Limit outcome |
|---|---:|---|---|
| Python import graph | 4 MiB and 100,000 lines per module; per scan 250,000 modules, 10,000,000 edges, 5,000,000 unresolved imports and 1,000,000 skipped modules | AST extraction over inventoried source; the graph's lists are rows of the scan database, streamed into the JSON report and sampled (10,000 each) into the HTML report | UNKNOWN for skipped or over-budget modules and for a list past its ceiling |
| Shared code model | 4 MiB per file | Bounded read; Python syntax tree or linear-time structural lexer, built once per file and worker | Each analyzer using the model records the limit; `code-index` reports the file as UNKNOWN |
| Code facts | Per file: 5,000 symbols, 20,000 call sites, 10,000 references, 5,000 domain facts. Per table: 5M symbols, 10M calls, 20M references, 5M facts | Stored with the file's findings in bounded SQLite batches | "Code index truncated" UNKNOWN finding; index-based results incomplete |
| Code index passes | 500,000 resolved call-graph edges for cycle detection; 5,000 items per integration list; network service map: 1,000 ports (20 declarations and 20 listeners each) and 1,000 items in each other list; endpoints: 20,000 routes, mounts nested at most 8 deep; GraphQL: 5,000 schema fields, resolvers and operations; RPC: 5,000 services, methods with HTTP routes, generated services, servers and clients; protocols: 5,000 endpoints, channels, topics, methods and operations, 2,000,000 wildcard topic comparisons; contract links: 5,000 operations and clients, 50,000 HTTP calls; endpoint catalog: 5,000 routes, 1,000 listed | Read-only connection and temporary tables | Edge limit recorded in `metrics.code_index`; a network service list at its cap is an UNKNOWN finding; per-pass errors become UNKNOWN findings |
| Data flow (Python) | 50,000 statement visits per function and round; summaries iterate until unchanged (at most 64 rounds); 4 passes per loop; 6 source labels per value (parameter labels are always kept); 500 exported summaries and 500 tainted calls per file | Syntax-tree interpretation of relevant functions only | Interrupted functions, a cap that stops a changing iteration and facts beyond the caps: a "Data-flow analysis truncated" UNKNOWN finding |
| Data flow (lexical languages) | 20,000 assignments and sinks per function region; 200,000 summary events per file; 3 helper rounds; 200 outgoing calls; 4,000 characters per right-hand side; 500 exported summaries and 500 tainted calls per file | Cleaned text of the code model | Any cut: a "Data-flow analysis truncated" UNKNOWN finding |

## Global oversized-file policy

The scan CLI's global oversized-file skip is opt-in. Without --skip, PDT does not suppress file content analysis globally based on file size. With --skip, files over --max-file-mb remain in inventory and receive an explicit skip reason.

An analyzer may apply its own specialized budget regardless of --skip. Such a result must be visible as UNKNOWN/partial with a reason and must never be represented as a clean assessment. A per-analyzer budget stop does not remove the file from inventory or prevent unrelated streaming analyzers from inspecting it.

## Important limitations

- The declared byte, line and entry limits are fixed in code; only the time and memory budgets are configurable.
- Lockfile text formats iterate lines from a bounded in-memory content buffer; JSON/TOML lockfiles are parsed as bounded in-memory objects. The 250,000 entry cap limits retained package results, not the initial JSON/TOML parser object graph.
- Core Python AST inventory, Python security AST, import graph and Python endpoint readers now use race-safe limit + 1 byte reads. The other listed parser-based analyzers also use bounded reads; newly added analyzers must follow the same contract.
- The archive wall-time limit is cooperative. It is checked between metadata/member operations and regex matches; it cannot preempt a blocked filesystem read or interrupt a single in-progress Python regular-expression call.
- Nested archives share the top-level archive's wall time, a depth limit (`nested_depth`) and, when they are buffered in memory, its `nested_bytes` budget; the declared-uncompressed budget applies to each archive record. A nested TAR stream gets its own decompression budget (`tar_decompressed_bytes`) rather than a share of its container's.
- The vulnerability lockfile limit is a format-parser admission limit, not a streaming parser; files below the limit may still need significant memory.
- Inventory records, findings, diagnostics and code facts are persisted in SQLite and read back lazily, the JSON report is streamed, and the HTML report embeds bounded subsets (`embedded_limits` in the payload). The Python import graph's lists are store rows (its module indexes and a compact integer adjacency stay in memory); the other report metrics and each per-file analyzer's working set are still held in memory. Tests scan a 128 MiB text file and a 1 GiB sparse file with a bounded Python heap, refuse files that change after inventory or during analysis, and finish with FIFOs in the tree or swapped in for a file. Bounded-memory behavior at 100 GB+ is unverified until the large-corpus benchmarks run.

## Release requirements

1. Make the declared byte budgets configurable per domain within safe ceilings: a parser that builds its whole input in memory (a syntax tree, a JSON document) cannot have its budget raised freely.
2. Record a per-file analyzer status (completed, partial, budget-stopped, unsupported, error) in the inventory, next to the per-analyzer totals in the metrics.
3. Add adversarial tests for file mutation inside a single analyzer read, long lines, deeply nested ASTs, malformed parser input, archive bombs and wall-time boundaries.
4. Benchmark wall time, throughput and peak RSS over 2GB, 10GB, 50GB and 100GB+ corpora.
5. Keep every budget-stopped outcome distinguishable from excluded, skipped, unsupported, parse-error and clean-complete states.
