# Production Roadmap

## Mission

PROJECT DISCOVERY TOOL (PDT) is a read-only, comprehensive polyglot project intelligence platform for local directories and remote repositories. It must discover the actual contents and structure of heterogeneous codebases—from multi-gigabyte repositories through 100GB+ workspaces—without assuming one programming language, one framework, one operating system, one architecture, or one deployment model.

The pipeline is:

1. **Inventory:** account for filesystem entries and project artifacts.
2. **Analyze:** run independent language/domain analyzers against bounded inputs.
3. **Correlate:** connect evidence across files, APIs, dependencies, build systems and projects.
4. **Report:** produce comprehensive offline JSON/Markdown/HTML and a focused terminal experience.

No scan may silently omit an entry. Exclusions, parser gaps, budget limits, unsupported archive formats and errors must be represented in the results.

## Release rules

- Work only on `feat/discovery-engine-foundation` and PR #1.
- Never merge into `master`; do not close the PR as complete until release gates pass.
- Keep all proprietary project data local. Only publish PDT implementation, tests and public documentation.
- Target repositories are read-only. Never follow symlinks during traversal, write inside targets, execute code/build scripts, extract archive members, or contact discovered endpoints.
- Findings must include evidence and confidence. A lexical marker is never presented as proof of exploitability, reachability, deployment, user identity or runtime behavior.
- Catalog entries and parser mappings are not completed capabilities. Every capability status must be truthful and test-backed.

## Capability-state definitions

| State | Meaning |
|---|---|
| `recognized` | File extension/name/signature is classified. No semantic support implied. |
| `parser_mapped` | A parser adapter/grammar mapping exists. |
| `parser_available` | Required parser is provisioned locally. |
| `parsed` | Input parsed successfully within documented limits. |
| `partial` | Useful evidence extraction exists but substantial domain coverage is missing. |
| `implemented` | Declared scope has conformance fixtures and accepted behavior. |
| `unknown` | Analysis unavailable, inconclusive or stopped by a resource budget. |
| `excluded` / `skipped` | Content was intentionally omitted with a recorded reason. |

## Status update — 0.2.0 (2026-11-05)

The production-readiness audit ([AUDIT.md](AUDIT.md)) and its remediation landed on this branch: every recorded defect is fixed with regression tests, CI passes on Linux, Windows and macOS for CPython 3.11–3.14 (including native builds and an optional-integrations job), and the scan engine gained multi-process analysis, `--resume`, `--inventory-only`, CI exit codes and performance telemetry. Items below are ticked only where the implementation is complete and verified. Third-party plugins now run in a verified operating-system sandbox (complete on Linux and macOS, partial on Windows; see [PLUGIN_SDK.md](../guides/PLUGIN_SDK.md)). Large-corpus benchmarks (2 GB–100 GB+) and an independent security review remain open release gates.

## Status update — code intelligence (2026-11-06, unreleased)

A shared code model (Python syntax tree; a structural lexer for about 25 brace languages), stored code facts and a cross-file code index now exist, with `pdt query`. Every domain that 0.2.0 only catalogued has a built-in analyzer and is `partial`: symbol index, call graph, type systems, performance, concurrency, memory and resources, data flow and taint (Python inter-procedural and cross-module), embedded, firmware, HDL, graphics shaders, frontend component graphs, and multi-project integration maps. See [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md) and [AUDIT.md §8](AUDIT.md#8-code-intelligence-and-the-formerly-planned-domains).

Inter-procedural taint for the lexical languages and cross-file taint beyond Python landed on 2026-11-06 ([AUDIT.md §10](AUDIT.md#10-inter-procedural-taint-for-the-lexically-modelled-languages)). Python calls on objects whose class the code states resolve since 2026-11-06 ([AUDIT.md §11](AUDIT.md#11-python-receiver-types)). Since 2026-11-12, a provisioned Tree-sitter grammar refines the code model for 16 brace languages ([AUDIT.md §13](AUDIT.md#13-tree-sitter-code-model)). Since 2026-11-13, Python return types the code does not annotate, inherited methods and the values imported factories return are completed across modules ([AUDIT.md §14](AUDIT.md#14-python-classes-the-code-does-not-state)). The HDL design hierarchy is elaborated through parameters, overrides and `generate` constructs since 2026-11-13 ([AUDIT.md §15](AUDIT.md#15-hdl-elaboration-of-generate-blocks-and-parameters)). Next step for these domains: measured index cost on the 100 GB+ corpora.

## Status update — checkbox verification (2026-11-06)

Every checkbox was re-checked against the code and tests, except the online repository scanning items in Phase 5, which are under active development and are re-verified when that work lands. A box is ticked only when the whole item is implemented end to end and covered by tests. An item that is only partly done is either split into a ticked part and an unticked part, or left unticked with a note saying what exists.

## Current branch baseline

The current feature branch has first-pass implementations for filesystem inventory, symlink records, hidden-name markers, directory aggregates, size buckets, common development-directory markers, SQLite fingerprints, Python AST/import graph, language recognition and optional Tree-sitter support. It also contains initial analyzers for documentation, dependencies/licenses, configuration, secrets/PII, secure-code patterns, REST/API contracts and route markers, SQL/NoSQL/ORM/migrations, test/build/CI, containers/deployment/IaC, archives, network indicators, OS/platform markers, ML/AI, ROS, mobile, game engines, frontend/accessibility, localization, observability, coverage and multi-project comparison.

The baseline is not production-ready:
- file, directory, symlink and special-entry records now use lazy SQLite-backed sequences in store-backed CLI scans; directory counters/errors live in bounded SQLite state, and the Python fallback keeps only active scandir iterators (O(depth)). finding records now use lazy SQLite persistence with deterministic content-key deduplication; dependency/architecture correlation state, per-file analyzer working sets and report metrics remain memory targets;
- all development/cache/build trees are traversed by default and only explicitly excluded subtrees are pruned;
- file types come from a validated signature catalog that Python and C++ share (executables, libraries, archives and packages, documents, media, fonts, databases, datasets, models, firmware, filesystem and disk images); formats without a magic number stay `binary/unknown`;
- FIFO/socket/device/unknown special entries have inventory records;
- Windows hidden attributes are captured by the native walker and Python fallback, but system attributes, ACLs and ownership metadata still need cross-platform validation;
- archive index inspection is substantive only for ZIP/TAR; other recognized formats are detection-only;
- ZIP central-directory preflight, archive entry-count/member-byte caps and cooperative ZIP/TAR wall-time budgets now exist; nested-depth, configurable budget policies, comprehensive metadata bounds and adversarial testing remain;
- some domain analyzers are lexical/heuristic; symbols, calls and data flow are now resolved semantically for Python and structurally for the lexically modelled languages, Python receiver classes are inferred where the code states them (annotations, constructors, assignments), other types are not, and framework semantics are pattern-based;
- report and CLI have a working first-pass command-center design, but still need completeness, scale, accessibility and usability gates.

## Phase 0 — Documentation and capability governance

- [x] Refresh root README with current capabilities, limitations, privacy policy, CLI and production criteria.
- [x] Refresh this roadmap before the next implementation block.
- [x] Maintain a generated language/domain capability matrix: status, parser, optional dependency, supported syntax, limitations and fixtures. [CAPABILITY_MATRIX.md](../architecture/CAPABILITY_MATRIX.md) is generated by `tools/capability_matrix.py` from the catalogs and the analyzer registry (level, code model, Tree-sitter grammar, analyzers and test fixtures per language; status and analyzers per domain; the limits of each level), and a test fails when it is stale.
- [x] Ensure README/roadmap claims are generated or reviewed against the analyzer registry and tests. `tests/test_documentation.py` checks the README figures, every documented `pdt` option, links and anchors, the capability matrix and plugin API version 1 against the code; roadmap checkboxes are reviewed at each status update.
- [x] Add release-note and change-log discipline for feature, schema and plugin API changes. [CONTRIBUTING.md](../../CONTRIBUTING.md) sets the policy, the `changelog` workflow fails a pull request that changes `src/` or `native/` without a `CHANGELOG.md` entry, and tests require the report schema version in the changelog and keep plugin API version 1 intact.

## Phase 1 — Filesystem inventory correctness

### Entry model
- [x] Separate file, directory and symlink records.
- [x] Record symlink target text, lexical scope and link permissions without traversing the target.
- [x] Record hidden-name indicators for dotfiles/directories.
- [x] Record Windows hidden attributes in the Rust walker and Python fallback.
- [x] Record Windows system attributes, ACLs and platform-specific ownership metadata. Every record carries the POSIX owner and group IDs and its platform attributes (Windows `FILE_ATTRIBUTE_*` names, macOS file flags), from both walkers; `--security-metadata` adds the Windows owner and group SIDs and DACL, or the Linux POSIX access and default ACLs, and is tested on Windows and Linux. macOS ACLs, Linux inode flags (`chattr`), SELinux labels and file capabilities are not read.
- [x] Add full records for FIFO, socket, block device, character device, junction/reparse point and unknown entry types. Special entries record type, mode, owner and group, attributes, size, modification time and, for devices, major and minor numbers; links and directories record their modification time, and every Windows reparse point names its tag (a junction is a link with `mount_point`). Windows AF_UNIX sockets and WSL FIFOs and device nodes are special entries instead of files. Tests use real FIFOs, sockets and 0:0 character devices on POSIX and AF_UNIX sockets and junctions on Windows, and recorded walker output for block devices, unknown types and WSL entries, which need privileges or WSL to create.
- [x] Add broken-link, self-link, cyclic-link, dangling-relative-link and external-target fixtures. Tests cover broken, self, cyclic, dangling-relative, chained, absolute-internal and external (absolute and relative) symbolic links, a symlinked scan root, Windows junction loops, and broken and external junctions: each link is recorded once with its exact target text and lexical scope, nothing behind it is read, and both walkers agree. On Windows the symbolic-link fixtures need the symlink privilege (Developer Mode or an elevated runner) and are skipped without it.
- [x] Harden symlink target classification against loops, permission failures, path races and platform-specific resolution behavior. Every target is resolved against the finished inventory, never the filesystem (no races): `resolved`, `broken`, `loop` (cycles and the 40/63-link limits), `external`, `unknown` (pruned or unreadable directories, unreadable links) or `unreadable`, with POSIX physical and Windows lexical `..`, case-insensitive matching on Windows and case-insensitive macOS volumes, and drive, UNC and verbatim Windows targets. No-download scans resolve against the tree listing.
- [x] Record directory depth, child counts, aggregate regular-file counts/bytes, marker and pruned state.
- [x] Add empty-directory, fan-out, inode/owner/group and timestamp aggregates where supported. `metrics.inventory_aggregates`: empty directories, fan-out (largest, mean, histogram), hard links from recorded device/inode identities (not in a Windows `--inventory-only` scan, which records none), entries per uid, gid and owner SID, and file modification times (oldest, newest, by year, future, before 1980), in every report format.
- [x] Record per-file byte size, extension, language label, hidden-name flag, mode and size bucket.
- [x] Add robust file signature/MIME detection for executables, libraries, images, audio/video, documents, archives, model/dataset files, firmware and unknown binaries. A catalog of magic-byte rules, each candidate checked by a validator for its family, sets `file_type`, `signature`, `type_detail` and `mime_type` from the first 4 KiB of the content (plus one read for ISO 9660/UDF descriptors and OLE directories): ELF, PE and Mach-O executables, libraries, objects and core files, EFI and .NET images, bytecode, ZIP-based documents and packages, OLE documents, archives, images, audio and video by container and codec, fonts, databases, datasets and models (HDF5, NumPy, Parquet, Arrow, safetensors, GGUF, PyTorch, pickles), firmware, filesystem and disk images, and text formats; other binary content is `binary/unknown` with its entropy. Per-format fixtures and a C++/Python parity test cover the catalog.
- [x] Keep extension-based recognition distinct from verified magic-byte detection. `file_type` comes from the content (`type_source` `signature` or `content`) and from the name only when the content was not read (`name`); `name_type` records what the name suggests, from a separate catalog, and `type_mismatch` flags names and contents that disagree. `language` remains name-based.

### Development and generated dependency trees
- [x] Initial marker catalog for `node_modules`, `.cache`, `.yarn`, `.pnpm-store`, `.npm`, `.gradle`, `.m2`, `.venv`, `vendor`, build outputs and other common workspaces.
- [x] Remove implicit default pruning of dependency/build/cache trees.
- [x] Traverse all recognized trees by default unless the operator explicitly opts out or a documented safety policy marks an entry unknown.
- [x] Add `--exclude-dir NAME` (a directory name, or a path relative to the root or absolute inside it); every pruned subtree keeps its directory record with `pruned` set and the exact `prune_reason`, and pruned counts appear in every report (terminal, Markdown, JSON and the HTML inventory summary).
- [x] Add optional exclusion profile presets. `--exclude-profile` prunes the marked trees of `vcs`, `dependencies`, `build`, `caches`, `ide`, `test-output`, `fuzzing`, `models` or `all`: only confirmed and distinctively named markers, never a possible one; each pruned directory keeps its record and a reason naming the preset and the marker, `metrics.pruned_by_profile` counts them, and `--resume` requires the same presets.
- [x] Add `--inventory-only`: inventory files, directories and links without reading file contents (no hashing or content analyzers), recorded as `metrics.execution.analysis_mode`.
- [x] Add directory-only and deep-analysis controls with explicit semantics. `--development-trees` is `deep` (inventoried and analyzed, the default), `inventory` (every entry recorded, no content read) or `directory-only` (directory records with totals; files, links and special entries counted but not recorded), for confirmed and distinctively named trees only; the semantics table is in OPERATIONS.md, links into directory-only trees resolve as `unknown`, and local and no-download scans behave alike.
- [x] Extend markers for pnpm/npm/yarn/bun, pip/uv/poetry/conda, Maven/Gradle, Cargo, Go modules, NuGet, Composer, Ruby/Bundler, SwiftPM/CocoaPods, Dart/Flutter, .NET, Bazel/Buck/Pants, SCons, CMake, IDE, compiler, fuzzing, model caches and language server caches. `inventory/markers.py` catalogs them by category and ecosystem, with the entries that confirm each, in local and no-download scans alike.
- [x] Add marker confidence and distinguish known dependency stores from arbitrary directories with similar names. `marker_confidence` is `confirmed` (an entry inside or beside the directory, recorded in `marker_evidence`), `name` (a distinctive name) or `possible` (a common name such as `build` or `vendor` that nothing confirmed); names that are mostly source (`packages`, `bin`, `env`, `deps`) are marked only with evidence.

### Oversized files
- [x] Global oversized-file content skipping is opt-in through `pdt scan PATH --skip`.
- [x] Keep all oversized files in inventory when `--skip` is active.
- [x] Ensure `--skip` is the only global size threshold gate; default scanning must not silently skip content based only on size. Files above 4 MiB are hashed in a streaming pass instead of being prefetched, but they are still analyzed.
- [x] Give every analyzer a documented per-file byte/time/memory budget and an explicit `UNKNOWN`/partial result when it cannot continue. Byte budgets are documented in [ANALYZER_RESOURCE_BUDGETS.md](../architecture/ANALYZER_RESOURCE_BUDGETS.md); every built-in and in-process plugin analyzer call on a file runs under `--analyzer-timeout` (default 120 s) and `--analyzer-memory-mb` (default 2048 MiB of resident-memory growth, sampled every 50 ms on Linux, Windows and macOS), and a stopped call's findings give way to an `UNKNOWN` coverage finding. Isolated plugins keep `--plugin-timeout` and `--plugin-memory-mb`. A single long C call (one regex search) finishes before a stop takes effect.
- [x] Support per-domain override budgets and show them in JSON/HTML/terminal reports: `--domain-budget DOMAIN:timeout=S,memory=MB`, reported in `metrics.analysis_budgets`, the terminal summary and the Markdown and HTML reports with every stop and each analyzer's time and memory. Byte budgets are not configurable yet.
- [x] Test 128MiB, 1GiB, sparse, changing and non-seekable files without unbounded memory use: a 128 MiB text file (hashed in full, analyzed under a 5-second analyzer budget) and a 1 GiB sparse file scan with a Python heap below 64 MiB; files changed after inventory or during analysis are refused and named; FIFOs in the tree, and a FIFO swapped in for a file after its check, never block a scan (verified reads open with `O_NONBLOCK`).

## Phase 2 — High-throughput engine for 2GB–100GB+

### Per-analyzer resource governance

- [x] Centralize per-analyzer limits into a policy object and add configured/consumed byte, time and stop-reason telemetry for all report formats: every built-in analyzer declares its content limits in one `AnalyzerLimits` object (`core/limits.py`) that references the constants it applies, and the engine reports them with the time and memory budget policy (`engine/budgets.py`). Each call's bytes read, time, sampled memory, budget stops and content limits reached are in `metrics.analysis_budgets` and the Markdown and HTML reports, and the terminal summary counts the stops and limits reached; the budget document's table is generated from the declarations. Byte budgets are declared, not configurable.


### Bounded thread-pool concurrency and C/OpenCL GPU execution (new release gate)
- [x] Add bounded concurrent thread-pool file-analysis scheduling with configurable worker count, back-pressure and deterministic result ordering; keep SQLite cache operations on the coordinator thread.
- [x] Stream Python fallback `os.scandir` entries directly without allocating and sorting a second per-directory entry list; retain deterministic ordering at the public inventory boundary and cover it with regression tests.
- [x] Add `pdt scan --jobs N` and `--jobs 0` auto-sizing; expose selected worker count and queue limits in scan metrics and every report format.
- [x] Extend the C extension with runtime OpenCL loader/device discovery without requiring GPU SDK headers or a GPU at build time.
- [x] Implement a bounded C/OpenCL byte-count/reduction kernel for large immutable byte buffers; dispatch to an available GPU only above a configured threshold and only for supported kernels. Threshold tuning is tracked below.
- [x] Fall back to portable C/SIMD/Python on missing OpenCL loader, no GPU device, unknown/insufficient device memory limits, kernel/build/dispatch failure, unsupported platforms or small workloads. GPU absence must never fail a scan.
- [x] Restrict GIL-releasing GPU reads to immutable bytes; mutable bytearray and other buffer exporters stay on the GIL-held CPU path.
- [x] Report GPU vendor/device/compute units/memory, threshold, actual dispatch counts and fallback counts without exposing device-specific private data.
- [x] Report the reason for each GPU fallback (loader, device, memory limit, kernel build or dispatch failure): `metrics.native_backend.gpu_unavailable_reason` names the first initialization step that failed (loader, device, context, kernel_build, host_memory) and `gpu_fallback_reasons` counts every large-buffer fallback by reason (also memory_limit and dispatch), summed over worker processes and shown in the terminal summary, the Markdown and HTML reports and `pdt capabilities`.
- [x] Add fake/no-device and kernel-failure tests plus hardware-backed GPU-present, threshold and fault-injection runs; benchmark GPU versus CPU and tune the default threshold: a fake OpenCL loader (Linux) drives every initialization, memory-limit and dispatch failure and a working fake device; a fault hook, threshold and disabled-default tests run everywhere; on an NVIDIA RTX 3060 (2026-11-13) GPU and CPU counts agree and `tools/gpu_benchmark.py` measured the GPU path 2.0-2.8 times slower than portable C from 1 MiB to 512 MiB, so GPU counting is now opt-in (`--gpu`, threshold `--gpu-min-mb`, 8 MiB). CI provisions no GPU.
- [x] Keep GPU scope explicit: analyzer semantics remain CPU-side unless a specific C/OpenCL kernel is implemented and validated.


- [ ] Move graph payloads, dependency/correlation indexes, report metrics and per-file analyzer working sets to bounded store-backed structures and producer/consumer queues. Done for the Python dependency graph in `pdt scan`: its modules, edges, unresolved imports and skipped modules are rows of the scan's SQLite inventory, de-duplicated per module and read back lazily (`StoredRows`); the JSON report streams them and the HTML report embeds at most 10,000 of each. Only the module indexes and a compact integer adjacency for cycle detection stay in memory, and the ceilings rose from 25,000 modules and 100,000 edges to 250,000 modules, 10,000,000 edges, 5,000,000 unresolved imports and 1,000,000 skipped modules (a library call without a store keeps the old in-memory ceilings). Any omitted or skipped evidence still marks the graph incomplete with an `UNKNOWN` finding. The architecture layout's top-level component counts are store counters, added in bounded batches and read back largest first, so `pdt scan` has no component cap (10,000 without a store). The other report metrics are catalog-sized or capped, and every analyzer bounds what it keeps for one file (aggregated findings with capped evidence; the secret scanner lists at most 10,000 findings per file): `tests/reporting/test_bounded_results.py` scans one tree at four times the size and fails when a metrics collection other than the store rows grows, or when an analyzer's findings or evidence for one file grow with its matches. Open: the Python graph's module index (at most 250,000 modules) is built in memory, not in the store. Findings use deterministic SHA-256 content keys and lazy `StoredFindingRecords`; diagnostics use insertion-ordered `StoredDiagnosticRecords` with transactional sequence IDs. Directory records and aggregates are persisted and read lazily. The Python fallback keeps only active directory iterators (O(depth)).
- [x] Add a bounded-batch SQLite `InventoryStore` primitive with deterministic streaming reads, atomic resumable metadata checkpoints, SQLite integrity checks, explicit close semantics, private POSIX file permissions and symlink-path rejection.
- [ ] Move all remaining inventory/result collections and report assembly onto store-backed streaming iterators. **Partial integration (2026-11-04):** CLI scans persist file, directory, symlink and special-entry records through bounded SQLite batches with running/complete/partial checkpoints, final directory aggregates and integrity telemetry. File records are rehydrated lazily through a typed `StoredFileRecords` sequence; symlink and special-entry records use typed `StoredRecordSequence` instances. All three use case-folded path ordering with exact-path tie-breaks, while private file identity remains in storage and excluded from public serialization. The Python fallback now keeps only active `os.scandir` iterators on a depth-proportional stack rather than retaining pending sibling-directory paths. Directory records and their direct-child/file/byte aggregates are updated through bounded SQLite directory-state deltas and exposed lazily. JSON and HTML array serialization and Markdown output iterate records incrementally. Findings are now persisted and rehydrated lazily; diagnostics are persisted with ordered, concurrency-safe sequence IDs and emitted incrementally without deduplicating repeated messages. The terminal security summary uses a bounded top-25 selection. Per-file analyzers return bounded finding lists (see the item above), the other report metrics are catalog-sized or capped, and the coordinator keeps counts, not lists, of per-file failures (fingerprint cache writes, skipped lockfiles). Open: the Python graph's module index is built in memory, and the browser receives one embedded report payload, capped per list (progressive loading is in Phase 11). Cancellation (Ctrl-C) and restartable scans (`--resume`) are implemented; bounded memory at 100 GB+ is unverified until the large-corpus benchmarks run.
- [x] Implement bounded concurrency, work stealing only if justified, back-pressure, cancellation and resumable checkpoints.
- [x] Stream SHA-256 and content scanning; avoid repeated passes when analyzers can share a bounded decoded stream safely. Files up to 4 MiB are read once, hashed and shared by every analyzer. Larger files are hashed in one streaming pass (1 MiB chunks), and each analyzer then streams its own bounded window, which the page cache serves. `tools/read_pass_benchmark.py` measured a 64 MiB text file (2026-11-13, Windows): hash pass 53 ms; the four analyzers that read it in full re-read it for about 102 ms and decode it for about 93 ms, 0.9% of their 21.5 s of analysis, so a shared decoded stream for larger files would not pay for its complexity.
- [x] Add content fingerprint cache with metadata validation, file identity where reliable, stale-entry pruning and corruption recovery: size, modification-time, change-time (POSIX `st_ctime`; on Windows the NTFS ChangeTime through an attributes-only handle, about 31 µs per cached file) and file-ID validation with IDs stored losslessly, stale-path pruning after complete walks, a private database, and recovery from damage: a database that cannot be opened is moved aside at the start, one that fails a read mid-scan is bypassed (every file hashed) and moved aside when the scan ends.
- [x] Separate metadata-only inventory from content analyzers so the same file is not read repeatedly without purpose.
- [x] Add configurable CPU, memory, I/O and per-analyzer budgets: `--jobs` bounds the analysis workers and `--analyzer-cpu-seconds` each analyzer call's CPU time on a file (the analyzing thread's clock; Linux and Windows); `--analyzer-memory-mb` bounds each call's memory growth and `--max-memory-mb` the whole scan's resident memory (the coordinator and its worker processes, shared pages counted once on Linux): over it, new work waits for queued work, and no call's memory budget exceeds it. `--analyzer-read-mb` bounds what each call reads (an I/O budget enforced by the verified readers), `--analyzer-timeout` its time, `--domain-budget` overrides any of them per analyzer domain, and `--plugin-timeout` and `--plugin-memory-mb` bound plugin hosts. The scan budget is back-pressure: it stops no running call, and the coordinator's passes after the analysis read store-backed records instead.
- [x] Make progress phase-based: inventory, hashing, analyzer domains, archive inspection, correlation, reporting. `engine/progress.py` counts each phase as the scan runs: entries and bytes walked (read live from the walk's counters), files and bytes hashed with the digests the fingerprint cache supplied and the workers' hashing time, files analyzed with analyzer calls and time per analyzer domain, archives inspected of the archive files the inventory found, and the correlation and reporting steps with their times. The terminal shows one live row per phase (`reporting/terminal.py`: progress bars, throughput, time left) in place of the single analysis bar, and `metrics.performance.phases` records the phases in the JSON, Markdown and HTML reports (schema 1.20). Local, remote and no-download scans report the same phases.
- [x] Implement portable C byte counting and host capability reporting, used by streaming secret analysis.
- [x] Implement a C++17 magic-byte signature classifier used by scanner file-type detection.
- [x] Implement Linux x86-64 SIMD Assembly byte counting with runtime SSE2/POPCNT detection and scalar C/Python fallbacks.
- [x] Implement and integrate the C++17 native file-signature classifier with Python fallback.
- [x] Extract the offline report client into a packaged JavaScript source asset bundled into standalone HTML.
- [x] Use cursor-based bounded DOM pagination for file inventory and findings without allocating full filtered-match arrays.
- [x] Implement and integrate the Rust PyO3 no-follow directory iterator with native metadata and bounded active-directory state.
- [x] Replace in-memory inventory/results with persistent streaming index storage, bounded analyzer queues and resumable checkpoints. Inventory records, findings, diagnostics and code facts live in the scan's SQLite inventory and are read lazily; at most twice the worker count of batches is pending; `--resume` continues from the stored inventory. Correlation working sets are tracked in the items above.
- [x] Cross-compile/test native modules on Linux, Windows and macOS; fuzz FFI boundaries and test graceful fallback. CI builds and tests the native modules natively on each operating system (Phase 13). `tests/engine/test_native_fuzz.py` fuzzes every FFI entry point differentially against its Python reference (the C byte counter, the C++ signature matcher, the Rust walker on random trees), checks that malformed arguments raise, and that a scan with every native module withdrawn reports the same results. The `Native backends` workflow runs the fuzzing under AddressSanitizer and UndefinedBehaviorSanitizer, the full suite on Linux aarch64 and Windows ARM64 runners, and cross-compiled wheels (macOS x86_64 on arm64, tested under Rosetta 2; Windows ARM64 on x64, checked by `tools/wheel_architecture.py`). Its first complete run passed every job on 2026-11-13 (the Windows ARM64 cross-build after PyO3 was given the target Python version).
- [ ] Benchmark 2GB, 10GB, 50GB and 100GB+ corpora with varied file counts/sizes, deep trees, large dependency directories, archives and symlink-heavy layouts.
- [ ] Publish wall time, files/sec, bytes/sec, cache hit rate, peak RSS, CPU, I/O, archive budgets and report-generation memory.

## Phase 3 — Archives and content without extraction

- [x] Recognize common archive/package extensions and ZIP/TAR signatures.
- [x] Inspect ZIP central directory and TAR member metadata without writing files to disk.
- [x] Record member path/name/type, timestamps, modes/permissions, compressed/uncompressed sizes, duplicate names, encryption and link/special-entry indicators where available: every indexed ZIP and TAR member is an `archive_members` record (path, type, size, ZIP compressed size, permission bits, ZIP DOS or TAR UTC time, link target, TAR owner and group, and the `unsafe-path`, `setuid`, `setgid`, `world-writable`, `encrypted`, `high-ratio` and `duplicate` flags), stored in the scan's SQLite inventory and streamed to the JSON report: up to 200,000 per archive and 1,000,000 per scan, with the records dropped past the ceiling counted.
- [x] Detect absolute paths, drive-prefixed paths, parent traversal, ZIP symlinks and TAR symlink/hardlink/device entries.
- [x] Perform bounded in-memory content samples for ZIP/TAR members with redacted secret/PII indicators.
- [x] Make archive inspection states explicit: detected, index-read, metadata-complete, sample-read, sample-truncated, encrypted, unsupported, malformed, budget-stopped. Each archive's record has a primary `state` and every state that applies; an archive the engine's per-call budget stops is recorded as budget-stopped too.
- [x] Refuse ZIP index materialization when EOCD/ZIP64 preflight cannot establish bounded central-directory limits; return UNKNOWN instead.
- [x] Enforce a per-archive wall-time budget during ZIP/TAR metadata traversal and bounded member sampling; time stops produce UNKNOWN findings.
- [x] Make archive byte, entry, nested-depth, total-uncompressed-byte, per-member sample, total-sample, compression-ratio and wall-time budgets configurable per scan/domain: `pdt scan --archive-limit NAME=VALUE` configures the entry, central-directory byte, per-member and per-archive sample, wall-time, TAR decompression, declared-uncompressed (an archive-bomb finding past it), compression-ratio, nesting-depth and nested-byte limits for the archive domain, in every worker process, and the reports show the values in force. ZIP and TAR archives inside archives are inspected in memory, one level deep by default, with their own records.
- [ ] Validate ZIP data descriptors, ZIP64, encrypted members, duplicate/case-colliding paths, Unicode path normalization and truncated directories. Implemented with tests: EOCD/ZIP64 preflight, encryption flags, duplicate names, and case-fold and NFC collisions. Missing: data-descriptor and truncated-directory validation.
- [ ] Add safe metadata readers for 7z, RAR, CAB, ISO, Zstandard, DEB/RPM and language package formats through optional offline dependencies where appropriate.
- [x] No archive backend may extract members to disk or follow archive links. Members are read only as bounded in-memory streams: TAR regular members, and ZIP regular members plus the stored target text of ZIP link entries. Links are recorded and checked, never followed. Tests check that the archive is unchanged and that nothing is written next to it.
- [ ] Add malicious fixture set: archive bombs, high-ratio entries, nested bombs, malformed headers, encrypted archives, path traversal, absolute paths, hardlinks, symlink loops, sparse TAR, huge entry counts and corrupt checksums.
- [x] Report every archive budget hit, per-archive member/content coverage percentage and which limits prevented deeper inspection: each archive record lists every limit that stopped it (entries, index bytes, wall time, TAR decompression, the archive and per-member sample budgets, the member-record limit, the engine's budgets) with its value and what it affected, and `member_coverage_pct` and `content_coverage_pct`; `metrics.archives` sums them and counts the archives each limit stopped, in every report format.

## Phase 4 — Network and endpoint intelligence

### Network and identifiers
- [x] IPv4 and IPv6 literal patterns with IP validation.
- [x] IPv4/IPv6 CIDR candidates with IP-network validation.
- [x] Port declarations, host:port strings, URL ports and common service-port labels.
- [x] URL/URI schemes and evidence redaction for userinfo, path, query and fragment.
- [x] FQDN/domain and probable subdomain candidates without DNS requests.
- [x] Common HTTP, WebSocket, gRPC, GraphQL, SOAP, MQTT, AMQP, Kafka, SSH and DNS markers.
- [ ] Add IPv4-mapped IPv6, zone-scoped IPv6, bracketed literals, URL edge cases, Unicode/IDNA domains and public-suffix-aware subdomain classification. IPv4-mapped and bracketed IPv6 literals are handled; IDNA domains and public-suffix-aware classification are not.
- [ ] Detect listen/bind/connect/accept/socket creation APIs and distinguish declaration/configuration from code call sites.
- [ ] Correlate host, address, port, protocol and service declarations across Docker, Kubernetes, Compose, Terraform and source code.
- [ ] Keep all network discovery passive: no DNS, scanning, probing or connection attempts. This holds by construction (analyzers import no network client and resolve no names), but no regression test enforces it.

### API types, contracts and endpoints
- [x] API-style classification for REST, GraphQL, gRPC/protobuf, JSON-RPC, SOAP/WSDL, WebSocket, event-driven APIs and webhooks.
- [x] Contract inventory for selected OpenAPI, GraphQL, protobuf, Thrift and API schema formats.
- [x] Initial source endpoint recognition in selected frameworks/languages.
- [ ] Expand endpoint adapters across Python, JS/TS, Go, Java/Kotlin, C#, PHP, Ruby, Rust, Swift, Dart and other supported languages. Python routes come from the syntax tree, and lexical patterns cover Express-style routers, Laravel, Spring, JAX-RS, ASP.NET, Sinatra-style Ruby, Rust route attributes, Go `HandleFunc` and Crow. Tests cover Python, TypeScript, Java, Go, Ruby, C# and C++ only.
- [ ] Resolve REST method/path/decorator/annotation/attribute and framework router registration patterns.
- [ ] Discover GraphQL schemas, operations, resolvers, directives, federation and subscriptions.
- [ ] Discover gRPC services, methods, protobuf messages, RPC frameworks and generated clients.
- [ ] Discover JSON-RPC, SOAP/WSDL, WebSocket, SSE, webhook, AsyncAPI, OpenRPC, MQTT and message-driven endpoints.
- [ ] Cross-reference source route handlers to API contracts and generated clients.
- [ ] Detect auth middleware, versioning, rate-limit and validation declarations where evidence exists.
- [ ] Build endpoint catalog with method, path, framework, handler symbol, contract, auth marker, source evidence and confidence. Never imply reachability.

## Phase 5 — VCS, source hosting and delivery-provider intelligence

- [x] Detect Git checkout metadata through .git directories and .git pointer files used by worktrees/submodules.
- [x] Inspect Git remotes and fingerprint GitHub, GitLab, Bitbucket, Azure Repos, AWS CodeCommit, Google Cloud Source Repositories, SourceHut and selected self-hosted hosts.
- [x] Detect Git HEAD references, detached HEAD, shallow clone boundaries, packed refs, branch config sections, submodule declarations and Git LFS rules.
- [x] Add Mercurial, Subversion, Bazaar, Darcs, Jujutsu, Pijul, CVS, Fossil and Perforce metadata markers: one finding per control directory from a file every repository of that VCS has (`.hg/requires`, `_darcs/format`, `.jj/repo/store/type`, `.bzr/branch-format`, `.pijul/pristine/db`, `.svn/wc.db` or `entries`, `CVS/Root`, Fossil's `_FOSSIL_`/`.fslckout`/`.fos`), remote providers from their configuration files (Jujutsu's Git backend config included), and bare Git repositories at any depth. *Corrected 2026-11-12: the item was ticked while only optional files (`hgrc`, `prefs/repos`, `config.toml`) triggered a finding, so `hg init`, `darcs init` and ordinary Jujutsu repositories produced none.*
- [x] Add online repository scanning over Git for GitHub, GitLab, Bitbucket, Azure Repos, CodeCommit, SourceHut and compatible hosts, verified end to end on Windows and Linux against a real Git server (clone, tree streaming, tags, commit IDs, batches, reports). See [ONLINE_MODE.md](../guides/ONLINE_MODE.md).
- [ ] Verify the Mercurial, Subversion, Bazaar/Breezy, Darcs, Git-backed Jujutsu, Pijul, CVS, Perforce and Fossil SCM adapters end to end against live servers. They are implemented and covered by recorded-invocation tests only; the 2026-11 audit fixed `svn+ssh`/`bzr+ssh` URLs, the CVSROOT port syntax, Fossil's `.fslckout` on Linux and the Jujutsu revision, none of which those tests had caught.
- [x] Add `pdt scan <target-url>` for a single repository and `pdt scan --url <file.txt>` for mixed-provider/mixed-VCS batches, per-target report directories and failure isolation; `pdt capabilities` reports installed native VCS clients.
- [x] Select a branch, tag, revision or commit with `--ref` or per-line `ref=`/`vcs=` options in URL files; write `batch-summary.json`/`.md` with per-repository status, revision, exit code and sanitized error (also when interrupted); define batch exit codes for `--fail-on` and `--strict`.
- [x] Harden remote acquisition: non-interactive clients without a controlling terminal, termination of the client's whole process tree on timeout or Ctrl-C, a pinned Git transport, plain-text transports only with `--allow-insecure-transport`, option-injection guards, refusal of Windows-unrepresentable paths (`aux.c`, `CON`, ...), materialization (`--remote-max-gb`) and free-disk budgets, bounded and sanitized client errors, and temporary-tree cleanup on every exit path.
- [x] Record per-target source metadata in every report (credential-free URL, provider, ref, revision, transport, acquisition time) and report unmaterialized content as `UNKNOWN` coverage findings that make `--strict` scans incomplete.
- [x] Add a second online path that analyzes a remote repository without cloning or writing it to disk (`pdt scan URL --no-download`, also for `--url` batches): GitHub/GitHub Enterprise, GitLab (gitlab.com and self-managed), Bitbucket Cloud and Gitea/Forgejo REST APIs stream the tree and file contents into the built-in analyzers in memory, bounded by file, byte, per-file and request budgets; tokens come from host-bound environment variables or the Git credential helper and never reach logs or reports; rate-limit and budget exhaustion are `UNKNOWN` coverage. Verified against a loopback emulation of all four APIs (with a no-disk-write guard) and, without credentials, against the live GitHub, GitLab, Bitbucket and Codeberg APIs.
- [x] Run third-party plugins in no-download mode: `--no-download-plugins` gives each sandboxed plugin call one transient copy in the plugin host's private folder under the output, deleted after the call, and reports record it.
- [x] Support Bitbucket Data Center/Server's REST API in no-download mode (`files` and `raw`, with clone, browse, personal and context-path URLs).
- [x] Show the scan mode (local or online), every network use and the remote source in all report formats: a top-level JSON `scan` block (report schema 1.7), Markdown *Scan Source* and *Vulnerability Intelligence* sections, and an HTML mode badge, NO TLS badge and scan-source view; the HTML client is exercised in tests by running it under Node.js.
- [x] Detect GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, Jenkins, CircleCI, Buildkite, Travis, Drone, Woodpecker and AppVeyor definitions.
- [x] Detect AWS CodeBuild/CodeDeploy/CDK/SAM, Google Cloud Build, Firebase and selected deployment markers.
- [ ] Deeply decode SVN working-copy SQLite metadata, Mercurial revlogs, specialized Jujutsu/Pijul layouts and Perforce workspaces.
- [ ] Add configurable provider fingerprints for GitHub Enterprise, GitLab self-managed, Bitbucket Data Center, Azure DevOps Server, Gitea/Forgejo, Gerrit and Gitolite. Current host heuristics are present but are not operator-configurable.
- [ ] Correlate remotes, submodules, package registries, CI workflows and cloud deployment manifests into a provenance graph.
- [ ] Add bare repositories, worktrees, nested repositories, detached/shallow clones, multiple remotes, malformed metadata and credential-bearing remote URL fixtures. Every fixture listed exists except multiple remotes.
- [ ] Verify credentials/query/fragment redaction across every report/output path.
- [x] Preserve offline local scanning by default; add explicit read-only remote source acquisition through VCS clients only when a URL target or `--url` batch is supplied.

## Phase 6 — Local vulnerability intelligence

- [x] Add a local SQLite advisory store with explicit OSV JSON import and coverage/status reporting.
- [x] Import advisories from a local JSON file or directory tree; do not download, update or contact advisory providers.
- [x] Match resolved package/version pairs from supported lockfiles against OSV affected package coordinates.
- [x] Support explicit affected-version lists and initial SEMVER/ECOSYSTEM event-range evaluation, including introduced/fixed/last_affected/limit boundaries.
- [x] Report advisory identifiers, CVE/GHSA aliases, severity, modified date, fixed-version boundary, lockfile evidence and confidence.
- [x] Treat unsupported range schemes, unreadable/malformed lockfiles, missing versions, 128 MiB input limits and 250,000-package extraction limits as UNKNOWN; do not label them clean.
- [x] Add dedicated JSON/Markdown/HTML vulnerability sections and CLI database import/status.
- [ ] Extend resolved lockfile coverage for all catalogued language ecosystems and package managers. Sixteen lockfile formats are parsed ([LOCKFILE_ANALYZER.md](../analyzers/LOCKFILE_ANALYZER.md)); CocoaPods, Conan, vcpkg and Gradle lockfiles are not among them.
- [ ] Add adapters for local NVD JSON feeds, GHSA exports, distro advisories (Debian, Ubuntu, Alpine, Red Hat), OS package DBs, container/SBOM advisories and vendor bulletins.
- [ ] Add ecosystem-native comparators for PEP 440, SemVer, Maven, NuGet, Go pseudo-versions, RubyGems, Debian, RPM and vendor-specific versions. PEP 440, SemVer (npm, crates.io, Go, Hex, SwiftPM, Pub), RubyGems, Composer and NuGet orderings exist with tests; Maven, Debian, RPM and vendor orderings do not, and Go pseudo-versions are compared as SemVer prereleases.
- [ ] Support CPE/purl matching, duplicate/alias resolution, withdrawn/superseded advisories, exploit maturity, CVSS vector parsing and VEX status. Implemented: CVSS v2/v3 vector severity and alias merging, both with tests. Withdrawn advisories are skipped, but no test covers this. Missing: CPE/purl matching, superseded advisories, exploit maturity and VEX.
- [ ] Resolve direct/transitive dependency graphs and retain parent path/provenance for vulnerable packages.
- [ ] Add static dependency reachability evidence where symbol/call graphs support it; never claim exploitability from version matching alone.
- [ ] Add offline allowlists/triage, accepted-risk rationale, fixed-version suggestions and remediation grouping.
- [ ] Test DB corruption/recovery, duplicate IDs, re-import, withdrawn advisories, boundary versions, prereleases, malformed records and large local feeds.
- [x] Include advisory snapshot provenance, import timestamp, source identity/hash, ecosystem coverage and freshness warning in reports.

### Online vulnerability intelligence (opt-in)

- [x] Add an explicit opt-in online advisory source, `--vuln-online`, for local paths and remote URLs: OSV.dev `/v1/querybatch` (1,000 packages per request, paginated results) and `/v1/vulns/{id}`, sending only ecosystem, package name and version, with findings built by the same code as the offline matcher. Verified against a loopback OSV/NVD/GitHub service in tests and against the real services with the opt-in live test.
- [x] Add optional `--vuln-enrich nvd,ghsa` enrichment from NVD CVE API 2.0 and the GitHub Advisory Database (CVSS v2/v3.x/v4.0, CWE, aliases), with each service's rolling rate limit, an enrichment budget, and API keys or tokens sent only to their own host.
- [x] Cache responses in a private SQLite file with a TTL (`--vuln-cache`, `--vuln-cache-ttl`), honor proxy variables and `--ca-bundle`, bound responses (including gzip), follow redirects only within the same host, and retry transient failures with `Retry-After` support.
- [x] Report network failures, rate limits, timeouts, unreadable lockfiles and unavailable advisory details as `UNKNOWN` coverage findings and scan diagnostics, never as a clean result; keep local mode offline (a test runs a scan with every socket call disabled).
- [x] Show online lookup provenance in every report format: provider, endpoint, query time, package/advisory counts, cache hits, requests per host, retries, failures and coverage state (JSON metrics; Markdown and HTML vulnerability views, with a warning whenever a lookup was incomplete and a per-finding source badge in HTML).
- [ ] Serve stale cache entries, clearly labelled, when the advisory service is unreachable, and let operators refresh the cache ahead of an offline scan.

## Phase 7 — Secrets, credentials and personal-data indicators

- [x] Field-name indicators for first/given/middle/last/family name, username, email, phone, address, date of birth and government-ID fields.
- [x] Email-shaped value indicators with raw values omitted.
- [x] Credential-related field-name indicators for password/passphrase, API key, client secret, tokens and private key.
- [x] Initial secret-pattern scanner and archive member secret-pattern scanner with redacted evidence.
- [x] Expand detectors for actual high-confidence secret value shapes: cloud keys, provider tokens, database URLs, private-key blocks, certificates, JWTs, OAuth credentials, signing keys, service-account credentials, webhook secrets and generic entropy/context-assisted tokens.
- [ ] Add password/passphrase assignment value detection without ever storing or logging the matched value; support YAML, JSON, TOML, INI, XML, dotenv, HCL, source literals and multiline formats. Literal assignments are detected and redacted, with tests, in Python, Go, PHP, TypeScript, shell, YAML, INI and dotenv files. TOML, XML, HCL and multiline values have no tests.
- [ ] Extend PII field/value detectors for firstname, first_name, givenName, middleName, lastname, surname, username, user_name, email, phone, address, account ID and related schemas in 40+ language syntaxes and data formats.
- [x] Distinguish key-name evidence, placeholder/example values and likely non-placeholder values. Never label a field name alone as an exposed credential.
- [ ] Add optional local keyed HMAC fingerprints to correlate repeated values without exposing reversible data; store no raw match in cache.
- [ ] Add strict redaction tests for JSON/HTML/Markdown/terminal/exception logs and archive member findings.
- [ ] Add allowlists/false-positive controls that do not suppress genuine findings silently; record suppression rules in the report.

## Phase 8 — Polyglot language and framework intelligence

- [ ] Maintain 40+ language packs with real conformance fixtures, not just extension recognition: mainstream, legacy, scientific, functional, scripting, mobile, game, embedded, HDL, GPU and smart-contract languages.
- [ ] Leverage Tree-sitter where grammar coverage is robust; add dedicated parsers/SDKs where Tree-sitter is insufficient or unavailable. Since 2026-11-12 a provisioned grammar refines the shared code model for 16 brace languages ([AUDIT.md §13](AUDIT.md#13-tree-sitter-code-model)), and the generic Tree-sitter analyzer parses 61 grammars. No dedicated parser exists where Tree-sitter is insufficient.
- [ ] Support declarations, imports/exports, module resolution, symbol indexes, types, call sites, common framework APIs and test/build patterns to each declared capability.
- [ ] Include JS/TS, Python, Rust, Go, C/C++, Java/Kotlin, C#/F#, Swift, Objective-C, Dart, PHP, Ruby, Perl, R, Julia, Lua, Shell, PowerShell, Elixir/Erlang, Haskell, OCaml, Clojure, Scala, Groovy, Fortran, COBOL, Pascal, Ada, Zig, Nim, Crystal, D, Odin/V, Solidity/Move, SQL and HDL/GPU ecosystems.
- [ ] Handle ambiguous extensions (for example `.m`, `.v`, `.h`) with path/build/manifest context; retain ambiguous/unknown instead of overclaiming. `.m` and `.v` are labelled ambiguous instead of being assigned one language, and the HDL analyzer confirms Verilog `.v` files from their content. Path, build and manifest context are not used.
- [ ] Add a language-agnostic symbol/module interface and analyzer SDK with source span, syntax node, parser version and capability status. The shared code model ([CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md)) gives built-in analyzers one symbol and call interface with source spans for Python and the lexically modelled languages. It is not part of the plugin SDK, and it exposes no syntax nodes or parser versions.
- [ ] Add mixed-language monorepo fixtures and projects containing generated, vendored and nested workspace trees.
- [ ] Every unsupported or partially supported language must report capability gaps explicitly. Every report carries `metrics.language_catalog` (each language's `analysis_status` and `structural_model`) and `local_parser_capabilities` for the detected languages. There are no per-language descriptions of what is missing.

## Phase 9 — Security, configuration, API, database, test and build coverage

- [ ] Security: credentials, injection, command execution, traversal, SSRF, unsafe deserialization, authentication, authorization, cryptography, TLS, insecure randomness, dataflow/taint, container/IaC and supply-chain indicators.
- [ ] Configuration: environment variables, defaults, overrides, secrets references, configuration layering, schema validation, drift and cross-file key references.
- [ ] APIs: routes, handlers, contracts, clients, middleware, protocols, versioning and security controls.
- [ ] Databases: SQL, NoSQL, graph, search, time-series, vector databases, ORMs, migrations, connection config, schema/lineage and query indicators.
- [ ] Tests: 40+ language test naming/framework patterns, fixtures, setup/teardown, mocks, coverage data, test-to-code links and untested-code candidates.
- [ ] Builds: Make/CMake/Meson/Ninja, Bazel/Buck/Pants, Gradle/Maven/Ant, Cargo/Go, npm/pnpm/yarn/bun, Python packaging, .NET, SwiftPM/CocoaPods, Flutter, game/embedded/FPGA/GPU toolchains and CI/CD.
- [ ] Build analyzer capability must separate recognized manifest, extracted target/task, resolved dependency, and executed build; PDT never runs the build.
- [ ] Add tests for common, legacy, proprietary and custom project conventions; support safe custom rules through plugins.

## Phase 10 — Domain extensions

- [ ] Expand AI/ML model architecture, tokenizer/config, training/inference, datasets, accelerators, distributed training and checkpoint metadata without deserializing untrusted payloads.
- [ ] Expand ROS 1/ROS 2 packages, nodes, topics, services, actions, launch compositions, QoS and message/interface relationships.
- [ ] Expand mobile platform manifests, permissions, entitlements, build variants, native bridges and privacy/data declarations.
- [ ] Expand Unity, Unreal, Godot, GameMaker, Defold, Bevy, Roblox and web-game engine project/asset intelligence.
- [ ] Expand frontend frameworks, component graphs, routes, state, accessibility, localization and asset pipelines.
- [ ] Add embedded/firmware, RTOS, board-support, cross-compilation, boot images, memory maps and hardware interfaces.
- [ ] Add Verilog/SystemVerilog/VHDL and FPGA module/port/testbench graph analysis.
- [ ] Add CUDA/OpenCL/Metal/shader kernel and host-device relationship analysis.
- [ ] Expand observability/logging/metrics/tracing, cloud service binding, supply chain, SBOM/provenance and privacy/data governance.
- [ ] Expand multi-project comparison and integration planning while keeping each project independent.

## Phase 11 — Comprehensive report schema and report UX

### Data model
- [x] Version the JSON schema and retain migration support for older report versions.
- [ ] Add explicit inventory records for every entry type, including special files and excluded/pruned subtree summaries. Files, directories, links (including junctions) and special entries each have records, and every pruned directory keeps a record with its reason. Pruned subtrees have no content summary.
- [ ] Add archive summary/member risk records, network endpoint records, API endpoint records, OS/platform indicators, credential/PII classifications and analyzer coverage.
- [ ] Add per-file analyzer status: not applicable, completed, partial, unsupported, budget-stopped, excluded, error.
- [ ] Add evidence spans/source locations, redaction state, confidence and severity. Findings carry line numbers, confidence, severity and redacted source lines; column spans and an explicit redaction-state field are missing.
- [x] Stream JSON, HTML payloads and Markdown output without building duplicate result dictionaries or a report-sized Markdown string; keep the Markdown largest-directory summary bounded to its top 100 entries.
- [ ] Add NDJSON/chunked external report data backed by a persistent inventory store.

### HTML report
- [x] Standalone offline dark UI baseline with responsive navigation and summary panels.
- [x] Search, category/severity/confidence filters and paginated finding display.
- [x] Per-finding disclosure plus open-all/close-all controls.
- [x] Use cursor-based bounded page rendering for file inventory and findings without allocating full filtered-match arrays.
- [ ] Add dedicated sections for subdirectories, hidden entries, development dependency trees, symlinks, file type/signature, size categories, network/IP/port/URL/subdomain, API routes/types, OS, archive/member content, secrets/PII and analysis coverage. Sections exist for directories, development trees, symlinks, special entries, file types, size buckets, local vulnerabilities and VCS providers. Hidden entries have a count and a row flag but no section of their own. Network, API, OS, archive, secrets/PII and analysis-coverage findings appear only in the general findings list.
- [ ] Add hierarchical directory explorer and archive member browser without flattening everything into one list.
- [x] Keep the rendered DOM bounded with cursor-based pagination for large file/finding lists.
- [x] Keep symlink and special-filesystem-entry tables bounded with independent 100-row pagination controls.
- [x] Bound local-advisory and VCS/provider detail-card copies while retaining complete category counts.
- [ ] Add progressive loading from external local report data or chunked embedded data so the browser does not need the full report payload at startup.
- [ ] Make all large tables sortable, searchable and paginated with stable row keys. File and finding lists are searchable and paginated, and symlink and special-entry tables are paginated; no table is sortable.
- [ ] Add severity heatmaps, category summaries, per-domain completion and unknown/skipped/error accounting.
- [x] Security-test HTML/JS data embedding, escaping, content security policy and offline isolation.
- [ ] Add keyboard accessibility, focus handling, contrast and screen-reader-friendly disclosure controls.
- [ ] Add golden screenshots and browser-based tests at desktop/tablet/mobile sizes.

### Terminal interface and CLI
- [x] ASCII banner and Rich progress/summary panels.
- [x] Clear screen only on an interactive TTY; never emit terminal control codes to redirected output.
- [x] Add a command-center dashboard showing Python orchestration and C/Assembly/C++/Rust backend status.
- [ ] Add phase timeline, domain status matrix, live counters, warning/error stream, confidence/severity legend and final scan-health panel. A live row per scan phase shows its counters and time, with analyzer calls in the busiest domains; the final summary panel shows phase timings, workers, GPU and vulnerability-database status, and a top-25 security summary follows it. There is no domain status matrix, warning/error stream, legend or scan-health panel.
- [ ] Group output by phase/domain; do not print every file as an unbounded line list. Files are never listed one per line, and progress is shown per phase; warnings and the security summary are not grouped by phase or domain.
- [x] Add `--quiet`, `--no-color` (the `NO_COLOR` environment variable is also honored) and stable, documented exit codes: `0` completed, `1` a finding at or above `--fail-on`, `2` usage or fatal error, `3` incomplete scan under `--strict`, `130` interrupted.
- [ ] Add `--json-lines` event output and verbosity levels.
- [x] Add CLI commands for the capability catalog and analyzer diagnostics (`pdt capabilities [--json]`: native backends, optional parsers, analyzers, domain status, plugin sandbox and plugin load diagnostics, VCS clients), and `pdt query` for code-index lookups.
- [ ] Add CLI commands for archive policy, budgets and general report inspection.
- [ ] Test TTY, no-TTY, narrow terminals, Windows console, ANSI-disabled terminals and large CI logs. Redirected (non-TTY) output, `--quiet` and `--no-color` are tested; the rest is not.

## Security finding evidence and developer remediation (new release gate)

- [x] Extend the finding schema with redacted source-line evidence, exact line numbers, attacker-impact explanation and actionable remediation guidance across secure-code, Python AST security, secret, privacy, risky-configuration and ZIP/TAR member analyzers; local OSV dependency findings also include conditional impact and fixed-version remediation.
- [x] Add rule-specific impact descriptions for credential exposure, command/code injection, unsafe deserialization, SQL injection, SSRF, path traversal, weak cryptography, TLS/JWT misconfiguration, unsafe C APIs and other supported security rules.
- [x] Render vulnerable source lines in red in the HTML report using safe text nodes (never inject source as HTML); show file path, line number, severity, confidence, impact and remediation together.
- [x] Bring JSON and Markdown outputs to schema parity; Markdown visibly marks vulnerable lines and includes impact/remediation.
- [x] Redact passwords, tokens, private keys, credential URL values, email addresses, phone/address/birth-date/government-ID fields and common identity literals at the source-excerpt/model boundary; test report escaping against HTML/script payloads.
- [x] Add focused regression tests for password/identity assignments, authorization headers, credential URLs, email addresses, provider-token formats, PEM headers and standalone base64 payload lines, excerpt length bounds and model-boundary redaction. Verification across every analyzer, plugin and output surface is the separate Phase 13 gate.
- [x] Add analyzer-level PEP 263 regression coverage for both Python AST structure analysis and Python AST security analysis; malformed/unsupported encodings remain explicit UNKNOWN outcomes.
- [ ] Keep severity evidence-driven: explain realistic consequences conditionally and never describe a heuristic marker as confirmed exploitability or runtime exposure.

## Phase 12 — Large-project and adversarial verification

- [ ] Build synthetic and representative corpora at 2GB, 10GB, 50GB and 100GB+.
- [ ] Include high file count, deep nesting, huge fan-out, large development dependency trees, mixed file size distributions and binary-heavy projects.
- [ ] Include malformed and adversarial archive corpus, symlink loops, special files, permissions, Unicode/case-colliding paths, race conditions and files changing mid-scan.
- [ ] Include polyglot monorepos with 40+ languages and many build/API/database/test/security domains.
- [ ] Measure wall time, throughput, peak RSS, descriptor count, thread count, cache overhead, archive budgets, HTML/JSON output and memory during report rendering.
- [ ] Set explicit resource SLOs by scan mode; fail CI when budgets regress materially.
- [ ] Run fuzzers/property tests for archive parsers, path normalization, language/file-type recognition and report serialization. `tests/test_regex_complexity.py` times every module-level regex against adversarial input; there are no fuzzers or property-based tests.

## Phase 13 — Production release

- [x] CI triggers on pushes to `master`, `main` and `feat/**`, and pull requests targeting `master` or `main`; matrix jobs have explicit timeouts and pip dependency caching, and superseded runs are cancelled to prevent stale matrix queues.

- [x] Full supported OS and Python CI matrix, plus native build matrix where Rust/C modules exist.
- [ ] Analyzer conformance and regression coverage for all claimed capabilities.
- [ ] Reproducible source/wheel builds, clean install, package metadata, dependency/license inventory and CLI smoke tests. Every CI matrix job builds the sdist and wheel, checks metadata with `twine`, installs the wheel over the development install and runs a CLI smoke scan. Reproducible builds, an install into a clean environment and a dependency/license inventory are missing.
- [x] Route built-in analyzer reads of scanned project files through shared descriptor-verified binary/text and bounded-reader helpers; apply private scan-time identity checks where the walker supplies them. SHA-256 and signature sampling use the same descriptor boundary; regression tests cover file replacement, symlink substitution, bounded reads and private identity serialization.
- [x] Add a descriptor-aware Analyzer/plugin file-access contract and migrate or reject legacy third-party path-open behavior where strict mode requires enforcement. Isolated plugins receive verified private copies and cannot open project paths; only `--plugin-isolation off` keeps the legacy path interface.
- [ ] Add stable Windows file identity to the Rust walker and verify scan-to-read continuity on Windows/macOS/Linux. The Windows Rust walker does not report a file ID. PDT instead pins the volume serial and file index of the descriptor it opens for the signature probe, and verifies every later read against them. On Windows only the window between enumeration and that first open is not pinned.
- [ ] Security review of filesystem races, symlink handling, parsers, archive streams, plugin execution, cache databases, output paths and HTML serialization.
- [ ] Verified read-only, offline and privacy guarantees.
- [ ] Verified secret/PII redaction across every output surface.
- [ ] Verified 100k+ report usability and large-project performance/resource limits.
- [x] Plugin SDK documentation, API versioning, compatibility policy, sandbox/isolation guidance and conformance suite ([PLUGIN_SDK.md](../guides/PLUGIN_SDK.md): the compatibility policy for API version 1, and `pdt plugin-check` / `assert_conformant`, which load a plugin the way a scan does and report what a scan would reject).
- [ ] User-facing threat model, architecture guide, support matrix, benchmark report, operations guide and release notes. [ARCHITECTURE.md](../architecture/ARCHITECTURE.md), [OPERATIONS.md](../guides/OPERATIONS.md), [BENCHMARKS.md](../guides/BENCHMARKS.md) (small-scale results only) and `CHANGELOG.md` exist. A threat model, a support matrix and the large-corpus benchmark report do not.
- [ ] Production gate signed off before PR #1 can be merged.

## Acceptance standard

A task is complete only when:
1. implementation exists in the feature branch;
2. behavior and limitations are documented;
3. focused positive, negative and malformed-input tests exist;
4. platform-sensitive cases run in the supported CI matrix;
5. resource bounds and error states are explicit;
6. evidence and redaction behavior are verified;
7. the final PR head has green CI.

## Release gate

PDT is **not production-ready** while any mandatory acceptance item remains open, any core behavior silently skips project content, any capability is advertised beyond its evidence, the 2GB–100GB+ resource budget is unverified, report UX fails at large scale, or the final CI head is not green.

PR #1 remains open and unmerged. The repository owner alone decides when the verified production-ready branch is merged into `master`.

## Execution order — production completion (2026-11-04)

The next implementation block follows this dependency order. Documentation is updated before implementation; each phase below must land with focused tests and a truthful capability state.

1. **Inventory semantics and no-silent-pruning:** remove implicit exclusions for dependency/cache/build trees; inventory every entry and retain explicit prune/skip reasons; complete symlink and special-entry semantics, hidden attributes, file signatures and size accounting.
2. **Polyglot scale engine:** replace unbounded in-memory inventory/results with a Rust walker/indexer, bounded queues, incremental persistence, cancellation and checkpoints. Keep Python as orchestration; retain C/SIMD Assembly only on measured hot paths; add C++ only for justified SDK/library integration.
   - **Progress (2026-11-04):** `InventoryStore` is connected to CLI scanner runs. All inventory record classes are written in bounded SQLite batches with running/complete/partial checkpoints and integrity telemetry. File, directory, symlink and special-entry records are exposed as typed lazy sequences; directory child/file/byte aggregates and errors are updated through bounded SQLite deltas. The Python fallback retains active directory iterators only (O(depth)). Findings use deterministic SHA-256 keys and lazy `StoredFindingRecords`; diagnostics use transactional insertion IDs and lazy `StoredDiagnosticRecords`. The Python dependency graph now has hard RAM ceilings (25k modules, 100k edge candidates, 100k unresolved imports, 25k skipped-module details, 8 duplicate-path samples per module); any dropped/partial evidence sets `graph_complete=false` and emits an `UNKNOWN` finding. The architecture top-level component sample is capped at 10k with an explicit incomplete-layout finding. Graph adjacency/SCC state and report graph payloads still live in memory within those caps; they are not persisted as graph tables. Per-file analyzer working lists, general report metrics and the browser's single embedded report payload remain memory gates. This is not end-to-end bounded-memory scanning. Cancellation (Ctrl-C), restartable `--resume` and cursor-based browser pagination have since landed (0.2.0); the 2GB–100GB+ benchmarks remain OPEN.
   - **Progress:** the Python fallback streams `os.scandir` entries without a per-directory sorted `DirEntry` buffer and retains only active iterators (O(depth)). Store-backed file/directory ordering is deterministic: files use case-folded path plus exact-path tie-break; directories use depth, then case-folded path and exact path. Directory counters/errors are updated in SQLite. High-fan-out, casefold-collision and aggregate-state regression tests cover these paths; analyzer findings and correlation structures remain the next significant memory targets.
3. **Archive inspection:** extend no-extraction readers, inspect member names/types/content/links/permissions/ownership/timestamps, and enforce nested-depth, expansion-ratio, entry-count, compressed/uncompressed byte, sample and wall-time budgets. Unsupported formats remain explicitly UNKNOWN/detection-only.
4. **Analyzer completeness:** expand security, configuration, API style/route/contracts, database/ORM/migrations, test/build/CI, OS/platform, network and identity/credential analyzers across the 40+ language-family catalog. Separate lexical evidence from parser-backed semantics.
5. **Report schema and UX:** expose every inventory/analyzer state in JSON; provide grouped domain dashboards and lazy/chunked HTML rendering, stable pagination, global search, keyboard-accessible disclosures and open/close-all without unbounded DOM creation.
6. **Terminal experience:** retain the ASCII banner and command-center presentation; group progress by phase/domain, keep TTY clearing conditional, and add quiet/no-color/JSON-lines/verbosity modes with stable exit codes.
7. **Native execution acceleration:** bounded concurrent thread-pool file analysis (`--jobs N`/automatic sizing), runtime C/OpenCL GPU detection, a supported large-buffer byte-count kernel, deterministic collection, CPU/SIMD/Python fallback and capability/dispatch reporting are implemented. Remaining release gates are GPU-hardware/fault-injection tests, per-device threshold benchmarks and 2GB–100GB+ throughput/peak-RSS measurements; GPU use remains limited to explicitly supported kernels.
8. **Security evidence and reporting:** attach safely redacted vulnerable source lines, precise line numbers, severity, attacker-impact context and remediation to findings; synchronize JSON, Markdown and HTML output and test XSS/secret redaction.
9. **Verification and release:** adversarial filesystem/archive fixtures, redaction tests, GPU/CPU parity and fallback tests, concurrent-scan/cache tests, cross-platform native builds, parser conformance, packaging checks, 2GB/10GB/50GB/100GB+ performance and peak-RSS benchmarks, and green CI on the final PR head.

### Polyglot implementation acceptance

A language is part of the implementation only when source files exist, it is built or provisioned reproducibly, a production code path invokes it, its boundary is documented, and tests exercise success/failure/fallback behavior. The required language-family coverage is 40+; Python is not the sole implementation language. C and x86-64 Assembly provide native byte-counting/hardware paths; the Rust no-follow iterator, C++ signature classifier and JavaScript report client are integrated and tested in CI. Persistent Rust-backed inventory/indexing remains a release gate. TypeScript is not currently a runtime dependency; unused language folders or placeholder wrappers do not count.

### Oversized-file invariant

Without `--skip`, no global file-size threshold may suppress content analysis. With `--skip`, oversized files remain inventoried and are marked with the configured threshold and reason. Independent analyzer-specific safety budgets may stop an individual parser; those outcomes must be visible as UNKNOWN/partial and must not be confused with the global skip option.
