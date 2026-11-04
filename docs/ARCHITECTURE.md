# Architecture

## Polyglot system boundary

PDT is not a Python-only scanner. Python is the control plane; native engines and the report client are first-class components with explicit responsibilities.

| Layer | Primary language | Responsibility |
|---|---|---|
| Control plane | Python | CLI, plugin lifecycle, policy, orchestration, cache, findings and report schema |
| Native low-level core | C | Bounded byte counting, host capability reporting and stable extension boundary |
| CPU acceleration | x86-64 Assembly + C dispatch | Linux x86-64 SIMD byte counting with runtime SSE2/POPCNT checks; scalar C fallback |
| GPU byte reduction | OpenCL C loaded dynamically by native C | Optional large immutable-buffer byte counting; runtime device discovery, 8MiB dispatch threshold and CPU fallback; analyzer semantics remain CPU-side |
| Filesystem traversal | Rust + PyO3 | Integrated no-follow directory iterator with native OS metadata and bounded depth state; persistent indexing remains planned |
| File-signature classification | C++17 | Integrated native magic-byte classifier with Python fallback |
| Report application | JavaScript + HTML/CSS | Separate packaged offline client bundled into the standalone report; filtering, pagination and disclosure controls |
| Domain packs | Polyglot | Language, build, API, database, security, tests, ML/robotics/mobile/game/VCS analyzers |

Each language component must serve a production execution path. Merely listing a language in the roadmap or catalog is not implementation.

## Pipeline

1. Python validates target/output paths and local-only policy.
2. Python inventory records files, directories, symlinks and special entries; traversal does not follow symlinks and does not silently prune development/dependency trees.
3. C provides native byte-counting and host capability reporting. Linux x86-64 may dispatch CPU byte counting to Assembly after runtime feature checks; large immutable byte buffers may use a dynamically loaded OpenCL reduction kernel when a supported GPU is available.
4. Python coordinates analyzer plugins and per-domain resource policies without importing or executing target modules.
5. Polyglot analyzers parse source/configuration/contracts and use locally provisioned optional parsers with explicit capability states.
6. Local vulnerability intelligence optionally matches resolved lockfile coordinates against an operator-imported OSV SQLite snapshot. No scan-time network fallback exists.
7. Correlation links symbols, endpoints, VCS remotes, dependencies, configuration and docs with evidence spans.
8. JSON/Markdown are generated locally; the offline JavaScript/TypeScript report application renders paginated/lazy views without remote assets.

## Native ABI and safety

- The current C extension accepts explicit contiguous Python buffers and returns bounded scalar results; it reports the selected backend and hardware concurrency.
- x86-64 Assembly uses the System V ABI and is compiled only on Linux x86-64. C dispatch checks SSE2 and POPCNT before calling it.
- Other CPUs/platforms use portable C. If the extension cannot be built, the Python fallback remains available.
- The C byte counter and Linux x86-64 Assembly backend are used by scanner/security code.
- The C module dynamically loads the OpenCL runtime without SDK headers at build time. It selects a GPU only when device discovery and kernel compilation succeed. A byte-count/reduction kernel is eligible for immutable bytes buffers at or above 8MiB; mutable buffers and other buffer exporters use the GIL-held CPU path to prevent concurrent mutation while the device reads host memory.
- Every GPU dispatch uses per-call command queue, kernel and buffer objects; unavailable devices, allocation limits and kernel/dispatch failures fall back to CPU. GPU metrics count actual dispatches and CPU fallbacks. No analyzer logic is moved to the GPU.
- The C++17 signature classifier is used by scanner file-type detection, with the Python catalog as fallback.
- Signature sampling uses a bounded 512-byte read from an `os.open` descriptor, requests `O_NOFOLLOW` where available, and compares descriptor `fstat` identity to the walker's no-follow metadata before reading. SHA-256 cache fingerprinting uses the same descriptor identity checks and bounded chunked reads. These protect signature/hash reads against symlink substitution and detected path replacement; analyzer implementations still independently open paths.
- The Rust PyO3 iterator is used by scanner traversal when built; it does not follow symlinks and retains only the active directory iterator stack.
- The Python fallback now consumes `os.scandir` entries directly rather than sorting/materializing each directory's `DirEntry` list; final inventory output is sorted by case-folded path with an exact-path tie-break and existing file/link/special lists are sorted in place to avoid transient duplicate allocations. This reduces peak memory for very high-fan-out directories and at finalization, but does not remove the scanner's global in-memory inventory lists.
- `InventoryStore` is wired into CLI scanner runs at `OUTPUT/.pdt-cache/inventory.sqlite3`. It persists file/directory/symlink/special metadata as records are discovered using bounded SQLite batches, WAL, an 8MiB page-cache target, integrity checks and running/completed metadata checkpoints; target contents and private scan-time identity tuples are not stored. Final directory aggregates are upserted after traversal. The scanner still materializes its public inventory lists and analyzer/report results remain in memory, so this persistence integration does not yet provide end-to-end bounded-memory scans.
- Persistent inventory/index storage, bounded analyzer queues, resumable checkpoints and 100GB+ benchmarks remain mandatory release work.
- Every native component needs ownership/error contracts, sanitizers/fuzz coverage, cross-platform compile tests, deterministic fallback behavior and repeatable benchmarks.

## VCS, hosting and delivery discovery

The VCS analyzer reads local metadata/configuration as inert text. It identifies Git remote providers after stripping credentials, query strings and fragments; detects HEAD state, shallow boundaries, packed refs, submodule declarations, worktree pointers and LFS attributes; and includes initial Mercurial, Subversion, Bazaar, Darcs, Jujutsu, Pijul, CVS and Perforce support. CI/cloud-provider files include GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, AWS CodeBuild/CodeDeploy/CDK/SAM and Google Cloud Build. It never invokes VCS clients, fetches refs, calls provider APIs or executes deployment definitions. Coverage remains partial.

## Local vulnerability intelligence

- Advisory data is imported only from local OSV JSON files into a local SQLite store.
- Scanning is offline and matches supported lockfile-resolved package versions against imported affected version lists/ranges.
- Findings carry CVE/GHSA aliases, severity, affected dependency coordinate, fixed-version boundary, local advisory modification date and file evidence.
- Unsupported range schemes and unavailable parser/resource-budget results are UNKNOWN, never silently clean.
- Version matches are not proof of runtime usage, reachability or exploitability. Advisory snapshots may be stale; reports expose import time and ecosystem coverage.
- No OSV/GHSA/NVD or package-provider endpoint is contacted by scan/import commands.

## Analyzer contract

Implement `project_discovery.analyzers.base.Analyzer`, then expose a no-argument constructor through the `pdt.analyzers` Python entry-point group. Configured analyzers needing local data (for example, the vulnerability database) are instantiated by the CLI with explicit local paths. Plugin code runs in-process and must be trusted. The core never imports target project modules.

## Confidence and privacy

- CONFIRMED: directly observed in source or metadata.
- INFERRED: heuristic conclusion requiring validation.
- UNKNOWN: insufficient evidence, unavailable parser or exhausted resource budget.

No telemetry or network requests. Target files are read-only. Cache and generated reports live outside target roots. Secret/PII values are redacted. Archive members are read only through bounded in-memory streams and are never extracted.
