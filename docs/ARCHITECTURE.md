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
- `FileRecord` carries a private scan-time identity tuple used by analysis but excluded from public JSON/Markdown/HTML output. The private SQLite inventory serializer retains this tuple so typed records can be restored for later analysis.
- Shared `open_verified_binary` / `open_verified_text` helpers reject non-regular and symlink paths, request `O_NOFOLLOW` where available, verify the opened descriptor with `fstat`, and compare available identity fields against the no-follow inventory observation. Bounded Python/text/binary readers use the same boundary.
- Built-in analyzer reads of scanned project files have been migrated to the verified helpers or bounded variants; ZIP/TAR readers operate on verified open descriptors. SHA-256 cache fingerprinting and the 512-byte signature probe also use descriptor identity checks. Focused tests cover replaced files, symlink substitution, bounded reads and serialization privacy.
- The Rust walker currently exposes stable device/inode/change-time identity on Unix. On Windows its stable metadata path does not yet supply a stable file ID to PDT; descriptor `fstat` is compared with a fresh `lstat` at open time, but scan-to-read identity continuity remains a Windows release gate. Third-party plugins also receive the legacy `Path` interface, so the core cannot yet enforce descriptor use inside arbitrary plugin code.
- The Rust PyO3 iterator is used by scanner traversal when built; it does not follow symlinks and retains only the active directory iterator stack.
- The Python fallback consumes `os.scandir` entries directly and keeps only active directory iterators on a depth-proportional stack; it does not materialize per-directory `DirEntry` lists or retain a pending list of sibling paths. In store-backed CLI scans, files use `StoredFileRecords`, while directories, symlinks and special entries use lazy typed `StoredRecordSequence` objects. All use deterministic stored ordering. Analyzer state is written back in bounded batches so subsequent graph, architecture and report passes see updates. Store-backed traversal does not build a directory map: direct-child counts, file counts, byte totals and directory errors are queued as bounded deltas in a separate SQLite directory-state table and overlaid during iteration.
- `InventoryStore` is wired into CLI scanner runs at `OUTPUT/.pdt-cache/inventory.sqlite3`. It persists file/directory/symlink/special metadata as records are discovered using bounded SQLite batches, WAL, an 8MiB page-cache target, integrity checks and running/complete/partial metadata checkpoints; traversal errors are retained as a partial status, and report metrics expose record counts plus SQLite integrity state. Private scan-time file identity is stored only in this private database and excluded from public report serialization; target file contents are never stored. Directory aggregate state uses bounded deltas rather than a per-directory Python map; all four inventory record kinds are exposed lazily. Analyzer findings are also persisted in bounded batches under deterministic SHA-256 content keys, identical serialized findings are deduplicated, and consumers receive a lazy `StoredFindingRecords` sequence. JSON/HTML array and Markdown writers stream to their output handles, and the terminal security summary keeps only a bounded top-25 selection. Per-file analyzer return lists, graph/correlation state and report metrics remain materialized; the browser still loads one embedded report payload. End-to-end bounded-memory analysis and interactive report rendering remain incomplete.
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
