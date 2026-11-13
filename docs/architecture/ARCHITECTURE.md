# Architecture

## Polyglot system boundary

PDT is not a Python-only scanner. Python is the control plane; native engines and the report client are first-class components with explicit responsibilities.

| Layer | Primary language | Responsibility |
|---|---|---|
| Control plane | Python | CLI, plugin lifecycle, policy, orchestration, cache, findings and report schema |
| Native low-level core | C | Bounded byte counting, host capability reporting and stable extension boundary |
| CPU acceleration | x86-64 Assembly + C dispatch | Linux x86-64 SIMD byte counting with runtime SSE2/POPCNT checks; scalar C fallback |
| GPU byte reduction | OpenCL C loaded dynamically by native C | Opt-in (`--gpu`) large immutable-buffer byte counting, off by default because it measured slower than the CPU; runtime device discovery, 8 MiB dispatch threshold (`--gpu-min-mb`) and CPU fallback; analyzer semantics remain CPU-side |
| Filesystem traversal | Rust + PyO3 | Integrated no-follow directory iterator with native OS metadata and bounded depth state; a persistent index reused across scans remains planned |
| File-signature classification | C++17 | Integrated native magic-byte classifier with Python fallback |
| Report application | JavaScript + HTML/CSS | Separate packaged offline client bundled into the standalone report; filtering, pagination and disclosure controls |
| Domain packs | Polyglot | Language, build, API, database, security, tests, ML/robotics/mobile/game/VCS analyzers |
| Online mode (opt-in) | Python standard library | `online`: URL targets and read-only VCS checkouts (`repositories`), provider REST clients and in-memory scans for `--no-download` (`providers`, `memory_scan`, `credentials`), and OSV.dev/NVD/GitHub advisory lookups (`osv`, `advisories`, `vulnerabilities`) over an HTTPS client with rate limits and a private response cache (`http`, `cache`) |

Each language component must serve a production execution path. Merely listing a language in the roadmap or catalog is not implementation.

## Pipeline

1. Python validates target and output paths and selects the scan mode. A local path is scanned offline. A repository URL is first acquired read-only, either into a private temporary copy (download and analyze) or, with `--no-download`, through the provider's API into memory; the same pipeline then runs (see [ONLINE_MODE.md](../guides/ONLINE_MODE.md)).
2. Python inventory records files, directories, symlinks and special entries, each with its owner and group IDs and platform attributes (and, with `--security-metadata`, its security descriptor or POSIX ACLs; see `inventory.entry_metadata`); traversal does not follow symlinks and does not silently prune development/dependency trees. Once the walk is complete, every link target is resolved against the inventory itself (`inventory.links`), never the filesystem.
3. C provides native byte-counting and host capability reporting. Linux x86-64 may dispatch CPU byte counting to Assembly after runtime feature checks; large immutable byte buffers may use a dynamically loaded OpenCL reduction kernel when a supported GPU is available.
4. Python coordinates analyzers and per-domain resource policies without importing or executing target modules. Third-party plugins run in sandboxed host processes and receive private copies of the files they analyze (see [PLUGIN_SDK.md](../guides/PLUGIN_SDK.md)).
5. Polyglot analyzers parse source/configuration/contracts and use locally provisioned optional parsers with explicit capability states. Source analyzers share one structural code model per file (`intelligence.model`: the Python syntax tree, or a linear-time structural lexer for about 25 brace languages) and record code facts (`intelligence.facts`) next to their findings.
6. Vulnerability intelligence matches resolved lockfile coordinates against an operator-imported OSV SQLite snapshot (`--vuln-db`) and, only with `--vuln-online`, against OSV.dev with optional NVD and GitHub Advisory enrichment. Without `--vuln-online` there is no network fallback.
7. Correlation links symbols, endpoints, VCS remotes, dependencies, configuration and docs with evidence spans. The code index (`intelligence.index`) reads the stored facts through a read-only connection and temporary tables: symbol index, call graph, module graph, cross-module taint flows, domain summaries and integration points (see [CODE_INTELLIGENCE.md](CODE_INTELLIGENCE.md)).
8. JSON/Markdown are generated locally; the offline JavaScript/TypeScript report application renders paginated/lazy views without remote assets.

## Native ABI and safety

- The current C extension accepts explicit contiguous Python buffers and returns bounded scalar results; it reports the selected backend and hardware concurrency.
- x86-64 Assembly uses the System V ABI and is compiled only on Linux x86-64. C dispatch checks SSE2 and POPCNT before calling it.
- Other CPUs/platforms use portable C. If the extension cannot be built, the Python fallback remains available.
- The C byte counter and Linux x86-64 Assembly backend are used by scanner/security code.
- The C module dynamically loads the OpenCL runtime without SDK headers at build time. It selects a GPU only when device discovery and kernel compilation succeed. With `--gpu`, a byte-count/reduction kernel is eligible for immutable bytes buffers at or above the threshold (8 MiB by default); without it the OpenCL runtime is never loaded; mutable buffers and other buffer exporters use the GIL-held CPU path to prevent concurrent mutation while the device reads host memory.
- Every GPU dispatch uses per-call command queue, kernel and buffer objects; unavailable devices, allocation limits and kernel/dispatch failures fall back to CPU. GPU metrics count actual dispatches and CPU fallbacks. No analyzer logic is moved to the GPU.
- The C++17 classifier matches the signature catalog's rules (a table generated from the Python catalog) and Python validates each candidate; the Python matcher is the fallback. `file_type` comes from the content, and `name_type` records what the name suggests, apart from it.
- `FileRecord` carries a private scan-time identity tuple used by analysis but excluded from public JSON/Markdown/HTML output. The private SQLite inventory serializer retains this tuple so typed records can be restored for later analysis.
- Shared `open_verified_binary` / `open_verified_text` helpers reject non-regular and symlink paths, request `O_NOFOLLOW` where available, verify the opened descriptor with `fstat`, and compare available identity fields against the no-follow inventory observation. Bounded Python/text/binary readers use the same boundary.
- Built-in analyzer reads of scanned project files have been migrated to the verified helpers or bounded variants; ZIP/TAR readers operate on verified open descriptors. SHA-256 cache fingerprinting and the 4 KiB signature sample (with its ISO 9660 and OLE directory probes) also use descriptor identity checks. Focused tests cover replaced files, symlink substitution, bounded reads and serialization privacy.
- The Rust walker exposes stable device/inode/change-time identity on Unix. On Windows it does not report a file ID, so PDT pins the identity of the descriptor it opens for the signature sample (volume serial and file index from `fstat`) and verifies every later analyzer read against it. Only the window between directory enumeration and that first open is not identity-pinned on Windows. Isolated third-party plugins never see a project path: PDT reads each file through the verified helpers and gives the plugin a private copy. Only plugins run with `--plugin-isolation off` still receive the legacy `Path` interface.
- The Rust PyO3 iterator is used by scanner traversal when built; it does not follow symlinks and retains only the active directory iterator stack.
- The Python fallback consumes `os.scandir` entries directly and keeps only active directory iterators on a depth-proportional stack; it does not materialize per-directory `DirEntry` lists or retain a pending list of sibling paths. In store-backed CLI scans, files use `StoredFileRecords`, while directories, symlinks and special entries use lazy typed `StoredRecordSequence` objects. All use deterministic stored ordering. Analyzer state is written back in bounded batches so subsequent graph, architecture and report passes see updates. Store-backed traversal does not build a directory map: direct-child counts, file counts, byte totals and directory errors are queued as bounded deltas in a separate SQLite directory-state table and overlaid during iteration.
- `InventoryStore` is wired into CLI scanner runs at `OUTPUT/.pdt-cache/inventory.sqlite3`. It persists file/directory/symlink/special metadata as records are discovered using bounded SQLite batches, WAL, an 8MiB page-cache target, integrity checks and running/complete/partial metadata checkpoints; traversal errors are retained as a partial status, and report metrics expose record counts plus SQLite integrity state. Private scan-time file identity is stored only in this private database and excluded from public report serialization; target file contents are never stored. Directory aggregate state uses bounded deltas rather than a per-directory Python map; all four inventory record kinds are exposed lazily. Analyzer findings are also persisted in bounded batches under deterministic SHA-256 content keys, identical serialized findings are deduplicated, and consumers receive a lazy `StoredFindingRecords` sequence. Scan diagnostics are stored in a separate insertion-ordered SQLite sequence with transactional IDs across independent store connections; repeats are preserved and JSON/HTML/Markdown writers stream them from `StoredDiagnosticRecords`. The terminal security summary keeps only a bounded top-25 selection. The Python dependency graph's modules, edges, unresolved imports and skipped modules are stored the same way and streamed by the report writers (`StoredRows`). So are the architecture layout's top-level component counts, aggregated in bounded batches. Per-file analyzer return lists and the other report metrics remain materialized; the browser still loads one embedded report payload. End-to-end bounded-memory analysis and interactive report rendering remain incomplete.
- Persistent inventory storage, bounded analyzer queues (at most twice the worker count of pending batches) and resumable checkpoints (`--resume`) are implemented; the 2 GB–100 GB+ benchmarks remain mandatory release work.
- Every native component needs ownership/error contracts, sanitizers/fuzz coverage, cross-platform compile tests, deterministic fallback behavior and repeatable benchmarks.

## VCS, hosting and delivery discovery

The VCS analyzer reads local metadata/configuration as inert text. It identifies Git remote providers after stripping credentials, query strings and fragments; detects HEAD state, shallow boundaries, packed refs, submodule declarations, worktree pointers and LFS attributes; and includes initial Mercurial, Subversion, Bazaar, Darcs, Jujutsu, Pijul, CVS and Perforce support. CI/cloud-provider files include GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, AWS CodeBuild/CodeDeploy/CDK/SAM and Google Cloud Build. It never invokes VCS clients, fetches refs, calls provider APIs or executes deployment definitions. Coverage remains partial.

## Local vulnerability intelligence

- Advisory data is imported only from local OSV JSON files into a local SQLite store.
- Matching against the store is offline and compares supported lockfile-resolved package versions with the imported affected version lists and ranges.
- `--vuln-online` (the `online` package) also looks packages up in OSV.dev. Only ecosystem, package name and version are sent, responses are cached privately, and a failed or partial lookup is an `UNKNOWN` finding, never a clean result.
- Findings carry CVE/GHSA aliases, severity, affected dependency coordinate, fixed-version boundary, local advisory modification date and file evidence.
- Unsupported range schemes and unavailable parser/resource-budget results are UNKNOWN, never silently clean.
- Version matches are not proof of runtime usage, reachability or exploitability. Advisory snapshots may be stale; reports expose import time and ecosystem coverage.
- No OSV/GHSA/NVD or package-provider endpoint is contacted by scan/import commands.

## Analyzer contract

Implement `project_discovery.analyzers.base.Analyzer`, then expose a no-argument constructor through the `pdt.analyzers` Python entry-point group. Configured analyzers needing local data (for example, the vulnerability database) are instantiated by the CLI with explicit local paths. The core never imports target project modules, and it never imports plugin code either (unless `--plugin-isolation off` is passed).

Plugin execution (`plugins.isolation`, `plugins.host`, `plugins.sandbox`, `plugins.appcontainer`, `plugins.protocol`):

1. For each entry point, PDT starts a host (`python -I -B`) with an allowlisted environment and a private staging folder. On Windows in `sandbox` mode (`plugins.appcontainer`), PDT starts the host suspended inside an AppContainer without capabilities, from a copy of the standard-library runtime and staged copies of PDT and the plugin's distributions, grants the container read access to those folders only, and places the host in a kill-on-close job object before it runs. In the other modes, PDT places the host in a job object before sending its configuration.
2. The host applies the operating-system sandbox, attempts each forbidden action to verify it, and only then imports the plugin. It reports the verified restrictions and the plugin's metadata, which PDT validates.
3. The analysis engine asks isolated plugins about `supports()` once per batch. For each supported file, PDT stages a verified copy, sends a JSON request and rebuilds the findings from the JSON reply, attributing, bounding and redacting them.
4. A watchdog kills hosts that exceed the request timeout. A crashed, hung or misbehaving host costs one `UNKNOWN` coverage finding and is replaced; three consecutive failures disable the plugin. Worker processes rebuild proxies from the coordinator's validated plugin specs and start their own hosts.

## Confidence and privacy

- CONFIRMED: directly observed in source or metadata.
- INFERRED: heuristic conclusion requiring validation.
- UNKNOWN: insufficient evidence, unavailable parser or exhausted resource budget.

No telemetry. A local scan makes no network request; the network is used only for a URL target and for `--vuln-online`, and the report's `scan` block records every kind of access. Target files are read-only. Cache and generated reports live outside target roots. Secret/PII values are redacted. Archive members are read only through bounded in-memory streams and are never extracted.
