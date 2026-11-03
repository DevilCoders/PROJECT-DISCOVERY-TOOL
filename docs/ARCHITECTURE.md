# Architecture

## Polyglot system boundary

PDT is not a Python-only scanner. Python is the control plane; native engines and the report client are first-class components with explicit responsibilities.

| Layer | Primary language | Responsibility |
|---|---|---|
| Control plane | Python | CLI, plugin lifecycle, policy, orchestration, cache, findings and report schema |
| Native low-level core | C | Bounded byte scanning, file-signature primitives, host capability reporting and stable extension boundary |
| CPU acceleration | x86-64 Assembly + C dispatch | Linux x86-64 SIMD byte counting with runtime SSE2/POPCNT checks; scalar C fallback |
| High-throughput traversal | Rust (required next subsystem) | Bounded concurrent walker, inventory streaming, resumable checkpoints and archive/index pipeline |
| Complex SDK integration | C++ | Optional native adapters needing mature C++ libraries/SDKs |
| Report application | JavaScript/TypeScript + HTML/CSS | Offline interactive views, filtering, pagination, directory and architecture graphs |
| Domain packs | Polyglot | Language, build, API, database, security, tests, ML/robotics/mobile/game/VCS analyzers |

Each language component must serve a production execution path. Merely listing a language in the roadmap or catalog is not implementation.

## Pipeline

1. Python validates target/output paths and local-only policy.
2. Python inventory records files, directories, symlinks and special entries; traversal does not follow symlinks and does not silently prune development/dependency trees.
3. C provides native byte-count/signature primitives and host hardware capability reporting. Linux x86-64 may dispatch byte counting to Assembly only after runtime feature checks.
4. Python coordinates analyzer plugins and per-domain resource policies without importing or executing target modules.
5. Polyglot analyzers parse source/configuration/contracts and use locally provisioned optional parsers with explicit capability states.
6. Local vulnerability intelligence optionally matches resolved lockfile coordinates against an operator-imported OSV SQLite snapshot. No scan-time network fallback exists.
7. Correlation links symbols, endpoints, VCS remotes, dependencies, configuration and docs with evidence spans.
8. JSON/Markdown are generated locally; the offline JavaScript/TypeScript report application renders paginated/lazy views without remote assets.

## Native ABI and safety

- The current C extension accepts explicit contiguous Python buffers and returns bounded scalar results; it reports the selected backend and hardware concurrency.
- x86-64 Assembly uses the System V ABI and is compiled only on Linux x86-64. C dispatch checks SSE2 and POPCNT before calling it.
- Other CPUs/platforms use portable C. If the extension cannot be built, the Python fallback remains available.
- The current native byte counter is used by scanner/security code; it is not yet a native filesystem walker.
- Rust traversal/indexing, bounded streaming inventory and 100GB+ benchmarks remain mandatory release work.
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
