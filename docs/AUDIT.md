# Production-Readiness Audit

**Audit date:** 2026-11-04 · **Branch:** `feat/discovery-engine-foundation` (PR #1) · **Baseline commit:** `1895455`

This audit separates what PDT *actually does* from what its documentation claims, records every defect found with reproducible evidence, and tracks remediation. It was performed by reading the core modules end to end, running the full test suite on Windows with all native extensions built (MSVC 17.14, Rust 1.99, NVIDIA RTX 3060 / OpenCL), scanning real projects end to end, and running an adversarial corpus through every analyzer under a watchdog.

## 1. Verdict

**At the baseline commit, PDT was not functional on any platform.** It is still not ready for a production release, and the remaining release gates are listed in §5.

- **CI was red on all 9 matrix jobs** (Ubuntu/Windows/macOS × Python 3.11–3.13) at the test step. None of the last 100 workflow runs succeeded.
- **`pdt scan` never executed a single per-file analyzer.** The analysis guard compared an `os.stat_result` (a 10-field tuple subclass) positionally against a 5-field identity, so every file was rejected as "identity changed" on every OS. Reports contained only graph/architecture findings and one diagnostic per file. The unit tests call analyzers directly, which is why they never exposed this.
- `pdt compare`, `pdt catalog-add` and `pdt catalog-compare` rejected every real scan report.
- Several documented capabilities were dead code: Python AST security, yarn/pnpm vulnerability matching, report SHA-256 fingerprints and API-style classification.

## 2. Baseline evidence

| Check | Result at `1895455` |
|---|---|
| GitHub Actions, head run | 9/9 jobs failed (`Run test suite with coverage gate`) |
| Local test suite (Windows, Py 3.12) | 59 failed |
| End-to-end scan of this repository | 0 per-file analyzer findings; 1 rejection diagnostic per file |
| Adversarial corpus (37 files) | 8 analyzer hangs (>15 s) from 423-byte YAML files |
| Windows junction loop, Python fallback walker | 800 files / 321 dirs inventoried instead of 25 / 10 |

## 3. Defect register

Severity: **P0** = core feature broken · **P1** = security · **P2** = correctness/precision/operability.
Status values: **Fixed** (implemented and covered by regression tests) · **Open**.

### P0: broken core functionality

| ID | Area | Defect and evidence | Status |
|---|---|---|---|
| PDT-001 | CLI analysis guard | `isinstance(expected, tuple)` treated `os.stat_result` as an identity tuple, so every file was refused on all platforms (reproduced against the HEAD code). | Fixed |
| PDT-002 | Verified reads (Windows) | `st_ctime` differs between `lstat()` and `fstat()` on Python 3.12+, and `DirEntry.stat()` reports `st_dev=st_ino=0`. Every descriptor-verified read failed. | Fixed |
| PDT-003 | Signature detection | The fallback walker passed `stat_result` to the signature reader, so magic bytes were never read and files were classified by extension only. | Fixed |
| PDT-004 | API type classifier | Called `str.decode()` on text lines and crashed on every supported file. | Fixed |
| PDT-005 | compare / catalog | `load_report` only accepted schema `1.0`, while scans write `1.3`. | Fixed |
| PDT-006 | Reports | `FileRecord.sha256` was never assigned (0/143 files), so duplicate-content comparison could never match. | Fixed |
| PDT-007 | Python security | `PythonSecurityAnalyzer` was never registered in `load_analyzers()`. | Fixed |
| PDT-008 | Test suite | 4 stale or non-portable tests plus 2 shadowed duplicate test functions; the CI lint gate could not catch F811. | Fixed |

### P1: security of PDT itself

| ID | Area | Defect and evidence | Status |
|---|---|---|---|
| PDT-101 | Native loader | Windows `LoadLibraryA("OpenCL.dll")` searches the current directory when System32 lacks OpenCL, and the macOS fallback `dlopen("OpenCL.framework/OpenCL")` is CWD-relative. A planted library in a scanned repository could execute code. | Fixed |
| PDT-102 | YAML parsing | Alias ("billion laughs") expansion. A 423-byte file hung the configuration and localization analyzers indefinitely. | Fixed |
| PDT-103 | TAR inspection | Traversal `break`s after the first member larger than 1 MiB, so later `../` and setuid entries were never examined. | Fixed |
| PDT-104 | Fallback walker | Windows junctions/mount points were followed, causing loops and duplicate inventory. | Fixed |
| PDT-105 | XML parsing | `ET.parse(path)` in the mobile, ROS and game-engine analyzers bypassed no-follow verified reads and byte budgets. No entity-declaration guard. | Fixed |
| PDT-106 | HTML report | `str.replace` placeholders were applied over user-controlled text (a path containing `__DATA__` corrupted the report). No Content-Security-Policy. | Fixed |
| PDT-107 | Markdown report | Raw HTML in untrusted file names and titles was emitted verbatim, and backslash escaping inside code spans is invalid in CommonMark. | Fixed |
| PDT-108 | Local databases | On POSIX, the inventory DB was created with umask permissions before `chmod`; the `-wal`/`-shm` files and the fingerprint cache were never restricted. | Fixed |
| PDT-109 | Rust walker | `to_string_lossy()` paths made non-UTF-8 names unopenable and allowed collisions. | Fixed |
| PDT-110 | Native packaging | PyO3 0.23.5 refuses CPython 3.14, so the optional Rust walker silently disappeared on current Python (found on Ubuntu 26.04 / Python 3.14). Upgraded to PyO3 0.30.1; 3.14 added to CI. | Fixed |
| PDT-225 | Redaction | The detector and redactor used separate token lists: Docker PATs, Stripe restricted keys and Azure AccountKey values were detected but copied verbatim into report excerpts. One shared registry (secret_patterns) now drives both. | Fixed |

### P2: correctness, precision and operability

| ID | Area | Defect and evidence | Status |
|---|---|---|---|
| PDT-201 | OSV severity | CVSS vectors and GHSA `MODERATE` were mapped to `UNKNOWN` and reported as LOW. A CVSS 9.8 advisory therefore appeared as LOW. | Fixed |
| PDT-202 | OSV ranges | Events were evaluated in file order instead of sorted order, causing false negatives on multi-range advisories. | Fixed |
| PDT-203 | Lockfiles | `yarn.lock` and pnpm v5/v6 lockfiles yielded **zero** packages, so no vulnerability matching happened. | Fixed |
| PDT-204 | Version comparison | Depended on the undeclared `packaging` package, and npm/Cargo/Go versions were compared with PEP 440 rules. | Fixed |
| PDT-205 | Go | `go.sum` `/go.mod`-only lines were treated as resolved versions, producing false positives. | Fixed |
| PDT-206 | Advisory DB | `lower()` lookups skipped the index (a full scan per package), and PyPI names were normalized on the query side only. | Fixed |
| PDT-207 | Network | Any `identifier.identifier` was reported as a domain (127 false files on a self-scan). | Fixed |
| PDT-208 | Network | A bare `::` and identifier fragments were reported as IPv6 literals. | Fixed |
| PDT-209 | ML | Substring device tokens (`mps` matched `dumps`, `tpu` matched `output`), and training/dataset findings were not gated on ML imports. | Fixed |
| PDT-210 | API types | The REST pattern matched every `.get(` call; the GraphQL pattern matched prose. | Fixed |
| PDT-211 | Secure code | False positives from `RegExp.exec`, Go `db.Exec`, `sprintf` in non-C code and `open(filename)`. Positional `SafeLoader` was flagged, and import aliases went unresolved. | Fixed |
| PDT-212 | Import graph | `src/` layouts left absolute imports unresolved (640 on a self-scan). | Fixed |
| PDT-213 | Python AST | One finding per function, class and import made up 69% of all findings, which bloats reports at scale. | Fixed |
| PDT-214 | Registry | `languages` was a string instead of a tuple in 3 analyzers, so it serialized as single characters. | Fixed |
| PDT-215 | Secrets | UTF-8 was split at chunk boundaries; read failures were reported as MEDIUM security findings; detection and redaction token lists had drifted; archives used weaker rules. | Fixed |
| PDT-216 | Coverage visibility | Analyzer exceptions produced diagnostics only, with no `UNKNOWN` finding. | Fixed |
| PDT-217 | Reports | Findings were ordered by SHA-256 key rather than by severity. | Fixed |
| PDT-218 | Terminal | The security summary omitted file locations. | Fixed |
| PDT-219 | CLI | `--vuln-db` was validated only after the full inventory; there were no exit codes for partial scans or severity gates, no Ctrl-C handling and no `--quiet`/`--no-color`. | Fixed |
| PDT-220 | HTML report | The entire inventory was embedded inline, making the report unusable for large repositories. | Fixed |
| PDT-221 | Repository hygiene | `.gitignore` did not cover native build outputs or coverage data. | Fixed |
| PDT-222 | CI | The lint gate was too narrow, and no end-to-end test asserted that analyzers run inside a real scan. | Fixed |
| PDT-223 | HTML report | Section kicker numbering was inconsistent. | Fixed |
| PDT-224 | ZIP | Case- and Unicode-colliding member names were not detected. | Fixed |

## 4. Capability matrix at the baseline

This matrix records what the audit found at `1895455`, before any remediation. "Finished" means the code works as documented when exercised directly and is covered by tests. "Partial" means it works but is heuristic, lexical or narrower than documented. "Broken" means it is documented but did not work. "Not implemented" means it is catalogued only. Post-remediation status is in §7.

### Finished (implementation sound; blocked end to end by PDT-001/002)

- Filesystem inventory model: files, directories, symlinks, special entries, hidden entries, size buckets, development markers, explicit exclusions with recorded reasons, opt-in `--skip`, and no implicit pruning.
- SQLite inventory, finding and diagnostic persistence with lazy sequences, bounded batches, checkpoints and integrity checks.
- Redaction at the `CodeEvidence` model boundary; Git remote credential sanitization (verified: tokens, userinfo, query and fragment removed).
- ZIP central-directory preflight and bounded in-memory member sampling.
- Streaming JSON report; HTML report client rendering through safe DOM text nodes only.
- Native backends: Rust no-follow walker, C++17 signature classifier (all reads bounds-checked) and C byte counter with per-call OpenCL kernels. All three build with MSVC 17.14 and Rust 1.99.
- Local OSV JSON import and `vuln-db status`.
- Python AST structure extraction; Python import graph for relative imports, with cycle detection and explicit memory ceilings.

### Partial (heuristic or lexical, or narrower than documented)

Network indicators (PDT-207/208), API types and source routes, API contracts (OpenAPI/AsyncAPI/GraphQL/protobuf/WSDL), configuration, deployment/IaC/containers, build systems and CI/CD, test discovery, coverage artifacts, secret patterns (PDT-215), secure-code patterns (PDT-211), data exposure and identity, licenses, lockfile inventory, ML/AI (PDT-209), ROS, mobile, game engines, localization, accessibility, observability, messaging, SQL/NoSQL/Prisma/migrations, OS/platform markers, documents (optional PDF/DOCX), Tree-sitter (optional), VCS/hosting, TAR inspection (PDT-103) and the Python import graph for absolute imports (PDT-212).

### Broken

- End-to-end per-file analysis in `pdt scan` on every platform (PDT-001), and all verified reads on Windows (PDT-002).
- Magic-byte file typing in the fallback walker (PDT-003), the API type classifier (PDT-004), and Python AST security, which was never registered (PDT-007).
- `pdt compare`, `catalog-add` and `catalog-compare` (PDT-005); report SHA-256 fingerprints and duplicate-content comparison (PDT-006).
- Vulnerability matching for yarn and pnpm v5/v6 (PDT-203); OSV severity for CVSS-vector and GHSA-`MODERATE` advisories (PDT-201).

### Not implemented (catalogued as `planned`)

Symbol index across languages, call graph, type systems, performance hotspots, concurrency, memory/resource management, data flow and taint, embedded, firmware, hardware description languages, graphics shaders and frontend component graphs.

## 5. Release gates that remain open

These gates cannot be closed by code changes alone and are not claimed as done:

1. **Large-corpus benchmarks.** The 2 GB / 10 GB / 50 GB / 100 GB+ wall-time, throughput and peak-RSS figures in the roadmap require representative corpora and dedicated hardware. A synthetic scale test is included, but it does not certify those targets.
2. **CI on the final head.** Linux and macOS native builds, plus the x86-64 Assembly path that only builds on Linux, must pass in GitHub Actions on the pushed branch.
3. **Plugin isolation.** Third-party analyzers still run in-process with PDT's permissions, as documented in `docs/PLUGIN_SDK.md`.
4. **Independent security review** of the parsers and native code.

## 6. Re-audit

See [§7](#7-re-audit-results), which is filled in after remediation, with the same checks re-run.
