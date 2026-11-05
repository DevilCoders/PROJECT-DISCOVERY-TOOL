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
| PDT-226 | Offline guarantee | `tree-sitter-language-pack` 1.23+ downloads grammar bundles from the network inside `get_parser()`, and its `has_parser()` probe does not exist in 1.23.1, so a scan of a polyglot repository silently made network requests. Parsing is now gated on `downloaded_languages()`: grammars that are not already provisioned are reported as `UNKNOWN` and nothing is fetched. | Fixed |
| PDT-227 | Regex denial of service | *Found in re-audit.* Scanned content is untrusted, yet the redaction patterns applied to every excerpt were cubic: 2,000 characters of `tokentoken…` took 9.3 s, so one crafted line could stall a worker indefinitely. The secret detector, network domain and string-literal scanners, email, archive-member, Nix-assignment and Markdown patterns were quadratic (50–220 ms at 4 KB, minutes to hours on megabyte lines). Each now uses start anchoring, possessive quantifiers, RFC length bounds or a linear scanner, and `tests/test_regex_complexity.py` times every package regex against 60 adversarial 48 KB inputs. | Fixed |
| PDT-230 | CI supply chain | *Found in re-audit by PDT's own deployment analyzer.* Workflows referenced `actions/checkout@v4`, `actions/setup-python@v5` and `dtolnay/rust-toolchain@stable`, which are mutable tags and branches. They are now pinned to verified commit SHAs, with the version in a comment. | Fixed |

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
| PDT-228 | Secrets (generic rule) | *Found in re-audit (self-scan).* The generic credential-assignment rule let separators span line breaks and treated unquoted right-hand sides in source code as values (for example a typed empty list or a `re.compile(...)` call assigned to a name containing "secret" or "token"), producing 10 false HIGH findings in PDT's own source. It also missed JSON/PHP keys (`"password": …`, `'password' => …`), Go `:=` and typed defaults (`secret: str = …`). In programming languages only string literals now count; configuration, environment and shell files keep unquoted values, and URL and path values are not reported as secrets. | Fixed |
| PDT-229 | Privacy indicators | *Found in re-audit (self-scan).* Email-shaped values were reported for domains that cannot receive mail: `pkg@1.0.0`, `logo@2x.png` and reserved `example.*`/`.test` names. That last case contradicted the analyzer's own advice to use reserved example addresses. SCP remotes and URL user info were also reported. Field-name inventories fired on prose documentation and on the bare word "mobile", and the PII name inventory was MEDIUM while the equivalent credential key-name inventory is LOW. Domains are now validated against the bundled IANA list, reserved and URL forms are skipped, prose files contribute values only, and both name inventories are LOW. | Fixed |
| PDT-231 | Interrupt handling | *Found in re-audit (code review).* A terminal Ctrl-C reaches every process in the group. Idle pool workers died inside `call_queue.get()`, each printing a `KeyboardInterrupt` traceback, and busy workers returned the interrupt as a task result. A SIGINT sent only to the coordinator (for example by a supervisor) waited for every in-flight batch to finish. Workers now ignore SIGINT, and a cancelled scan terminates them immediately. | Fixed |
| PDT-232 | Resume integrity | *Found in re-audit (live interrupt/resume test).* An analyzed file's record, whose SHA-256 marks it complete for `--resume`, was committed in batches through its own connection, independently of the finding store's 512-row buffer. A `KeyboardInterrupt` during a finding commit also discarded the rolled-back rows. A crash or interrupt in that window left files marked analyzed whose findings were never stored, so `--resume` skipped them and silently lost those findings. Also, an interrupted scan kept none of its uncommitted progress, so resume redid it. Records are now committed only after the finding store has flushed, an interrupted flush keeps its rows, and an interrupted scan saves its completed files. Regression tests check the ordering at every commit and resume an interrupted scan to identical findings. | Fixed |
| PDT-233 | Console output | *Found while adding plugin isolation.* Status lines were printed as Rich markup, so `pdt scan` on a directory whose path contained `[/x]` crashed with `MarkupError`, and `[bold]` in a path restyled the output. `pdt capabilities` printed plugin diagnostics, which are plugin-controlled text, the same way. Messages are now escaped, and plugin names and errors never pass through markup. | Fixed |
| PDT-234 | Coverage reporting | *Found in the re-audit self-scan on Windows.* The API endpoint analyzer decided whether its 32 MiB budget had truncated a file by comparing the file size with the length of the decoded text. Universal-newline decoding shortens CRLF text, so every CRLF source file it supports got a false "API endpoint scan budget reached" `UNKNOWN` finding: four files in this repository, and potentially every source file of a Windows-checked-out project. Truncation is now reported only when content remains after the budget is used. | Fixed |

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

Gates 1, 2 and 4 cannot be closed by code changes alone and are not claimed as done. Gate 3 is closed as far as each operating system allows:

1. **Large-corpus benchmarks.** The 2 GB / 10 GB / 50 GB / 100 GB+ wall-time, throughput and peak-RSS figures in the roadmap require representative corpora and dedicated hardware. The tooling is ready (`tools/benchmark.py`, `--resume`, `--inventory-only` and per-phase telemetry; see [BENCHMARKS.md](BENCHMARKS.md)), and the runs are waiting for operator-provided corpora. Small-scale measurements do not certify those targets.
2. **CI on the final head.** Linux and macOS native builds, plus the x86-64 Assembly path that only builds on Linux, must pass in GitHub Actions on the pushed branch. `4a19af3` passed all 14 jobs on both its push and pull-request runs; every later push must pass the same matrix before merge.
3. **Plugin isolation: closed on Linux and macOS, partial on Windows.** Third-party analyzers now run in sandboxed host processes by default ([PLUGIN_SDK.md](PLUGIN_SDK.md)). On Linux and macOS, a plugin cannot write files, read outside the runtime and its staged input, use the network or start processes. On Linux this was verified by the red-team run in §7, which also showed that a plugin cannot trace, signal or throttle PDT's process. On macOS it was verified by the sandbox tests on GitHub's macOS runners (Python 3.11–3.14); the profile also denies signals to other processes, but no test covers that yet. Windows denies writes, process creation and access to PDT's memory. It cannot deny reads or network access without ACL changes, and plugins there can terminate same-user processes. Untrusted plugins should therefore run on Linux or macOS. The sandbox does not cover a package's install-time or `.pth` startup code.
4. **Independent security review** of the parsers and native code.

## 6. Re-audit

See [§7](#7-re-audit-results), which is filled in after remediation, with the same checks re-run.

## 7. Re-audit results

**Re-audit date:** 2026-11-05 · **Code:** the remediated branch after `352fe33`, plus the fixes for the re-audit's own findings.

The baseline checks were re-run, and new kinds of check were added. The re-audit found six more defects: PDT-227 (regex denial of service), PDT-228 and PDT-229 (self-scan precision), PDT-230 (CI supply chain), PDT-231 (interrupt handling) and PDT-232 (resume integrity). Adding plugin isolation (gate 3 in §5) surfaced PDT-233 (console markup), and the final self-scan surfaced PDT-234 (false truncation reports for CRLF files). All are fixed and recorded in §3 above.

| Check | Baseline (`1895455`) | Re-audit |
|---|---|---|
| GitHub Actions | 9/9 jobs failed | `4a19af3`: 14/14 jobs passed on both the push and pull-request runs (lint, Ubuntu/Windows/macOS × CPython 3.11–3.14, optional integrations). The plugin-isolation tests have no skip paths, so they ran under the real sandbox on every runner: Landlock and seccomp on GitHub's Ubuntu kernels, Seatbelt on macOS, and the job object with untrusted integrity on Windows Server. |
| Test suite | 59 failed (Windows, Py 3.12) | 589 tests. Windows 10, Py 3.12: 576 passed, 13 skipped (symlink privilege, POSIX modes, FIFO, case-sensitive fixtures). Ubuntu 26.04, Py 3.14, with the C SSE2/POPCNT assembly, C++ and Rust backends online: 586 passed, 3 skipped (no OpenCL GPU, NTFS-only cases). Coverage 82–83% against an 80% gate; plugin-host code runs in subprocesses that coverage does not measure. `ruff --select E9,F,B,PLE` clean. |
| End-to-end scan of this repository | 0 per-file analyzer findings | 201 files analyzed with all 35 analyzers loaded; per-file findings from every applicable analyzer; no `UNKNOWN` coverage findings (after PDT-234); exit 0 under `--strict` |
| Adversarial corpus (37 files) | 8 analyzer hangs | Every analyzer on every file under a 15 s watchdog: 0 hangs, 0 crashes, 0 calls over 3 s. End-to-end `--strict` scans exit 0, and the process and thread executors produce identical findings. |
| Windows junction loop | 800 files / 321 dirs instead of 25 / 10 | Junctions are recorded as links and never followed (regression tests for both walkers) |
| Regex complexity *(new)* | — | 312 package regexes × 266 adversarial inputs at 16 KB: worst case 16 ms. Before the fix, the redactor took 9.3 s on 2 KB and seven detectors took 50–220 ms on 4 KB. Guarded by `tests/test_regex_complexity.py`. |
| Self-scan precision *(new)* | — | CRITICAL/HIGH/MEDIUM findings outside `tests/` went from 30 (10 HIGH) to 0. The remaining HIGH/MEDIUM findings are deliberate credential fixtures in `tests/`, lowered one level and labelled as such. |
| Interrupt and resume *(new)* | — | 10,000-file synthetic corpus (`tools/benchmark.py generate`, seed 7) on a 4-core Ubuntu host, Py 3.14, 4 workers. SIGINT to the process group 20 s into analysis: exit 130 within 0.2 s, no process left running, no traceback. `--resume` skipped the 544 completed files and produced the same 14,045 findings and file hashes as an uninterrupted scan, exiting 0 under `--strict`. Process and thread executors produced identical findings. |
| Plugin isolation *(new)* | Plugins ran in-process with PDT's permissions | `tests/test_plugin_isolation.py` loads real plugin modules through entry points and checks five things. (1) The sandbox the host probes matches what a hostile plugin observes, including import-time code. (2) Findings are re-attributed, redacted and bounded. (3) Crashes, hangs (2 s timeout) and protocol floods are contained, and 3 consecutive failures disable the plugin. (4) The environment is scrubbed, and Ctrl-C leaves no host running. (5) The process executor matches the thread executor. A BPF interpreter checks the seccomp filter's decisions for x86-64 and arm64. A `pip install`-ed plugin loaded from its real entry point, ran under `--strict`, and its finding was attributed to its distribution. Cost: 0.3–1.1 ms per file the plugin handles (2,000 files, 4 workers). |
| Plugin sandbox red-team *(new)* | — | A hostile plugin ran 37 attacks, plus a harmless `socketpair` control, during a real scan. Ubuntu 26.04 (kernel 7.0, Landlock ABI 8, seccomp): **all denied**. These included reads of the project, PDT's database, `/etc` and PDT's `/proc/<pid>/environ`; writes to `/tmp`, `/dev/shm` and its staging folder; chmod, utime, xattr, symlinks and hard links; fork, exec and memfd exec; TCP, UDP, Unix and netlink sockets; ptrace, signals, `prlimit` and CPU pinning against PDT; user namespaces, io_uring and keyctl; `/dev/tty` and TIOCSTI; and an 8 GiB allocation. Only the control succeeded. Windows 10: writes (including LocalLow, `C:\Users\Public` and import-time writes), `subprocess`, direct `CreateProcessW`, writing PDT's memory and the 8 GiB allocation were denied. Reads, loopback TCP/UDP and opening PDT with terminate rights succeeded, as documented. No file outside the staging folder was created, and the project was unchanged. |

### Capability status after remediation

- **Working end to end.** These items were blocked or broken at the baseline: per-file analysis in `pdt scan` on every platform; verified, identity-pinned reads; magic-byte typing in both walkers; API type classification; Python AST security (one engine); `compare`, `catalog-add` and `catalog-compare` on real reports; report SHA-256 fingerprints; yarn v1/Berry and pnpm v5/v6/v9 vulnerability matching; and CVSS/GHSA-based OSV severity.
- **Added.** A multi-process engine with worker-crash isolation; `--resume`, `--inventory-only`, `--fail-on` and `--strict`; `pdt capabilities`; per-phase timing, throughput and peak-RSS telemetry; `tools/benchmark.py`; offline OSV ZIP import with provenance; bounded HTML embedding; a linear-time guarantee for every package regex; and sandboxed, verified plugin isolation (`--plugin-isolation`).
- **Still partial.** The analyzers listed as Partial in §4 are pattern-based by design. The precision defects this audit found in them are fixed (PDT-207–211, PDT-215, PDT-228, PDT-229), but they remain lexical indicators, not semantic analyses.
- **Not implemented.** The 13 `planned` domains in §4 are still catalogue entries only: symbol index, call graph, type systems, performance hotspots, concurrency, memory and resource management, data flow and taint, embedded, firmware, hardware description languages, graphics shaders and frontend component graphs.

### Verdict

**0.2.0 is a release candidate, not a production release.** Every defect recorded by the audit and this re-audit is fixed and covered by a regression test, and the same 589-test suite passes on Windows and Linux. Plugin isolation (gate 3) is closed on Linux and macOS and partial on Windows, as described in §5. These gates remain open: large-corpus benchmarks, which are waiting for operator data; CI on each final head; and an independent security review, which should now include the plugin sandbox.
