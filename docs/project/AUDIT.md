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
| PDT-235 | Import graph and code index | *Found in the 2026-11-12 re-audit (§12).* A scan root that is itself a Python package (a root `__init__.py`, as in add-on repositories or `pdt scan src/pkg`) never finished: the package walk climbed from `.` to `PurePosixPath(".").parent`, which is `.` again. The walk now stops at the scan root. | Fixed |
| PDT-236 | Process executor | *Found in the 2026-11-12 re-audit.* When a worker died, every in-flight future of the broken pool restarted the pool again, which cancelled the batches already queued on the replacement, and the scan aborted with an unhandled `CancelledError`. A pool is now replaced once per breakage, cancelled futures are handled like broken ones, and a file is blamed only after failing twice on its own. | Fixed |
| PDT-237 | Inventory | *Found in the 2026-11-12 re-audit.* The fallback walker crashed the whole scan on a WSL (LX) symlink, because `os.readlink` raises `ValueError` for it. The Rust walker dropped link-read errors, so unreadable links were reported as `internal`. Both walkers now record such links with `target_state: "unreadable"`, scope `unknown`, and an entry error. | Fixed |
| PDT-238 | Tree-sitter analyzer | *Found in the 2026-11-12 re-audit.* With grammars provisioned, every file got "Tree-sitter analysis error", because the analyzer passed `str` to `Parser.parse()`, which accepts bytes only. C# was mapped to `c_sharp`, a name the grammar pack does not use. The tests used fake parsers, and CI provisioned no grammars. Parsing now uses bytes, error columns count characters, and CI provisions real grammars for the tests. | Fixed |

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
| PDT-239 | Terminal and report output | *Found in the 2026-11-12 re-audit.* Escape sequences in scanned content reached the console and Markdown verbatim: a flagged source line could retitle or clear the operator's terminal and forge links (OSC 0/8, CSI 2J). Plugin exception and load-error text took the same path. C0/C1 control characters are now neutralized in findings, code evidence, diagnostics, status lines and Markdown. | Fixed |
| PDT-240 | Comparison report | *Found in the 2026-11-12 re-audit.* `pdt compare` and `catalog-compare` wrote dependency, module and path names from scanned projects into `project-comparison.md` verbatim, so a `package.json` entry could inject HTML, links or Markdown blocks: the PDT-107 defect class in the second Markdown writer. Every value now goes through the scan report's neutralizer. | Fixed |
| PDT-241 | Lockfiles and online advisories | *Found in the 2026-11-12 re-audit.* npm v1 lockfiles record git and local dependencies as their version (`git+https://user:token@host/repo.git`, `file:../lib`). The string reached report evidence and, with `--vuln-online`, OSV.dev and the response cache. Such specifiers are no longer versions: the names are reported as an `UNKNOWN` coverage gap, `npm:` aliases resolve to the real package, and only plain versions are ever sent online. | Fixed |
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
| PDT-242 | Plugins with `--plugin-isolation off` | *Found while fixing PDT-236.* Process-mode workers rediscovered entry points instead of loading the ones the coordinator had loaded, so a worker could run a different plugin set, and a worker-side load failure went unreported. Workers now load exactly the coordinator's entry points and refuse to run without them. | Fixed |

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

1. **Large-corpus benchmarks.** The 2 GB / 10 GB / 50 GB / 100 GB+ wall-time, throughput and peak-RSS figures in the roadmap require representative corpora and dedicated hardware. The tooling is ready (`tools/benchmark.py`, `--resume`, `--inventory-only` and per-phase telemetry; see [BENCHMARKS.md](../guides/BENCHMARKS.md)), and the runs are waiting for operator-provided corpora. Small-scale measurements do not certify those targets.
2. **CI on the final head.** Linux and macOS native builds, plus the x86-64 Assembly path that only builds on Linux, must pass in GitHub Actions on the pushed branch. `4a19af3` passed all 14 jobs on both its push and pull-request runs; every later push must pass the same matrix before merge.
3. **Plugin isolation: closed on Linux, macOS and Windows.** Third-party analyzers run in sandboxed host processes by default ([PLUGIN_SDK.md](../guides/PLUGIN_SDK.md)). On every platform a plugin cannot write files, read outside the runtime and its staged input, use the network or start processes. On Linux this was verified by the red-team run in §7, which also showed that a plugin cannot trace, signal or throttle PDT's process. On macOS it was verified by the sandbox tests on GitHub's macOS runners (Python 3.11–3.14). The escape test also checks, on every platform, that a sandboxed plugin cannot signal or open PDT's process, while the same plugin can in `process` mode. On Windows, hosts have run in an AppContainer without capabilities since 2026-11-06, which also stops them from opening PDT's or any other process (§9). The sandbox does not cover a package's install-time or `.pth` startup code.
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
| Plugin isolation *(new)* | Plugins ran in-process with PDT's permissions | `tests/plugins/test_plugin_isolation.py` loads real plugin modules through entry points and checks five things. (1) The sandbox the host probes matches what a hostile plugin observes, including import-time code. (2) Findings are re-attributed, redacted and bounded. (3) Crashes, hangs (2 s timeout) and protocol floods are contained, and 3 consecutive failures disable the plugin. (4) The environment is scrubbed, and Ctrl-C leaves no host running. (5) The process executor matches the thread executor. A BPF interpreter checks the seccomp filter's decisions for x86-64 and arm64. A `pip install`-ed plugin loaded from its real entry point, ran under `--strict`, and its finding was attributed to its distribution. Cost: 0.3–1.1 ms per file the plugin handles (2,000 files, 4 workers). |
| Plugin sandbox red-team *(new)* | — | A hostile plugin ran 37 attacks, plus a harmless `socketpair` control, during a real scan. Ubuntu 26.04 (kernel 7.0, Landlock ABI 8, seccomp): **all denied**. These included reads of the project, PDT's database, `/etc` and PDT's `/proc/<pid>/environ`; writes to `/tmp`, `/dev/shm` and its staging folder; chmod, utime, xattr, symlinks and hard links; fork, exec and memfd exec; TCP, UDP, Unix and netlink sockets; ptrace, signals, `prlimit` and CPU pinning against PDT; user namespaces, io_uring and keyctl; `/dev/tty` and TIOCSTI; and an 8 GiB allocation. Only the control succeeded. Windows 10: writes (including LocalLow, `C:\Users\Public` and import-time writes), `subprocess`, direct `CreateProcessW`, writing PDT's memory and the 8 GiB allocation were denied. Reads, loopback TCP/UDP and opening PDT with terminate rights succeeded, as documented. No file outside the staging folder was created, and the project was unchanged. |

### Capability status after remediation

- **Working end to end.** These items were blocked or broken at the baseline: per-file analysis in `pdt scan` on every platform; verified, identity-pinned reads; magic-byte typing in both walkers; API type classification; Python AST security (one engine); `compare`, `catalog-add` and `catalog-compare` on real reports; report SHA-256 fingerprints; yarn v1/Berry and pnpm v5/v6/v9 vulnerability matching; and CVSS/GHSA-based OSV severity.
- **Added.** A multi-process engine with worker-crash isolation; `--resume`, `--inventory-only`, `--fail-on` and `--strict`; `pdt capabilities`; per-phase timing, throughput and peak-RSS telemetry; `tools/benchmark.py`; offline OSV ZIP import with provenance; bounded HTML embedding; a linear-time guarantee for every package regex; and sandboxed, verified plugin isolation (`--plugin-isolation`).
- **Still partial.** The analyzers listed as Partial in §4 are pattern-based by design. The precision defects this audit found in them are fixed (PDT-207–211, PDT-215, PDT-228, PDT-229), but they remain lexical indicators, not semantic analyses. §8 adds a shared code model under them; imports, REST endpoints (client calls), RPC (gRPC services and stubs) and messaging (topic names) gained structural depth from it.
- **Not implemented at 0.2.0, implemented since.** The 13 domains that were `planned` (symbol index, call graph, type systems, performance hotspots, concurrency, memory and resource management, data flow and taint, embedded, firmware, hardware description languages, graphics shaders, frontend component graphs and multi-project integration) now have shipped analyzers and are catalogued as `partial`. See §8.

### Verdict

**0.2.0 is a release candidate, not a production release.** Every defect recorded by the audit and this re-audit is fixed and covered by a regression test, and the same 589-test suite passes on Windows and Linux. Plugin isolation (gate 3) was closed on Linux and macOS and partial on Windows at 0.2.0; §9 closes it on Windows. These gates remain open: large-corpus benchmarks, which are waiting for operator data; CI on each final head; and an independent security review, which should now include the plugin sandbox.

## 8. Code intelligence and the formerly planned domains

**Date:** 2026-11-06 · **Scope:** the work after `3261602` (see the Unreleased section of the [changelog](../../CHANGELOG.md)). Methods and limits per analyzer are in [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md).

### What was added

- **A shared code model.** Python comes from the syntax tree; about 25 brace languages come from a linear-time structural lexer that blanks comments and strings while keeping offsets. Each file is modelled once per worker and reused by every analyzer.
- **Code facts and a cross-file index.** Facts are stored with each file's findings in the same transaction, so `--resume` stays consistent, and are bounded per file and per table. After analysis, read-only passes build the symbol index, call graph (with recursion cycles), unreferenced private functions, test links, a polyglot module graph and the domain summaries. `pdt query` reads the index.
- **Twelve analyzers** for the formerly planned domains, plus the integration map in `pdt compare`. Python data flow is semantic: labels are propagated through assignments, branches, loops and same-module helper summaries iterated to a fixed point, and flows are joined across modules in the index. The other languages are analysed structurally, and every heuristic result is `INFERRED`.

### Verification

| Check | Result |
|---|---|
| Test suite | 695 tests on the merged head, which also contains the online multi-VCS scanning work. Windows 10, Py 3.12: 681 passed, 14 skipped (symlink privilege and POSIX-only cases). Ubuntu 26.04, Py 3.14, native backends online: 692 passed, 3 skipped. 44 new tests cover the code model (including hostile input timing), the index and `pdt query`, every new analyzer, the integration map and the catalog contract. Two remote-VCS tests that assumed symlink privilege now skip, or check the documented fallback, where Windows refuses symlinks. |
| Regex complexity | Every new module-level pattern runs under `tests/test_regex_complexity.py`. Patterns that are only ever anchored with `.match()` at a fixed offset are allowlisted with the reason. |
| Self-scan precision | Scanning this repository, the new analyzers report no CRITICAL, HIGH or MEDIUM finding. The data-flow analyzer reports nothing, as PDT has no untrusted-input sources. Building this check found, and fixed, false N+1 reports on batched SQLite writes and comprehensions over query results, and false lock-release reports on deliberate acquire/release hand-offs. |
| Analysis cost | On 4,683 real third-party files (65 MB, mostly Python): the new analyzers took 21.7 s next to 113.4 s for the existing ones (about +19% analysis time). The costliest are the code index (2.1 ms per file, including model building), performance hotspots (2.0 ms) and data flow (1.8 ms). |
| End to end | Scans of polyglot sample projects produce every new summary with no analyzer or index-pass failures. `pdt compare` across four sample services found all six expected links: package dependency, HTTP calls with exact and prefixed paths, a Kafka topic and a gRPC service. |

Defects found while building this work were fixed before it was committed to the branch, and none affected 0.2.0. They included possessive quantifiers that could never match (`\w{1,120}+Client`), section headers in CRLF manifests, a lexer that took `const x = (expr)` for an arrow function, and a keyword collision when recording facts.

### Limits

- The lexer does not expand macros, resolve overloads or instantiate templates and generics. Lexical call resolution is by name within a language group, and ambiguous names are reported as ambiguous rather than guessed.
- Taint analysis does not reason about branches. Outside Python it follows the file's own functions and joins calls into other files only by a function name that a single file defines, so calls through object receivers with common method names are not followed (§10). Python calls on objects resolve when the code states the receiver's class (§11). Values whose class is only known at run time, or from code PDT does not see, are not inferred, so a sink reached through such a call can be missed.
- Static analysis cannot see run-time validation, authorization, framework escaping or deployment. Data-flow, concurrency, resource, HDL lint, rules-of-hooks and integration-map results need review before they are treated as defects.
- Very large repositories reach the index ceilings (5–20 million rows per table). This is reported as an `UNKNOWN` finding, and the index-based results are then incomplete.

The release gates in §5 are unchanged. The large-corpus benchmarks now also measure the code index, using the per-phase timings (`code_index`) in each report.

## 9. Windows plugin sandbox

**Date:** 2026-11-06 · **Scope:** gate 3 in §5 on Windows. At 0.2.0 a sandboxed plugin on Windows could still read any file the user could read, use the network and terminate same-user processes, because the job object and untrusted integrity level do not restrict those.

### What changed

- In `sandbox` mode, PDT starts each plugin host suspended inside an AppContainer that holds no capabilities, assigns it to the job object and only then resumes it. Only the three protocol pipes are inherited.
- An AppContainer reads only what is granted to it. PDT grants read access on three folders it creates and on nothing else: a copy of the standard-library runtime (made once per Python build, about 40 MB), a per-scan copy of PDT's package and the plugin with the distributions it requires, and each host's staging folder. The user's installation, site-packages and projects keep their permissions.
- Inside the container the host still lowers itself to untrusted integrity, which also denies writes to the container's own folder, and applies the mitigation policies. PDT deletes any file in that folder before its first host starts, so no host can leave data for a later one.
- Sandbox mode on Windows now requires all four restrictions, as on Linux and macOS. The network check combines the token (an AppContainer with no capabilities), a loopback connection to a listener outside the container that must fail, and a connection to an unrouted documentation address that must fail.

### Verification

| Check | Result |
|---|---|
| Restriction probes | Windows 10, Py 3.12: writes, reads, network and process creation verified for every host; mechanisms `appcontainer`, `job-object`, `untrusted-integrity` and three mitigation policies. |
| Hostile plugin (`test_windows_appcontainer_denies_a_hostile_plugin`) | Denied: reading the original project file, PDT's inventory database, the user's site-packages and home folder; writing outside, into the staged PDT package, the runtime copy, the container's folder, `C:\Users\Public` and LocalLow; TCP to loopback and to an unrouted address; name resolution; starting a process; opening PDT with terminate or memory-write rights; and a 1 GiB allocation under a 512 MB limit. A UDP datagram to a loopback socket outside the container was never delivered. |
| Fixture plugins | All 26 plugin-isolation tests pass under the AppContainer, including import-time escapes, crashes, hangs, floods, interrupts and the process executor. |
| Test suites | Windows 10, Py 3.12 and Ubuntu 26.04, Py 3.14: the full suites pass (seven new tests cover staging, the launcher and the container's folder). |
| Cost | Starting a host takes about 1.3 s, mostly the 1 s loopback check. Hosts are reused, so this is paid once per plugin and worker. |

### Limits

- Files that Windows grants to every app container, such as those under `C:\Windows` and `C:\Program Files`, stay readable. They hold no project data.
- On Windows a plugin can import only the standard library, its own package and the distributions it declares as dependencies. Python builds that keep native libraries outside `DLLs` (for example conda) can fail to import the affected standard-library modules in the sandbox.
- The AppContainer profile `ProjectDiscoveryTool.PluginHost` persists per user, as browsers' profiles do; [PLUGIN_SDK.md](../guides/PLUGIN_SDK.md) explains how to remove it.

## 10. Inter-procedural taint for the lexically modelled languages

**Date:** 2026-11-06 · **Scope:** the §8 limit that taint analysis outside Python stayed within one function and that only Python flows were joined across modules.

### What changed

- **Summaries.** Each function of a JavaScript/TypeScript, PHP, Java/Kotlin/Scala/Groovy, Go, C#, Rust or C/C++ file is summarized. Its parameters are followed as marked values to the sinks they reach and to what the function returns, and input the function reads and returns itself is recorded. Summaries are iterated, up to three rounds under an event budget, so chains of helpers are followed. Only functions that hold a sink, call another function of the file, or return to a caller in the file are summarized.
- **Calls in the file.** A call carries taint into the sinks inside the callee (`app.js:17 req.query -> outer() -> inner() -> exec`) and out through its return value, with the callee's sanitizers respected.
- **Calls into other files.** Calls passing untrusted input to a function the file does not define are recorded as code facts, with the same fact kinds Python uses. The code index joins a call with the callee's summary when exactly one file of the same language family defines a function of that name. An ambiguous name is not guessed. Calls to source, sink and sanitizer functions and callback arguments are not recorded. Files in dependency trees are summarized for others only when they read untrusted input themselves.
- **Speed.** Patterns that begin with a boundary lookbehind are searched through a variant without it, and each candidate is confirmed with the original pattern. The variant is built only when the alternative then starts with a fixed character, so every search stays linear. The regex-complexity test checks all 85 variants, and the results equal the original patterns' on every family.

### Verification

| Check | Result |
|---|---|
| Unit tests | Helper sinks, returned parameters, returned sources, a two-level chain and sanitized calls in JavaScript, PHP, Go, Java and C give the expected flows and helper chains. |
| End to end | A scan of a JavaScript project reports `app.js:3 req.query -> runQuery() -> pool.query at lib/db.js:2` across files. A call to `save()`, defined in two files, is not joined. |
| Cost | 1,199 JavaScript files of npm and Babel (17 MB): the data-flow analyzer took 5.62 s before and 5.88 s after (+5%); treating the same files as first-party code, 6.15 s (+9%). One more open-redirect flow, through a helper, was found. |
| Test suites | Windows 10, Py 3.12 and Ubuntu 26.04, Py 3.14 pass, including the regex-complexity check over every generated pattern. |

### Limits

- Branches are not distinguished, and a variable stays tainted along every path after a tainted assignment.
- Calls through an object receiver (`dao.find(x)`) are joined only when the method name is unique within the language family, so common method names are not followed across files.
- A function is identified by name. Overloads and same-named methods of different classes in one file share a summary.

## 11. Python receiver types

**Date:** 2026-11-06 · **Scope:** the §8 limit that no language had type inference, so calls on objects (`repo.find(name)`) were not resolved and taint stopped there.

### What changed

- `intelligence.model.python_types` gives a name the class that the code states for it. Sources are a constructor call, a parameter or variable annotation (including `Optional[...]`, `... | None` and quoted forward references), a return annotation, `with C() as x`, `x or C()`, a module-level instance, and `self` attributes assigned in any method. The inference is flow-insensitive and conservative. A name assigned two classes, or anything of unknown class other than `None`, gets no type, and a parameter shadows a module-level name.
- The code model resolves calls on such objects to the class's method (`@Repo.find` in the module, or `.store.Store.run` for an imported class), which the code index turns into call-graph edges.
- The Python taint engine applies method summaries at those calls and exports summaries of public methods. A call on an object of an imported class is recorded for the cross-module join, which now reports flows such as `shop/views.py:5 request.args -> shop.store.Store.run() -> execute`.
- The code model and the taint engine share one type table per file. Imports are found by scanning statements, not every node, which also removes a full tree walk from the taint engine.

### Verification

| Check | Result |
|---|---|
| Unit tests | Typed calls through `self` attributes, `x or C()`, locals, module instances, return annotations and context managers resolve. A class conflict, an unannotated parameter, reassignment from an unknown call and a shadowing parameter stay unresolved. Taint follows typed method calls in the module and across modules. |
| Equivalence | The statement-only import scan finds the same imports as a full walk in 955 real modules. |
| Effect and cost | 671 scikit-learn modules: 79.8% of call sites resolved instead of 70.7% (8,742 more edges). Model building plus Python taint took 4.29 s instead of 4.82 s; `rich`: 71.9% instead of 59.8%. |

### Limits

- Values whose class is only known at run time (factories without return annotations, dependency injection, `getattr`) are not typed.
- Imported names count as classes only when capitalized, and an imported class's methods are resolved by name in its module, without its base classes.

## 12. Re-audit of 2026-11-12

**Date:** 2026-11-12 · **Code:** `65dc3e2`, the head after §11 · **Findings:** [AUDIT_2026-11-12.md](AUDIT_2026-11-12.md)

The owner suspected that parts of PDT had been started and left unfinished, or were broken in ways the green test suites (Windows 891 passed, Linux 900 passed) did not show. Eleven auditors each took one subsystem, read its code, tests and documentation end to end, and proved candidate defects with scripts against a fixture or the real code. Seven areas finished and reported 124 findings: 4 P0, 4 P1, 62 P2 and 54 P3. The security analyzers, both domain-analyzer groups and the black-box end-to-end run did not finish before the session's usage limit and are not covered by this round.

At the owner's request the findings were not independently verified by further agents; the owner verifies them. [AUDIT_2026-11-12.md](AUDIT_2026-11-12.md) lists every finding as reported, with its status. Each one fixed so far has a register entry in §3 and a regression test.

### Fixed

- **P0:** PDT-235 (package scan roots hung), PDT-236 (a dead worker aborted process-mode scans), PDT-237 (WSL symlinks crashed the fallback walker; unreadable links were reported as internal) and PDT-238 (the Tree-sitter analyzer failed on every file once grammars were provisioned).
- **P1:** PDT-239 (terminal escape sequences from scanned content and plugin errors), PDT-240 (HTML and Markdown injection in comparison reports) and PDT-241 (npm v1 source specifiers leaked credentials into reports and online queries).
- **P2:** PDT-242 (with `--plugin-isolation off`, process workers could load a different plugin set).

### Method notes

- The CI job with optional integrations installed `tree-sitter-language-pack` but provisioned no grammar, so the Tree-sitter tests only ever exercised fakes. That job now provisions real grammars before the suite runs, as an operator would.
- Process-mode tests now kill a real worker process (`os._exit`) to exercise pool recovery end to end.

The open findings are worked through in severity order. The release gates in §5 are unchanged.
