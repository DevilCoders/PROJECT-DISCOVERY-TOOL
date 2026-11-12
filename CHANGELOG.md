# Changelog

All notable changes to PDT. IDs such as PDT-001 refer to the defect register in
[docs/project/AUDIT.md](docs/project/AUDIT.md).

## Unreleased

Semantic code intelligence and the thirteen domains that 0.2.0 only catalogued. Details,
methods and limits are in [docs/architecture/CODE_INTELLIGENCE.md](docs/architecture/CODE_INTELLIGENCE.md).

### Added: code intelligence
- A shared per-file code model: Python from the syntax tree (qualified symbols, calls resolved
  through imports, `self`/`cls`, module scope and the receiver's class where the code states it:
  constructors, annotations, return annotations and `self` attributes) and about 25 brace
  languages from a linear-time structural lexer. Every analyzer of a file reuses one model.
- Code facts stored with each file's findings in the scan's private SQLite inventory (bounded
  per file and per table, consistent with `--resume`), and a cross-file code index: symbol
  index, call graph with recursion cycles, unreferenced private functions, test-to-code links
  and a polyglot module graph (JavaScript/TypeScript, C/C++, JVM, Go, Rust, PHP, Dart).
- `pdt query OUTPUT --symbol|--callers|--callees|--references NAME [--json]`.

- A Tree-sitter-backed code model: where a grammar is provisioned, the syntax tree supplies the
  symbols and calls of C, C++, CUDA, Arduino, Java, C#, Kotlin, Scala, Swift, JavaScript,
  TypeScript, Go, Rust, PHP and Solidity files (exact nesting, method containers, constructors,
  interface members, expression-bodied members), with the lexer as fallback for unprovisioned
  grammars, broken or pathologically deep files, and `PDT_CODE_MODEL=lexical`.
  `metrics.code_index.symbols.models` reports which backend modelled each language.

### Added: analyzers
- `performance-hotspots`, `concurrency`, `resource-management` and `type-systems`.
- `dataflow`: taint from web requests, sockets and stdin to SQL, command, code,
  deserialization, template, path, SSRF, XSS, redirect, format-string and buffer sinks. Python
  is analysed inter-procedurally (helper summaries iterated to a fixed point) and across
  modules; JavaScript/TypeScript, PHP, Java/Kotlin/Scala/Groovy, Go, C#, Rust and C/C++ through
  the file's own functions (parameter and return summaries) and into other files by a function
  name that only one file defines.
- `embedded` (PlatformIO, ESP-IDF, Zephyr, STM32CubeMX, Rust targets, FreeRTOS, linker memory
  maps, device trees, interrupt-handler safety), `firmware` (ELF/PE metadata and hardening,
  HEX, S-record, UF2, DTB/FIT, uImage, Android boot, ESP32 images, filesystems, Cortex-M vector
  tables, component versions; Yocto, Buildroot, OpenWrt, ESP-IDF partitions), `hdl`
  (Verilog/SystemVerilog/VHDL, RTL lint, FPGA constraints and projects, design hierarchy),
  `shaders` (GLSL/HLSL/WGSL/Metal/Godot/ShaderLab, SPIR-V, DXBC/DXIL, metallib) and `frontend`
  (React/Vue/Svelte/Angular components and children, rules of hooks, list keys, routes
  including file-system routing, libraries, bundler configuration, component graph).
- `integration-points` (outbound HTTP calls, message topics, gRPC services and clients,
  package identity) and an `integration_map` in `pdt compare` linking projects by package
  dependencies, HTTP endpoints, topics and gRPC services.

### Added: online mode
Two acquisition paths and online advisory sources, all opt-in; local scans stay offline. Details
are in [docs/guides/ONLINE_MODE.md](docs/guides/ONLINE_MODE.md).
- **Download and analyze.** `pdt scan URL` and `pdt scan --url FILE` (one URL per line, with
  per-line `ref=` and `vcs=` options) materialize remote repositories read-only into a private
  temporary directory, scan them and delete the copy on every exit path. Git hosts (GitHub,
  GitLab, Bitbucket, Azure Repos, CodeCommit, SourceHut and self-hosted) and native backends
  (Mercurial, Subversion, Bazaar/Breezy, Darcs, Git-backed Jujutsu, Pijul, CVS, Perforce, Fossil)
  run through their installed clients. Git trees are read from objects without a working-tree
  checkout, so filters and hooks never run. `--vcs`, `--ref`, `--remote-timeout`,
  `--remote-workdir` and `--remote-max-gb` control acquisition, and a free-disk floor applies.
  URLs that embed a password or credential query parameters are rejected (SSH and CVS pserver
  user names are allowed), plain-text transports need `--allow-insecure-transport`, and option
  injection through URLs is refused. A timeout or Ctrl-C stops the client and every process it
  started. Client output is bounded and redacted. Windows device names are refused while
  materializing. Batches write `batch-summary.json` and `.md` and exit with the worst outcome.
  The native-VCS adapters have not yet been verified against live servers.
- **Analyze without downloading.** `--no-download` reads GitHub (including Enterprise), GitLab
  (including self-managed), Bitbucket Cloud and Gitea/Forgejo repositories through their REST
  APIs and analyzes the files in memory; nothing is written to disk. `--api-provider`,
  `--api-url` and the `--api-max-files`, `--api-max-mb`, `--api-max-file-mb`, `--api-max-requests`
  and `--api-workers` budgets apply. Unfetched files stay inventoried as `UNKNOWN` coverage gaps.
  Tokens are bound to their host (`PDT_API_TOKEN_<HOST>`, or `--use-credential-helper`). Third-party
  plugins do not run in this mode, because their sandbox needs a file on disk.
- **Online vulnerability intelligence.** `--vuln-online` looks up every lockfile-resolved package
  in OSV.dev, next to or instead of `--vuln-db`, with optional NVD and GitHub Advisory enrichment
  (`--vuln-enrich nvd,ghsa`). Only ecosystem, package name and version are sent. Responses are
  cached privately (`--vuln-cache`, `--vuln-cache-ttl`). Requests are rate-limited and honor proxy
  settings and `--ca-bundle`. A failed or partial lookup becomes an `UNKNOWN` finding and fails
  `--strict`, never a clean result.
- `pdt capabilities` lists the installed VCS clients.

### Added: plugin tooling
- `pdt plugin-check PLUGIN [SAMPLES...]` and `project_discovery.plugins.conformance.assert_conformant`
  load a plugin the way a scan does (sandboxed host, same protocol, same validation), run it twice
  on sample files and report errors (what a scan would reject or turn into `UNKNOWN` coverage) and
  warnings (missing metadata, findings that set `analyzer`, redacted evidence, non-deterministic
  results). docs/guides/PLUGIN_SDK.md states the compatibility policy for plugin API version 1.

### Changed: Windows plugin sandbox
- On Windows, `--plugin-isolation sandbox` starts each plugin host suspended inside an AppContainer
  without capabilities, then assigns it to the job object. Hosts can no longer read the user's files,
  use the network (loopback included) or open other processes, so sandbox mode now verifies all four
  restrictions on Windows too. Hosts run from a copy of the standard-library runtime (cached once per
  Python build under `%LOCALAPPDATA%\ProjectDiscoveryTool\plugin-runtime`) and from staged copies of
  PDT and the plugin's declared dependencies; only those PDT-created folders are granted to the
  container. See docs/guides/PLUGIN_SDK.md and §9 of docs/project/AUDIT.md.

### Changed
- The package is organized into subpackages by responsibility (`inventory`, `engine`,
  `analyzers/<domain>`, `intelligence`, `vulnerabilities`, `plugins`, `online`, `reporting`,
  `projects`, `catalog`, `core`), and tests, docs and native sources are nested the same way.
  `project_discovery.models`, `project_discovery.analyzers.base` and the `pdt` entry point keep
  their paths. Internal module paths changed: for example `project_discovery.code_facts` is now
  `project_discovery.intelligence.facts`.
- The thirteen catalog domains that were `planned` are now `partial`, each claimed by a
  shipped analyzer; a test keeps `planned` domains and shipped analyzers disjoint. Lexically
  modelled languages report `analysis_status: lexical_structure` and a new `structural_model`.
- The language catalog recognizes more shader stages (compute, mesh, task, ray tracing), HLSL
  includes, ShaderLab, SPIR-V, Arduino sketches, linker scripts, device trees and blobs, Intel
  HEX, S-record, UF2, ELF, STM32CubeMX projects, Kconfig files, FPGA constraints and projects,
  and BitBake recipes.
- Report schema 1.7: 1.6 added `metrics.code_index`, and 1.7 adds a top-level `scan` block (mode,
  network use, credential-free remote source and vulnerability sources), shown in Markdown and HTML
  as scan-source and vulnerability-intelligence sections. Comparison schema 1.1 (`integration_map`).

### Performance
- On 4,683 real third-party files (65 MB), the new analyzers add 21.7 s to 113.4 s of existing
  analysis time (about +19%), at most about 2.1 ms per file each. Files without taint sources
  or sinks cost the data-flow analyzer a single syntax-tree walk.

### Fixed: the 2026-11-12 re-audit
Findings and their status are in [docs/project/AUDIT_2026-11-12.md](docs/project/AUDIT_2026-11-12.md).
- A scan whose root is itself a Python package (a root `__init__.py`) never finished (PDT-235).
- A worker process that died aborted the whole process-mode scan with `CancelledError`; now
  only the culprit file is reported, after failing twice on its own (PDT-236).
- WSL (LX) symlinks crashed the fallback walker, and the Rust walker reported unreadable links
  as `internal`; both now record `target_state: "unreadable"` and an entry error (PDT-237).
- The Tree-sitter analyzer failed on every file once grammars were provisioned (`str` passed to
  the parser), and C# could never be provisioned (`c_sharp` instead of `csharp`). Error columns
  now count characters, and CI tests against real grammars (PDT-238).
- Terminal control characters in scanned content, plugin errors and diagnostics are neutralized
  on every output surface, so a scanned file cannot rewrite the operator's terminal (PDT-239).
- `project-comparison.md` escapes the names, roots and paths it takes from scanned projects
  (PDT-240).
- npm v1 git, file and URL dependencies are no longer treated as versions: their specifiers
  could carry credentials into reports, OSV.dev queries and the cache. They are reported as an
  `UNKNOWN` coverage gap, and `npm:` aliases resolve to the real package (PDT-241).
- With `--plugin-isolation off`, process workers load exactly the coordinator's plugins
  (PDT-242).
- Code model: JavaScript/TypeScript regex literals no longer blank the code after them
  (`/\//g` read as a comment dropped the rest of a minified bundle); keyword-prefixed names
  (`function_exists`, `funcs`) are not definitions; calls inside `if (a() && b(x)) {` are not
  typed definitions; Rust `impl Trait for Type {` is not a loop (PDT-243 to PDT-246).
- Python SQL built only from placeholder lists or constant table names is no longer reported as
  dynamically constructed; parameters and rebound names still are (PDT-247).
- `--strict` is the completeness gate it is documented to be: it also fails on entries whose
  metadata could not be read during the walk (now diagnostics in every report) and on `UNKNOWN`
  coverage findings above INFO, and its FAILED line names the counts (PDT-248, PDT-249).
- The HTML vulnerability and VCS views count every finding, not only the embedded slice
  (PDT-250).
- On Windows, `catalog-*`, `compare`, `query` and `vuln-db status` no longer exit 2 when stdout
  is redirected and a path is outside the ANSI code page (PDT-251).
- The project catalog keys remote scans by URL and ref instead of resolving the URL as a
  local path; `pdt catalog-remove URL` removes every ref (PDT-252).
- Reports of `--inventory-only` scans say that no contents were analyzed, and a local advisory
  database is recorded as skipped rather than as a clean result (PDT-253).
- Lockfile entries are classified by source. The project's own packages (root, workspace and
  path members) are listed as local and never sent to OSV.dev or matched; git and URL
  dependencies are an `UNKNOWN` coverage gap. Aliased dependencies (yarn `npm:` aliases,
  `mix.lock` keys, `ssh://` Swift URLs) match under the real package (PDT-254, PDT-255).
- Advisory matching: GIT commit ranges no longer turn decidable versions into `UNKNOWN`
  (PDT-256); Composer orders patch releases and stabilities as Composer does, NuGet labels
  ordinally (PDT-257); online findings cover every lockfile and take the fixed version from
  the matching release line (PDT-258).
- `vuln-db import` refuses unsupported sources and keeps the snapshot's provenance when it
  imports nothing (PDT-259). Reports flag snapshots older than 30 days, show the snapshot's
  source and ecosystems, and report an uncovered lockfile ecosystem as `UNKNOWN` (PDT-260).
- A corrupt `--vuln-cache` file is detected before the scan (PDT-261), and `--vuln-db` opens
  databases on Windows UNC shares (PDT-262).
- Inventory: both walkers make the same `--exclude-dir` decision with full Unicode case folding
  (PDT-263); the Rust walker reports pre-1970 modification times (PDT-264); the Windows fallback
  reports link targets without the `\\?\` prefix, so internal junctions are internal (PDT-265).
- GPU dispatch and fallback counts include worker processes (PDT-266).
- `--inventory-only` opens no file; file types come from names (PDT-267).
- The fingerprint cache stores file IDs beyond 64 bits and never fails a file (PDT-268).
- Inventory records are read in keyset pages, so the WAL no longer grows through the analysis
  phase (PDT-269).
- A malformed provider answer fails only its own `--url` target, and an unexpected error exits 2
  with a one-line message instead of 1, the `--fail-on` code; `pdt compare` reads null report
  sections as empty (PDT-270).
- `--remote-max-gb` and the file budget apply to every backend, not only Git (PDT-271).
- Remote trees with directories that differ only in case are no longer merged on Windows and
  macOS; the colliding paths are reported as not materialized (PDT-272).
- No-download: GitLab files without a listed size are reported as of unknown size instead of
  0 bytes; `--skip`/`--max-file-mb` apply to them; `--api-max-mb` holds with parallel reads
  (PDT-273). GitHub's secondary rate limit is retried or stops requests (PDT-274).
- A `--url` file with one repository gets the batch layout, summary and exit codes (PDT-275).
- VCS markers for `hg init`, `darcs init`, Jujutsu, Bazaar, Pijul, CVS and POSIX Fossil
  checkouts, Jujutsu Git remotes and bare repositories at any depth (PDT-276).
- `pdt plugin-check` hands plugins the file records a scan builds (PDT-277).
- Plugin findings over the 16 MiB response frame are cut with a coverage note instead of
  all being lost (PDT-278).
- Linux and macOS sandbox: the current directory and `PYTHONPATH` directories are no longer
  readable to plugins (PDT-279).
- A second scan into the same output in one process no longer refuses every sandboxed
  plugin (PDT-280).
- `.m` files with Objective-C content get the Objective-C code model (PDT-281).
- Integration maps: dependency and vendor trees are not the project's own packages, capped
  lists are counted (PDT-282); Django routes match calls (PDT-283); declaring a queue is not
  publishing, and shared use is a `shared_channel` edge (PDT-284).
- `pdt compare` reports per-project coverage and warnings instead of presenting missing
  evidence as no links (PDT-285), compares every resolved package from
  `metrics.code_index.dependencies` (PDT-286), and keeps inputs with one root apart (PDT-287).
- `tools/benchmark.py` records a failed scan as failed and exits with its code (PDT-288).
- Code index: Python modules that several files define resolve to the importer's own file,
  so no taint flow or call edge crosses unrelated services (PDT-289); `pdt query --callers`
  finds same-file and module-qualified callers (PDT-290); Go standard-library imports never
  match local directories (PDT-291); delegation through another receiver is not recursion
  (PDT-292); bodies after multi-line headers (PDT-293) and Go type groups, closures, Swift
  `init`, C++ out-of-class constructors and destructors and C# expression members (PDT-294)
  are modelled; a reference cut is reported and called functions are never dead code
  (PDT-295); loop containment is logarithmic (PDT-296); the Python dependency graph names
  modules by import name and resolves namespace packages (PDT-297).
- Credentials without a scheme are redacted from client errors, and report URLs never keep
  userinfo (PDT-298); a redirected POST fails at once instead of hanging (PDT-299).
- A damaged `.pdt-cache` database is moved aside and rebuilt instead of failing every scan
  (PDT-300).
- Malformed advisory records are skipped at import and never crash matching (PDT-301); an
  advisory confirmed by any of its affected entries is confirmed (PDT-302).
- Skipped lockfiles count as unchecked, online and offline, and incomplete lookups name their
  cause (PDT-303); advisory cache entries are scoped to their endpoint (PDT-304); enrichment
  adds CVE/GHSA aliases (PDT-305).
- License analysis reads workspace, Poetry and `LICENSE-*` declarations (PDT-306) and SPDX
  headers in any encoding and size, from comments only (PDT-307).
- Dependency manifests tolerate empty sections and read more declaration forms (PDT-308);
  Cabal fields and go.mod comments are no longer dependencies (PDT-309).
- `phase_seconds` names each pass, with the shutdown as its own phase (PDT-310); `--quiet`
  keeps the reason a `--fail-on`/`--strict` gate failed (PDT-311).
- `pdt query` shows resolved names with a resolution label, accepts module-qualified
  `--callees`, and warns and exits 3 on a scan without a code index (PDT-312).
- No HTTP-in-loop finding for dict values bound by a loop (PDT-313); `ScanResult.to_dict()`
  writes the schema 1.7 `scan` block (PDT-314); README report claims corrected (PDT-315).
- `pdt plugin-check` reports samples beyond its limit (PDT-316); in-process plugins are
  attributed to their own name (PDT-317); Debian packages classify as `archive/deb` (PDT-318).
- `--resume` lists run-scoped diagnostics once (PDT-319); advisory matches have their own
  Markdown heading (PDT-320); Windows entries report no synthesized mode bits in either walker
  (PDT-321); `--resume` documents that failed files are not retried (PDT-322).
- Code index: a module and its `.pyi` stub are one module (PDT-323); a class with explicit
  constructors resolves uniquely (PDT-324); nested functions no longer inflate complexity
  (PDT-325); Rust `use crate::` paths resolve and PHP function/trait imports are read
  correctly (PDT-326); Go locks need a deferred release (PDT-327).
- No-download: failures group by cause with sample paths (PDT-330), and a limit hit while
  listing keeps a truncated inventory (PDT-331); API scans are described as such (PDT-332).
- Git metadata: valueless config keys, remote HEADs, nested `.gitmodules`/`.gitattributes`,
  Codeberg (PDT-333).
- Batch summaries: absolute or null report directories, no clone progress, separate cleanup
  errors (PDT-334); equivalent repository spellings are scanned once (PDT-335); Git over
  `http://` works with `--allow-insecure-transport` (PDT-336); `.cmd`/`.bat` wrappers are
  not reported as available (PDT-337); a lookup that sent no request is not online (PDT-338).
- `pdt compare`: version conflicts per ecosystem with one rule (PDT-339); empty files excluded
  and duplicates capped with a total (PDT-340); `--output` inside a compared project refused,
  API evidence and per-pair module names in Markdown (PDT-343); `Other` is not a shared
  language, and the catalog lists `C` once (PDT-345).
- `tools/benchmark.py generate` writes the requested size (PDT-341); README, BENCHMARKS and
  domain scopes describe what exists (PDT-342, PDT-344).

### Fixed: the 2026-11-12 re-audit, second round
Findings and their status are in the second-round section of
[docs/project/AUDIT_2026-11-12.md](docs/project/AUDIT_2026-11-12.md#second-round).
- Report excerpts kept credential values the secret scanner had just reported (Go `:=`,
  PHP/Ruby `=>`, typed defaults, signing and encryption keys); detector and redactor now share
  one key list and operator definition (PDT-346).
- JDBC `;user=...;password=...` properties no longer reach URI or host evidence (PDT-347), and
  webhook secrets no longer reach integration paths or `pdt compare` (PDT-348).
- Parse-error findings name the error and its position only; configparser and YAML messages
  quoted the offending line or value (PDT-349). INI files are read without interpolation.
- Plugin findings are validated and redacted with `--plugin-isolation off` too (PDT-350), and
  `plugin-check` neutralizes and redacts plugin-supplied text (PDT-351).
- Lines that name a credential field hide every quoted literal (PDT-352).
- One crafted line or file no longer stalls a worker: the secure-code rules scan each statement
  once (PDT-353); nginx directives, SQL `DROP COLUMN`, Liquibase ids, Terraform `cidr_blocks` and
  Prisma blocks are linear scans (PDT-354); line numbers come from a shared index instead of
  counting from the file start per match (PDT-355); PO and `.strings` patterns are no longer
  exponential on backslashes (PDT-356).
- `tests/test_regex_complexity.py` sees rule objects and patterns compiled inside functions and
  builds backtracking witnesses from each pattern; the 86 more super-linear patterns it found are
  fixed (PDT-357).
- Python taint follows loop-carried values, `except` handlers as alternatives, comprehension
  elements (PDT-358), positional-only route parameters (PDT-359), helper chains of any depth and
  every parameter label (PDT-360); every lexical budget cut is reported (PDT-361), and
  parameters after `=>`/`->` function types are kept (PDT-362).
- UTF-16 and UTF-32 files are decoded and scanned (PDT-363); the self-scan is clean outside
  `tests/` again (PDT-364); credential names need a credential noun last, and type names and
  elided examples are placeholders (PDT-365); archive members use the file scanners' rules
  (PDT-366); Python gets the JWT, permission, XXE, randomness and redirect rules (PDT-367);
  `setWritable`, `chmodSync`, `chmod -R` and `exec "$@"` are judged by meaning (PDT-368).

## 0.2.0 — 2026-11-05

The production-readiness release. At 0.1.0 (`1895455`) CI failed on every job and `pdt scan`
never ran a per-file analyzer. This release fixes every defect in the audit register and adds
the scale and operability features needed for very large repositories.

### Fixed: core functionality
- `pdt scan` now runs every per-file analyzer. The analysis guard had compared an
  `os.stat_result` positionally against a five-field identity, so every file was refused on
  every platform (PDT-001).
- Verified, identity-pinned reads work on Windows (`st_ctime` and `DirEntry` semantics),
  and magic-byte file typing works in the fallback walker (PDT-002, PDT-003).
- API-style classification no longer crashes on every file (PDT-004).
- `compare`, `catalog-add` and `catalog-compare` accept real scan reports (schema 1.x), and
  reports now carry each file's SHA-256 (PDT-005, PDT-006).
- One Python AST security engine with import-alias resolution, shared by both presentations
  (PDT-007, PDT-211).

### Fixed: security of PDT itself
- OpenCL is loaded only from System32 on Windows and from the absolute framework path on macOS;
  a library planted in a scanned repository can no longer be loaded (PDT-101).
- YAML alias ("billion laughs") and XML entity bombs are rejected before any traversal; XML is
  parsed from verified, bounded reads (PDT-102, PDT-105).
- TAR inspection continues past large members under decompression and wall-time budgets that
  are enforced inside reads; case- and Unicode-colliding member names are reported
  (PDT-103, PDT-224).
- Windows junctions and mount points are recorded, never followed (PDT-104).
- File names that are not valid Unicode round-trip end to end; the scan no longer crashes on
  them (PDT-109).
- HTML reports use single-pass templating and a nonce-based Content-Security-Policy that also
  blocks all network access; Markdown reports neutralize HTML, links and code-span breakouts
  (PDT-106, PDT-107).
- Inventory and cache databases are created private (0600) together with their WAL files
  (PDT-108).
- Detection and redaction share one credential registry: Docker PATs, Stripe restricted keys
  and Azure account keys had been detected but copied verbatim into reports (PDT-225).
- Tree-sitter grammars are never downloaded: tree-sitter-language-pack 1.23+ fetches grammars
  inside `get_parser()`, so parsing is gated on grammars already provisioned locally (PDT-226).
- Regex denial of service: the excerpt redactor was cubic on long identifier runs (9 s for
  2,000 characters) and nine detector patterns were quadratic. All are now linear, and a
  regression test times every package regex against adversarial input (PDT-227).
- CI actions are pinned to commit SHAs instead of mutable tags (PDT-230).

### Fixed: correctness
- OSV matching: severity from CVSS v2/v3 vectors and GHSA labels, range events sorted per the
  OSV specification, ecosystem-correct version ordering (SemVer, PEP 440, RubyGems, Composer,
  NuGet), alias-merged findings, indexed lookups and read-only access during scans
  (PDT-201, PDT-202, PDT-204, PDT-206).
- Lockfiles: yarn (v1 and Berry), pnpm (v5, v6 and v9), NuGet and `go.sum` parse correctly;
  uv, pdm and Dart `pubspec.lock` are new. One parser set serves both lockfile analyzers
  (PDT-203, PDT-205).
- Network indicators validate TLDs against the bundled IANA list and require string-literal
  context in source code; bare `::` is no longer reported as IPv6 (PDT-207, PDT-208).
- ML heuristics run only in files that import an ML framework, and device tokens match whole
  name components (PDT-209).
- The Python import graph resolves absolute imports through package roots (`src/` layouts)
  (PDT-212).
- `python-ast` emits one structure finding and one import finding per module instead of one
  finding per symbol (PDT-213).
- Secret scanning: incremental UTF-8 decoding, more than 30 provider formats, lower severity in
  test/fixture/example/docs paths, placeholder recognition and one finding per secret
  (PDT-215).
- The generic credential rule no longer spans line breaks or treats code expressions as values,
  and now covers JSON/PHP keys, Go `:=` and typed defaults (PDT-228).
- Email indicators require a real, non-reserved domain and skip SCP remotes and URL user info;
  prose documentation contributes values but not field names; PII field-name inventories are
  LOW, like credential key-name inventories (PDT-229).
- `--resume` can no longer lose findings: a file is marked analyzed only after its findings
  are committed, an interrupted commit keeps its rows, and an interrupted scan saves its
  completed files (PDT-232).
- Console status lines no longer interpret Rich markup: a path containing `[/x]` crashed the
  scan, and plugin diagnostics could restyle `pdt capabilities` output (PDT-233).
- The API endpoint analyzer no longer reports every CRLF source file as truncated by its scan
  budget (PDT-234).

### Added
- Plugin isolation (`--plugin-isolation sandbox|process|off`, default `sandbox`). PDT no longer
  imports third-party analyzers. Each plugin runs in host processes that apply an OS sandbox,
  verify it by attempting each forbidden action, and only then import the plugin. Linux uses
  Landlock and seccomp-bpf; macOS uses Seatbelt; Windows uses a job object, untrusted integrity
  and mitigation policies. Hosts get a scrubbed environment and private copies of files, and
  talk JSON, never pickle. PDT validates, bounds, redacts and attributes their findings.
  Crashes, timeouts (`--plugin-timeout`) and floods become `UNKNOWN` coverage findings, and a
  plugin is disabled after three consecutive host failures. Memory is limited with
  `--plugin-memory-mb`. Windows cannot restrict reads or network access; see
  docs/guides/PLUGIN_SDK.md.
- `pdt capabilities` reports what the plugin sandbox verifies on the machine and whether each
  plugin loads; reports record each plugin's verified sandbox in `metrics.plugin_isolation`.
- Multi-process analysis engine (`--executor auto|process|thread`) with batched tasks, worker
  crash isolation, read-once prefetch, a shared AST memo and parallel import-graph parsing.
- `pdt scan --resume` continues an interrupted scan; `--inventory-only` inventories without
  reading file contents.
- `--fail-on SEVERITY` and `--strict` exit codes for CI, plus `--quiet` and `--no-color`; Ctrl-C
  exits with status 130, stops worker processes immediately and leaves a resumable inventory
  (PDT-231).
- Per-phase timings, throughput and peak RSS in every report's `metrics.performance`.
- `pdt capabilities [--json]` and `python -m project_discovery`.
- `tools/benchmark.py` generates synthetic corpora and records performance for any corpus.
- Offline import of OSV `all.zip` bundles, with import provenance and snapshot age.
- Severity-first finding order, file locations in the terminal security summary, `UNKNOWN`
  findings when an analyzer fails, and bounded HTML embedding for very large reports.
- CPython 3.14 support (PyO3 0.30.1), committed `Cargo.lock`, `.gitattributes` and a CI gate
  of `ruff --select E9,F,B,PLE` plus an optional-integrations job.

### Changed
- Report schema 1.5. All changes are additive: `metrics.performance`, executor and resume fields
  in `metrics.execution`, populated `files[].sha256`, the `analysis_coverage` category, HTML
  `totals`, `metrics.plugin_isolation`, and `origin`/`isolation` in `metrics.analyzer_registry`.
  Readers of 1.x reports keep working.
- Plugins run sandboxed by default. A plugin that needs other files, the network or temporary
  files must be run with `--plugin-isolation process` or `off`. Isolated plugins cannot set
  `Finding.analyzer`, and their text fields are redacted.
- Built-in analyzers are imported when they are loaded, not when `project_discovery.analyzers`
  is imported, so importing `analyzers.base` is cheap.
- `packaging` is now a declared dependency.
