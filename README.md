# PROJECT DISCOVERY TOOL

**PDT — local-first, read-only, polyglot project intelligence for large and heterogeneous codebases.**

PDT inventories a project first, analyzes it with independent evidence-producing analyzers, then produces machine-readable and human-oriented reports. It is designed for repositories containing many languages, frameworks, build systems, operating systems, APIs, data stores, deployment systems, archives, binaries, hardware/robotics components, and generated/development dependency trees.

PDT does not assume that a project is Python-based, that one language is its core, or that a repository's README accurately describes its implementation.

> **Status: 0.2.0 — release candidate.** The production-readiness audit ([docs/project/AUDIT.md](docs/project/AUDIT.md)) found that 0.1.0 never ran its per-file analyzers and failed CI everywhere; every defect it recorded is fixed and covered by regression tests, and CI passes on Linux, Windows and macOS for CPython 3.11–3.14. Third-party plugins run in a verified operating-system sandbox on Linux, macOS and Windows (see the [Plugin SDK](docs/guides/PLUGIN_SDK.md)). Remaining release gates are listed in [AUDIT.md §5](docs/project/AUDIT.md#5-release-gates-that-remain-open): large-corpus (2 GB–100 GB+) benchmarks and an independent security review. Unreleased work on this branch adds a shared code model, a cross-file code index and analyzers for every domain that 0.2.0 only catalogued ([AUDIT.md §8](docs/project/AUDIT.md#8-code-intelligence-and-the-formerly-planned-domains), [Code Intelligence](docs/architecture/CODE_INTELLIGENCE.md)). Catalog coverage, grammar mappings, pattern analyzers and full semantic support are still different capability levels, and a catalog entry is never presented as a completed analyzer. See [CHANGELOG.md](CHANGELOG.md) and the [Operations Guide](docs/guides/OPERATIONS.md).

## Project identity

```text
  ____  ____ _____
 |  _ \/ ___|_   _|
 | |_) \___ \ | |
 |  __/ ___) || |
 |_|   |____/ |_|

  PROJECT DISCOVERY TOOL
  POLYGLOT INTELLIGENCE // LOCAL-FIRST // READ-ONLY
```

## Non-negotiable engineering contracts

### Local-first, offline and read-only

- No target source, credentials, configuration, reports or scan results are uploaded to hosted services.
- Target source is never imported, executed, launched, compiled or connected to a running service as part of static analysis.
- No telemetry, hosted inference, DNS lookup, network probe, automatic grammar download, target dependency installation or archive extraction.
- Cache and report output are placed outside the analyzed tree by default.
- Symlinks are inventoried as links and are never followed during filesystem traversal.
- Built-in analyzer reads use shared descriptor-verified helpers: reject symlinks/non-regular paths, request `O_NOFOLLOW` where supported, compare the opened descriptor with `fstat`, and enforce available scan-time identity from inventory. Bounded text/Python/binary readers, SHA-256 fingerprinting, signature sampling and ZIP/TAR input streams use that boundary. Third-party plugins still receive the legacy `Path` interface; PDT cannot enforce how arbitrary plugin code opens files. The Rust Windows walker also lacks a stable scan-time file ID in the current implementation, so cross-platform identity continuity remains a release gate.
- ZIP/TAR members can be inspected through bounded in-memory streams; archive entries are never extracted to disk. ZIP central-directory count/size is checked before materializing the member index; ZIP/TAR traversal and member sampling have an 8-second cooperative wall-time budget, plus a 32 MiB total and 1 MiB per-member content-sample budget. Unknown or exceeded bounds produce `UNKNOWN`/partial findings. Formats without a supported index reader are reported as detected but not deeply inspected.
- Secret and PII evidence must be redacted. Reports may retain category, file/member path, line, confidence and a keyed local fingerprint; they must not contain complete passwords, tokens, private keys, email addresses or personal-data values.
- Third-party analyzer plugins never run inside PDT by default. Each runs in a sandboxed host process that receives private copies of the files it analyzes and an allowlisted environment. On Linux (Landlock, seccomp) and macOS (Seatbelt), plugins cannot write files, read outside the Python runtime, use the network or start processes; Windows restricts writes and process creation only. See the [Plugin SDK](docs/guides/PLUGIN_SDK.md).
- Static references are not runtime facts. A URL, hostname, port, API route, dependency, package manifest or ROS topic found in source is not proof that it is deployed, reachable, installed or active.

### Polyglot, not Python-only

The recognition catalog covers 40+ source-language families plus schemas, configuration, documentation, build formats, game formats, shaders, hardware description languages, model artifacts and mobile formats. The optional Tree-sitter adapter maps 60+ grammar names.

Every language adapter must publish its actual capability level:

1. file/language recognition;
2. parser mapping;
3. parser installed and available locally;
4. syntax parsing;
5. declaration and import extraction;
6. project-local module/symbol resolution;
7. framework/API/database/security/test/build semantics.

A grammar mapping is not semantic coverage. Production support means tested source fixtures, explicit limitations, parser-version compatibility, evidence locations and graceful behavior when optional dependencies are missing.

### Large-repository target

Target workload: projects from approximately 2GB to 100GB+.

The production engine must provide:

- bounded-memory directory discovery and analysis queues;
- streaming hash and text scanning;
- incremental cache validation and resumable checkpoints;
- configurable concurrency, back-pressure, cancellation and progress phases;
- per-analyzer time, byte, entry-count and memory budgets;
- explicit accounting for files, directories, symlinks, special entries, archives, excluded trees and skipped content;
- report generation that does not require rendering every finding as a DOM element;
- benchmark gates for wall time, throughput, peak RSS, cache performance and output size.

**Oversized-file policy:** content skipping is opt-in. `pdt scan PATH --skip --max-file-mb 128` skips content analysis for files above the threshold and leaves them in inventory with an explicit skip reason. Without `--skip`, PDT applies no global size-based skip. A specialized parser may still refuse an input because its own safe resource budget is exceeded; that capability gap must appear as `UNKNOWN`, not as a clean scan.

## Current implementation baseline

The current branch contains first-pass implementations of:

- File, directory and symlink records; hidden-name indicators; size buckets; permission metadata; directory byte/file totals; common development/cache directory markers; a SQLite fingerprint cache.
- Incremental SQLite inventory persistence at `OUTPUT/.pdt-cache/inventory.sqlite3` with bounded batches, running/complete/partial checkpoints, directory counters/errors, record-count telemetry and integrity status. Store-backed CLI scans now expose file, directory, symlink and special-entry records through lazy SQLite-backed sequences. Directory aggregates are maintained in a separate bounded SQLite delta state, and the Python fallback uses a depth-bounded active iterator stack. Analyzer findings and ordered scan diagnostics now use lazy SQLite-backed sequences; dependency/architecture correlation state and report metrics still have in-memory components; this is not yet the 100GB+ bounded-memory implementation.
- Python AST analysis and a Python internal-import graph with cycle detection, explicit module/edge/unresolved-import/skipped-module RAM ceilings, and `UNKNOWN` partial-graph findings when evidence is omitted.
- A shared code model (Python syntax tree; structural lexer for about 25 brace languages) and a cross-file code index stored in the scan's SQLite inventory: symbol index, call graph with recursion cycles, unreferenced private functions, test links and a polyglot module graph, queried with `pdt query`. See [Code Intelligence](docs/architecture/CODE_INTELLIGENCE.md).
- Performance hotspots, concurrency defects, resource leaks, type-system usage, and data-flow/taint analysis from untrusted input to injection, path, SSRF, XSS and redirect sinks (Python inter-procedurally and across modules; eight more language families through the file's own functions and into other files by unambiguous function name).
- Embedded targets and interrupt-handler safety, firmware and binary metadata (ELF/PE hardening, HEX, UF2, DTB, uImage, Android boot, ESP32 images), Verilog/SystemVerilog/VHDL design hierarchy and FPGA constraints, shader stages and bindings (including SPIR-V and DXIL), frontend component graphs and routes, and cross-project integration maps in `pdt compare`.
- Language/file-format recognition and an optional, offline-first Tree-sitter adapter.
- Markdown plus optional PDF/DOCX document extraction.
- Dependency manifests, selected lockfiles, licenses and configuration metadata.
- Secret-pattern, personal-data field-name, email-shaped-value and secure-code indicators with redacted evidence.
- Static API-type classification, API contracts and initial source route extraction.
- SQL, NoSQL, Prisma ORM and migration indicators.
- Test discovery, build manifests, CI/CD, container and deployment manifests.
- ZIP/TAR member metadata and bounded in-memory content samples without extraction, preflight index limits, and cooperative per-archive wall-time limits; archive-member secret/PII findings carry redacted line evidence, impact and remediation. Other recognized archive formats may be detection-only.
- IPv4/IPv6/CIDR/port, URI/URL, hostname/subdomain and protocol indicators; host OS metadata and target-platform markers.
- Initial AI/ML, ROS 1/2, mobile, game-engine, accessibility, localization, observability, coverage and VCS/hosting analysis.
- Local-only OSV advisory database import and lockfile-based vulnerability matching when an operator supplies `--vuln-db`, and an opt-in online lookup in OSV.dev (`--vuln-online`, optional NVD/GitHub Advisory enrichment) that sends only package coordinates.
- JSON/Markdown reports and an offline dark HTML report with search, filters, pagination and collapsible findings.
- A Rich CLI with an ASCII banner, progress phases, compact summary panels and TTY-aware screen clearing.
- A multi-process analysis engine (`--executor auto|process|thread`, `--jobs 0` auto or `--jobs N`) with batched tasks, worker-crash isolation, read-once file prefetch and parallel import-graph parsing, plus a C-native OpenCL GPU byte-count path for large immutable buffers with runtime detection and C/SIMD/Python fallback.
- Interrupted-scan resume (`--resume`), metadata-only scans (`--inventory-only`), CI exit codes (`--fail-on`, `--strict`; their reason is printed even with `--quiet`) and per-phase timing, throughput and peak-RSS telemetry in every JSON report.
- Sandboxed plugin execution (`--plugin-isolation sandbox|process|off`, `--plugin-timeout`, `--plugin-memory-mb`). Hosts verify their restrictions before importing a plugin, and the JSON report records what each plugin's sandbox enforced.
- A bounded-batch SQLite `InventoryStore` integrated into CLI scanner traversal. File, directory, symlink and special-entry records are stored as discovered and exposed through lazy, deterministic, typed sequences. File records preserve private scan-time identity in storage while excluding it from public serialization; directory counters/errors are incrementally persisted in a normalized state table. Scan checkpoints, SQLite integrity checks, explicit cursor closure and private POSIX database permissions are implemented. Findings and scan diagnostics are persisted in SQLite and consumed as lazy sequences; dependency/architecture correlation state, per-file analyzer working sets and report metrics still have in-memory components.

These are initial implementations with varying depth. In store-backed CLI scans, all four inventory record classes are exposed through lazy SQLite-backed sequences; directory counters/errors are updated incrementally and the Python fallback retains only active directory iterators (O(depth)). The Python dependency graph has explicit RAM ceilings (25k modules, 100k edge candidates, 100k unresolved imports and 25k skipped-module details); duplicate module evidence samples at most 8 paths, with every omission/skipped source represented as incomplete `UNKNOWN` evidence. The architecture top-level component detail index is capped at 10k. These graph structures remain in memory within their caps, not SQLite-backed; the code index, by contrast, is built from SQLite with bounded per-file and per-table ceilings. The JSON report is streamed and the HTML report embeds bounded subsets. Per-file analyzer working sets and report metrics are still held in memory, and the large-corpus benchmarks remain open, so the memory model is not yet certified for 100GB+ target workloads. Dependency/cache/build directories are traversed by default unless explicitly excluded, non-ZIP/TAR archive formats have limited inspection, and many polyglot analyzers use conservative lexical patterns rather than full language semantics. Those are explicit production work items—not completed capabilities.

See [Analyzer Coverage](docs/architecture/ANALYZER_COVERAGE.md), [Architecture](docs/architecture/ARCHITECTURE.md), [Analyzer Resource Budgets](docs/architecture/ANALYZER_RESOURCE_BUDGETS.md), and [Roadmap](docs/project/ROADMAP.md).

## Required discovery surface

| Domain | Required intelligence |
|---|---|
| Filesystem | Files, directories, subdirectories, depth, fan-out, empty directories, hidden entries, symlinks, broken/external/internal links, special files, permission/mode, timestamps, file type/signature, extension, size buckets and directory aggregates |
| Development artifacts | `node_modules`, `.cache`, `.yarn`, `.pnpm-store`, `.npm`, `.gradle`, `.m2`, `.venv`, `vendor`, build outputs, IDE indexes, compiler caches, fuzz corpora, package stores and ecosystem-specific generated trees |
| OS/platform | Host OS versus inferred target OS; architecture, shells, package managers, service managers, containers, sysroots, cross-compilers, platform manifests and CI OS matrices |
| Network | IPv4, IPv6, IPv4-mapped IPv6, CIDR, ports, host:port, URLs, URIs, domains, subdomains, protocols, sockets, bind/listen/connect, proxy and service-discovery indicators |
| API | REST, GraphQL, RPC/gRPC, JSON-RPC, SOAP/WSDL, WebSocket, event-driven APIs, webhooks, OpenAPI, AsyncAPI, OpenRPC, API collections, framework routes, middleware and generated clients |
| Credentials and identity | Password/passphrase, username, first/given/middle/last/family name, email, phone, address, user/account IDs, API keys, tokens, private keys, cloud/database credentials, certificates and service accounts—with strict redaction |
| Archives | ZIP/JAR/WAR/EAR/APK/AAB/IPA, TAR and compressed formats, 7z/RAR/CAB/ISO/package archives; member paths, types, symlinks, hardlinks, permissions, owners, timestamps, compression ratios, encryption, traversal paths and bounded member content |
| Application domains | SQL/NoSQL/vector/graph/search/time-series stores, ORMs, tests, builds, CI/CD, cloud/IaC, containers, AI/ML, robotics, mobile, game engines, embedded, firmware, HDL/FPGA and GPU |
| Reports | Inventory views, dashboards, distributions, searchable/filterable findings, grouped collapsible sections, open/close-all, archive/network/API/identity sections, severity/confidence/evidence, skip/error accounting and portable JSON |

## Installation

Core:

```bash
python -m pip install -e .
```

Development:

```bash
python -m pip install -e ".[dev]"
pytest
```

Optional parser, document and infrastructure integrations:

```bash
python -m pip install -e ".[polyglot,documents,infrastructure]"
```

PDT must not download parser grammars or install dependencies from an analyzed project. Optional integrations are provisioned explicitly by the operator.

## CLI

```bash
pdt --version
pdt --help
pdt scan /path/to/project
pdt scan /path/to/project --output /path/to/reports --format json,markdown,html
pdt scan https://github.com/owner/repository
pdt scan https://github.com/owner/repository --ref v2.1.0
pdt scan --url repositories.txt --output /reports/remotes
pdt scan --url repositories.txt --vcs auto --remote-timeout 900 --remote-workdir /scratch
pdt scan https://github.com/owner/repository --no-download           # provider API, nothing written to disk
pdt scan /path/to/project --skip --max-file-mb 128
pdt scan /path/to/project --exclude-dir node_modules --exclude-dir .cache
pdt vuln-db import /local/advisories/osv --db ~/.pdt/vulnerability-advisories.sqlite3
pdt vuln-db status --db ~/.pdt/vulnerability-advisories.sqlite3
pdt scan /path/to/project --vuln-db ~/.pdt/vulnerability-advisories.sqlite3
pdt scan /path/to/project --vuln-online --vuln-enrich nvd              # opt-in OSV.dev lookup
pdt scan /path/to/project --fail-on HIGH --strict --quiet --no-color   # CI gate
pdt scan /path/to/project --output /reports/project --resume          # continue an interrupted scan
pdt scan /path/to/project --inventory-only                            # metadata only, no content reads
pdt scan /path/to/project --plugin-timeout 30 --plugin-memory-mb 2048  # tighter plugin limits
pdt capabilities --json
pdt plugin-check my_package.analyzer:MyAnalyzer tests/samples/      # check a plugin the way scans load it
pdt query /path/to/reports --callers parse_config --json             # look up the code index
pdt compare project-a-report/discovery-report.json project-b-report/discovery-report.json
pdt catalog-add /reports/project-a/discovery-report.json
pdt catalog-list
pdt catalog-compare --output /reports/project-comparison
```

### Remote repository scans (online mode)

Local scans are offline. Online mode is used only when the target is a repository URL or a `--url` list; PDT then downloads each repository read-only into a private temporary directory, scans it like a local project and deletes the copy. The [Online Mode guide](docs/guides/ONLINE_MODE.md) describes every option, the security model, resource limits, report fields and platform behavior.

```bash
pdt scan https://github.com/owner/repository
pdt scan https://github.com/owner/repository --ref v2.1.0      # branch, tag or full commit ID
pdt scan hg+https://hg.example.net/team/project
pdt scan svn+ssh://svn.example.net/repos/project/trunk --ref 4182
pdt scan fossil+https://fossil.example.net/project
```

For a batch, create a UTF-8 text file with one repository per line: the URL, optionally followed by `ref=NAME` and `vcs=BACKEND`, and an optional `# comment`. Blank lines and lines beginning with `#` are ignored; duplicate targets are removed. A single file can mix providers and VCS types:

```text
# Git hosting providers
https://github.com/owner/project-a
https://github.com/owner/project-a ref=v1.4.0        # the release tag as a second target
https://gitlab.com/group/project-b
ssh://git@bitbucket.org/workspace/project-c.git

# Native VCS backends
hg+https://hg.example.net/team/project-d
svn+https://svn.example.net/repos/project-e/trunk ref=9120
bzr+https://code.example.net/team/project-f
darcs+https://code.example.net/team/project-g
jj+https://github.com/owner/project-h
pijul+https://nest.pijul.com/owner/project-i
cvs+ssh://cvs@cvs.example.net/cvsroot/project-j
p4+ssl://perforce.example.net:1666/depot/project-k
fossil+https://fossil.example.net/project-l
```

Then run:

```bash
pdt scan --url repositories.txt --output ./remote-reports
```

The batch creates a separate report directory for each repository, continues after a repository-specific failure, and writes `batch-summary.json` and `batch-summary.md` (status, revision, exit code and error for every repository, also when interrupted). Supported backends are Git (including GitHub, GitLab, Bitbucket, Azure Repos, CodeCommit, SourceHut and compatible/self-hosted hosts), Mercurial, Subversion, Bazaar/Breezy, Darcs, Jujutsu Git-backed repositories, Pijul, CVS, Perforce and Fossil SCM. The corresponding command-line client must be installed; `pdt capabilities --json` reports which clients are present. Use `--vcs` to force a backend for an ambiguous URL; `auto` uses a VCS prefix when present and otherwise treats the target as Git. The Git path is tested end to end against a real Git server; the other backends are tested with recorded client invocations only.

Remote acquisition is read-only and non-interactive: PDT does not push, commit or modify remote repositories, run hooks or filters, fetch submodules/externals or download Git LFS objects, and clients never prompt (a missing credential fails fast). Passwords, tokens and user names embedded in URLs are rejected; use an SSH agent, a credential helper or your VCS client's configuration. Plain-text transports (`git://`, `http://`, `svn://`, `bzr://`, CVS pserver, Perforce `tcp`) are refused unless you pass `--allow-insecure-transport`, and reports then flag them. Repository paths are validated before anything is written (including Windows device names such as `aux.c`), clients are stopped together with their child processes on timeout or Ctrl-C, the content analyzed is capped by `--remote-max-gb` (default 64) and a 2,000,000-file budget for every backend, downloads by a free-disk floor, and the temporary checkout is removed on every exit path. Content PDT could not materialize is reported as `UNKNOWN` coverage findings and makes `--strict` scans incomplete. Each report records the credential-free URL, revision, ref, transport and coverage under `metrics.source`.

#### Analyze without downloading (`--no-download`)

Online mode has a second path that never clones or writes the repository to disk. `--no-download` reads one commit through the provider's REST API (GitHub and GitHub Enterprise Server, GitLab.com and self-managed GitLab, Bitbucket Cloud, Gitea/Forgejo/Codeberg), turns the tree listing into PDT's inventory and streams each file's content into the built-in analyzers in memory:

```bash
pdt scan https://github.com/owner/repository --no-download
pdt scan https://gitlab.example.com/group/project --no-download --api-url https://gitlab.example.com/api/v4
pdt scan --url repositories.txt --no-download --vuln-online --output ./api-reports
```

Tokens come only from host-bound variables (`PDT_API_TOKEN_<HOST>`, or `GITHUB_TOKEN`/`GITLAB_TOKEN`/`BITBUCKET_TOKEN`/`CODEBERG_TOKEN` for the public hosts) or, with `--use-credential-helper`, from your Git credential helper; they are never logged or written to reports. Work is bounded per repository by `--api-max-files`, `--api-max-mb`, `--api-max-file-mb`, `--api-max-requests` and `--api-workers`; a file left unfetched by a budget, a failed request or an exhausted rate limit stays in the inventory and is reported as an `UNKNOWN` coverage gap (so `--strict` reports the scan as incomplete). Third-party plugins are not run in this mode because their sandbox needs a file copy on disk. Details: [Online Mode guide](docs/guides/ONLINE_MODE.md#analyze-without-downloading---no-download).

The output directory must remain outside the analyzed project. PDT never changes target files.

Exit codes: `0` scan completed, `1` a finding at or above `--fail-on`, `2` usage or fatal error (including a single remote URL that cannot be fetched), `3` incomplete scan under `--strict` or a URL batch in which a repository could not be fetched, `130` interrupted. In a batch, a `--fail-on` hit in any repository takes precedence. See the [Operations Guide](docs/guides/OPERATIONS.md) for large-scan practice and [Benchmarks](docs/guides/BENCHMARKS.md) for `tools/benchmark.py`.

### Exclusions and skip accounting

`--skip` controls only global oversized-file content skipping. `--exclude-dir NAME` is an explicit directory-pruning request. The current scanner traverses development dependency, cache and build directories by default; the marker catalog classifies these trees without excluding them. Explicitly excluded directories remain in the inventory with a prune reason. This behavior is covered by scanner tests, including `node_modules`, `.cache`, `.yarn` and `.fuff`.

### Clean terminal behavior

The terminal is an analysis console, not an append-only file dump. On an interactive TTY, a new scan starts from a clean screen and displays the ASCII brand, phase progress, grouped statuses and a concise end summary. Redirected output must remain deterministic and must not emit terminal-control sequences. `--no-color` turns colors off; narrow-terminal layouts and stable machine-readable logging remain in the roadmap.

## Concurrent execution and GPU acceleration

The scan pipeline schedules file analysis through a bounded pool and exposes `pdt scan --jobs N`; `--jobs 0` selects a bounded automatic worker count based on detected hardware concurrency. Because analyzers are CPU-bound Python, `--executor auto` (the default) uses worker processes for inventories of 1,000 files or more and threads below that; `--executor process|thread` forces either. Small files are batched per task, pending batches are capped at twice the worker count, results are collected in deterministic submission order, and every SQLite write stays in the coordinator process. Each file up to 4 MiB is read once through the verified descriptor, hashed from that buffer and served to every analyzer. If a worker process dies, the pool restarts and the affected batch is re-run file by file. Stateful third-party analyzers can declare `concurrent_safe = False` to serialize their own calls in thread mode.

The C extension dynamically discovers OpenCL at runtime; PDT does not require OpenCL headers, an SDK or a GPU to install/build. For buffers of at least 8 MiB, the supported byte-count operation may dispatch to a detected GPU using a bounded reduction kernel. The large-file secret scanner uses this native byte counter. Small buffers, unsupported devices, allocation failures and kernel/dispatch errors fall back to C/SIMD; when the C extension is unavailable, the Python fallback remains functional. The runtime reports device capabilities, dispatches and fallback counts.

This is deliberately capability-scoped: PDT does not claim that every analyzer runs on the GPU. Language parsing, security rules, framework semantics and report generation remain analyzer-side CPU work. An 8 MiB threshold is an initial engineering default, not a proven optimal threshold; per-device benchmarks and GPU/no-GPU CI coverage remain release gates.

## Security findings: code, impact and remediation

Security findings now carry exact source line numbers, redacted vulnerable-line excerpts, severity, confidence, conditional attacker-impact explanations and recommended remediation. This includes secure-code patterns, Python AST security, secret/PII/configuration indicators, and credential/email patterns found inside ZIP/TAR members. The interactive CLI prints the highest-severity source lines in red; the HTML report displays source excerpts in red using safe DOM text nodes; the JSON report holds every finding field (Markdown shows the title, severity, confidence, detail, evidence, impact and recommendation), and Markdown marks vulnerable lines with a red indicator. The HTML/JSON payload schema and JSON report schema are versioned as 1.7; minor versions are additive, and `compare`/`catalog` accept any 1.x report.

Redaction is applied by the source excerpt helper and again at the `CodeEvidence` model boundary, including for third-party analyzers. It covers common password/token/key assignments, bearer/basic authorization values, credential URLs, provider token formats, JWT-shaped values, email addresses and common identity-field assignments. No heuristic finding is proof of exploitability or runtime exposure: impact text is conditional on reachability and attacker-controlled data, and severity must be reviewed against actual data flow and deployment context.

## Reporting UX

The HTML report is a standalone offline document with a dark command-center visual system. It includes project summary panels, inventory tables, a scan-source view, dedicated vulnerability and VCS/provider views, directory and symlink views, finding search/filter controls, bounded pagination, per-finding disclosure and open/close controls.

Every report format states how the scan obtained its data. The JSON report (schema 1.7) has a top-level `scan` block: `mode` (`local`, or `online` when the network was used), `source` (`local` or `remote`), `network_access` (for example `git-client`, `provider-api`, `osv.dev`, `nvd`, `ghsa`), the credential-free remote source (URL, provider, VCS, ref, revision, transport and whether it lacks TLS) and the vulnerability sources used. The Markdown report adds *Scan Source* and *Vulnerability Intelligence* sections; the HTML header shows a LOCAL SCAN / ONLINE SCAN badge (and NO TLS for plain-text transports), and its scan-source and vulnerability views show the remote metadata, coverage gaps and the online advisory provenance (source, endpoint, query time, cache hits, requests and coverage), with a warning whenever an online lookup was incomplete. The report files themselves never load remote assets, whichever mode produced them.

Production report goals:
- comprehensive overview of files, directories, hidden entries, links, file types, languages, sizes and development trees;
- dedicated network, endpoint/API, OS/platform, archive, identity/secret and analyzer-coverage views;
- grouped findings by domain, severity and confidence;
- lazy/bounded rendering for 100k+ findings and large inventories;
- global search, filters, stable navigation, open/close-all, section collapse and evidence detail;
- redacted content and no remote assets, scripts, fonts or requests;
- keyboard accessibility, responsive layouts, clear empty/loading/error states and tests for report-data escaping.

## Local vulnerability intelligence

PDT can match resolved dependency versions from supported lockfiles against an operator-provisioned local OSV JSON snapshot. Import and scan are separate operations:

```bash
# Import JSON advisory records already stored on this machine (no network access)
pdt vuln-db import /local/advisories/osv --db ~/.pdt/vulnerability-advisories.sqlite3
pdt vuln-db status --db ~/.pdt/vulnerability-advisories.sqlite3

# Enable local advisory matching for this scan
pdt scan /path/to/project --vuln-db ~/.pdt/vulnerability-advisories.sqlite3
```

The initial matching layer covers ecosystems represented by supported lockfile parsers (npm, PyPI, crates.io, Go, Packagist, RubyGems, Hex, NuGet and Swift Package Manager). It evaluates OSV explicit affected-version lists and supported SEMVER/ECOSYSTEM event ranges, records aliases such as CVE/GHSA, severity and fixed-version boundaries, and includes advisory snapshot metadata in reports. Lockfile reads are capped at 128 MiB and package extraction is capped at 250,000 resolved entries per lockfile; crossing either limit produces an `UNKNOWN` finding, not a partial clean result.

Confirmed advisory matches include a conditional attacker-impact explanation based on the imported advisory description and a remediation recommendation tied to its fixed-version boundary where available. Uncomparable range schemes (including commit-only GIT ranges), missing version information and parser-budget failures remain `UNKNOWN`, with manual verification guidance. A confirmed range match means the resolved version matches the imported advisory range; it does **not** prove runtime loading, reachability, exploitability or exposure. The `--vuln-db` path performs no automatic online update, hosted API call, telemetry or network fallback. The advisory DB is local and should be refreshed by an operator using a separately obtained, trusted advisory snapshot. Current support is partial; distro packages, OS packages, transitive resolution not represented in lockfiles and additional advisory feeds remain roadmap work.

### Online vulnerability intelligence (opt-in)

`--vuln-online` looks the same lockfile packages up in OSV.dev instead of, or in addition to, a local snapshot, for local paths and remote URLs alike. Only the ecosystem, package name and resolved version are sent; file contents, paths and project names never leave the machine. `--vuln-enrich nvd,ghsa` adds CVSS and CWE details from NVD CVE API 2.0 and the GitHub Advisory Database (keys from `NVD_API_KEY` and `GITHUB_TOKEN`, sent only to their own hosts and never written anywhere). Answers are cached in a local SQLite file for 24 hours (`--vuln-cache`, `--vuln-cache-ttl`), requests are batched (1,000 packages per OSV.dev request) and rate-limited, and the standard proxy variables and `--ca-bundle` are honored. A network failure, rate limit or timeout is reported as an `UNKNOWN` coverage finding and makes `--strict` scans incomplete; it is never reported as "no vulnerabilities". Without `--vuln-online` no advisory service is contacted.

```bash
pdt scan /path/to/project --vuln-online
pdt scan https://github.com/owner/repository --vuln-online --vuln-enrich nvd,ghsa
```

Request formats, failure handling, every option and the provenance recorded in reports are described in the [Online Mode guide](docs/guides/ONLINE_MODE.md#online-vulnerability-intelligence).

## Evidence and confidence

- **CONFIRMED** — directly supported by source, file metadata, manifest or parser evidence.
- **INFERRED** — heuristic observation that requires review.
- **UNKNOWN** — evidence is insufficient, parsing was unavailable, or a resource limit prevented analysis.

Documentation does not prove implementation. A declared package does not prove installation or runtime usage. A route definition does not prove that the endpoint is exposed. An email-shaped string does not prove an individual's identity. A host OS metric does not prove the project's target OS.

## Repository layout

```text
src/project_discovery/
  cli.py             command-line interface and scan orchestration
  models.py          report data model (Finding, FileRecord, ScanResult)
  inventory/         no-follow filesystem walker, SQLite inventory store, fingerprint cache
  engine/            bounded process/thread executor, native backends, runtime telemetry
  analyzers/         built-in analyzers by domain, the plugin base class and the registry
    code/  security/  dependencies/  api/  databases/
    delivery/  environment/  content/  domains/
  intelligence/      shared code model, code facts, cross-file code index, project graphs
  vulnerabilities/   local OSV advisory database, ecosystem version ordering, CVSS
  plugins/           plugin isolation policy, sandboxed hosts and their protocol
  online/            online mode: URL targets, read-only VCS checkouts, provider APIs for
                     no-download scans, online advisory sources
  reporting/         JSON, Markdown and HTML writers; the offline HTML client in web/
  projects/          multi-project comparison, integration maps, local project catalog
  catalog/           language and analyzer-domain capability catalogs
  core/              verified reads, redaction, safe parsers, credential registry
  data/              bundled data (IANA TLD list)
native/              c/, cpp/, asm/ and rust/ sources of the optional native extensions
tests/               pytest suite, laid out like the package
docs/                architecture/, analyzers/, guides/ and project/ (roadmap, audit)
tools/               benchmark corpus generator and runner
```

Plugins depend only on `project_discovery.analyzers.base` and `project_discovery.models`, whose paths are stable. The [documentation index](docs/README.md) lists every guide.

## Polyglot and native implementation strategy

PDT is intentionally polyglot. Python is the control plane, not the only implementation language:

- **Python:** CLI/control plane, analyzer orchestration, the built-in analyzers and shared code model, plugin SDK, capability registry, local cache coordination and shared report schema.
- **C:** portable native core for bounded byte counting and hardware capability reporting. The active implementation block adds dynamic OpenCL device discovery and a bounded GPU kernel with automatic CPU fallback; no GPU SDK is required at build time.
- **x86-64 Assembly:** implemented Linux x86-64 SIMD backend using SSE2 compare/movemask and POPCNT, selected only after runtime CPU-feature checks. Other CPUs/platforms use C fallback.
- **Rust:** an optional PyO3 no-follow filesystem iterator is integrated into scanner traversal. It uses native directory iterators and bounded active-directory state; a persistent index reused across scans remains planned.
- **C++:** an optional C++17 signature classifier is compiled as a native extension and used by scanner file-type detection, with a Python fallback.
- **JavaScript:** the offline report client is a real source asset at `src/project_discovery/reporting/web/report.js`; it is bundled into standalone HTML. TypeScript is not currently a compiled runtime dependency.
- **Other languages:** analyzers and parsers use the languages/framework SDKs that provide the most accurate evidence.

C, x86-64 Assembly, C++, Rust and JavaScript now have source files and actual execution paths. Store-backed CLI scans persist all four inventory record kinds in bounded SQLite batches and expose files, directories, symlinks and special entries through lazy typed sequences. Directory child counts, ancestor file counts, byte totals and traversal errors use bounded SQLite state deltas rather than a Python directory map. The Python fallback retains only active directory iterators on a depth-proportional stack. Analyzer findings are persisted in SQLite with deterministic duplicate suppression and lazy iteration; scan diagnostics preserve insertion order and duplicates. The CLI security summary uses bounded top-25 selection. Python dependency-graph indexes/edges/unresolved imports and architecture component details now have explicit caps and incomplete-evidence reporting, but graph adjacency/SCC structures remain in memory within those limits. Per-file analyzer working sets, report metrics and the offline browser's embedded report payload (bounded by `embedded_limits`) remain memory gates. Cross-platform native packaging, sanitizer/fuzz coverage and 2GB–100GB+ benchmarks remain release gates. Every native component needs explicit API/ownership/error contracts, tests, a portable fallback and repeatable benchmark evidence.

## Polyglot source map

| Component | Source files | Runtime responsibility |
|---|---|---|
| Python orchestration and analyzers | `src/project_discovery/` | CLI, analyzer registry, evidence correlation, report schema and portable fallbacks |
| Rust filesystem iterator | `native/rust/Cargo.toml`, `native/rust/src/lib.rs` | PyO3 no-follow directory iteration and native filesystem metadata |
| C++ signature engine | `native/cpp/pdt_signatures.cpp` | C++17 magic-byte classifier used by scanner file-type detection |
| C native core | `native/c/pdt_native.c` | Portable C/SIMD byte counting, runtime OpenCL GPU detection, bounded large-buffer reduction kernel and CPU fallback |
| x86-64 Assembly | `native/asm/pdt_simd_x86_64.S` | Linux x86-64 SIMD/POPCNT byte-counting primitive |
| Offline report client | `src/project_discovery/reporting/web/report.js` | Search, paging, filters and expandable/collapsible findings; bundled into HTML |

Native build integration is defined in `setup.py`, `pyproject.toml` and `MANIFEST.in`. The test suite requires the C++, Rust and platform-appropriate C/Assembly components to build in CI; Python fallbacks remain available for unsupported local environments.


## Release policy

The current PR remains unmerged. Production readiness requires all mandatory roadmap gates, a green CI run on the final PR head, representative 2GB/10GB/50GB/100GB+ benchmarks, bounded-memory behavior, adversarial archive and symlink tests, broad language/analyzer conformance, verified redaction, offline/read-only guarantees, usable large HTML reports, reproducible packages and security review. As of 0.2.0, CI is green across the full matrix, the adversarial corpus (archive, YAML/XML bomb, junction-loop, encoding and non-UTF-8 name cases) runs without hangs or crashes, redaction is enforced from one shared credential registry, and reports are bounded. Plugin isolation is complete on Linux, macOS and Windows; the large-corpus benchmarks and an independent security review remain open. Only the repository owner decides when to merge into `master`.

## Production engineering priorities (2026-11-06)

The work prioritizes correctness and scale over adding catalog labels. Done on this branch: persistent SQLite-backed inventory and findings with no silent pruning, multi-process analysis with `--resume`, bounded archive inspection (sample, decompression and wall-time budgets), the shared code model and cross-file code index, data-flow/taint analysis, sandboxed plugins, bounded HTML embedding, and redacted vulnerable-line findings across every report format. Remaining release work:

1. Finish online mode end to end, including online vulnerability sources and a no-download path (in progress).
2. Reorganize `src/` into a nested package layout.
3. Archives: nested-archive traversal under a shared budget, and metadata readers for 7z, RAR, CAB and ISO.
4. Deeper semantics: inference of classes the code does not state, and HDL elaboration of `generate` blocks and parameters. (Lexical inter-procedural taint and Tree-sitter-backed code models are implemented; see the changelog.)
5. Chunked offline HTML rendering for result sets larger than the embedded bounds.
6. GPU-present, GPU-absent, OpenCL-failure and CPU/GPU parity tests on supported hardware.
7. Benchmark 2 GB/10 GB/50 GB/100 GB+ corpora and tune worker and GPU thresholds using wall time, throughput and peak RSS.
8. Run the full cross-platform build, security, coverage and packaging gates on the final PR head, and an independent security review.

PDT recognizes 128 languages and formats (81 source languages), with capability states reported per language and analyzer; see [Polyglot Parsers](docs/architecture/POLYGLOT_PARSERS.md). Python is the control plane and implements the analyzers. Native C and x86-64 Assembly provide byte counting, C++ the signature classifier and Rust the integrated filesystem traversal. C++ is used only where an actual native dependency or performance boundary justifies it, and JavaScript owns the offline report interaction layer. No language is considered implemented because it appears in documentation or a catalog.

The default scan inventories and analyzes oversized files. Only the explicit `--skip` option enables the global threshold-based content skip; skipped files remain in inventory and carry a visible reason. Analyzer-specific hard safety budgets are reported as UNKNOWN/partial and must never be represented as a clean result.
