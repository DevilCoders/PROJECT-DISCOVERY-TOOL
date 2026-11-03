# PROJECT DISCOVERY TOOL

**PDT — local-first, read-only, polyglot project intelligence for large and heterogeneous codebases.**

PDT inventories a project first, analyzes it with independent evidence-producing analyzers, then produces machine-readable and human-oriented reports. It is designed for repositories containing many languages, frameworks, build systems, operating systems, APIs, data stores, deployment systems, archives, binaries, hardware/robotics components, and generated/development dependency trees.

PDT does not assume that a project is Python-based, that one language is its core, or that a repository's README accurately describes its implementation.

> **Status: active engineering / pre-production.** The current feature PR is not a production release. Catalog coverage, grammar mappings, initial pattern analyzers and full semantic support are different capability levels. A catalog entry must never be presented as a completed analyzer.

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
- ZIP/TAR members can be inspected through bounded in-memory streams; archive entries are never extracted to disk. Formats without a supported index reader are reported as detected but not deeply inspected.
- Secret and PII evidence must be redacted. Reports may retain category, file/member path, line, confidence and a keyed local fingerprint; they must not contain complete passwords, tokens, private keys, email addresses or personal-data values.
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
- Python AST analysis and a Python internal-import graph with cycle detection.
- Language/file-format recognition and an optional, offline-first Tree-sitter adapter.
- Markdown plus optional PDF/DOCX document extraction.
- Dependency manifests, selected lockfiles, licenses and configuration metadata.
- Secret-pattern, personal-data field-name, email-shaped-value and secure-code indicators with redacted evidence.
- Static API-type classification, API contracts and initial source route extraction.
- SQL, NoSQL, Prisma ORM and migration indicators.
- Test discovery, build manifests, CI/CD, container and deployment manifests.
- ZIP/TAR member metadata and bounded content samples without extraction; other recognized archive formats may be detection-only.
- IPv4/IPv6/CIDR/port, URI/URL, hostname/subdomain and protocol indicators; host OS metadata and target-platform markers.
- Initial AI/ML, ROS 1/2, mobile, game-engine, frontend, accessibility, localization, observability, coverage, VCS/hosting and multi-project analysis.
- Local-only OSV advisory database import and lockfile-based vulnerability matching when an operator supplies `--vuln-db`.
- JSON/Markdown reports and an offline dark HTML report with search, filters, pagination and collapsible findings.
- A Rich CLI with an ASCII banner, progress phases, compact summary panels and TTY-aware screen clearing.

These are initial implementations with varying depth. In particular, the filesystem inventory is currently retained in memory, common dependency/build directories are still implicitly pruned by the scanner, non-ZIP/TAR archive formats have limited inspection, and many polyglot analyzers use conservative lexical patterns rather than full language semantics. Those are explicit production work items—not completed capabilities.

See [Analyzer Coverage](docs/ANALYZER_COVERAGE.md), [Architecture](docs/ARCHITECTURE.md), and [Roadmap](docs/ROADMAP.md).

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
pdt scan /path/to/project --skip --max-file-mb 128
pdt scan /path/to/project --exclude-dir node_modules --exclude-dir .cache
pdt vuln-db import /local/advisories/osv --db ~/.pdt/vulnerability-advisories.sqlite3
pdt vuln-db status --db ~/.pdt/vulnerability-advisories.sqlite3
pdt scan /path/to/project --vuln-db ~/.pdt/vulnerability-advisories.sqlite3
pdt compare project-a-report/discovery-report.json project-b-report/discovery-report.json
pdt catalog-add /reports/project-a/discovery-report.json
pdt catalog-list
pdt catalog-compare --output /reports/project-comparison
```

The output directory must remain outside the analyzed project. PDT never changes target files.

### Exclusions and skip accounting

`--skip` controls only global oversized-file content skipping. `--exclude-dir NAME` is an explicit directory-pruning request. The current scanner traverses development dependency, cache and build directories by default; the marker catalog classifies these trees without excluding them. Explicitly excluded directories remain in the inventory with a prune reason. This behavior is covered by scanner tests, including `node_modules`, `.cache`, `.yarn` and `.fuff`.

### Clean terminal behavior

The terminal is an analysis console, not an append-only file dump. On an interactive TTY, a new scan starts from a clean screen and displays the ASCII brand, phase progress, grouped statuses and a concise end summary. Redirected output must remain deterministic and must not emit terminal-control sequences. A no-color mode, narrow-terminal layouts and stable machine-readable logging remain in the roadmap.

## Reporting UX

The HTML report is a standalone offline document with a dark command-center visual system. It includes project summary panels, inventory tables, dedicated local vulnerability and VCS/provider views, directory and symlink views, finding search/filter controls, bounded pagination, per-finding disclosure and open/close controls.

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

The initial matching layer covers ecosystems represented by supported lockfile parsers (npm, PyPI, crates.io, Go, Packagist, RubyGems, Hex, NuGet and Swift Package Manager). It evaluates OSV explicit affected-version lists and supported SEMVER/ECOSYSTEM event ranges, records aliases such as CVE/GHSA, severity and fixed-version boundaries, and includes advisory snapshot metadata in reports.

A confirmed range match means the resolved version matches the imported advisory range. It does **not** prove runtime loading, reachability, exploitability or exposure. Unsupported range schemes (including commit-only GIT ranges), missing version information and parser-budget failures remain UNKNOWN. No automatic online update, hosted API, telemetry or network fallback is performed during scanning. The advisory DB is local and should be refreshed by an operator using a separately obtained, trusted advisory snapshot. Current support is partial; distro packages, OS packages, transitive resolution not represented in lockfiles and additional advisory feeds remain roadmap work.

## Evidence and confidence

- **CONFIRMED** — directly supported by source, file metadata, manifest or parser evidence.
- **INFERRED** — heuristic observation that requires review.
- **UNKNOWN** — evidence is insufficient, parsing was unavailable, or a resource limit prevented analysis.

Documentation does not prove implementation. A declared package does not prove installation or runtime usage. A route definition does not prove that the endpoint is exposed. An email-shaped string does not prove an individual's identity. A host OS metric does not prove the project's target OS.

## Polyglot and native implementation strategy

PDT is intentionally polyglot. Python is the control plane, not the only implementation language:

- **Python:** CLI/control plane, analyzer orchestration, plugin SDK, capability registry, local cache coordination and shared report schema.
- **C:** implemented portable native core for bounded byte counting and hardware capability reporting. The streaming secret analyzer uses it for native newline counting.
- **x86-64 Assembly:** implemented Linux x86-64 SIMD backend using SSE2 compare/movemask and POPCNT, selected only after runtime CPU-feature checks. Other CPUs/platforms use C fallback.
- **Rust:** an optional PyO3 no-follow filesystem iterator is now integrated into scanner traversal. It uses native directory iterators and bounded active-directory state; persistent indexing and bounded analyzer queues remain outstanding.
- **C++:** an optional C++17 signature classifier is compiled as a native extension and used by scanner file-type detection, with a Python fallback.
- **JavaScript:** the offline report client is a real source asset at `src/project_discovery/web/report.js`; it is bundled into standalone HTML. TypeScript is not currently a compiled runtime dependency.
- **Other languages:** analyzers and parsers use the languages/framework SDKs that provide the most accurate evidence.

C, x86-64 Assembly, C++, Rust and JavaScript now have source files and actual execution paths. The Rust iterator reduces Python-level traversal overhead but does not yet solve the all-in-memory inventory/result model. Persistent storage, bounded analyzer queues, cross-platform native packaging, sanitizer/fuzz coverage and 2GB–100GB+ benchmarks remain release gates. Every native component needs explicit API/ownership/error contracts, tests, a portable fallback and repeatable benchmark evidence.

## Polyglot source map

| Component | Source files | Runtime responsibility |
|---|---|---|
| Python orchestration and analyzers | `src/project_discovery/` | CLI, analyzer registry, evidence correlation, report schema and portable fallbacks |
| Rust filesystem iterator | `native/rust/Cargo.toml`, `native/rust/src/lib.rs` | PyO3 no-follow directory iteration and native filesystem metadata |
| C++ signature engine | `native/pdt_signatures.cpp` | C++17 magic-byte classifier used by scanner file-type detection |
| C native core | `native/pdt_native.c` | Portable byte counting and CPU capability reporting |
| x86-64 Assembly | `native/pdt_simd_x86_64.S` | Linux x86-64 SIMD/POPCNT byte-counting primitive |
| Offline report client | `src/project_discovery/web/report.js` | Search, paging, filters and expandable/collapsible findings; bundled into HTML |

Native build integration is defined in `setup.py`, `pyproject.toml` and `MANIFEST.in`. The test suite requires the C++, Rust and platform-appropriate C/Assembly components to build in CI; Python fallbacks remain available for unsupported local environments.


## Release policy

The current PR remains unmerged. Production readiness requires all mandatory roadmap gates, a green CI run on the final PR head, representative 2GB/10GB/50GB/100GB+ benchmarks, bounded-memory behavior, adversarial archive and symlink tests, broad language/analyzer conformance, verified redaction, offline/read-only guarantees, usable large HTML reports, reproducible packages and security review. Only the repository owner decides when to merge into `master`.

## Production engineering priorities (2026-11-04)

The next implementation cycle prioritizes correctness and scale over adding catalog labels. The required order is: (1) remove silent inventory pruning and introduce bounded streaming inventory; (2) implement the Rust traversal/index engine and stable native boundary; (3) complete archive metadata/content inspection under explicit decompression, nesting, ratio, time and byte budgets; (4) expand cross-language security/configuration/API/database/test/build evidence; (5) complete redacted identity/credential, network, OS, file-type and dependency-tree reporting; (6) make the offline HTML report lazy and bounded for very large result sets; (7) validate the full system with adversarial fixtures, polyglot corpora and 2GB–100GB+ benchmarks.

PDT's language goal is 40+ language families, with capability states reported per analyzer. Python remains orchestration only. Native C and x86-64 Assembly are implemented; Rust must become an integrated, tested execution path for traversal/indexing. C++ is used only where an actual native dependency or performance boundary justifies it. JavaScript/TypeScript own the offline report interaction layer. No language is considered implemented because it appears in documentation or a catalog.

The default scan inventories and analyzes oversized files. Only the explicit `--skip` option enables the global threshold-based content skip; skipped files remain in inventory and carry a visible reason. Analyzer-specific hard safety budgets are reported as UNKNOWN/partial and must never be represented as a clean result.
