# PROJECT DISCOVERY TOOL

**PDT — local-first, read-only, polyglot project intelligence for large and heterogeneous codebases.**

PDT is designed to discover what a project actually contains: source languages, files, directories, hidden entries, development dependency trees, build systems, APIs, network indicators, credentials/PII indicators, archives, databases, deployment infrastructure, AI/ML components, robotics, game engines, and relationships between independent projects.

It is not a one-language directory counter. A repository may combine dozens of programming languages, generated formats, binaries, embedded systems, mobile applications, frontend applications, ML artifacts, and infrastructure definitions. PDT must report that heterogeneity without assuming that any single language or framework is the project's center.

> **Status:** active engineering / pre-production. The current PR is not a production release. Capability catalogs distinguish implemented, partial, parser-mapped, and planned coverage. Presence in a catalog is not a claim of complete semantic analysis.

## Project banner

```text
 ____  ____ _____
|  _ \/ ___|_   _|
| |_) \___ \ | |
|  __/ ___) || |
|_|   |____/ |_|

PROJECT DISCOVERY TOOL
POLYGLOT INTELLIGENCE  //  LOCAL-FIRST  //  READ-ONLY
```

## Engineering contracts

### Local-first and read-only

- No target source, reports, configuration, or scan results are uploaded to hosted services.
- Target code is never imported, executed, launched, or connected to a runtime service.
- No automatic grammar downloads, dependency installation, archive extraction, or cloud/API calls.
- Scan cache and generated reports are stored outside the analyzed project by default.
- Symlinks are recorded as links and never traversed.
- Archive members are inspected through archive metadata/index structures; entries are never extracted to disk.
- Secret-like values and personal data are redacted in findings. Reports should retain evidence locations and classifications, not raw passwords, tokens, private keys, or full PII values.
- Static observations are separated from runtime facts. A URL, port, dependency, endpoint, or ROS topic found in source is not proof that it is reachable or active.

### Polyglot by design

The language catalog recognizes 40+ programming languages and many additional schemas, build formats, configuration languages, documentation formats, and binary artifact types. The optional Tree-sitter adapter maps 60+ grammar names.

PDT tracks language capability states separately:

1. file type recognized;
2. parser integration mapped;
3. parser available locally;
4. syntax tree parsed;
5. declarations/imports extracted;
6. project-local symbols and references resolved;
7. language-specific semantics analyzed.

A grammar mapping is not equivalent to semantic support. The long-term target is substantive analyzer coverage across 40+ languages and their framework ecosystems, not merely extension recognition. Language/analyzer packs are independently testable and optional where a parser or SDK is required.

### Large-repository design

Target workload: repositories from a few gigabytes through 100GB+.

- Deterministic, incremental inventory with metadata-aware cache invalidation.
- Bounded-memory streaming for hashing and text-pattern analysis.
- Parallelizable file work with configurable concurrency and back-pressure.
- Separate resource budgets for parsers, archives, and individual analyzers.
- Directory and development-dependency summaries to identify large generated/vendor/cache trees.
- Progress reporting based on discovery and analysis phases, with errors isolated per entry/analyzer.
- No unbounded read of a large file into memory merely because global oversized-file skipping is disabled.

**Oversized-file policy transition:** the current branch still has a global size threshold that marks oversized files as skipped automatically. This is a known behavior to remove before release. The target behavior is opt-in: content analysis is skipped only when the user explicitly supplies `--skip` (with a configurable size threshold); otherwise compatible streaming analyzers continue. Parsers that cannot safely process a particular huge file must report an analyzer-specific resource-limit status rather than silently hiding the file or pretending it was fully analyzed.

## Current implementation

The following capabilities have initial implementations in the current branch; their documentation and tests describe the current scope, not complete production coverage:

- Deterministic filesystem inventory, read-only output boundary, common generated/vendor directory pruning, and SQLite fingerprint caching.
- Python AST analysis and evidence-backed internal Python import graph with cycle detection.
- Central language recognition catalog and optional offline-first Tree-sitter grammar adapter.
- Markdown/document analysis with optional PDF and DOCX integrations.
- JSON, Markdown, and standalone interactive dark HTML reports.
- Rich terminal progress and summary UI.
- Analyzer plugin entry-point API and domain coverage catalog.
- Dependency manifests, selected lockfiles, license inventory, and configuration key inventory.
- Secret-pattern detection, Python and polyglot secure-code heuristics, and identity/access-control markers.
- REST/OpenAPI, GraphQL, RPC, event, SOAP/WSDL, API collection, and selected source endpoint discovery.
- SQL, NoSQL, Prisma ORM, and cross-framework migration inventory.
- Test/build/CI/CD, container, deployment, and infrastructure manifest discovery.
- Initial ML/AI, ROS 1/ROS 2, mobile, game-engine, frontend, accessibility, and multi-project intelligence.

See [Analyzer Coverage](docs/ANALYZER_COVERAGE.md), [Architecture](docs/ARCHITECTURE.md), and [Roadmap](docs/ROADMAP.md) for capability status and work remaining.

## Required discovery domains

The following are first-class PDT inventory/analyzer domains. The roadmap tracks their implementation state and acceptance criteria.

| Area | Required discovery |
|---|---|
| Filesystem | Files, subdirectories, directory depth/fan-out, empty directories, hidden entries, symlinks, special files, permissions, ownership where available, timestamps, file type, extension, size buckets and per-directory totals |
| Development artifacts | `node_modules`, `.cache`, `.yarn`, `.pnpm-store`, `.npm`, `.gradle`, `.m2`, `.venv`, `vendor`, build outputs, IDE indexes, compiler caches, fuzzing corpora and other ecosystem-specific trees |
| Operating systems | Host OS versus inferred project target OS; OS/package manager, shell, service, kernel, cross-compilation, platform and CI matrix indicators |
| Network indicators | IPv4, IPv6, CIDR, ports, hostnames, domains/subdomains, URLs/URIs, socket/protocol references, proxy, bind/listen/connect and service-discovery references |
| APIs and protocols | REST, GraphQL, RPC/gRPC, JSON-RPC, SOAP, WebSocket, event/messaging, AsyncAPI, OpenAPI, schema registries, framework routes, generated clients and API collections |
| Secrets and identity data | Passwords, passphrases, tokens, API keys, private-key material, access credentials, usernames, first/last-name fields, email addresses, phone/address identifiers and other PII indicators—with strict value redaction |
| Archives | ZIP, TAR and compressed/container formats; archive member names, entry types, symlinks, permissions, timestamps, compression metadata, encrypted entries, path traversal/absolute paths and suspicious metadata, without extraction |
| Project structure | File-type/signature classification, size distributions, hidden files, subdirectory maps, dependency/build trees, symlink targets/scopes, and generated/vendor/cache indicators |
| Reports | Searchable/filterable HTML, grouped and collapsible findings, open-all/close-all controls, summary dashboards, inventory tables, archive and network sections, severity/confidence, evidence paths and machine-readable JSON |

PDT must never turn an inferred value into a confirmed fact. Detection of an email-shaped string is a PII indicator; it is not proof of a person's identity. Detection of `0.0.0.0:8080` in a config file is not proof of a listener is bound on that port.

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

Optional parser and document integrations:

```bash
python -m pip install -e ".[polyglot,documents,infrastructure]"
```

Install optional extras only when required. PDT must not download grammars or install target-project dependencies during a scan.

## Current CLI

```bash
pdt --version
pdt scan /path/to/project
pdt scan /path/to/project --output /path/to/reports --format json,markdown,html
pdt compare project-a-report/discovery-report.json project-b-report/discovery-report.json
pdt catalog-add /reports/project-a/discovery-report.json
pdt catalog-list
pdt catalog-compare --output /reports/project-comparison
```

The output directory must be outside the analyzed project. PDT does not modify target files.

### Resource-control CLI target

The explicit oversized-file policy is being implemented. The intended interface is:

```bash
# Default: do not globally skip large files; use bounded/streaming analyzers.
pdt scan /path/to/project

# Opt in to skipping content analysis above the configured threshold.
pdt scan /path/to/project --skip --max-file-mb 128

# Opt in to ignoring selected directory trees without hiding their directory markers.
pdt scan /path/to/project --exclude-dir node_modules --exclude-dir .cache
```

Flags will be documented as available only after they are implemented and tested. Exclusion of a tree must be visible in the inventory/report and never silently look like a directory did not exist.

## Reporting and terminal UX

The terminal interface is intended to behave like a focused analysis console, not an ever-growing raw file listing: clear command boundaries, a branded ASCII header, phase-oriented progress, grouped status messages, compact metric panels, actionable warnings, and a final summary. Interactive terminals may clear the previous screen; redirected/non-interactive output must remain stable and script-friendly.

The HTML report is intended for large result sets. It must provide:
- high-level project overview and scan health;
- inventory and size distribution;
- directory and development-artifact maps;
- symlink, hidden-entry, file-type and archive sections;
- network and API endpoint sections;
- redacted secret/PII indicators;
- analyzer/domain coverage and diagnostics;
- category, severity, confidence and text filters;
- lazy/collapsible findings with open-all and close-all controls;
- evidence navigation, summary counts, and responsive dark UI.

## Confidence and evidence model

- **CONFIRMED** — directly supported by source, metadata, or configuration evidence.
- **INFERRED** — heuristic conclusion that requires validation.
- **UNKNOWN** — evidence is insufficient or a capability is unavailable.

A dependency declaration does not prove installation or use. Documentation does not prove code implementation. A source URL or port does not prove network reachability. A parser error is not by itself a compiler/runtime failure. A project OS indicator does not prove the current host OS.

## Polyglot and native implementation strategy

- **Python** remains the orchestration, plugin, CLI, reporting, and rapid analyzer layer.
- **Rust** is the preferred candidate for a memory-safe high-throughput filesystem/archive/indexing core if benchmarks show that the Python implementation is a bottleneck. The native boundary must have a stable, versioned interface and a portable fallback.
- **C** is reserved for narrowly scoped native interoperability or a measured hot path that cannot be handled cleanly through Rust/Python.
- **Assembly** is not a default requirement for filesystem discovery. It may be considered only for a measured, architecture-specific bottleneck with reproducible benchmarks and a portable fallback.
- **JavaScript/TypeScript** may be used for self-contained report UI behavior, while remaining bundled/offline and not requiring a hosted service.
- Other languages may be added when a concrete analyzer, ecosystem, or runtime makes them the most maintainable choice.

The project will not add C/ASM merely to appear low-level. Every native component needs benchmarks, portability tests, memory-safety review, and a documented reason to exist.

## Plugin development

Implement the analyzer contract in `project_discovery.analyzers.base.Analyzer` and expose a no-argument constructor through the `pdt.analyzers` entry-point group. Plugins execute in the PDT process and must be trusted. The plugin SDK and conformance suite are part of the production release gate.

## Production-release policy

PDT remains pre-production until the release gate in [ROADMAP](docs/ROADMAP.md) is satisfied: cross-platform CI, analyzer conformance, broad polyglot coverage, large-repository benchmarks, memory/resource limits, read-only and offline guarantees, archive adversarial tests, secret redaction, report UX/accessibility, reproducible packages, and security review. The feature PR must remain unmerged until the repository owner explicitly approves it.
