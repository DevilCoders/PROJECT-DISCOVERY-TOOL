# PROJECT DISCOVERY TOOL

**Local-first, read-only project intelligence and architecture analyzer.**

PDT inventories and analyzes heterogeneous software repositories without importing or executing target project code. It is designed for polyglot codebases and extensible analysis domains; it does not assume that a repository uses one language, framework, architecture, or deployment model.

## Current capabilities

- Deterministic filesystem inventory; skips symlinks and common generated/vendor directories.
- SQLite fingerprint cache for incremental content hashing.
- Python AST analysis and evidence-backed internal Python import graph with cycle detection.
- Structural documentation analysis for Markdown, HTML, reStructuredText and text formats; optional PDF and DOCX extraction.
- Conservative secret-pattern detection with strict value redaction, plus configuration key inventory and risky-setting indicators.
- Static API contract inventory for OpenAPI/Swagger, GraphQL, Protocol Buffers and Thrift.
- SQL DDL/schema inventory, Prisma ORM models/relations and inferred destructive migration indicators.
- Test-suite discovery and static build-manifest inventory across common ecosystems.
- Dependency declaration extraction for Python, Node.js, Rust, Go and Composer manifests.
- Recognition catalog for 40+ languages and project file formats.
- Optional offline-first Tree-sitter adapter covering 60+ language/format grammar mappings, declaration extraction and selected-language import-reference inventory when grammars are already provisioned locally.
- Machine-readable analyzer domain catalog spanning 50+ domains, including security, APIs, databases, infrastructure, CI/CD, AI/ML, robotics, embedded, game engines, mobile and multi-project intelligence.
- Rich terminal progress and summary output, plus JSON, Markdown and standalone dark HTML reports with search, category/confidence filters, collapsible findings and raw metrics.

The language and domain catalogs are coverage maps, not claims that every language-specific semantic analyzer or every domain analyzer is complete. Current implementation status is included in scan metrics.

## Install

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
python -m pip install -e ".[polyglot,documents]"
```

PDT never downloads grammars during a scan. The Tree-sitter adapter checks local parser availability first. Provision any required grammar libraries separately under your own operational policy; unavailable grammars are reported as capability gaps and skipped.

## Run

```bash
pdt scan /path/to/project
```

By default, reports are written to a sibling directory named `<project-name>-pdt-report`, outside the target repository. Override it explicitly:

```bash
pdt scan /path/to/project --output /path/to/reports --format json,markdown,html
```

The output directory must be outside the analyzed project. PDT does not modify target files.

Compare independent scan reports without merging project identities:

```bash
pdt compare project-a-report/discovery-report.json project-b-report/discovery-report.json --output comparison-report
```

## Confidence model

- **CONFIRMED** — directly supported by source or configuration evidence.
- **INFERRED** — heuristic conclusion; requires validation.
- **UNKNOWN** — evidence is insufficient or a capability is unavailable.

A dependency manifest declaration does not prove that a dependency is installed or used. Documentation does not prove that a described feature is implemented. Parser diagnostics do not prove that a program fails to compile or run.

## Extending PDT

Implement the analyzer contract in `project_discovery.analyzers.base.Analyzer` and expose a no-argument constructor through the `pdt.analyzers` entry-point group. Plugins execute in the PDT process and must be trusted. The analyzer domain catalog documents the broader coverage contract and distinguishes implemented domains from planned work.

## Privacy and operational boundaries

- No telemetry or hosted inference is part of the scanner.
- Target source is not uploaded.
- Target files are read only; cache and reports are written to the external output directory.
- Symlinks are not followed.
- Oversized files are inventoried but skipped for content analysis.
- Optional parser grammars must already be present locally; scanning does not initiate parser downloads.
- PDT is a static analyzer, not a sandbox. Review third-party plugins before enabling them.

## Project status

PDT is under active development. The current PR is not a production release. Production readiness requires the full analyzer suite, regression/performance testing, packaging validation, security review, and release documentation.
