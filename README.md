# Project Discovery Tool (PDT)

**Read-only project intelligence for large, polyglot codebases, on local disks and in remote repositories.**

PDT scans a local directory or a remote repository, inventories every file, directory and link, analyzes the content with independent, evidence-producing analyzers, and writes JSON, Markdown and offline HTML reports. It does not assume that a project is written in one language or that its documentation describes it accurately, and it never executes, modifies or uploads the code it reads.

> **Status:** 0.2.0 release candidate, with substantial unreleased work on this branch (see the [changelog](CHANGELOG.md)). The open release gates are large-corpus benchmarks, CI on the final head and an independent security review: [AUDIT.md §5](docs/project/AUDIT.md#5-release-gates-that-remain-open).

## Guarantees

- **Read-only, local or remote.** Target code is never imported, executed, compiled or installed, and remote repositories are never modified. A local scan makes no network request: the network is used only for a repository URL and for `--vuln-online`, and every report records which access the scan used. PDT has no telemetry.
- **No silent gaps.** Budgets, parse failures and missing parsers are reported as `UNKNOWN` coverage findings, never as clean results; `--strict` turns them into a failing exit code.
- **Redacted evidence.** Secrets and personal data are reported by category, path and line. Their values are removed from every report format.
- **Safe traversal.** Symlinks are recorded, never followed, and their targets are resolved against the inventory itself. Archives are inspected in memory, never extracted. File reads are verified against the identity recorded at inventory time.
- **Isolated plugins.** Third-party analyzers run in sandboxed host processes on Linux, macOS and Windows: no file writes, network access or process creation.

## Features

| Area | What PDT reports |
|---|---|
| Inventory | Files, directories, symlinks and special entries with sizes, permissions, owners, Windows attributes and macOS file flags, file types and MIME types from content signatures (apart from what names suggest), hidden entries, development and cache trees (with their ecosystem and how sure each marker is), explicit prunes and `--exclude-profile` presets, and `--development-trees` modes, in a resumable SQLite store; `--security-metadata` adds Windows security descriptors or POSIX ACLs |
| Code intelligence | A shared code model (Python syntax tree; a structural lexer for about 25 brace languages, refined by Tree-sitter grammars where provisioned), symbol index, call graph, recursion, unreferenced code, test links and module graph, queried with `pdt query` |
| Security | Secrets in 30+ provider formats, secure-code rules, Python AST checks, and taint from untrusted input to injection, path, SSRF, XSS and redirect sinks (Python across modules); identity and privacy indicators |
| Dependencies | Manifests, lockfiles, installed OS packages (dpkg, apk, rpm), SBOMs and licenses; vulnerability matching against a local advisory snapshot (`--vuln-db`: OSV, NVD, GitHub, Debian, Alpine, CSAF, CycloneDX) or OSV.dev (`--vuln-online`) |
| Services and delivery | API contracts and routes, SQL/NoSQL/ORM schemas and migrations, configuration, network indicators, builds, tests, coverage, CI/CD, containers and deployment |
| Domains | Embedded and firmware, HDL/FPGA with an elaborated design hierarchy, shaders, frontend components, AI/ML including notebooks, ROS, mobile, game engines, accessibility, localization and archives |
| Multi-project | Report comparison, integration maps and a local project catalog |

PDT recognizes 128 languages and formats (81 source languages) and maps 61 optional Tree-sitter grammars. Recognition, parsing and semantic analysis are distinct capability levels; the generated [Capability Matrix](docs/architecture/CAPABILITY_MATRIX.md) gives each language's level and analyzers, and [Analyzer Coverage](docs/architecture/ANALYZER_COVERAGE.md) what each domain covers.

## Installation

Requires Python 3.11 or later.

```bash
python -m pip install -e .            # core
python -m pip install -e ".[all]"     # Tree-sitter, PDF/DOCX, YAML and Zstandard integrations
python -m pip install -e ".[dev]"     # development (then run: pytest)
```

Optional integrations are provisioned by the operator: PDT never downloads parser grammars or installs dependencies during a scan. `pdt capabilities` shows what a host provides.

## Usage

```bash
pdt scan /path/to/project --output /reports/project          # JSON, Markdown and HTML reports
pdt scan /path/to/project --inventory-only                    # metadata only, no content reads
pdt scan /path/to/project --resume                            # continue an interrupted scan
pdt scan /path/to/project --fail-on HIGH --strict --quiet     # CI gate
pdt scan /path/to/project --exclude-dir node_modules --skip --max-file-mb 512
pdt scan /path/to/project --vuln-db ~/.pdt/advisories.sqlite3 # after: pdt vuln-db import SNAPSHOT --db ...
pdt query /reports/project --callers parse_config             # look up the code index
pdt compare a/discovery-report.json b/discovery-report.json   # compare two projects
```

| Exit code | Meaning |
|---|---|
| `0` | Scan completed (findings may exist) |
| `1` | `--fail-on`: a finding at or above the given severity |
| `2` | Invalid usage or a fatal error |
| `3` | `--strict`: the scan is incomplete, or a repository in a URL batch could not be fetched |
| `130` | Interrupted |

The report directory must be outside the scanned project. Every command and option is explained, with examples, in the [CLI Reference](docs/guides/CLI_REFERENCE.md); large-scan practice, resume and performance data are in the [Operations Guide](docs/guides/OPERATIONS.md).

## Remote repositories

Online mode is used only when the target is a repository URL or a `--url` list.

```bash
pdt scan https://github.com/owner/repository --ref v2.1.0     # read-only checkout, deleted after the scan
pdt scan https://github.com/owner/repository --no-download    # provider API, analyzed in memory
pdt scan --url repositories.txt --output /reports/remotes     # one report per repository, plus a summary
```

- **Download mode** checks out one revision read-only into a private temporary directory (Git and nine other VCS backends), runs no hooks, fetches no submodules or LFS objects, and removes the checkout on every exit path.
- **No-download mode** reads GitHub, GitLab, Bitbucket (Cloud and Data Center/Server) and Gitea/Forgejo through their REST APIs within request, file and byte budgets. Nothing is written to disk unless `--no-download-plugins` lets sandboxed plugins read a transient copy.
- Tokens are bound to their host (`PDT_API_TOKEN_<HOST>`, or the provider's standard variable) and never logged. Content that could not be fetched is reported as an `UNKNOWN` coverage gap.

Details: [Online Mode guide](docs/guides/ONLINE_MODE.md).

## Reports

- **JSON** (schema 1.22): every finding, file record and metric, streamed for large scans.
- **Markdown:** summaries, the scan source and findings with evidence, impact and remediation.
- **HTML:** a standalone offline report with search, filters, pagination and collapsible findings; it loads no remote assets.

Each finding carries a confidence level:

- **CONFIRMED:** supported directly by source, metadata, manifest or parser evidence.
- **INFERRED:** a heuristic observation that needs review.
- **UNKNOWN:** not determined, because input could not be parsed, a parser is missing or a resource limit was reached.

Security findings add the source line, a redacted excerpt, the conditional impact and a recommendation. A static finding is evidence, not proof that code is reachable or exploitable.

## Scale and execution

- SQLite-backed inventory, findings and code facts, written in bounded batches with checkpoints for `--resume`.
- A multi-process engine (`--executor`, `--jobs`) with worker-crash isolation, read-once file prefetch and deterministic results.
- Native components with Python fallbacks: a Rust no-follow walker, a C++ signature classifier, C/SIMD byte counting (x86-64 assembly on Linux) and an opt-in OpenCL GPU path for large buffers (`--gpu`; slower than the CPU on the hardware measured so far).
- Per-analyzer byte, entry, time, memory, CPU and read budgets, and a whole-scan memory budget: [Analyzer Resource Budgets](docs/architecture/ANALYZER_RESOURCE_BUDGETS.md).

The 2 GB to 100 GB+ benchmarks await representative corpora, so the memory model is not yet certified for the largest targets ([Benchmarks](docs/guides/BENCHMARKS.md)).

## Plugins

Third-party analyzers are Python entry points in the `pdt.analyzers` group. They run sandboxed by default (`--plugin-isolation sandbox|process|off`) with per-plugin time and memory limits, and `pdt plugin-check` tests a plugin the way scans load it. See the [Plugin SDK](docs/guides/PLUGIN_SDK.md).

## Repository layout

```text
src/project_discovery/
  cli.py             command-line interface and scan orchestration
  models.py          report data model (Finding, FileRecord, ScanResult)
  inventory/         no-follow filesystem walker, SQLite inventory store, fingerprint cache
  engine/            bounded process/thread executor, native backends, runtime telemetry
  analyzers/         built-in analyzers by domain, the plugin base class and the registry
  intelligence/      shared code model, code facts, cross-file code index, project graphs
  vulnerabilities/   local advisory database, format adapters, ecosystem version ordering, CVSS
  plugins/           plugin isolation policy, sandboxed hosts and their protocol
  online/            URL targets, read-only checkouts, provider APIs, online advisory sources
  reporting/         JSON, Markdown and HTML writers; the offline HTML client in web/
  projects/          multi-project comparison, integration maps, local project catalog
  catalog/           language and analyzer-domain capability catalogs
  core/              verified reads, redaction, safe parsers, credential registry
  data/              bundled data (IANA top-level domain list)
native/              C, C++, x86-64 assembly and Rust sources of the optional native extensions
tests/               pytest suite, laid out like the package
docs/                architecture, analyzer, guide and project documents
tools/               benchmark corpus generator and runner
```

Plugins depend only on `project_discovery.analyzers.base` and `project_discovery.models`, whose paths are stable.

## Documentation

[Documentation index](docs/README.md) · [Roadmap](docs/project/ROADMAP.md) · [Audit and defect register](docs/project/AUDIT.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

This branch is unmerged; only the repository owner decides when it is merged.
