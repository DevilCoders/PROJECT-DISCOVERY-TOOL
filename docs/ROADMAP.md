# Roadmap

## Mission and non-negotiable scope

PDT is a local-first, read-only, comprehensive polyglot project intelligence system. It must analyze heterogeneous repositories from a few GB to 100GB+ without assuming a single language, framework, OS, build system, architecture, or deployment model.

The tool must inventory first, analyze second, and report evidence third. It must not silently omit files, symlinks, hidden entries, directories, archives, development dependency trees, or oversized files. Any exclusion or resource limit must be explicit, observable, and represented in the report.

Language and analyzer catalogs are coverage contracts. The presence of a language or domain in a catalog is not proof of parser support or completed semantic analysis. Every adapter must declare its capability level and uncertainty.

## Current implementation baseline

The current branch contains an initial Python-based orchestration/scanner, Rich CLI, SQLite cache, reporting pipeline, plugin API, 40+ language recognition, 60+ optional Tree-sitter grammar mappings, and initial analyzer families for dependencies, documentation, configuration, security, APIs, SQL/NoSQL, ORM/migrations, tests/build/CI/CD, deployment, AI/ML, ROS, mobile, game engines, frontend/accessibility, localization, observability, coverage, and multi-project comparison.

These are initial implementations of varying depth. Production readiness is not implied. Keep the full current tests and CI matrix green as each feature is added.

## Phase 0 — Documentation and release contract

- [x] Update root README to describe the complete local-first/polyglot scope, privacy boundaries, report UX requirements, and pre-production status.
- [x] Update this roadmap before feature implementation.
- [ ] Keep README feature claims synchronized with tested implementations; mark partial capability honestly.
- [ ] Maintain a capability matrix by language, format, analyzer domain, confidence behavior, parser dependency, and fixture coverage.

## Phase 1 — Filesystem inventory and resource model

- [ ] Replace lossy file-only discovery with a typed entry inventory: regular files, directories, symlinks, and special filesystem entries.
- [ ] Record symlinks without following them: link path, target text (with report-safe handling), target scope (relative/internal/external/unknown), and link metadata.
- [ ] Detect hidden files/directories on POSIX and Windows, including dotfiles and Windows hidden attributes where available.
- [ ] Detect file type using filename/extension plus bounded signature inspection; distinguish text, source, configuration, document, archive, executable, shared library, image, audio, video, model, dataset, firmware and unknown binary.
- [ ] Add file-size buckets and per-extension/per-language/per-directory size summaries; retain exact size in bytes.
- [ ] Add directory inventory: depth, child counts, aggregate file counts/bytes, empty directories, large fan-out and largest subtrees.
- [ ] Detect development dependency/generated/cache trees including `node_modules`, `.cache`, `.yarn`, `.pnpm-store`, `.npm`, `.gradle`, `.m2`, `.venv`, `vendor`, `target`, IDE indexes, compiler outputs, fuzz corpora and ecosystem-specific stores.
- [ ] Do not silently prune dependency trees by default. Provide explicit tree exclusion/deep-analysis controls and always report detected skipped/excluded trees.
- [ ] Make oversized-file skipping opt-in through `pdt scan PATH --skip`; default scanning must not globally skip oversized files. Add configurable thresholds and analyzer-specific resource-limit diagnostics.
- [ ] Preserve the read-only guarantee, deterministic ordering, per-entry error isolation, and no-follow symlink behavior.
- [ ] Add filesystem tests for permissions, broken links, external links, loops, hidden paths, special files, Windows attributes, unreadable paths, deep nesting and huge fan-out.

## Phase 2 — Large-repository engine and native acceleration

- [ ] Convert file discovery to bounded-memory, streaming iteration; avoid materializing every file's full content or an unbounded in-memory work queue.
- [ ] Add configurable concurrency, bounded queues, back-pressure, cancellation, progress phases and resumable checkpoints.
- [ ] Stream hashing and regex-oriented scanning; make parser-specific memory/time budgets explicit.
- [ ] Add incremental cache invalidation using stable file identity and metadata with safe fallbacks on platforms lacking inode/ctime semantics.
- [ ] Build repeatable benchmarks for 2GB, 10GB, 50GB and 100GB synthetic/representative repositories; measure wall time, peak RSS, throughput, cache hit rate and report generation memory.
- [ ] Implement a Rust native walker/indexer only where benchmarks demonstrate a bottleneck; expose a stable interface and retain a portable fallback.
- [ ] Use C only for a narrow measured interoperability/hot-path requirement. Consider assembly only after profiling demonstrates a meaningful architecture-specific win. No decorative low-level code.
- [ ] Stress test concurrent scans, cancellation, cache corruption, network filesystems, huge directories and changing files.

## Phase 3 — Archives and artifact intelligence

- [ ] Detect archives through both extension and signatures: ZIP, JAR/WAR/EAR, APK/AAB, IPA, TAR, TAR.GZ, TGZ, TAR.BZ2, TAR.XZ, GZIP, BZIP2, XZ, 7z, RAR, CAB, ISO, Zstandard and other common containers.
- [ ] Inspect archive central directories or metadata indexes without extracting members to disk.
- [ ] Record archive member paths, types, uncompressed/compressed sizes, compression ratio, CRC metadata, timestamps, permissions, ownership metadata and encryption indicators where formats expose them.
- [ ] Detect symlink and hardlink entries, absolute paths, drive-prefixed paths, parent traversal, duplicate names, special devices/FIFOs and suspicious path normalization.
- [ ] Add configurable archive entry-count, metadata-size, nesting-depth, parsing-time and compression-ratio limits to resist archive bombs.
- [ ] Distinguish metadata-only support from format-specific content inspection. Never claim to have inspected compressed member payloads unless a bounded in-memory streaming path actually did so.
- [ ] Add fixtures for malformed, encrypted, nested, huge, truncated, malicious-path and symlink archives.

## Phase 4 — Network, API and OS intelligence

- [ ] Detect IPv4/IPv6 literals, CIDR ranges, ports, host:port pairs, listen/bind/connect calls, socket types and common network protocol references.
- [ ] Detect URLs and URIs across source, config, documents and manifests; normalize schemes and redact userinfo, query tokens and credential-like URL components.
- [ ] Detect hostnames, FQDNs, domains and subdomains; distinguish literal domains from templates/placeholders and avoid presenting public reachability conclusions.
- [ ] Expand API endpoint discovery across source languages/frameworks: REST methods/routes, GraphQL operations, gRPC/RPC, WebSocket, SOAP, event APIs, generated clients and route middleware.
- [ ] Build static API inventories and code-to-contract cross references with CONFIRMED/INFERRED/UNKNOWN semantics.
- [ ] Detect host OS separately from inferred target OS. Use platform manifests, package managers, shells, service definitions, CI matrices, sysroots, cross toolchains and deployment manifests.
- [ ] Add tests for IPv4/IPv6 edge cases, IPv4-mapped IPv6, ports, URL userinfo, internationalized domains, subdomains, templated hosts and false-positive-heavy source text.

## Phase 5 — Security, secrets and personal-data indicators

- [ ] Expand secret detection across source/config/docs/build files and 40+ language syntaxes: passwords, passphrases, API keys, cloud credentials, tokens, JWTs, private keys, certificates, database credentials, signing material and service-account files.
- [ ] Detect identity/PII field names and values: first name, given name, middle name, last name, surname, username, email, phone, address, account/user IDs and related records.
- [ ] Treat field-name recognition as metadata evidence; treat value-shaped matches as heuristic PII indicators. Never copy full raw credential/PII values into findings.
- [ ] Add redaction, keyed local fingerprints where appropriate, false-positive suppression and context-aware confidence.
- [ ] Expand secure-code analysis for injection, command execution, path traversal, SSRF, unsafe deserialization, authn/authz, cryptography, TLS, insecure randomness, data exposure, cloud/IaC, containers, CI/CD and supply-chain weaknesses.
- [ ] Never claim exploitability from a lexical match. Add severity, evidence, remediation context and dataflow path only when traceable.
- [ ] Add regression corpus for secret formats, PII edge cases, encoded values, multiline keys, false positives and report redaction.

## Phase 6 — Polyglot analyzer coverage (40+ languages)

- [ ] Maintain language packs for 40+ actual source languages, including mainstream, legacy, scientific, functional, scripting, mobile, game, embedded, HDL, GPU and smart-contract ecosystems.
- [ ] For each pack, support declarations, imports/exports, module resolution, types, call sites, common framework APIs and test/build patterns to the depth claimed in its capability metadata.
- [ ] Build ecosystem fixture repositories for mixed-language and monorepo configurations.
- [ ] Expand security/configuration/API/database/ORM/messaging/test/build analyzers across languages rather than shipping language-name-only adapters.
- [ ] Cover SQL, NoSQL, graph, search, time-series, vector databases, ORMs, migrations, schema registries and data-pipeline formats.
- [ ] Cover REST, GraphQL, RPC/gRPC, SOAP/WSDL, WebSocket, event/messaging, OpenAPI/AsyncAPI/OpenRPC, API collections and generated clients.
- [ ] Cover build systems and toolchains across native, managed, scripting, mobile, game, embedded, FPGA, GPU and robotics workspaces.
- [ ] Add analyzer conformance tests, parser-version fixtures, graceful optional dependency behavior and explicit unsupported-feature reporting.

## Phase 7 — Comprehensive reports and terminal experience

- [ ] Extend the report schema for entries/directories, symlinks, hidden entries, file types, size buckets, dependency trees, OS indicators, network endpoints, secrets/PII, archives and archive-member risks.
- [ ] Add dashboard metrics, largest files/directories, file-type/extension/language distributions, directory tree summaries and analysis coverage/skip diagnostics.
- [ ] Redesign HTML as a polished offline dark command-center UI with responsive navigation and summary dashboards.
- [ ] Add global search and category/severity/confidence filters; lazy-render or paginate large finding groups.
- [ ] Add working open-all/close-all controls, per-category expand/collapse, evidence details, copy-safe redacted identifiers and stable anchor navigation.
- [ ] Ensure huge reports do not create thousands of initially expanded DOM nodes; validate with 100k+ synthetic findings.
- [ ] Redesign terminal output with an ASCII banner, phase panels, live progress, grouped findings, status taxonomy and compact summary. Clear screen only for interactive TTY sessions; keep redirected output deterministic.
- [ ] Add terminal accessibility, color/no-color mode, narrow terminal tests and CI log readability.

## Phase 8 — Project architecture and intelligence depth

- [ ] Expand cross-language symbol/module graphs, API/dataflow links and architecture boundary detection.
- [ ] Cross-reference documentation claims to implementation evidence without treating docs as proof.
- [ ] Expand ML/AI architecture, model metadata, tokenizer/config, training/inference, datasets and accelerator analysis without deserializing untrusted model payloads.
- [ ] Expand ROS 1/ROS 2 packages, nodes, topics, services, actions, launch compositions, QoS and message/interface relationships.
- [ ] Expand game engine, mobile, embedded, firmware, FPGA/HDL, GPU, observability, accessibility, localization and asset intelligence.
- [ ] Compare independent project reports for overlaps, dependencies, complementary capabilities, conflicts and integration opportunities without merging repository identities.

## Phase 9 — Production quality and release

- [ ] Full cross-platform CI matrix for supported OS/Python versions and native builds.
- [ ] Coverage gates plus focused regression/negative tests for every analyzer and format.
- [ ] Reproducible wheel/sdist build, package metadata checks, clean installation and CLI smoke tests.
- [ ] Security review of parsers, archive handling, plugins, output encoding, symlink races and path handling.
- [ ] Performance and peak-memory budgets for large repositories and large report output.
- [ ] Offline behavior, read-only guarantees, privacy/redaction and cache/report safety verified.
- [ ] Plugin SDK, analyzer contract versioning, compatibility policy and third-party fixture suite.
- [ ] Release notes, support matrix, threat model, architecture guide, benchmark report and production operations documentation.

## Release gate

PDT is not production-ready until all mandatory phases have accepted implementations and passing tests, all partial/planned capability states are documented, cross-platform CI is green on the final head commit, large-repository benchmarks meet declared resource budgets, reports remain usable at 100k+ findings, and security/privacy/read-only/offline guarantees are verified.

The feature branch and PR remain unmerged. Only the repository owner decides when the production-ready PR is merged into `master`.
