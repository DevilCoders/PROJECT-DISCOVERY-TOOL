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

- [x] Replace lossy file-only discovery with separate regular-file, directory and symlink records; special entries are currently counted by type but do not yet have full per-entry records.
- [x] Record symlinks without following them: link path, target text, lexical target scope (internal/external/unknown), hidden flag and mode metadata.
- [x] Detect hidden files/directories on POSIX and Windows, including dotfiles and Windows hidden attributes where available.
- [ ] Expand the initial bounded signature/MIME classifier into a complete artifact taxonomy for source, configuration, documents, archives, executables/shared libraries, images/audio/video, model/dataset, firmware and unknown binary formats.
- [x] Add file-size buckets, exact size in bytes and per-directory aggregate bytes; add richer per-extension/per-language size summaries.
- [x] Add directory inventory: depth, direct child counts, aggregate file counts/bytes and hidden state; add empty-directory and large-fan-out scoring.
- [x] Detect initial development dependency/generated/cache tree markers including `node_modules`, `.cache`, `.yarn`, `.pnpm-store`, `.npm`, `.gradle`, `.m2`, `.venv`, `vendor`, `target`, IDE indexes, compiler outputs, fuzz corpora and ecosystem-specific stores.
- [ ] Do not silently prune dependency trees by default. Provide explicit tree exclusion/deep-analysis controls and always report detected skipped/excluded trees.
- [x] Make oversized-file skipping opt-in through `pdt scan PATH --skip`; default scanning does not globally skip oversized files. Initial Python AST analyzers and the Python dependency graph report `UNKNOWN` when their independent 16 MiB parser budget is exceeded. Expand per-analyzer budgets and reporting.
- [x] Preserve the read-only guarantee, deterministic ordering, per-entry error isolation, and no-follow symlink behavior.
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

- [x] Detect IPv4/IPv6 literals, CIDR ranges, common port declarations, URL ports, host:port pairs and common network protocol references; expand socket API, bind/listen/connect extraction.
- [x] Detect URLs/URIs in recognized text/source/config files; evidence redacts userinfo, paths, query tokens and fragments.
- [x] Detect hostname/FQDN/domain candidates and probable subdomains without DNS queries; improve template and public-suffix false-positive handling.
- [x] Add initial source endpoint patterns and API-style classification for REST, GraphQL, gRPC/protobuf, JSON-RPC, SOAP/WSDL, WebSocket and event-driven APIs. Expand API endpoint discovery across source languages/frameworks: REST methods/routes, GraphQL operations, gRPC/RPC, WebSocket, SOAP, event APIs, generated clients and route middleware.
- [ ] Build static API inventories and code-to-contract cross references with CONFIRMED/INFERRED/UNKNOWN semantics.
- [x] Add host OS metadata and initial inferred target-OS markers from text/config/build files; expand platform manifests, package managers, shells, service definitions, sysroots and cross-toolchains.
- [ ] Add tests for IPv4/IPv6 edge cases, IPv4-mapped IPv6, ports, URL userinfo, internationalized domains, subdomains, templated hosts and false-positive-heavy source text.

## Phase 5 — Security, secrets and personal-data indicators

- [ ] Expand secret detection across source/config/docs/build files and 40+ language syntaxes: passwords, passphrases, API keys, cloud credentials, tokens, JWTs, private keys, certificates, database credentials, signing material and service-account files.
- [ ] Detect identity/PII field names and values: first name, given name, middle name, last name, surname, username, email, phone, address, account/user IDs and related records.
- [ ] Treat field-name recognition as metadata evidence; treat value-shaped matches as heuristic PII indicators. Never copy full raw credential/PII values into findings.
- [x] Add initial value redaction for PII and secret field-name findings. Add keyed local fingerprints, false-positive suppression and context-aware confidence.
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
- [x] Add an initial offline dark command-center HTML design with responsive navigation and summary dashboards; continue visual polish and accessibility validation.
- [x] Add global finding search and category/severity/confidence filters with 100-item client-side finding pages; improve search indexing for very large data.
- [x] Add working open-all/close-all controls for rendered findings, per-finding collapse, evidence details and stable section navigation; add per-category expand/collapse.
- [x] Ensure the report does not eagerly create a DOM node for every finding; validate and optimize with 100k+ synthetic findings.
- [x] Add an ASCII banner, phase progress and compact summary; clear screen only for interactive TTY sessions. Continue advanced terminal panels, theme controls and grouped status taxonomy.
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
