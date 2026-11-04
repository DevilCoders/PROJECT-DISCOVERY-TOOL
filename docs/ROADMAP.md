# Production Roadmap

## Mission

PROJECT DISCOVERY TOOL (PDT) is a local-first, read-only, comprehensive polyglot project intelligence platform. It must discover the actual contents and structure of heterogeneous codebases—from multi-gigabyte repositories through 100GB+ workspaces—without assuming one programming language, one framework, one operating system, one architecture, or one deployment model.

The pipeline is:

1. **Inventory:** account for filesystem entries and project artifacts.
2. **Analyze:** run independent language/domain analyzers against bounded inputs.
3. **Correlate:** connect evidence across files, APIs, dependencies, build systems and projects.
4. **Report:** produce comprehensive offline JSON/Markdown/HTML and a focused terminal experience.

No scan may silently omit an entry. Exclusions, parser gaps, budget limits, unsupported archive formats and errors must be represented in the results.

## Release rules

- Work only on `feat/discovery-engine-foundation` and PR #1.
- Never merge into `master`; do not close the PR as complete until release gates pass.
- Keep all proprietary project data local. Only publish PDT implementation, tests and public documentation.
- Target repositories are read-only. Never follow symlinks during traversal, write inside targets, execute code/build scripts, extract archive members, or contact discovered endpoints.
- Findings must include evidence and confidence. A lexical marker is never presented as proof of exploitability, reachability, deployment, user identity or runtime behavior.
- Catalog entries and parser mappings are not completed capabilities. Every capability status must be truthful and test-backed.

## Capability-state definitions

| State | Meaning |
|---|---|
| `recognized` | File extension/name/signature is classified. No semantic support implied. |
| `parser_mapped` | A parser adapter/grammar mapping exists. |
| `parser_available` | Required parser is provisioned locally. |
| `parsed` | Input parsed successfully within documented limits. |
| `partial` | Useful evidence extraction exists but substantial domain coverage is missing. |
| `implemented` | Declared scope has conformance fixtures and accepted behavior. |
| `unknown` | Analysis unavailable, inconclusive or stopped by a resource budget. |
| `excluded` / `skipped` | Content was intentionally omitted with a recorded reason. |

## Current branch baseline

The current feature branch has first-pass implementations for filesystem inventory, symlink records, hidden-name markers, directory aggregates, size buckets, common development-directory markers, SQLite fingerprints, Python AST/import graph, language recognition and optional Tree-sitter support. It also contains initial analyzers for documentation, dependencies/licenses, configuration, secrets/PII, secure-code patterns, REST/API contracts and route markers, SQL/NoSQL/ORM/migrations, test/build/CI, containers/deployment/IaC, archives, network indicators, OS/platform markers, ML/AI, ROS, mobile, game engines, frontend/accessibility, localization, observability, coverage and multi-project comparison.

The baseline is not production-ready:
- file, symlink and special-entry records now use lazy SQLite-backed sequences in store-backed CLI scans; directory metadata/maps, active directory depth, analyzer findings and result metrics still have in-memory structures;
- all development/cache/build trees are traversed by default and only explicitly excluded subtrees are pruned;
- C++ now provides first-pass magic-byte classification for common archive, executable, document, database, image, audio/video and font formats; the signature catalog is not exhaustive;
- FIFO/socket/device/unknown special entries have inventory records;
- Windows hidden attributes are captured by the native walker and Python fallback, but system attributes, ACLs and ownership metadata still need cross-platform validation;
- archive index inspection is substantive only for ZIP/TAR; other recognized formats are detection-only;
- ZIP central-directory preflight, archive entry-count/member-byte caps and cooperative ZIP/TAR wall-time budgets now exist; nested-depth, configurable budget policies, comprehensive metadata bounds and adversarial testing remain;
- some domain analyzers are lexical/heuristic and do not yet resolve symbols, types, dataflow or framework semantics;
- report and CLI have a working first-pass command-center design, but still need completeness, scale, accessibility and usability gates.

## Phase 0 — Documentation and capability governance

- [x] Refresh root README with current capabilities, limitations, privacy policy, CLI and production criteria.
- [x] Refresh this roadmap before the next implementation block.
- [ ] Maintain a generated language/domain capability matrix: status, parser, optional dependency, supported syntax, limitations and fixtures.
- [ ] Ensure README/roadmap claims are generated or reviewed against the analyzer registry and tests.
- [ ] Add release-note and change-log discipline for feature, schema and plugin API changes.

## Phase 1 — Filesystem inventory correctness

### Entry model
- [x] Separate file, directory and symlink records.
- [x] Record symlink target text, lexical scope and link permissions without traversing the target.
- [x] Record hidden-name indicators for dotfiles/directories.
- [x] Record Windows hidden attributes in the Rust walker and Python fallback.
- [ ] Record Windows system attributes, ACLs and platform-specific ownership metadata.
- [ ] Add full records for FIFO, socket, block device, character device, junction/reparse point and unknown entry types.
- [ ] Add broken-link, self-link, cyclic-link, dangling-relative-link and external-target fixtures.
- [ ] Harden symlink target classification against loops, permission failures, path races and platform-specific resolution behavior.
- [x] Record directory depth, child counts, aggregate regular-file counts/bytes, marker and pruned state.
- [ ] Add empty-directory, fan-out, inode/owner/group and timestamp aggregates where supported.
- [x] Record per-file byte size, extension, language label, hidden-name flag, mode and size bucket.
- [ ] Add robust file signature/MIME detection for executables, libraries, images, audio/video, documents, archives, model/dataset files, firmware and unknown binaries.
- [ ] Keep extension-based recognition distinct from verified magic-byte detection.

### Development and generated dependency trees
- [x] Initial marker catalog for `node_modules`, `.cache`, `.yarn`, `.pnpm-store`, `.npm`, `.gradle`, `.m2`, `.venv`, `vendor`, build outputs and other common workspaces.
- [ ] Remove implicit default pruning of dependency/build/cache trees.
- [ ] Traverse all recognized trees by default unless the operator explicitly opts out or a documented safety policy marks an entry unknown.
- [ ] Add `--exclude-dir NAME` and optional profile presets; retain a directory record and exact exclusion reason for every pruned subtree.
- [ ] Add optional directory-only / inventory-only / deep-analysis controls with explicit semantics.
- [ ] Extend markers for pnpm/npm/yarn/bun, pip/uv/poetry/conda, Maven/Gradle, Cargo, Go modules, NuGet, Composer, Ruby/Bundler, SwiftPM/CocoaPods, Dart/Flutter, .NET, Bazel/Buck/Pants, SCons, CMake, IDE, compiler, fuzzing, model caches and language server caches.
- [ ] Add marker confidence and distinguish known dependency stores from arbitrary directories with similar names.

### Oversized files
- [x] Global oversized-file content skipping is opt-in through `pdt scan PATH --skip`.
- [x] Keep all oversized files in inventory when `--skip` is active.
- [ ] Ensure `--skip` is the only global size threshold gate; default scanning must not silently skip content based only on size.
- [ ] Give every analyzer a documented per-file byte/time/memory budget and an explicit `UNKNOWN`/partial result when it cannot continue.
- [ ] Support per-domain override budgets and show them in JSON/HTML/terminal reports.
- [ ] Test 128MiB, 1GiB, sparse, changing and non-seekable files without unbounded memory use.

## Phase 2 — High-throughput engine for 2GB–100GB+

### Per-analyzer resource governance

- [ ] Centralize per-analyzer limits into a policy object and add configured/consumed byte, time and stop-reason telemetry for all report formats.


### Bounded thread-pool concurrency and C/OpenCL GPU execution (new release gate)
- [x] Add bounded concurrent thread-pool file-analysis scheduling with configurable worker count, back-pressure and deterministic result ordering; keep SQLite cache operations on the coordinator thread.
- [x] Stream Python fallback `os.scandir` entries directly without allocating and sorting a second per-directory entry list; retain deterministic ordering at the public inventory boundary and cover it with regression tests.
- [x] Add `pdt scan --jobs N` and `--jobs 0` auto-sizing; expose selected worker count and queue limits in scan metrics and every report format.
- [x] Extend the C extension with runtime OpenCL loader/device discovery without requiring GPU SDK headers or a GPU at build time.
- [x] Implement a bounded C/OpenCL byte-count/reduction kernel for large immutable byte buffers; dispatch to an available GPU only above a configured threshold and only for supported kernels. Device-specific threshold benchmarking remains open.
- [x] Fall back to portable C/SIMD/Python on missing OpenCL loader, no GPU device, unknown/insufficient device memory limits, kernel/build/dispatch failure, unsupported platforms or small workloads. GPU absence must never fail a scan.
- [x] Restrict GIL-releasing GPU reads to immutable bytes; mutable bytearray and other buffer exporters stay on the GIL-held CPU path.
- [x] Report GPU vendor/device/compute units/memory, threshold, actual dispatch counts and fallback counts without exposing device-specific private data. Detailed per-failure reason telemetry remains open.
- [ ] Add fake/no-device and kernel-failure tests plus hardware-backed GPU-present, threshold and fault-injection runs; benchmark GPU versus CPU and tune the default threshold. Current CI covers large-buffer CPU-equivalence, concurrent calls and safe mutable-buffer fallback; it does not provision a GPU.
- [x] Keep GPU scope explicit: analyzer semantics remain CPU-side unless a specific C/OpenCL kernel is implemented and validated.


- [ ] Replace remaining in-memory directory metadata/maps and findings with bounded store-backed structures and bounded producer/consumer queues. File, symlink and special-entry records already use lazy SQLite-backed sequences in store-backed CLI scans; Python fallback traversal now keeps only active directory iterators (O(depth)), not a pending list of sibling directory paths.
- [x] Add a bounded-batch SQLite `InventoryStore` primitive with deterministic streaming reads, atomic resumable metadata checkpoints, SQLite integrity checks, explicit close semantics, private POSIX file permissions and symlink-path rejection.
- [ ] Move all remaining inventory/result collections and report assembly onto store-backed streaming iterators. **Partial integration (2026-11-04):** CLI scans persist file, directory, symlink and special-entry records through bounded SQLite batches with running/complete/partial checkpoints, final directory aggregates and integrity telemetry. File records are rehydrated lazily through a typed `StoredFileRecords` sequence; symlink and special-entry records use typed `StoredRecordSequence` instances. All three use case-folded path ordering with exact-path tie-breaks, while private file identity remains in storage and excluded from public serialization. The Python fallback now keeps only active `os.scandir` iterators on a depth-proportional stack rather than retaining pending sibling-directory paths. JSON and HTML array serialization and Markdown output iterate records incrementally. Directory maps/lists, findings, graph state and report metrics still materialize; the browser still receives a single embedded report payload. Full bounded-memory analysis/rendering, findings persistence, cancellation and restartable scan recovery remain OPEN.
- [ ] Implement bounded concurrency, work stealing only if justified, back-pressure, cancellation and resumable checkpoints.
- [ ] Stream SHA-256 and content scanning; avoid repeated passes when analyzers can share a bounded decoded stream safely.
- [ ] Add content fingerprint cache with metadata validation, file identity where reliable, stale-entry pruning and corruption recovery.
- [ ] Separate metadata-only inventory from content analyzers so the same file is not read repeatedly without purpose.
- [ ] Add configurable CPU, memory, I/O and per-analyzer budgets.
- [ ] Make progress phase-based: inventory, hashing, analyzer domains, archive inspection, correlation, reporting.
- [x] Implement portable C byte counting and host capability reporting, used by streaming secret analysis.
- [x] Implement a C++17 magic-byte signature classifier used by scanner file-type detection.
- [x] Implement Linux x86-64 SIMD Assembly byte counting with runtime SSE2/POPCNT detection and scalar C/Python fallbacks.
- [x] Implement and integrate the C++17 native file-signature classifier with Python fallback.
- [x] Extract the offline report client into a packaged JavaScript source asset bundled into standalone HTML.
- [x] Use cursor-based bounded DOM pagination for file inventory and findings without allocating full filtered-match arrays.
- [x] Implement and integrate the Rust PyO3 no-follow directory iterator with native metadata and bounded active-directory state.
- [ ] Replace in-memory inventory/results with persistent streaming index storage, bounded analyzer queues and resumable checkpoints.
- [ ] Cross-compile/test native modules on Linux, Windows and macOS; fuzz FFI boundaries and test graceful fallback.
- [ ] Benchmark 2GB, 10GB, 50GB and 100GB+ corpora with varied file counts/sizes, deep trees, large dependency directories, archives and symlink-heavy layouts.
- [ ] Publish wall time, files/sec, bytes/sec, cache hit rate, peak RSS, CPU, I/O, archive budgets and report-generation memory.

## Phase 3 — Archives and content without extraction

- [x] Recognize common archive/package extensions and ZIP/TAR signatures.
- [x] Inspect ZIP central directory and TAR member metadata without writing files to disk.
- [x] Record member path/name/type, timestamps, modes/permissions, compressed/uncompressed sizes, duplicate names, encryption and link/special-entry indicators where available.
- [x] Detect absolute paths, drive-prefixed paths, parent traversal, ZIP symlinks and TAR symlink/hardlink/device entries.
- [x] Perform bounded in-memory content samples for ZIP/TAR members with redacted secret/PII indicators.
- [ ] Make archive inspection states explicit: detected, index-read, metadata-complete, sample-read, sample-truncated, encrypted, unsupported, malformed, budget-stopped.
- [x] Refuse ZIP index materialization when EOCD/ZIP64 preflight cannot establish bounded central-directory limits; return UNKNOWN instead.
- [x] Enforce a per-archive wall-time budget during ZIP/TAR metadata traversal and bounded member sampling; time stops produce UNKNOWN findings.
- [ ] Make archive byte, entry, nested-depth, total-uncompressed-byte, per-member sample, total-sample, compression-ratio and wall-time budgets configurable per scan/domain; current ZIP/TAR limits are fixed safety defaults.
- [ ] Validate ZIP data descriptors, ZIP64, encrypted members, duplicate/case-colliding paths, Unicode path normalization and truncated directories.
- [ ] Add safe metadata readers for 7z, RAR, CAB, ISO, Zstandard, DEB/RPM and language package formats through optional offline dependencies where appropriate.
- [ ] No archive backend may extract members to disk or follow archive links.
- [ ] Add malicious fixture set: archive bombs, high-ratio entries, nested bombs, malformed headers, encrypted archives, path traversal, absolute paths, hardlinks, symlink loops, sparse TAR, huge entry counts and corrupt checksums.
- [ ] Report every archive budget hit, per-archive member/content coverage percentage and which limits prevented deeper inspection.

## Phase 4 — Network and endpoint intelligence

### Network and identifiers
- [x] IPv4 and IPv6 literal patterns with IP validation.
- [x] IPv4/IPv6 CIDR candidates with IP-network validation.
- [x] Port declarations, host:port strings, URL ports and common service-port labels.
- [x] URL/URI schemes and evidence redaction for userinfo, path, query and fragment.
- [x] FQDN/domain and probable subdomain candidates without DNS requests.
- [x] Common HTTP, WebSocket, gRPC, GraphQL, SOAP, MQTT, AMQP, Kafka, SSH and DNS markers.
- [ ] Add IPv4-mapped IPv6, zone-scoped IPv6, bracketed literals, URL edge cases, Unicode/IDNA domains and public-suffix-aware subdomain classification.
- [ ] Detect listen/bind/connect/accept/socket creation APIs and distinguish declaration/configuration from code call sites.
- [ ] Correlate host, address, port, protocol and service declarations across Docker, Kubernetes, Compose, Terraform and source code.
- [ ] Keep all network discovery passive: no DNS, scanning, probing or connection attempts.

### API types, contracts and endpoints
- [x] API-style classification for REST, GraphQL, gRPC/protobuf, JSON-RPC, SOAP/WSDL, WebSocket, event-driven APIs and webhooks.
- [x] Contract inventory for selected OpenAPI, GraphQL, protobuf, Thrift and API schema formats.
- [x] Initial source endpoint recognition in selected frameworks/languages.
- [ ] Expand endpoint adapters across Python, JS/TS, Go, Java/Kotlin, C#, PHP, Ruby, Rust, Swift, Dart and other supported languages.
- [ ] Resolve REST method/path/decorator/annotation/attribute and framework router registration patterns.
- [ ] Discover GraphQL schemas, operations, resolvers, directives, federation and subscriptions.
- [ ] Discover gRPC services, methods, protobuf messages, RPC frameworks and generated clients.
- [ ] Discover JSON-RPC, SOAP/WSDL, WebSocket, SSE, webhook, AsyncAPI, OpenRPC, MQTT and message-driven endpoints.
- [ ] Cross-reference source route handlers to API contracts and generated clients.
- [ ] Detect auth middleware, versioning, rate-limit and validation declarations where evidence exists.
- [ ] Build endpoint catalog with method, path, framework, handler symbol, contract, auth marker, source evidence and confidence. Never imply reachability.

## Phase 5 — VCS, source hosting and delivery-provider intelligence

- [x] Detect Git checkout metadata through .git directories and .git pointer files used by worktrees/submodules.
- [x] Inspect Git remotes and fingerprint GitHub, GitLab, Bitbucket, Azure Repos, AWS CodeCommit, Google Cloud Source Repositories, SourceHut and selected self-hosted hosts.
- [x] Detect Git HEAD references, detached HEAD, shallow clone boundaries, packed refs, branch config sections, submodule declarations and Git LFS rules.
- [x] Add initial Mercurial, Subversion, Bazaar, Darcs, Jujutsu, Pijul, CVS and Perforce metadata markers.
- [x] Detect GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, Jenkins, CircleCI, Buildkite, Travis, Drone, Woodpecker and AppVeyor definitions.
- [x] Detect AWS CodeBuild/CodeDeploy/CDK/SAM, Google Cloud Build, Firebase and selected deployment markers.
- [ ] Deeply decode SVN working-copy SQLite metadata, Mercurial revlogs, specialized Jujutsu/Pijul layouts and Perforce workspaces.
- [ ] Add configurable provider fingerprints for GitHub Enterprise, GitLab self-managed, Bitbucket Data Center, Azure DevOps Server, Gitea/Forgejo, Gerrit and Gitolite.
- [ ] Correlate remotes, submodules, package registries, CI workflows and cloud deployment manifests into a provenance graph.
- [ ] Add bare repositories, worktrees, nested repositories, detached/shallow clones, multiple remotes, malformed metadata and credential-bearing remote URL fixtures.
- [ ] Verify credentials/query/fragment redaction across every report/output path.
- [ ] Keep analysis offline: no VCS command execution, ref fetching, host lookup or provider API requests.

## Phase 6 — Local vulnerability intelligence

- [x] Add a local SQLite advisory store with explicit OSV JSON import and coverage/status reporting.
- [x] Import advisories from a local JSON file or directory tree; do not download, update or contact advisory providers.
- [x] Match resolved package/version pairs from supported lockfiles against OSV affected package coordinates.
- [x] Support explicit affected-version lists and initial SEMVER/ECOSYSTEM event-range evaluation, including introduced/fixed/last_affected/limit boundaries.
- [x] Report advisory identifiers, CVE/GHSA aliases, severity, modified date, fixed-version boundary, lockfile evidence and confidence.
- [x] Treat unsupported range schemes, unreadable/malformed lockfiles, missing versions, 128 MiB input limits and 250,000-package extraction limits as UNKNOWN; do not label them clean.
- [x] Add dedicated JSON/Markdown/HTML vulnerability sections and CLI database import/status.
- [ ] Extend resolved lockfile coverage for all catalogued language ecosystems and package managers.
- [ ] Add adapters for local NVD JSON feeds, GHSA exports, distro advisories (Debian, Ubuntu, Alpine, Red Hat), OS package DBs, container/SBOM advisories and vendor bulletins.
- [ ] Add ecosystem-native comparators for PEP 440, SemVer, Maven, NuGet, Go pseudo-versions, RubyGems, Debian, RPM and vendor-specific versions.
- [ ] Support CPE/purl matching, duplicate/alias resolution, withdrawn/superseded advisories, exploit maturity, CVSS vector parsing and VEX status.
- [ ] Resolve direct/transitive dependency graphs and retain parent path/provenance for vulnerable packages.
- [ ] Add static dependency reachability evidence where symbol/call graphs support it; never claim exploitability from version matching alone.
- [ ] Add offline allowlists/triage, accepted-risk rationale, fixed-version suggestions and remediation grouping.
- [ ] Test DB corruption/recovery, duplicate IDs, re-import, withdrawn advisories, boundary versions, prereleases, malformed records and large local feeds.
- [ ] Include advisory snapshot provenance, import timestamp, source identity/hash, ecosystem coverage and freshness warning in reports.

## Phase 7 — Secrets, credentials and personal-data indicators

- [x] Field-name indicators for first/given/middle/last/family name, username, email, phone, address, date of birth and government-ID fields.
- [x] Email-shaped value indicators with raw values omitted.
- [x] Credential-related field-name indicators for password/passphrase, API key, client secret, tokens and private key.
- [x] Initial secret-pattern scanner and archive member secret-pattern scanner with redacted evidence.
- [ ] Expand detectors for actual high-confidence secret value shapes: cloud keys, provider tokens, database URLs, private-key blocks, certificates, JWTs, OAuth credentials, signing keys, service-account credentials, webhook secrets and generic entropy/context-assisted tokens.
- [ ] Add password/passphrase assignment value detection without ever storing or logging the matched value; support YAML, JSON, TOML, INI, XML, dotenv, HCL, source literals and multiline formats.
- [ ] Extend PII field/value detectors for firstname, first_name, givenName, middleName, lastname, surname, username, user_name, email, phone, address, account ID and related schemas in 40+ language syntaxes and data formats.
- [ ] Distinguish key-name evidence, placeholder/example values and likely non-placeholder values. Never label a field name alone as an exposed credential.
- [ ] Add optional local keyed HMAC fingerprints to correlate repeated values without exposing reversible data; store no raw match in cache.
- [ ] Add strict redaction tests for JSON/HTML/Markdown/terminal/exception logs and archive member findings.
- [ ] Add allowlists/false-positive controls that do not suppress genuine findings silently; record suppression rules in the report.

## Phase 8 — Polyglot language and framework intelligence

- [ ] Maintain 40+ language packs with real conformance fixtures, not just extension recognition: mainstream, legacy, scientific, functional, scripting, mobile, game, embedded, HDL, GPU and smart-contract languages.
- [ ] Leverage Tree-sitter where grammar coverage is robust; add dedicated parsers/SDKs where Tree-sitter is insufficient or unavailable.
- [ ] Support declarations, imports/exports, module resolution, symbol indexes, types, call sites, common framework APIs and test/build patterns to each declared capability.
- [ ] Include JS/TS, Python, Rust, Go, C/C++, Java/Kotlin, C#/F#, Swift, Objective-C, Dart, PHP, Ruby, Perl, R, Julia, Lua, Shell, PowerShell, Elixir/Erlang, Haskell, OCaml, Clojure, Scala, Groovy, Fortran, COBOL, Pascal, Ada, Zig, Nim, Crystal, D, Odin/V, Solidity/Move, SQL and HDL/GPU ecosystems.
- [ ] Handle ambiguous extensions (for example `.m`, `.v`, `.h`) with path/build/manifest context; retain ambiguous/unknown instead of overclaiming.
- [ ] Add a language-agnostic symbol/module interface and analyzer SDK with source span, syntax node, parser version and capability status.
- [ ] Add mixed-language monorepo fixtures and projects containing generated, vendored and nested workspace trees.
- [ ] Every unsupported or partially supported language must report capability gaps explicitly.

## Phase 9 — Security, configuration, API, database, test and build coverage

- [ ] Security: credentials, injection, command execution, traversal, SSRF, unsafe deserialization, authentication, authorization, cryptography, TLS, insecure randomness, dataflow/taint, container/IaC and supply-chain indicators.
- [ ] Configuration: environment variables, defaults, overrides, secrets references, configuration layering, schema validation, drift and cross-file key references.
- [ ] APIs: routes, handlers, contracts, clients, middleware, protocols, versioning and security controls.
- [ ] Databases: SQL, NoSQL, graph, search, time-series, vector databases, ORMs, migrations, connection config, schema/lineage and query indicators.
- [ ] Tests: 40+ language test naming/framework patterns, fixtures, setup/teardown, mocks, coverage data, test-to-code links and untested-code candidates.
- [ ] Builds: Make/CMake/Meson/Ninja, Bazel/Buck/Pants, Gradle/Maven/Ant, Cargo/Go, npm/pnpm/yarn/bun, Python packaging, .NET, SwiftPM/CocoaPods, Flutter, game/embedded/FPGA/GPU toolchains and CI/CD.
- [ ] Build analyzer capability must separate recognized manifest, extracted target/task, resolved dependency, and executed build; PDT never runs the build.
- [ ] Add tests for common, legacy, proprietary and custom project conventions; support safe custom rules through plugins.

## Phase 10 — Domain extensions

- [ ] Expand AI/ML model architecture, tokenizer/config, training/inference, datasets, accelerators, distributed training and checkpoint metadata without deserializing untrusted payloads.
- [ ] Expand ROS 1/ROS 2 packages, nodes, topics, services, actions, launch compositions, QoS and message/interface relationships.
- [ ] Expand mobile platform manifests, permissions, entitlements, build variants, native bridges and privacy/data declarations.
- [ ] Expand Unity, Unreal, Godot, GameMaker, Defold, Bevy, Roblox and web-game engine project/asset intelligence.
- [ ] Expand frontend frameworks, component graphs, routes, state, accessibility, localization and asset pipelines.
- [ ] Add embedded/firmware, RTOS, board-support, cross-compilation, boot images, memory maps and hardware interfaces.
- [ ] Add Verilog/SystemVerilog/VHDL and FPGA module/port/testbench graph analysis.
- [ ] Add CUDA/OpenCL/Metal/shader kernel and host-device relationship analysis.
- [ ] Expand observability/logging/metrics/tracing, cloud service binding, supply chain, SBOM/provenance and privacy/data governance.
- [ ] Expand multi-project comparison and integration planning while keeping each project independent.

## Phase 11 — Comprehensive report schema and report UX

### Data model
- [ ] Version the JSON schema and retain migration support for older report versions.
- [ ] Add explicit inventory records for every entry type, including special files and excluded/pruned subtree summaries.
- [ ] Add archive summary/member risk records, network endpoint records, API endpoint records, OS/platform indicators, credential/PII classifications and analyzer coverage.
- [ ] Add per-file analyzer status: not applicable, completed, partial, unsupported, budget-stopped, excluded, error.
- [ ] Add evidence spans/source locations, redaction state, confidence and severity.
- [x] Stream JSON, HTML payloads and Markdown output without building duplicate result dictionaries or a report-sized Markdown string; keep the Markdown largest-directory summary bounded to its top 100 entries.
- [ ] Add NDJSON/chunked external report data backed by a persistent inventory store.

### HTML report
- [x] Standalone offline dark UI baseline with responsive navigation and summary panels.
- [x] Search, category/severity/confidence filters and paginated finding display.
- [x] Per-finding disclosure plus open-all/close-all controls.
- [x] Use cursor-based bounded page rendering for file inventory and findings without allocating full filtered-match arrays.
- [ ] Add dedicated sections for subdirectories, hidden entries, development dependency trees, symlinks, file type/signature, size categories, network/IP/port/URL/subdomain, API routes/types, OS, archive/member content, secrets/PII and analysis coverage.
- [ ] Add hierarchical directory explorer and archive member browser without flattening everything into one list.
- [x] Keep the rendered DOM bounded with cursor-based pagination for large file/finding lists.
- [x] Keep symlink and special-filesystem-entry tables bounded with independent 100-row pagination controls.
- [x] Bound local-advisory and VCS/provider detail-card copies while retaining complete category counts.
- [ ] Add progressive loading from external local report data or chunked embedded data so the browser does not need the full report payload at startup.
- [ ] Make all large tables sortable, searchable and paginated with stable row keys.
- [ ] Add severity heatmaps, category summaries, per-domain completion and unknown/skipped/error accounting.
- [ ] Security-test HTML/JS data embedding, escaping, content security policy and offline isolation.
- [ ] Add keyboard accessibility, focus handling, contrast and screen-reader-friendly disclosure controls.
- [ ] Add golden screenshots and browser-based tests at desktop/tablet/mobile sizes.

### Terminal interface and CLI
- [x] ASCII banner and Rich progress/summary panels.
- [x] Clear screen only on an interactive TTY; never emit terminal control codes to redirected output.
- [x] Add a command-center dashboard showing Python orchestration and C/Assembly/C++/Rust backend status.
- [ ] Add phase timeline, domain status matrix, live counters, warning/error stream, confidence/severity legend and final scan-health panel.
- [ ] Group output by phase/domain; do not print every file as an unbounded line list.
- [ ] Add `--quiet`, `--no-color`, `--json-lines`, verbosity levels and stable exit codes.
- [ ] Add CLI commands for capability catalog, analyzer diagnostics, archive policy, budgets and report inspection.
- [ ] Test TTY, no-TTY, narrow terminals, Windows console, ANSI-disabled terminals and large CI logs.

## Security finding evidence and developer remediation (new release gate)

- [x] Extend the finding schema with redacted source-line evidence, exact line numbers, attacker-impact explanation and actionable remediation guidance across secure-code, Python AST security, secret, privacy, risky-configuration and ZIP/TAR member analyzers; local OSV dependency findings also include conditional impact and fixed-version remediation.
- [x] Add rule-specific impact descriptions for credential exposure, command/code injection, unsafe deserialization, SQL injection, SSRF, path traversal, weak cryptography, TLS/JWT misconfiguration, unsafe C APIs and other supported security rules.
- [x] Render vulnerable source lines in red in the HTML report using safe text nodes (never inject source as HTML); show file path, line number, severity, confidence, impact and remediation together.
- [x] Bring JSON and Markdown outputs to schema parity; Markdown visibly marks vulnerable lines and includes impact/remediation.
- [x] Redact passwords, tokens, private keys, credential URL values, email addresses, phone/address/birth-date/government-ID fields and common identity literals at the source-excerpt/model boundary; test report escaping against HTML/script payloads.
- [x] Add focused regression tests for password/identity assignments, authorization headers, credential URLs, email addresses, provider-token formats, PEM headers and standalone base64 payload lines, excerpt length bounds and model-boundary redaction. Full analyzer/plugin/report-surface redaction verification remains a release gate.
- [x] Add analyzer-level PEP 263 regression coverage for both Python AST structure analysis and Python AST security analysis; malformed/unsupported encodings remain explicit UNKNOWN outcomes.
- [ ] Keep severity evidence-driven: explain realistic consequences conditionally and never describe a heuristic marker as confirmed exploitability or runtime exposure.

## Phase 12 — Large-project and adversarial verification

- [ ] Build synthetic and representative corpora at 2GB, 10GB, 50GB and 100GB+.
- [ ] Include high file count, deep nesting, huge fan-out, large development dependency trees, mixed file size distributions and binary-heavy projects.
- [ ] Include malformed and adversarial archive corpus, symlink loops, special files, permissions, Unicode/case-colliding paths, race conditions and files changing mid-scan.
- [ ] Include polyglot monorepos with 40+ languages and many build/API/database/test/security domains.
- [ ] Measure wall time, throughput, peak RSS, descriptor count, thread count, cache overhead, archive budgets, HTML/JSON output and memory during report rendering.
- [ ] Set explicit resource SLOs by scan mode; fail CI when budgets regress materially.
- [ ] Run fuzzers/property tests for archive parsers, path normalization, language/file-type recognition and report serialization.

## Phase 13 — Production release

- [ ] CI triggers on pushes to `master`, `main` and `feat/**`, and pull requests targeting `master` or `main`; matrix jobs have explicit timeouts and pip dependency caching, and superseded runs are cancelled to prevent stale matrix queues.

- [ ] Full supported OS and Python CI matrix, plus native build matrix where Rust/C modules exist.
- [ ] Analyzer conformance and regression coverage for all claimed capabilities.
- [ ] Reproducible source/wheel builds, clean install, package metadata, dependency/license inventory and CLI smoke tests.
- [x] Route built-in analyzer reads of scanned project files through shared descriptor-verified binary/text and bounded-reader helpers; apply private scan-time identity checks where the walker supplies them. SHA-256 and signature sampling use the same descriptor boundary; regression tests cover file replacement, symlink substitution, bounded reads and private identity serialization.
- [ ] Add a descriptor-aware Analyzer/plugin file-access contract and migrate or reject legacy third-party path-open behavior where strict mode requires enforcement.
- [ ] Add stable Windows file identity to the Rust walker and verify scan-to-read continuity on Windows/macOS/Linux. The current Windows Rust walker does not yet supply a stable file ID; open-time `lstat`/`fstat` checks alone do not prove continuity from inventory.
- [ ] Security review of filesystem races, symlink handling, parsers, archive streams, plugin execution, cache databases, output paths and HTML serialization.
- [ ] Verified read-only, offline and privacy guarantees.
- [ ] Verified secret/PII redaction across every output surface.
- [ ] Verified 100k+ report usability and large-project performance/resource limits.
- [ ] Plugin SDK documentation, API versioning, compatibility policy, sandbox/isolation guidance and conformance suite.
- [ ] User-facing threat model, architecture guide, support matrix, benchmark report, operations guide and release notes.
- [ ] Production gate signed off before PR #1 can be merged.

## Acceptance standard

A task is complete only when:
1. implementation exists in the feature branch;
2. behavior and limitations are documented;
3. focused positive, negative and malformed-input tests exist;
4. platform-sensitive cases run in the supported CI matrix;
5. resource bounds and error states are explicit;
6. evidence and redaction behavior are verified;
7. the final PR head has green CI.

## Release gate

PDT is **not production-ready** while any mandatory acceptance item remains open, any core behavior silently skips project content, any capability is advertised beyond its evidence, the 2GB–100GB+ resource budget is unverified, report UX fails at large scale, or the final CI head is not green.

PR #1 remains open and unmerged. The repository owner alone decides when the verified production-ready branch is merged into `master`.

## Execution order — production completion (2026-11-04)

The next implementation block follows this dependency order. Documentation is updated before implementation; each phase below must land with focused tests and a truthful capability state.

1. **Inventory semantics and no-silent-pruning:** remove implicit exclusions for dependency/cache/build trees; inventory every entry and retain explicit prune/skip reasons; complete symlink and special-entry semantics, hidden attributes, file signatures and size accounting.
2. **Polyglot scale engine:** replace unbounded in-memory inventory/results with a Rust walker/indexer, bounded queues, incremental persistence, cancellation and checkpoints. Keep Python as orchestration; retain C/SIMD Assembly only on measured hot paths; add C++ only for justified SDK/library integration.
   - **Progress (2026-11-04):** `InventoryStore` is connected to CLI scanner runs. All inventory record classes are written in bounded SQLite batches with running/complete/partial checkpoints, final directory aggregates and integrity telemetry. Store-backed runs return typed lazy sequences for files (`StoredFileRecords`), symlinks and special entries, ordered by case-folded path plus exact-path tie-break; private file identity is retained in the database but excluded from public serialization. The CLI, Python graph, architecture pass and incremental JSON/HTML/Markdown writers iterate these sequences without duplicate record lists. The Python fallback now retains only active directory iterators (O(depth)), not queued sibling directory paths. Directory maps/lists, findings, graph state and report metrics remain materialized, and the browser still receives a single embedded report payload. This is a partial memory reduction, not end-to-end bounded-memory scanning; full inventory streaming, findings persistence, cancellation and true restartable resume remain OPEN.
   - **Progress:** the Python fallback streams `os.scandir` entries without a per-directory sorted `DirEntry` buffer. Store-backed file iteration preserves deterministic case-folded ordering with an exact-path tie-break. High-fan-out and casefold-collision regression tests cover the ordering behavior; the directory map/list, symlink/special collections and fallback traversal stack still need bounded designs.
3. **Archive inspection:** extend no-extraction readers, inspect member names/types/content/links/permissions/ownership/timestamps, and enforce nested-depth, expansion-ratio, entry-count, compressed/uncompressed byte, sample and wall-time budgets. Unsupported formats remain explicitly UNKNOWN/detection-only.
4. **Analyzer completeness:** expand security, configuration, API style/route/contracts, database/ORM/migrations, test/build/CI, OS/platform, network and identity/credential analyzers across the 40+ language-family catalog. Separate lexical evidence from parser-backed semantics.
5. **Report schema and UX:** expose every inventory/analyzer state in JSON; provide grouped domain dashboards and lazy/chunked HTML rendering, stable pagination, global search, keyboard-accessible disclosures and open/close-all without unbounded DOM creation.
6. **Terminal experience:** retain the ASCII banner and command-center presentation; group progress by phase/domain, keep TTY clearing conditional, and add quiet/no-color/JSON-lines/verbosity modes with stable exit codes.
7. **Native execution acceleration:** bounded concurrent thread-pool file analysis (`--jobs N`/automatic sizing), runtime C/OpenCL GPU detection, a supported large-buffer byte-count kernel, deterministic collection, CPU/SIMD/Python fallback and capability/dispatch reporting are implemented. Remaining release gates are GPU-hardware/fault-injection tests, per-device threshold benchmarks and 2GB–100GB+ throughput/peak-RSS measurements; GPU use remains limited to explicitly supported kernels.
8. **Security evidence and reporting:** attach safely redacted vulnerable source lines, precise line numbers, severity, attacker-impact context and remediation to findings; synchronize JSON, Markdown and HTML output and test XSS/secret redaction.
9. **Verification and release:** adversarial filesystem/archive fixtures, redaction tests, GPU/CPU parity and fallback tests, concurrent-scan/cache tests, cross-platform native builds, parser conformance, packaging checks, 2GB/10GB/50GB/100GB+ performance and peak-RSS benchmarks, and green CI on the final PR head.

### Polyglot implementation acceptance

A language is part of the implementation only when source files exist, it is built or provisioned reproducibly, a production code path invokes it, its boundary is documented, and tests exercise success/failure/fallback behavior. The required language-family coverage is 40+; Python is not the sole implementation language. C and x86-64 Assembly provide native byte-counting/hardware paths; the Rust no-follow iterator, C++ signature classifier and JavaScript report client are integrated and tested in CI. Persistent Rust-backed inventory/indexing remains a release gate. TypeScript is not currently a runtime dependency; unused language folders or placeholder wrappers do not count.

### Oversized-file invariant

Without `--skip`, no global file-size threshold may suppress content analysis. With `--skip`, oversized files remain inventoried and are marked with the configured threshold and reason. Independent analyzer-specific safety budgets may stop an individual parser; those outcomes must be visible as UNKNOWN/partial and must not be confused with the global skip option.
