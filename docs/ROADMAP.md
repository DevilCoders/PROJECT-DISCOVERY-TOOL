# Roadmap

## Scope contract

PDT must handle heterogeneous and polyglot repositories. Language work is not restricted to Rust, JavaScript/TypeScript, Go or C/C++. The recognition catalog covers 40+ source languages and the optional parser adapter maps 60+ grammar integrations. Every language must expose distinct capability levels: recognized, parser mapped, parser provisioned, syntax analyzed, structure extracted and semantics resolved. These states must never be conflated.

The same breadth requirement applies to analyzer domains. Security, configuration, API, database, testing and build/deployment intelligence must be expanded as independent, composable analyzers across language and ecosystem matrices. The 50+ domain catalog is a coverage contract, not a completion claim.

## Implemented foundation
- [x] Deterministic read-only filesystem inventory, symlink avoidance and common generated/vendor pruning
- [x] SQLite fingerprint cache with metadata validation and stale-entry pruning
- [x] Python AST symbol/import inventory and confirmed internal dependency graph
- [x] Markdown structure and optional PDF/DOCX document extraction
- [x] JSON, Markdown and interactive HTML reports with search and filters
- [x] Rich terminal progress and summary
- [x] Analyzer API and entry-point plugin discovery with diagnostics
- [x] 40+ language recognition and 60+ optional Tree-sitter grammar mappings
- [x] Static dependency manifests and selected lockfile/license inventory
- [x] Initial security, secrets, identity, configuration and secure-code analyzers
- [x] REST/OpenAPI, GraphQL, RPC and selected source endpoint inventory
- [x] SQL, NoSQL, ORM and cross-framework migration inventory
- [x] Test, build, CI/CD, container and deployment discovery
- [x] ML/AI, game-engine, mobile, ROS and multi-project initial intelligence
- [x] Local project catalog and N-project comparison

## Production-readiness work
1. Keep the full cross-platform CI matrix green, with coverage gates and reproducible package builds.
2. Expand parser-specific symbols, imports/exports, types, call graphs and reference resolution across all mapped grammars.
3. Deliver language-specific adapters in broad packs; target 40+ genuinely analyzed languages, not merely recognized extensions.
4. Security: broaden source-language and framework coverage for injection, authn/authz, SSRF, path traversal, deserialization, crypto misuse, secrets, cloud/IaC, containers, CI/CD and supply chain. Add taint/dataflow only with traceable source-to-sink evidence.
5. Configuration: cover application frameworks, operating systems, network services, cloud providers, containers, orchestration, robotics, embedded and game-engine configuration.
6. APIs: REST, GraphQL, RPC/gRPC, event-driven, SOAP/WSDL, WebSocket, schema registries, generated clients, API collections and framework-specific routing.
7. Databases: SQL engines, NoSQL, graph, search, time-series, vector stores, ORMs, migrations, schema evolution and data pipelines.
8. Tests: 40+ language/framework ecosystems, fixtures, test runners, coverage formats, test-to-code relationships and CI test execution declarations.
9. Build/deployment: native, managed, scripting, mobile, game, embedded, FPGA, GPU, robotics and monorepo build systems.
10. ROS 1/ROS 2 graph analysis: packages, nodes, topics, services, actions, launch composition, QoS and interface relationships.
11. Architecture, dataflow, observability, concurrency, memory, performance, accessibility, localization and asset intelligence.
12. Documentation cross-reference and claim validation for PDF, DOCX, HTML, RST, AsciiDoc and notebooks.
13. Large-repository, cache, ignore-rule, malformed-input, adversarial fixture and output-safety regression suites.
14. Plugin SDK, compatibility contracts, analyzer conformance tests and third-party plugin fixtures.
15. Benchmarks, SBOM, reproducible distributions, security review and release checklist.

## Release gate
PDT is not production-ready until the full release checklist, supported-platform CI matrix, coverage gate, package validation, read-only guarantees, offline behavior, output safety, plugin contract, documentation and regression suite are verified. PRs remain unmerged until the repository owner explicitly approves the merge.
