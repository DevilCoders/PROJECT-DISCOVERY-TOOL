# Roadmap

## Foundation (current PR)
- [x] Deterministic filesystem inventory and common-directory pruning
- [x] Symlink avoidance and per-file error isolation
- [x] SQLite content fingerprint cache
- [x] Python AST symbol/import inventory
- [x] Markdown structural inventory
- [x] JSON, Markdown and HTML reports
- [x] Analyzer entry-point extension contract
- [x] Python module registry and confirmed internal import graph
- [x] Strongly connected component detection for Python import cycles
- [x] Dependency manifest inventory (Python, Node, Rust, Go, Composer)
- [x] Polyglot recognition catalog covering 40+ languages and project formats
- [x] Explicit 50+ domain analyzer coverage catalog
- [ ] Rich terminal UI and CLI ergonomics
- [ ] CI coverage gates

## Production-readiness work
1. Complete parser adapter contracts, parser availability reporting and version compatibility.
2. Implement language adapters in prioritized packs while keeping optional dependencies isolated.
3. Expand domain analyzers across security, configuration, APIs, databases, tests, build/deployment, supply chain, ML/AI, robotics, embedded and other project-specific domains.
4. Add cache invalidation, ignore-rule, output safety, malformed-input and large-repository regression suites.
5. Add docs ingestion for PDF/DOCX/HTML and cross-reference validation.
6. Add architecture and data-flow inference with explicit evidence and confidence.
7. Add multi-project catalog, comparison and integration-opportunity analysis.
8. Add interactive graph exploration and richer HTML search/filtering.
9. Add plugin SDK documentation, compatibility contracts and fixture suite.
10. Add performance benchmarks, reproducible packaging, security review and release checklist.
