# Roadmap

## Foundation (this PR)
- [x] Deterministic filesystem inventory and common-directory pruning
- [x] Symlink avoidance and per-file error isolation
- [x] SQLite content fingerprint cache
- [x] Python AST inventory
- [x] Markdown structural inventory
- [x] JSON, Markdown and HTML reports
- [x] Analyzer entry-point extension contract
- [ ] CI matrix and coverage gates

## Next milestones
1. Add automated tests for cache invalidation, ignore rules, output safety and malformed files.
2. Add language analyzers behind optional parser dependencies (Rust, JS/TS, Go, C/C++).
3. Build normalized symbol and dependency graph models.
4. Add docs ingestion for PDF/DOCX/HTML and cross-reference validation.
5. Add security/configuration/API/database/test/build analyzers.
6. Add architecture and data-flow inference with explicit evidence and confidence.
7. Add multi-project catalog, comparison and integration-opportunity analysis.
8. Add interactive graph exploration and richer HTML search/filtering.
9. Add plugin SDK documentation, compatibility contracts and fixture suite.
