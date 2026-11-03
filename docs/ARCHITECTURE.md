# Architecture

## Design goals
PDT is a local-first, read-only analyzer. The core owns traversal, shared models, cache coordination, CLI orchestration and report output. Language and domain knowledge belongs in analyzers.

## Pipeline
1. Resolve and validate the target and report paths.
2. Walk the target deterministically, pruning common generated/vendor directories and skipping symlinks.
3. Fingerprint files and reuse cached hashes when size and nanosecond mtime match.
4. Dispatch eligible files to analyzers.
5. Build static language-specific dependency graphs from inventoried source and extract declared dependency manifests.
6. Serialize findings, graph evidence and inventory to local report formats.

## Analyzer contract
Implement `project_discovery.analyzers.base.Analyzer`, then expose a no-argument constructor through the `pdt.analyzers` Python entry-point group. Analyzer code runs inside the PDT process and must be trusted. The core does not import target project modules.

## Python module graph
The first dependency graph is Python AST based. It maps unambiguous `.py` and `.pyi` paths to module names, resolves absolute and relative imports only against inventoried modules, and records source path and line evidence. Strongly connected components identify circular dependencies. External, missing and ambiguous imports remain UNKNOWN; they are not presented as confirmed internal edges. Target modules are parsed, never imported or executed.

## Dependency manifests
The manifest analyzer reads `pyproject.toml`, `requirements*.txt`, `package.json`, `Cargo.toml`, `go.mod`, and `composer.json`. Findings confirm that a dependency is declared in a manifest; they do not claim that it is installed, imported, or used at runtime. Malformed manifests produce UNKNOWN findings.

## Confidence
- CONFIRMED: directly observed in source or configuration.
- INFERRED: heuristic conclusion, requiring validation.
- UNKNOWN: evidence is insufficient.

Documentation text is not treated as proof that a described feature exists in code.

## Privacy and safety
No telemetry or network requests are implemented. Target files are read only; generated reports and SQLite cache are written to the output directory. Symlinks are not followed. Files above the configured size limit are inventoried but not parsed. This is a static analyzer, not a sandbox: trusted plugins execute with the permissions of the PDT process.
