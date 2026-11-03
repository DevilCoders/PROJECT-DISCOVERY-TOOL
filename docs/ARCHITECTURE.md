# Architecture

## Design goals
PDT is a local-first, read-only analyzer. The core owns traversal, shared models, cache coordination, CLI orchestration and report output. Language and domain knowledge belongs in analyzers.

## Pipeline
1. Resolve and validate the target and report paths.
2. Walk the target deterministically, pruning common generated/vendor directories and skipping symlinks.
3. Fingerprint files and reuse cached hashes when size and nanosecond mtime match.
4. Dispatch eligible files to analyzers.
5. Serialize findings and inventory to local report formats.

## Analyzer contract
Implement `project_discovery.analyzers.base.Analyzer`, then expose a no-argument constructor through the `pdt.analyzers` Python entry-point group. Analyzer code runs inside the PDT process and must be trusted. The core does not import target project modules.

## Confidence
- CONFIRMED: directly observed in source or configuration.
- INFERRED: heuristic conclusion, requiring validation.
- UNKNOWN: evidence is insufficient.

The initial analyzers emit direct structural observations only. Documentation text is not treated as proof that a described feature exists in code.

## Privacy and safety
No telemetry or network requests are implemented. Target files are read only; generated reports and SQLite cache are written to the output directory. Symlinks are not followed. Files above the configured size limit are inventoried but not parsed. This is a static analyzer, not a sandbox: trusted plugins execute with the permissions of the PDT process.
