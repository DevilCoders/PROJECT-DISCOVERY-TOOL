# Analyzer resource budgets

These are per-analyzer safety limits, not a global scan-size policy. They are currently fixed implementation defaults; they are not all exposed as CLI options yet.

## Current bounded work

| Analyzer / subsystem | Current limit | Input strategy | Limit outcome |
|---|---:|---|---|
| Configuration intelligence | 16 MiB per file | Reads at most limit + 1 bytes; parses one decoded buffer and reuses its source lines | UNKNOWN on indexed oversize or file growth |
| Cross-language secure-code patterns | 16 MiB per file | Reads at most limit + 1 bytes; PEP 263 decoding for Python | UNKNOWN on oversize/growth/decode/AST resource failure |
| Identity intelligence | 16 MiB per file | Reads at most limit + 1 bytes; PEP 263 decoding for Python; reuses one line list | UNKNOWN on oversize/growth/decode/AST resource failure |
| Data-exposure / PII indicators | 64 MiB per file; 256 KiB per line; 100 evidence line references; 20 code excerpts | Binary line streaming; redacted excerpts; bounded evidence retention | UNKNOWN/partial when byte budget is reached |
| Secret-pattern analysis | 64 MiB per file; 8 MiB chunks; 4 KiB overlap; at most 10,000 findings | Binary chunk streaming with cross-chunk overlap | UNKNOWN/partial on byte or finding limits |
| Python AST inventory/security | 16 MiB per file | PEP 263-aware source reads with AST parsing | UNKNOWN on indexed oversize or parse failure |
| Python import graph | 16 MiB per module | AST extraction over inventoried source | UNKNOWN for skipped or over-budget modules |
| Python API endpoint extraction | 16 MiB per Python AST file | PEP 263-aware AST parsing | UNKNOWN on over-budget source |
| Non-Python API endpoint scanning | 32 MiB per file; 256 KiB per line | Bounded line streaming | UNKNOWN/partial when scan byte limit is reached |
| Local vulnerability lockfiles | 128 MiB per lockfile | Format parser after size gate | UNKNOWN when the parser budget is exceeded |
| ZIP archive index | 200,000 entries; 64 MiB declared central-directory bytes | EOCD/ZIP64 preflight before ZipFile.infolist() | UNKNOWN without index materialization when bounds are exceeded or unavailable |
| ZIP/TAR member content | 1 MiB per member; 32 MiB per archive | In-memory member streams only; no extraction | UNKNOWN/partial when member/sample limit is reached |
| ZIP/TAR archive inspection | 8 seconds per archive | Cooperative checks during metadata iteration, member sampling and content-pattern matching | UNKNOWN/partial when the deadline is reached |

## Global oversized-file policy

The scan CLI's global oversized-file skip is opt-in. Without --skip, PDT does not suppress file content analysis globally based on file size. With --skip, files over --max-file-mb remain in inventory and receive an explicit skip reason.

An analyzer may apply its own specialized budget regardless of --skip. Such a result must be visible as UNKNOWN/partial with a reason and must never be represented as a clean assessment. A per-analyzer budget stop does not remove the file from inventory or prevent unrelated streaming analyzers from inspecting it.

## Important limitations

- Most byte limits are fixed constants and are not yet configurable by CLI or a policy file.
- Python AST and import-graph limits use an indexed-size precheck; not every AST reader has a race-safe limit + 1 byte read yet.
- The archive wall-time limit is cooperative. It is checked between metadata/member operations and regex matches; it cannot preempt a blocked filesystem read or interrupt a single in-progress Python regular-expression call.
- The archive implementation does not yet impose a shared nested-archive depth or total-uncompressed-size budget because recursive nested archive inspection is not implemented.
- The vulnerability lockfile limit is a format-parser admission limit, not a streaming parser; files below the limit may still need significant memory.
- Inventory, scan findings and the complete embedded JSON report payload are still retained in memory. The 100GB+ objective is not met until persistent streaming inventory, bounded result aggregation and external/chunked report data are implemented and benchmarked.

## Release requirements

1. Centralize the budget definitions in a policy object and expose safe per-domain overrides.
2. Record configured budget, consumed bytes/time, stop reason and analyzer state in JSON, Markdown, HTML and terminal summaries.
3. Add adversarial tests for file mutation during reads, long lines, deeply nested ASTs, malformed parser input, archive bombs and wall-time boundaries.
4. Benchmark wall time, throughput and peak RSS over 2GB, 10GB, 50GB and 100GB+ corpora.
5. Keep every budget-stopped outcome distinguishable from excluded, skipped, unsupported, parse-error and clean-complete states.
