# Analyzer resource budgets

These are per-analyzer safety limits, not a global scan-size policy. They are currently fixed implementation defaults; they are not all exposed as CLI options yet.

## Current bounded work

| Analyzer / subsystem | Current limit | Input strategy | Limit outcome |
|---|---:|---|---|
| Configuration intelligence | 16 MiB per file | Reads at most limit + 1 bytes; parses one decoded buffer and reuses its source lines | UNKNOWN on indexed oversize or file growth |
| Cross-language secure-code patterns | 16 MiB per file | Reads at most limit + 1 bytes; PEP 263 decoding for Python | UNKNOWN on oversize/growth/decode/AST resource failure |
| Identity intelligence | 16 MiB per file; 100 retained source locations per category | Reads at most limit + 1 bytes; PEP 263 decoding for Python; bounded location aggregation and line iteration | UNKNOWN on oversize/growth/decode/AST resource failure |
| Data-exposure / PII indicators | 64 MiB per file; 256 KiB per line; 100 evidence line references; 20 code excerpts | Binary line streaming; redacted excerpts; bounded evidence retention | UNKNOWN/partial when byte budget is reached |
| Secret-pattern analysis | 64 MiB per file; 8 MiB chunks; 4 KiB overlap; at most 10,000 findings | Binary chunk streaming with cross-chunk overlap | UNKNOWN/partial on byte or finding limits |
| Python AST inventory/security | 16 MiB per file | PEP 263-aware source reads with AST parsing | UNKNOWN on indexed oversize or parse failure |
| Python import graph | 16 MiB per module | AST extraction over inventoried source | UNKNOWN for skipped or over-budget modules |
| Python API endpoint extraction | 16 MiB per Python AST file | PEP 263-aware limit + 1 byte read and AST parsing | UNKNOWN on oversize/growth/parser resource failure |
| Non-Python API endpoint scanning | 32 MiB per file; 256 KiB per line | Bounded line streaming | UNKNOWN/partial when scan byte limit is reached |
| API-style classification | 32 MiB per file; 256 KiB per line; 25,000 retained unique indicators; 100 evidence lines | Bounded byte/line streaming with bounded per-category samples | UNKNOWN/partial on byte or indicator cap |
| API contract parsing | 16 MiB per file | Bounded one-buffer read for OpenAPI, AsyncAPI, OpenRPC, WSDL, RAML, GraphQL, Protobuf and Thrift | UNKNOWN on oversize/growth/parse failure |
| Tree-sitter syntax parsing | 16 MiB per file | Bounded source read before parser invocation | UNKNOWN on oversize/growth/parser failure |
| Build manifest analysis | 16 MiB per file | Bounded one-buffer read for build/CI manifests | UNKNOWN on oversize/growth/parse failure |
| Markdown structure analysis | 32 MiB per file | Bounded UTF-8 read | UNKNOWN on oversize/growth |
| Coverage artifact parsing | 64 MiB per file | Bounded UTF-8 read before JSON/XML/LCOV parsing | UNKNOWN on oversize/growth/parse failure |
| Generic lockfile inventory | 128 MiB per lockfile; 250,000 retained package/version entries | Bounded one-buffer read; JSON/TOML objects parsed in memory; text formats iterated from bounded in-memory content | UNKNOWN on byte or entry-count limit |
| Local vulnerability lockfiles | 128 MiB per lockfile; 250,000 retained package/version entries | Bounded one-buffer read; JSON/TOML objects parsed in memory; text formats iterated from bounded in-memory content | UNKNOWN on byte or entry-count limit |
| License headers and declarations | First 64 KiB of each source or license file (lenient decoding); 8 MiB per package manifest | Bounded prefix read through a verified descriptor | Files are checked within the header window; an unparsable manifest is an UNKNOWN finding |
| Text/HTML/RST documents | 32 MiB per file | Bounded UTF-8 read | UNKNOWN on oversize/growth |
| Markdown | 32 MiB per file | Bounded UTF-8 read | UNKNOWN on oversize/growth |
| PDF/DOCX documents | 16 MiB compressed input; PDF 5,000 pages; extracted text 16 MiB; DOCX 10,000 entries and 32 MiB total declared uncompressed data | Bounded bytes; DOCX ZIP metadata/ratio checks before python-docx | UNKNOWN on input, page, text, package entry or uncompressed-byte budget stop |
| ZIP archive index | 200,000 entries; 64 MiB declared central-directory bytes | EOCD/ZIP64 preflight before ZipFile.infolist() | UNKNOWN without index materialization when bounds are exceeded or unavailable |
| ZIP/TAR member content | 1 MiB per member; 32 MiB per archive | In-memory member streams only; no extraction | UNKNOWN/partial when member/sample limit is reached |
| ZIP/TAR archive inspection | 8 seconds per archive; compressed TAR output capped at 4 GiB | Cooperative checks during metadata iteration, member sampling and content-pattern matching; the TAR decompression reader enforces both limits inside reads | UNKNOWN/partial when the deadline or decompression budget is reached |
| Shared code model | 4 MiB per file | Bounded read; Python syntax tree or linear-time structural lexer, built once per file and worker | UNKNOWN (code-index analyzer) when a file is too large to model |
| Code facts | Per file: 5,000 symbols, 20,000 call sites, 10,000 references, 5,000 domain facts. Per table: 5M symbols, 10M calls, 20M references, 5M facts | Stored with the file's findings in bounded SQLite batches | "Code index truncated" UNKNOWN finding; index-based results incomplete |
| Code index passes | 500,000 resolved call-graph edges for cycle detection; 5,000 items per integration list | Read-only connection and temporary tables | Edge limit recorded in `metrics.code_index`; per-pass errors become UNKNOWN findings |
| Data flow (Python) | 50,000 statement visits per function and round; summaries iterate until unchanged (at most 64 rounds); 4 passes per loop; 6 source labels per value (parameter labels are always kept); 500 exported summaries and 500 tainted calls per file | Syntax-tree interpretation of relevant functions only | Interrupted functions, a cap that stops a changing iteration and facts beyond the caps: a "Data-flow analysis truncated" UNKNOWN finding |
| Data flow (lexical languages) | 20,000 assignments and sinks per function region; 200,000 summary events per file; 3 helper rounds; 200 outgoing calls; 4,000 characters per right-hand side; 500 exported summaries and 500 tainted calls per file | Cleaned text of the code model | Any cut: a "Data-flow analysis truncated" UNKNOWN finding |
| Type-checker and frontend configuration | 2 MiB per file | Bounded read | File skipped |
| Embedded configuration | 4 MiB per file (platformio.ini, sdkconfig, .ioc, linker scripts, device trees, FreeRTOSConfig.h) | Bounded read | File skipped |
| Firmware and binary headers | 1 MiB header sample; 4 MiB per ELF/PE table and per firmware build file; 64 MiB per Intel HEX or S-record image; 8 MiB scanned for component strings; 65,536 UF2 blocks | Verified binary stream with seeks, never a full read | Partial header results; unreadable formats report nothing |
| HDL sources and constraints | 8 MiB per file; 2,000 design units per file | Bounded read with linear comment/string blanking | File skipped |
| Shaders | 4 MiB per source file; SPIR-V up to 2,000,000 words | Bounded read or verified binary stream | File skipped |
| Integration points | 2 MiB per manifest or `.proto`; 400 facts per source file | Bounded read; source through the code model | Later facts in the file are not recorded |

## Global oversized-file policy

The scan CLI's global oversized-file skip is opt-in. Without --skip, PDT does not suppress file content analysis globally based on file size. With --skip, files over --max-file-mb remain in inventory and receive an explicit skip reason.

An analyzer may apply its own specialized budget regardless of --skip. Such a result must be visible as UNKNOWN/partial with a reason and must never be represented as a clean assessment. A per-analyzer budget stop does not remove the file from inventory or prevent unrelated streaming analyzers from inspecting it.

## Important limitations

- Most byte limits are fixed constants and are not yet configurable by CLI or a policy file.
- Lockfile text formats iterate lines from a bounded in-memory content buffer; JSON/TOML lockfiles are parsed as bounded in-memory objects. The 250,000 entry cap limits retained package results, not the initial JSON/TOML parser object graph.
- Core Python AST inventory, Python security AST, import graph and Python endpoint readers now use race-safe limit + 1 byte reads. The other listed parser-based analyzers also use bounded reads; newly added analyzers must follow the same contract.
- The archive wall-time limit is cooperative. It is checked between metadata/member operations and regex matches; it cannot preempt a blocked filesystem read or interrupt a single in-progress Python regular-expression call.
- The archive implementation does not yet impose a shared nested-archive depth or total-uncompressed-size budget because recursive nested archive inspection is not implemented.
- The vulnerability lockfile limit is a format-parser admission limit, not a streaming parser; files below the limit may still need significant memory.
- Inventory records, findings, diagnostics and code facts are persisted in SQLite and read back lazily, the JSON report is streamed, and the HTML report embeds bounded subsets (`embedded_limits` in the payload). Report metrics, the Python import graph (within its caps) and each per-file analyzer's working set are still held in memory. Bounded-memory behavior at 100 GB+ is unverified until the large-corpus benchmarks run.

## Release requirements

1. Centralize the budget definitions in a policy object and expose safe per-domain overrides.
2. Record configured budget, consumed bytes/time, stop reason and analyzer state in JSON, Markdown, HTML and terminal summaries.
3. Add adversarial tests for file mutation during reads, long lines, deeply nested ASTs, malformed parser input, archive bombs and wall-time boundaries.
4. Benchmark wall time, throughput and peak RSS over 2GB, 10GB, 50GB and 100GB+ corpora.
5. Keep every budget-stopped outcome distinguishable from excluded, skipped, unsupported, parse-error and clean-complete states.
