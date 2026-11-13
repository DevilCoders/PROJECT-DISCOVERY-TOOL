# Polyglot Parsing and Language Capability Levels

PDT is designed for heterogeneous and polyglot repositories. Its language catalog recognizes 128 languages and formats, 81 of them source languages, plus schemas, build, configuration and documentation formats, game-engine assets, firmware images, hardware description and constraint files, and shaders. `pdt capabilities` and `metrics.language_catalog` in every report list each entry with its capability state.

## Capability levels

| Level | Meaning | Where it shows |
|---|---|---|
| Recognized | A file extension or known file name maps to a language or format. | Every catalog entry (`recognition: CONFIRMED`). |
| Structure extracted | PDT's built-in code model extracts definitions, calls, imports and references: from the syntax tree for Python, and from a linear-time structural lexer for about 25 brace languages (C/C++, Java, Kotlin, Scala, Groovy, C#, Swift, Dart, JavaScript/TypeScript, Vue, Svelte, Go, Rust, PHP, Solidity, Zig, CUDA, OpenCL, GLSL, HLSL, Metal, WGSL, Arduino). For 16 of those languages a provisioned Tree-sitter grammar refines the lexer's symbols and calls (see [CODE_INTELLIGENCE.md](CODE_INTELLIGENCE.md)). | `structural_model: "ast"` or `"lexical"`; `model_grammar` names the refining grammar; `analysis_status: "implemented"` (Python) or `"lexical_structure"`; `metrics.code_index.symbols.models` shows the backend each scan used. |
| Parser mapped | An optional Tree-sitter grammar is configured (61 grammar identifiers). | `parser_backend: "optional:tree-sitter-language-pack"`; `analysis_status: "optional_parser"` when no built-in model exists. |
| Parser provisioned | The optional grammar is available locally. | Tree-sitter findings (syntax tree, declarations, imports and parser diagnostics) and, for the code-model languages, the Tree-sitter backend. With the pack installed, a scan lists the languages it found whose grammar is not provisioned in one INFO `UNKNOWN` finding ("Tree-sitter grammars not provisioned"); without the pack, `metrics.local_parser_capabilities` records each language's state. |
| Semantics resolved | Symbols, modules, calls and data flow are resolved with evidence. | Python today: calls through imports and `self`, module graph, inter-procedural taint. |
| Inventory only | Recognized and counted, analysed only by format-specific analyzers. | `analysis_status: "inventory_only"`. |

The code model and index are described in [CODE_INTELLIGENCE.md](CODE_INTELLIGENCE.md).

## Optional Tree-sitter grammars

Install the optional parser package with:

    python -m pip install -e ".[polyglot]"

The adapter checks local grammar availability before constructing a parser and never invokes the parser pack's on-demand download path during a scan. If a grammar is not provisioned locally, PDT records the capability gap and continues without network access.

A syntax tree confirms parser structure and diagnostics; it does not prove that a program compiles, links, passes tests or behaves correctly. Generic import references are not considered internal dependencies until resolution proves that relationship. The grammar mapping is an integration surface, not a claim that language-specific semantic analyzers are complete.
