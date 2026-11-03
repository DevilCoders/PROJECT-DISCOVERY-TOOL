# Polyglot Parser Adapter

PDT is designed for heterogeneous and polyglot repositories. Its language catalog recognizes more than 40 source languages and a wider range of schemas, build formats, configuration formats, documentation formats, game-engine assets and hardware/compute languages. The optional Tree-sitter adapter maps more than 60 grammar identifiers.

## Capability levels
- Recognized: a file extension or known filename maps to a language or format.
- Parser mapped: a grammar adapter is configured.
- Parser provisioned: the optional grammar is available locally.
- Syntax analyzed: a syntax tree and parser diagnostics are generated.
- Structure extracted: declarations and selected imports are extracted.
- Semantics resolved: symbols, modules, types, calls and relationships are resolved with evidence.

Install the optional parser package with:

    python -m pip install -e ".[polyglot]"

The adapter checks local parser availability before constructing a parser. It never invokes the parser pack's on-demand download path during a project scan. If a grammar is not provisioned locally, PDT records the capability gap and continues without network access.

A syntax tree confirms parser structure and parser diagnostics; it does not prove that a program compiles, links, passes tests or behaves correctly. Generic import references are not considered internal dependencies until resolution proves that relationship.

The 60+ grammar mapping is an integration surface, not a claim that all language-specific semantic analyzers are complete.
