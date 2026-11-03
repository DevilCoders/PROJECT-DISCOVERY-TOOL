# Polyglot Parser Adapter

PDT includes a generic Tree-sitter adapter for a broad language set through the optional `polyglot` extra:

```bash
python -m pip install -e ".[polyglot]"
```

The adapter uses `has_parser()` before requesting a parser. That capability check does not perform network I/O. If a grammar is not already available in the local parser cache, PDT reports the missing capability in scan metrics and skips syntax analysis for that language. It never invokes the parser pack's on-demand download path during a project scan.

This preserves local-only scan behavior: target source is not uploaded, and parser provisioning is a separate operator-controlled setup step. A syntax tree confirms parser structure and error/missing nodes; it does not prove that a program compiles, links, passes tests, or behaves correctly.

The adapter currently provides generic syntax-tree metrics and parser diagnostics. Language-specific symbol extraction, call graphs, type resolution, dataflow and framework semantics remain separate analyzer milestones. The 60+ grammar mapping is a parser integration surface, not a claim that all language-specific semantic analyzers are complete.

Parser capability status is included only for languages actually detected in the current project. The adapter checks local availability and does not download grammars.
