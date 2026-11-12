"""Record every modelled file's symbols, calls, references and imports for the index.

This analyzer produces no per-file findings of its own. It turns the shared code model
into facts; after analysis, ``code_index`` builds the symbol index, the call graph,
the polyglot module graph and test-to-code links from them.
"""
from __future__ import annotations

from pathlib import Path

from ...intelligence import facts as code_facts
from ...intelligence.model import MAX_MODEL_BYTES, model_for, supports_language
from ...intelligence.model.lexical import LEXICAL_LANGUAGES
from ...models import FileRecord, Finding
from ..base import Analyzer


def _lexical_target(caller: str, callee: str, receiver: str) -> str:
    """Resolution hint for a lexical call; the index resolves names across files."""
    # this./self. calls, and Rust's Self::new(), name the caller's own type.
    if receiver in {"this", "self", "Self"} and "." in caller:
        return f"@{caller.rsplit('.', 1)[0]}.{callee}"
    if receiver and receiver not in {"new", "<expression>"}:
        return f"~{receiver}.{callee}"
    return ""


class CodeIndexAnalyzer(Analyzer):
    name = "code-index"
    version = "1.0.0"
    description = "Symbols, call sites, references and imports for the cross-file code index."
    domains = ("symbol_index", "call_graph", "imports")
    languages = ("Python", *sorted(LEXICAL_LANGUAGES))

    def supports(self, record: FileRecord) -> bool:
        return (
            code_facts.collecting() and record.error is None
            and record.content_skipped_reason is None and supports_language(record.language)
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > MAX_MODEL_BYTES:
            return [Finding(
                "symbol_index",
                f"Code index budget exceeded: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the {MAX_MODEL_BYTES:,}-byte code "
                "model budget, so its symbols and calls are not in the index or call graph.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW",
            )]
        model = model_for(path, record)
        if model is None:
            return []
        code_facts.emit_fact("code_model", model.backend, language=model.language)
        for symbol in model.symbols:
            # Decorated Python functions are registered by frameworks, so count them as used.
            exported = symbol.exported or bool(symbol.decorators)
            code_facts.emit_symbol(
                model.language, symbol.kind, symbol.name, symbol.qualified,
                symbol.line, symbol.end_line, exported,
            )
        python = model.backend == "python-ast"
        for call in model.calls:
            target = call.target if python else _lexical_target(call.caller, call.callee, call.receiver)
            code_facts.emit_call(call.caller, call.callee, target, call.line)
        code_facts.emit_references(model.references)
        for item in model.imports:
            code_facts.emit_fact(
                "import", item.target, line=item.line, level=item.level,
                names=list(item.names[:50]), language=model.language,
            )
        return []
