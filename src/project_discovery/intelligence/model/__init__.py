"""Shared, per-file structural model of source code.

Many analyzers need the same structure: definitions, call sites, imports and the
identifiers a file references. :func:`model_for` builds it once per file and analysis
thread and serves it to every analyzer of that file.

Three backends exist. Python uses the standard-library ``ast`` parser, so symbols, calls
and their resolution through imports and ``self`` are semantic. About 25 brace-language
families (C, C++, Java, C#, JavaScript/TypeScript, Go, Rust, Kotlin, Swift, PHP and
others) use a linear-time structural lexer: comments and string contents are blanked
while offsets are kept, braces are matched, and definitions, calls and imports are read
from the cleaned text. Where a Tree-sitter grammar for the language is provisioned
locally, ``tree_sitter_model`` replaces the lexer's symbols and calls with ones read from
the syntax tree and keeps the rest of the lexical model. Lexical and Tree-sitter results
carry no type resolution and are reported as INFERRED.
"""
from __future__ import annotations

import bisect
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ...core.source_utils import SourceBudgetExceeded, read_python_source_bounded, read_text_bounded
from ...models import FileRecord

# Larger files are almost always generated or minified; they are not modelled.
MAX_MODEL_BYTES = 4 * 1024 * 1024


@dataclass(slots=True)
class Symbol:
    kind: str
    name: str
    # Qualified within the file: "Class.method"; modules are added in the index.
    qualified: str
    line: int
    end_line: int
    container: str
    exported: bool
    is_async: bool = False
    decorators: tuple[str, ...] = ()
    params: tuple[str, ...] = ()
    # Lexical and Tree-sitter backends: offsets of the body's ``{`` and ``}`` in ``FileModel.clean``.
    body: tuple[int, int] | None = None
    # Lexical and Tree-sitter backends: offset of the name in the text (-1 when unknown).
    offset: int = -1


@dataclass(slots=True)
class Call:
    caller: str
    callee: str
    receiver: str
    # Resolution hint: "" (unresolved), "@Local.name" (defined in this file),
    # "pkg.mod.name" (absolute import) or ".rel.name" (relative import).
    target: str
    line: int
    offset: int = -1


@dataclass(slots=True)
class Import:
    target: str
    line: int
    names: tuple[str, ...] = ()
    level: int = 0


@dataclass(slots=True)
class FileModel:
    path: str
    language: str
    backend: str
    text: str
    symbols: list[Symbol] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    references: set[str] = field(default_factory=set)
    # Lexical backend only: the text with comments and string contents blanked, and
    # the [start, end) spans of string literals in the original text.
    clean: str = ""
    strings: list[tuple[int, int]] = field(default_factory=list)
    # Lexical backend only: matching offsets of braces and parentheses in ``clean``.
    braces: dict[int, int] = field(default_factory=dict)
    parens: dict[int, int] = field(default_factory=dict)
    tree: object | None = None
    # Python backend only: class types of names (``python_types.TypeTable``), shared with taint.
    types: object | None = None
    _line_starts: list[int] | None = None
    # Lexical backend: occurrences of each identifier in ``clean`` (the Tree-sitter refinement reuses them).
    _identifier_counts: dict[str, int] | None = None

    def line_of(self, offset: int) -> int:
        if self._line_starts is None:
            starts = [0]
            find = self.text.find
            position = find("\n")
            while position != -1:
                starts.append(position + 1)
                position = find("\n", position + 1)
            self._line_starts = starts
        return bisect.bisect_right(self._line_starts, offset)

    def line_start(self, line: int) -> int:
        """Offset of the first character of a 1-based line (clamped to the file)."""
        self.line_of(0)
        starts = self._line_starts
        return starts[min(max(line, 1), len(starts)) - 1]

    def line_text(self, line: int) -> str:
        """The source text of a 1-based line."""
        self.line_of(0)
        starts = self._line_starts
        if not 1 <= line <= len(starts):
            return ""
        end = starts[line] - 1 if line < len(starts) else len(self.text)
        return self.text[starts[line - 1]:end].rstrip("\r")

    def string_value(self, span: tuple[int, int]) -> str:
        """The literal's contents without its quotes."""
        start, end = span
        raw = self.text[start:end]
        for quote in ('"""', "'''"):
            if raw.startswith(quote) and raw.endswith(quote) and len(raw) >= 6:
                return raw[3:-3]
        opening = 1
        while opening < len(raw) and raw[opening - 1] not in "\"'`":
            opening += 1
        return raw[opening:-1] if len(raw) > opening else ""

    def strings_between(self, start: int, end: int) -> list[tuple[int, int]]:
        index = bisect.bisect_left(self.strings, (start, -1))
        spans = []
        while index < len(self.strings) and self.strings[index][0] < end:
            spans.append(self.strings[index])
            index += 1
        return spans

    def functions(self) -> list[Symbol]:
        return [item for item in self.symbols if item.kind in FUNCTION_KINDS]


FUNCTION_KINDS = frozenset({"function", "method", "constructor"})

_memo = threading.local()


def supports_language(language: str) -> bool:
    from .lexical import LEXICAL_LANGUAGES

    return language == "Python" or language in LEXICAL_LANGUAGES


def model_for(path: Path, record: FileRecord) -> FileModel | None:
    """The file's model, built once per file and thread; None when not modelled."""
    key = (record.path, record.size_bytes, record.mtime_ns)
    cached = getattr(_memo, "entry", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    model = _build(path, record)
    _memo.entry = (key, model)
    return model


def _build(path: Path, record: FileRecord) -> FileModel | None:
    if (
        record.error or record.content_skipped_reason
        or record.size_bytes > MAX_MODEL_BYTES or not supports_language(record.language)
    ):
        return None
    try:
        if record.language == "Python":
            from .python_model import build_python_model

            source = read_python_source_bounded(
                path, MAX_MODEL_BYTES, expected_identity=record.analysis_identity,
            )
            return build_python_model(record.path, source)
        from .lexical import build_lexical_model
        from .tree_sitter_model import model_grammar

        source = read_text_bounded(
            path, MAX_MODEL_BYTES, errors="replace", expected_identity=record.analysis_identity,
        )
        model = build_lexical_model(record.path, record.language, source)
        grammar = model_grammar(record.language, record.path)
        if grammar is not None:
            from .tree_sitter_model import refine

            model = refine(model, grammar)
        return model
    except (OSError, SourceBudgetExceeded, UnicodeDecodeError, LookupError, SyntaxError,
            ValueError, RecursionError, MemoryError):
        return None
