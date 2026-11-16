"""Tree-sitter refinement of the lexical code model, where a grammar is provisioned.

When ``tree-sitter-language-pack`` is installed and the file's grammar is already on disk,
the file is parsed, and the grammar's *tags* query (the definitions and call sites the
grammar declares for code navigation), completed by patterns PDT adds where a bundled
query has gaps, supplies the model's symbols and calls. That gives exact definition spans
and nesting; method containers (enclosing classes and namespaces, Go receiver types, Rust
``impl`` blocks, C++ ``Type::method`` scopes); call sites the lexer cannot see, such as
Kotlin trailing-lambda calls; and no false calls or functions from prototypes and
declarations.

Everything else comes from the lexical model built first, so both backends keep one
contract. The cleaned text, the brace and parenthesis pairs that the lexical analyses
use, string spans, imports and C/C++ macros are the lexer's. Bodies are the same
``{``/``}`` offsets in the cleaned text. Receivers are read from the cleaned text exactly
as the lexer reads them. References are recounted against the refined definitions.

Regions the tree does not structure (error nodes, Rust macro arguments and ``macro_rules!``
bodies, C/C++ ``#define`` bodies) keep the lexer's definitions and calls.

Grammars are never downloaded. The lexical model is kept when no grammar is provisioned,
when ``PDT_CODE_MODEL=lexical`` is set, when error nodes cover more than 20% of the
parse, when the tree nests deeper than 4,096 levels (Tree-sitter's query cursor slows
down quadratically on such trees), and on any failure.
"""
from __future__ import annotations

import bisect
import importlib
import os
import re
import threading
from collections import Counter

from . import FUNCTION_KINDS, Call, FileModel, Symbol
from .lexical import (
    _CONTAINER_KINDS,
    _IDENTIFIER,
    _NOT_NAMES,
    LEXICAL_LANGUAGES,
    _exported,
    _statement_prefix,
    call_receiver,
    identifier_references,
    js_exported_names,
)

# Lexically modelled language -> the grammar whose tags query refines it.
MODEL_GRAMMARS = {
    "C": "c", "C++": "cpp", "C/C++ Header": "cpp", "CUDA": "cuda", "Arduino Sketch": "arduino",
    "Java": "java", "C#": "csharp", "Kotlin": "kotlin", "Scala": "scala", "Swift": "swift",
    "JavaScript": "javascript", "TypeScript": "typescript", "Go": "go", "Rust": "rust",
    "PHP": "php", "Solidity": "solidity",
}
# Grammars that extend another: the base grammar's tags query and patterns apply too.
_BASE = {"typescript": "javascript", "tsx": "javascript", "cuda": "cpp", "arduino": "cpp"}

_C_CALLS = (
    "(call_expression function: (identifier) @name) @reference.call",
    "(call_expression function: (field_expression field: (field_identifier) @name)) @reference.call",
)
# Definitions and calls the bundled tags queries miss. Each pattern is compiled on its own
# first and dropped if this grammar version lacks one of its node types or fields.
_EXTRA_PATTERNS = {
    "c": _C_CALLS,
    "cpp": (
        "(call_expression function: (qualified_identifier name: (identifier) @name)) @reference.call",
        "(call_expression function: (template_function name: (identifier) @name)) @reference.call",
        "(call_expression function: (qualified_identifier name: (template_function name: (identifier) @name)))"
        " @reference.call",
        "(new_expression type: (_) @name) @reference.class",
        # The declarator, at any depth below the definition (``T *f()``, ``T &f()``); a
        # declarator outside a function definition is a prototype and is dropped.
        "(function_declarator declarator: (identifier) @name) @definition.function",
        "(function_declarator declarator: (field_identifier) @name) @definition.method",
        "(function_declarator declarator: (qualified_identifier name: (identifier) @name)) @definition.method",
        "(function_declarator declarator: (qualified_identifier name:"
        " (qualified_identifier name: (identifier) @name))) @definition.method",
        "(function_declarator declarator: (qualified_identifier name: (qualified_identifier name:"
        " (qualified_identifier name: (identifier) @name)))) @definition.method",
        "(struct_specifier name: (type_identifier) @name body: (_)) @definition.class",
        # Specializations (``struct S<T *> {}``) and out-of-namespace definitions (``struct a::S {}``).
        "(struct_specifier name: (template_type name: (type_identifier) @name) body: (_)) @definition.class",
        "(class_specifier name: (template_type name: (type_identifier) @name) body: (_)) @definition.class",
        "(struct_specifier name: (qualified_identifier name: (type_identifier) @name) body: (_)) @definition.class",
        "(class_specifier name: (qualified_identifier name: (type_identifier) @name) body: (_)) @definition.class",
        "(struct_specifier name: (qualified_identifier name: (template_type name: (type_identifier) @name))"
        " body: (_)) @definition.class",
        "(class_specifier name: (qualified_identifier name: (template_type name: (type_identifier) @name))"
        " body: (_)) @definition.class",
        "(union_specifier name: (type_identifier) @name body: (_)) @definition.class",
        "(enum_specifier name: (type_identifier) @name body: (_)) @definition.class",
        "(type_definition declarator: (type_identifier) @name) @definition.type",
        "(alias_declaration name: (type_identifier) @name) @definition.type",
        "(namespace_definition name: (_) @name) @definition.module",
    ),
    "java": (
        "(object_creation_expression type: (_) @name) @reference.class",
        "(enum_declaration name: (identifier) @name) @definition.class",
        "(record_declaration name: (identifier) @name) @definition.class",
    ),
    "csharp": (
        "(invocation_expression function: (identifier) @name) @reference.call",
        "(invocation_expression function: (member_access_expression name: (identifier) @name)) @reference.call",
        "(invocation_expression function: (generic_name (identifier) @name)) @reference.call",
        "(object_creation_expression type: (_) @name) @reference.class",
        "(constructor_declaration name: (identifier) @name) @definition.method",
        "(struct_declaration name: (identifier) @name) @definition.class",
        "(interface_declaration name: (identifier) @name) @definition.interface",
        "(enum_declaration name: (identifier) @name) @definition.class",
        "(record_declaration name: (identifier) @name) @definition.class",
        "(namespace_declaration name: (_) @name) @definition.module",
        "(local_function_statement name: (identifier) @name) @definition.function",
    ),
    "kotlin": (
        "(object_declaration (type_identifier) @name) @definition.class",
    ),
    "scala": (
        "(call_expression function: (identifier) @name) @reference.call",
        "(call_expression function: (field_expression field: (identifier) @name)) @reference.call",
        "(instance_expression (type_identifier) @name) @reference.class",
        "(trait_definition name: (identifier) @name) @definition.interface",
        # Abstract members (``def find(k: K): V`` in a trait), as for Java interfaces.
        "(function_declaration name: (identifier) @name) @definition.method",
    ),
    "swift": (
        "(call_expression (simple_identifier) @name) @reference.call",
        "(call_expression (navigation_expression suffix: (navigation_suffix suffix: (simple_identifier) @name)))"
        " @reference.call",
        "(protocol_declaration name: (type_identifier) @name) @definition.interface",
        # ``extension Service {`` names the extended type through a user_type node.
        "(class_declaration name: (user_type (type_identifier) @name)) @definition.class",
    ),
    "go": (
        # Interface methods (``method_elem``; ``method_spec`` in older grammar versions).
        "(method_elem name: (field_identifier) @name) @definition.method",
        "(method_spec name: (field_identifier) @name) @definition.method",
    ),
    "javascript": (
        '(call_expression function: (identifier) @name (#eq? @name "require")) @reference.call',
        # The bundled query leaves out constructors (and private ``#methods``).
        "(method_definition name: [(property_identifier) (private_property_identifier)] @name) @definition.method",
        "(field_definition property: [(property_identifier) (private_property_identifier)] @name"
        " value: [(arrow_function) (function_expression)]) @definition.method",
    ),
    "typescript": (
        "(public_field_definition name: [(property_identifier) (private_property_identifier)] @name"
        " value: [(arrow_function) (function_expression)]) @definition.method",
        "(enum_declaration name: (identifier) @name) @definition.class",
        "(type_alias_declaration name: (type_identifier) @name) @definition.type",
        "(internal_module name: (_) @name) @definition.module",
        "(interface_declaration name: (type_identifier) @name) @definition.interface",
    ),
    "rust": (
        "(call_expression function: (scoped_identifier name: (identifier) @name)) @reference.call",
        "(call_expression function: (generic_function function: (identifier) @name)) @reference.call",
        "(call_expression function: (generic_function function: (scoped_identifier name: (identifier) @name)))"
        " @reference.call",
        "(call_expression function: (generic_function function: (field_expression field: (field_identifier) @name)))"
        " @reference.call",
        "(function_signature_item name: (identifier) @name) @definition.method",
        "(impl_item type: (_) @name) @definition.impl",
        "(mod_item name: (identifier) @name body: (_)) @definition.module",
        "(enum_item name: (type_identifier) @name) @definition.class",
        "(union_item name: (type_identifier) @name) @definition.class",
        "(trait_item name: (type_identifier) @name) @definition.interface",
    ),
    "php": (
        "(scoped_call_expression name: (name) @name) @reference.call",
        "(nullsafe_member_call_expression name: (name) @name) @reference.call",
        "(object_creation_expression (name) @name) @reference.class",
        "(object_creation_expression (qualified_name) @name) @reference.class",
        "(interface_declaration name: (name) @name) @definition.interface",
        "(trait_declaration name: (name) @name) @definition.class",
        "(enum_declaration name: (name) @name) @definition.class",
    ),
    "solidity": (
        # The bundled query tags functions in contracts and at file level only.
        "(library_declaration body: (_ (function_definition name: (identifier) @name) @definition.method))",
        "(interface_declaration body: (_ (function_definition name: (identifier) @name) @definition.method))",
        '(constructor_definition "constructor" @name) @definition.method',
        "(modifier_definition name: (identifier) @name) @definition.function",
        "(interface_declaration name: (identifier) @name) @definition.interface",
        "(library_declaration name: (identifier) @name) @definition.class",
        "(struct_declaration name: (identifier) @name) @definition.class",
        "(enum_declaration name: (identifier) @name) @definition.class",
    ),
}
_EXTRA_PATTERNS["tsx"] = _EXTRA_PATTERNS["typescript"]

_TAG_KINDS = frozenset({
    "class", "interface", "module", "struct", "enum", "trait", "object", "type", "impl",
    "function", "method", "constructor",
})
_CALL_TAGS = frozenset({"reference.call", "reference.send"})
_CONSTRUCTIONS = frozenset({"new_expression", "object_creation_expression", "instance_expression"})
# Nodes between a C/C++ function's name and its definition (or its prototype).
_DECLARATORS = frozenset({
    "function_declarator", "pointer_declarator", "reference_declarator", "parenthesized_declarator",
    "qualified_identifier", "template_function",
})
_DECLARATION_SUFFIXES = ("_declaration", "_definition", "_item", "_specifier", "_signature")
# Tagged definitions that are not symbols: Swift subscripts (tagged by their parameter's
# name) and Solidity events.
_NOT_DEFINITIONS = frozenset({"subscript_declaration", "event_definition"})
# Statement keywords; an unexpanded C macro before ``if (...) {`` reads as a definition.
_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "catch", "try", "throw", "return",
    "goto", "sizeof", "typeof", "alignof", "decltype", "defined",
})
# C and C++ reserved words that name nothing (``MACRO constexpr auto f()`` reads as ``constexpr``).
_C_KEYWORDS = _KEYWORDS | frozenset("""
    constexpr consteval constinit inline static virtual explicit noexcept template typename const
    volatile auto register extern mutable friend operator new delete struct class union enum
    namespace using typedef public private protected void int char long short unsigned signed
    float double bool true false nullptr this co_await co_return co_yield static_assert
    thread_local alignas concept requires
""".split())
_C_FAMILY = frozenset({"c", "cpp", "cuda", "arduino"})
# Definitions reachable as object properties rather than by name: ``x.f = function`` and
# ``{f: function}`` / ``{f() {}}`` outside a class. Like exported names, they are not dead code.
_PROPERTY_DEFINITIONS = frozenset({"pair", "assignment_expression", "method_definition"})
# Definitions whose function is their value: ``const f = () => {}``, ``x.f = function () {}``.
_VALUE_HOLDERS = frozenset({
    "variable_declarator", "assignment_expression", "pair", "public_field_definition", "field_definition",
})
_BODY_TYPES = frozenset({
    "class_body", "function_body", "block", "statement_block", "compound_statement", "declaration_list",
    "field_declaration_list", "enum_body", "enum_class_body", "interface_body", "template_body",
    "protocol_body", "enum_variant_list", "object_type", "contract_body", "enumerator_list",
})
# Kinds by node type, as the lexer names them; other definitions take the tag's kind.
_NODE_KINDS = {
    "struct_specifier": "struct", "union_specifier": "union", "enum_specifier": "enum",
    "class_specifier": "class", "namespace_definition": "namespace", "type_definition": "type",
    "class_declaration": "class", "interface_declaration": "interface", "enum_declaration": "enum",
    "record_declaration": "record", "struct_declaration": "struct", "annotation_type_declaration": "interface",
    "namespace_declaration": "namespace", "file_scoped_namespace_declaration": "namespace",
    "object_declaration": "object", "object_definition": "object", "trait_definition": "trait",
    "class_definition": "class", "protocol_declaration": "protocol", "trait_declaration": "trait",
    "struct_item": "struct", "enum_item": "enum", "trait_item": "trait", "union_item": "union",
    "mod_item": "module", "impl_item": "impl", "type_item": "type",
    "abstract_class_declaration": "class", "internal_module": "namespace", "module": "namespace",
    "type_alias_declaration": "type", "contract_declaration": "contract", "library_declaration": "library",
    "constructor_declaration": "constructor", "init_declaration": "constructor",
}
_SWIFT_KINDS = {"class": "class", "struct": "struct", "enum": "enum", "extension": "extension", "actor": "class"}
_CONSTRUCTOR_NAMES = frozenset({"constructor", "__construct"})
# Regions the tree does not structure; the lexer's definitions and calls there are kept:
# error nodes, Rust macro arguments and ``macro_rules!`` bodies, C/C++ ``#define`` bodies.
_OPAQUE_PATTERNS = {
    "": ("(ERROR) @opaque",),
    "rust": ("(macro_invocation (token_tree) @opaque)", "(macro_definition) @opaque"),
    "c": ("(preproc_arg) @opaque",),
    "cpp": ("(preproc_arg) @opaque",),
}
_NAME = re.compile(r"[A-Za-z_$][\w$]*")
_MAX_ERROR_SHARE = 0.2
# The deepest of 1,124 real npm JavaScript files measured 53 levels.
_MAX_DEPTH = 4_096
_MAX_SYMBOLS = 20_000
_MAX_CALLS = 200_000

_state = threading.local()
_queries: dict[str, object] = {}
_queries_lock = threading.Lock()
_downloaded: tuple[object, frozenset[str]] | None = None


def model_grammar(language: str, path: str) -> str | None:
    """The grammar that refines this file's lexical model, if PDT has one for its language."""
    if os.environ.get("PDT_CODE_MODEL", "").strip().lower() == "lexical":
        return None
    if language == "TypeScript" and path.lower().endswith(".tsx"):
        return "tsx"
    return MODEL_GRAMMARS.get(language)


def _pack():
    try:
        return importlib.import_module("tree_sitter_language_pack")
    except ImportError:
        return None


def grammar_provisioned(pack, grammar: str) -> bool:
    """True only when the grammar is already on disk; this never downloads.

    tree-sitter-language-pack 1.23+ downloads a missing grammar inside ``get_parser()``
    and ``get_language()``, so nothing else of the pack is called before this check. The
    set of downloaded grammars is read once per process.
    """
    global _downloaded
    if hasattr(pack, "downloaded_languages"):
        cached = _downloaded
        if cached is None or cached[0] is not pack:
            cached = _downloaded = (pack, frozenset(pack.downloaded_languages()))
        return grammar in cached[1]
    if hasattr(pack, "has_parser"):
        return bool(pack.has_parser(grammar))
    return False


def available(grammar: str) -> bool:
    pack = _pack()
    try:
        return pack is not None and grammar_provisioned(pack, grammar) and _query(pack, grammar) is not None
    except Exception:  # noqa: BLE001 - a broken pack or grammar means "not available"
        return False


def _query(pack, grammar: str):
    """The grammar's tags query plus the extra patterns that compile; None if nothing does."""
    with _queries_lock:
        if grammar in _queries:
            return _queries[grammar]
    import tree_sitter

    language = pack.get_language(grammar)
    base = _BASE.get(grammar)
    tags = [pack.get_tags_query(base) if base else None, pack.get_tags_query(grammar),
            *_EXTRA_PATTERNS.get(base or "", ()), *_EXTRA_PATTERNS.get(grammar, ())]
    opaque = [*_OPAQUE_PATTERNS[""], *(_OPAQUE_PATTERNS.get(base, ()) if base else ()),
              *_OPAQUE_PATTERNS.get(grammar, ())]

    def compiled(sources) -> list[str]:
        valid = []
        for source in sources:
            if not source:
                continue
            try:
                tree_sitter.Query(language, source)
            except Exception:  # noqa: BLE001 - a node type or field this grammar version lacks
                continue
            valid.append(source)
        return valid

    valid = compiled(tags)
    query = tree_sitter.Query(language, "\n".join(valid + compiled(opaque))) if valid else None
    with _queries_lock:
        _queries[grammar] = query
    return query


def _parser(pack, grammar: str):
    parsers = getattr(_state, "parsers", None)
    if parsers is None:
        parsers = _state.parsers = {}
    if grammar not in parsers:
        parsers[grammar] = pack.get_parser(grammar)
    return parsers[grammar]


class _Offsets:
    """Character offsets in the model's text for UTF-8 byte offsets of the parse."""

    def __init__(self, text: str, data: bytes) -> None:
        self.data = data
        self.identity = len(text) == len(data)
        if not self.identity:
            self.byte_lines, self.char_lines = [0], [0]
            for line in text.splitlines(keepends=True):
                self.byte_lines.append(self.byte_lines[-1] + len(line.encode("utf-8", "surrogatepass")))
                self.char_lines.append(self.char_lines[-1] + len(line))

    def char(self, byte: int) -> int:
        if self.identity:
            return byte
        index = bisect.bisect_right(self.byte_lines, byte) - 1
        start = self.byte_lines[index]
        return self.char_lines[index] + len(self.data[start:byte].decode("utf-8", "surrogatepass"))


def _deeper_than(root, limit: int) -> bool:
    """Whether the tree nests deeper than ``limit``; stops as soon as it does."""
    cursor = root.walk()
    depth = 0
    while True:
        if cursor.goto_first_child():
            depth += 1
            if depth > limit:
                return True
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return False
            depth -= 1


def _error_bytes(root) -> int:
    """Bytes covered by error nodes (missing nodes count one each); only error paths are walked."""
    total = 0
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_error:
            total += max(node.end_byte - node.start_byte, 1)
        elif node.is_missing:
            total += 1
        elif node.has_error:
            stack.extend(node.children)
    return total


def refine(model: FileModel, grammar: str) -> FileModel:
    """``model`` with symbols and calls from the syntax tree; ``model`` itself on any failure."""
    pack = _pack()
    if pack is None:
        return model
    try:
        if not grammar_provisioned(pack, grammar):
            return model
        return _refine(pack, model, grammar) or model
    except Exception:  # noqa: BLE001 - any parser or query failure keeps the lexical model
        return model


def _refine(pack, model: FileModel, grammar: str) -> FileModel | None:
    query = _query(pack, grammar)
    if query is None:
        return None
    import tree_sitter

    data = model.text.encode("utf-8", "surrogatepass")
    root = _parser(pack, grammar).parse(data).root_node
    if root.has_error and _error_bytes(root) > _MAX_ERROR_SHARE * max(len(data), 1):
        return None
    # Tree-sitter's query cursor slows down quadratically below depth 32,767 (a 300 KB
    # file of nested calls took minutes), so pathologically deep trees keep the lexer.
    if root.descendant_count > _MAX_DEPTH and _deeper_than(root, _MAX_DEPTH):
        return None
    definitions: dict[int, tuple[str, object, object]] = {}   # name byte -> (tag kind, name, node)
    references: dict[int, object] = {}                         # name byte -> name node
    opaque: list[tuple[int, int]] = []
    for _pattern, captures in tree_sitter.QueryCursor(query).matches(root):
        regions = captures.get("opaque")
        if regions:
            opaque.extend((node.start_byte, node.end_byte) for node in regions)
            continue
        names = captures.get("name")
        if not names:
            continue
        name = names[0]
        for tag, nodes in captures.items():
            if not nodes or tag == "name":
                continue
            if tag.startswith("definition."):
                kind = tag[len("definition."):]
                if kind in _TAG_KINDS and name.start_byte not in definitions:
                    node = _definition_node(name, nodes[0])
                    if node is not None:
                        definitions[name.start_byte] = (kind, name, node)
            elif tag in _CALL_TAGS or (tag == "reference.class" and nodes[0].type in _CONSTRUCTIONS):
                # ``(identifier) @name @reference.call`` tags every identifier, and macros
                # (Rust ``println!``) are not calls, as for the lexer.
                if nodes[0].id != name.id and nodes[0].type != "macro_invocation":
                    references.setdefault(name.start_byte, name)
    offsets = _Offsets(model.text, data)
    symbols, spans, names = _symbols(model, definitions.values(), offsets, grammar)
    sites = _sites(references.values(), offsets)
    regions = _regions(opaque, offsets)
    if regions:
        # The lexer's definitions and calls where the tree has no structure to read them from.
        starts = [start for start, _end in regions]

        def inside(offset: int) -> bool:
            index = bisect.bisect_right(starts, offset) - 1
            return index >= 0 and offset < regions[index][1]

        for item in model.symbols:
            if item.kind != "macro" and item.offset >= 0 and item.offset not in names and inside(item.offset):
                symbols.append(item)
                names[item.offset] = item.name
                if item.kind in FUNCTION_KINDS and item.body:
                    spans.append((item.body[0], item.body[1], item.qualified))
        found = {offset for offset, _callee in sites}
        sites += [(call.offset, call.callee) for call in model.calls
                  if call.offset >= 0 and call.offset not in found and inside(call.offset)]
    symbols.sort(key=lambda item: item.offset)
    refined = FileModel(model.path, model.language, "tree-sitter", model.text)
    refined.symbols = symbols + [item for item in model.symbols if item.kind == "macro"]
    refined.calls = _calls(model, sites, spans, set(names))
    refined.imports = model.imports
    refined.clean, refined.strings = model.clean, model.strings
    refined.braces, refined.parens = model.braces, model.parens
    counts = model._identifier_counts
    if counts is None:
        counts = Counter(_IDENTIFIER.findall(model.clean))
    refined._identifier_counts = counts
    refined.references = identifier_references(counts, names.values())
    return refined


def _regions(spans: list[tuple[int, int]], offsets: _Offsets) -> list[tuple[int, int]]:
    """Outermost [start, end) character spans of the opaque byte spans, in order."""
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        elif end > start:
            merged.append([start, end])
    return [(offsets.char(start), offsets.char(end)) for start, end in merged]


def _definition_node(name, captured):
    """The node that defines ``name``: the captured node, or the declaration nearest the name."""
    node = name.parent
    while node is not None and node.type in _DECLARATORS:
        node = node.parent
    if captured.type in _DECLARATORS or captured.id == name.id:
        # C and C++ tags name the declarator: only a function definition defines; a prototype declares.
        return node if node is not None and node.type == "function_definition" else None
    probe = name.parent
    while probe is not None and probe.id != captured.id and not probe.type.endswith(_DECLARATION_SUFFIXES):
        probe = probe.parent   # Swift tags capture the class for each of its methods
    if probe is None or probe.type in _NOT_DEFINITIONS:
        return None
    if probe.type.endswith("_specifier") and probe.child_by_field_name("body") is None:
        return None   # ``struct stat st;`` and ``class Foo;`` name a type; they do not define one
    return probe


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _type_name(text: str) -> str:
    """``Foo`` for ``Foo<T>``, ``a::b::Foo``, ``&'a mut Foo`` and similar type spellings."""
    words = _NAME.findall(text.split("<", 1)[0])
    return words[-1] if words else ""


def _name_and_scope(name, node, grammar: str) -> tuple[str, str, int]:
    """The definition's simple name, the scope its own spelling names, and the name's byte."""
    if node.type == "impl_item":
        text = _text(name)
        simple = _type_name(text)
        position = text.split("<", 1)[0].rfind(simple)
        return simple, "", name.start_byte + len(text[:max(position, 0)].encode("utf-8", "surrogatepass"))
    if grammar == "go" and node.type == "method_declaration":
        receiver = node.child_by_field_name("receiver")
        types = []
        stack = [receiver] if receiver is not None else []
        while stack and not types:
            current = stack.pop()
            if current.type == "type_identifier":
                types.append(current)
            stack.extend(reversed(current.children))
        return _text(name), _text(types[0]) if types else "", name.start_byte
    parent = name.parent
    if parent is not None and parent.type == "template_type":   # ``struct a::S<T *> {}``
        parent = parent.parent
    if parent is not None and parent.type == "qualified_identifier":   # C++ ``Type::method``
        scopes = []
        while parent is not None and parent.type == "qualified_identifier":
            scope = parent.child_by_field_name("scope")
            if scope is not None:
                scopes.append(_text(scope).split("<", 1)[0].replace("::", ".").strip())
            parent = parent.parent
        return _text(name), ".".join(item for item in reversed(scopes) if item), name.start_byte
    return _text(name).replace("::", "."), "", name.start_byte


def _kind(tag_kind: str, node, grammar: str) -> str:
    if node.type == "type_spec":   # Go
        value = node.child_by_field_name("type")
        return {"struct_type": "struct", "interface_type": "interface"}.get(value.type if value else "", "type")
    if grammar == "swift" and node.type == "class_declaration":
        keyword = node.child_by_field_name("declaration_kind")
        return _SWIFT_KINDS.get(keyword.type if keyword is not None else "", "class")
    if grammar == "kotlin" and node.type == "class_declaration":
        return "interface" if any(child.type == "interface" for child in node.children) else "class"
    return _NODE_KINDS.get(node.type, tag_kind)


def _body(model: FileModel, node, offsets: _Offsets):
    """The brace body (offsets of ``{`` and ``}`` in the cleaned text, as the lexer gives
    them) and the span the definition's calls are attributed by."""
    holder = node
    if node.type in _VALUE_HOLDERS:
        holder = node.child_by_field_name("value") or node.child_by_field_name("right")
        if holder is None:
            return None, None
    elif node.type == "type_spec":
        holder = node.child_by_field_name("type") or node
    body = holder.child_by_field_name("body")
    if body is None:
        body = next((child for child in holder.children if child.type in _BODY_TYPES), None)
    clean, braces = model.clean, model.braces
    if body is None:   # Go ``interface { ... }`` holds its braces directly
        brace = next((child for child in holder.children if child.type == "{"), None)
        start = offsets.char(brace.start_byte) if brace is not None else -1
        close = braces.get(start)
        return ((start, close), (start, close)) if close is not None else (None, None)
    start, end = offsets.char(body.start_byte), offsets.char(body.end_byte) - 1
    if end < start:
        return None, None
    if clean[start] != "{":
        return None, (start, end)   # an expression body: ``fun f() = g()``, ``x => g(x)``
    close = braces.get(start)
    if close is None:
        if clean[end] != "}":
            return None, (start, end)
        close = end
    return (start, close), (start, close)


def _symbols(model: FileModel, definitions, offsets: _Offsets, grammar: str):
    family = LEXICAL_LANGUAGES[model.language]
    exported_names = js_exported_names(model.clean) if family == "js" else set()
    keywords = _C_KEYWORDS if grammar in _C_FAMILY else _KEYWORDS
    lexical = {(item.name, item.line): item for item in model.symbols}
    ordered = sorted(definitions, key=lambda item: (item[2].start_byte, -item[2].end_byte))[:_MAX_SYMBOLS]
    stack: list[tuple[int, str, str]] = []   # (end byte, qualified, kind) of enclosing definitions
    symbols: list[Symbol] = []
    spans: list[tuple[int, int, str]] = []
    names: dict[int, str] = {}               # name offset -> name
    values: set[int] = set()                 # functions that are a definition's value
    for tag_kind, name_node, node in ordered:
        while stack and stack[-1][0] <= node.start_byte:
            stack.pop()
        if node.id in values:
            continue   # ``x = function name() {}`` is one definition, named as it is assigned
        name, scope, name_byte = _name_and_scope(name_node, node, grammar)
        if not name or name in keywords:
            continue   # ``MACRO if (x) {`` parses as a function named ``if``
        enclosing, enclosing_kind = (stack[-1][1], stack[-1][2]) if stack else ("", "")
        if scope:
            container = scope if not enclosing or scope.startswith(enclosing + ".") else f"{enclosing}.{scope}"
        else:
            container = enclosing
        kind = _kind(tag_kind, node, grammar)
        if kind in FUNCTION_KINDS and kind != "constructor":
            # As for the lexer, a method is a function of a type (an object literal's is not).
            in_type = bool(scope) or enclosing_kind in _CONTAINER_KINDS
            kind = "method" if in_type else "function"
            if in_type and (container.rsplit(".", 1)[-1] == name or name in _CONSTRUCTOR_NAMES):
                kind = "constructor"
        qualified = f"{container}.{name}" if container else name
        name_offset = offsets.char(name_byte)
        start = offsets.char(node.start_byte)
        line = model.line_of(name_offset)
        body, span = _body(model, node, offsets)
        end_line = model.line_of(body[1]) if body else model.line_of(max(offsets.char(node.end_byte) - 1, name_offset))
        previous = lexical.get((name, line))
        if previous is not None:
            exported, is_async = previous.exported, previous.is_async
        else:
            prefix = _statement_prefix(model.clean, start) + model.clean[start:name_offset]
            exported = _exported(family, name, prefix, kind, exported_names)
            is_async = "async" in prefix.split()
        if node.type in _PROPERTY_DEFINITIONS and kind == "function" and (
            node.type != "assignment_expression" or name_node.parent.type == "member_expression"
        ):
            exported = True
        symbols.append(Symbol(kind, name, qualified, line, end_line, container, exported,
                              is_async=is_async, body=body, offset=name_offset))
        names[name_offset] = name
        if node.type in _VALUE_HOLDERS:
            value = node.child_by_field_name("value") or node.child_by_field_name("right")
            if value is not None:
                values.add(value.id)
        stack.append((node.end_byte, qualified, kind))
        if kind in FUNCTION_KINDS and span is not None:
            spans.append((span[0], span[1], qualified))
    return symbols, spans, names


def _sites(references, offsets: _Offsets) -> list[tuple[int, str]]:
    """(offset, callee) of each call the tree names; the callee is the last name written."""
    sites = []
    for name_node in references:
        # ``pkg.Thing``, ``List<T>``, ``\\App\\Thing``: the last name is the callee.
        found = list(_NAME.finditer(_text(name_node).split("<", 1)[0]))
        if not found or found[-1].group() in _NOT_NAMES:
            continue
        sites.append((offsets.char(name_node.start_byte) + found[-1].start(), found[-1].group()))
    return sites


def _calls(model: FileModel, sites, spans, definition_offsets: set[int]) -> list[Call]:
    """Call sites attributed to their innermost enclosing function, in one sweep as the lexer does."""
    sites.sort()
    spans.sort()
    calls: list[Call] = []
    open_spans: list[tuple[int, str]] = []   # (end, qualified), innermost last
    next_span = 0
    clean = model.clean
    for offset, callee in sites[:_MAX_CALLS]:
        while next_span < len(spans) and spans[next_span][0] < offset:
            start, end, qualified = spans[next_span]
            while open_spans and open_spans[-1][0] < start:
                open_spans.pop()
            open_spans.append((end, qualified))
            next_span += 1
        while open_spans and open_spans[-1][0] < offset:
            open_spans.pop()
        if offset in definition_offsets:
            continue
        caller = open_spans[-1][1] if open_spans else "<module>"
        calls.append(Call(caller, callee, call_receiver(clean, offset), "", model.line_of(offset), offset))
    return calls
