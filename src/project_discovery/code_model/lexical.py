"""Linear-time structural lexer for brace-delimited languages.

1. **Clean.** One pass finds each comment or string opener and consumes the construct
   with a bounded rule: a line comment ends at the newline, a block comment at ``*/``
   (or end of file), a quoted string at its closing quote on the same line. Comments
   and string contents become spaces in ``FileModel.clean``, so offsets and line
   numbers are preserved and code inside comments or strings is never mistaken for
   code. An unterminated multi-line construct ends the scan instead of being retried,
   which keeps hostile input linear.
2. **Match.** Braces and parentheses are paired with stacks.
3. **Extract.** Keyword-introduced definitions (``class``, ``fn``, ``func``,
   ``function``...), C-style typed definitions (``Type name(...) {``), macros, call
   sites and imports are read from the cleaned text. Definitions nest by brace ranges,
   which gives qualified names such as ``Outer.Inner.method``.

The result is structural, not semantic: there is no type resolution or overload
selection, and macros are not expanded.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from . import Call, FileModel, Import, Symbol

_MAX_STRINGS = 50_000
_MAX_REFERENCES = 10_000
_SIGNATURE_LOOKAHEAD = 400
_NON_NEWLINE = re.compile(r"[^\n]")
_TERMINATOR = re.compile(r"[{;}]")
_SCRIPT_BLOCK = re.compile(r"(?is)<script\b[^>]{0,2000}+>(.*?)</script\s*>")


@dataclass(frozen=True)
class LexicalSpec:
    family: str
    line_comments: tuple[str, ...] = ("//",)
    block_comments: bool = True
    string_quotes: str = '"'          # quotes that always start a string
    char_quote: bool = True           # ' starts a one-character literal (else a string)
    backtick: str = ""                # "template" (escapes, multi-line) or "raw"
    triple_quotes: bool = False
    verbatim: bool = False            # C# @"..."
    cpp_raw: bool = False             # C++ R"delim(...)delim"
    rust_raw: bool = False            # Rust r"..." / r#"..."#
    type_keywords: tuple[tuple[str, str], ...] = ()
    function_keywords: tuple[str, ...] = ()
    typed_functions: bool = True      # C-style ``Type name(...) {`` definitions
    untyped_methods: bool = False     # ``name(...) {`` methods inside class bodies (JS/TS)
    nested_functions: bool = False
    bodiless_types: bool = False      # Kotlin/Scala ``data class P(val x: Int)``


_C_TYPES = (("struct", "struct"), ("union", "union"), ("enum", "enum"))
_CPP_TYPES = (("class", "class"), ("struct", "struct"), ("union", "union"),
              ("enum", "enum"), ("namespace", "namespace"))

_SPECS = {
    "c": LexicalSpec("c", type_keywords=_C_TYPES),
    "cpp": LexicalSpec("cpp", cpp_raw=True, type_keywords=_CPP_TYPES),
    "java": LexicalSpec("java", triple_quotes=True, type_keywords=(
        ("class", "class"), ("interface", "interface"), ("enum", "enum"), ("record", "record"))),
    "csharp": LexicalSpec("csharp", verbatim=True, triple_quotes=True, nested_functions=True,
                          type_keywords=(("class", "class"), ("struct", "struct"),
                                         ("interface", "interface"), ("enum", "enum"),
                                         ("record", "record"), ("namespace", "namespace"))),
    "kotlin": LexicalSpec("kotlin", triple_quotes=True, typed_functions=False, nested_functions=True,
                          function_keywords=("fun",), bodiless_types=True,
                          type_keywords=(("class", "class"), ("interface", "interface"),
                                         ("object", "object"))),
    "scala": LexicalSpec("scala", triple_quotes=True, typed_functions=False, nested_functions=True,
                         function_keywords=("def",), bodiless_types=True,
                         type_keywords=(("class", "class"), ("trait", "trait"), ("object", "object"))),
    "groovy": LexicalSpec("groovy", string_quotes="\"'", char_quote=False, triple_quotes=True,
                          nested_functions=True, function_keywords=("def",),
                          type_keywords=(("class", "class"), ("interface", "interface"),
                                         ("trait", "trait"), ("enum", "enum"))),
    "swift": LexicalSpec("swift", char_quote=False, triple_quotes=True, typed_functions=False,
                         nested_functions=True, function_keywords=("func",),
                         type_keywords=(("class", "class"), ("struct", "struct"), ("enum", "enum"),
                                        ("protocol", "protocol"), ("extension", "extension"),
                                        ("actor", "class"))),
    "dart": LexicalSpec("dart", string_quotes="\"'", char_quote=False, triple_quotes=True,
                        nested_functions=True,
                        type_keywords=(("class", "class"), ("mixin", "mixin"), ("enum", "enum"),
                                       ("extension", "extension"))),
    "js": LexicalSpec("js", string_quotes="\"'", char_quote=False, backtick="template",
                      typed_functions=False, untyped_methods=True, nested_functions=True,
                      function_keywords=("function",),
                      type_keywords=(("class", "class"), ("interface", "interface"),
                                     ("enum", "enum"), ("namespace", "namespace"))),
    "go": LexicalSpec("go", backtick="raw", typed_functions=False, nested_functions=True,
                      function_keywords=("func",)),
    "rust": LexicalSpec("rust", rust_raw=True, typed_functions=False, nested_functions=True,
                        function_keywords=("fn",),
                        type_keywords=(("struct", "struct"), ("enum", "enum"), ("trait", "trait"),
                                       ("union", "union"), ("mod", "module"))),
    "php": LexicalSpec("php", line_comments=("//", "#"), string_quotes="\"'", char_quote=False,
                       typed_functions=False, nested_functions=True, function_keywords=("function",),
                       type_keywords=(("class", "class"), ("interface", "interface"),
                                      ("trait", "trait"), ("enum", "enum"))),
    "solidity": LexicalSpec("solidity", string_quotes="\"'", char_quote=False, typed_functions=False,
                            function_keywords=("function", "modifier"),
                            type_keywords=(("contract", "contract"), ("interface", "interface"),
                                           ("library", "library"), ("struct", "struct"),
                                           ("enum", "enum"))),
    "zig": LexicalSpec("zig", block_comments=False, typed_functions=False, function_keywords=("fn",)),
    "wgsl": LexicalSpec("wgsl", typed_functions=False, function_keywords=("fn",),
                        type_keywords=(("struct", "struct"),)),
}

LEXICAL_LANGUAGES: dict[str, str] = {
    "C": "c", "C/C++ Header": "cpp", "Objective-C": "c", "Objective-C++": "cpp",
    "C++": "cpp", "CUDA": "cpp", "OpenCL": "c", "GLSL": "c", "HLSL": "cpp",
    "Metal Shading Language": "cpp", "Java": "java", "C#": "csharp", "Kotlin": "kotlin",
    "Scala": "scala", "Groovy": "groovy", "Swift": "swift", "Dart": "dart",
    "JavaScript": "js", "TypeScript": "js", "Vue": "js", "Svelte": "js", "Go": "go",
    "Rust": "rust", "PHP": "php", "Solidity": "solidity", "Zig": "zig", "WGSL": "wgsl",
}
_CONTAINER_KINDS = frozenset({
    "class", "struct", "interface", "record", "impl", "object", "trait", "enum",
    "extension", "protocol", "contract", "library", "mixin", "union",
})
_FUNCTION_KINDS = frozenset({"function", "method", "constructor"})

# Words that look like calls or definitions but are syntax. Words that are also real
# function names somewhere (new, delete, select, match, go...) are deliberately absent:
# ``new Foo(`` only ever matches ``Foo(``, and ``go f()`` matches ``f(``.
_NOT_NAMES = frozenset("""
if for while switch catch return sizeof typeof alignof decltype else do try throw async
case using foreach lock fixed checked unchecked default goto await yield in is as instanceof
void static_assert assert defined __attribute__ __declspec asm __asm__ elif when
unsafe synchronized super this self base function fn func fun def operator noexcept requires
typeid static_cast dynamic_cast const_cast reinterpret_cast nameof with import package
""".split())
_TYPE_PRECEDERS = frozenset("return else new throw case goto await yield in is as delete typeof define".split())
_JS_METHOD_PRECEDERS = frozenset({
    "", ";", "{", "}", ",", "*", "async", "static", "get", "set", "public", "private",
    "protected", "readonly", "override", "abstract",
})

_IDENTIFIER = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*+")
_CALL = re.compile(
    r"(?<![\w$])([A-Za-z_$][\w$]*+)[ \t\r\n]*+(?:<[^<>(){};\n]{0,120}+>[ \t]*+)?\("
)
_BRACKETS = re.compile(r"[{}()]")
_FUNCTION_EXPRESSION = re.compile(
    r"(?<![\w$])(?:const|let|var)[ \t\r\n]++([A-Za-z_$][\w$]*+)[ \t\r\n]*+"
    r"(?::[^=;\n]{0,200}+)?=[ \t\r\n]*+(?:async[ \t\r\n]++)?(?=function\b|\(|[A-Za-z_$][\w$]*+[ \t]*+=>)"
)
_GO_FUNC = re.compile(r"(?<![\w$])func[ \t]*+(?:\(([^()]{0,200}+)\)[ \t]*+)?([A-Za-z_]\w*+)")
_GO_TYPE = re.compile(
    r"(?<![\w$])type[ \t]++([A-Za-z_]\w*+)[ \t]++(?:\[[^\]\n]{0,200}+\][ \t]*+)?(struct|interface)\b"
)
_RUST_IMPL = re.compile(r"(?<![\w$])impl\b")
_TYPEDEF = re.compile(r"(?<![\w$])typedef\b")
_MACRO = re.compile(r"(?m)^[ \t]*+#[ \t]*+define[ \t]++([A-Za-z_]\w*+)")
_JS_EXPORTS = re.compile(r"(?<![\w$])(?:module\.)?exports\.([A-Za-z_$][\w$]*+)[ \t]*+=")
_JS_EXPORT_LIST = re.compile(r"(?<![\w$])export[ \t]*+\{([^{}]{0,4000}+)\}")
_GENERIC_SUFFIX = re.compile(r"[<\s(].*", re.S)

# Import forms: (pattern over clean text, group holding the target or None to read the
# next string literal after the match).
_IMPORTS = {
    "c": [(re.compile(r"(?m)^[ \t]*+#[ \t]*+(?:include|import)[ \t]*+<([^>\n]{1,300})>"), 1),
          (re.compile(r"(?m)^[ \t]*+#[ \t]*+(?:include|import)[ \t]*+(?=\")"), None)],
    "java": [(re.compile(r"(?m)^[ \t]*+import[ \t]++(?:static[ \t]++)?([\w.]+(?:\.\*)?)"), 1)],
    "csharp": [(re.compile(r"(?m)^[ \t]*+(?:global[ \t]++)?using[ \t]++(?:static[ \t]++)?(?:\w+[ \t]*+=[ \t]*+)?([\w.]+)[ \t]*+;"), 1)],
    "kotlin": [(re.compile(r"(?m)^[ \t]*+import[ \t]++([\w.]+(?:\.\*)?)"), 1)],
    "scala": [(re.compile(r"(?m)^[ \t]*+import[ \t]++([\w.]+)"), 1)],
    "groovy": [(re.compile(r"(?m)^[ \t]*+import[ \t]++(?:static[ \t]++)?([\w.]+(?:\.\*)?)"), 1)],
    "swift": [(re.compile(r"(?m)^[ \t]*+(?:@testable[ \t]++)?import[ \t]++(?:\w+[ \t]++)?([\w.]+)"), 1)],
    "dart": [(re.compile(r"(?m)^[ \t]*+(?:import|export|part)[ \t]++(?=['\"])"), None)],
    "js": [(re.compile(r"(?<![\w$.])(?:import|export)[^;'\"`()]{0,500}?[ \t\r\n}*]from[ \t\r\n]*+(?=['\"])"), None),
           (re.compile(r"(?m)^[ \t]*+import[ \t\r\n]*+(?=['\"])"), None),
           (re.compile(r"(?<![\w$.])(?:require|import)[ \t]*+\([ \t]*+(?=['\"])"), None)],
    "go": [(re.compile(r"(?m)^[ \t]*+import[ \t]++(?:[\w.]+[ \t]++)?(?=\")"), None)],
    "rust": [(re.compile(r"(?m)^[ \t]*+(?:pub(?:\([^)\n]{0,40}\))?[ \t]++)?use[ \t]++([\w:]+)"), 1),
             (re.compile(r"(?m)^[ \t]*+(?:pub[ \t]++)?mod[ \t]++(\w+)[ \t]*+;"), 1)],
    "php": [(re.compile(r"(?m)^[ \t]*+use[ \t]++([\w\\]+)"), 1),
            (re.compile(r"(?<![\w$])(?:require|include)(?:_once)?[ \t(]*+(?=['\"])"), None)],
    "solidity": [(re.compile(r"(?m)^[ \t]*+import[ \t]++(?:[^;'\"]{0,200}?from[ \t]++)?(?=['\"])"), None)],
    "zig": [(re.compile(r"@import[ \t]*+\([ \t]*+(?=\")"), None)],
}
_GO_IMPORT_BLOCK = re.compile(r"(?m)^[ \t]*+import[ \t]*+\(")


def _type_pattern(keyword: str) -> re.Pattern:
    # ``enum class Foo`` / ``enum struct Foo`` (C++, Kotlin) take an optional second word.
    return re.compile(
        rf"(?<![\w$.@]){keyword}[ \t\r\n]++(?:(?:class|struct)[ \t\r\n]++)?([A-Za-z_$][\w$]*+)"
    )


def _function_pattern(keyword: str) -> re.Pattern:
    # Optional generics before the name (Kotlin ``fun <T> f``) and a receiver type
    # (Kotlin extension ``fun String.ext``), which arrives in group 2.
    return re.compile(
        rf"(?<![\w$.]){keyword}[ \t\r\n]*+(?:<[^<>{{}}();\n]{{0,120}}+>[ \t\r\n]*+)?\*?[ \t\r\n]*+&?"
        r"([A-Za-z_$][\w$]*+)(?:\.([A-Za-z_$][\w$]*+))?"
    )


_TYPE_PATTERNS = {
    keyword: _type_pattern(keyword)
    for spec in _SPECS.values() for keyword, _ in spec.type_keywords
}
_FUNCTION_PATTERNS = {
    keyword: _function_pattern(keyword)
    for spec in _SPECS.values() for keyword in spec.function_keywords
}
# A class field initialised with an arrow function (React class components).
_CLASS_FIELD_ARROW = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*+)[ \t]*+(?::[^=;\n]{0,200}+)?=[ \t]*+(?:async[ \t]++)?"
    r"(?=\([^()\n]{0,300}+\)[ \t]*+(?::[^=;\n{]{0,200}+)?=>|[A-Za-z_$][\w$]*+[ \t]*+=>)"
)


def _openers(spec: LexicalSpec) -> re.Pattern:
    alternatives = []
    if spec.cpp_raw:
        alternatives.append(r'(?<![\w$])(?:u8|[uUL])?R"(?P<raw>[^()\\ \n]{0,16})\(')
    if spec.rust_raw:
        alternatives.append(r'(?<![\w$])b?r(?P<hashes>#{0,8})"')
    if spec.verbatim:
        alternatives.append(r'\$?@\$?"')
    if spec.triple_quotes:
        alternatives.append(r'"""|\'\'\'')
    alternatives.extend(re.escape(token) for token in spec.line_comments)
    if spec.block_comments:
        alternatives.append(r"/\*")
    quotes = spec.string_quotes + ("'" if spec.char_quote and "'" not in spec.string_quotes else "")
    if spec.backtick:
        quotes += "`"
    alternatives.append(f"[{re.escape(quotes)}]")
    return re.compile("|".join(alternatives))


_OPENERS = {family: _openers(spec) for family, spec in _SPECS.items()}
_QUOTED = {
    '"': re.compile(r'"(?:[^"\\\n]|\\.)*+"'),
    "'": re.compile(r"'(?:[^'\\\n]|\\.)*+'"),
}
_CHAR_LITERAL = re.compile(
    r"'(?:\\(?:x[0-9A-Fa-f]{1,2}|u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[^\n])|[^'\\\n])'"
)
_TEMPLATE = re.compile(r"`(?:[^`\\]|\\[\s\S])*+`")
_RAW_BACKTICK = re.compile(r"`[^`]*+`")
_VERBATIM = re.compile(r'(?:[^"]|"")*+"')


def clean_source(text: str, family: str) -> tuple[str, list[tuple[int, int]]]:
    """Blank comments and string contents; return (clean text, string spans)."""
    spec = _SPECS[family]
    opener = _OPENERS[family]
    pieces: list[str] = []
    strings: list[tuple[int, int]] = []
    length = len(text)
    copied = 0      # text[:copied] has been emitted to ``pieces``
    position = 0    # where the next opener search starts

    def emit(start: int, end: int, keep: int) -> None:
        # The closing delimiter stays in the text; scanning resumes after it.
        nonlocal copied, position
        inner_start, inner_end = start + keep, max(start + keep, end - keep)
        pieces.append(text[copied:inner_start])
        pieces.append(_NON_NEWLINE.sub(" ", text[inner_start:inner_end]))
        copied = inner_end
        position = end

    def literal(start: int, end: int, keep: int) -> None:
        emit(start, end, keep)
        if len(strings) < _MAX_STRINGS:
            strings.append((start, end))

    # Line end beyond which a quote kind is known to be unterminated: once a quote fails
    # to close on a line, every later quote of that kind on the line fails too, so it
    # is skipped without rescanning (keeps lines like '\'\'\'... linear).
    unterminated: dict[str, int] = {}
    while position < length:
        match = opener.search(text, position)
        if match is None:
            break
        start, token = match.start(), match.group()
        if token in _QUOTED and unterminated.get(token, -1) > start:
            position = start + 1
            continue
        if token in spec.line_comments:
            end = text.find("\n", start)
            end = length if end == -1 else end
            emit(start, end, 0)
        elif token == "/*":
            end = text.find("*/", start + 2)
            end = length if end == -1 else end + 2
            emit(start, end, 0)
        elif token in ('"""', "'''"):
            end = text.find(token, start + 3)
            end = length if end == -1 else end + 3
            literal(start, end, 3 if end - start >= 6 else 0)
        elif spec.cpp_raw and match.lastgroup == "raw":
            closing = ")" + (match.group("raw") or "") + '"'
            end = text.find(closing, match.end())
            end = length if end == -1 else end + len(closing)
            literal(start, end, 0)
        elif spec.rust_raw and match.lastgroup == "hashes":
            closing = '"' + (match.group("hashes") or "")
            end = text.find(closing, match.end())
            end = length if end == -1 else end + len(closing)
            literal(start, end, 0)
        elif "@" in token:
            body = _VERBATIM.match(text, match.end())
            end = body.end() if body else length
            literal(start, end, 0)
        elif token == "`":
            body = (_TEMPLATE if spec.backtick == "template" else _RAW_BACKTICK).match(text, start)
            literal(start, body.end() if body else length, 1 if body else 0)
        elif token == "'" and spec.char_quote:
            found = _CHAR_LITERAL.match(text, start)
            if found is None:
                position = start + 1  # a lifetime or label such as 'a, not a literal
                continue
            literal(start, found.end(), 1)
        else:
            found = _QUOTED[token].match(text, start)
            if found is not None:
                literal(start, found.end(), 1)
            else:
                # Unterminated on its line, such as an apostrophe in JSX text ("Don't"):
                # treat the quote as an ordinary character.
                end = text.find("\n", start)
                unterminated[token] = length if end == -1 else end
                position = start + 1
    pieces.append(text[copied:])
    return "".join(pieces), strings


def _script_only(text: str) -> str:
    """Vue/Svelte: keep <script> contents and blank the markup, preserving offsets."""
    pieces, copied = [], 0
    for match in _SCRIPT_BLOCK.finditer(text):
        pieces.append(_NON_NEWLINE.sub(" ", text[copied:match.start(1)]))
        pieces.append(match.group(1))
        copied = match.end(1)
    pieces.append(_NON_NEWLINE.sub(" ", text[copied:]))
    return "".join(pieces)


def _pairs(clean: str) -> tuple[dict[int, int], dict[int, int]]:
    braces: dict[int, int] = {}
    parens: dict[int, int] = {}
    brace_stack: list[int] = []
    paren_stack: list[int] = []
    for match in _BRACKETS.finditer(clean):
        char, offset = match.group(), match.start()
        if char == "{":
            brace_stack.append(offset)
        elif char == "}":
            if brace_stack:
                braces[brace_stack.pop()] = offset
        elif char == "(":
            paren_stack.append(offset)
        elif paren_stack:
            parens[paren_stack.pop()] = offset
    return braces, parens


def _previous_token(clean: str, offset: int) -> tuple[str, int]:
    """The word or single non-space character ending before ``offset``, and its start."""
    index = offset - 1
    while index >= 0 and clean[index] in " \t\r\n":
        index -= 1
    if index < 0:
        return "", -1
    if clean[index].isalnum() or clean[index] in "_$":
        end = index + 1
        while index >= 0 and (clean[index].isalnum() or clean[index] in "_$"):
            index -= 1
        return clean[index + 1:end], index + 1
    return clean[index], index


def _qualifier_before(clean: str, offset: int) -> tuple[str, int]:
    """A C++ ``A::B::`` chain ending at ``offset`` as ("A.B", chain start), else ("", offset).

    A bounded backward scan; an end-anchored regex search would be quadratic.
    """
    parts: list[str] = []
    position = offset
    while len(parts) < 16:
        index = position - 1
        while index >= 0 and clean[index] in " \t":
            index -= 1
        if index < 1 or clean[index - 1:index + 1] != "::":
            break
        word, word_start = _previous_token(clean, index - 1)
        if not word or not (word[0].isalpha() or word[0] == "_") or not word.replace("_", "a").isalnum():
            break
        parts.append(word)
        position = word_start
    return (".".join(reversed(parts)), position) if parts else ("", offset)


def _statement_prefix(clean: str, offset: int) -> str:
    start = max(0, offset - 240)
    window = clean[start:offset]
    cut = max(window.rfind(";"), window.rfind("{"), window.rfind("}"))
    return window[cut + 1:]


# Families whose opening brace sits on the declaration's line (by syntax in Go, by
# universal convention in the others), so a newline means there is no body.
_SAME_LINE_BRACES = frozenset({"go", "kotlin", "scala", "swift", "rust"})


def _body_after(clean: str, start: int, braces: dict[int, int], family: str = "") -> tuple[int, int] | None:
    """The brace body opening after ``start``, unless a ``;`` or ``}`` comes first."""
    found = _TERMINATOR.search(clean, start, min(len(clean), start + _SIGNATURE_LOOKAHEAD))
    if found is None or found.group() != "{":
        return None
    if family in _SAME_LINE_BRACES and "\n" in clean[start:found.start()]:
        return None
    close = braces.get(found.start())
    return (found.start(), close) if close is not None else None


def _exported(family: str, name: str, prefix: str, kind: str, exported_names: set[str]) -> bool:
    words = set(prefix.split())
    if family == "go":
        return name[:1].isupper()
    if family in {"rust", "zig"}:
        return any(word.startswith("pub") for word in words)
    if family == "js":
        return "export" in words or name in exported_names
    if family in {"java", "csharp"}:
        return bool(words & {"public", "protected"}) or kind == "interface"
    if family in {"kotlin", "scala", "groovy"}:
        return not words & {"private", "internal"}
    if family == "swift":
        return bool(words & {"public", "open"})
    if family == "dart":
        return not name.startswith("_")
    if family == "php":
        return "private" not in words
    if family in {"c", "cpp"} and kind == "function":
        return "static" not in words
    # C++ members, Solidity, shaders: visibility is not readable lexically; assume used.
    return True


@dataclass(slots=True)
class _Definition:
    name_offset: int
    start: int
    kind: str
    name: str
    body: tuple[int, int] | None
    container: str = ""


def _type_definitions(clean: str, spec: LexicalSpec, braces) -> list[_Definition]:
    found = []
    for keyword, kind in spec.type_keywords:
        for match in _TYPE_PATTERNS[keyword].finditer(clean):
            name = match.group(1)
            if name in _NOT_NAMES:
                continue
            body = _body_after(clean, match.end(), braces, spec.family)
            if body is None:
                following = clean[match.end():match.end() + 40].lstrip()
                if not (spec.bodiless_types and following[:1] in {"(", ":"}) and not (
                    kind == "record" and following[:1] == "("
                ):
                    continue  # a forward declaration or a type reference
            found.append(_Definition(match.start(1), match.start(), kind, name, body))
    return found


def _rust_impls(clean: str, braces) -> list[_Definition]:
    found = []
    for match in _RUST_IMPL.finditer(clean):
        terminator = _TERMINATOR.search(clean, match.end(), min(len(clean), match.end() + _SIGNATURE_LOOKAHEAD))
        if terminator is None or terminator.group() != "{" or terminator.start() not in braces:
            continue
        header = clean[match.end():terminator.start()].split(" where ", 1)[0].strip()
        if header.startswith("<"):  # impl<T> ...: skip the generic parameter list
            depth = 0
            for index, char in enumerate(header):
                depth += {"<": 1, ">": -1}.get(char, 0)
                if depth == 0:
                    header = header[index + 1:].strip()
                    break
        implemented = header.rsplit(" for ", 1)[-1].strip()
        name = _GENERIC_SUFFIX.sub("", implemented.split("::")[-1]).strip("&*")
        if name.isidentifier():
            body = (terminator.start(), braces[terminator.start()])
            found.append(_Definition(match.start(), match.start(), "impl", name, body))
    return found


def _typedefs(clean: str, braces) -> list[_Definition]:
    found = []
    for match in _TYPEDEF.finditer(clean):
        position = match.end()
        for _ in range(4):  # skip at most a few nested aggregate bodies
            terminator = _TERMINATOR.search(clean, position, min(len(clean), position + 20_000))
            if terminator is None:
                break
            if terminator.group() == "{" and terminator.start() in braces:
                position = braces[terminator.start()] + 1
                continue
            if terminator.group() == ";":
                name, name_start = _previous_token(clean, terminator.start())
                if name.isidentifier() and name not in _NOT_NAMES and name_start >= position:
                    found.append(_Definition(name_start, match.start(), "type", name, None))
            break
    return found


def _keyword_functions(clean: str, spec: LexicalSpec, braces, parens) -> list[_Definition]:
    found = []
    for keyword in spec.function_keywords:
        if keyword == "func" and spec.family == "go":
            matches = (
                (m.start(2), m.start(), m.group(2), m.end(), (m.group(1) or "").split()[-1:])
                for m in _GO_FUNC.finditer(clean)
            )
        else:
            matches = (
                (m.start(2) if m.group(2) else m.start(1), m.start(),
                 m.group(2) or m.group(1), m.end(), [m.group(1)] if m.group(2) else [])
                for m in _FUNCTION_PATTERNS[keyword].finditer(clean)
            )
        for name_offset, start, name, end, receiver in matches:
            # After fn/func/fun/def/function every name is a definition (even ``new``).
            following = clean[end:end + 200].lstrip()
            if following[:1] in {"<", "["}:  # generic parameters before the parameter list
                depth = 0
                for index, char in enumerate(following):
                    depth += {"<": 1, "[": 1, ">": -1, "]": -1}.get(char, 0)
                    if depth == 0:
                        following = following[index + 1:].lstrip()
                        break
            if following[:1] == "(":
                paren = clean.find("(", end, end + 200)
                close = parens.get(paren) if paren != -1 else None
                body = None
                if close is not None:
                    after = clean[close + 1:close + 1 + _SIGNATURE_LOOKAHEAD]
                    assignment = after.find("=")
                    brace = after.find("{")
                    # ``fun f() = expr`` has no block body (``= {`` and ``=>`` still do).
                    expression = assignment != -1 and (brace == -1 or assignment < brace) and \
                        after[assignment + 1:assignment + 2] not in {">", "="}
                    if not expression or after[assignment + 1:].lstrip()[:1] == "{":
                        body = _body_after(clean, close + 1, braces, spec.family)
            elif spec.family == "groovy":
                continue  # ``def x = ...`` declares a variable, not a method
            else:  # Scala parameterless ``def size: Int = ...`` or ``def run {``
                body = _body_after(clean, end, braces, spec.family) if following[:1] in {"{", ":"} else None
            container = receiver[0].lstrip("*&").split("[", 1)[0] if receiver else ""
            found.append(_Definition(name_offset, start, "function", name, body, container))
    return found


def _typed_functions(clean: str, spec: LexicalSpec, braces, parens, class_bodies) -> list[_Definition]:
    """C-style ``Type name(...) {`` definitions, and untyped methods in JS/TS classes.

    ``class_bodies`` holds (start, end, class name); a member named like its class is a
    constructor, which needs no return type (C++ ``public:\\n  Server(int port) {``).
    """
    found = []
    class_bodies = sorted(class_bodies)
    for match in _CALL.finditer(clean):
        name = match.group(1)
        if name in _NOT_NAMES or name in {"new", "operator"}:
            continue
        close = parens.get(match.end() - 1)
        if close is None:
            continue
        body = _body_after(clean, close + 1, braces)
        if body is None:
            continue
        previous, previous_start = _previous_token(clean, match.start())
        qualifier = ""
        if previous == ":" and clean[max(0, previous_start - 1):previous_start + 1] == "::":
            qualifier, chain_start = _qualifier_before(clean, match.start())
            if not qualifier:
                continue
            previous, previous_start = _previous_token(clean, chain_start)
        if previous == "." or (previous == ">" and clean[previous_start - 1:previous_start + 1] == "->"):
            continue
        enclosing = [owner for start, end, owner in class_bodies if start < match.start() < end]
        in_class = bool(enclosing)
        constructor = in_class and enclosing[-1] == name and not qualifier
        if spec.untyped_methods:
            if not (in_class and previous in _JS_METHOD_PRECEDERS):
                continue
        elif not constructor and not (
            previous and (previous[-1:].isalnum() or previous[-1:] in "_*&>]~")
            and previous not in _TYPE_PRECEDERS
        ):
            continue
        found.append(_Definition(match.start(1), previous_start if previous_start >= 0 else match.start(),
                                 "method" if in_class else "function", name, body, qualifier))
    return found


def build_lexical_model(path: str, language: str, text: str) -> FileModel:
    family = LEXICAL_LANGUAGES[language]
    spec = _SPECS[family]
    source = _script_only(text) if language in {"Vue", "Svelte"} else text
    clean, strings = clean_source(source, family)
    braces, parens = _pairs(clean)
    model = FileModel(path, language, "lexical", text, clean=clean, strings=strings,
                      braces=braces, parens=parens)
    exported_names: set[str] = set()
    if family == "js":
        exported_names = {match.group(1) for match in _JS_EXPORTS.finditer(clean)}
        for match in _JS_EXPORT_LIST.finditer(clean):
            for item in match.group(1).split(","):
                words = item.split()
                if words:
                    exported_names.add(words[0])

    definitions = _type_definitions(clean, spec, braces)
    if family == "rust":
        definitions += _rust_impls(clean, braces)
    if family == "go":
        definitions += [
            _Definition(m.start(1), m.start(), m.group(2), m.group(1), _body_after(clean, m.end(), braces))
            for m in _GO_TYPE.finditer(clean)
        ]
    if family in {"c", "cpp"}:
        definitions += _typedefs(clean, braces)
    definitions += _keyword_functions(clean, spec, braces, parens)
    if family == "js":
        for match in _FUNCTION_EXPRESSION.finditer(clean):
            arrow = clean.find("=>", match.end(), match.end() + _SIGNATURE_LOOKAHEAD)
            body = _body_after(clean, arrow + 2 if arrow != -1 else match.end(), braces)
            definitions.append(_Definition(match.start(1), match.start(), "function", match.group(1), body))
    if spec.typed_functions or spec.untyped_methods:
        class_bodies = [
            (*item.body, item.name) for item in definitions if item.body and item.kind in _CONTAINER_KINDS
        ]
        definitions += _typed_functions(clean, spec, braces, parens, class_bodies)
        if family == "js":
            for match in _CLASS_FIELD_ARROW.finditer(clean):
                previous, _ = _previous_token(clean, match.start(1))
                if previous in _JS_METHOD_PRECEDERS and any(
                    start < match.start() < end for start, end, _owner in class_bodies
                ):
                    arrow = clean.find("=>", match.end(), match.end() + _SIGNATURE_LOOKAHEAD)
                    body = _body_after(clean, arrow + 2, braces) if arrow != -1 else None
                    definitions.append(_Definition(match.start(1), match.start(1), "method", match.group(1), body))

    unique: dict[int, _Definition] = {}
    for item in definitions:
        unique.setdefault(item.name_offset, item)
    ordered = sorted(unique.values(), key=lambda item: item.name_offset)
    stack: list[tuple[int, str, str]] = []  # (body end, qualified, kind)
    function_bodies: list[tuple[int, int, str]] = []
    for item in ordered:
        while stack and stack[-1][0] < item.name_offset:
            stack.pop()
        kind = item.kind
        if stack and stack[-1][2] in _FUNCTION_KINDS and not spec.nested_functions and kind in _FUNCTION_KINDS:
            continue  # a call inside a body that looked like a definition
        container = item.container or (stack[-1][1] if stack else "")
        if item.container or (kind == "function" and stack and stack[-1][2] in _CONTAINER_KINDS):
            kind = "method"
        if kind == "method" and (container.rsplit(".", 1)[-1] == item.name or item.name == "constructor"):
            kind = "constructor"
        qualified = f"{container}.{item.name}" if container else item.name
        prefix = _statement_prefix(clean, item.start) + clean[item.start:item.name_offset]
        model.symbols.append(Symbol(
            kind, item.name, qualified, model.line_of(item.name_offset),
            model.line_of(item.body[1]) if item.body else model.line_of(item.name_offset),
            container, _exported(family, item.name, prefix, kind, exported_names),
            is_async="async" in prefix.split(), body=item.body,
        ))
        if item.body:
            stack.append((item.body[1], qualified, kind))
            if kind in _FUNCTION_KINDS:
                function_bodies.append((item.body[0], item.body[1], qualified))
    if family in {"c", "cpp"}:
        for match in _MACRO.finditer(clean):
            model.symbols.append(Symbol(
                "macro", match.group(1), match.group(1), model.line_of(match.start(1)),
                model.line_of(match.start(1)), "", True,
            ))

    _calls(model, clean, ordered, function_bodies)
    counts = Counter(_IDENTIFIER.findall(clean))
    for item in ordered:
        counts[item.name] -= 1
    for word, count in counts.items():
        if count > 0 and word not in _NOT_NAMES:
            model.references.add(word)
            if len(model.references) >= _MAX_REFERENCES:
                break
    _imports(model, family)
    return model


def _calls(model: FileModel, clean: str, ordered, function_bodies) -> None:
    """Attribute each call site to its innermost enclosing function (one sweep)."""
    definition_offsets = {item.name_offset for item in ordered}
    function_bodies.sort()
    open_bodies: list[tuple[int, str]] = []  # (body end, qualified), innermost last
    next_body = 0
    for match in _CALL.finditer(clean):
        name, offset = match.group(1), match.start(1)
        if name in _NOT_NAMES or offset in definition_offsets:
            continue
        while next_body < len(function_bodies) and function_bodies[next_body][0] < offset:
            start, end, qualified = function_bodies[next_body]
            while open_bodies and open_bodies[-1][0] < start:
                open_bodies.pop()
            open_bodies.append((end, qualified))
            next_body += 1
        while open_bodies and open_bodies[-1][0] < offset:
            open_bodies.pop()
        previous, previous_start = _previous_token(clean, offset)
        receiver = ""
        if previous == "." or (
            previous in {">", ":"} and clean[previous_start - 1:previous_start + 1] in {"->", "::"}
        ):
            chain_end = previous_start - (0 if previous == "." else 1)
            token, _ = _previous_token(clean, chain_end)
            receiver = token if token.replace("$", "_").isidentifier() else "<expression>"
        elif previous == "new":
            receiver = "new"
        caller = open_bodies[-1][1] if open_bodies else "<module>"
        model.calls.append(Call(caller, name, receiver, "", model.line_of(offset), offset))


def _imports(model: FileModel, family: str) -> None:
    clean = model.clean
    for pattern, group in _IMPORTS.get("c" if family == "cpp" else family, []):
        for match in pattern.finditer(clean):
            if group is not None:
                target = match.group(group)
            else:
                spans = model.strings_between(match.end(), match.end() + 4)
                if not spans:
                    continue
                target = model.string_value(spans[0])
            if target:
                model.imports.append(Import(target.strip(), model.line_of(match.start())))
    if family == "go":
        for match in _GO_IMPORT_BLOCK.finditer(clean):
            opening = match.end() - 1
            closing = clean.find(")", opening)
            if closing == -1:
                continue
            for span in model.strings_between(opening, closing):
                model.imports.append(Import(model.string_value(span), model.line_of(span[0])))
