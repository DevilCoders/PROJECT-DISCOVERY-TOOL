"""Route handlers: the function, method or action a route declaration names, read from the source
next to the declaration.

A decorator, annotation or attribute (``@app.get``, ``@GetMapping``, ``[HttpGet]``, ``#[Route]``)
names the function or method declared after it; a Python route reports its ``def``; a registration
call (``app.get("/x", auth, users.list)``, ``r.HandleFunc("/x", list)``, ``path("x/", views.list)``)
names its last positional argument that is not a string, or a handler keyword's value
(``view_func=``); Rails ``to: "photos#index"``, Laravel ``[UserController::class, 'index']`` and
``'UserController@show'``, and Phoenix ``get "/users", UserController, :index`` name their actions.
A function written in the call or a trailing block is ``(inline)``.
"""
from __future__ import annotations

import re

_DECORATED = re.compile(r"^[ \t]*+(?:@|\[|#\[)")
_DEF_NAME = re.compile(r"\b(?:def|fn|func|function|sub)[ \t]++(?:\([^)\n]{0,200}\)[ \t]*+)?(?P<name>[A-Za-z_$][\w$]{0,119})")
# A line that defines a function: Python's def (decorated routes report it), fn, func, function.
_DEF_LINE = re.compile(r"(?:(?:pub(?:\([\w ]{1,20}\))?|export|public|private|protected|static|async|override|default)"
                       r"[ \t]++){0,4}(?:def|fn|func|function|sub)[ \t]++(?:\([^)\n]{0,200}\)[ \t]*+)?"
                       r"(?P<name>[A-Za-z_$][\w$]{0,119})")
_MEMBER_NAME = re.compile(r"(?<![\w$])(?P<name>[A-Za-z_$][\w$]{0,119})[ \t]*+(?:<[^<>()\n]{0,200}>[ \t]*+)?\(")
_NOT_HANDLERS = frozenset({"if", "for", "while", "switch", "return", "new", "function", "async", "await", "def", "fn",
                           "func", "sub", "catch", "using", "lock", "typeof", "sizeof", "nameof"})
_RAILS_ACTION = re.compile(r"""(?:\bto:|=>)\s*+["'](?P<name>[\w/]{1,120}#\w{1,120})["']""")
_LARAVEL_ACTION = re.compile(r"""\[\s*+\\?(?P<cls>[\w\\]{1,200})::class\s*+,\s*+["'](?P<method>\w{1,120})["']\s*+\]|"""
                             r"""["'](?P<at>[\w\\]{1,200}@\w{1,120})["']""")
_HANDLER_KEYWORDS = frozenset({"view_func", "handler", "view", "endpoint", "to", "action", "controller", "uses"})
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]{0,119}(?:(?:\.|::|->|\\)[A-Za-z_$][\w$]{0,119}){0,8}")
_MAX_CALL_CHARS = 2048


def _arguments(call: str, opening: int) -> tuple[list[str], int]:
    """The top-level arguments of the call whose parenthesis is at ``opening``, and the offset
    after its closing parenthesis (or -1 when it does not close within the text)."""
    depth = 0
    quote = ""
    start = opening + 1
    found = []
    position = opening
    while position < len(call):
        character = call[position]
        if quote:
            if character == "\\":
                position += 1
            elif character == quote:
                quote = ""
        elif character in "\"'`":
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
            if depth == 0:
                found.append(call[start:position].strip())
                return [item for item in found if item], position + 1
        elif character == "," and depth == 1:
            found.append(call[start:position].strip())
            start = position + 1
        position += 1
    return [item for item in found if item], -1


def _handler_argument(arguments: list[str]) -> str:
    """The handler among a registration call's arguments: the last positional one that names a
    function, or a handler keyword's value; "(inline)" for a function written in the call."""
    positional, keyword = [], ""
    for argument in arguments:
        name, separator, value = argument.partition("=")
        if separator and not value.startswith((">", "=")) and _IDENTIFIER.fullmatch(name.strip()):
            if name.strip() in _HANDLER_KEYWORDS:
                keyword = value.strip()
            continue
        if argument[0] not in "\"'`":  # paths and names are strings; handlers are not
            positional.append(argument)
    candidate = positional[-1] if positional else keyword
    if not candidate or candidate[0] in "\"'`":
        return ""
    if candidate.startswith(("function", "async", "(", "{", "lambda", "fn ", "func(", "func (")) or "=>" in candidate \
            or "->" in candidate[:3]:
        return "(inline)"
    match = _IDENTIFIER.match(candidate)
    return match.group(0) if match and match.end() >= len(candidate.rstrip("()! ")) else ""


def route_handler(lines: list[str], line: int) -> str:
    """The handler a route declared at ``line`` (1-based) names: the function or method a
    decorator, annotation or attribute is on, the def a Python route reports, or the handler a
    registration call passes ("Controller@method", "controller#action" and "Module.action"
    included); "(inline)" for a function written in the call; "" when the source does not say."""
    if not 0 < line <= len(lines):
        return ""
    text = lines[line - 1]
    rails = _RAILS_ACTION.search(text)
    if rails:
        return rails.group("name")
    laravel = _LARAVEL_ACTION.search(text)
    if laravel:
        return laravel.group("at") or f"{laravel.group('cls').rsplit(chr(92), 1)[-1]}@{laravel.group('method')}"
    if _DECORATED.match(text):
        for following in lines[line:line + 12]:
            stripped = following.strip()
            if not stripped or stripped.startswith(("@", "[", "#[", "//", "#", "*", "/*")):
                continue
            definition = _DEF_NAME.search(stripped)
            if definition:
                return definition.group("name")
            for member in _MEMBER_NAME.finditer(stripped):
                if member.group("name") not in _NOT_HANDLERS:
                    return member.group("name")
            return ""
        return ""
    definition = _DEF_LINE.match(text.strip())
    if definition:
        return definition.group("name")
    call = "\n".join(lines[line - 1:line + 7])[:_MAX_CALL_CHARS]
    opening = call.find("(")
    quote = min((position for position in (call.find('"'), call.find("'"), call.find("`")) if position >= 0), default=-1)
    if opening == -1 or (quote != -1 and quote < opening and call.find("(") > call.find("\n")):
        # Elixir and Ruby DSLs without parentheses: get "/users", UserController, :index
        parts = [part.strip() for part in call.split("\n", 1)[0].split(",")]
        if len(parts) >= 3 and parts[-1].startswith(":") and _IDENTIFIER.fullmatch(parts[-2]):
            return f"{parts[-2]}.{parts[-1][1:]}"
        return ""
    arguments, end = _arguments(call, opening)
    handler = _handler_argument(arguments)
    if not handler and end != -1 and call[end:].lstrip().startswith("{"):
        return "(inline)"  # a trailing block or lambda: Ktor, Gradle-style DSLs
    return handler
