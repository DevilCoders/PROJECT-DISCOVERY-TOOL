"""Route structure: the prefixes that apply to the routes a file declares, resolved in the file.

The route adapters (``routes.py``) find declarations; this module finds what encloses them:

* class-level mappings (Spring ``@RequestMapping``, JAX-RS ``@Path``, NestJS and Micronaut
  ``@Controller``, ASP.NET ``[Route]``/``[RoutePrefix]`` with its ``[controller]`` token,
  Symfony ``#[Route]``) apply to the routes in the class body;
* block groups (chi and Fiber ``Route``, Ktor ``route``, Javalin and Spark ``path``, Akka
  ``pathPrefix``, Laravel and Slim prefix groups, Vapor ``group`` closures) apply to the routes
  in their braces; Compojure ``context``, Giraffe ``subRoute`` and Dream ``scope`` to those in
  their parentheses or brackets;
* indented groups (Rails ``namespace``, ``scope`` and nested resources, Grape ``namespace``,
  ``resource`` and ``route_param``, Roda ``r.on``, Phoenix ``scope`` and nested resources) to the
  routes indented under them;
* router variables (Gin, Echo and Fiber ``Group``, ASP.NET ``MapGroup``, Vapor ``grouped``,
  Mojolicious ``under``) and mounts (Express, Koa and Hono ``use``/``route`` of a router
  variable, axum ``nest``, Rocket ``mount``) to the routes declared on that variable or handler.

A class-level mapping is one followed by a class declaration within a few lines, with no
route and no brace between them; otherwise it maps a method. Spans come from the brace,
bracket and indentation depth the scan records for every line.
"""
from __future__ import annotations

import bisect
import re
from array import array
from dataclasses import dataclass, field
from typing import Callable

# Parentheses, brackets and braces, and the string literals and line comments to skip; an
# unterminated literal runs to the end of the line, so every character is read once.
DEPTH_TOKEN = re.compile(r'''[()\[\]{}]|//[^\n]*|"(?:[^"\\\n]|\\.)*+"?|'(?:[^'\\\n]|\\.)*+'?|`(?:[^`\\\n]|\\.)*+`?''')
# Languages where a single quote starts a character literal or a lifetime (Rust's &'static
# str), never a string: only a short quoted character is skipped.
DEPTH_TOKEN_CHARS = re.compile(r'''[()\[\]{}]|//[^\n]*|"(?:[^"\\\n]|\\.)*+"?|'(?:[^'\\\n]|\\.){1,8}'|`(?:[^`\\\n]|\\.)*+`?''')
_PARENS = {"(": 1, "[": 1, ")": -1, "]": -1}
_BRACES = {"{": 1, "}": -1}
_QUOTED = re.compile(r""""([^"\n]{0,200})"|'([^'\n]{0,200})'""")
_CLASS_GAP = 8  # lines between a class-level mapping and its class declaration, at most
_PAIR_GAP = 3  # lines between a method-level path and its method annotation, at most


def depth_changes(text: str, chars: bool = False) -> tuple[int, int]:
    """(parenthesis and bracket change, brace change) over a text, strings and // comments
    skipped; with ``chars``, single quotes enclose a character, not a string."""
    parens = braces = 0
    for token in (DEPTH_TOKEN_CHARS if chars else DEPTH_TOKEN).findall(text):
        parens += _PARENS.get(token, 0)
        braces += _BRACES.get(token, 0)
    return parens, braces


def singular(word: str) -> str:
    """A resource name's singular, as Rails, Laravel and Phoenix name the member parameter."""
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith(("sses", "xes", "zes", "ches", "shes")):
        return word[:-2]
    if word.endswith("s") and not word.endswith(("ss", "us", "is")):
        return word[:-1]
    return word


def join_path(parts: list[str]) -> str:
    """Prefixes and a route joined into one served path: ``["/api", "users/", ":id"]`` is
    ``/api/users/:id``; a trailing slash on the last part is kept."""
    pieces = [part.strip().strip("/") for part in parts if part and part.strip().strip("/")]
    joined = "/" + "/".join(pieces)
    last = next((part.strip() for part in reversed(parts) if part and part.strip()), "")
    return joined + "/" if last.endswith("/") and joined != "/" else joined


def segments_prefix(text: str) -> str:
    """Vapor's path segments, the quoted arguments of grouped("api", "v1")."""
    parts = [(first or second).strip("/") for first, second in _QUOTED.findall(text)]
    return "/" + "/".join(part for part in parts if part)


@dataclass(frozen=True, slots=True)
class Shape:
    """A structural declaration form.

    ``kind`` is one of: ``class`` and ``function`` (declarations, with a ``name`` group),
    ``class-prefix`` (applies only to the class that follows), ``path-annotation`` (a class
    prefix before a class, otherwise a method's path: JAX-RS ``@Path``, ASP.NET ``[Route]``),
    ``block`` (braces), ``paren-block`` (parentheses or brackets), ``indent``, ``var`` (a
    router variable derived from ``parent``), ``mount`` (router variables mounted at a prefix)
    and ``rocket-mount`` (handler names mounted at a prefix). ``read`` turns the match into the
    prefix when its ``prefix`` group is not it.
    """

    kind: str
    pattern: re.Pattern
    marker: str = ""
    unless: str = ""
    role: str = ""
    read: Callable[[re.Match], str] | None = None


@dataclass(slots=True)
class Event:
    kind: str
    line: int
    column: int
    prefix: str = ""
    name: str = ""
    parent: str = ""
    marker: str = ""
    unless: str = ""
    role: str = ""
    names: tuple[str, ...] = ()
    target: str = ""  # an import's module specifier
    # Where the event's block opens: the line and column of its brace (or parenthesis), and the
    # depth inside it; for indented groups, the line's indentation.
    open_line: int = 0
    open_column: int = 0
    level: int = 0


@dataclass(slots=True)
class Route:
    method: str
    path: str
    line: int
    column: int
    framework: str
    marker: str = ""
    unless: str = ""
    receiver: str = ""
    # "mapping": a Spring or Symfony mapping, a class prefix when a class follows it;
    # "http-verb": an ASP.NET [HttpGet] that a method-level [Route] template completes;
    # "jaxrs": a JAX-RS method annotation that a method-level @Path completes.
    role: str = ""
    handler: str = ""


@dataclass(slots=True)
class Layout:
    """Per-line depths of a scanned file: brace and parenthesis depth after each line, and each
    line's indentation (-1 for a blank line). Index ``line - 1``."""

    braces: array = field(default_factory=lambda: array("i"))
    parens: array = field(default_factory=lambda: array("i"))
    indents: array = field(default_factory=lambda: array("i"))

    def after(self, values: array, line: int) -> int:
        return values[line - 1] if 0 < line <= len(values) else (values[-1] if values else 0)

    def before(self, values: array, line: int) -> int:
        return values[line - 2] if 2 <= line <= len(values) + 1 else 0


def _active(item, seen: set[str]) -> bool:
    return (not item.marker or item.marker in seen) and not (item.unless and item.unless in seen)


def _block_end(layout: Layout, values: array, open_line: int, level: int) -> int:
    """The line on which the block at ``level`` that opens on ``open_line`` closes."""
    for line in range(open_line, len(values) + 1):
        if values[line - 1] < level:
            return line
    return len(values)


def _indent_end(layout: Layout, line: int) -> int:
    """The last line indented under ``line`` (blank lines included)."""
    indents = layout.indents
    base = layout.after(indents, line)
    end = line
    for number in range(line + 1, len(indents) + 1):
        indent = indents[number - 1]
        if indent == -1:
            continue
        if indent <= base:
            break
        end = number
    return end


def _inside(route: Route, span: tuple[int, int, int]) -> bool:
    open_line, open_column, end_line = span
    return (route.line, route.column) > (open_line, open_column) and route.line <= end_line


def _variables(events: list[Event]) -> dict[str, tuple[str, str]]:
    """Router variable -> (the router it derives from or is mounted on, its prefix there)."""
    variables: dict[str, tuple[str, str]] = {}
    for event in events:
        if event.kind == "var":
            variables[event.name] = (event.parent, event.prefix)
        elif event.kind == "mount":
            for name in event.names:
                variables.setdefault(name, (event.parent, event.prefix))
    return variables


def _chain(variables: dict[str, tuple[str, str]], receiver: str) -> list[str]:
    """The prefixes of a router variable, outermost first."""
    prefixes, guard = [], set()
    while receiver in variables and receiver not in guard:
        guard.add(receiver)
        receiver, prefix = variables[receiver]
        prefixes.append(prefix)
    return prefixes[::-1]


def external_mounts(routes: list[Route], events: list[Event], seen: set[str]) -> list[dict[str, str]]:
    """Routers a file mounts but imports from another module (``app.use('/api', users)`` with
    ``users`` required from ``./routes/users``): the prefix they are mounted at, with the
    mounting router's own prefixes in the file, the import specifier and the imported name."""
    events = [event for event in events if _active(event, seen)]
    imports = {name: event.target for event in events if event.kind == "import" for name in event.names}
    declared = {route.receiver for route in routes if route.receiver}
    variables = _variables(events)
    mounts = []
    for event in events:
        if event.kind != "mount":
            continue
        for name in event.names:
            if name in imports and name not in declared:
                mounts.append({"prefix": join_path([*_chain(variables, event.parent), event.prefix]),
                               "spec": imports[name], "name": name})
    return mounts


def resolve(routes: list[Route], events: list[Event], seen: set[str], layout: Layout) -> list[Route]:
    """The routes with their paths resolved through the file's structure; class-level mappings
    become prefixes rather than routes."""
    routes = [route for route in routes if _active(route, seen)]
    events = [event for event in events if _active(event, seen)]
    classes = sorted((event for event in events if event.kind == "class"), key=lambda event: (event.line, event.column))
    class_lines = [event.line for event in classes]

    def class_after(line: int, column: int) -> Event | None:
        """The class a mapping at (line, column) annotates: declared within a few lines, with no
        route and no brace between them."""
        index = bisect.bisect_left(class_lines, line)
        while index < len(classes) and (classes[index].line, classes[index].column) <= (line, column):
            index += 1
        if index == len(classes) or classes[index].line - line > _CLASS_GAP:
            return None
        target = classes[index]
        base = layout.before(layout.braces, line)
        if any(layout.after(layout.braces, number) != base for number in range(line, target.line)):
            return None
        if any((line, column) < (route.line, route.column) < (target.line, target.column) for route in routes):
            return None
        return target

    # Class-level mappings: (open line, open column, end line, prefix, class name, role).
    scopes: list[tuple[int, int, int, str, str, str]] = []
    consumed: set[int] = set()
    candidates = [(route.line, route.column, route.path, route.role, id(route)) for route in routes
                  if route.role == "mapping"]
    candidates += [(event.line, event.column, event.prefix, event.role or event.kind, id(event)) for event in events
                   if event.kind in {"class-prefix", "path-annotation"}]
    for line, column, prefix, role, identity in sorted(candidates):
        target = class_after(line, column)
        if target is None or not target.level:
            continue
        end = _block_end(layout, layout.braces, target.open_line, target.level)
        controller = target.name[:-len("Controller")] if target.name.endswith("Controller") else target.name
        scopes.append((target.open_line, target.open_column, end, prefix.replace("[controller]", controller),
                       target.name, role))
        consumed.add(identity)
    routes = [route for route in routes if id(route) not in consumed]

    # Method-level paths: JAX-RS @Path and ASP.NET [Route] complete a method annotation nearby.
    for event in events:
        if event.kind != "path-annotation" or id(event) in consumed:
            continue
        role = "jaxrs" if event.role == "jaxrs" else "http-verb"
        near = sorted((abs(route.line - event.line), route.line, route.column) for route in routes
                      if route.role == role and not route.path and abs(route.line - event.line) <= _PAIR_GAP)
        paired = [route for route in routes if near and route.role == role and not route.path
                  and abs(route.line - event.line) == near[0][0]]
        if paired:
            for route in paired:
                route.path = event.prefix
        elif event.role == "asp":
            routes.append(Route("ANY", event.prefix, event.line, event.column, "ASP.NET"))

    # Blocks, indented groups and parenthesized groups: (open line, open column, end line, prefix).
    spans: list[tuple[int, int, int, str]] = []
    for event in events:
        if event.kind == "block" and event.level:
            spans.append((event.open_line, event.open_column,
                          _block_end(layout, layout.braces, event.open_line, event.level), event.prefix))
        elif event.kind == "paren-block" and event.level:
            spans.append((event.open_line, event.open_column,
                          _block_end(layout, layout.parens, event.open_line, event.level), event.prefix))
        elif event.kind == "indent":
            spans.append((event.line, event.column, _indent_end(layout, event.line), event.prefix))
    spans.sort()

    variables = _variables(events)
    rocket = {name: event.prefix for event in events if event.kind == "rocket-mount" for name in event.names}
    functions = sorted((event.line, event.name) for event in events if event.kind == "function")

    resolved = []
    for route in routes:
        parts = _chain(variables, route.receiver) if route.receiver else []
        parts += [prefix for open_line, open_column, end, prefix in spans
                  if _inside(route, (open_line, open_column, end))]
        absolute = route.path.startswith(("/", "~/")) and any(scope[5] == "asp" for scope in scopes)
        scope = [item for item in scopes if _inside(route, (item[0], item[1], item[2]))]
        path = route.path[1:] if route.path.startswith("~/") else route.path
        if scope:
            innermost = max(scope)
            controller = innermost[4][:-len("Controller")] if innermost[4].endswith("Controller") else innermost[4]
            path = path.replace("[controller]", controller)
            if not (absolute and innermost[5] == "asp"):
                parts.append(innermost[3])
        if rocket and functions:
            index = bisect.bisect_left(functions, (route.line, ""))
            if index < len(functions) and functions[index][0] - route.line <= _PAIR_GAP:
                route.handler = functions[index][1]
                if route.handler in rocket:
                    parts.insert(0, rocket[route.handler])
        if parts:
            route.path = join_path([*parts, path])
        else:
            route.path = path
        resolved.append(route)
    return resolved
