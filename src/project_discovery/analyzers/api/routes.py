"""Source-level HTTP endpoint declaration discovery, by language and framework.

Python routes come from the syntax tree, the file's imports deciding which framework a
decorator or registration call belongs to. Every other language is read as text by the
adapters of its family (``_FAMILY_FORMS``, chosen by file extension): each form names its
framework, a pattern for one declaration form and, where the form is not distinctive on its
own (``router.get('/x')`` is also how an HTTP client is called), a marker the file must
contain, usually the framework's import. A declaration spanning lines (a call a formatter
wrapped, a multi-line annotation) is read from its first line joined with the next ones, up
to 8 lines and 2,048 characters, and each route keeps the line it starts on. File-system
routers (Next.js, SvelteKit, Nuxt, Dart Frog) take the route from the file's path. Route
prefixes, mounts and resource expansions are not resolved here.
"""
from __future__ import annotations

import ast
import bisect
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

from ...catalog.languages import source_extensions, source_language_names
from ...core.limits import AnalyzerLimits, limit_reached, over_limit
from ...core.source_utils import (
    SourceBudgetExceeded,
    describe_error,
    open_verified_text,
    parse_python,
    read_python_source_bounded,
)
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer

_SOURCE_EXTENSIONS = source_extensions()
MAX_PYTHON_ENDPOINT_AST_BYTES = 4 * 1024 * 1024  # the syntax-tree budget
MAX_SOURCE_ENDPOINT_SCAN_BYTES = 32 * 1024 * 1024
MAX_ENDPOINT_LINE_CHARS = 256 * 1024
MAX_ENDPOINT_FACTS = 500
# A declaration that spans lines is read from its first line joined with the next ones.
MAX_JOINED_LINES = 8
MAX_JOINED_CHARS = 2048

# JAX-RS method annotations take no arguments; the path is a separate @Path annotation.
_JAXRS_METHOD = re.compile(r"@(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b(?!\s*\()")
_JAXRS_PATH = re.compile(r"""@Path\s*\(\s*(?:value\s*=\s*)?["']([^"']*)["']""")

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
_METHOD_ALIASES = {"ALL": "ANY", "MATCH": "ANY", "REQUEST": "ANY", "*": "ANY", "DEL": "DELETE", "LIVE": "GET",
                   "WS": "WEBSOCKET", "FORWARD": "ANY", "ROUTE": "ANY", "IS": "ANY", "": "ANY"}
_METHOD_WORD = re.compile(r"(?i)(?<![\w$])(get|post|put|patch|delete|del|options|head|trace|connect|any|all)(?![\w$])")
# WordPress's WP_REST_Server method constants.
_WP_METHODS = {"READABLE": ["GET"], "CREATABLE": ["POST"], "EDITABLE": ["POST", "PUT", "PATCH"],
               "DELETABLE": ["DELETE"], "ALLMETHODS": ["ANY"]}
_WP_METHODS_FIELD = re.compile(
    r"""['"]methods['"]\s*=>\s*(?:['"]([^'"\n]{1,60})['"]|(?:\\?WP_REST_Server|self|static)::([A-Z]{1,20})"""
    r"""|(?:array\s*\(|\[)([^)\]\n]{0,200}))"""
)
_WP_GROUP = re.compile(r"\(\?P<(\w{1,60})>[^()\n]{0,100}\)")
_METHODS_FIELD = re.compile(r"""\bmethods?\s*[:=]\s*(\[[^\]\n]{0,200}\]|\{[^}\n]{0,200}\}|['"][^'"\n]{0,60}['"]|[\w.]{1,80})""")
_QUOTED = re.compile(r""""([^"\n]{0,200})"|'([^'\n]{0,200})'""")
# Parentheses and brackets, and string literals to skip; an unterminated literal runs to the
# end of the line (the closing quote is optional), so every character is read once.
_DEPTH_TOKEN = re.compile(r'''[()\[\]]|"(?:[^"\\\n]|\\.)*+"?|'(?:[^'\\\n]|\\.)*+'?|`(?:[^`\\\n]|\\.)*+`?''')
_DEPTH = {"(": 1, "[": 1, ")": -1, "]": -1}
# Cheap test before a line's forms run: every form's declarations name one of these words
# (JVM files skip the test: JAX-RS annotations are paired across lines).
_HINT = re.compile(r"(?i)get|post|put|patch|delete|route|handle|map|options|head|any|all|path|endpoint|resource|"
                   r"match|live|forward|\bat\b|\bon\b|crow_|method|register|\bdel\b|\bws\b|export|root|onrequest|"
                   r"connect|trace|controller")


def _method(word: str | None) -> str:
    upper = (word or "").strip().upper()
    return _METHOD_ALIASES.get(upper, upper)


def _methods(text: str) -> list[str]:
    return list(dict.fromkeys(_method(word) for word in _METHOD_WORD.findall(text)))


def _call_rest(text: str, start: int, limit: int = 1000) -> str:
    """The text from ``start`` to the parenthesis or bracket closing the call ``start`` is in."""
    depth, position, end = 1, start, min(len(text), start + limit)
    while position < end:
        char = text[position]
        if char in "\"'`":
            close = text.find(char, position + 1, end)
            position = end if close < 0 else close + 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:position]
        position += 1
    return text[start:end]


Reader = Callable[[re.Match], list[tuple[str, str]]]


@dataclass(frozen=True, slots=True)
class _Form:
    """One declaration form of a framework.

    The pattern's named groups give the ``method`` and ``path`` (``path2`` as an alternative
    spelling), or ``methods``: text naming several methods. ``method`` is the method when
    the pattern captures none, ``marker`` a ``_MARKERS`` key the file must match, ``read``
    a reader for forms the groups alone do not give, and ``file_route`` the file-system
    router kinds whose handler files the form marks (the route is then the file's path).
    """

    framework: str
    pattern: re.Pattern
    method: str = ""
    marker: str = ""
    read: Reader | None = None
    file_route: tuple[str, ...] = ()


def _read(form: _Form, match: re.Match) -> list[tuple[str, str]]:
    if form.read is not None:
        return form.read(match)
    groups = match.groupdict()
    path = groups.get("path") or groups.get("path2") or ""
    listed = _methods(groups["methods"]) if groups.get("methods") else []
    if listed:
        return [(method, path) for method in listed]
    return [(_method(groups.get("method") or form.method), path)]


def _rest_methods(pattern: re.Pattern | None = None) -> Reader:
    """Methods named in the rest of the call after the match (by ``pattern``'s first group,
    or any method word), else the matched or ANY method."""
    def read(match: re.Match) -> list[tuple[str, str]]:
        rest = _call_rest(match.string, match.end())
        found = [_method(word) for word in pattern.findall(rest)] if pattern else _methods(rest)
        method = match.groupdict().get("method")
        methods = list(dict.fromkeys(found)) or [_method(method)]
        return [(item, match.group("path") or "") for item in methods]
    return read


def _field_methods(match: re.Match) -> list[tuple[str, str]]:
    """Methods from a ``methods: [...]``/``methods = {...}`` argument after the path (Symfony,
    Quarkus), else the matched or ANY method."""
    field = _METHODS_FIELD.search(_call_rest(match.string, match.end()))
    methods = _methods(field.group(1)) if field else []
    return [(item, match.group("path") or "") for item in methods or [_method(match.groupdict().get("method"))]]


_SPRING_PATH = re.compile(r"""^\s*+\{?\s*+["']([^"'\n]*)["']|\b(?:value|path)\s*+=\s*+\{?\s*+["']([^"'\n]*)["']""")


def _spring(match: re.Match) -> list[tuple[str, str]]:
    """Spring mappings, their arguments in any order: @GetMapping("/x"), @GetMapping(value = "/x"),
    @RequestMapping(method = RequestMethod.POST, path = "/x")."""
    following = match.string[match.end():match.end() + 200]
    gap = len(following) - len(following.lstrip())
    arguments = _call_rest(match.string, match.end() + gap + 1) if following[gap:gap + 1] == "(" else ""
    found = _SPRING_PATH.search(arguments)
    path = (found.group(1) if found.group(1) is not None else found.group(2)) if found else ""
    if match.group("method") != "Request":
        return [(_method(match.group("method")), path)]
    methods = re.findall(r"RequestMethod\s*\.\s*([A-Z]+)", arguments)
    return [(item, path) for item in dict.fromkeys(methods)] or [("ANY", path)]


def _wordpress(match: re.Match) -> list[tuple[str, str]]:
    route = "/" + "/".join(part.strip("/") for part in ("wp-json", match.group("ns"), match.group("path")) if part.strip("/"))
    route = _WP_GROUP.sub(lambda group: "{" + group.group(1) + "}", route)
    methods: list[str] = []
    for literal, constant, listed in _WP_METHODS_FIELD.findall(_call_rest(match.string, match.end(), 2000)):
        if literal:
            methods += _methods(literal.replace(",", " "))
        elif constant:
            methods += _WP_METHODS.get(constant, [])
        else:
            methods += _methods(listed)
    return [(item, route) for item in dict.fromkeys(methods)] or [("GET", route)]  # WordPress's default


def _segments(match: re.Match) -> list[tuple[str, str]]:
    """Vapor, Kitura and Hummingbird: the path is the call's string arguments, joined."""
    rest = _call_rest(match.string, match.end())
    head = re.split(r"\buse\s*:", rest, maxsplit=1)[0]
    parts = [(first or second).strip("/") for first, second in _QUOTED.findall(head)]
    if any("://" in part for part in parts):
        return []  # an HTTP client's request (app.client.get("https://...")), not a route
    method = match.group("method")
    if method == "on":
        named = re.search(r"\.\s*([A-Z]{3,7})\b", head)
        method = named.group(1) if named else "ANY"
    parts = [part for part in parts if part]
    # No segment: the group's own path (app.grouped("users").get(use: index)).
    return [(_method(method), "/" + "/".join(parts) if parts else "")]


def _http4s(match: re.Match) -> list[tuple[str, str]]:
    parts = []
    for token in match.group("rest").split(":?", 1)[0].split("/"):
        token = token.strip()
        literal = re.fullmatch(r'"([^"]*)"', token)
        variable = re.fullmatch(r"\w+\((\w+)\)", token) or re.fullmatch(r"(\w+)", token)
        if literal:
            parts.append(literal.group(1))
        elif variable:
            parts.append("{" + variable.group(1) + "}")
    return [(_method(match.group("method")), "/" + "/".join(part for part in parts if part))]


def _servant(match: re.Match) -> list[tuple[str, str]]:
    parts = []
    for literal, capture in re.findall(r'(?:^|:>)\s*(?:"([^"\n]*)"|Capture\'?\s+(?:\'\[[^\]\n]*\]\s+)?"([^"\n]*)")',
                                       match.group("segments")):
        parts.append(literal or "{" + capture + "}")
    return [(_method(match.group("method")), "/" + "/".join(part for part in parts if part))]


def _warp(match: re.Match) -> list[tuple[str, str]]:
    parts = []
    for token in match.group("rest").split("/"):
        token = token.strip()
        literal = re.fullmatch(r'"([^"]*)"', token)
        if literal:
            parts.append(literal.group(1))
        elif token and token != "..":
            parts.append("{" + token + "}")
    return [("ANY", "/" + "/".join(part for part in parts if part))]


_CHAIN_CALL = re.compile(r"\.\s*(get|post|put|patch|delete|all|head|options)\s*\(")
_CROW_METHODS = re.compile(r"\.\s*methods\s*\(([^()\n]{0,300})\)")


def _chain_methods(text: str, start: int) -> list[str]:
    """The methods of the calls chained at ``start``: ``.get(list).post(create)``."""
    methods: list[str] = []
    position, length = start, len(text)
    while len(methods) < 16:
        while position < length and text[position] in " \t\r\n":
            position += 1
        call = _CHAIN_CALL.match(text, position)
        if call is None:
            break
        methods.append(_method(call.group(1)))
        position = call.end() + len(_call_rest(text, call.end())) + 1
    return methods


def _route_chain(match: re.Match) -> list[tuple[str, str]]:
    """Express's ``app.route('/x').get(h).post(h)``: one route per chained method."""
    return [(method, match.group("path")) for method in _chain_methods(match.string, match.end())]


def _go_handle(match: re.Match) -> list[tuple[str, str]]:
    """net/http patterns, with Go 1.22's method prefix ("GET /items/{id}"), and gorilla/mux's
    ``.Methods(...)``."""
    path, method = match.group("path"), "ANY"
    prefixed = re.match(r"([A-Z]{3,7})[ \t]+(\S.*)", path)
    if prefixed:
        method, path = prefixed.group(1), prefixed.group(2)
    listed = _methods(match.group("methods")) if match.group("methods") else []
    return [(item, path) for item in listed or [method]]


def _chained(match: re.Match) -> list[tuple[str, str]]:
    """tide's ``app.at("/x").get(h).post(h)``, poem's ``.at("/x", get(h).post(h))``, actix's
    ``web::resource("/x").route(web::get()...)`` and Crow's ``CROW_ROUTE(app, "/x").methods(...)``:
    the methods inside the call or chained after it."""
    text, path = match.string, match.group("path") or ""
    rest = _call_rest(text, match.end())
    crow = match.group(0).upper().startswith("CROW_")  # the macro's own arguments name no method
    methods = [] if crow else _methods(rest)
    after = match.end() + len(rest) + 1
    listed = _CROW_METHODS.match(text[after:after + 400].lstrip())
    if listed:
        methods = _methods(listed.group(1))
    elif not methods:
        methods = _chain_methods(text, after)
    return [(item, path) for item in methods] or [("WEBSOCKET" if "WEBSOCKET" in match.group(0) else "ANY", path)]


_OBJECT_METHOD = re.compile(r"""\bmethod\s*:\s*(\[[^\]\n]{0,100}\]|['"][\w*]{1,10}['"])""")
_OBJECT_PATH = re.compile(r"""\b(?:url|path)\s*:\s*['"`](/[^'"`\n]*)['"`]""")


def _route_object(match: re.Match) -> list[tuple[str, str]]:
    """Fastify and hapi route objects: ``{ method: 'GET', url: '/x' }``, in either order; the
    body is read to its closing brace with strings skipped ('/users/{id}' holds braces)."""
    body = _call_rest(match.string, match.end(), 1500)
    path = _OBJECT_PATH.search(body)
    if path is None:
        return []
    method = _OBJECT_METHOD.search(body)
    return [(item, path.group(1)) for item in (_methods(method.group(1)) if method else []) or ["ANY"]]


def _http_receiver(methods: str) -> str:
    """A ``receiver.verb(`` call prefix: a whole identifier or a call's closing parenthesis."""
    return rf"(?:\b[A-Za-z_$][\w$]{{0,63}}|\))\s*\.\s*(?P<method>{methods})\s*\("


_MARKERS = {
    "js-server": re.compile(
        r"""(?:require\s*\(\s*|\bfrom\s+|\bimport\s+)['"](?:express|koa-router|@koa/router|koa-tree-router|fastify|hono"""
        r"""|restify|polka|@hapi/hapi|@tinyhttp/app|hyper-express|ultimate-express|elysia|router|find-my-way"""
        r"""|@feathersjs/express|@adonisjs/core|@nestjs/core)['"/]"""
    ),
    "go-router": re.compile(
        r'"github\.com/(?:go-chi/chi|gofiber/fiber|gorilla/mux|labstack/echo|gin-gonic/gin|julienschmidt/httprouter'
        r"|kataras/iris|beego/beego|astaxie/beego|fasthttp/router|go-martini/martini|go-zoo/bone)"
    ),
    "jvm-router": re.compile(
        r"\bimport\s+(?:static\s+)?(?:io\.javalin|io\.vertx|io\.jooby|ratpack|org\.scalatra|spark\.|io\.ktor"
        r"|org\.http4k|com\.linecorp\.armeria|io\.helidon|org\.jooby)"
    ),
    "free-router": re.compile(r"\bimport\s+(?:static\s+)?(?:spark\.Spark|spark\.kotlin|io\.ktor|org\.scalatra)"),
    "vertx": re.compile(r"\bimport\s+io\.vertx"),
    "micronaut": re.compile(r"\bimport\s+io\.micronaut"),
    "quarkus": re.compile(r"\bimport\s+io\.quarkus\.vertx\.web"),
    "akka": re.compile(r"\bimport\s+(?:akka\.http|org\.apache\.pekko\.http)"),
    "scalatra": re.compile(r"\bimport\s+org\.scalatra"),
    "nancy": re.compile(r"^\s*using\s+(?:Nancy|FastEndpoints)\b"),
    "axum": re.compile(r"\b(?:use|extern\s+crate)\s+(?:axum|actix_web|salvo)\b"),
    "warp": re.compile(r"\b(?:use|extern\s+crate)\s+warp\b"),
    "tide": re.compile(r"\b(?:use|extern\s+crate)\s+(?:tide|poem)\b"),
    "swift-server": re.compile(r"^\s*import\s+(?:Vapor|Kitura|Hummingbird)\b"),
    "shelf": re.compile(r"""\bimport\s+['"]package:(?:shelf_router|shelf_plus|alfred)/"""),
    "conduit": re.compile(r"""\bimport\s+['"]package:(?:conduit|aqueduct)(?:_core)?/"""),
    "dart-frog": re.compile(r"""\bimport\s+['"]package:dart_frog/"""),
    "httplib": re.compile(r"""#\s*include\s*[<"](?:[\w/]*/)?httplib\.h[>"]"""),
    "grape": re.compile(r"\bGrape::API\b"),
    "roda": re.compile(r"<\s*Roda\b|\bRoda\.route\b|\broute\s+do\s*\|\s*r\s*\|"),
    "reitit": re.compile(r"\breitit\b"),
    "cowboy": re.compile(r"\bcowboy_router\b"),
    "vibe": re.compile(r"\bimport\s+vibe\."),
    "nuxt": re.compile(r"\b(?:defineEventHandler|eventHandler|defineCachedEventHandler)\s*\("),
}

_JS_CLIENTS = r"(?!(?:axios|http|https|client|request|got|ky|superagent|fetch|instance|service|\$http)\b)"
_JS = (
    # Express-style routers with the receivers routers are usually named (not `api`, which
    # names an HTTP client as often as a router: it counts in a file importing a server).
    _Form("Express-style", re.compile(
        r"""(?<![\w$])(?:app|router|server|fastify|r|mux|e|g|group|engine)\s*\.\s*"""
        r"""(?P<method>get|post|put|patch|delete|options|head)\s*\(\s*['"`](?P<path>(?:/|\*)[^'"`]*)['"`]""",
        re.I,
    )),
    # Any receiver, in a file that imports a server framework (HTTP clients are excluded by name).
    _Form("Express-style", re.compile(
        r"""(?<![\w$])""" + _JS_CLIENTS + r"""[A-Za-z_$][\w$]{0,63}\s*\.\s*"""
        r"""(?P<method>get|post|put|patch|delete|options|head|all)\s*\(\s*['"`](?P<path>/[^'"`]*)['"`]"""
    ), marker="js-server"),
    _Form("Express", re.compile(r"""\.\s*route\s*\(\s*['"`](?P<path>/[^'"`]*)['"`]\s*\)"""), read=_route_chain,
          marker="js-server"),
    # Fastify and hapi route objects: { method: 'GET', url: '/x' }, in either order.
    _Form("Fastify/hapi", re.compile(r"\.\s*route\s*\(\s*\{"), read=_route_object),
    # NestJS (and Micronaut) decorators; Retrofit and Feign's @GET("...") declare calls a
    # client makes, not endpoints the project serves.
    _Form("NestJS", re.compile(r"""@(?P<method>Get|Post|Put|Patch|Delete|Options|Head|All)\(\s*(?:['"`](?P<path>[^'"`]*)['"`])?""")),
    # Next.js App Router and SvelteKit: exported method handlers in route files.
    _Form("file router", re.compile(
        r"(?m)^[ \t]*export[ \t]+(?:async[ \t]+)?(?:function[ \t]+|const[ \t]+|let[ \t]+)"
        r"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"
    ), file_route=("next-app", "sveltekit")),
    _Form("file router", re.compile(r"(?m)^[ \t]*export[ \t]+default\b"), file_route=("next-pages",)),
    _Form("file router", re.compile(r"\b(?:defineEventHandler|eventHandler|defineCachedEventHandler)\s*\("),
          file_route=("nuxt",)),
)
_GO = (
    # net/http (Go 1.22 method patterns: "GET /items/{id}") and gorilla/mux's .Methods(...).
    _Form("net/http", re.compile(
        r'\bHandle(?:Func)?\s*\(\s*"(?P<path>(?:[A-Z]{3,7}\s+)?[^"\s/]*/[^"\n]*)"'
        r"(?:[^()\n]{0,200}\)\s*\.\s*Methods\s*\((?P<methods>[^()\n]{0,200})\))?"
    ), read=_go_handle),
    # Gin, Echo, httprouter and Iris: upper-case method names on any receiver.
    _Form("Gin/Echo", re.compile(
        r'(?:\b\w{1,64}|\))\s*\.\s*(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)\s*\(\s*"(?P<path>[^"\n]*)"'
    )),
    # chi and Fiber: capitalized method names, in a file that imports a router.
    _Form("chi/Fiber", re.compile(
        r'(?:\b\w{1,64}|\))\s*\.\s*(?P<method>Get|Post|Put|Patch|Delete|Options|Head|Connect|Trace|All)\s*\(\s*"(?P<path>/[^"\n]*)"'
    ), marker="go-router"),
    _Form("chi/Echo", re.compile(
        r'\.\s*(?:Method|MethodFunc|Add|Handle)\s*\(\s*"(?P<method>[A-Z]{3,7})"\s*,\s*"(?P<path>[^"\n]*)"'
    ), marker="go-router"),
    _Form("Beego", re.compile(r'\b(?:beego|web)\s*\.\s*Router\s*\(\s*"(?P<path>/[^"\n]*)"'), method="ANY"),
)
_JVM = (
    # Spring: @GetMapping, @GetMapping("/x"), @GetMapping(value = "/x"), and @RequestMapping
    # with its method = RequestMethod.X.
    _Form("Spring", re.compile(r"@(?P<method>Get|Post|Put|Patch|Delete|Request)Mapping\b"), read=_spring),
    _Form("Micronaut", re.compile(r"""@(?P<method>Get|Post|Put|Patch|Delete|Options|Head)\(\s*(?:["'](?P<path>[^"']*)["'])?""")),
    _Form("Micronaut", re.compile(r"@(?P<method>Get|Post|Put|Patch|Delete|Options|Head)\b(?!\s*\()"), marker="micronaut"),
    # Javalin, Spark, Vert.x, Jooby, Ratpack and Scalatra: receiver.verb("/x", ...).
    _Form("Javalin/Vert.x", re.compile(_http_receiver("get|post|put|patch|delete|head|options") + r'\s*"(?P<path>/[^"\n]*)"'),
          marker="jvm-router"),
    # Spark's static imports, Ktor's routing DSL and Scalatra: get("/x") { ... }.
    _Form("Ktor/Spark", re.compile(r'(?<![\w.])(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*"(?P<path>/[^"\n]*)"'),
          marker="free-router"),
    _Form("Vert.x", re.compile(r'\.\s*route\s*\(\s*(?:HttpMethod\s*\.\s*(?P<method>[A-Z]{3,7})\s*,\s*)?"(?P<path>/[^"\n]*)"'),
          marker="vertx"),
    _Form("Quarkus", re.compile(r'@Route\s*\(\s*(?:path\s*=\s*)?"(?P<path>[^"\n]*)"'), read=_field_methods, marker="quarkus"),
    _Form("http4s", re.compile(
        r"case\s+(?:\w{1,64}\s*@\s*)?(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*->\s*Root(?P<rest>[^\n=]{0,300})"
    ),
          read=_http4s),
    _Form("Akka HTTP", re.compile(r'(?<![\w.])path\s*\(\s*"(?P<path>[^"\n]+)"'), method="ANY", marker="akka",
          read=lambda match: [("ANY", "/" + match.group("path").strip("/"))]),
    _Form("Cask", re.compile(r'@cask\s*\.\s*(?P<method>get|post|put|delete|route)\s*\(\s*"(?P<path>[^"\n]*)"')),
    # Grails URL mappings: "/books"(controller: "book") and get "/books"(...).
    _Form("Grails", re.compile(r'(?m)^[ \t]*(?:(?P<method>get|post|put|patch|delete)[ \t]+)?"(?P<path>/[^"\n]*)"\s*\(\s*\w+\s*:'),
          marker="grails"),
)
_CSHARP = (
    _Form("ASP.NET", re.compile(
        r"""\[\s*Http(?P<method>Get|Post|Put|Patch|Delete|Options|Head)(?:\s*\(\s*['"](?P<path>[^'"]*)['"]\s*\))?\s*\]""",
        re.I,
    )),
    # Minimal APIs and Carter: MapGet on any receiver; MapMethods with its method list.
    _Form("ASP.NET minimal API", re.compile(
        r'(?:\b\w{1,64}|\))\s*\.\s*Map(?P<method>Get|Post|Put|Patch|Delete)\s*\(\s*(?:pattern\s*:\s*)?@?"(?P<path>[^"\n]*)"'
    )),
    _Form("ASP.NET minimal API", re.compile(
        r'\.\s*MapMethods\s*\(\s*@?"(?P<path>[^"\n]*)"\s*,\s*(?:new\s*+(?:\[\]\s*+)?\{|\[)(?P<methods>[^}\]\n]{0,200})'
    )),
    _Form("ASP.NET", re.compile(
        r'\.\s*MapControllerRoute\s*\(\s*(?:name\s*:\s*)?"[^"\n]*"\s*,\s*(?:pattern\s*:\s*)?"(?P<path>[^"\n]*)"'
    ), method="ANY"),
    _Form("ServiceStack", re.compile(r'\[\s*Route\s*\(\s*"(?P<path>/[^"\n]*)"\s*,\s*"(?P<methods>[^"\n]*)"')),
    # Nancy modules and FastEndpoints: Get("/x", ...) in a file that uses them.
    _Form("Nancy/FastEndpoints", re.compile(r'(?<![\w.])(?P<method>Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*"(?P<path>/[^"\n]*)"'),
          marker="nancy"),
)
_VB = (
    _Form("ASP.NET", re.compile(r'<\s*Http(?P<method>Get|Post|Put|Patch|Delete)\s*+(?:\(\s*"(?P<path>[^"\n]*)"\s*\)\s*+)?>', re.I)),
    _Form("ASP.NET minimal API", re.compile(r'\.\s*Map(?P<method>Get|Post|Put|Patch|Delete)\s*\(\s*"(?P<path>[^"\n]*)"')),
)
_PHP = (
    _Form("Laravel", re.compile(r"""Route\s*::\s*(?P<method>get|post|put|patch|delete|options|head|any)\s*\(\s*['"](?P<path>[^'"]+)['"]""", re.I)),
    _Form("Laravel", re.compile(r"""Route\s*::\s*match\s*\(\s*\[(?P<methods>[^\]\n]{0,200})\]\s*,\s*['"](?P<path>[^'"]+)['"]""", re.I)),
    # Slim, Lumen, CodeIgniter 4 and Mezzio: $app->get('/x', ...) on a router-named receiver.
    _Form("Slim/Lumen", re.compile(
        r"""\$(?:app|router|routes|route|group|r|api|collector|routeCollector)\s*->\s*"""
        r"""(?P<method>get|post|put|patch|delete|options|any)\s*\(\s*['"](?P<path>[^'"\n]*)['"]"""
    )),
    _Form("Slim", re.compile(r"""\$\w{1,64}\s*->\s*map\s*\(\s*\[(?P<methods>[^\]\n]{0,200})\]\s*,\s*['"](?P<path>[^'"\n]*)['"]""")),
    # Symfony: #[Route('/x', methods: ['GET'])] and the docblock @Route("/x", methods={"GET"}).
    _Form("Symfony", re.compile(r"""#\[\s*Route\s*\(\s*(?:path\s*:\s*)?['"](?P<path>[^'"\n]*)['"]"""), read=_field_methods),
    _Form("Symfony", re.compile(r"""@Route\s*\(\s*(?:path\s*=\s*)?"(?P<path>[^"\n]*)\""""), read=_field_methods),
    _Form("WordPress REST API", re.compile(
        r"""\bregister_rest_route\s*\(\s*['"](?P<ns>[^'"\n]{1,200})['"]\s*,\s*['"](?P<path>[^'"\n]{0,300})['"]"""
    ), read=_wordpress),
)
_RUBY = (
    # Sinatra and Kemal-style blocks: get '/x' do, get('/x') { ... }.
    _Form("Sinatra", re.compile(
        r"""(?m)^[ \t]*(?P<method>get|post|put|patch|delete|options|head)[ \t]*+\(?[ \t]*+['"](?P<path>[^'"\n]+)['"]"""
        r"""[ \t]*+\)?[ \t]*+(?:do\b|\{)""",
        re.I,
    )),
    # Rails and Hanami: get 'x', to: 'c#a' / get 'x' => 'c#a'; match ... via: [...].
    _Form("Rails", re.compile(
        r"""(?m)^[ \t]*(?P<method>get|post|put|patch|delete|options|head)\s+['"](?P<path>[^'"]+)['"]\s*(?:,\s*to:|=>)""",
        re.I,
    )),
    _Form("Rails", re.compile(
        r"""(?m)^[ \t]*match\s+['"](?P<path>[^'"]+)['"][^\n]{0,200}?\bvia:\s*(?P<methods>\[[^\]\n]{0,100}\]|:\w+)"""
    )),
    _Form("Rails", re.compile(r"""(?m)^[ \t]*root\s+(?:to:\s*)?['"][\w/#]+['"]"""), method="GET",
          read=lambda match: [("GET", "/")]),
    _Form("Grape", re.compile(
        r"""(?m)^[ \t]*(?P<method>get|post|put|patch|delete)[ \t]*+(?:\(?[ \t]*+['"](?P<path>[^'"\n]*)['"][ \t]*+\)?)?"""
        r"""[ \t]*+do\b"""
    ), marker="grape"),
    _Form("Roda", re.compile(r"""\br\s*\.\s*(?P<method>get|post|put|patch|delete|is)\s+['"](?P<path>[^'"\n]*)['"]"""),
          marker="roda"),
)
_RUST = (
    # actix-web and Rocket attributes.
    _Form("actix-web/Rocket", re.compile(
        r"""#\s*\[\s*(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['"](?P<path>[^'"]+)['"]""", re.I,
    )),
    _Form("actix-web/Rocket", re.compile(
        r'#\s*\[\s*route\s*\(\s*(?:(?P<method>[A-Z]{3,7})\s*,\s*uri\s*=\s*)?"(?P<path>[^"\n]*)"'
    ), read=_rest_methods(re.compile(r'method\s*=\s*"(\w+)"'))),
    # axum and actix-web: .route("/x", get(h).post(h)) / .route("/x", web::get().to(h)).
    _Form("axum/actix-web", re.compile(r'\.\s*route\s*\(\s*"(?P<path>/[^"\n]*)"\s*,'), read=_rest_methods(),
          marker="axum"),
    _Form("actix-web", re.compile(r'web\s*::\s*resource\s*\(\s*"(?P<path>[^"\n]*)"\s*\)'), read=_chained, marker="axum"),
    _Form("warp", re.compile(r"warp\s*::\s*path!\s*\((?P<rest>[^()\n]{0,300})\)"), read=_warp, marker="warp"),
    _Form("tide/poem", re.compile(r'\.\s*at\s*\(\s*"(?P<path>/[^"\n]*)"'), read=_chained, marker="tide"),
)
_SWIFT = (
    _Form("Vapor/Kitura", re.compile(_http_receiver("get|post|put|patch|delete|on")), read=_segments,
          marker="swift-server"),
)
_DART = (
    # router.get('/x', h), and the cascade form: Router()..get('/x', h)..post('/y', h).
    _Form("shelf_router", re.compile(
        r"""(?:\b[A-Za-z_$][\w$]{0,63}\s*\.|\)\s*\.|\.\.)\s*(?P<method>get|post|put|patch|delete|head|options|all)"""
        r"""\s*\(\s*['"](?P<path>/[^'"\n]*)['"]"""
    ), marker="shelf"),
    _Form("shelf_router", re.compile(
        r"""@Route\s*\.\s*(?P<method>get|post|put|patch|delete|head|options|all)\s*\(\s*['"](?P<path>[^'"\n]*)['"]"""
    )),
    _Form("shelf_router", re.compile(r"""@Route\s*\(\s*['"](?P<method>[A-Z]{3,7})['"]\s*,\s*['"](?P<path>[^'"\n]*)['"]""")),
    _Form("Conduit", re.compile(r"""\brouter\s*\.\s*route\s*\(\s*['"](?P<path>/[^'"\n]*)['"]"""), method="ANY", marker="conduit"),
    _Form("file router", re.compile(r"\bonRequest\s*\("), file_route=("dart-frog",), marker="dart-frog"),
)
_CPP = (
    _Form("Crow", re.compile(r'\bCROW_(?:BP_|WEBSOCKET_)?ROUTE\s*\([^,()\n]+,\s*"(?P<path>[^"\n]+)"'), read=_chained),
    _Form("Drogon", re.compile(
        r'\b(?:METHOD_ADD|ADD_METHOD_TO|ADD_METHOD_VIA_REGEX|PATH_ADD)\s*\(\s*(?:[\w:&]+\s*,\s*)?"(?P<path>[^"\n]*)"'
    ), read=_rest_methods()),
    _Form("Pistache", re.compile(r'Routes\s*::\s*(?P<method>Get|Post|Put|Patch|Delete|Options|Head)\s*\(\s*\w+\s*,\s*"(?P<path>[^"\n]*)"')),
    _Form("oatpp", re.compile(r'\bENDPOINT(?:_ASYNC)?\s*\(\s*"(?P<method>[A-Z]{3,7})"\s*,\s*"(?P<path>[^"\n]*)"')),
    # httplib::Server's svr.Get("/x", ...); an httplib::Client is usually named cli or client.
    _Form("cpp-httplib", re.compile(
        r'(?:\b(?!(?:cli|client)\b)[A-Za-z_]\w{0,63}|\))\s*\.\s*(?P<method>Get|Post|Put|Patch|Delete|Options)\s*\(\s*"(?P<path>/[^"\n]*)"'
    ), marker="httplib"),
)
_C = (
    _Form("Mongoose", re.compile(r'\bmg_(?:http_)?match_uri\s*\(\s*[\w>.-]{1,64}\s*,\s*"(?P<path>/[^"\n]*)"'), method="ANY"),
    _Form("Mongoose", re.compile(r'\bmg_match\s*\(\s*[\w>.-]{1,64}\s*,\s*mg_str\s*\(\s*"(?P<path>/[^"\n]*)"'), method="ANY"),
)
_ELIXIR = (
    # Phoenix routers and Plug.Router: get "/x", PageController, :index / get "/x" do.
    _Form("Phoenix", re.compile(
        r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete|options|head|live|forward)\s+"(?P<path>[^"\n]*)"\s*,\s*[A-Z]'
    )),
    _Form("Phoenix", re.compile(r'(?m)^[ \t]*match\s+:(?P<method>\w+|\*)\s*,\s*"(?P<path>[^"\n]*)"')),
    _Form("Plug.Router", re.compile(
        r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete|options|head|match)[ \t]+"(?P<path>[^"\n]*)"'
        r'(?:[ \t]*,[ \t]*via:[ \t]*(?P<methods>\[[^\]\n]{0,100}\]|:\w+))?(?:[ \t]*,[^\n]{0,100}?)?[ \t]+do\b'
    )),
)
_CLOJURE = (
    _Form("Compojure", re.compile(r'\(\s*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+"(?P<path>[^"\n]*)"')),
    _Form("Reitit", re.compile(r'\[\s*"(?P<path>/[^"\n]*)"\s*\{(?P<methods>[^{}\n]{0,400})'), marker="reitit",
          read=lambda match: [(item, match.group("path")) for item in _methods(
              " ".join(re.findall(r":(get|post|put|patch|delete|head|options)\b", match.group("methods"))))]
          or [("ANY", match.group("path"))]),
)
_CRYSTAL = (
    _Form("Kemal", re.compile(r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete|options|ws)\s+"(?P<path>[^"\n]*)"\s*(?:do\b|\{)')),
    _Form("Amber", re.compile(r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete)\s+"(?P<path>[^"\n]*)"\s*,\s*[A-Z]\w*\s*,\s*:')),
)
_PERL = (
    # Mojolicious::Lite and Dancer2: get '/x' => sub { ... }.
    _Form("Mojolicious/Dancer2", re.compile(
        r"""(?m)^[ \t]*(?P<method>get|post|put|patch|del|any|options)\s+['"](?P<path>[^'"\n]*)['"]\s*=>"""
    )),
    _Form("Mojolicious", re.compile(
        r"""\$(?:r|routes?|router|auth|api|admin|bridge)\s*->\s*(?P<method>get|post|put|patch|delete|any)\s*\(\s*['"](?P<path>/[^'"\n]*)['"]"""
    )),
)
_LUA = (
    _Form("Lapis/lor", re.compile(
        r"""(?<![\w.])(?:app|router|r)\s*:\s*(?P<method>get|post|put|patch|delete|match)\s*\(\s*(?:["'][\w.-]{1,60}["']\s*,\s*)?["'](?P<path>/[^"'\n]*)["']"""
    )),
)
_HASKELL = (
    _Form("Scotty", re.compile(
        r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete|options)\s+(?:"(?P<path>/[^"\n]*)"|\(\s*(?:literal|capture)\s+"(?P<path2>/[^"\n]*)"\s*\))'
    )),
    _Form("Servant", re.compile(
        r"""(?P<segments>(?:"[^"\n]{0,100}"\s*:>\s*|Capture'?\s+(?:'\[[^\]\n]{0,60}\]\s+)?"[^"\n]{0,60}"\s+\w+\s*:>\s*"""
        r"""|QueryParam\w*\s+"[^"\n]{0,60}"\s+\w+\s*:>\s*|ReqBody\s+'\[[^\]\n]{0,60}\]\s+\w+\s*:>\s*){1,12})"""
        r"""(?P<method>Get|Post|Put|Patch|Delete)\s+'\["""
    ), read=_servant),
)
_NIM = (_Form("Jester", re.compile(r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete)\s+"(?P<path>/[^"\n]*)"\s*:')),)
_FSHARP = (
    _Form("Giraffe", re.compile(r'\b(?P<method>GET|POST|PUT|PATCH|DELETE)\s*>=>\s*routef?\s+"(?P<path>[^"\n]*)"')),
    _Form("Saturn/Falco", re.compile(r'(?m)^[ \t]*(?P<method>get|post|put|patch|delete|forward)\s+"(?P<path>/[^"\n]*)"\s+\S')),
)
_ERLANG = (_Form("Cowboy", re.compile(r'\{\s*"(?P<path>/[^"\n]*)"\s*,\s*[a-z]\w*\s*,'), method="ANY", marker="cowboy"),)
_JULIA = (
    _Form("Genie", re.compile(r'(?<![\w.])route\s*\(\s*"(?P<path>/[^"\n]*)"'), read=_field_methods),
    _Form("Oxygen", re.compile(r'@(?P<method>get|post|put|patch|delete)\s+"(?P<path>/[^"\n]*)"')),
    _Form("HTTP.jl", re.compile(r'HTTP\s*\.\s*register!\s*\(\s*\w+\s*,\s*"(?P<method>[A-Z]{3,7})"\s*,\s*"(?P<path>[^"\n]*)"')),
)
_R = (
    _Form("plumber", re.compile(r"#\*\s*@(?P<method>get|post|put|delete|patch|head|options)\s+(?P<path>/[^\s\n]*)")),
    _Form("plumber", re.compile(r'\bpr_(?P<method>get|post|put|delete|patch|head)\s*\(\s*(?:[\w.]+\s*,\s*)?"(?P<path>/[^"\n]*)"')),
)
_OCAML = (_Form("Dream", re.compile(r'\bDream\s*\.\s*(?P<method>get|post|put|patch|delete|any)\s+"(?P<path>[^"\n]*)"')),)
_D = (_Form("vibe.d", re.compile(_http_receiver("get|post|put|patch|delete|any") + r'\s*"(?P<path>/[^"\n]*)"'), marker="vibe"),)
_PASCAL = (_Form("Horse", re.compile(r"""\bTHorse\s*\.\s*(?P<method>Get|Post|Put|Patch|Delete)\s*\(\s*'(?P<path>/[^'\n]*)'""", re.I)),)
# Play and Revel route files: METHOD /path controller.action.
_ROUTES_FILE = (
    _Form("Play/Revel routes", re.compile(r"(?m)^[ \t]*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|\*)\s+(?P<path>/\S*)\s+\S")),
)
_MARKERS["grails"] = re.compile(r"\bclass\s+\w*UrlMappings\b|\bstatic\s+mappings\s*=")

_FAMILY_FORMS: dict[str, tuple[_Form, ...]] = {
    "js": _JS, "go": _GO, "jvm": _JVM, "csharp": _CSHARP, "vb": _VB, "php": _PHP, "ruby": _RUBY, "rust": _RUST,
    "swift": _SWIFT, "dart": _DART, "cpp": _CPP, "c": _C, "elixir": _ELIXIR, "clojure": _CLOJURE, "crystal": _CRYSTAL,
    "perl": _PERL, "lua": _LUA, "haskell": _HASKELL, "nim": _NIM, "fsharp": _FSHARP, "erlang": _ERLANG,
    "julia": _JULIA, "r": _R, "ocaml": _OCAML, "d": _D, "pascal": _PASCAL, "routes": _ROUTES_FILE,
}
_EXTENSION_FAMILIES = {
    **dict.fromkeys((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro"), "js"),
    ".go": "go", **dict.fromkeys((".java", ".kt", ".kts", ".scala", ".sc", ".groovy"), "jvm"), ".cs": "csharp",
    ".vb": "vb", ".php": "php", ".phtml": "php", ".rb": "ruby", ".rake": "ruby", ".rs": "rust", ".swift": "swift",
    ".dart": "dart", **dict.fromkeys((".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h", ".ipp", ".ino"), "cpp"),
    ".c": "c", ".ex": "elixir", ".exs": "elixir", **dict.fromkeys((".clj", ".cljs", ".cljc"), "clojure"),
    ".cr": "crystal", ".pl": "perl", ".pm": "perl", ".lua": "lua", ".hs": "haskell", ".lhs": "haskell",
    ".nim": "nim", ".fs": "fsharp", ".fsx": "fsharp", ".erl": "erlang", ".jl": "julia", ".r": "r", ".ml": "ocaml",
    ".d": "d", ".pas": "pascal",
}
_FILE_ROUTE_FRAMEWORKS = {"next-app": "Next.js", "next-pages": "Next.js", "sveltekit": "SvelteKit", "nuxt": "Nuxt",
                          "dart-frog": "Dart Frog"}
_NUXT_METHOD = re.compile(r"^(?P<stem>.+)\.(?P<method>get|post|put|patch|delete|head|options)$")
_DYNAMIC_SEGMENT = re.compile(r"\[{1,2}(\.\.\.)?([^\[\]]{1,100})\]{1,2}")


def _is_routes_file(path: str) -> bool:
    """Play and Revel route files: conf/routes and conf/*.routes."""
    parts = PurePosixPath(path.replace("\\", "/")).parts
    return len(parts) >= 2 and parts[-2] == "conf" and (parts[-1] == "routes" or parts[-1].endswith(".routes"))


def _family(record: FileRecord) -> str | None:
    if _is_routes_file(record.path):
        return "routes"
    return _EXTENSION_FAMILIES.get(record.extension)


def _route_segment(name: str) -> str | None:
    """A file-system router's directory or file name as a route segment: "" for a route group
    ``(group)``, None for a folder that is not routable (``_private``, ``@slot``)."""
    if name.startswith("(") and name.endswith(")"):
        return ""
    if name.startswith(("_", "@")):
        return None
    dynamic = _DYNAMIC_SEGMENT.fullmatch(name)
    if dynamic:
        return "{" + ("..." if dynamic.group(1) else "") + dynamic.group(2) + "}"
    return name


def _joined(segments: list[str]) -> str | None:
    parts = [_route_segment(segment) for segment in segments]
    if any(part is None for part in parts):
        return None
    return "/" + "/".join(part for part in parts if part)


def _file_route(path: str) -> tuple[str, str, str] | None:
    """(kind, route, method) of a file-system router's handler file, from its path."""
    parts = PurePosixPath(path.replace("\\", "/")).parts
    name, directories = parts[-1], list(parts[:-1])
    stem, _, extension = name.rpartition(".")
    if extension in {"js", "jsx", "ts", "tsx", "mjs"} and stem == "route" and "app" in directories:
        start = len(directories) - directories[::-1].index("app")
        route = _joined(directories[start:])
        return ("next-app", route, "") if route is not None else None
    if extension in {"js", "ts"} and stem == "+server":
        for index in range(len(directories) - 1):
            if directories[index:index + 2] == ["src", "routes"]:
                route = _joined(directories[index + 2:])
                return ("sveltekit", route, "") if route is not None else None
    if extension in {"js", "jsx", "ts", "tsx", "mjs"} and "pages" in directories:
        start = len(directories) - directories[::-1].index("pages")
        if directories[start:start + 1] == ["api"]:
            route = _joined(directories[start:] + ([] if stem == "index" else [stem]))
            return ("next-pages", route, "ANY") if route is not None else None
    if extension in {"js", "ts", "mjs"}:
        for index in range(len(directories) - 1):
            if directories[index] == "server" and directories[index + 1] in {"api", "routes"}:
                method = _NUXT_METHOD.match(stem)
                base = method.group("stem") if method else stem
                prefix = ["api"] if directories[index + 1] == "api" else []
                route = _joined(prefix + directories[index + 2:] + ([] if base == "index" else [base]))
                if route is not None:
                    return "nuxt", route, method.group("method").upper() if method else "ANY"
    if extension == "dart" and "routes" in directories:
        start = len(directories) - directories[::-1].index("routes")
        route = _joined(directories[start:] + ([] if stem == "index" else [stem]))
        return ("dart-frog", route, "ANY") if route is not None else None
    return None


# --------------------------------------------------------------------------------- Python

_PY_FRAMEWORKS = (
    ("fastapi", "FastAPI"), ("flask", "Flask"), ("quart", "Quart"), ("sanic", "Sanic"), ("aiohttp", "aiohttp"),
    ("starlette", "Starlette"), ("litestar", "Litestar"), ("starlite", "Litestar"), ("robyn", "Robyn"),
    ("falcon", "Falcon"), ("bottle", "Bottle"), ("blacksheep", "BlackSheep"), ("tornado", "Tornado"),
    ("pyramid", "Pyramid"), ("rest_framework", "Django REST framework"), ("django", "Django"),
)
# Frameworks whose route decorators are free functions: @get("/x"), @route("/x").
_PY_FREE_DECORATORS = frozenset({"litestar", "starlite", "blacksheep", "bottle"})
_PY_ROUTE_CLASSES = {"Route": "ANY", "APIRoute": "ANY", "WebSocketRoute": "WEBSOCKET", "APIWebSocketRoute": "WEBSOCKET"}


def _literal(node: ast.AST) -> str | None:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    return value if isinstance(value, str) else None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _py_methods(call: ast.Call, default: str = "ANY") -> list[str]:
    """The ``methods=[...]`` (or ``method=``) keyword's methods, upper-cased."""
    value = _keyword(call, "methods") or _keyword(call, "method") or _keyword(call, "http_method")
    if isinstance(value, ast.List | ast.Tuple | ast.Set):
        methods = [_literal(item) for item in value.elts]
        return [item.upper() for item in methods if item] or [default]
    single = _literal(value) if value is not None else None
    return [single.upper()] if single else [default]


def _py_imports(tree: ast.AST) -> tuple[set[str], set[str]]:
    """(top-level modules imported, local names imported from free-decorator frameworks)."""
    modules: set[str] = set()
    free: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            top = node.module.split(".")[0]
            modules.add(top)
            if top in _PY_FREE_DECORATORS:
                free.update(alias.asname or alias.name for alias in node.names)
    return modules, free


def _python_routes(source: str, relative: str) -> list[tuple[str, str, int, str]]:
    """(method, path, line, framework) of the routes a Python file declares."""
    tree = parse_python(source, filename=relative)
    modules, free = _py_imports(tree)
    framework = next((name for module, name in _PY_FRAMEWORKS if module in modules), "Python")
    django = "django" in modules or PurePosixPath(relative.replace("\\", "/")).name == "urls.py"
    routes: list[tuple[str, str, int, str]] = []

    def add(methods: list[str], path: str | None, line: int, name: str = framework) -> None:
        if path is not None:
            routes.extend((method, path, line, name) for method in methods)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                if isinstance(func, ast.Attribute):
                    method = func.attr.lower()
                elif isinstance(func, ast.Name) and func.id in free:
                    method = func.id.lower()
                else:
                    continue
                if method not in _HTTP_METHODS | {"route", "api_route", "websocket"}:
                    continue
                path = _literal(decorator.args[0]) if decorator.args else _literal(_keyword(decorator, "path"))
                if method in {"route", "api_route"}:
                    add(_py_methods(decorator), path, node.lineno)
                else:
                    add(["WEBSOCKET" if method == "websocket" else method.upper()], path, node.lineno)
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            strings = [_literal(argument) for argument in node.args]
            first = strings[0] if strings else None
            if name in {"path", "re_path", "url"} and django and first is not None and (name != "url" or "django" in modules):
                add(["ANY"], first, node.lineno, "Django")
            elif name in _PY_ROUTE_CLASSES and first is not None and first.startswith("/"):
                add(_py_methods(node, _PY_ROUTE_CLASSES[name]), first, node.lineno)
            elif name in {"add_url_rule", "add_api_route", "add_api_websocket_route"} and first is not None:
                default = "WEBSOCKET" if name == "add_api_websocket_route" else "GET" if name == "add_url_rule" else "ANY"
                add(_py_methods(node, default), first, node.lineno)
            elif name.startswith("add_") and name[4:] in _HTTP_METHODS and first is not None:  # aiohttp
                add([name[4:].upper()], first, node.lineno, "aiohttp")
            elif name == "add_route":
                literal = [value for value in strings if value is not None]
                if len(literal) >= 2 and literal[0].upper() in {item.upper() for item in _HTTP_METHODS} | {"*"}:
                    add([_method(literal[0])], literal[1], node.lineno, "aiohttp")  # add_route('GET', '/x', h)
                elif len(literal) >= 2 and not literal[0].startswith("/"):
                    add(["ANY"], literal[1], node.lineno, "Pyramid")  # config.add_route('name', '/x')
                elif literal and literal[0].startswith("/"):
                    add(_py_methods(node), literal[0], node.lineno)  # Falcon, and Sanic's add_route(h, '/x')
            elif (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "web"
                    and name in _HTTP_METHODS | {"route", "view"} and "aiohttp" in modules):
                if name == "route" and len(strings) >= 2 and strings[0] and strings[1] is not None:
                    add([_method(strings[0])], strings[1], node.lineno, "aiohttp")
                elif name != "route":
                    add(["ANY" if name == "view" else name.upper()], first, node.lineno, "aiohttp")
            elif name == "url" and "tornado" in modules and first is not None:
                add(["ANY"], first, node.lineno, "Tornado")
        elif isinstance(node, ast.List) and "tornado" in modules:
            # Application([(r"/x", Handler), ...]): handler tuples.
            for item in node.elts:
                if isinstance(item, ast.Tuple) and len(item.elts) >= 2 and isinstance(item.elts[1], ast.Name | ast.Attribute):
                    path = _literal(item.elts[0])
                    if path and path.lstrip("^").startswith("/"):
                        add(["ANY"], path, item.lineno, "Tornado")
    return sorted(set(routes), key=lambda item: (item[2], item[0], item[1], item[3]))


# --------------------------------------------------------------------------------- text scan

class _Scan:
    """Reads a source file's logical lines and collects the declarations its forms match."""

    def __init__(self, forms: tuple[_Form, ...], jaxrs: bool, file_route: tuple[str, str, str] | None) -> None:
        self.forms = forms
        self.jaxrs = jaxrs
        self.file_route = file_route
        self.markers = {form.marker: _MARKERS[form.marker] for form in forms if form.marker}
        self.seen: set[str] = set()
        self.routes: list[tuple[str, str, int, str, str]] = []  # (method, path, line, framework, marker)
        self.jaxrs_methods: list[tuple[str, int]] = []
        self.jaxrs_paths: list[tuple[str, int]] = []
        self._lines: list[str] = []
        self._numbers: list[int] = []
        self._depth = 0
        self._chars = 0
        self._complete = False

    def add(self, line: str, number: int) -> None:
        for name, marker in self.markers.items():
            if name not in self.seen and marker.search(line):
                self.seen.add(name)
        text = line.rstrip("\r\n")
        # A complete statement waits for the next line: one that starts with "." continues it
        # (a fluent chain, `.get(...)` or `.route(...)` on a line of its own).
        if self._complete and not text.lstrip().startswith("."):
            self.flush()
        self._lines.append(text)
        self._numbers.append(number)
        self._chars += len(text) + 1
        if "(" in text or "[" in text or ")" in text or "]" in text:
            self._depth += sum(_DEPTH.get(token, 0) for token in _DEPTH_TOKEN.findall(text))
        self._complete = self._depth <= 0
        if len(self._lines) >= MAX_JOINED_LINES or self._chars >= MAX_JOINED_CHARS:
            self.flush()

    def flush(self) -> None:
        if not self._lines:
            return
        offsets, position = [], 0
        for text in self._lines:
            offsets.append(position)
            position += len(text) + 1
        joined = "\n".join(self._lines)
        numbers = self._numbers
        self._lines, self._numbers, self._depth, self._chars, self._complete = [], [], 0, 0, False
        if not _HINT.search(joined) and not self.jaxrs:
            return

        def line_of(offset: int) -> int:
            return numbers[bisect.bisect_right(offsets, offset) - 1]

        if self.jaxrs:
            self.jaxrs_methods += [(match.group(1).upper(), line_of(match.start())) for match in _JAXRS_METHOD.finditer(joined)]
            self.jaxrs_paths += [(match.group(1), line_of(match.start())) for match in _JAXRS_PATH.finditer(joined)]
        for form in self.forms:
            if form.file_route and (self.file_route is None or self.file_route[0] not in form.file_route):
                continue
            for match in form.pattern.finditer(joined):
                line = line_of(match.start())
                if form.file_route:
                    kind, route, method = self.file_route
                    methods = [method] if method else [_method(match.groupdict().get("method"))]
                    self.routes.extend((item, route, line, _FILE_ROUTE_FRAMEWORKS[kind], form.marker) for item in methods)
                    continue
                for method, route in _read(form, match):
                    self.routes.append((method, route, line, form.framework, form.marker))

    def result(self) -> list[tuple[str, str, int, str]]:
        self.flush()
        # A form gated by its framework's marker is the more specific: where two forms match
        # one declaration (Grape's `get ':id' do` reads as Sinatra too), it names the framework.
        routes = [(method, path, line, framework)
                  for method, path, line, framework, marker in sorted(self.routes, key=lambda item: not item[4])
                  if not marker or marker in self.seen]
        # JAX-RS: @GET and its @Path on neighbouring lines (either order).
        for method, line in self.jaxrs_methods:
            near = sorted((abs(path_line - line), path) for path, path_line in self.jaxrs_paths if abs(path_line - line) <= 3)
            routes.append((method, near[0][1] if near else "", line, "JAX-RS"))
        return routes


class APIEndpointAnalyzer(Analyzer):
    """Discover route declarations without starting web servers or resolving runtime routing."""

    name = "api-endpoints"
    limits = AnalyzerLimits(
        MAX_SOURCE_ENDPOINT_SCAN_BYTES,
        "stream",
        {"python_ast_bytes": MAX_PYTHON_ENDPOINT_AST_BYTES, "line_chars": MAX_ENDPOINT_LINE_CHARS, "facts": MAX_ENDPOINT_FACTS},
        outcome="UNKNOWN or partial finding at the byte, Python AST or fact limit",
    )
    domains = ("api_rest", "networking")
    languages = source_language_names()

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and (record.extension in _SOURCE_EXTENSIONS or _is_routes_file(record.path))

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        routes: list[tuple[str, str, int, str]] = []
        truncated = False
        if record.extension in {".py", ".pyi"}:
            if over_limit(record.size_bytes, MAX_PYTHON_ENDPOINT_AST_BYTES):
                return [Finding(
                    "api",
                    f"Python endpoint AST resource limit: {record.path}",
                    f"File size {record.size_bytes:,} bytes exceeds this endpoint parser's "
                    f"{MAX_PYTHON_ENDPOINT_AST_BYTES:,}-byte AST budget.",
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                    severity="LOW",
                )]
            try:
                source = read_python_source_bounded(
                    path, MAX_PYTHON_ENDPOINT_AST_BYTES,
                    expected_identity=record.analysis_identity,
                )
                routes = _python_routes(source, record.path)
            except SourceBudgetExceeded as exc:
                return [Finding(
                    "api", f"Python endpoint AST resource limit: {record.path}",
                    str(exc), confidence="UNKNOWN", evidence=[record.path],
                    analyzer=self.name, severity="LOW",
                )]
            except (OSError, UnicodeDecodeError, SyntaxError, LookupError, RecursionError, MemoryError) as exc:
                return [Finding(
                    "api", f"API endpoint scan unavailable: {record.path}",
                    describe_error(exc), confidence="UNKNOWN",
                    evidence=[record.path], analyzer=self.name, severity="LOW",
                )]
        else:
            family = _family(record)
            if family is None:
                return []
            scan = _Scan(_FAMILY_FORMS[family], family == "jvm", _file_route(record.path))
            bytes_scanned = 0
            line_number = 1
            try:
                with open_verified_text(
                    path, encoding="utf-8", errors="replace",
                    expected_identity=record.analysis_identity,
                ) as stream:
                    while True:
                        if bytes_scanned >= MAX_SOURCE_ENDPOINT_SCAN_BYTES:
                            # Truncated only if content remains. Comparing the file size with
                            # decoded text undercounts CRLF files (newline translation).
                            truncated = bool(stream.read(1))
                            break
                        line = stream.readline(min(
                            MAX_ENDPOINT_LINE_CHARS,
                            MAX_SOURCE_ENDPOINT_SCAN_BYTES - bytes_scanned,
                        ))
                        if not line:
                            break
                        bytes_scanned += len(line.encode("utf-8", errors="replace"))
                        scan.add(line, line_number)
                        if line.endswith(("\n", "\r")):
                            line_number += 1
            except OSError as exc:
                return [Finding(
                    "api", f"API endpoint scan unavailable: {record.path}",
                    describe_error(exc), confidence="UNKNOWN", severity="LOW",
                    evidence=[record.path], analyzer=self.name,
                )]
            routes = scan.result()

        # One declaration per method, route and line; the first form's framework names it.
        first: dict[tuple[str, str, int], str] = {}
        for method, route, line, framework in routes:
            first.setdefault((str(method).upper(), route, line), framework)
        unique = sorted(first.items(), key=lambda item: (item[0][2], item[0][0], item[0][1]))
        for (method, route, line), framework in unique[:MAX_ENDPOINT_FACTS]:
            # Provided endpoints, for the scan's integration summary and cross-project maps.
            code_facts.emit_fact("api_endpoint", f"{method} {route}", line=line, framework=framework)
        findings: list[Finding] = []
        if unique:
            frameworks = sorted({framework for _, framework in unique})
            findings.append(Finding(
                "api",
                f"API route declarations: {record.path}",
                f"Detected {len(unique)} statically recognizable endpoint declaration(s) "
                f"({', '.join(frameworks[:8])}). Route prefixes, middleware, runtime registration, and deployed "
                "reachability are not resolved.",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{line} {method} {route}"
                    for (method, route, line), _ in unique[:150]
                ],
                analyzer=self.name,
            ))
        if over_limit(len(unique), MAX_ENDPOINT_FACTS, "entries"):
            findings.append(Finding(
                "api",
                f"API endpoint facts truncated: {record.path}",
                f"Only the first {MAX_ENDPOINT_FACTS:,} of {len(unique):,} endpoint declarations feed the "
                "integration summary and pdt compare.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        if truncated:
            limit_reached("bytes", MAX_SOURCE_ENDPOINT_SCAN_BYTES, record.size_bytes)
            findings.append(Finding(
                "api",
                f"API endpoint scan budget reached: {record.path}",
                f"Only the first {MAX_SOURCE_ENDPOINT_SCAN_BYTES:,} bytes were scanned. "
                "Later route declarations may not appear in this report.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
