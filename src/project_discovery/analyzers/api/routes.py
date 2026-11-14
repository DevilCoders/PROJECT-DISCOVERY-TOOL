"""Source-level HTTP endpoint declaration discovery, by language and framework.

Python routes come from the syntax tree, the file's imports deciding which framework a
decorator or registration call belongs to. Every other language is read as text by the
adapters of its family (``_FAMILY_FORMS``, chosen by file extension): each form names its
framework, a pattern for one declaration form and, where the form is not distinctive on its
own (``router.get('/x')`` is also how an HTTP client is called), a marker the file must
contain, usually the framework's import. A declaration spanning lines (a call a formatter
wrapped, a multi-line annotation) is read from its first line joined with the next ones, up
to 8 lines and 2,048 characters, and each route keeps the line it starts on. File-system
routers (Next.js, SvelteKit, Nuxt, Dart Frog) take the route from the file's path. Resource
declarations (Rails, Laravel, Phoenix, Django REST framework routers) expand to their routes, and
``route_structure`` resolves each route's full path in the file: class-level mappings, router
groups and blocks, indented scopes and mounted router variables.
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
from .handlers import route_handler
from .route_structure import (
    Event,
    Layout,
    Route,
    Shape,
    depth_changes,
    external_mounts,
    join_path,
    resolve,
    segments_prefix,
    singular,
)

_SOURCE_EXTENSIONS = source_extensions()
MAX_PYTHON_ENDPOINT_AST_BYTES = 4 * 1024 * 1024  # the syntax-tree budget
MAX_SOURCE_ENDPOINT_SCAN_BYTES = 32 * 1024 * 1024
MAX_ENDPOINT_LINE_CHARS = 256 * 1024
MAX_ENDPOINT_FACTS = 500
# Line text kept while a file streams, to read the handler next to each route.
MAX_HANDLER_TEXT_CHARS = 8 * 1024 * 1024
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
    A ``recv`` group names the router variable the route is declared on; ``unless`` is a
    marker that rules the form out (Rails resources are Grape namespaces in a Grape API), and
    ``role`` tells ``route_structure`` how the declaration may combine with others.
    """

    framework: str
    pattern: re.Pattern
    method: str = ""
    marker: str = ""
    read: Reader | None = None
    file_route: tuple[str, ...] = ()
    role: str = ""
    unless: str = ""


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


_RAILS_PLURAL = (("index", "GET", ""), ("create", "POST", ""), ("new", "GET", "/new"), ("edit", "GET", "/:id/edit"),
                 ("show", "GET", "/:id"), ("update", "PATCH", "/:id"), ("update", "PUT", "/:id"),
                 ("destroy", "DELETE", "/:id"))
_RAILS_SINGULAR = (("create", "POST", ""), ("new", "GET", "/new"), ("edit", "GET", "/edit"), ("show", "GET", ""),
                   ("update", "PATCH", ""), ("update", "PUT", ""), ("destroy", "DELETE", ""))
_PHOENIX = (("index", "GET", ""), ("edit", "GET", "/:id/edit"), ("new", "GET", "/new"), ("show", "GET", "/:id"),
            ("create", "POST", ""), ("update", "PATCH", "/:id"), ("update", "PUT", "/:id"), ("delete", "DELETE", "/:id"))
_LARAVEL = (("index", "GET", ""), ("create", "GET", "/create"), ("store", "POST", ""), ("show", "GET", "/{%s}"),
            ("edit", "GET", "/{%s}/edit"), ("update", "PUT", "/{%s}"), ("update", "PATCH", "/{%s}"),
            ("destroy", "DELETE", "/{%s}"))
_ONLY = re.compile(r"""\b(only|except)\s*:\s*(\[[^\]\n]{0,300}\]|%i\[[^\]\n]{0,300}\]|:\w{1,40})""")
_RAILS_PATH = re.compile(r"""\bpath\s*:\s*['"]([^'"\n]{0,200})['"]""")
_LARAVEL_ONLY = re.compile(r"""->\s*(only|except)\s*\(\s*\[?([^\])\n]{0,300})""")


def _actions(options: str, pattern: re.Pattern = _ONLY) -> tuple[set[str] | None, set[str]]:
    """The ``only`` and ``except`` action names a resource declaration lists."""
    only: set[str] | None = None
    excluded: set[str] = set()
    for kind, listed in pattern.findall(options):
        names = set(re.findall(r"\w+", listed.removeprefix("%i")))
        if kind == "only":
            only = names
        else:
            excluded |= names
    return only, excluded


def _rails_resources(match: re.Match) -> list[tuple[str, str]]:
    """Rails ``resources :photos`` (and ``resource :profile``): the routes it declares, with its
    ``only:``/``except:`` and ``path:`` options."""
    options = match.group("options") or ""
    only, excluded = _actions(options)
    renamed = _RAILS_PATH.search(options)
    actions = _RAILS_PLURAL if match.group("kind") == "resources" else _RAILS_SINGULAR
    routes = []
    for name in re.findall(r":(\w+)", match.group("names")):
        base = "/" + (renamed.group(1).strip("/") if renamed else name)
        routes += [(method, base + suffix) for action, method, suffix in actions
                   if (only is None or action in only) and action not in excluded]
    return routes


def _phoenix_resources(match: re.Match) -> list[tuple[str, str]]:
    """Phoenix ``resources "/users", UserController``, with ``only:``/``except:`` and singletons."""
    options = match.group("options") or ""
    only, excluded = _actions(options)
    base = "/" + match.group("path").strip("/")
    if re.search(r"\bsingleton\s*:\s*true", options):
        actions = tuple((action, method, suffix.replace("/:id", "")) for action, method, suffix in _PHOENIX
                        if action != "index")
    else:
        actions = _PHOENIX
    return [(method, base + suffix) for action, method, suffix in actions
            if (only is None or action in only) and action not in excluded]


def _laravel_resource(match: re.Match) -> list[tuple[str, str]]:
    """Laravel ``Route::resource('photos', ...)`` and ``apiResource``, nested names
    (``photos.comments``) and a chained ``->only([...])``/``->except([...])``."""
    rest = _call_rest(match.string, match.end())
    following = match.string[match.end() + len(rest):match.end() + len(rest) + 400]
    only, excluded = _actions(following, _LARAVEL_ONLY)
    names = match.group("name").split(".")
    base = "".join(f"/{name}/{{{singular(name).replace('-', '_')}}}" for name in names[:-1]) + "/" + names[-1]
    parameter = singular(names[-1]).replace("-", "_")
    api = match.group("kind") == "apiResource"
    return [(method, base + (suffix % parameter if "%s" in suffix else suffix)) for action, method, suffix in _LARAVEL
            if not (api and action in {"create", "edit"}) and (only is None or action in only) and action not in excluded]


def _http_receiver(methods: str) -> str:
    """A ``receiver.verb(`` call prefix: a whole identifier or a call's closing parenthesis."""
    return rf"(?:\b(?P<recv>[A-Za-z_$][\w$]{{0,63}})|\))\s*\.\s*(?P<method>{methods})\s*\("


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
    "free-router": re.compile(
        r"\bimport\s+(?:static\s+)?(?:spark\.Spark|spark\.kotlin|io\.ktor|org\.scalatra|io\.javalin\.apibuilder)"
    ),
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
        r"""(?<![\w$])(?P<recv>app|router|server|fastify|r|mux|e|g|group|engine)\s*\.\s*"""
        r"""(?P<method>get|post|put|patch|delete|options|head)\s*\(\s*['"`](?P<path>(?:/|\*)[^'"`]*)['"`]""",
        re.I,
    )),
    # Any receiver, in a file that imports a server framework (HTTP clients are excluded by name).
    _Form("Express-style", re.compile(
        r"""(?<![\w$])""" + _JS_CLIENTS + r"""(?P<recv>[A-Za-z_$][\w$]{0,63})\s*\.\s*"""
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
        r'(?:\b(?P<recv>\w{1,64})\s*\.\s*)?\bHandle(?:Func)?\s*\(\s*"(?P<path>(?:[A-Z]{3,7}\s+)?[^"\s/]*/[^"\n]*)"'
        r"(?:[^()\n]{0,200}\)\s*\.\s*Methods\s*\((?P<methods>[^()\n]{0,200})\))?"
    ), read=_go_handle),
    # Gin, Echo, httprouter and Iris: upper-case method names on any receiver.
    _Form("Gin/Echo", re.compile(
        r'(?:\b(?P<recv>\w{1,64})|\))\s*\.\s*(?P<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)\s*\(\s*"(?P<path>[^"\n]*)"'
    )),
    # chi and Fiber: capitalized method names, in a file that imports a router.
    _Form("chi/Fiber", re.compile(
        r'(?:\b(?P<recv>\w{1,64})|\))\s*\.\s*(?P<method>Get|Post|Put|Patch|Delete|Options|Head|Connect|Trace|All)\s*\(\s*"(?P<path>/[^"\n]*)"'
    ), marker="go-router"),
    _Form("chi/Echo", re.compile(
        r'\.\s*(?:Method|MethodFunc|Add|Handle)\s*\(\s*"(?P<method>[A-Z]{3,7})"\s*,\s*"(?P<path>[^"\n]*)"'
    ), marker="go-router"),
    _Form("Beego", re.compile(r'\b(?:beego|web)\s*\.\s*Router\s*\(\s*"(?P<path>/[^"\n]*)"'), method="ANY"),
)
_JVM = (
    # Spring: @GetMapping, @GetMapping("/x"), @GetMapping(value = "/x"), and @RequestMapping
    # with its method = RequestMethod.X.
    _Form("Spring", re.compile(r"@(?P<method>Get|Post|Put|Patch|Delete|Request)Mapping\b"), read=_spring, role="mapping"),
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
    ), role="http-verb"),
    # Minimal APIs and Carter: MapGet on any receiver; MapMethods with its method list.
    _Form("ASP.NET minimal API", re.compile(
        r'(?:\b(?P<recv>\w{1,64})|\))\s*\.\s*Map(?P<method>Get|Post|Put|Patch|Delete)\s*\(\s*(?:pattern\s*:\s*)?@?"(?P<path>[^"\n]*)"'
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
    _Form("Symfony", re.compile(r"""#\[\s*Route\s*\(\s*(?:path\s*:\s*)?['"](?P<path>[^'"\n]*)['"]"""), read=_field_methods,
          role="mapping"),
    _Form("Symfony", re.compile(r"""@Route\s*\(\s*(?:path\s*=\s*)?"(?P<path>[^"\n]*)\""""), read=_field_methods,
          role="mapping"),
    _Form("Laravel", re.compile(r"""Route\s*::\s*(?P<kind>resource|apiResource)\s*\(\s*['"](?P<name>[^'"\n]{1,200})['"]"""),
          read=lambda match: _laravel_resource(match)),
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
    _Form("Rails", re.compile(
        r"(?m)^[ \t]*(?P<kind>resources|resource)[ \t]+(?P<names>:\w{1,64}(?:[ \t]*,[ \t]*:\w{1,64}){0,20})(?P<options>[^\n]*)"
    ), read=lambda match: _rails_resources(match), unless="grape"),
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
        r"""(?:\b(?P<recv>[A-Za-z_$][\w$]{0,63})\s*\.|\)\s*\.|\.\.)\s*(?P<method>get|post|put|patch|delete|head|options|all)"""
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
        r'(?:\b(?!(?:cli|client)\b)(?P<recv>[A-Za-z_]\w{0,63})|\))\s*\.\s*(?P<method>Get|Post|Put|Patch|Delete|Options)\s*\(\s*"(?P<path>/[^"\n]*)"'
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
    _Form("Phoenix", re.compile(r'(?m)^[ \t]*resources[ \t]+"(?P<path>[^"\n]*)"[ \t]*,[ \t]*[A-Z][\w.]{0,200}(?P<options>[^\n]*)'),
          read=lambda match: _phoenix_resources(match)),
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
        r"""\$(?P<recv>r|routes?|router|auth|api|admin|bridge|v\d{1,3})\s*->\s*(?P<method>get|post|put|patch|delete|any)\s*\(\s*['"](?P<path>/[^'"\n]*)['"]"""
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
def _quoted_prefix(match: re.Match) -> str:
    return match.groupdict().get("prefix") or match.groupdict().get("path2") or ""


_STRUCTURE: dict[str, tuple[Shape, ...]] = {
    "js": (
        Shape("class", re.compile(r"\bclass[ \t]+(?P<name>[A-Za-z_$][\w$]{0,63})")),
        Shape("class-prefix", re.compile(
            r"""@Controller[ \t]*\([ \t]*(?:['"`](?P<prefix>[^'"`\n]*)['"`]|\{[^{}\n]{0,200}?\bpath[ \t]*:[ \t]*"""
            r"""['"`](?P<path2>[^'"`\n]*)['"`])?"""
        ), read=_quoted_prefix),
        # Express, Koa and Hono: app.use('/api', router) / app.route('/api', api).
        Shape("mount", re.compile(
            r"""\b(?P<parent>[A-Za-z_$][\w$]{0,63})[ \t]*\.[ \t]*(?:use|route)[ \t]*\([ \t]*['"`](?P<prefix>/[^'"`\n]*)['"`]"""
            r"""[ \t]*,"""
        ), marker="js-server"),
        # Where a mounted router comes from: import x from '...', const x = require('...'),
        # import { router as x } from '...'.
        Shape("import", re.compile(
            r"""\bimport[ \t]+(?P<name>[A-Za-z_$][\w$]{0,63})[ \t]*(?:,[ \t]*\{[^{}\n]{0,300}\}[ \t]*)?from[ \t]+"""
            r"""['"](?P<spec>[^'"\n]{1,300})['"]"""
        )),
        Shape("import", re.compile(
            r"""\b(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]{0,63})[ \t]*=[ \t]*require[ \t]*\([ \t]*"""
            r"""['"](?P<spec>[^'"\n]{1,300})['"][ \t]*\)"""
        )),
        Shape("import", re.compile(
            r"""\bimport[ \t]*\{(?P<names>[^{}\n]{1,300})\}[ \t]*from[ \t]+['"](?P<spec>[^'"\n]{1,300})['"]"""
        )),
    ),
    "go": (
        Shape("var", re.compile(r'\b(?P<name>\w{1,64})[ \t]*:?=[ \t]*(?P<parent>\w{1,64})[ \t]*\.[ \t]*Group[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"')),
        Shape("block", re.compile(r'\.[ \t]*Route[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"[ \t]*,[ \t]*func\b'), marker="go-router"),
    ),
    "jvm": (
        Shape("class", re.compile(r"\b(?:class|interface|object|record)[ \t]+(?P<name>[A-Za-z_]\w{0,63})")),
        Shape("class-prefix", re.compile(r'@Controller[ \t]*\([ \t]*(?:value[ \t]*=[ \t]*)?"(?P<prefix>[^"\n]*)"')),
        Shape("block", re.compile(r'(?<![\w.])route[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"[ \t]*\)[ \t]*\{'), marker="free-router"),
        Shape("block", re.compile(r'(?<![\w.])path[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"[ \t]*,[ \t]*\([ \t]*\)[ \t]*->'),
              marker="jvm-router"),
        Shape("block", re.compile(r'(?<![\w.])pathPrefix[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"'), marker="akka"),
    ),
    "csharp": (
        Shape("class", re.compile(r"\b(?:class|record)[ \t]+(?P<name>[A-Za-z_]\w{0,63})")),
        Shape("path-annotation", re.compile(
            r'\[[ \t]*(?:Route|RoutePrefix)[ \t]*\([ \t]*(?:template[ \t]*:[ \t]*)?@?"(?P<prefix>[^"\n]*)"[ \t]*'
            r'(?:,[ \t]*(?:Name|Order)[ \t]*=[^\]\n]{0,100})?\)[ \t]*\]'
        ), role="asp"),
        Shape("var", re.compile(
            r'\b(?:var|RouteGroupBuilder)[ \t]+(?P<name>\w{1,64})[ \t]*=[ \t]*(?P<parent>\w{1,64})[ \t]*\.[ \t]*MapGroup'
            r'[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"'
        )),
    ),
    "vb": (
        Shape("path-annotation", re.compile(r'<[ \t]*(?:Route|RoutePrefix)[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"[ \t]*\)[ \t]*>', re.I),
              role="asp"),
    ),
    "php": (
        Shape("class", re.compile(r"\bclass[ \t]+(?P<name>[A-Za-z_]\w{0,63})")),
        Shape("block", re.compile(r"""(?:Route[ \t]*::|->)[ \t]*prefix[ \t]*\([ \t]*['"](?P<prefix>[^'"\n]*)['"]""")),
        Shape("block", re.compile(
            r"""Route[ \t]*::[ \t]*group[ \t]*\([ \t]*\[[^\]\n]{0,300}?['"]prefix['"][ \t]*=>[ \t]*['"](?P<prefix>[^'"\n]*)['"]"""
        )),
        Shape("block", re.compile(r"""\$\w{1,64}[ \t]*->[ \t]*group[ \t]*\([ \t]*['"](?P<prefix>[^'"\n]*)['"]""")),
    ),
    "ruby": (
        Shape("indent", re.compile(r"(?m)^[ \t]*namespace[ \t]+:(?P<prefix>\w{1,64})"), unless="grape"),
        Shape("indent", re.compile(r"""(?m)^[ \t]*scope[ \t]+(?:path:[ \t]*)?['"](?P<prefix>[^'"\n]*)['"]"""), unless="grape"),
        Shape("indent", re.compile(r"(?m)^[ \t]*resources[ \t]+:(?P<name>\w{1,64})[^\n]*\bdo\b"), unless="grape",
              read=lambda match: f"/{match['name']}/:{singular(match['name'])}_id"),
        Shape("indent", re.compile(r"(?m)^[ \t]*resource[ \t]+:(?P<prefix>\w{1,64})[^\n]*\bdo\b"), unless="grape"),
        Shape("indent", re.compile(
            r"""(?m)^[ \t]*(?:namespace|resources?|group|segment)[ \t]+(?::(?P<prefix>\w{1,64})|['"](?P<path2>[^'"\n]*)['"])"""
            r"""[^\n]*\bdo\b"""
        ), marker="grape", read=_quoted_prefix),
        Shape("indent", re.compile(r"(?m)^[ \t]*route_param[ \t]+:(?P<name>\w{1,64})"), marker="grape",
              read=lambda match: ":" + match["name"]),
        Shape("indent", re.compile(r"""\br[ \t]*\.[ \t]*on[ \t]+['"](?P<prefix>[^'"\n]*)['"]"""), marker="roda"),
    ),
    "elixir": (
        Shape("indent", re.compile(r'(?m)^[ \t]*scope[ \t]+(?:path:[ \t]*)?"(?P<prefix>[^"\n]*)"')),
        Shape("indent", re.compile(r'(?m)^[ \t]*resources[ \t]+"(?P<path2>[^"\n]*)"[^\n]*\bdo\b'),
              read=lambda match: f"{match['path2'].rstrip('/')}/:{singular(match['path2'].rstrip('/').rsplit('/', 1)[-1])}_id"),
    ),
    "swift": (
        Shape("var", re.compile(
            r"\blet[ \t]+(?P<name>\w{1,64})[ \t]*=[ \t]*(?P<parent>\w{1,64})[ \t]*\.[ \t]*grouped[ \t]*\((?P<segments>[^()\n]{0,300})\)"
        ), read=lambda match: segments_prefix(match["segments"])),
        Shape("block", re.compile(r"\.[ \t]*group[ \t]*\((?P<segments>[^()\n]{0,300})\)[ \t]*\{"),
              read=lambda match: segments_prefix(match["segments"])),
    ),
    "rust": (
        Shape("function", re.compile(r"\bfn[ \t]+(?P<name>\w{1,64})")),
        Shape("mount", re.compile(r'\.[ \t]*nest[ \t]*\([ \t]*"(?P<prefix>/[^"\n]*)"[ \t]*,'), marker="axum"),
        Shape("rocket-mount", re.compile(
            r'\.[ \t]*mount[ \t]*\([ \t]*"(?P<prefix>[^"\n]*)"[ \t]*,[ \t]*routes![ \t]*\[(?P<handlers>[^\]\n]{0,1000})\]'
        )),
    ),
    "clojure": (Shape("paren-block", re.compile(r'\([ \t]*context[ \t]+"(?P<prefix>[^"\n]*)"')),),
    "fsharp": (Shape("paren-block", re.compile(r'\bsubRoute[ \t]+"(?P<prefix>[^"\n]*)"')),),
    "ocaml": (Shape("paren-block", re.compile(r'\bDream[ \t]*\.[ \t]*scope[ \t]+"(?P<prefix>[^"\n]*)"')),),
    "perl": (
        Shape("var", re.compile(
            r"""\bmy[ \t]+\$(?P<name>\w{1,64})[ \t]*=[ \t]*\$(?P<parent>\w{1,64})[ \t]*->[ \t]*(?:under|any)[ \t]*\([ \t]*"""
            r"""['"](?P<prefix>/[^'"\n]*)['"]"""
        )),
    ),
}
# Single quotes enclose a character (or a Rust lifetime) in these families, not a string.
_CHAR_FAMILIES = frozenset({"rust", "c", "cpp", "jvm", "csharp", "go"})
# axum's `let api = Router::new()`: the variable a statement's routes are declared on.
_RUST_ROUTER_VARIABLE = re.compile(r"^[ \t]*let[ \t]+(?:mut[ \t]+)?(?P<name>\w{1,64})\b[^=\n]{0,80}=[ \t]*Router[ \t]*::[ \t]*new\b")
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]{0,63}")

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


def _callee(call: ast.Call) -> str:
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _receiver(func: ast.AST) -> str:
    """The router variable a decorator or call is made on: ``router`` in ``router.get(...)``,
    ``app`` in aiohttp's ``app.router.add_get(...)``."""
    value = func.value if isinstance(func, ast.Attribute) else None
    while isinstance(value, ast.Attribute) and value.attr == "router":
        value = value.value
    return value.id if isinstance(value, ast.Name) else ""


def _python_imports(tree: ast.AST) -> dict[str, tuple[str, str, int]]:
    """Local name -> (module, imported attribute or "", relative level) of the file's imports."""
    imports: dict[str, tuple[str, str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0], "", 0)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports[alias.asname or alias.name] = (node.module or "", alias.name, node.level)
    return imports


def _imported_router(node: ast.AST | None, imports: dict[str, tuple[str, str, int]]) -> tuple[str, str, int] | None:
    """(module, router variable, relative level) of a router imported from another module:
    ``users.router`` after ``from app.routers import users``, or ``router`` after
    ``from app.routers.users import router``."""
    if isinstance(node, ast.Name) and node.id in imports:
        module, attribute, level = imports[node.id]
        return (module, attribute, level) if attribute else None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in imports:
        module, attribute, level = imports[node.value.id]
        return (f"{module}.{attribute}" if module and attribute else module or attribute), node.attr, level
    return None


def _python_routes(source: str, relative: str) -> list[tuple[str, str, int, str, str]]:
    """(method, path, line, framework, receiver) of the routes a Python file declares, with the
    prefixes the file gives its routers: ``APIRouter(prefix=)``, ``Blueprint(url_prefix=)``,
    ``include_router(..., prefix=)``, ``register_blueprint(..., url_prefix=)`` (which replaces
    the blueprint's own), aiohttp ``add_subapp``, Starlette ``Mount`` and Django
    ``include(router.urls)``."""
    tree = parse_python(source, filename=relative)
    modules, free = _py_imports(tree)
    framework = next((name for module, name in _PY_FRAMEWORKS if module in modules), "Python")
    django = "django" in modules or PurePosixPath(relative.replace("\\", "/")).name == "urls.py"
    own: dict[str, str] = {}  # router variable -> its own prefix
    mounts: dict[str, tuple[str, str, bool]] = {}  # router -> (mounting router, prefix, replaces its own)
    nested: dict[int, str] = {}  # id(route inside a Starlette Mount) -> the Mount's prefix
    drf: set[str] = set()  # Django REST framework routers
    imports = _python_imports(tree)
    external: list[dict[str, object]] = []  # routers mounted from other modules

    def mount_elsewhere(target: ast.AST | None, prefix: str, receiver: str) -> bool:
        imported = _imported_router(target, imports)
        if imported is None:
            return False
        module, name, level = imported
        external.append({"prefix": prefix, "target_module": module, "target_name": name, "level": level,
                         "receiver": receiver, "framework": framework})
        return True

    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)):
            name, callee = node.targets[0].id, _callee(node.value)
            if callee == "APIRouter":
                own[name] = _literal(_keyword(node.value, "prefix")) or ""
            elif callee == "Blueprint":
                own[name] = _literal(_keyword(node.value, "url_prefix")) or ""
            elif callee in {"DefaultRouter", "SimpleRouter"}:
                drf.add(name)
        elif isinstance(node, ast.Call):
            callee = _callee(node)
            first = node.args[0] if node.args else None
            if callee == "include_router" and first is not None:
                prefix = _literal(_keyword(node, "prefix")) or ""
                local = isinstance(first, ast.Name) and (first.id in own or first.id not in imports)
                if local:
                    mounts[first.id] = (_receiver(node.func), prefix, False)
                else:
                    mount_elsewhere(first, prefix, _receiver(node.func))
            elif callee == "register_blueprint" and first is not None:
                prefix = _literal(_keyword(node, "url_prefix"))
                local = isinstance(first, ast.Name) and (first.id in own or first.id not in imports)
                if local:
                    mounts[first.id] = (_receiver(node.func), prefix or "", prefix is not None)
                else:
                    mount_elsewhere(first, prefix or "", _receiver(node.func))
            elif callee == "add_subapp" and len(node.args) >= 2:
                target = node.args[1]
                if isinstance(target, ast.Name) and target.id not in imports:
                    mounts[target.id] = (_receiver(node.func), _literal(first) or "", False)
                else:
                    mount_elsewhere(target, _literal(first) or "", _receiver(node.func))
            elif callee in {"path", "re_path", "url"} and len(node.args) >= 2 and isinstance(node.args[1], ast.Call):
                included = node.args[1]
                inner = included.args[0] if _callee(included) == "include" and included.args else None
                if isinstance(inner, ast.Tuple) and inner.elts:
                    inner = inner.elts[0]  # include(("blog.urls", "blog"))
                if isinstance(inner, ast.Attribute) and inner.attr == "urls" and isinstance(inner.value, ast.Name) \
                        and inner.value.id not in imports:
                    mounts[inner.value.id] = ("", _literal(first) or "", False)  # include(router.urls)
                elif _literal(inner) is not None:  # include("blog.urls"): another module's urlpatterns
                    external.append({"prefix": _literal(first) or "", "target_module": _literal(inner), "target_name": "",
                                     "level": 0, "receiver": "", "framework": "Django"})
                elif isinstance(inner, ast.Name) and inner.id in imports:  # include(blog_urls)
                    module, attribute, level = imports[inner.id]
                    external.append({"prefix": _literal(first) or "", "target_module": ".".join(
                        part for part in (module, attribute) if part), "target_name": "", "level": level,
                        "receiver": "", "framework": "Django"})
            elif callee == "Mount" and first is not None:
                prefix = join_path([nested.get(id(node), ""), _literal(first) or ""])
                children = _keyword(node, "routes") or (node.args[1] if len(node.args) > 1 else None)
                if isinstance(children, ast.List | ast.Tuple):
                    for child in children.elts:
                        nested[id(child)] = prefix

    def prefixed(path: str, receiver: str, node: ast.AST | None = None) -> str:
        parts, name, guard = [], receiver, set()
        while name and name not in guard:
            guard.add(name)
            mount = mounts.get(name)
            if mount and mount[2]:
                parts.append(mount[1])
            else:
                parts.append(own.get(name, ""))
                if mount:
                    parts.append(mount[1])
            name = mount[0] if mount else ""
        parts.reverse()
        if node is not None and id(node) in nested:
            parts.insert(0, nested[id(node)])
        return join_path([*parts, path]) if any(part.strip("/") for part in parts) else path

    routes: list[tuple[str, str, int, str, str]] = []

    def add(methods: list[str], path: str | None, line: int, name: str = framework, receiver: str = "",
            node: ast.AST | None = None) -> None:
        if path is not None:
            full = prefixed(path, receiver, node)
            routes.extend((method, full, line, name, receiver) for method in methods)

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
                receiver = _receiver(func)
                if method in {"route", "api_route"}:
                    # Flask, Quart, Sanic, Bottle and FastAPI default a route without methods= to GET.
                    add(_py_methods(decorator, "GET"), path, node.lineno, receiver=receiver)
                else:
                    add(["WEBSOCKET" if method == "websocket" else method.upper()], path, node.lineno, receiver=receiver)
        elif isinstance(node, ast.Call):
            func = node.func
            name = _callee(node)
            receiver = _receiver(func)
            strings = [_literal(argument) for argument in node.args]
            first = strings[0] if strings else None
            if name in {"path", "re_path", "url"} and django and first is not None and (name != "url" or "django" in modules):
                included = node.args[1] if len(node.args) > 1 else None
                if not (isinstance(included, ast.Call) and _callee(included) == "include"):
                    add(["ANY"], first, node.lineno, "Django")
            elif name == "register" and receiver in drf and first is not None:
                # A Django REST framework router's list and detail routes.
                base = first.strip("/")
                add(["ANY"], base + "/", node.lineno, "Django REST framework", receiver)
                add(["ANY"], base + "/{pk}/", node.lineno, "Django REST framework", receiver)
            elif name in _PY_ROUTE_CLASSES and first is not None and first.startswith("/"):
                add(_py_methods(node, _PY_ROUTE_CLASSES[name]), first, node.lineno, node=node)
            elif name in {"add_url_rule", "add_api_route", "add_api_websocket_route"} and first is not None:
                default = "WEBSOCKET" if name == "add_api_websocket_route" else "GET" if name == "add_url_rule" else "ANY"
                add(_py_methods(node, default), first, node.lineno, receiver=receiver)
            elif name.startswith("add_") and name[4:] in _HTTP_METHODS and first is not None:  # aiohttp
                add([name[4:].upper()], first, node.lineno, "aiohttp", receiver)
            elif name == "add_route":
                literal = [value for value in strings if value is not None]
                if len(literal) >= 2 and literal[0].upper() in {item.upper() for item in _HTTP_METHODS} | {"*"}:
                    add([_method(literal[0])], literal[1], node.lineno, "aiohttp", receiver)  # add_route('GET', '/x', h)
                elif len(literal) >= 2 and not literal[0].startswith("/"):
                    add(["ANY"], literal[1], node.lineno, "Pyramid", receiver)  # config.add_route('name', '/x')
                elif literal and literal[0].startswith("/"):
                    add(_py_methods(node), literal[0], node.lineno, receiver=receiver)  # Falcon; Sanic's add_route(h, '/x')
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
    return sorted(set(routes), key=lambda item: (item[2], item[0], item[1], item[3])), external


# --------------------------------------------------------------------------------- text scan

class _Scan:
    """Reads a source file's logical lines: the declarations its forms match, the structure its
    shapes find, and each line's brace, bracket and indentation depth."""

    def __init__(self, family: str, file_route: tuple[str, str, str] | None) -> None:
        self.family = family
        self.forms = _FAMILY_FORMS[family]
        self.shapes = _STRUCTURE.get(family, ())
        self.jaxrs = family == "jvm"
        self.chars = family in _CHAR_FAMILIES
        self.file_route = file_route
        names = {form.marker for form in self.forms} | {form.unless for form in self.forms}
        names |= {shape.marker for shape in self.shapes} | {shape.unless for shape in self.shapes}
        self.markers = {name: _MARKERS[name] for name in names if name}
        self.seen: set[str] = set()
        self.routes: list[Route] = []
        self.events: list[Event] = []
        self.layout = Layout()
        self._lines: list[str] = []
        self._numbers: list[int] = []
        self._depth = 0
        self._chars = 0
        self._complete = False
        self._braces = 0  # running totals over the file
        self._parens = 0
        self._base = (0, 0)  # the totals before the logical line being read
        self._router = ""  # Rust: the Router variable the current statement declares

    def add(self, line: str, number: int) -> None:
        for name, marker in self.markers.items():
            if name not in self.seen and marker.search(line):
                self.seen.add(name)
        text = line.rstrip("\r\n")
        # A complete statement waits for the next line: one that starts with "." continues it
        # (a fluent chain, `.get(...)` or `.route(...)` on a line of its own).
        if self._complete and not text.lstrip().startswith("."):
            self.flush()
        if not self._lines:
            self._base = (self._braces, self._parens)
        self._lines.append(text)
        self._numbers.append(number)
        self._chars += len(text) + 1
        parens = braces = 0
        if any(character in text for character in "()[]{}"):
            parens, braces = depth_changes(text, self.chars)
        self._depth += parens
        self._braces += braces
        self._parens += parens
        layout = self.layout
        if len(layout.braces) >= number:  # the next part of a line longer than one read
            layout.braces[number - 1], layout.parens[number - 1] = self._braces, self._parens
        else:
            while len(layout.braces) < number:
                layout.braces.append(self._braces)
                layout.parens.append(self._parens)
                stripped = text.lstrip(" \t")
                layout.indents.append(len(text) - len(stripped) if stripped else -1)
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
        base_braces, base_parens = self._base
        self._lines, self._numbers, self._depth, self._chars, self._complete = [], [], 0, 0, False

        def place(offset: int) -> tuple[int, int]:
            index = bisect.bisect_right(offsets, offset) - 1
            return numbers[index], offset - offsets[index]

        self._structure(joined, place, base_braces, base_parens)
        if not _HINT.search(joined) and not self.jaxrs:
            return
        if self.family == "rust":
            variable = _RUST_ROUTER_VARIABLE.match(joined)
            if variable:
                self._router = variable.group("name")
            elif not joined.lstrip().startswith("."):
                self._router = ""
        if self.jaxrs:
            for match in _JAXRS_METHOD.finditer(joined):
                line, column = place(match.start())
                self.routes.append(Route(match.group(1).upper(), "", line, column, "JAX-RS", role="jaxrs"))
            for match in _JAXRS_PATH.finditer(joined):
                line, column = place(match.start())
                self.events.append(Event("path-annotation", line, column, prefix=match.group(1), role="jaxrs"))
        for form in self.forms:
            if form.file_route and (self.file_route is None or self.file_route[0] not in form.file_route):
                continue
            for match in form.pattern.finditer(joined):
                line, column = place(match.start())
                if form.file_route:
                    kind, route, method = self.file_route
                    methods = [method] if method else [_method(match.groupdict().get("method"))]
                    self.routes.extend(Route(item, route, line, column, _FILE_ROUTE_FRAMEWORKS[kind], form.marker)
                                       for item in methods)
                    continue
                receiver = match.groupdict().get("recv") or self._router
                for method, route in _read(form, match):
                    self.routes.append(Route(method, route, line, column, form.framework, form.marker, form.unless,
                                             receiver, form.role))

    def _structure(self, joined: str, place, base_braces: int, base_parens: int) -> None:
        for shape in self.shapes:
            for match in shape.pattern.finditer(joined):
                line, column = place(match.start())
                groups = match.groupdict()
                prefix = shape.read(match) if shape.read else (groups.get("prefix") or "")
                event = Event(shape.kind, line, column, prefix=prefix, name=groups.get("name") or "",
                              parent=groups.get("parent") or "", marker=shape.marker, unless=shape.unless, role=shape.role)
                if shape.kind in {"class", "block"}:
                    # The block opens at the first brace after the declaration: on this logical
                    # line, or on the next line (a brace on a line of its own).
                    brace = joined.find("{", match.end())
                    if brace >= 0:
                        event.open_line, event.open_column = place(brace)
                        event.level = base_braces + depth_changes(joined[:brace], self.chars)[1] + 1
                    else:
                        event.open_line, event.open_column = numbers_after(place, joined), -1
                        event.level = base_braces + depth_changes(joined, self.chars)[1] + 1
                elif shape.kind == "paren-block":
                    # Compojure's (context ...) and Giraffe's subRoute (...): the parenthesis or
                    # bracket the group opens.
                    opening = match.start() if joined[match.start()] == "(" else _next_open(joined, match.end())
                    if self.family == "ocaml" and opening >= 0:
                        # Dream.scope "/x" [middlewares] [routes]: the routes are the second list.
                        opening = _next_open(joined, opening + len(_call_rest(joined, opening + 1)) + 2)
                    if opening < 0:
                        continue
                    event.open_line, event.open_column = place(opening)
                    event.level = base_parens + depth_changes(joined[:opening], self.chars)[0] + 1
                elif shape.kind == "mount":
                    rest = _call_rest(joined, match.end())
                    event.names = tuple(dict.fromkeys(_IDENTIFIER.findall(re.sub(r"""(['"`]).*?\1""", "", rest))))
                elif shape.kind == "rocket-mount":
                    event.names = tuple(_IDENTIFIER.findall(groups.get("handlers") or ""))
                elif shape.kind == "import":
                    event.target = groups.get("spec") or ""
                    listed = groups.get("names")
                    # import { router as users, other } binds users and other.
                    event.names = tuple(item.split(" as ")[-1].strip() for item in listed.split(",") if item.strip()) \
                        if listed else (event.name,)
                self.events.append(event)

    def mounts(self) -> list[dict[str, str]]:
        """Routers this file mounts but imports from another module (after ``result``)."""
        return external_mounts(self.routes, self.events, self.seen)

    def result(self) -> list[Route]:
        self.flush()
        # A form gated by its framework's marker is the more specific: where two forms match
        # one declaration (Grape's `get ':id' do` reads as Sinatra too), it names the framework.
        routes = sorted(self.routes, key=lambda route: not route.marker)
        return resolve(routes, self.events, self.seen, self.layout)


def numbers_after(place, joined: str) -> int:
    """The line after the logical line ``joined`` (where a brace on its own line opens)."""
    return place(len(joined))[0] + 1


def _next_open(text: str, start: int) -> int:
    """The first parenthesis or bracket at or after ``start``, or -1."""
    positions = [position for position in (text.find("(", start), text.find("[", start)) if position >= 0]
    return min(positions) if positions else -1


class APIEndpointAnalyzer(Analyzer):
    """Discover route declarations without starting web servers or resolving runtime routing."""

    name = "api-endpoints"
    limits = AnalyzerLimits(
        MAX_SOURCE_ENDPOINT_SCAN_BYTES,
        "stream",
        {"python_ast_bytes": MAX_PYTHON_ENDPOINT_AST_BYTES, "line_chars": MAX_ENDPOINT_LINE_CHARS, "facts": MAX_ENDPOINT_FACTS,
         "handler_text_chars": MAX_HANDLER_TEXT_CHARS},
        outcome="UNKNOWN or partial finding at the byte, Python AST or fact limit",
    )
    domains = ("api_rest", "networking")
    languages = source_language_names()

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and (record.extension in _SOURCE_EXTENSIONS or _is_routes_file(record.path))

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        routes: list[tuple[str, str, int, str, str]] = []
        lines: list[str] = []  # the source's lines, to read the handler each route names
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
                routes, mounts = _python_routes(source, record.path)
                lines = source.splitlines()
                for mount in mounts:
                    code_facts.emit_fact("api_mount", str(mount.pop("prefix")), kind="python", **mount)
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
            scan = _Scan(family, _file_route(record.path))
            bytes_scanned = 0
            line_number = 1
            pending: list[str] = []
            kept = 0
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
                        if kept < MAX_HANDLER_TEXT_CHARS:
                            pending.append(line)
                            kept += len(line)
                        if line.endswith(("\n", "\r")):
                            line_number += 1
                            if pending:
                                lines.append("".join(pending))
                                pending = []
                    if pending:
                        lines.append("".join(pending))
            except OSError as exc:
                return [Finding(
                    "api", f"API endpoint scan unavailable: {record.path}",
                    describe_error(exc), confidence="UNKNOWN", severity="LOW",
                    evidence=[record.path], analyzer=self.name,
                )]
            routes = [(route.method, route.path, route.line, route.framework, route.receiver) for route in scan.result()]
            for mount in scan.mounts():
                code_facts.emit_fact("api_mount", mount["prefix"], kind="js", spec=mount["spec"], name=mount["name"])

        # One declaration per method, route and line; the first form's framework names it.
        first: dict[tuple[str, str, int], tuple[str, str]] = {}
        for method, route, line, framework, receiver in routes:
            first.setdefault((str(method).upper(), route, line), (framework, receiver))
        unique = sorted(first.items(), key=lambda item: (item[0][2], item[0][0], item[0][1]))
        for (method, route, line), (framework, receiver) in unique[:MAX_ENDPOINT_FACTS]:
            # Provided endpoints, for the scan's integration summary, cross-project maps and the
            # endpoint catalog, with the handler the declaration names.
            handler = route_handler(lines, line) if lines else ""
            code_facts.emit_fact("api_endpoint", f"{method} {route}", line=line, framework=framework,
                                 **({"receiver": receiver} if receiver else {}), **({"handler": handler} if handler else {}))
        findings: list[Finding] = []
        if unique:
            frameworks = sorted({framework for _, (framework, _) in unique})
            findings.append(Finding(
                "api",
                f"API route declarations: {record.path}",
                f"Detected {len(unique)} statically recognizable endpoint declaration(s) "
                f"({', '.join(frameworks[:8])}), with the prefixes this file declares for them (class mappings, "
                "router groups, scopes and mounts). Prefixes added in other files, middleware, runtime "
                "registration, and deployed reachability are not resolved.",
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
