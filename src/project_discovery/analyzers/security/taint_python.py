"""Python taint tracking over the syntax tree, used by the data-flow analyzer.

Untrusted input enters at *sources*: web request data (Flask, Django, FastAPI,
Starlette, aiohttp, Tornado, Pyramid, Bottle), route-handler parameters, and WebSocket
or socket reads. Values carry *labels* that name where the input entered. Each function
is interpreted in statement order: assignments propagate labels and re-assignment
replaces them, branches merge (a value is tainted if any branch taints it) and loops run
until their labels stop growing. Sanitizers clear labels for the sink kinds they defend
against (``shlex.quote`` for commands, ``os.path.basename`` for paths, ``int()`` for all).

Functions of the same module get *summaries*: which parameters reach a sink and which
reach the return value. Summaries are iterated to a fixed point, so input that passes
through local helpers is followed. Calls into other modules that pass tainted values are
returned as outgoing calls, and module-level functions whose parameters reach a sink are
returned as exported summaries; the code index joins the two across files.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

from ...intelligence.model.python_types import TypeTable, module_aliases

MAX_LABELS = 6
MAX_VISITS = 50_000          # statements interpreted per function and round
MAX_ROUNDS = 4               # summary fixed-point rounds (helper call depth)
MAX_SINKS_PER_PARAMETER = 24

EMPTY: frozenset = frozenset()


@dataclass(frozen=True, slots=True)
class Label:
    kind: str                       # "source" or "param"
    name: str                       # source description or parameter name
    line: int
    index: int = -1                 # parameter position, without self/cls
    cleared: frozenset = EMPTY      # sink kinds the value was sanitized for


@dataclass(frozen=True, slots=True)
class Flow:
    kind: str           # sink kind: sql, command, code, deserialization, template, path, ssrf, xss, redirect
    sink: str           # the sink call as written, e.g. "cursor.execute"
    sink_line: int
    source: str
    source_line: int
    call_line: int      # where the tainted value leaves this function (== sink_line when direct)
    via: str            # helper chain, e.g. "build_query() -> run()"
    function: str


@dataclass(frozen=True, slots=True)
class OutgoingCall:
    target: str         # alias-resolved call target ("pkg.db.run" or ".db.run")
    arg: int            # positional index, or -1 for a keyword argument
    keyword: str
    source: str
    source_line: int
    line: int


@dataclass(slots=True)
class Summary:
    params: tuple[str, ...]
    sinks: dict[int, frozenset] = field(default_factory=dict)   # index -> {(kind, sink, line, via)}
    returns: frozenset = EMPTY                                  # parameter indices reaching return
    returned_sources: frozenset = EMPTY                         # source labels returned

    def key(self) -> tuple:
        return (tuple(sorted(self.sinks.items())), self.returns, self.returned_sources)


@dataclass(slots=True)
class TaintResult:
    flows: list[Flow]
    exported: dict[str, Summary]
    outgoing: list[OutgoingCall]
    sources: int
    truncated: bool


# --------------------------------------------------------------------------- tables

_REQUEST_NAMES = frozenset({"request", "req"})
_REQUEST_ATTRIBUTES = frozenset({
    "args", "form", "values", "json", "data", "cookies", "headers", "files", "GET", "POST",
    "FILES", "COOKIES", "META", "body", "query_params", "path_params", "query", "match_info",
    "query_string", "url", "full_path", "view_args", "params", "matchdict", "raw_post_data",
    "stream", "content", "forms", "query_arguments", "body_arguments", "arguments",
})
_REQUEST_METHODS = frozenset({
    "get_json", "get_data", "json", "form", "body", "text", "read", "post", "stream",
    "get_full_path", "build_absolute_uri",
})
_HANDLER_METHODS = frozenset({
    "get_argument", "get_arguments", "get_query_argument", "get_query_arguments",
    "get_body_argument", "get_body_arguments", "get_cookie",
})
_SOCKET_METHODS = frozenset({"recv", "recvfrom", "receive_text", "receive_json", "receive_bytes"})
_SOCKET_RECEIVER = re.compile(r"(?i)sock|conn|client|websocket|(?:^|_)ws(?:$|_)|peer|channel")
_ROUTE_DECORATORS = frozenset({
    "route", "get", "post", "put", "delete", "patch", "head", "options", "api_route", "websocket",
})
_VALIDATED_ANNOTATIONS = frozenset({
    "int", "float", "bool", "UUID", "uuid.UUID", "date", "datetime", "time", "Decimal",
    "Request", "WebSocket", "BackgroundTasks", "Response", "Session", "AsyncSession", "HTTPConnection",
})
_FLASK_TYPED = re.compile(r"<(?:int|float|uuid):([A-Za-z_]\w*+)>")

_SINK_FUNCTIONS: dict[str, tuple[str, tuple[int, ...]]] = {
    "os.system": ("command", (0,)), "os.popen": ("command", (0,)),
    "subprocess.getoutput": ("command", (0,)), "subprocess.getstatusoutput": ("command", (0,)),
    "commands.getoutput": ("command", (0,)), "asyncio.create_subprocess_shell": ("command", (0,)),
    "eval": ("code", (0,)), "exec": ("code", (0,)), "compile": ("code", (0,)),
    "pickle.loads": ("deserialization", (0,)), "pickle.load": ("deserialization", (0,)),
    "_pickle.loads": ("deserialization", (0,)), "cPickle.loads": ("deserialization", (0,)),
    "marshal.loads": ("deserialization", (0,)), "dill.loads": ("deserialization", (0,)),
    "jsonpickle.decode": ("deserialization", (0,)), "yaml.unsafe_load": ("deserialization", (0,)),
    "pandas.read_pickle": ("deserialization", (0,)), "shelve.open": ("deserialization", (0,)),
    "open": ("path", (0,)), "io.open": ("path", (0,)), "codecs.open": ("path", (0,)),
    "os.remove": ("path", (0,)), "os.unlink": ("path", (0,)), "os.rmdir": ("path", (0,)),
    "shutil.rmtree": ("path", (0,)), "shutil.copy": ("path", (0, 1)), "shutil.copyfile": ("path", (0, 1)),
    "shutil.move": ("path", (0, 1)), "os.rename": ("path", (0, 1)), "flask.send_file": ("path", (0,)),
    "starlette.responses.FileResponse": ("path", (0,)), "fastapi.responses.FileResponse": ("path", (0,)),
    "requests.get": ("ssrf", (0,)), "requests.post": ("ssrf", (0,)), "requests.put": ("ssrf", (0,)),
    "requests.patch": ("ssrf", (0,)), "requests.delete": ("ssrf", (0,)), "requests.head": ("ssrf", (0,)),
    "requests.options": ("ssrf", (0,)), "requests.request": ("ssrf", (1,)),
    "httpx.get": ("ssrf", (0,)), "httpx.post": ("ssrf", (0,)), "httpx.put": ("ssrf", (0,)),
    "httpx.patch": ("ssrf", (0,)), "httpx.delete": ("ssrf", (0,)), "httpx.request": ("ssrf", (1,)),
    "urllib.request.urlopen": ("ssrf", (0,)), "urllib.request.Request": ("ssrf", (0,)),
    "urllib.urlopen": ("ssrf", (0,)), "urllib2.urlopen": ("ssrf", (0,)),
    "flask.render_template_string": ("template", (0,)), "jinja2.Template": ("template", (0,)),
    "mako.template.Template": ("template", (0,)), "django.template.Template": ("template", (0,)),
    "flask.redirect": ("redirect", (0,)), "django.shortcuts.redirect": ("redirect", (0,)),
    "django.http.HttpResponseRedirect": ("redirect", (0,)),
    "django.http.HttpResponsePermanentRedirect": ("redirect", (0,)),
    "starlette.responses.RedirectResponse": ("redirect", (0,)),
    "fastapi.responses.RedirectResponse": ("redirect", (0,)), "werkzeug.utils.redirect": ("redirect", (0,)),
    "markupsafe.Markup": ("xss", (0,)), "flask.Markup": ("xss", (0,)), "jinja2.Markup": ("xss", (0,)),
    "django.utils.safestring.mark_safe": ("xss", (0,)), "django.http.HttpResponse": ("xss", (0,)),
    "sqlalchemy.text": ("sql", (0,)), "sqlalchemy.sql.text": ("sql", (0,)),
    "sqlalchemy.sql.expression.text": ("sql", (0,)), "pandas.read_sql": ("sql", (0,)),
    "pandas.read_sql_query": ("sql", (0,)),
}
_SHELL_FUNCTIONS = frozenset({
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen",
})
_SQL_METHODS = frozenset({"execute", "executemany", "executescript", "exec_driver_sql", "mogrify"})
# Receivers that hold a database connection; ``connect`` is the result of ``sqlite3.connect(...)``.
_DATABASE_RECEIVER = re.compile(
    r"(?i)(?:^|[._])(?:db|database|conn|connection|connect|cur|cursor|session|engine|txn?|transaction|"
    r"connections?)(?:$|[._])"
)

# Calls whose result carries no input-controlled text at all.
_CLEAN_FUNCTIONS = frozenset({
    "int", "float", "bool", "len", "abs", "round", "ord", "hash", "id", "type", "isinstance",
    "callable", "uuid.UUID", "bson.ObjectId", "bson.objectid.ObjectId", "decimal.Decimal",
    "ipaddress.ip_address", "ipaddress.ip_network", "datetime.date.fromisoformat",
    "datetime.datetime.fromisoformat", "hashlib.sha256", "hashlib.md5", "hashlib.sha1",
})
# Calls that make their argument safe for some sink kinds only.
_SANITIZERS: dict[str, frozenset] = {
    "shlex.quote": frozenset({"command"}), "pipes.quote": frozenset({"command"}),
    "os.path.basename": frozenset({"path"}), "posixpath.basename": frozenset({"path"}),
    "ntpath.basename": frozenset({"path"}), "werkzeug.utils.secure_filename": frozenset({"path"}),
    "werkzeug.secure_filename": frozenset({"path"}), "django.utils.text.get_valid_filename": frozenset({"path"}),
    "html.escape": frozenset({"xss", "template"}), "markupsafe.escape": frozenset({"xss", "template"}),
    "flask.escape": frozenset({"xss", "template"}), "jinja2.escape": frozenset({"xss", "template"}),
    "django.utils.html.escape": frozenset({"xss", "template"}), "cgi.escape": frozenset({"xss", "template"}),
    "bleach.clean": frozenset({"xss", "template"}), "urllib.parse.quote": frozenset({"xss", "command"}),
    "urllib.parse.quote_plus": frozenset({"xss", "command"}),
    "django.utils.http.url_has_allowed_host_and_scheme": frozenset({"redirect"}),
}
# Calls whose result is (a transformation of) their arguments.
_PROPAGATING_FUNCTIONS = frozenset({
    "str", "bytes", "bytearray", "repr", "format", "list", "tuple", "set", "frozenset", "dict",
    "sorted", "reversed", "iter", "next", "min", "max", "getattr", "vars",
    "json.loads", "ujson.loads", "orjson.loads", "simplejson.loads", "base64.b64decode",
    "base64.urlsafe_b64decode", "base64.b32decode", "binascii.unhexlify", "binascii.a2b_base64",
    "codecs.decode", "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.urljoin",
    "urllib.parse.parse_qs", "urllib.parse.parse_qsl", "urllib.parse.urlparse", "urllib.parse.urlsplit",
    "urllib.parse.urlunparse", "os.path.join", "os.path.normpath", "os.path.abspath",
    "os.path.expanduser", "os.path.realpath", "os.path.dirname", "posixpath.join", "ntpath.join",
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.PurePosixPath",
    "textwrap.dedent", "copy.copy", "copy.deepcopy", "string.Template", "functools.reduce",
})
_PROPAGATING_METHODS = frozenset({
    "get", "getlist", "pop", "setdefault", "copy", "items", "values", "keys", "strip", "lstrip",
    "rstrip", "lower", "upper", "casefold", "title", "capitalize", "swapcase", "replace", "split",
    "rsplit", "splitlines", "partition", "rpartition", "join", "format", "format_map", "encode",
    "decode", "removeprefix", "removesuffix", "ljust", "rjust", "center", "zfill", "expandtabs",
    "translate", "read", "readline", "readlines", "getvalue", "to_dict", "dict", "model_dump",
    "joinpath", "resolve", "absolute", "with_name", "with_suffix", "as_posix", "substitute",
    "safe_substitute", "first", "geturl", "decode_contents",
})
_ARGUMENT_METHODS = frozenset({"format", "format_map", "join", "replace", "joinpath", "substitute",
                               "safe_substitute"})


class _Budget(Exception):
    pass


def _rank(label: Label) -> tuple:
    return (label.kind != "source", label.line, label.name, label.index, tuple(sorted(label.cleared)))


def _merge(first: frozenset, second: frozenset) -> frozenset:
    if not second:
        return first
    if not first:
        return second
    merged = first | second
    if len(merged) > MAX_LABELS:
        merged = frozenset(sorted(merged, key=_rank)[:MAX_LABELS])
    return merged


def _merge_env(first: dict, second: dict) -> dict:
    if first is second:
        return first
    merged = dict(first)
    for key, value in second.items():
        current = merged.get(key)
        merged[key] = value if current is None else _merge(current, value)
    return merged


def _clear(taint: frozenset, kinds: frozenset) -> frozenset:
    return frozenset(
        Label(label.kind, label.name, label.line, label.index, label.cleared | kinds) for label in taint
    )


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _display(node: ast.AST) -> str:
    dotted = _dotted(node)
    if dotted:
        return dotted
    if isinstance(node, ast.Attribute):
        return f"(...).{node.attr}"
    return "<call>"


def _base_name(node: ast.AST) -> str:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _aliases(tree: ast.Module) -> dict[str, str]:
    return module_aliases(tree)


def _header(node: ast.stmt) -> tuple:
    """Expressions a statement evaluates itself (not those of its nested blocks)."""
    if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr, ast.Return)):
        return (node.value,) if node.value is not None else ()
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return (node.iter,)
    if isinstance(node, (ast.While, ast.If)):
        return (node.test,)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return tuple(item.context_expr for item in node.items)
    if isinstance(node, ast.Match):
        return (node.subject,)
    if isinstance(node, ast.Raise):
        return tuple(item for item in (node.exc, node.cause) if item is not None)
    return ()


def _argument(call: ast.Call, index: int, params: tuple[str, ...]) -> ast.AST | None:
    if index < len(call.args):
        argument = call.args[index]
        return None if isinstance(argument, ast.Starred) else argument
    if params and index < len(params):
        for keyword in call.keywords:
            if keyword.arg == params[index]:
                return keyword.value
    return None


def _shell_true(call: ast.Call) -> bool:
    return any(
        keyword.arg == "shell" and not (isinstance(keyword.value, ast.Constant) and not keyword.value.value)
        for keyword in call.keywords
    )


def _yaml_unsafe(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "Loader":
            return "Safe" not in _dotted(keyword.value) and "Base" not in _dotted(keyword.value)
    return len(call.args) < 2


@dataclass(slots=True)
class _Function:
    key: str
    body: list
    line: int
    owner: str | None
    params: tuple[str, ...]
    route_sources: dict[str, str]
    top_level: bool
    node: object = None


class _Collector:
    def __init__(self) -> None:
        self.flows: set[Flow] = set()
        self.outgoing: set[OutgoingCall] = set()


class PythonTaintEngine:
    def __init__(self, tree: ast.Module, types: TypeTable | None = None) -> None:
        self.tree = tree
        self.aliases = types.aliases if types is not None else _aliases(tree)
        self.types = types if types is not None else TypeTable(tree, self.aliases)
        self.functions: dict[str, _Function] = {}
        self.source_sites: set[tuple[int, str]] = set()
        self.truncated = False
        nested: deque = deque()
        self._collect(tree.body, owner=None, prefix="", top_level=True, nested=nested)
        # Nested functions are callable by their bare name unless a module-level or class
        # definition already uses it.
        while nested:
            body = nested.popleft()
            self._collect(body, owner=None, prefix="", top_level=False, nested=nested)
        self.summaries = {key: Summary(function.params) for key, function in self.functions.items()}
        module_body = [node for node in tree.body
                       if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        self.module = _Function("<module>", module_body, 1, None, (), {}, False)
        self.relevant, self.has_sources = self._relevance()

    # -- relevance -------------------------------------------------------------
    def _features(self, function: _Function) -> tuple[bool, bool, set[str]]:
        """(reads a source, calls a sink, local functions called) for one body."""
        source, sink, called = bool(function.route_sources), False, set()
        for statement in function.body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Attribute):
                    if not source and node.attr in _REQUEST_ATTRIBUTES and self.attribute_source(node):
                        source = True
                elif isinstance(node, ast.Call):
                    name = self.call_name(node.func)
                    local = self.local_function(name, function.owner)
                    if local is not None:
                        called.add(local)
                    elif not source and self.call_source(node, name):
                        source = True
                    elif not sink and self.sink(node, name):
                        sink = True
        return source, sink, called

    def _relevance(self) -> tuple[list[str], bool]:
        """Functions worth interpreting: those reading sources or calling sinks, their
        callers (which may pass parameters on) and their callees (which may return input)."""
        features = {key: self._features(function) for key, function in self.functions.items()}
        module_source, module_sink, module_calls = self._features(self.module)
        relevant = {key for key, (source, sink, _) in features.items() if source or sink}
        if module_source or module_sink:
            relevant |= module_calls
        changed = bool(relevant)
        while changed:
            changed = False
            for key, (_, _, called) in features.items():
                if key in relevant:
                    added = called - relevant
                    if added:
                        relevant |= added
                        changed = True
                elif called & relevant:
                    relevant.add(key)
                    changed = True
        has_sources = module_source or any(source for source, _, _ in features.values())
        if module_source or module_sink or module_calls & relevant:
            relevant.add("<module>")
        return [key for key in [*self.functions, "<module>"] if key in relevant], has_sources

    # -- discovery -------------------------------------------------------------
    def _collect(self, body: list, owner: str | None, prefix: str, top_level: bool, nested: deque) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = f"{prefix}{node.name}"
                arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                if owner is not None and arguments and arguments[0].arg in {"self", "cls"}:
                    arguments = arguments[1:]
                params = tuple(argument.arg for argument in arguments)
                function = _Function(key, node.body, node.lineno, owner, params,
                                     self._route_sources(node, arguments), top_level and owner is None, node)
                if key not in self.functions:
                    self.functions[key] = function
                nested.append(node.body)
            elif isinstance(node, ast.ClassDef) and owner is None:
                self._collect(node.body, owner=node.name, prefix=f"{node.name}.", top_level=False, nested=nested)

    def _route_sources(self, node: ast.FunctionDef | ast.AsyncFunctionDef, arguments: list) -> dict[str, str]:
        route = None
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in _ROUTE_DECORATORS and decorator.args
                    and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)):
                route = decorator.args[0].value
                break
        if route is None:
            return {}
        typed = set(_FLASK_TYPED.findall(route))
        defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + list(node.args.defaults)
        default_of = dict(zip((argument.arg for argument in node.args.args), defaults, strict=True))
        default_of.update(zip((argument.arg for argument in node.args.kwonlyargs), node.args.kw_defaults, strict=True))
        sources = {}
        for argument in arguments:
            name = argument.arg
            annotation = _dotted(argument.annotation) if argument.annotation is not None else ""
            default = default_of.get(name)
            if name in _REQUEST_NAMES or name in typed or annotation in _VALIDATED_ANNOTATIONS:
                continue
            if isinstance(default, ast.Call) and _dotted(default.func).rsplit(".", 1)[-1] in {"Depends", "Security"}:
                continue
            sources[name] = f"route parameter `{name}`"
        return sources

    # -- name resolution -------------------------------------------------------
    def call_name(self, func: ast.AST) -> str:
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        elif isinstance(node, ast.Call):
            inner = self.call_name(node.func)
            if not inner:
                return ""
            parts.append(inner + "()")
        else:
            return ""
        return ".".join(reversed(parts))

    def local_function(self, name: str, owner: str | None) -> str | None:
        if not name:
            return None
        if "." not in name:
            return name if name in self.functions else None
        head, _, rest = name.partition(".")
        if owner and head in {"self", "cls"} and "." not in rest:
            key = f"{owner}.{rest}"
            return key if key in self.functions else None
        return name if name.count(".") == 1 and name in self.functions else None

    def typed_method(self, func: ast.AST, function: _Function) -> str | None:
        """``Ref.method`` for a call on an object whose class the code states."""
        if not isinstance(func, ast.Attribute):
            return None
        owner = function.owner if function.owner in self.types.classes else None
        scope = self.types.scope(function.node, owner) if function.node is not None else self.types.module_scope
        return self.types.method_target(func.value, func.attr, scope, owner)

    def resolve(self, call: ast.Call, name: str, function: _Function) -> tuple[str | None, str | None]:
        """(this module's function key, imported method target) for a call."""
        local = self.local_function(name, function.owner)
        if local is not None:
            return local, None
        typed = self.typed_method(call.func, function)
        if typed is None:
            return None, None
        if typed.startswith("@"):
            key = typed[1:]
            return (key if key in self.functions else None), None
        return None, typed

    def attribute_source(self, node: ast.Attribute) -> str | None:
        if node.attr not in _REQUEST_ATTRIBUTES:
            return None
        value = node.value
        if isinstance(value, ast.Name) and value.id in _REQUEST_NAMES:
            if self.aliases.get(value.id, "").startswith(("urllib", "six.moves")):
                return None
            return f"{value.id}.{node.attr}"
        if isinstance(value, ast.Attribute) and value.attr == "request" and _dotted(value) == "self.request":
            return f"self.request.{node.attr}"
        return None

    def call_source(self, call: ast.Call, name: str) -> str | None:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return None
        method, receiver = func.attr, _dotted(func.value)
        if method in _REQUEST_METHODS and receiver in {"request", "req", "self.request"}:
            if not self.aliases.get(receiver, "").startswith(("urllib", "six.moves")):
                return f"{receiver}.{method}()"
        if method in _HANDLER_METHODS and receiver == "self":
            return f"self.{method}()"
        if method in _SOCKET_METHODS and receiver and _SOCKET_RECEIVER.search(receiver):
            return f"{receiver}.{method}()"
        return None

    def sink(self, call: ast.Call, name: str) -> tuple[str, tuple[int, ...]] | None:
        found = _SINK_FUNCTIONS.get(name)
        if found is not None:
            return found
        if name in _SHELL_FUNCTIONS:
            return ("command", (0,)) if _shell_true(call) else None
        if name == "yaml.load" and _yaml_unsafe(call):
            return ("deserialization", (0,))
        if isinstance(call.func, ast.Attribute):
            method = call.func.attr
            receiver = name.rpartition(".")[0].replace("()", "")
            if method in _SQL_METHODS and _DATABASE_RECEIVER.search(receiver.rsplit(".", 1)[-1]):
                return ("sql", (0,))
            if method == "raw" and receiver.endswith(("objects", "manager")):
                return ("sql", (0,))
            if method == "from_string":
                return ("template", (0,))
        return None

    # -- interpretation --------------------------------------------------------
    def run(self) -> TaintResult:
        functions = [key for key in self.relevant if key != "<module>"]
        for _ in range(MAX_ROUNDS if functions else 0):
            changed = False
            for key in functions:
                summary = _Interpreter(self, self.functions[key], None).run()
                if summary.key() != self.summaries[key].key():
                    self.summaries[key] = summary
                    changed = True
            if not changed:
                break
        collector = _Collector()
        if self.has_sources:
            # Without a source in the file no flow can start here; summaries are enough.
            for key in self.relevant:
                function = self.module if key == "<module>" else self.functions[key]
                _Interpreter(self, function, collector).run()
        exported = {
            key: summary for key, summary in self.summaries.items()
            if summary.sinks and (self.functions[key].top_level or self.functions[key].owner is not None)
            and not key.rpartition(".")[2].startswith("_") and not key.startswith("_")
        }
        return TaintResult(
            sorted(collector.flows, key=lambda flow: (flow.call_line, flow.sink_line, flow.kind, flow.source)),
            exported,
            sorted(collector.outgoing, key=lambda call: (call.line, call.target, call.arg)),
            len(self.source_sites), self.truncated,
        )


class _Interpreter:
    def __init__(self, engine: PythonTaintEngine, function: _Function, collect: _Collector | None) -> None:
        self.engine = engine
        self.function = function
        self.collect = collect
        self.env: dict[str, frozenset] = {}
        self.sinks: dict[int, set] = defaultdict(set)
        self.returns: set[int] = set()
        self.returned_sources: set[Label] = set()
        self.visits = 0
        for index, name in enumerate(function.params):
            labels = {Label("param", name, function.line, index)}
            if name in function.route_sources:
                labels.add(Label("source", function.route_sources[name], function.line))
                self.note_source(function.line, function.route_sources[name])
            self.env[name] = frozenset(labels)

    def run(self) -> Summary:
        try:
            self.block(self.function.body)
        except _Budget:
            self.engine.truncated = True
        except RecursionError:
            self.engine.truncated = True
        return Summary(
            self.function.params,
            {index: frozenset(sorted(entries)[:MAX_SINKS_PER_PARAMETER]) for index, entries in self.sinks.items()},
            frozenset(self.returns), frozenset(sorted(self.returned_sources, key=_rank)[:MAX_LABELS]),
        )

    # -- statements ------------------------------------------------------------
    def block(self, statements: list) -> None:
        for node in statements:
            self.statement(node)

    def statement(self, node: ast.stmt) -> None:
        self.visits += 1
        if self.visits > MAX_VISITS:
            raise _Budget
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        for expression in _header(node):
            for child in ast.walk(expression):
                if isinstance(child, ast.Call):
                    self.check_call(child)
        if isinstance(node, ast.Assign):
            value = self.taint(node.value)
            for target in node.targets:
                self.bind(target, value)
        elif isinstance(node, ast.AugAssign):
            self.bind(node.target, _merge(self.taint(node.target), self.taint(node.value)))
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.bind(node.target, self.taint(node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.bind(node.target, self.taint(node.iter))
            self.loop(node.body)
            self.block(node.orelse)
        elif isinstance(node, ast.While):
            self.loop(node.body)
            self.block(node.orelse)
        elif isinstance(node, ast.If):
            self.branches((node.body, node.orelse))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, self.taint(item.context_expr))
            self.block(node.body)
        elif isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            self.block(node.body)
            for handler in node.handlers:
                self.block(handler.body)
            self.block(node.orelse)
            self.block(node.finalbody)
        elif isinstance(node, ast.Match):
            self.branches([case.body for case in node.cases] + [[]])
        elif isinstance(node, ast.Return):
            if node.value is not None:
                for label in self.taint(node.value):
                    if label.kind == "param":
                        self.returns.add(label.index)
                    else:
                        self.returned_sources.add(label)
        elif isinstance(node, ast.Expr):
            self.taint(node.value)

    def loop(self, body: list) -> None:
        before = self.env
        self.env = dict(before)
        self.block(body)
        merged = _merge_env(before, self.env)
        if merged != self.env:
            self.env = dict(merged)
            self.block(body)
            merged = _merge_env(merged, self.env)
        self.env = merged

    def branches(self, blocks) -> None:
        start = self.env
        merged = None
        for body in blocks:
            self.env = dict(start)
            self.block(body)
            merged = self.env if merged is None else _merge_env(merged, self.env)
        self.env = merged if merged is not None else start

    def bind(self, target: ast.AST, taint: frozenset) -> None:
        if isinstance(target, ast.Name):
            if taint:
                self.env[target.id] = taint
            else:
                self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element, taint)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, taint)
        elif isinstance(target, ast.Attribute):
            key = _dotted(target)
            if key:
                if taint:
                    self.env[key] = taint
                else:
                    self.env.pop(key, None)
        elif isinstance(target, ast.Subscript):
            key = _dotted(target.value)
            if key and taint:
                self.env[key] = _merge(self.env.get(key, EMPTY), taint)

    # -- expressions -----------------------------------------------------------
    def taint(self, node: ast.AST | None) -> frozenset:
        if node is None:
            return EMPTY
        if isinstance(node, ast.Name):
            return self.env.get(node.id, EMPTY)
        if isinstance(node, ast.Attribute):
            source = self.engine.attribute_source(node)
            if source:
                self.note_source(node.lineno, source)
                return frozenset({Label("source", source, node.lineno)})
            key = _dotted(node)
            if key and key in self.env:
                return self.env[key]
            return self.taint(node.value)
        if isinstance(node, ast.Subscript):
            return self.taint(node.value)
        if isinstance(node, ast.Call):
            return self.call_taint(node)
        if isinstance(node, ast.BinOp):
            return _merge(self.taint(node.left), self.taint(node.right))
        if isinstance(node, ast.BoolOp):
            return self.union(node.values)
        if isinstance(node, ast.IfExp):
            return _merge(self.taint(node.body), self.taint(node.orelse))
        if isinstance(node, ast.JoinedStr):
            return self.union(node.values)
        if isinstance(node, ast.FormattedValue):
            return self.taint(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self.union(node.elts)
        if isinstance(node, ast.Dict):
            return self.union([value for value in node.values if value is not None])
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self.union([generator.iter for generator in node.generators])
        if isinstance(node, (ast.Await, ast.Starred)):
            return self.taint(node.value)
        if isinstance(node, ast.NamedExpr):
            value = self.taint(node.value)
            self.bind(node.target, value)
            return value
        if isinstance(node, ast.UnaryOp) and not isinstance(node.op, ast.Not):
            return self.taint(node.operand)
        return EMPTY

    def union(self, nodes) -> frozenset:
        result = EMPTY
        for node in nodes:
            result = _merge(result, self.taint(node))
        return result

    def note_source(self, line: int, description: str) -> None:
        if self.collect is not None:
            self.engine.source_sites.add((line, description))

    def call_taint(self, call: ast.Call) -> frozenset:
        engine = self.engine
        func = call.func
        name = engine.call_name(func)
        source = engine.call_source(call, name)
        if source:
            self.note_source(call.lineno, source)
            return frozenset({Label("source", source, call.lineno)})
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        local, _ = engine.resolve(call, name, self.function)
        if local is not None:
            summary = engine.summaries[local]
            result = summary.returned_sources
            for index in summary.returns:
                argument = _argument(call, index, summary.params)
                if argument is not None:
                    result = _merge(result, self.taint(argument))
            return result
        if name in _CLEAN_FUNCTIONS:
            return EMPTY
        cleared = _SANITIZERS.get(name)
        if cleared is not None:
            return _clear(self.union(arguments), cleared)
        if name in _PROPAGATING_FUNCTIONS:
            return self.union(arguments)
        if isinstance(func, ast.Attribute) and func.attr in _PROPAGATING_METHODS:
            receiver = self.taint(func.value)
            return _merge(receiver, self.union(arguments)) if func.attr in _ARGUMENT_METHODS else receiver
        return EMPTY

    # -- sinks -----------------------------------------------------------------
    def check_call(self, call: ast.Call) -> None:
        engine = self.engine
        name = engine.call_name(call.func)
        local, imported = engine.resolve(call, name, self.function)
        if local is not None:
            summary = engine.summaries[local]
            for index, entries in summary.sinks.items():
                argument = _argument(call, index, summary.params)
                if argument is None:
                    continue
                for label in self.taint(argument):
                    for kind, sink, line, via in entries:
                        if kind not in label.cleared:
                            self.reach(label, kind, sink, line, call.lineno,
                                       f"{local}()" + (f" -> {via}" if via else ""))
            return
        found = engine.sink(call, name)
        if found is not None:
            kind, positions = found
            display = _display(call.func)
            for position in positions:
                argument = _argument(call, position, ())
                if argument is None:
                    continue
                for label in self.taint(argument):
                    if kind not in label.cleared:
                        self.reach(label, kind, display, call.lineno, call.lineno, "")
            return
        if imported is not None:
            name = imported  # a method of an imported class, for the cross-module join
        if self.collect is not None and (imported is not None or _base_name(call.func) in engine.aliases):
            for index, argument in enumerate(call.args):
                for label in self.taint(argument):
                    if label.kind == "source":
                        self.collect.outgoing.add(
                            OutgoingCall(name, index, "", label.name, label.line, call.lineno))
            for keyword in call.keywords:
                if keyword.arg is None:
                    continue
                for label in self.taint(keyword.value):
                    if label.kind == "source":
                        self.collect.outgoing.add(
                            OutgoingCall(name, -1, keyword.arg, label.name, label.line, call.lineno))

    def reach(self, label: Label, kind: str, sink: str, sink_line: int, call_line: int, via: str) -> None:
        if label.kind == "source":
            if self.collect is not None:
                self.collect.flows.add(Flow(kind, sink, sink_line, label.name, label.line, call_line, via,
                                            self.function.key))
        elif len(self.sinks[label.index]) < MAX_SINKS_PER_PARAMETER:
            self.sinks[label.index].add((kind, sink, sink_line, via))


def analyze_python_taint(tree: ast.Module, types: TypeTable | None = None) -> TaintResult:
    return PythonTaintEngine(tree, types).run()
