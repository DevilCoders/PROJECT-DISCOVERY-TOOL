"""Memory and resource management: acquisitions that are never released.

Python is analysed on its syntax tree: a file, socket, connection, child process or
temporary file bound to a name, outside ``with``, that the same function neither
closes, returns nor stores. C/C++, Go, Java and C# use the structural lexer's function
bodies with the same rule; the Rust and JavaScript/TypeScript checks are file-level
patterns (``mem::forget``/``unsafe`` counts, ``setInterval``/``useEffect`` without cleanup). Ownership can move to other
functions in ways a per-function view cannot see, so findings are INFERRED.
"""
from __future__ import annotations

import ast
import re
from collections import Counter, defaultdict
from pathlib import Path

from ...intelligence import facts as code_facts
from ...intelligence.model import FUNCTION_KINDS, FileModel, model_for, supports_language
from ...intelligence.model.lexical import LEXICAL_LANGUAGES
from ...models import FileRecord, Finding
from ..base import Analyzer
from .findings import code_finding

_PY_RESOURCES = {
    "file": ("open", "io.open", "codecs.open", "gzip.open", "bz2.open", "lzma.open", "tarfile.open",
             "zipfile.ZipFile", "ZipFile"),
    "socket": ("socket.socket", "socket.create_connection"),
    "connection": ("sqlite3.connect", "psycopg2.connect", "pymysql.connect", "mysql.connector.connect",
                   "psycopg.connect", "cx_Oracle.connect", "pyodbc.connect"),
    "process": ("subprocess.Popen", "Popen"),
}
_PY_RELEASES = {
    "file": {"close"}, "socket": {"close", "shutdown"}, "connection": {"close"},
    "process": {"wait", "communicate", "kill", "terminate"},
}
# Passing a resource to these hands it to something that will release it; any other
# call (json.load(f), memcpy(p, ...)) only uses it.
_TAKES_OWNERSHIP = re.compile(
    r"(?i)(?:closing|enter_context|append|add|extend|insert|push|put|register|enqueue|attach|"
    r"store|emplace|setdefault|callback|own|take)\w*$"
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


def _direct_names(value: ast.AST) -> set[str]:
    """Names that are the value itself or elements of a literal tuple, list or dict."""
    if isinstance(value, ast.Name):
        return {value.id}
    if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
        return {item.id for item in value.elts if isinstance(item, ast.Name)}
    if isinstance(value, ast.Dict):
        return {item.id for item in value.values if isinstance(item, ast.Name)}
    return set()


_KINDS = {name: kind for kind, names in _PY_RESOURCES.items() for name in names}


def _unbounded_cache(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    arguments = function.args.posonlyargs + function.args.args
    if not arguments or arguments[0].arg not in {"self", "cls"}:
        return False
    for decorator in function.decorator_list:
        name = _dotted(decorator.func if isinstance(decorator, ast.Call) else decorator)
        if name in {"functools.cache", "cache"} or (
            name in {"functools.lru_cache", "lru_cache"} and isinstance(decorator, ast.Call)
            and any(k.arg == "maxsize" and isinstance(k.value, ast.Constant) and k.value.value is None
                    for k in decorator.keywords)
        ):
            return True
    return False


def _python_resources(tree: ast.Module) -> dict[str, list[int]]:
    """One walk over the tree; each function body is its own scope (nested bodies excluded)."""
    issues: dict[str, list[int]] = defaultdict(list)

    def scope(body: list, in_function: bool) -> None:
        acquired: list[tuple[str, str, int]] = []
        handled: set[str] = set()
        released: dict[str, set[str]] = defaultdict(set)
        calls: list[ast.Call] = []
        stack = list(body)
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _unbounded_cache(node):
                    issues["unbounded_method_cache"].append(node.lineno)
                scope(node.body, True)
                stack.extend(node.decorator_list)
                stack.extend(default for default in (*node.args.defaults, *node.args.kw_defaults) if default)
                continue
            if isinstance(node, ast.ClassDef):
                # Module-level handles usually live for the whole program: only functions count.
                scope(node.body, False)
                stack.extend(node.decorator_list)
                continue
            if isinstance(node, ast.Lambda):
                continue
            if isinstance(node, ast.Call):
                if _dotted(node.func) == "tempfile.mktemp":
                    issues["insecure_temporary_name"].append(node.lineno)
                if in_function:
                    calls.append(node)
            if in_function:
                if isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        handled.add(_dotted(item.context_expr))
                        if isinstance(item.context_expr, ast.Call):
                            handled.add(_dotted(item.context_expr.func) + "()")
                elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and len(node.targets) == 1 \
                        and isinstance(node.targets[0], ast.Name):
                    kind = _KINDS.get(_dotted(node.value.func))
                    if kind:
                        acquired.append((node.targets[0].id, kind, node.lineno))
                elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None:
                    # Returning the resource itself hands it to the caller; ``return
                    # json.load(f)`` only uses it.
                    handled.update(_direct_names(node.value))
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(not isinstance(target, ast.Name) for target in targets):
                        handled.update(_direct_names(node.value))  # self.handle = f
            stack.extend(ast.iter_child_nodes(node))
        if not acquired:
            return  # nothing acquired: the call bookkeeping is not needed
        for call in calls:
            name = _dotted(call.func)
            receiver, _, method = name.rpartition(".")
            if receiver:
                released[receiver].add(method)
            if _TAKES_OWNERSHIP.search(method or name or "-"):
                for argument in [*call.args, *(k.value for k in call.keywords)]:
                    if isinstance(argument, ast.Name):
                        handled.add(argument.id)
        for name, kind, line in acquired:
            if name in handled or released[name] & _PY_RELEASES[kind]:
                continue
            issues[f"unreleased_{kind}"].append(line)

    scope(tree.body, False)
    for values in issues.values():
        values.sort()
    return issues


_C_ALLOCATION = re.compile(
    r"(?<![\w$.>])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+(?:\([^()\n]{0,80}+\)[ \t]*+)?"
    r"(malloc|calloc|strdup|strndup|aligned_alloc)[ \t]*+\("
)
_C_REALLOC_SAME = re.compile(r"(?<![\w$.>])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+realloc[ \t]*+\([ \t]*+\1[ \t]*+,")
_C_FOPEN = re.compile(r"(?<![\w$.>])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+fopen[ \t]*+\(")
_CPP_ARRAY_NEW = re.compile(r"(?<![\w$.>])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+new[ \t]++[\w:<>]++[ \t]*+\[")
_ALLOCA = re.compile(r"(?<![\w$.])alloca[ \t]*+\(")
_GO_OPEN = re.compile(r"(?<![\w$.])([A-Za-z_]\w*+)[ \t]*+,[ \t]*+(?:err|_)[ \t]*+:?=[ \t]*+os\.(?:Open|Create|OpenFile)\(")
_GO_HTTP = re.compile(
    r"(?<![\w$.])([A-Za-z_]\w*+)[ \t]*+,[ \t]*+(?:err|_)[ \t]*+:?=[ \t]*+"
    r"(?:http\.(?:Get|Post|Head|PostForm)|[A-Za-z_]\w*+\.Do)\("
)
_GO_ROWS = re.compile(
    r"(?<![\w$.])([A-Za-z_]\w*+)[ \t]*+,[ \t]*+(?:err|_)[ \t]*+:?=[ \t]*+[A-Za-z_][\w.]*?\.Query(?:Context)?\("
)
_JVM_CLOSEABLE = re.compile(
    r"(?<![\w$.])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+new[ \t]++(FileInputStream|FileOutputStream|FileReader|FileWriter|"
    r"RandomAccessFile|BufferedReader|BufferedWriter|PrintWriter|Scanner|ZipFile|JarFile|Socket|ServerSocket|"
    r"ObjectInputStream|ObjectOutputStream|DatagramSocket)[ \t]*+\("
)
_JDBC = re.compile(
    r"(?<![\w$.])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+[A-Za-z_][\w.]*?\.(getConnection|createStatement|prepareStatement|executeQuery)\("
)
_CSHARP_DISPOSABLE = re.compile(
    r"(?<![\w$.])([A-Za-z_]\w*+)[ \t]*+=[ \t]*+new[ \t]++(FileStream|StreamReader|StreamWriter|BinaryReader|"
    r"BinaryWriter|SqlConnection|SqlCommand|NpgsqlConnection|MySqlConnection|TcpClient|Socket|Process|"
    r"FileSystemWatcher|Timer)[ \t]*+\("
)
_CSHARP_NEW_HTTPCLIENT = re.compile(r"(?<![\w$.])new[ \t]++HttpClient[ \t]*+\(")
_RUST_MANUAL = re.compile(r"(?<![\w$])(?:mem::forget|Box::leak|ManuallyDrop::new|mem::transmute)[ \t]*+[(<]")
_RUST_UNSAFE_BLOCK = re.compile(r"(?<![\w$])unsafe[ \t\r\n]*+\{")
_JS_EFFECT = re.compile(r"(?<![\w$.])useEffect[ \t]*+\(")
_JS_SUBSCRIBES = re.compile(r"addEventListener\(|setInterval\(|\.subscribe\(|\.on\(")
_TRY_RESOURCES = re.compile(r"(?<![\w$])(?:try|using)[ \t]*+\(")
_CPP_SMART = re.compile(r"(?<![\w$])(?:make_unique|make_shared|unique_ptr|shared_ptr)\b")


def _guarded_ranges(model: FileModel) -> list[tuple[int, int]]:
    """Resource specifications of try-with-resources and using statements."""
    ranges = []
    for match in _TRY_RESOURCES.finditer(model.clean):
        close = model.parens.get(match.end() - 1)
        if close is not None:
            ranges.append((match.start(), close))
    return ranges


def _released(body: str, name: str, *methods: str) -> bool:
    """Closed by one of ``methods``, returned, assigned elsewhere, or handed to a store."""
    escaped = re.escape(name)
    calls = "|".join(re.escape(method) for method in methods)
    return bool(
        re.search(rf"(?<![\w$.]){escaped}\.(?:{calls})\(", body)
        or re.search(rf"(?<![\w$])return\b[^;\n]{{0,200}}(?<![\w$.]){escaped}\b", body)
        or re.search(rf"[\w$\]][ \t]*+=[ \t]*+{escaped}[ \t]*+;", body)
        or re.search(
            rf"(?i)(?<![\w$.])\w*(?:append|add|push|insert|put|set|store|register|enqueue|attach|emplace|own|take)\w*"
            rf"[ \t]*+\([^;\n]{{0,200}}(?<![\w$.]){escaped}\b", body,
        )
    )


def _lexical_resources(model: FileModel) -> tuple[dict[str, list[int]], Counter]:
    issues: dict[str, list[int]] = defaultdict(list)
    family = LEXICAL_LANGUAGES[model.language]
    clean = model.clean
    stats: Counter = Counter()
    guarded = _guarded_ranges(model) if family in {"java", "csharp", "kotlin", "scala", "groovy"} else []
    functions = [symbol for symbol in model.symbols if symbol.kind in FUNCTION_KINDS and symbol.body]
    for symbol in functions:
        start, end = symbol.body
        body = clean[start:end]

        def line(match, start=start) -> int:
            return model.line_of(start + match.start())

        if family in {"c", "cpp"}:
            for match in _C_ALLOCATION.finditer(body):
                name = match.group(1)
                freed = re.search(rf"(?<![\w$])free[ \t]*+\([ \t]*+{re.escape(name)}[ \t]*+\)", body)
                if not freed and not _released(body, name, "release"):
                    issues["unfreed_allocation"].append(line(match))
            issues["realloc_overwrite"].extend(line(m) for m in _C_REALLOC_SAME.finditer(body))
            for match in _C_FOPEN.finditer(body):
                name = match.group(1)
                if not re.search(rf"fclose[ \t]*+\([ \t]*+{re.escape(name)}[ \t]*+\)", body) and not _released(body, name, "close"):
                    issues["unreleased_file"].append(line(match))
            for match in _CPP_ARRAY_NEW.finditer(body):
                name = re.escape(match.group(1))
                if re.search(rf"(?<![\w$])delete[ \t]++{name}\b", body) and not re.search(rf"delete[ \t]*+\[\][ \t]*+{name}\b", body):
                    issues["array_delete_mismatch"].append(line(match))
            issues["alloca"].extend(line(m) for m in _ALLOCA.finditer(body))
        elif family == "go":
            for match in _GO_OPEN.finditer(body):
                if not _released(body, match.group(1), "Close"):
                    issues["unreleased_file"].append(line(match))
            for match in _GO_HTTP.finditer(body):
                if not re.search(rf"(?<![\w$.]){re.escape(match.group(1))}\.Body\.Close\(", body) and \
                        not _released(body, match.group(1), "Body.Close"):
                    issues["unclosed_response_body"].append(line(match))
            for match in _GO_ROWS.finditer(body):
                if not _released(body, match.group(1), "Close"):
                    issues["unclosed_rows"].append(line(match))
        elif family in {"java", "kotlin", "scala", "groovy"}:
            for pattern in (_JVM_CLOSEABLE, _JDBC):
                for match in pattern.finditer(body):
                    offset = start + match.start()
                    if any(low <= offset <= high for low, high in guarded):
                        continue
                    if not _released(body, match.group(1), "close"):
                        issues["unreleased_stream"].append(line(match))
        elif family == "csharp":
            for match in _CSHARP_DISPOSABLE.finditer(body):
                offset = start + match.start()
                declaration = clean[max(0, offset - 60):offset]
                if any(low <= offset <= high for low, high in guarded) or re.search(r"(?<![\w$])using\b[^;{}]*$", declaration):
                    continue
                if not _released(body, match.group(1), "Dispose", "Close", "DisposeAsync"):
                    issues["undisposed"].append(line(match))
            issues["httpclient_per_call"].extend(line(m) for m in _CSHARP_NEW_HTTPCLIENT.finditer(body))
    if family == "rust":
        issues["manual_memory"].extend(model.line_of(m.start()) for m in _RUST_MANUAL.finditer(clean))
        stats["unsafe_blocks"] = len(_RUST_UNSAFE_BLOCK.findall(clean))
    if family == "js":
        if "setInterval(" in clean and "clearInterval(" not in clean:
            issues["interval_never_cleared"].extend(
                model.line_of(m.start()) for m in re.finditer(r"(?<![\w$.])setInterval\(", clean)
            )
        for match in _JS_EFFECT.finditer(clean):
            close = model.parens.get(match.end() - 1)
            if close is None:
                continue
            effect = clean[match.end():close]
            if _JS_SUBSCRIBES.search(effect) and not re.search(r"(?<![\w$])return\b", effect):
                issues["effect_without_cleanup"].append(model.line_of(match.start()))
    if family in {"c", "cpp"}:
        stats["allocations"] = len(re.findall(r"(?<![\w$.])(?:malloc|calloc|realloc)[ \t]*+\(", clean))
        stats["frees"] = len(re.findall(r"(?<![\w$.])free[ \t]*+\(", clean))
        stats["raw_new"] = len(re.findall(r"(?<![\w$.])new[ \t]++[A-Za-z_]", clean))
        stats["smart_pointers"] = len(_CPP_SMART.findall(clean))
    return issues, +stats


_MESSAGES = {
    "unreleased_file": ("File opened without a guaranteed close", "LOW",
                        "If the code returns or raises before closing, the handle leaks until the process exits.",
                        "Use a context manager (with open(...)), defer f.Close(), or close it in a finally block."),
    "unreleased_socket": ("Socket opened without a guaranteed close", "LOW",
                          "Leaked sockets exhaust file descriptors and keep connections half-open.",
                          "Use the socket as a context manager or close it in a finally block."),
    "unreleased_connection": ("Database connection opened without a guaranteed close", "LOW",
                              "Leaked connections exhaust the database's connection limit.",
                              "Use a context manager or a connection pool, and close in a finally block."),
    "unreleased_process": ("Child process never waited for", "LOW",
                           "A child that is never waited for stays a zombie and its pipes stay open.",
                           "Call communicate() or wait(), or use subprocess.run."),
    "insecure_temporary_name": ("Insecure temporary file name", "MEDIUM",
                                "tempfile.mktemp returns a name another process can create first (a race).",
                                "Use tempfile.mkstemp or NamedTemporaryFile."),
    "unbounded_method_cache": ("Unbounded cache on a method", "LOW",
                               "functools.cache/lru_cache(maxsize=None) on a method keeps every instance (self) alive forever.",
                               "Bound the cache, cache a module-level function, or use cached_property."),
    "unfreed_allocation": ("Allocation without a matching free", "LOW",
                           "Memory allocated in the function is neither freed, returned nor handed on there.",
                           "Free it on every path, or document the function that takes ownership."),
    "realloc_overwrite": ("realloc result overwrites its input pointer", "MEDIUM",
                          "If realloc fails it returns NULL and the original block leaks, with its only pointer lost.",
                          "Assign to a temporary, check it, then replace the original pointer."),
    "array_delete_mismatch": ("delete on memory from new[]", "MEDIUM",
                              "Memory from new[] must be released with delete[]; delete is undefined behaviour.",
                              "Use delete[], or better std::vector or std::unique_ptr<T[]>."),
    "alloca": ("Runtime-sized stack allocation (alloca)", "LOW",
               "alloca with an input-dependent size can overflow the stack without any error return.",
               "Allocate on the heap, or bound the size."),
    "unclosed_response_body": ("HTTP response body not closed", "MEDIUM",
                               "An unclosed response body leaks the connection and its goroutine.",
                               "defer resp.Body.Close() right after checking the error."),
    "unclosed_rows": ("Query rows not closed", "MEDIUM",
                      "Rows that are never closed hold their database connection.",
                      "defer rows.Close() right after checking the error."),
    "unreleased_stream": ("Stream, socket or JDBC resource not closed", "LOW",
                          "A resource outside try-with-resources that is never closed leaks its handle.",
                          "Use try-with-resources."),
    "undisposed": ("IDisposable not disposed", "LOW",
                   "A disposable object created outside using and never disposed leaks its handle.",
                   "Use a using declaration or statement."),
    "httpclient_per_call": ("HttpClient created per call", "LOW",
                            "A new HttpClient per call exhausts sockets under load (TIME_WAIT).",
                            "Reuse one HttpClient, or use IHttpClientFactory."),
    "manual_memory": ("Manual memory management", "LOW",
                      "mem::forget, Box::leak, ManuallyDrop and transmute bypass Rust's ownership checks.",
                      "Document why each is sound, or use a safe alternative."),
    "interval_never_cleared": ("Interval never cleared", "LOW",
                               "setInterval without a matching clearInterval keeps running and holds its closure.",
                               "Keep the handle and clear it when the owner goes away."),
    "effect_without_cleanup": ("React effect subscribes without cleanup", "LOW",
                               "An effect that adds listeners, intervals or subscriptions without returning a cleanup leaks them on every re-render.",
                               "Return a cleanup function from the effect."),
}


class ResourceManagementAnalyzer(Analyzer):
    name = "resource-management"
    version = "1.0.0"
    description = "Resources and memory that are acquired without a guaranteed release."
    domains = ("memory",)
    languages = ("Python", *sorted(LEXICAL_LANGUAGES))

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and supports_language(record.language)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        model = model_for(path, record)
        if model is None:
            return []
        if model.tree is not None:
            issues, stats = _python_resources(model.tree), Counter()
        else:
            issues, stats = _lexical_resources(model)
        if stats:
            code_facts.emit_fact("memory_stats", model.language, **dict(sorted(stats.items())))
        findings = []
        for kind, lines in sorted(issues.items()):
            if not lines:
                continue
            title, severity, impact, recommendation = _MESSAGES[kind]
            findings.append(code_finding(
                model, "resource_management", title, impact, lines, analyzer=self.name,
                severity=severity, recommendation=recommendation,
            ))
        return findings
