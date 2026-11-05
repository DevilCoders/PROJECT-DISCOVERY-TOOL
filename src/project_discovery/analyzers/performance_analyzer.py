"""Static performance hotspots: N+1 calls in loops, deep nesting, complexity, artifacts.

Python is analysed on its syntax tree (exact loop nesting and call targets); other
languages on the structural lexer's cleaned text and loop bodies. These are indicators
of likely cost, not measurements: a call in a loop may be cheap or batched elsewhere.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from .. import code_facts
from ..code_model import FUNCTION_KINDS, FileModel, model_for, supports_language
from ..code_model.lexical import LEXICAL_LANGUAGES
from ..models import FileRecord, Finding
from .base import Analyzer
from .code_findings import Intervals, code_finding, loop_bodies

COMPLEXITY_THRESHOLD = 25
LONG_FUNCTION_LINES = 300
NESTED_LOOP_DEPTH = 3
_RECORDED_COMPLEXITY = 15

_PY_DB_ATTRIBUTES = frozenset({"execute"})
# ``Model.objects`` (Django managers); a local variable named ``objects`` is not one.
_DJANGO_MANAGER = re.compile(r"[\w)]\.objects(?:\.|$)")
_CONTROL_STATEMENT = re.compile(r"(?i)(?:COMMIT|BEGIN|ROLLBACK|SAVEPOINT|RELEASE|PRAGMA|VACUUM|ANALYZE)\b")


def _batch_or_control(node: ast.Call, attribute: str) -> bool:
    """Transaction control and PRAGMA statements are not per-row queries."""
    if attribute != "execute" or not node.args:
        return False
    first = node.args[0]
    return isinstance(first, ast.Constant) and isinstance(first.value, str) and bool(
        _CONTROL_STATEMENT.match(first.value.lstrip()))
_PY_ORM_ATTRIBUTES = frozenset({
    "get", "filter", "exclude", "all", "count", "create", "update", "delete", "first", "last",
    "exists", "values", "values_list", "aggregate", "annotate", "get_or_create", "update_or_create",
})
_PY_SESSION_ATTRIBUTES = frozenset({"query", "execute", "get", "scalar", "scalars", "add", "merge", "refresh"})
_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen", "fetch"})
_DATABASE_RECEIVER = re.compile(
    r"(?i)(?:^|[._])(?:db|database|conn|connection|cur|cursor|stmt|statement|session|repo|repository|"
    r"knex|prisma|pool|tx|txn|query|orm|dao)(?:$|[._])"
)
_HTTP_RECEIVER = re.compile(r"(?i)(?:^|[._])(?:requests|httpx|aiohttp|http|https|axios|client|session|resttemplate|webclient|httpclient|api)(?:$|[._])")
_LEXICAL_DB_CALLEES = frozenset({
    "query", "execute", "executeQuery", "executeUpdate", "exec", "Exec", "Query", "QueryRow",
    "QueryContext", "ExecContext", "QueryRowContext", "find", "findOne", "findById", "findByPk",
    "findAll", "findMany", "findUnique", "findFirst", "save", "insertOne", "updateOne", "deleteOne",
    "get_results", "get_row", "get_var", "raw", "aggregate",
})
_LEXICAL_HTTP_CALLEES = frozenset({
    "get", "post", "put", "patch", "delete", "request", "Get", "Post", "Do", "GetAsync", "PostAsync",
    "PutAsync", "DeleteAsync", "SendAsync", "getForObject", "postForObject", "exchange", "retrieve",
})
_SLEEPS = frozenset({"sleep", "Sleep", "usleep", "nanosleep", "msleep"})
_DECISIONS = re.compile(r"(?<![\w$])(?:if|for|while|case|catch|foreach|elif|except|when)\b|&&|\|\|")

# Profiling and dump artifacts (name pattern, description, dump that may hold data).
_ARTIFACTS = (
    (re.compile(r"(?i)\.(?:prof|pstats|cprof)$"), "Python cProfile output", False),
    (re.compile(r"(?i)\.cpuprofile$"), "V8/Chrome CPU profile", False),
    (re.compile(r"(?i)\.heapsnapshot$"), "V8/Chrome heap snapshot", True),
    (re.compile(r"(?i)\.heapprofile$"), "V8 heap profile", True),
    (re.compile(r"(?i)(?:^|/)perf\.data(?:\.old)?$"), "Linux perf recording", False),
    (re.compile(r"(?i)(?:^|/)(?:callgrind|cachegrind|massif)\.out(?:\.\d+)?$"), "Valgrind profile", False),
    (re.compile(r"(?i)\.pprof$"), "Go pprof profile", False),
    (re.compile(r"(?i)\.jfr$"), "Java Flight Recorder recording", False),
    (re.compile(r"(?i)\.hprof$"), "Java heap dump", True),
    (re.compile(r"(?i)\.(?:nettrace|etl|diagsession)$"), ".NET/Windows trace", False),
    (re.compile(r"(?i)\.(?:nsys-rep|qdrep|ncu-rep)$"), "NVIDIA Nsight report", False),
    (re.compile(r"(?i)\.speedscope\.json$|(?:^|/)flamegraph[^/]*\.svg$|\.(?:folded|collapsed)$"), "Flame graph or stack profile", False),
    (re.compile(r"(?i)\.trace$"), "Instruments or Chrome trace", False),
    (re.compile(r"(?i)(?:^|/)core(?:\.\d+)?$|\.(?:dmp|mdmp|core)$"), "Process memory dump", True),
)


def _artifact(path: str):
    normalized = path.replace("\\", "/")
    return next(((label, sensitive) for pattern, label, sensitive in _ARTIFACTS if pattern.search(normalized)), None)


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


def _complexity(function: ast.AST) -> int:
    """McCabe complexity of one function, not counting nested function bodies."""
    count = 1
    stack = list(ast.iter_child_nodes(function))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.Assert)):
            count += 1
        elif isinstance(node, ast.BoolOp):
            count += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            count += 1 + len(node.ifs)
        elif type(node).__name__ == "match_case":
            count += 1
        stack.extend(ast.iter_child_nodes(node))
    return count


def _constant_iterable(node: ast.AST) -> bool:
    """Loops over literals or module constants run a fixed number of times."""
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(isinstance(element, (ast.Constant, ast.Name, ast.Attribute, ast.Tuple)) for element in node.elts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"values", "items", "keys"}:
        node = node.func.value
    if isinstance(node, ast.Call) and _dotted(node.func) == "range":
        return all(isinstance(argument, ast.Constant) for argument in node.args)
    name = _dotted(node).rsplit(".", 1)[-1]
    return bool(name) and name.lstrip("_").isupper()


class _PythonHotspots(ast.NodeVisitor):
    def __init__(self) -> None:
        self.depth = 0
        # Enclosing loops whose trip count depends on data (not a literal or constant).
        self.data_loops = 0
        self.issues: dict[str, list[int]] = defaultdict(list)
        self.functions: list[tuple[str, int, int, int]] = []  # (qualified, line, complexity, length)
        self.scope: list[str] = []

    def _function(self, node) -> None:
        qualified = ".".join((*self.scope, node.name))
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        self.functions.append((qualified, node.lineno, _complexity(node), length))
        saved, self.depth = self.depth, 0  # loops do not carry into a nested function body
        saved_data, self.data_loops = self.data_loops, 0
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.depth = saved
        self.data_loops = saved_data

    visit_FunctionDef = visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def _loop(self, node, children, data: bool = True) -> None:
        self.depth += 1
        self.data_loops += data
        if data and self.data_loops == NESTED_LOOP_DEPTH:
            self.issues["nested_loops"].append(node.lineno)
        for child in children:
            self.visit(child)
        self.depth -= 1
        self.data_loops -= data

    def visit_For(self, node) -> None:
        self.visit(node.iter)  # evaluated once, before the first iteration
        self._loop(node, [node.target, *node.body, *node.orelse], not _constant_iterable(node.iter))

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self._loop(node, [node.test, *node.body, *node.orelse])

    def _comprehension(self, node) -> None:
        generators = node.generators
        self.visit(generators[0].iter)  # the outermost iterable is evaluated once
        loops = len(generators)
        data = sum(1 for generator in generators if not _constant_iterable(generator.iter))
        self.depth += loops
        self.data_loops += data
        if self.data_loops >= NESTED_LOOP_DEPTH > self.data_loops - data:
            self.issues["nested_loops"].append(node.lineno)
        for index, generator in enumerate(generators):
            self.visit(generator.target)
            if index:
                self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for part in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
            self.visit(part)
        self.depth -= loops
        self.data_loops -= data

    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _comprehension

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self.depth and isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name) and (
            isinstance(node.value, ast.JoinedStr)
            or (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
            or (isinstance(node.value, ast.Call) and _dotted(node.value.func) == "str")
        ):
            self.issues["string_concatenation"].append(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        attribute = name.rsplit(".", 1)[-1]
        receiver = name.rpartition(".")[0]
        if attribute in {"iterrows", "itertuples"} or (
            attribute == "apply" and any(k.arg == "axis" and getattr(k.value, "value", None) == 1 for k in node.keywords)
        ):
            self.issues["row_iteration"].append(node.lineno)
        if self.depth and self.data_loops:
            if not _batch_or_control(node, attribute) and (
                (attribute in _PY_DB_ATTRIBUTES and (
                    attribute != "execute" or _DATABASE_RECEIVER.search(receiver or "-")
                ))
                or (_DJANGO_MANAGER.search(receiver) and attribute in _PY_ORM_ATTRIBUTES)
                or (attribute in _PY_SESSION_ATTRIBUTES and _DATABASE_RECEIVER.search(receiver or "-"))
            ):
                self.issues["query_in_loop"].append(node.lineno)
            elif attribute in _HTTP_VERBS and (
                name.startswith(("requests.", "httpx.", "urllib.request.", "aiohttp."))
                or name in {"urlopen", "urllib.request.urlopen"}
                or (_HTTP_RECEIVER.search(receiver or "-") and receiver.split(".")[-1] not in {"dict", "os", "environ"})
            ):
                self.issues["http_in_loop"].append(node.lineno)
            elif name in {"time.sleep", "asyncio.sleep", "sleep"}:
                self.issues["sleep_in_loop"].append(node.lineno)
            elif name in {"copy.deepcopy", "deepcopy"}:
                self.issues["deepcopy_in_loop"].append(node.lineno)
            elif attribute in {"insert", "pop"} and node.args and isinstance(node.args[0], ast.Constant) \
                    and node.args[0].value == 0:
                self.issues["list_front_operation"].append(node.lineno)
        self.generic_visit(node)


def _lexical_hotspots(model: FileModel) -> tuple[dict[str, list[int]], list[tuple[str, int, int, int]]]:
    issues: dict[str, list[int]] = defaultdict(list)
    loops = Intervals(loop_bodies(model))
    for start, _end, depth in loops.deepest():
        if depth == NESTED_LOOP_DEPTH:
            issues["nested_loops"].append(model.line_of(start))
    for call in model.calls:
        if call.offset < 0 or not loops.contains(call.offset):
            continue
        receiver = call.receiver
        if call.callee in _LEXICAL_DB_CALLEES and receiver and (
            _DATABASE_RECEIVER.search(receiver) or (receiver[:1].isupper() and call.callee.startswith(("find", "save")))
        ):
            issues["query_in_loop"].append(call.line)
        elif (call.callee == "fetch" and receiver in {"", "window", "globalThis"}) or (
            call.callee in _LEXICAL_HTTP_CALLEES and receiver and _HTTP_RECEIVER.search(receiver)
        ):
            issues["http_in_loop"].append(call.line)
        elif call.callee in _SLEEPS and receiver in {"", "Thread", "time", "this_thread", "std", "TimeUnit"}:
            issues["sleep_in_loop"].append(call.line)
    functions = []
    for symbol in model.symbols:
        if symbol.kind in FUNCTION_KINDS and symbol.body:
            body = model.clean[symbol.body[0]:symbol.body[1]]
            complexity = 1 + len(_DECISIONS.findall(body))
            functions.append((symbol.qualified, symbol.line, complexity, symbol.end_line - symbol.line + 1))
    return issues, functions


_MESSAGES = {
    "query_in_loop": (
        "Database query inside a loop", "LOW",
        "A query issued once per iteration (the N+1 pattern) multiplies round trips with input size.",
        "Fetch the rows in one query (a join, IN list or prefetch) before the loop, or batch the writes.",
    ),
    "http_in_loop": (
        "HTTP request inside a loop", "LOW",
        "One network round trip per iteration makes latency grow with input size.",
        "Batch the requests, use a bulk endpoint, or issue them concurrently with a bounded pool.",
    ),
    "nested_loops": (
        "Deeply nested loops", "LOW",
        f"Loops nested {NESTED_LOOP_DEPTH} or more deep are polynomial in input size.",
        "Index the inner data (a set or dict) or restructure the algorithm.",
    ),
    "sleep_in_loop": (
        "Sleep inside a loop", "LOW",
        "A sleep in a loop usually means polling, which adds latency and holds resources.",
        "Wait on an event, condition or callback instead of polling.",
    ),
    "string_concatenation": (
        "String built with += in a loop", "LOW",
        "Repeated string concatenation can copy the accumulated text on every iteration.",
        "Collect the pieces in a list and join them once.",
    ),
    "deepcopy_in_loop": (
        "Deep copy inside a loop", "LOW",
        "copy.deepcopy walks the whole object graph on every iteration.",
        "Copy once outside the loop, or copy only what changes.",
    ),
    "list_front_operation": (
        "List insert or pop at index 0 in a loop", "LOW",
        "Inserting or removing at the front of a list moves every element (quadratic overall).",
        "Use collections.deque for queue-like access.",
    ),
    "row_iteration": (
        "Row-by-row DataFrame iteration", "LOW",
        "iterrows/itertuples/apply(axis=1) run Python per row and are orders of magnitude slower than vectorised operations.",
        "Use vectorised column operations, or numpy on the underlying arrays.",
    ),
}


class PerformanceHotspotAnalyzer(Analyzer):
    name = "performance-hotspots"
    version = "1.0.0"
    description = "N+1 queries and requests in loops, nested loops, complexity hotspots and profiling artifacts."
    domains = ("performance",)
    languages = ("Python", *sorted(LEXICAL_LANGUAGES))

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.content_skipped_reason:
            return False
        return supports_language(record.language) or _artifact(record.path) is not None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        artifact = _artifact(record.path)
        if artifact is not None:
            label, sensitive = artifact
            return [Finding(
                "performance", f"Profiling artifact: {record.path}",
                f"{label} ({record.size_bytes:,} bytes) is committed to the project."
                + (" Memory dumps can contain secrets, tokens and personal data from the profiled process."
                   if sensitive else ""),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                severity="LOW" if sensitive else "INFO",
                recommendation="Keep profiling output out of version control unless it is a deliberate fixture.",
            )]
        model = model_for(path, record)
        if model is None:
            return []
        if model.tree is not None:
            visitor = _PythonHotspots()
            visitor.visit(model.tree)
            issues, functions = visitor.issues, visitor.functions
        else:
            issues, functions = _lexical_hotspots(model)
        findings = []
        for kind, lines in sorted(issues.items()):
            title, severity, impact, recommendation = _MESSAGES[kind]
            findings.append(code_finding(
                model, "performance", title, impact, lines, analyzer=self.name,
                severity=severity, recommendation=recommendation,
            ))
        complex_functions = sorted(
            (item for item in functions if item[2] >= COMPLEXITY_THRESHOLD), key=lambda item: -item[2],
        )
        if complex_functions:
            finding = code_finding(
                model, "performance", "High cyclomatic complexity",
                f"{len(complex_functions)} function(s) have cyclomatic complexity of {COMPLEXITY_THRESHOLD} "
                "or more: " + ", ".join(f"{name} ({value})" for name, _, value, _ in complex_functions[:10]) + ".",
                [line for _, line, _, _ in complex_functions], analyzer=self.name,
                recommendation="Split the function along its decision branches; complex functions are hard to test and slow to change.",
            )
            findings.append(finding)
        long_functions = [item for item in functions if item[3] >= LONG_FUNCTION_LINES]
        if long_functions:
            findings.append(code_finding(
                model, "performance", "Very long function",
                f"{len(long_functions)} function(s) span {LONG_FUNCTION_LINES} lines or more: "
                + ", ".join(f"{name} ({length} lines)" for name, _, _, length in long_functions[:10]) + ".",
                [line for _, line, _, _ in long_functions], analyzer=self.name, severity="INFO",
            ))
        if functions:
            values = [item[2] for item in functions]
            code_facts.emit_fact(
                "complexity_stats", model.language, functions=len(values), total=sum(values),
                maximum=max(values), high=len(complex_functions),
            )
            for name, line, value, length in functions:
                if value >= _RECORDED_COMPLEXITY:
                    code_facts.emit_fact("complex_function", name, complexity=value, line=line, lines=length)
        return findings

