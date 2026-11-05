"""Concurrency and parallelism: primitives in use and common misuse patterns.

Python is analysed on its syntax tree: blocking calls inside ``async def``, coroutines
that are never awaited, locks acquired without a guaranteed release, and thread targets
that mutate globals without a lock. Go, JVM languages, C#, JavaScript/TypeScript,
Rust, Kotlin and C use the structural lexer's cleaned text and function bodies. Every
file also contributes a primitive inventory to the project-wide concurrency summary.
Findings are INFERRED: a race needs shared state and an interleaving that static
patterns can suggest but not prove.
"""
from __future__ import annotations

import ast
import re
from collections import Counter, defaultdict
from pathlib import Path

from .. import code_facts
from ..code_model import FUNCTION_KINDS, FileModel, model_for, supports_language
from ..code_model.lexical import LEXICAL_LANGUAGES
from ..models import FileRecord, Finding
from .base import Analyzer
from .code_findings import Intervals, code_finding, loop_bodies

_PY_BLOCKING = frozenset({
    "time.sleep", "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.request", "urllib.request.urlopen", "urlopen",
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "os.system", "socket.create_connection", "input", "sqlite3.connect", "psycopg2.connect",
    "pymysql.connect", "mysql.connector.connect",
})
_PY_INVENTORY = {
    "threads": ("threading.Thread", "Thread"),
    "thread_pools": ("ThreadPoolExecutor", "concurrent.futures.ThreadPoolExecutor"),
    "process_pools": ("ProcessPoolExecutor", "concurrent.futures.ProcessPoolExecutor",
                      "multiprocessing.Pool", "Pool"),
    "processes": ("multiprocessing.Process",),
    "locks": ("threading.Lock", "threading.RLock", "threading.Semaphore", "threading.BoundedSemaphore",
              "threading.Condition", "Lock", "RLock", "asyncio.Lock", "asyncio.Semaphore"),
    "queues": ("queue.Queue", "multiprocessing.Queue", "asyncio.Queue"),
    "async_tasks": ("asyncio.create_task", "asyncio.gather", "asyncio.ensure_future", "asyncio.run",
                    "asyncio.TaskGroup", "loop.run_until_complete"),
}


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _python_concurrency(tree: ast.Module) -> tuple[dict[str, list[int]], Counter]:
    issues: dict[str, list[int]] = defaultdict(list)
    inventory: Counter = Counter()
    async_names: set[str] = set()
    async_methods: dict[str, set[str]] = defaultdict(set)
    functions: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef):
            async_names.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
        if isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, ast.AsyncFunctionDef):
                    async_methods[node.name].add(member.name)
    known = frozenset(name for names in _PY_INVENTORY.values() for name in names)
    thread_targets: set[str] = set()

    def walk(node: ast.AST, in_async: bool, owner: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.AsyncFunctionDef):
                inventory["async_functions"] += 1
                walk(child, True, owner)
                continue
            if isinstance(child, (ast.FunctionDef, ast.Lambda)):
                walk(child, False, owner)
                continue
            if isinstance(child, ast.ClassDef):
                walk(child, False, child.name)
                continue
            if isinstance(child, ast.Call):
                name = _dotted(child.func)
                if name in known:
                    for category, names in _PY_INVENTORY.items():
                        if name in names:
                            inventory[category] += 1
                if in_async and name in _PY_BLOCKING:
                    issues["blocking_in_async"].append(child.lineno)
                if name.endswith((".Thread", ".Process")) or name in {"Thread", "Process"}:
                    for keyword in child.keywords:
                        if keyword.arg == "target" and isinstance(keyword.value, ast.Name):
                            thread_targets.add(keyword.value.id)
                if name.rsplit(".", 1)[-1] in {"submit", "map", "apply_async", "run_in_executor"} and child.args:
                    first = child.args[1] if name.endswith("run_in_executor") and len(child.args) > 1 else child.args[0]
                    if isinstance(first, ast.Name):
                        thread_targets.add(first.id)
            if isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                func = child.value.func
                name = _dotted(func)
                receiver, _, attribute = name.rpartition(".")
                if (
                    name in async_names or name == "asyncio.sleep"
                    or (receiver in {"self", "cls"} and owner and attribute in async_methods.get(owner, ()))
                ):
                    issues["not_awaited"].append(child.lineno)
            walk(child, in_async, owner)

    walk(tree, False, None)

    def acquires_without_release(function: ast.AST) -> list[int]:
        acquired: list[tuple[str, int]] = []
        released: set[str] = set()
        guarded: set[str] = set()
        for node in ast.walk(function):
            if isinstance(node, (ast.With, ast.AsyncWith)):
                guarded.update(_dotted(item.context_expr) for item in node.items)
            elif isinstance(node, ast.Try):
                for statement in node.finalbody:
                    for inner in ast.walk(statement):
                        if isinstance(inner, ast.Call) and _dotted(inner.func).endswith(".release"):
                            released.add(_dotted(inner.func).rsplit(".", 1)[0])
            elif isinstance(node, ast.Call):
                name = _dotted(node.func)
                if name.endswith(".acquire"):
                    acquired.append((name.rsplit(".", 1)[0], node.lineno))
        return [line for receiver, line in acquired if receiver not in released and receiver not in guarded]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            issues["lock_without_release"].extend(acquires_without_release(node))
    for name in sorted(thread_targets):
        function = functions.get(name)
        if function is None:
            continue
        declared = {item for node in ast.walk(function) if isinstance(node, ast.Global) for item in node.names}
        locked = any(isinstance(node, (ast.With, ast.AsyncWith)) for node in ast.walk(function))
        if declared and not locked and any(
            isinstance(node, (ast.Assign, ast.AugAssign))
            and any(isinstance(target, ast.Name) and target.id in declared
                    for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))
            for node in ast.walk(function)
        ):
            issues["unsynchronized_global"].append(function.lineno)
    return issues, inventory


_GO_ROUTINE = re.compile(r"(?<![\w$.])go[ \t]++(?:func\b|[A-Za-z_][\w.]*+[ \t]*+\()")
# Receiver chains are ``ident.`` groups, so the method name after them stays matchable.
_GO_LOCK = re.compile(r"(?<![\w$.])((?:[A-Za-z_]\w*+\.)++)(R?Lock)\(\)")
_GO_WAITGROUP_ADD_IN_GOROUTINE = re.compile(
    r"(?<![\w$.])go[ \t]++func[ \t]*+\([^()\n]{0,200}+\)[ \t]*+\{[ \t\r\n]*+(?:[A-Za-z_]\w*+\.)++Add\("
)
_JAVA_DOUBLE_CHECK = re.compile(
    r"if[ \t]*+\([ \t]*+([A-Za-z_]\w*+)[ \t]*+==[ \t]*+null[ \t]*+\)[ \t\r\n]*+\{?[ \t\r\n]*+synchronized\b"
)
_JAVA_EXECUTOR = re.compile(r"(?<![\w$])Executors\.new\w+\(")
_JAVA_SYNCHRONIZED_BLOCK = re.compile(r"(?<![\w$])synchronized[ \t]*+\(")
_CSHARP_ASYNC_VOID = re.compile(r"(?<![\w$])async[ \t]++void[ \t]++([A-Za-z_]\w*+)[ \t]*+\(([^()]{0,300}+)\)")
# .Result only on task-like expressions: any property may be called Result.
_CSHARP_BLOCKING = re.compile(
    r"(?:Async\([^()\n]{0,200}+\)|(?<![\w$])[Tt]ask\w*+)\.Result\b|\.Wait\(\)|\.GetAwaiter\(\)\.GetResult\(\)"
)
_CSHARP_PUBLIC_LOCK = re.compile(r"(?<![\w$])lock[ \t]*+\([ \t]*+(?:this|typeof\([^()]{1,200}+\))[ \t]*+\)")
_RUST_MANUAL_SEND = re.compile(r"(?<![\w$])unsafe[ \t]++impl\b[^{;]{0,200}?\b(?:Send|Sync)\b")
_RUST_STATIC_MUT = re.compile(r"(?<![\w$])static[ \t]++mut[ \t]++")
_KOTLIN_GLOBAL_SCOPE = re.compile(r"(?<![\w$])GlobalScope\.(?:launch|async)\b")
_AWAIT = re.compile(r"(?<![\w$])await\b")
_LEXICAL_INVENTORY = {
    "threads": re.compile(r"(?<![\w$])(?:new[ \t]++Thread\b|std::thread\b|pthread_create\b|thread::spawn\b|Thread\.start\b|Task\.Run\b)"),
    "goroutines": _GO_ROUTINE,
    "async_tasks": re.compile(r"(?<![\w$])(?:Promise\.(?:all|race|allSettled|any)\b|tokio::spawn\b|CompletableFuture\b|launch[ \t]*+\{|async[ \t]*+\{)"),
    "locks": re.compile(r"(?<![\w$])(?:sync\.(?:RW)?Mutex\b|std::mutex\b|Mutex<|RwLock<|pthread_mutex_t\b|ReentrantLock\b|synchronized\b|lock[ \t]*+\()"),
    "channels": re.compile(r"(?<![\w$])(?:make\([ \t]*+chan\b|mpsc::channel\b|Channel<|BlockingQueue\b)"),
    "workers": re.compile(r"(?<![\w$])(?:new[ \t]++Worker\(|worker_threads\b|SharedArrayBuffer\b|Atomics\.)"),
    "atomics": re.compile(r"(?<![\w$])(?:std::atomic\b|atomic\.\w+\(|AtomicInteger\b|AtomicLong\b|Interlocked\.)"),
}


def _bodies(model: FileModel):
    return [symbol for symbol in model.symbols if symbol.kind in FUNCTION_KINDS and symbol.body]


def _lexical_concurrency(model: FileModel) -> tuple[dict[str, list[int]], Counter]:
    issues: dict[str, list[int]] = defaultdict(list)
    clean = model.clean
    family = LEXICAL_LANGUAGES[model.language]
    inventory = Counter({
        key: len(pattern.findall(clean)) for key, pattern in _LEXICAL_INVENTORY.items()
    })
    inventory = +inventory
    functions = _bodies(model)
    if family == "go":
        for symbol in functions:
            body = clean[symbol.body[0]:symbol.body[1]]
            for match in _GO_LOCK.finditer(body):
                receiver, kind = match.groups()  # receiver keeps its trailing dot
                unlock = f"{receiver}{'RUnlock' if kind == 'RLock' else 'Unlock'}()"
                if unlock not in body:
                    issues["lock_without_release"].append(model.line_of(symbol.body[0] + match.start()))
        for match in _GO_WAITGROUP_ADD_IN_GOROUTINE.finditer(clean):
            issues["waitgroup_add_in_goroutine"].append(model.line_of(match.start()))
    if family in {"java", "kotlin", "scala", "groovy"}:
        for match in _JAVA_DOUBLE_CHECK.finditer(clean):
            field = match.group(1)
            if not re.search(rf"(?<![\w$])volatile\b[^;\n]{{0,200}}\b{re.escape(field)}\b", clean) and \
                    not re.search(rf"@Volatile[^;\n]{{0,200}}\b{re.escape(field)}\b", clean):
                issues["double_checked_locking"].append(model.line_of(match.start()))
        if _JAVA_EXECUTOR.search(clean) and not re.search(r"\.shutdown(?:Now)?\(|\.close\(\)|try[ \t]*+\(", clean):
            issues["executor_not_shut_down"].extend(model.line_of(m.start()) for m in _JAVA_EXECUTOR.finditer(clean))
        locked = []
        for match in _JAVA_SYNCHRONIZED_BLOCK.finditer(clean):
            close = model.parens.get(match.end() - 1)
            if close is not None:
                brace = clean.find("{", close, close + 50)
                if brace != -1 and brace in model.braces:
                    locked.append((brace, model.braces[brace]))
        for symbol in functions:
            prefix = clean[max(0, symbol.body[0] - 400):symbol.body[0]]
            if "synchronized" in prefix.rsplit("}", 1)[-1].rsplit(";", 1)[-1]:
                locked.append(symbol.body)
        held = Intervals(locked)
        for call in model.calls:
            if call.callee == "sleep" and call.receiver in {"Thread", "TimeUnit"} and held.contains(call.offset):
                issues["sleep_while_locked"].append(call.line)
    if family == "kotlin":
        for symbol in functions:
            prefix = clean[max(0, symbol.body[0] - 300):symbol.body[0]]
            if "suspend" in prefix.split() and "runBlocking" in clean[symbol.body[0]:symbol.body[1]]:
                issues["blocking_in_async"].append(symbol.line)
        issues["global_scope"].extend(model.line_of(m.start()) for m in _KOTLIN_GLOBAL_SCOPE.finditer(clean))
    if family == "csharp":
        for match in _CSHARP_ASYNC_VOID.finditer(clean):
            parameters = match.group(2)
            if not re.search(r"EventArgs\b", parameters):
                issues["async_void"].append(model.line_of(match.start()))
        for symbol in functions:
            if symbol.is_async:
                body = clean[symbol.body[0]:symbol.body[1]]
                for match in _CSHARP_BLOCKING.finditer(body):
                    issues["blocking_wait"].append(model.line_of(symbol.body[0] + match.start()))
        for call in model.calls:
            if call.callee == "Sleep" and call.receiver == "Thread" and any(
                symbol.is_async and symbol.body[0] < call.offset < symbol.body[1] for symbol in functions
            ):
                issues["blocking_in_async"].append(call.line)
        issues["public_lock"].extend(model.line_of(m.start()) for m in _CSHARP_PUBLIC_LOCK.finditer(clean))
    if family == "rust":
        issues["manual_send_sync"].extend(model.line_of(m.start()) for m in _RUST_MANUAL_SEND.finditer(clean))
        issues["static_mut"].extend(model.line_of(m.start()) for m in _RUST_STATIC_MUT.finditer(clean))
        for call in model.calls:
            if call.callee == "sleep" and call.receiver == "thread" and any(
                symbol.is_async and symbol.body[0] < call.offset < symbol.body[1] for symbol in functions
            ):
                issues["blocking_in_async"].append(call.line)
    if family == "js":
        async_names = {symbol.name for symbol in functions if symbol.is_async}
        for call in model.calls:
            if call.callee in async_names and call.receiver in {"", "this"}:
                raw = clean[max(0, call.offset - 120):call.offset]
                if call.receiver == "this" and "this" in raw:
                    raw = raw[:raw.rfind("this")]
                before = raw.rstrip()
                # A statement of its own: after ; { } or, in semicolon-free code, on a new
                # line after a complete expression. Anything else (await, return, =, an
                # argument list) consumes the promise.
                if not before or before[-1] in ";{}" or (
                    "\n" in raw[len(before):] and (before[-1] in ")]" or before[-1].isalnum())
                    and before.rsplit(None, 1)[-1] not in {"await", "return", "yield", "void", "new", "typeof"}
                ):
                    issues["not_awaited"].append(call.line)
        loops = Intervals(loop_bodies(model))
        for match in _AWAIT.finditer(clean):
            if loops.contains(match.start()):
                issues["await_in_loop"].append(model.line_of(match.start()))
    if family == "c":
        for symbol in functions:
            body = clean[symbol.body[0]:symbol.body[1]]
            if "pthread_mutex_lock" in body and "pthread_mutex_unlock" not in body:
                issues["lock_without_release"].append(symbol.line)
    return issues, inventory


_MESSAGES = {
    "blocking_in_async": (
        "Blocking call inside async code", "MEDIUM",
        "A blocking call in a coroutine stalls the event loop (or the dispatcher thread) for every task.",
        "Use the async equivalent (asyncio.sleep, an async HTTP client, run_in_executor / spawn_blocking).",
    ),
    "not_awaited": (
        "Coroutine or promise not awaited", "MEDIUM",
        "Calling an async function without awaiting it never runs it to completion (Python) or loses its errors (JavaScript).",
        "Await the call, or schedule it explicitly (asyncio.create_task, Promise handling) and keep a reference.",
    ),
    "lock_without_release": (
        "Lock acquired without a guaranteed release", "LOW",
        "If code between acquire and release raises or returns early, the lock stays held and other threads deadlock.",
        "Use a context manager (with lock:), defer mu.Unlock(), or release in a finally block.",
    ),
    "unsynchronized_global": (
        "Thread target modifies global state without a lock", "LOW",
        "Threads that assign the same globals without synchronisation can interleave and lose updates.",
        "Guard the shared state with a lock, or pass results back through a queue.",
    ),
    "waitgroup_add_in_goroutine": (
        "WaitGroup.Add inside the goroutine", "MEDIUM",
        "wg.Add inside the goroutine can run after wg.Wait returns, so the wait does not cover it.",
        "Call wg.Add before starting the goroutine.",
    ),
    "double_checked_locking": (
        "Double-checked locking without volatile", "MEDIUM",
        "Without volatile, another thread can see the field assigned before the object is fully constructed.",
        "Declare the field volatile, or use an initialization-on-demand holder.",
    ),
    "executor_not_shut_down": (
        "Executor service never shut down", "LOW",
        "Executor threads that are never shut down keep the process alive and leak threads.",
        "Call shutdown() when done, or manage the executor with try-with-resources (Java 19+).",
    ),
    "sleep_while_locked": (
        "Sleep while holding a lock", "LOW",
        "Sleeping inside synchronized code blocks every other thread waiting for the lock.",
        "Release the lock before sleeping, or wait on a condition instead.",
    ),
    "global_scope": (
        "GlobalScope coroutine", "LOW",
        "GlobalScope coroutines are not tied to any lifecycle, so they leak and their failures go unnoticed.",
        "Launch from a structured scope (viewModelScope, coroutineScope, a supervisor scope).",
    ),
    "async_void": (
        "async void method", "LOW",
        "async void methods cannot be awaited, and their exceptions crash the process.",
        "Return Task instead; keep async void only for event handlers.",
    ),
    "blocking_wait": (
        "Blocking wait on a task inside async code", "MEDIUM",
        ".Result, .Wait() and GetResult() block the thread and can deadlock with a synchronization context.",
        "Use await instead.",
    ),
    "public_lock": (
        "Lock on a publicly accessible object", "LOW",
        "lock(this) and lock(typeof(T)) let unrelated code take the same lock and deadlock.",
        "Lock on a private readonly object.",
    ),
    "manual_send_sync": (
        "Manual Send/Sync implementation", "MEDIUM",
        "unsafe impl Send/Sync asserts thread safety the compiler cannot check; a mistake is a data race.",
        "Document the invariant that makes the type thread-safe, or wrap the state in Mutex/Arc.",
    ),
    "static_mut": (
        "Mutable static", "MEDIUM",
        "Every access to a static mut is unsynchronised and is undefined behaviour under concurrent use.",
        "Use an atomic, a Mutex, or OnceLock/LazyLock.",
    ),
    "await_in_loop": (
        "Sequential await in a loop", "INFO",
        "Awaiting each iteration serialises independent operations.",
        "Start the operations together (Promise.all with a concurrency limit) when they are independent.",
    ),
}


class ConcurrencyAnalyzer(Analyzer):
    name = "concurrency"
    version = "1.0.0"
    description = "Threads, async code, locks and channels, plus common concurrency misuse patterns."
    domains = ("concurrency",)
    languages = ("Python", *sorted(LEXICAL_LANGUAGES))

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and supports_language(record.language)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        model = model_for(path, record)
        if model is None:
            return []
        if model.tree is not None:
            issues, inventory = _python_concurrency(model.tree)
        else:
            issues, inventory = _lexical_concurrency(model)
        if inventory:
            code_facts.emit_fact("concurrency", model.language, **dict(sorted(inventory.items())))
        findings = []
        for kind, lines in sorted(issues.items()):
            if not lines:
                continue
            title, severity, impact, recommendation = _MESSAGES[kind]
            findings.append(code_finding(
                model, "concurrency", title, impact, lines, analyzer=self.name,
                severity=severity, recommendation=recommendation,
            ))
        return findings
