"""Cross-file code intelligence built from the facts analyzers record per file.

After analysis, the scan's inventory database holds every modelled file's symbols,
call sites, referenced identifiers and imports (see ``code_facts``). The passes here
query those tables with temporary tables and bounded in-memory structures, so memory
does not grow with repository size:

* **Symbol index:** definitions by language and kind; ``pdt query`` looks them up.
* **Call graph:** Python calls are resolved semantically to module-qualified
  definitions. Lexical calls are resolved by name within a language group (local,
  unique, ambiguous or external). Recursion cycles come from strongly connected
  components of the resolved edges.
* **Unreferenced private functions:** private definitions whose name never appears in
  any scanned file (dead-code candidates).
* **Test-to-code links:** public functions referenced from test files.
* **Polyglot module graph:** imports resolved to files for JavaScript/TypeScript,
  C/C++, JVM languages, Go, Rust, PHP and Dart, with dependency cycles.
"""
from __future__ import annotations

import itertools
import json
import posixpath
import re
import sqlite3
from collections import Counter, defaultdict
from importlib.util import resolve_name
from pathlib import Path, PurePosixPath
from typing import Iterable

from ..analyzers.delivery.testing import is_test_path
from ..inventory.store import sqlite_text
from ..models import FileRecord, Finding
from .model import supports_language
from .python_graph import _import_name, _strongly_connected_components
from .reachability import reachability as _reachability

MAX_GRAPH_EDGES = 500_000
MAX_LISTED = 100
MAX_CYCLES_LISTED = 20
_FUNCTION_KINDS = ("function", "method", "constructor")
_CALLABLE_KINDS = _FUNCTION_KINDS + ("class", "struct", "record", "object", "type", "macro")
# Languages whose definitions can call each other, for lexical name resolution.
_LANGUAGE_GROUPS = {
    "C": "c-family", "C++": "c-family", "C/C++ Header": "c-family", "Objective-C": "c-family",
    # .m files: modelled (as Objective-C) only when their content is Objective-C.
    "Objective-C / MATLAB (ambiguous)": "c-family",
    "Objective-C++": "c-family", "CUDA": "c-family", "OpenCL": "c-family", "Arduino Sketch": "c-family",
    "JavaScript": "javascript", "TypeScript": "javascript", "Vue": "javascript", "Svelte": "javascript",
    "Java": "jvm", "Kotlin": "jvm", "Scala": "jvm", "Groovy": "jvm",
    "GLSL": "shaders", "HLSL": "shaders", "WGSL": "shaders", "Metal Shading Language": "shaders",
}
_ENTRY_NAMES = frozenset({
    "main", "init", "setup", "teardown", "setUp", "tearDown", "handler", "run", "dispose",
    "Dispose", "finalize", "toString", "equals", "hashCode", "constructor", "render",
})
_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".d.ts")
_JVM_EXTENSIONS = (".java", ".kt", ".scala", ".groovy")


def _connect(inventory_path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(f"{Path(inventory_path).absolute().as_uri()}?mode=ro", uri=True)
    db.execute("PRAGMA temp_store=FILE")
    db.execute("PRAGMA cache_size=-65536")
    return db


def _namespace_alias(path: str, module: str) -> str | None:
    """The name a module has through the namespace directory above its top package.

    ``src/ns/pkg/mod.py`` is ``pkg.mod`` by package chain, but code imports it as
    ``ns.pkg.mod`` when ``ns`` is a PEP 420 namespace package (no ``__init__.py``).
    """
    directories = path.split("/")[:-1]
    package_depth = module.count(".") + (1 if path.endswith("/__init__.py") or path == "__init__.py" else 0)
    top = len(directories) - package_depth
    if package_depth == 0 or top < 1:
        return None
    namespace = directories[top - 1]
    return f"{namespace}.{module}" if namespace.isidentifier() else None


def _namespace_resolved(fq: str, aliases: dict[str, str]) -> str:
    if aliases:
        parts = fq.split(".")
        for end in range(len(parts), 1, -1):
            owner = aliases.get(".".join(parts[:end]))
            if owner is not None:
                return ".".join([owner, *parts[end:]])
    return fq


def _placeholders(values: Iterable[str]) -> str:
    return ",".join("?" for _ in values)


class _Context:
    def __init__(self, db: sqlite3.Connection, records: Iterable[FileRecord]) -> None:
        self.db = db
        row = db.execute("SELECT value FROM inventory_metadata WHERE key='code_index_truncated'").fetchone()
        self.truncated = json.loads(row[0]) if row else {"tables": [], "files": 0}
        package_dirs = set()
        for record in records:
            if record.path.endswith("__init__.py"):
                package_dirs.add(PurePosixPath(record.path.replace("\\", "/")).parent.as_posix())
        db.execute(
            """CREATE TEMP TABLE files (
                path TEXT PRIMARY KEY, language TEXT, grp TEXT, module TEXT,
                package INTEGER, test INTEGER, dir TEXT, base TEXT
            ) WITHOUT ROWID"""
        )
        rows = []
        namespace_names: dict[str, list[str]] = defaultdict(list)
        modules: set[str] = set()
        for record in records:
            if not supports_language(record.language):
                continue
            posix = record.path.replace("\\", "/")
            module = _import_name(posix, package_dirs) if record.language == "Python" else None
            if module:
                modules.add(module)
                alias = _namespace_alias(posix, module)
                if alias:
                    namespace_names[alias].append(module)
            rows.append((
                sqlite_text(record.path), record.language,
                _LANGUAGE_GROUPS.get(record.language, record.language), module,
                int(posix.endswith("__init__.py")), int(is_test_path(posix)),
                posixpath.dirname(posix), posixpath.basename(posix),
            ))
            if len(rows) >= 4096:
                db.executemany("INSERT OR IGNORE INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
                rows.clear()
        db.executemany("INSERT OR IGNORE INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        db.execute("CREATE INDEX temp.files_base ON files(base)")
        # ``ns.pkg.mod`` -> ``pkg.mod`` for modules below a PEP 420 namespace directory.
        self.namespace_aliases = {
            alias: owners[0] for alias, owners in namespace_names.items()
            if len(owners) == 1 and alias not in modules
        }
        self.file_count = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        self._ambiguous: dict[str, list[str]] | None = None
        self._python_types: _PythonTypes | None = None
        # Served routes with the prefixes of routers mounted from other files (the endpoints
        # pass), for the integration summary.
        self.endpoint_routes: list[dict] | None = None
        # (file, line, method) of a route -> the contract operation it serves (the contract_links pass).
        self.route_contracts: dict[tuple, str] | None = None

    @property
    def ambiguous(self) -> dict[str, list[str]]:
        if self._ambiguous is None:
            self._ambiguous = _ambiguous_modules(self.db)
        return self._ambiguous

    def python_key(self, qualified: str, module: str, path: str) -> str:
        """A definition's key, as ``py_defs`` names it (``path:qualified`` in a shared module)."""
        return f"{path}:{qualified}" if module in self.ambiguous else f"{module}.{qualified}"

    def python_fq(self, target: str, module: str, package: bool, path: str) -> str | None:
        """A Python call target or type reference as a definition name, or None."""
        resolved = _python_target(target, module, package)
        if resolved:
            resolved = _disambiguated(_namespace_resolved(resolved, self.namespace_aliases), path, self.ambiguous)
        return resolved

    @property
    def python_types(self) -> _PythonTypes:
        """Return and base classes across modules (needs ``py_defs`` from the call graph)."""
        if self._python_types is None:
            self._python_types = _PythonTypes(self)
        return self._python_types


def analyze_code_index(inventory_path: Path, records: Iterable[FileRecord]) -> tuple[dict, list[Finding]]:
    """Build the cross-file passes; returns (metrics, findings)."""
    metrics: dict = {}
    findings: list[Finding] = []
    db = _connect(inventory_path)
    try:
        context = _Context(db, records)
        for name, build in _PASSES:
            try:
                value, items = build(context)
            except (sqlite3.Error, ValueError, RecursionError, MemoryError) as exc:
                value, items = {"error": f"{type(exc).__name__}: {exc}"}, [Finding(
                    "analysis_coverage", f"Code index pass failed: {name}",
                    f"{type(exc).__name__}: {exc}. This pass's results are missing from the report.",
                    confidence="UNKNOWN", analyzer="code-index", severity="LOW",
                )]
            metrics[name] = value
            findings.extend(items)
        if context.truncated["tables"] or context.truncated["files"]:
            findings.append(Finding(
                "analysis_coverage", "Code index truncated",
                f"Tables at their ceiling: {', '.join(context.truncated['tables']) or 'none'}; "
                f"{context.truncated['files']:,} file(s) exceeded a per-file fact limit. Index-based "
                "results (call graph, unreferenced functions, test links) are incomplete.",
                confidence="UNKNOWN", analyzer="code-index", severity="LOW",
            ))
        metrics["truncated"] = context.truncated
    finally:
        db.close()
    return metrics, findings


# --------------------------------------------------------------------------- symbols

def _symbols(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    by_language: dict[str, dict[str, int]] = defaultdict(dict)
    total = 0
    for language, kind, count in db.execute(
        "SELECT language, kind, COUNT(*) FROM code_symbols GROUP BY language, kind ORDER BY language, kind"
    ):
        by_language[language][kind] = count
        total += count
    files = db.execute("SELECT COUNT(DISTINCT path) FROM code_symbols").fetchone()[0]
    # Which backend modelled each file: python-ast, tree-sitter (a provisioned grammar) or
    # lexical. Results differ by backend, so reports say which one each language got.
    models: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for backend, detail in db.execute("SELECT name, detail FROM code_facts WHERE kind = 'code_model'"):
        language = json.loads(detail).get("language", "unknown") if detail else "unknown"
        models[backend][language] += 1
    value = {
        "symbol_count": total, "files_with_symbols": files, "by_language": dict(by_language),
        "models": {backend: dict(sorted(languages.items())) for backend, languages in sorted(models.items())},
    }
    if not total:
        return value, []
    summary = "; ".join(
        f"{language}: " + ", ".join(f"{count:,} {kind}" for kind, count in sorted(kinds.items()))
        for language, kinds in sorted(by_language.items(), key=lambda item: -sum(item[1].values()))[:12]
    )
    backends = ", ".join(
        f"{sum(languages.values()):,} {backend}" for backend, languages in sorted(models.items())
    ) or "none recorded"
    return value, [Finding(
        "symbol_index", "Symbol index",
        f"{total:,} definitions in {files:,} files. {summary}. Files modelled by backend: "
        f"{backends}. Python symbols come from the syntax tree; other languages from a "
        "Tree-sitter grammar where one is provisioned, else from PDT's structural lexer. "
        "Query the index with `pdt query OUTPUT --symbol NAME`.",
        confidence="CONFIRMED", analyzer="code-index",
    )]


# --------------------------------------------------------------------------- call graph

def _python_target(target: str, module: str, package: bool) -> str | None:
    if not target or target.startswith(("builtins.", "~")):
        return None
    if target.startswith("@"):
        return f"{module}.{target[1:]}"
    if target.startswith("."):
        level = len(target) - len(target.lstrip("."))
        rest = target[level:]
        anchor = module if package else module.rpartition(".")[0]
        try:
            return resolve_name("." * level + rest, anchor) if anchor or level == 1 else None
        except (ImportError, ValueError):
            return None
    return target


class _PythonTypes:
    """Return classes and base classes of Python definitions, joined across modules.

    The code model types what one file states. This completes call targets across files:
    a method a class inherits (``app.B.save`` defined in base ``lib.A``), and a call on the
    value an imported function or method returns (``pkg.store.make_store().run``).
    Lookups go through temporary tables, so memory stays bounded by distinct targets.
    """

    _DEPTH = 8

    def __init__(self, context: "_Context") -> None:
        self.db = context.db
        self._memo: dict[str, str | None] = {}
        db = context.db
        db.execute("CREATE TEMP TABLE IF NOT EXISTS py_returns (fq TEXT PRIMARY KEY, type TEXT) WITHOUT ROWID")
        db.execute(
            "CREATE TEMP TABLE IF NOT EXISTS py_bases (cls TEXT, position INTEGER, base TEXT, PRIMARY KEY (cls, position))"
            " WITHOUT ROWID"
        )
        returns, bases = [], []
        for kind, name, detail, path, module, package in db.execute(
            """SELECT c.kind, c.name, c.detail, c.path, f.module, f.package FROM code_facts c
               JOIN files f ON f.path = c.path
               WHERE c.kind IN ('py_return', 'py_class_bases') AND f.language = 'Python' AND f.module IS NOT NULL"""
        ):
            try:
                data = json.loads(detail)
            except (ValueError, TypeError):
                continue
            key = context.python_key(name, module, path)
            if kind == "py_return":
                reference = data.get("type")
                value = reference if reference == "<self>" else (
                    context.python_fq(reference, module, bool(package), path) if isinstance(reference, str) else None
                )
                if value:
                    returns.append((key, value))
            else:
                for position, reference in enumerate(data.get("bases") or ()):
                    value = context.python_fq(reference, module, bool(package), path) if isinstance(reference, str) else None
                    if value:
                        bases.append((key, position, value))
        db.executemany("INSERT OR IGNORE INTO py_returns VALUES (?, ?)", returns)
        db.executemany("INSERT OR IGNORE INTO py_bases VALUES (?, ?, ?)", bases)
        self.empty = not returns and not bases

    def _kind(self, fq: str) -> str | None:
        row = self.db.execute("SELECT kind FROM py_defs WHERE fq = ?", (fq,)).fetchone()
        return row[0] if row else None

    def definition(self, fq: str, depth: int = 0) -> str | None:
        """The definition ``fq`` names: itself, or the method a base class defines."""
        if self._kind(fq) is not None:
            return fq
        owner, _, method = fq.rpartition(".")
        if not owner or depth > self._DEPTH:
            return None
        for (base,) in self.db.execute("SELECT base FROM py_bases WHERE cls = ? ORDER BY position", (owner,)).fetchall():
            found = self.definition(f"{base}.{method}", depth + 1)
            if found is not None:
                return found
        return None

    def value(self, expression: str, depth: int = 0) -> str | None:
        """The class of a deferred value ``callable()``."""
        if depth > self._DEPTH or not expression.endswith("()"):
            return None
        callable_ = expression[:-2]
        if "()." in callable_:  # a method called on an earlier returned value
            inner, _, method = callable_.rpartition("().")
            receiver = self.value(inner + "()", depth + 1)
            if receiver is None:
                return None
            callable_ = f"{receiver}.{method}"
        defined = self.definition(callable_)
        if defined is None:
            return None
        if self._kind(defined) == "class":
            return defined  # calling a class constructs it
        row = self.db.execute("SELECT type FROM py_returns WHERE fq = ?", (defined,)).fetchone()
        if row is None:
            return None
        if row[0] == "<self>":
            return callable_.rpartition(".")[0] or None  # the receiver's class, not the base's
        return self.value(row[0], depth + 1) if row[0].endswith("()") else row[0]

    def complete(self, target: str) -> str:
        """``target`` completed through returned values and base classes, when the index can."""
        if self.empty or target in self._memo:
            return self._memo.get(target, target) or target
        completed = target
        if "()." in target:
            inner, _, method = target.rpartition("().")
            receiver = self.value(inner + "()")
            completed = f"{receiver}.{method}" if receiver else target
        if "()" not in completed:
            completed = self.definition(completed) or completed
        if len(self._memo) < 200_000:
            self._memo[target] = completed
        return completed


def _ambiguous_modules(db: sqlite3.Connection) -> dict[str, list[str]]:
    """Python module names that more than one scanned file defines, with those files.

    A module outside any package is named by its stem, so svc_a/helpers.py and
    svc_b/helpers.py are both ``helpers`` (also conftest.py, setup.py, handler.py).
    """
    ambiguous: dict[str, list[str]] = defaultdict(list)
    for module, path in db.execute(
        """SELECT module, path FROM files WHERE language = 'Python' AND module IN (
               SELECT module FROM files WHERE language = 'Python' AND module IS NOT NULL
               GROUP BY module HAVING COUNT(*) > 1)"""
    ):
        ambiguous[module].append(path)
    return dict(ambiguous)


def _module_root(module: str, path: str) -> str:
    """The directory ``module`` is imported from, as ``path`` locates it ("" for the root)."""
    relative = module.replace(".", "/")
    for suffix in (relative + ".py", relative + ".pyi", relative + "/__init__.py"):
        if path == suffix or path.endswith("/" + suffix):
            return path[: len(path) - len(suffix)]
    return posixpath.dirname(path) + "/"


def _disambiguated(fq: str, importer: str, ambiguous: dict[str, list[str]]) -> str | None:
    """``fq``, or ``path:rest`` when its module is defined by several files.

    The file whose import root contains the importer is chosen (the innermost one), as
    ``sys.path[0]`` picks a script's own directory. With no single such file the call
    stays unresolved: joining an arbitrary file of that name reported a sink in
    svc_b/helpers.py as a HIGH flow from svc_a/app.py.
    """
    if not ambiguous:
        return fq
    parts = fq.split(".")
    for end in range(len(parts), 0, -1):
        module = ".".join(parts[:end])
        paths = ambiguous.get(module)
        if paths is None:
            continue
        rest = ".".join(parts[end:])
        if importer in paths:
            chosen = [importer]
        else:
            roots = [(_module_root(module, item), item) for item in paths]
            fitting = [(root, item) for root, item in roots if importer.startswith(root)]
            deepest = max((len(root) for root, _ in fitting), default=-1)
            chosen = [item for root, item in fitting if len(root) == deepest]
        if len(chosen) != 1:
            return None
        return f"{chosen[0]}:{rest}" if rest else chosen[0]
    return fq


def _call_graph(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    kinds = _placeholders(_CALLABLE_KINDS)
    ambiguous = _ambiguous_modules(db)
    db.execute("CREATE TEMP TABLE py_ambiguous (module TEXT PRIMARY KEY) WITHOUT ROWID")
    db.executemany("INSERT INTO py_ambiguous VALUES (?)", [(module,) for module in ambiguous])
    db.execute("CREATE TEMP TABLE py_defs (fq TEXT PRIMARY KEY, path TEXT, kind TEXT) WITHOUT ROWID")
    # Definitions in a module that several files share are named ``path:qualified``.
    db.execute(
        f"""INSERT OR IGNORE INTO py_defs
            SELECT CASE WHEN a.module IS NULL THEN f.module || '.' || s.qualified
                        ELSE s.path || ':' || s.qualified END, s.path, s.kind
            FROM code_symbols s JOIN files f ON f.path = s.path
            LEFT JOIN py_ambiguous a ON a.module = f.module
            WHERE f.language = 'Python' AND f.module IS NOT NULL AND s.kind IN ({kinds})""",
        _CALLABLE_KINDS,
    )
    db.execute("CREATE TEMP TABLE py_calls (caller TEXT, target TEXT, path TEXT, line INTEGER)")
    batch = []
    for path, caller, target, line, module, package in db.execute(
        """SELECT c.path, c.caller, c.target, c.line, f.module, f.package FROM code_calls c
           JOIN files f ON f.path = c.path WHERE f.language = 'Python' AND f.module IS NOT NULL"""
    ):
        resolved = _python_target(target, module, bool(package))
        if resolved:
            resolved = _disambiguated(_namespace_resolved(resolved, context.namespace_aliases), path, ambiguous)
        if resolved:
            if module in ambiguous:
                caller_fq = path if caller == "<module>" else f"{path}:{caller}"
            else:
                caller_fq = module if caller == "<module>" else f"{module}.{caller}"
            batch.append((caller_fq, resolved, path, line))
            if len(batch) >= 8192:
                db.executemany("INSERT INTO py_calls VALUES (?, ?, ?, ?)", batch)
                batch.clear()
    db.executemany("INSERT INTO py_calls VALUES (?, ?, ?, ?)", batch)
    db.execute("CREATE INDEX temp.py_calls_target ON py_calls(target)")
    # Calls the defining file could not finish: on a value another module's function
    # returns, or of a method a class inherits.
    types = context.python_types
    if not types.empty:
        pending = [
            target for (target,) in db.execute(
                """SELECT DISTINCT c.target FROM py_calls c
                   WHERE NOT EXISTS (SELECT 1 FROM py_defs d WHERE d.fq = c.target)"""
            ).fetchall()
        ]
        updates = [(completed, target) for target in pending if (completed := types.complete(target)) != target]
        db.executemany("UPDATE py_calls SET target = ? WHERE target = ?", updates)

    total = db.execute("SELECT COUNT(*) FROM code_calls").fetchone()[0]
    python_total = db.execute(
        "SELECT COUNT(*) FROM code_calls c JOIN files f ON f.path = c.path WHERE f.language = 'Python'"
    ).fetchone()[0]
    python_resolved = db.execute(
        "SELECT COUNT(*) FROM py_calls c JOIN py_defs d ON d.fq = c.target"
    ).fetchone()[0]
    python_builtin = db.execute(
        """SELECT COUNT(*) FROM code_calls c JOIN files f ON f.path = c.path
           WHERE f.language = 'Python' AND c.target LIKE 'builtins.%'"""
    ).fetchone()[0]

    # Lexical calls: resolve by name within each language group.
    db.execute(
        f"""CREATE TEMP TABLE lex_names AS
            SELECT s.name AS name, f.grp AS grp, COUNT(DISTINCT s.path) AS n, MIN(s.path) AS path,
                   MIN(s.qualified) AS qualified
            FROM code_symbols s JOIN files f ON f.path = s.path
            WHERE f.language != 'Python' AND s.kind IN ({kinds}) GROUP BY s.name, f.grp""",
        _CALLABLE_KINDS,
    )
    db.execute("CREATE INDEX temp.lex_names_key ON lex_names(name, grp)")
    # A call through another receiver (items.size(), PathBuf::new()) is not a call of the
    # same-named function in this file, and never of the caller itself: resolving it by
    # name alone reported delegation as recursion. Receiverless calls, this./self./Self::
    # calls and calls through the caller's own class name resolve in the file.
    db.create_function(
        "pdt_class_of", 1, lambda qualified: qualified.rpartition(".")[0] if qualified else "", deterministic=True,
    )
    db.execute(
        f"""CREATE TEMP TABLE lex_calls AS
            SELECT c.path AS path, c.caller AS caller, c.callee AS callee, c.line AS line, f.grp AS grp,
                   COALESCE(c.target, '') AS target,
                   CASE
                     WHEN (COALESCE(c.target, '') = '' OR c.target LIKE '@%'
                           OR c.target = '~' || pdt_class_of(c.caller) || '.' || c.callee)
                          AND EXISTS (SELECT 1 FROM code_symbols s WHERE s.path = c.path AND s.name = c.callee
                                      AND s.kind IN ({kinds})) THEN 'local'
                     WHEN c.target LIKE '~%' AND n.n = 1 AND n.path = c.path AND n.qualified = c.caller
                       THEN 'external'
                     WHEN n.n = 1 THEN 'unique'
                     WHEN n.n > 1 THEN 'ambiguous'
                     ELSE 'external'
                   END AS resolution
            FROM code_calls c JOIN files f ON f.path = c.path
            LEFT JOIN lex_names n ON n.name = c.callee AND n.grp = f.grp
            WHERE f.language != 'Python'""",
        _CALLABLE_KINDS,
    )
    lexical = dict(db.execute("SELECT resolution, COUNT(*) FROM lex_calls GROUP BY resolution"))
    resolved = python_resolved + lexical.get("local", 0) + lexical.get("unique", 0)

    fan_in = []
    for target, count in db.execute(
        """SELECT c.target, COUNT(*) FROM py_calls c JOIN py_defs d ON d.fq = c.target
           GROUP BY c.target ORDER BY 2 DESC, 1 LIMIT 20"""
    ):
        fan_in.append((count, target))
    for _callee, _group, count, path, qualified in db.execute(
        """SELECT c.callee, c.grp, COUNT(*), n.path, n.qualified FROM lex_calls c
           JOIN lex_names n ON n.name = c.callee AND n.grp = c.grp
           WHERE c.resolution = 'unique' GROUP BY c.callee, c.grp ORDER BY 3 DESC LIMIT 20"""
    ):
        fan_in.append((count, f"{path}: {qualified}"))
    fan_in.sort(key=lambda item: (-item[0], item[1]))

    # Recursion and cycles over resolved edges (bounded).
    edges: dict[str, set[str]] = defaultdict(set)
    edge_count = 0
    for caller, target in db.execute(
        "SELECT DISTINCT c.caller, c.target FROM py_calls c JOIN py_defs d ON d.fq = c.target LIMIT ?",
        (MAX_GRAPH_EDGES,),
    ):
        edges[caller].add(target)
        edge_count += 1
    remaining = MAX_GRAPH_EDGES - edge_count
    if remaining > 0:
        for path, caller, target_path, target in db.execute(
            f"""SELECT DISTINCT c.path, c.caller, COALESCE(s.path, n.path), COALESCE(s.qualified, n.qualified)
                FROM lex_calls c
                LEFT JOIN code_symbols s ON c.resolution = 'local' AND s.path = c.path AND s.name = c.callee
                     AND s.kind IN ({kinds})
                     -- this.run() and Engine::run() name one function, not every run() in the file.
                     AND (c.target = '' OR s.qualified = substr(c.target, 2))
                LEFT JOIN lex_names n ON c.resolution = 'unique' AND n.name = c.callee AND n.grp = c.grp
                WHERE c.resolution IN ('local', 'unique') AND c.caller != '<module>' LIMIT ?""",
            (*_CALLABLE_KINDS, remaining),
        ):
            if target is not None:
                edges[f"{path}: {caller}"].add(f"{target_path}: {target}")
                edge_count += 1
    graph_complete = edge_count < MAX_GRAPH_EDGES
    nodes = sorted(set(edges) | {target for targets in edges.values() for target in targets})
    cycles = [component for component in _strongly_connected_components(nodes, edges) if len(component) > 1]
    direct = sorted(node for node, targets in edges.items() if node in targets)

    value = {
        "call_sites": total,
        "resolved": resolved,
        "python": {"call_sites": python_total, "resolved": python_resolved, "builtin": python_builtin},
        "lexical": lexical,
        "edges_analysed": edge_count,
        "edge_limit_reached": not graph_complete,
        "direct_recursion": len(direct),
        "recursive_cycles": len(cycles),
        "top_fan_in": [{"calls": count, "target": target} for count, target in fan_in[:20]],
    }
    if not total:
        return value, []
    findings = [Finding(
        "call_graph", "Call graph",
        f"{total:,} call sites; {resolved:,} resolved to a definition in the scanned code. "
        f"Python: {python_resolved:,} of {python_total:,} resolved through imports, classes and "
        f"module scope ({python_builtin:,} built-in). Other languages, by name: "
        f"{lexical.get('local', 0):,} same-file, {lexical.get('unique', 0):,} unique, "
        f"{lexical.get('ambiguous', 0):,} ambiguous, {lexical.get('external', 0):,} external or "
        "dynamic. Lexical resolution ignores types and overloads, so its edges are INFERRED.",
        confidence="INFERRED", analyzer="code-index",
        evidence=[f"{count:,} calls -> {target}" for count, target in fan_in[:20]],
    )]
    if direct or cycles:
        findings.append(Finding(
            "call_graph", "Recursive call cycles",
            f"{len(direct):,} function(s) call themselves and {len(cycles):,} group(s) of functions "
            "call each other in a cycle. Check termination and stack-depth bounds, especially for "
            "input-driven recursion." + ("" if graph_complete else " The edge limit was reached; cycles may be missing."),
            confidence="INFERRED", analyzer="code-index", severity="LOW",
            evidence=[f"{node} -> itself" for node in direct[:MAX_LISTED // 2]] + [
                " -> ".join(component[:8]) + (" -> ..." if len(component) > 8 else "")
                for component in cycles[:MAX_CYCLES_LISTED]
            ],
        ))
    return value, findings


# --------------------------------------------------------------------------- dead code

def _unreferenced(context: _Context) -> tuple[dict, list[Finding]]:
    if {"code_references", "code_symbols"} & set(context.truncated["tables"]):
        return {"skipped": "index truncated"}, []
    db = context.db
    entries = sorted(_ENTRY_NAMES)
    where = f"""s.kind IN ({_placeholders(_FUNCTION_KINDS)}) AND s.exported = 0 AND f.test = 0
        AND s.name NOT LIKE '\\_\\_%' ESCAPE '\\' AND s.name NOT IN ({_placeholders(entries)})
        AND NOT EXISTS (SELECT 1 FROM code_references r WHERE r.name = s.name)
        AND NOT EXISTS (SELECT 1 FROM code_calls c WHERE c.callee = s.name)"""
    parameters = (*_FUNCTION_KINDS, *entries)
    count = db.execute(
        f"SELECT COUNT(*) FROM code_symbols s JOIN files f ON f.path = s.path WHERE {where}", parameters,
    ).fetchone()[0]
    cut = int(context.truncated.get("kinds", {}).get("references", 0))
    value = {"unreferenced_private_functions": count}
    if cut:
        value["references_truncated_files"] = cut
    if not count:
        return value, []
    listed = db.execute(
        f"""SELECT s.path, s.line, s.qualified FROM code_symbols s JOIN files f ON f.path = s.path
            WHERE {where} ORDER BY s.path, s.line LIMIT {MAX_LISTED}""",
        parameters,
    ).fetchall()
    return value, [Finding(
        "call_graph", "Unreferenced private functions",
        f"{count:,} private (non-exported) function(s) or method(s) are never referenced by name "
        "anywhere in the scanned code: dead-code candidates. Reflection, string-based dispatch, "
        "framework registration and code outside the scan are not visible, so confirm before removal."
        + (f" {cut:,} file(s) had more distinct names than the index keeps, so a name used only in "
           "those files can be listed here wrongly." if cut else ""),
        confidence="INFERRED", analyzer="code-index", severity="LOW",
        evidence=[f"{path}:{line} {qualified}" for path, line, qualified in listed],
        recommendation="Remove confirmed dead code, or document why it is reached indirectly.",
    )]


# --------------------------------------------------------------------------- tests

def _test_links(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    test_files = db.execute("SELECT COUNT(*) FROM files WHERE test = 1").fetchone()[0]
    if not test_files:
        return {"test_files": 0}, []
    base = f"""FROM code_symbols s JOIN files f ON f.path = s.path
        WHERE s.kind IN ({_placeholders(_FUNCTION_KINDS)}) AND s.exported = 1 AND f.test = 0
        AND s.name NOT LIKE '\\_\\_%' ESCAPE '\\'"""
    tested = """EXISTS (SELECT 1 FROM code_references r JOIN files t ON t.path = r.path
                WHERE r.name = s.name AND t.test = 1)"""
    public = db.execute(f"SELECT COUNT(*) {base}", _FUNCTION_KINDS).fetchone()[0]
    referenced = db.execute(f"SELECT COUNT(*) {base} AND {tested}", _FUNCTION_KINDS).fetchone()[0]
    by_language = {
        language: {"public": total, "referenced_from_tests": hit}
        for language, total, hit in db.execute(
            f"SELECT s.language, COUNT(*), SUM({tested}) {base} GROUP BY s.language", _FUNCTION_KINDS,
        )
    }
    value = {"test_files": test_files, "public_functions": public,
             "referenced_from_tests": referenced, "by_language": by_language}
    if not public:
        return value, []
    untested = db.execute(
        f"SELECT s.path, s.line, s.qualified {base} AND NOT {tested} ORDER BY s.path, s.line LIMIT {MAX_LISTED // 2}",
        _FUNCTION_KINDS,
    ).fetchall()
    share = referenced / public * 100
    return value, [Finding(
        "testing", "Test-to-code references",
        f"{referenced:,} of {public:,} public functions and methods ({share:.0f}%) are referenced by "
        f"name from {test_files:,} test file(s). A shared name counts as referenced, so this "
        "over-estimates direct test reach; it is not line coverage (see coverage artifacts for that). "
        "Evidence lists public functions that no test references.",
        confidence="INFERRED", analyzer="code-index",
        evidence=[f"{path}:{line} {qualified}" for path, line, qualified in untested],
    )]


# --------------------------------------------------------------------------- modules

def _module_graph(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    edges: dict[str, set[str]] = defaultdict(set)
    edge_count = 0
    external: Counter = Counter()
    resolved = unresolved = 0
    # Go imports resolve against the module paths the scanned go.mod files declare. Without
    # a go.mod, a directory suffix of at least two segments ("b/c" of .../repo/b/c) is used.
    # A single trailing segment never matches: "log", "net/http" or "encoding/json" found
    # local log/, http/ or json/ directories, inventing edges and module cycles.
    go_dirs = {directory for (directory,) in db.execute("SELECT DISTINCT dir FROM files WHERE language = 'Go'")}
    go_modules = sorted(
        ((name, posixpath.dirname(path)) for name, path, values in _fact_rows(db, "package_name")
         if values.get("ecosystem") == "go"),
        key=lambda item: -len(item[0]),
    )
    go_suffixes: dict[str, str] = {}
    if not go_modules:
        for directory in go_dirs:
            parts = directory.split("/") if directory else []
            for start in range(len(parts) - 1):
                go_suffixes.setdefault("/".join(parts[start:]), directory)

    def go_directory(target: str) -> str | None:
        for module, root in go_modules:
            if target == module or target.startswith(module + "/"):
                directory = posixpath.join(root, target[len(module) + 1:]) if target != module else root
                directory = "" if directory in {"", "."} else posixpath.normpath(directory)
                return directory if directory in go_dirs else None
        if go_modules or "." not in target.split("/", 1)[0]:
            return None  # another module, or the standard library (no dot in the first segment)
        segments = target.split("/")
        for start in range(len(segments) - 1):
            match = go_suffixes.get("/".join(segments[start:]))
            if match is not None:
                return match
        return None

    def exists(path: str) -> bool:
        return db.execute("SELECT 1 FROM files WHERE path = ?", (sqlite_text(path),)).fetchone() is not None

    def by_suffix(suffix: str, origin_dir: str) -> str | None:
        base = posixpath.basename(suffix)
        candidates = [row[0] for row in db.execute("SELECT path FROM files WHERE base = ? LIMIT 64", (base,))
                      if row[0] == suffix or row[0].endswith("/" + suffix)]
        if not candidates:
            return None
        # Prefer the candidate that shares the longest directory prefix with the importer.
        return max(candidates, key=lambda item: (len(posixpath.commonprefix([item, origin_dir])), -len(item)))

    def rust_module(target: str, origin: str) -> str | None:
        """The module file a ``use`` path names: its longest prefix that is a module file."""
        parts = [part for part in target.split("::") if part]
        if not parts or parts[0] not in {"crate", "self", "super"}:
            return None  # another crate, or the standard library
        stem = posixpath.splitext(posixpath.basename(origin))[0]
        directory = posixpath.dirname(origin)
        # The directory holding the current module's children.
        module_dir = directory if stem in {"mod", "lib", "main"} else posixpath.join(directory, stem)
        if parts[0] == "crate":
            base = None
            probe = directory
            while True:  # the crate root: the nearest lib.rs or main.rs above the file
                if exists(posixpath.join(probe, "lib.rs") if probe else "lib.rs") or exists(
                        posixpath.join(probe, "main.rs") if probe else "main.rs"):
                    base = probe
                    break
                if not probe:
                    break
                probe = posixpath.dirname(probe)
            if base is None:
                return None
        else:
            base = module_dir
            for _ in parts[:1] if parts[0] == "super" else ():
                base = posixpath.dirname(base)
        names = [part for part in parts[1:] if part.isidentifier()]
        for end in range(len(names), 0, -1):
            stem_path = posixpath.join(base, *names[:end]) if base else posixpath.join(*names[:end])
            for candidate in (stem_path + ".rs", posixpath.join(stem_path, "mod.rs")):
                if exists(candidate):
                    return candidate
        return None

    for target, path, detail in db.execute(
        "SELECT name, path, detail FROM code_facts WHERE kind = 'import' ORDER BY path"
    ):
        language = json.loads(detail).get("language", "")
        if language == "Python":
            continue  # the Python module graph covers these
        origin_dir = posixpath.dirname(path)
        found: str | None = None
        package = ""
        if language in {"JavaScript", "TypeScript", "Vue", "Svelte", "Dart"}:
            if target.startswith((".", "/")) or (language == "Dart" and ":" not in target):
                base = posixpath.normpath(posixpath.join(origin_dir, target)).lstrip("/")
                for candidate in (base, *(base + ext for ext in _JS_EXTENSIONS),
                                  *(base + "/index" + ext for ext in _JS_EXTENSIONS)):
                    if exists(candidate):
                        found = candidate
                        break
            elif target.startswith("package:"):
                package = target[len("package:"):].split("/")[0]
            elif not target.startswith("dart:"):
                package = "/".join(target.split("/")[:2]) if target.startswith("@") else target.split("/")[0]
        elif language == "PHP" and target.endswith(".php"):
            local = posixpath.normpath(posixpath.join(origin_dir, target)).lstrip("/")
            found = local if exists(local) else by_suffix(target.lstrip("./"), origin_dir)
        elif language in {"C", "C++", "C/C++ Header", "Objective-C", "Objective-C++", "CUDA", "OpenCL"}:
            local = posixpath.normpath(posixpath.join(origin_dir, target))
            found = local if exists(local) else by_suffix(target, origin_dir)
            package = "" if found else target
        elif language in {"Java", "Kotlin", "Scala", "Groovy"}:
            if not target.endswith(".*"):
                stem = target.replace(".", "/")
                for ext in _JVM_EXTENSIONS:
                    found = by_suffix(stem + ext, origin_dir)
                    if found:
                        break
            package = "" if found else ".".join(target.split(".")[:2])
        elif language == "Go":
            segments = target.split("/")
            match = go_directory(target)
            if match is not None:
                found = f"{match}/"  # Go packages are directories ("/" is the root package)
            package = "" if found else "/".join(segments[:3])
        elif language == "Rust":
            if "::" not in target:  # ``mod name;``
                stem = posixpath.splitext(posixpath.basename(path))[0]
                base_dir = origin_dir if stem in {"mod", "lib", "main"} else posixpath.join(origin_dir, stem)
                for candidate in (posixpath.join(base_dir, f"{target}.rs"), posixpath.join(base_dir, target, "mod.rs")):
                    if exists(candidate):
                        found = candidate
                        break
            else:  # ``use crate::a::b::Item``, ``use self::x``, ``use super::y``
                found = rust_module(target, path)
            package = "" if found or target.startswith(("crate", "self", "super")) else target.split("::")[0]
        elif language == "PHP":
            stem = target.replace("\\", "/")
            found = by_suffix(stem + ".php", origin_dir) or by_suffix("/".join(stem.split("/")[1:]) + ".php", origin_dir)
            package = "" if found else stem.split("/")[0]
        else:
            package = target.split(".")[0]
        if found:
            resolved += 1
            source = f"{origin_dir}/" if language == "Go" else path
            if found != source and edge_count < MAX_GRAPH_EDGES and found not in edges[source]:
                edges[source].add(found)
                edge_count += 1
        else:
            unresolved += 1
            if package:
                external[package] += 1
    nodes = sorted(set(edges) | {target for targets in edges.values() for target in targets})
    cycles = [component for component in _strongly_connected_components(nodes, edges) if len(component) > 1]
    fan_in = Counter(target for targets in edges.values() for target in targets)
    value = {
        "resolved_imports": resolved, "unresolved_imports": unresolved,
        "modules": len(nodes), "edges": edge_count, "cycles": len(cycles),
        "most_imported": [{"module": module, "importers": count} for module, count in fan_in.most_common(20)],
        "external_packages": [{"package": name, "imports": count} for name, count in external.most_common(30)],
    }
    if not resolved and not unresolved:
        return value, []
    findings = [Finding(
        "dependency", "Module graph",
        f"{resolved:,} import(s) resolved to {len(nodes):,} files or packages in the scanned code "
        f"({value['edges']:,} edges); {unresolved:,} refer to external packages, the platform or "
        "paths that were not resolved. Python imports are covered by the Python module graph.",
        confidence="INFERRED", analyzer="code-index",
        evidence=[f"{count:,} importers -> {module}" for module, count in fan_in.most_common(15)]
        + [f"external {name} ({count:,} imports)" for name, count in external.most_common(15)],
    )]
    if cycles:
        findings.append(Finding(
            "dependency", "Module dependency cycles",
            f"{len(cycles):,} group(s) of files or packages import each other in a cycle. Cycles "
            "couple modules so they cannot be built, tested or reasoned about separately.",
            confidence="INFERRED", analyzer="code-index", severity="LOW",
            evidence=[" -> ".join(component[:8]) + (" -> ..." if len(component) > 8 else "")
                      for component in cycles[:MAX_CYCLES_LISTED]],
        ))
    return value, findings


# --------------------------------------------------------------------------- fact summaries

def _fact_totals(db: sqlite3.Connection, kind: str) -> tuple[dict[str, Counter], Counter]:
    """Sum the numeric fields of one fact kind per language: (totals, file counts)."""
    totals: dict[str, Counter] = defaultdict(Counter)
    files: Counter = Counter()
    for language, detail in db.execute("SELECT name, detail FROM code_facts WHERE kind = ?", (kind,)):
        try:
            values = json.loads(detail)
        except ValueError:
            continue
        if not isinstance(values, dict):
            continue
        files[language] += 1
        for key, number in values.items():
            if isinstance(number, (int, float)) and not isinstance(number, bool):
                if key == "maximum":
                    totals[language][key] = max(totals[language][key], number)
                else:
                    totals[language][key] += number
    return totals, files


def _percent(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def _complexity(context: _Context) -> tuple[dict, list[Finding]]:
    totals, files = _fact_totals(context.db, "complexity_stats")
    functions = sum(counts["functions"] for counts in totals.values())
    if not functions:
        return {"functions": 0}, []
    total = sum(counts["total"] for counts in totals.values())
    high = sum(counts["high"] for counts in totals.values())
    heaviest = []
    for name, path, detail in context.db.execute(
        "SELECT name, path, detail FROM code_facts WHERE kind = 'complex_function'"
    ):
        try:
            values = json.loads(detail)
            heaviest.append((int(values["complexity"]), path, int(values.get("line", 0)), name))
        except (ValueError, KeyError, TypeError):
            continue
        if len(heaviest) > 4 * MAX_LISTED:
            heaviest = sorted(heaviest, reverse=True)[:MAX_LISTED]
    heaviest = sorted(heaviest, reverse=True)[:MAX_LISTED]
    value = {
        "functions": functions, "mean": round(total / functions, 2), "high": high,
        "maximum": max(counts["maximum"] for counts in totals.values()),
        "by_language": {
            language: {"files": files[language], "functions": counts["functions"],
                       "mean": round(counts["total"] / counts["functions"], 2) if counts["functions"] else 0,
                       "maximum": counts["maximum"], "high": counts["high"]}
            for language, counts in sorted(totals.items())
        },
        "most_complex": [{"name": name, "path": path, "line": line, "complexity": score}
                         for score, path, line, name in heaviest[:20]],
    }
    return value, [Finding(
        "performance", "Code complexity summary",
        f"{functions:,} functions measured; mean cyclomatic complexity {value['mean']}, maximum "
        f"{value['maximum']}; {high:,} function(s) at 25 or more. Python complexity comes from the "
        "syntax tree; other languages count decision keywords and operators in each function body.",
        confidence="INFERRED", analyzer="code-index",
        evidence=[f"{path}:{line} {name} (complexity {score})" for score, path, line, name in heaviest[:15]],
    )]


def _type_summary(context: _Context) -> tuple[dict, list[Finding]]:
    totals, files = _fact_totals(context.db, "type_stats")
    if not totals:
        return {}, []
    parts = []
    python = totals.get("Python")
    if python and python["functions"]:
        parts.append(
            f"Python: {python['fully_annotated']:,} of {python['functions']:,} functions fully annotated "
            f"({_percent(python['fully_annotated'], python['functions'])}), "
            f"{_percent(python['typed_parameters'], python['parameters'])} of parameters typed, "
            f"{python['any']:,} `Any`, {python['suppressions']:,} `# type: ignore`"
            + (f", {python['file_ignored']:,} module(s) excluded from checking" if python["file_ignored"] else "")
        )
    typescript = Counter()
    for language in ("TypeScript", "Vue", "Svelte"):
        if totals.get(language, Counter())["typescript"]:
            typescript.update(totals[language])
    if typescript:
        parts.append(
            f"TypeScript ({typescript['typescript']:,} files): {typescript['any']:,} `any`, "
            f"{typescript['suppressions']:,} `@ts-ignore`/`@ts-expect-error`, "
            f"{typescript['non_null_assertions']:,} non-null assertions"
            + (f", {typescript['nocheck']:,} file(s) with `@ts-nocheck`" if typescript["nocheck"] else "")
        )
    javascript = files.get("JavaScript", 0)
    if javascript:
        parts.append(f"JavaScript: {totals['JavaScript']['checked']:,} of {javascript:,} files with "
                     "functions opt into type checking (`// @ts-check` or `// @flow`)")
    labels = {
        "Kotlin": ("not_null_assertions", "`!!` not-null assertions"),
        "Swift": ("forced", "forced casts or tries (`as!`, `try!`)"),
        "C#": ("dynamic", "`dynamic` declarations"),
        "Java": ("suppressions", "unchecked or raw-type warning suppressions"),
        "Go": ("empty_interfaces", "empty interfaces (`interface{}`)"),
    }
    for language, (key, label) in labels.items():
        if language in totals:
            parts.append(f"{language}: {totals[language][key]:,} {label}")
    value = {
        language: dict(sorted(counts.items())) | {"files": files[language]}
        for language, counts in sorted(totals.items())
    }
    if not parts:
        return value, []
    return value, [Finding(
        "type_systems", "Type system usage",
        "; ".join(parts) + ". Escape hatches are counted in code with comments and strings removed.",
        confidence="INFERRED", analyzer="code-index",
    )]


_CONCURRENCY_LABELS = {
    "async_functions": "async functions", "async_tasks": "task spawns or joins", "threads": "thread starts",
    "thread_pools": "thread pools", "process_pools": "process pools", "processes": "processes",
    "goroutines": "goroutines", "channels": "channels or queues", "queues": "queues", "locks": "locks",
    "workers": "web workers", "atomics": "atomics",
}


def _concurrency_summary(context: _Context) -> tuple[dict, list[Finding]]:
    totals, files = _fact_totals(context.db, "concurrency")
    if not totals:
        return {}, []
    parts = []
    for language, counts in sorted(totals.items(), key=lambda item: -sum(item[1].values())):
        described = ", ".join(
            f"{count:,} {_CONCURRENCY_LABELS.get(key, key.replace('_', ' '))}"
            for key, count in counts.most_common() if count
        )
        if described:
            parts.append(f"{language} ({files[language]:,} files): {described}")
    value = {language: dict(sorted(counts.items())) | {"files": files[language]}
             for language, counts in sorted(totals.items())}
    return value, [Finding(
        "concurrency", "Concurrency model",
        "; ".join(parts[:12]) + ".", confidence="INFERRED", analyzer="code-index",
    )] if parts else []


def _memory_summary(context: _Context) -> tuple[dict, list[Finding]]:
    totals, files = _fact_totals(context.db, "memory_stats")
    if not totals:
        return {}, []
    native = Counter()
    for language, counts in totals.items():
        if language != "Rust":
            native.update(counts)
    parts = []
    if native["allocations"] or native["raw_new"]:
        parts.append(
            f"C/C++: {native['allocations']:,} malloc/calloc/realloc and {native['frees']:,} free calls; "
            f"{native['raw_new']:,} raw `new` expressions and {native['smart_pointers']:,} smart-pointer uses"
        )
    if totals.get("Rust", Counter())["unsafe_blocks"]:
        parts.append(f"Rust: {totals['Rust']['unsafe_blocks']:,} `unsafe` blocks in {files['Rust']:,} files")
    value = {language: dict(sorted(counts.items())) | {"files": files[language]}
             for language, counts in sorted(totals.items())}
    return value, [Finding(
        "resource_management", "Manual memory management",
        "; ".join(parts) + ". Per-file findings flag allocations, handles and unsafe operations "
        "without a visible release.", confidence="INFERRED", analyzer="code-index",
    )] if parts else []


def _lexical_cross_flows(db: sqlite3.Connection, cross: dict[str, list[str]], kinds) -> tuple[int, int]:
    """Flows from a tainted call in one lexically modelled file into a function of another.

    A call is matched by the callee's name within the language family, and only when a
    single file defines a function of that name: an ambiguous name is not guessed.
    Returns (flows found, exported summaries).
    """
    summaries: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for name, detail, path, group in db.execute(
        """SELECT f.name, f.detail, f.path, files.grp FROM code_facts f JOIN files ON files.path = f.path
           WHERE f.kind = 'taint_sink_param' AND files.module IS NULL"""
    ):
        try:
            summaries[(group, name)].append(json.loads(detail) | {"path": path})
        except (ValueError, TypeError):
            continue
    if not summaries:
        return 0, 0
    db.execute("CREATE TEMP TABLE IF NOT EXISTS taint_names (name TEXT PRIMARY KEY) WITHOUT ROWID")
    db.execute("DELETE FROM taint_names")
    db.executemany("INSERT OR IGNORE INTO taint_names VALUES (?)", ((name,) for _, name in summaries))
    placeholders = ", ".join("?" for _ in _FUNCTION_KINDS)
    definitions = {
        (group, name): count for name, group, count in db.execute(
            f"""SELECT s.name, files.grp, COUNT(DISTINCT s.path) FROM taint_names t
                JOIN code_symbols s ON s.name = t.name JOIN files ON files.path = s.path
                WHERE s.kind IN ({placeholders}) AND files.module IS NULL GROUP BY s.name, files.grp""",
            _FUNCTION_KINDS,
        )
    }
    found = 0
    for target, detail, path, group in db.execute(
        """SELECT f.name, f.detail, f.path, files.grp FROM code_facts f JOIN files ON files.path = f.path
           WHERE f.kind = 'tainted_call' AND files.module IS NULL"""
    ):
        entries = summaries.get((group, target))
        if not entries or definitions.get((group, target)) != 1:
            continue
        try:
            call = json.loads(detail)
        except ValueError:
            continue
        for entry in entries:
            if entry["path"] == path or call.get("arg") != entry.get("param"):
                continue
            found += 1
            kind = entry.get("sink_kind")
            if kind in kinds and len(cross[kind]) < MAX_LISTED:
                callee = f"{call['receiver']}.{target}" if call.get("receiver") else target
                cross[kind].append(
                    f"{path}:{call.get('line')} `{call.get('source')}` (line {call.get('source_line')}) -> "
                    f"{callee}() -> " + (f"{entry['via']} -> " if entry.get("via") else "")
                    + f"`{entry.get('sink')}` at {entry['path']}:{entry.get('line')}"
                )
    return found, sum(len(entries) for entries in summaries.values())


def _dataflow(context: _Context) -> tuple[dict, list[Finding]]:
    """Totals of per-file taint flows, plus Python flows that cross module boundaries:
    a call passing untrusted input to an imported function whose parameter reaches a sink."""
    from ..analyzers.security.dataflow import KINDS

    db = context.db
    totals, files = _fact_totals(db, "dataflow_stats")
    by_kind: Counter = Counter()
    for counts in totals.values():
        by_kind.update({key: value for key, value in counts.items() if key in KINDS})
    summaries: dict[str, list[dict]] = defaultdict(list)
    ambiguous = _ambiguous_modules(db)
    for name, detail, path, module in db.execute(
        """SELECT f.name, f.detail, f.path, files.module FROM code_facts f JOIN files ON files.path = f.path
           WHERE f.kind = 'taint_sink_param' AND files.module IS NOT NULL"""
    ):
        # Keyed like the call graph: ``path:name`` in a module that several files share.
        key = f"{path}:{name}" if module in ambiguous else f"{module}.{name}"
        try:
            summaries[key].append(json.loads(detail) | {"path": path})
        except (ValueError, TypeError):
            continue
    cross: dict[str, list[str]] = defaultdict(list)
    cross_count = 0
    if summaries:
        for target, detail, path, module, package in db.execute(
            """SELECT f.name, f.detail, f.path, files.module, files.package FROM code_facts f
               JOIN files ON files.path = f.path WHERE f.kind = 'tainted_call' AND files.module IS NOT NULL"""
        ):
            resolved = context.python_fq(target, module, bool(package), path)
            if resolved and resolved not in summaries:
                # A call on a returned value or an inherited method, completed across modules.
                try:
                    resolved = context.python_types.complete(resolved)
                except sqlite3.OperationalError:  # the call-graph pass failed: no py_defs
                    pass
            entries = summaries.get(resolved or "")
            if not entries:
                continue
            try:
                call = json.loads(detail)
            except ValueError:
                continue
            for entry in entries:
                if call.get("arg") != entry.get("param") and not (
                    call.get("keyword") and call.get("keyword") == entry.get("parameter")
                ):
                    continue
                cross_count += 1
                kind = entry.get("sink_kind")
                if kind in KINDS and len(cross[kind]) < MAX_LISTED:
                    cross[kind].append(
                        f"{path}:{call.get('line')} `{call.get('source')}` (line {call.get('source_line')}) -> "
                        f"{resolved}() -> " + (f"{entry['via']} -> " if entry.get("via") else "")
                        + f"`{entry.get('sink')}` at {entry['path']}:{entry.get('line')}"
                    )
    lexical_count, lexical_summaries = _lexical_cross_flows(db, cross, KINDS)
    cross_count += lexical_count
    sources = sum(counts["sources"] for counts in totals.values())
    flows = sum(counts["flows"] for counts in totals.values())
    truncated = db.execute("SELECT COUNT(*) FROM code_facts WHERE kind = 'dataflow_truncated'").fetchone()[0]
    value = {
        "sources": sources, "files": sum(files.values()),
        "flows": flows, "by_kind": dict(sorted(by_kind.items())), "cross_module_flows": cross_count,
        "exported_summaries": sum(len(entries) for entries in summaries.values()) + lexical_summaries,
        "truncated_files": truncated,
        "by_language": {language: dict(sorted(counts.items())) | {"files": files[language]}
                        for language, counts in sorted(totals.items())},
    }
    findings = []
    for kind, evidence in sorted(cross.items()):
        title, severity, impact, recommendation = KINDS[kind]
        findings.append(Finding(
            "security", f"{title} across modules",
            f"{impact} The input enters in one module and reaches the sink inside a function of another "
            f"module ({len(evidence):,} flow(s) listed).", confidence="INFERRED", analyzer="dataflow",
            severity=severity, evidence=evidence, recommendation=recommendation,
        ))
    if sources or flows:
        findings.append(Finding(
            "dataflow", "Data-flow summary",
            f"{sources:,} untrusted-input source site(s); {flows:,} flow(s) reach a dangerous operation"
            + (" (" + ", ".join(f"{count:,} {kind}" for kind, count in by_kind.most_common()) + ")" if by_kind else "")
            + f"; {cross_count:,} cross module boundaries. Python flows are followed through assignments, "
            "branches, loops and helper functions; other languages through assignments and the file's own "
            "functions, and into other files by a function name that only one file defines.",
            confidence="INFERRED", analyzer="dataflow",
        ))
    if truncated:
        findings.append(Finding(
            "analysis_coverage", "Data-flow analysis truncated",
            f"{truncated:,} file(s) hit the per-function interpretation budget; flows in them may be missing.",
            confidence="UNKNOWN", analyzer="dataflow", severity="LOW",
        ))
    return value, findings


# --------------------------------------------------------------------------- domain summaries

def _fact_rows(db: sqlite3.Connection, kind: str, ordered: bool = False):
    """(name, path, detail dict) rows of one fact kind; ``ordered`` by path and name, so lists
    cut at a cap keep the same items from scan to scan."""
    query = "SELECT name, path, detail FROM code_facts WHERE kind = ?"
    for name, path, detail in db.execute(query + (" ORDER BY path, name, detail" if ordered else ""), (kind,)):
        try:
            values = json.loads(detail)
        except ValueError:
            continue
        if isinstance(values, dict):
            yield name, path, values


def _bytes(value: int) -> str:
    for unit, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if value >= scale:
            return f"{value / scale:.4g} {unit}"
    return f"{value} B"


def _embedded_summary(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    targets: dict[str, set[str]] = defaultdict(set)
    for name, _, values in _fact_rows(db, "embedded_target"):
        targets[str(values.get("source", "other"))].add(name)
    stats: Counter = Counter()
    files = 0
    for _, _, values in _fact_rows(db, "embedded_stats"):
        files += 1
        stats.update({key: value for key, value in values.items() if isinstance(value, int)})
    regions = Counter()
    for name, _, values in _fact_rows(db, "memory_region"):
        length = values.get("length")
        if isinstance(length, int):
            kind = "flash" if "x" in str(values.get("attributes", "")).lower() and "w" not in str(
                values.get("attributes", "")).lower() or re.search(r"(?i)flash|rom|text|code", name) else "ram"
            regions[kind] += length
    compatibles = Counter()
    for name, _, values in _fact_rows(db, "device_tree_compatible"):
        compatibles[name] += int(values.get("count", 1) or 1)
    value = {
        "targets": {source: sorted(names)[:50] for source, names in sorted(targets.items())},
        "rtos": {key[5:]: count for key, count in stats.items() if key.startswith("rtos:")},
        "frameworks": {key[10:]: count for key, count in stats.items() if key.startswith("framework:")},
        "interrupt_handlers": stats["interrupt_handlers"], "register_accesses": stats["register_accesses"],
        "memory_bytes": dict(regions), "files": files,
        "device_tree_compatibles": dict(compatibles.most_common(30)),
    }
    if not (targets or files or regions):
        return value, []
    parts = []
    if targets:
        parts.append("targets " + "; ".join(f"{source}: {', '.join(sorted(names)[:8])}" for source, names in sorted(targets.items())))
    if value["rtos"]:
        parts.append("RTOS " + ", ".join(f"{name} ({count:,} calls)" for name, count in sorted(value["rtos"].items())))
    if value["frameworks"]:
        parts.append("frameworks " + ", ".join(f"{name} ({count:,})" for name, count in sorted(value["frameworks"].items())))
    if stats["interrupt_handlers"]:
        parts.append(f"{stats['interrupt_handlers']:,} interrupt handler(s)")
    if stats["register_accesses"]:
        parts.append(f"{stats['register_accesses']:,} direct register access(es)")
    if regions:
        parts.append("linker memory " + ", ".join(f"{kind} {_bytes(size)}" for kind, size in sorted(regions.items())))
    return value, [Finding("embedded", "Embedded systems summary", "; ".join(parts) + ".",
                           confidence="INFERRED", analyzer="code-index")]


def _firmware_summary(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    elf: Counter = Counter()
    hardening: dict[str, Counter] = defaultdict(Counter)
    for machine, _, values in _fact_rows(db, "elf_binary"):
        role = str(values.get("role", "binary"))
        elf[f"{machine} {role}"] += 1
        if role in {"Linux executable", "Linux shared object"}:
            counts = hardening[role]
            counts["total"] += 1
            for key in ("nx", "pie", "full_relro", "relro", "canary", "fortify", "rpath"):
                counts[key] += int(values.get(key, 0) or 0)
    pe: Counter = Counter()
    pe_hardening: Counter = Counter()
    for architecture, _, values in _fact_rows(db, "pe_binary"):
        pe[f"{architecture} {values.get('role', 'binary')}"] += 1
        pe_hardening["total"] += 1
        for key in ("aslr", "nx", "cfg"):
            pe_hardening[key] += int(values.get(key, 0) or 0)
    images = Counter(name for name, _, _ in _fact_rows(db, "firmware_image"))
    components = sorted({(name, str(values.get("version", ""))) for name, _, values in _fact_rows(db, "firmware_component")})
    recipes = sum(1 for _ in _fact_rows(db, "yocto_recipe"))
    value = {
        "elf": dict(elf.most_common(40)), "elf_hardening": {role: dict(counts) for role, counts in hardening.items()},
        "pe": dict(pe.most_common(20)), "pe_hardening": dict(pe_hardening), "images": dict(images.most_common()),
        "components": [{"name": name, "version": version} for name, version in components[:100]],
        "yocto_recipes": recipes,
    }
    if not (elf or pe or images or components or recipes):
        return value, []
    parts = []
    if elf:
        parts.append(f"{sum(elf.values()):,} ELF file(s): " + ", ".join(f"{count:,} {kind}" for kind, count in elf.most_common(8)))
    for role, counts in sorted(hardening.items()):
        total = counts["total"]
        protections = [f"NX {counts['nx']}/{total}", f"full RELRO {counts['full_relro']}/{total}",
                       f"stack protector {counts['canary']}/{total}", f"FORTIFY {counts['fortify']}/{total}"]
        if role == "Linux executable":
            protections.insert(1, f"PIE {counts['pie']}/{total}")
        parts.append(f"{role}s hardening: " + ", ".join(protections))
    if pe:
        total = pe_hardening["total"]
        parts.append(f"{total:,} PE file(s) (ASLR {pe_hardening['aslr']}/{total}, NX {pe_hardening['nx']}/{total}, "
                     f"CFG {pe_hardening['cfg']}/{total})")
    if images:
        parts.append("firmware images " + ", ".join(f"{count:,} {name}" for name, count in images.most_common(10)))
    if components:
        parts.append("embedded components " + ", ".join(f"{name} {version}" for name, version in components[:15]))
    if recipes:
        parts.append(f"{recipes:,} Yocto recipe(s)")
    return value, [Finding("firmware", "Binary and firmware inventory", "; ".join(parts) + ".",
                           confidence="CONFIRMED", analyzer="code-index")]


def _hdl_hierarchy(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    modules: dict[str, tuple[str, str, bool, str]] = {}
    for name, path, values in _fact_rows(db, "hdl_module"):
        modules.setdefault(name.lower(), (name, path, bool(values.get("testbench")), str(values.get("kind", ""))))
    if not modules:
        return {}, []
    edges: dict[str, Counter] = defaultdict(Counter)
    unresolved: Counter = Counter()
    for child, _, values in _fact_rows(db, "hdl_instance"):
        parent = str(values.get("parent", "")).lower()
        count = int(values.get("count", 1) or 1)
        if child.lower() in modules:
            edges[parent][child.lower()] += count
        else:
            unresolved[child] += count
    instantiated = {child for children in edges.values() for child in children}
    design = {key for key, (_, _, testbench, kind) in modules.items() if not testbench and kind in {"module", "entity"}}
    tops = sorted(key for key in design if key not in instantiated)
    cycles = [component for component in _strongly_connected_components(
        sorted(modules), {key: set(children) for key, children in edges.items()}) if len(component) > 1]
    cyclic = {node for component in cycles for node in component}
    memo: dict[str, tuple[int, int]] = {}

    def measure(node: str, trail: frozenset) -> tuple[int, int]:
        """(depth, total instances below) without re-entering cycles."""
        if node in memo:
            return memo[node]
        depth, total = 1, 0
        for child, count in edges.get(node, {}).items():
            if child in trail or child in cyclic:
                continue
            child_depth, child_total = measure(child, trail | {child})
            depth = max(depth, child_depth + 1)
            total += count * (1 + child_total)
        memo[node] = (depth, min(total, 10 ** 12))
        return memo[node]

    # Elaboration: parameter defaults and overrides, generate loops and conditions.
    from .hdl_elaboration import Elaborator

    parameters = {
        name.lower(): [item for item in values.get("parameters") or [] if isinstance(item, list) and len(item) == 3]
        for name, _, values in _fact_rows(db, "hdl_parameters")
    }
    languages = {
        name.lower(): "vhdl" if str(values.get("language", "")).upper() == "VHDL" else "verilog"
        for name, _, values in _fact_rows(db, "hdl_module")
    }
    sites: dict[str, list] = defaultdict(list)
    site_counts: dict[str, Counter] = defaultdict(Counter)
    for child, _, values in _fact_rows(db, "hdl_generate"):
        parent = str(values.get("parent", "")).lower()
        constructs = [item for item in values.get("constructs") or [] if isinstance(item, list) and item]
        array = values.get("array")
        sites[parent].append((child.lower(), constructs, values.get("overrides"), array if isinstance(array, str) else None))
        site_counts[parent][child.lower()] += 1
    plain = {
        parent: Counter({child: max(0, count - site_counts[parent][child]) for child, count in children.items()})
        for parent, children in edges.items()
    }
    elaborator = Elaborator(set(modules), plain, sites, parameters, languages) if sites else None

    top_details = []
    for key in tops[:MAX_LISTED]:
        depth, lexical = measure(key, frozenset({key}))
        if elaborator is None:
            top_details.append((modules[key][0], modules[key][1], depth, lexical, lexical, True))
            continue
        elaborated = elaborator.top(key)
        top_details.append((modules[key][0], modules[key][1], elaborated["depth"], elaborated["instances"],
                            lexical, elaborated["complete"]))
    top_details.sort(key=lambda item: (-item[3], item[0]))
    partial = [name for name, _, _, _, _, complete in top_details if not complete]
    clocks = sum(1 for _ in _fact_rows(db, "hdl_clock_constraint"))
    parts = sorted({(name, str(values.get("family", ""))) for name, _, values in _fact_rows(db, "fpga_part")})
    testbenches = sum(1 for _, _, testbench, _ in modules.values() if testbench)
    value = {
        "units": len(modules), "testbenches": testbenches,
        "tops": [
            {"name": name, "path": path, "depth": depth, "instances": total, "lexical_instances": lexical,
             "elaboration": "complete" if complete else "partial"}
            for name, path, depth, total, lexical, complete in top_details
        ],
        "generate_sites": sum(len(items) for items in sites.values()),
        "unelaborated": {} if elaborator is None else {
            "reasons": dict(sorted(elaborator.reasons.items(), key=lambda item: -item[1])[:10]),
            "samples": elaborator.samples[:10],
        },
        "unresolved_types": dict(unresolved.most_common(50)), "cycles": [component[:10] for component in cycles[:10]],
        "clock_constraints": clocks, "fpga_parts": [{"part": part, "family": family} for part, family in parts],
    }
    detail = (f"{len(modules):,} design unit(s) ({testbenches:,} testbench(es)); {len(tops):,} top-level unit(s): "
              + ", ".join(
                  f"{name} (depth {depth}, {total:,} instances" + (f"; {lexical:,} as written" if lexical != total else "")
                  + ")" for name, _, depth, total, lexical, _ in top_details[:10])
              + "." + (" Instance counts are elaborated: parameter defaults and overrides, generate loops and "
                       "conditions." if elaborator is not None else "")
              + (" Elaboration was partial for " + ", ".join(partial[:10]) + " (an expression, loop or construct "
                 "that could not be evaluated keeps its written count; see metrics.code_index.hdl.unelaborated)."
                 if partial else "")
              + (" Unresolved instance types (vendor primitives or IP not in the scan): "
                       + ", ".join(f"{name} ({count})" for name, count in unresolved.most_common(15)) + "."
                       if unresolved else "")
              + (" Targets: " + ", ".join(f"{part} ({family})" if family else part for part, family in parts[:8]) + "."
                 if parts else ""))
    findings = [Finding("hardware_description", "HDL design hierarchy", detail, confidence="INFERRED",
                        analyzer="code-index", evidence=[f"{path}: {name}" for name, path, *_ in top_details[:15]])]
    if cycles:
        findings.append(Finding(
            "hardware_description", "Recursive module instantiation",
            f"{len(cycles)} group(s) of design units instantiate each other; synthesis rejects recursion that is not "
            "bounded by a generate condition.", confidence="INFERRED", analyzer="code-index", severity="LOW",
            evidence=[" -> ".join(modules[node][0] for node in component[:8]) for component in cycles[:10]],
        ))
    return value, findings


def _shader_inventory(context: _Context) -> tuple[dict, list[Finding]]:
    languages: Counter = Counter()
    stages: Counter = Counter()
    entries = bindings = 0
    for language, _, values in _fact_rows(context.db, "shader"):
        languages[language] += 1
        for stage in str(values.get("stage", "")).split(","):
            if stage:
                stages[stage] += 1
        entries += int(values.get("entries", 0) or 0)
        bindings += int(values.get("bindings", 0) or 0)
    if not languages:
        return {}, []
    value = {"files": dict(languages.most_common()), "stages": dict(stages.most_common()), "entry_points": entries,
             "bindings": bindings}
    return value, [Finding(
        "graphics_shaders", "Shader inventory",
        f"{sum(languages.values()):,} shader file(s): " + ", ".join(f"{count:,} {name}" for name, count in languages.most_common())
        + "; stages " + ", ".join(f"{name} {count:,}" for name, count in stages.most_common(12))
        + f"; {entries:,} entry point(s), {bindings:,} resource binding(s).",
        confidence="CONFIRMED", analyzer="code-index",
    )]


_ROOT_COMPONENTS = frozenset({"App", "Root", "Layout", "RootLayout", "Page", "Document", "Error", "NotFound",
                              "Main", "AppComponent", "Home", "Index"})
_FILE_ROUTERS = {"Next.js": "Next.js", "Next.js API": "Next.js", "Nuxt": "Nuxt", "SvelteKit": "SvelteKit",
                 "SvelteKit API": "SvelteKit", "Remix": "Remix", "Astro": "Astro"}


def _component_graph(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    components: dict[str, tuple[str, str, str]] = {}
    for name, path, values in _fact_rows(db, "component"):
        components.setdefault(name, (str(values.get("framework", "")), path, str(values.get("selector", "") or "")))
    selectors = {selector: name for name, (_, _, selector) in components.items() if selector}
    by_stem = {PurePosixPath(path.replace("\\", "/")).name.split(".")[0]: name
               for name, (framework, path, _) in components.items() if framework == "Angular"}
    edges: dict[str, Counter] = defaultdict(Counter)
    used: Counter = Counter()
    for child, _, values in _fact_rows(db, "component_child"):
        parent = str(values.get("parent", ""))
        if parent.startswith("template:"):
            parent = by_stem.get(parent[9:], parent)
        target = selectors.get(child, child) if values.get("selector") else child
        if target in components and target != parent:
            count = int(values.get("count", 1) or 1)
            edges[parent][target] += count
            used[target] += count
    libraries: dict[str, Counter] = defaultdict(Counter)
    for name, _, values in _fact_rows(db, "frontend_library"):
        libraries[str(values.get("kind", "other"))][name] += 1
    tools = Counter(name for name, _, _ in _fact_rows(db, "frontend_tool"))
    frameworks = set(libraries.get("framework", {})) | set(tools)
    routes: dict[str, set[str]] = defaultdict(set)
    for route, _, values in _fact_rows(db, "route"):
        routes[str(values.get("framework", ""))].add(route)
    routed_files = set()
    for route, path, values in _fact_rows(db, "route_file"):
        framework = str(values.get("framework", ""))
        if _FILE_ROUTERS.get(framework) in frameworks:
            routes[framework].add(route)
            routed_files.add(path)
    if not (components or routes or libraries or tools):
        return {}, []
    routed_components = {name for name, (_, path, _) in components.items() if path in routed_files}
    unused = sorted(name for name in components if not used[name] and name not in _ROOT_COMPONENTS
                    and name not in routed_components and "/" not in name)
    roots = sorted(name for name in components if not used[name] and edges.get(name))
    value = {
        "components": len(components),
        "by_framework": dict(Counter(framework for framework, _, _ in components.values()).most_common()),
        "edges": sum(len(children) for children in edges.values()), "roots": roots[:MAX_LISTED],
        "most_used": [{"name": name, "uses": count} for name, count in used.most_common(20)],
        "unused_candidates": unused[:MAX_LISTED],
        "routes": {framework: sorted(paths)[:200] for framework, paths in sorted(routes.items())},
        "libraries": {kind: dict(counter.most_common()) for kind, counter in sorted(libraries.items())},
        "tools": dict(tools.most_common()),
    }
    findings = []
    if components:
        findings.append(Finding(
            "frontend", "Component graph",
            f"{len(components):,} component(s) (" + ", ".join(f"{count:,} {name or 'unknown'}" for name, count in
                                                         value["by_framework"].items())
            + f"); {value['edges']:,} parent-child edge(s); roots: {', '.join(roots[:10]) or 'none'}; most reused: "
            + (", ".join(f"{name} ({count})" for name, count in used.most_common(8)) or "none") + ".",
            confidence="INFERRED", analyzer="code-index",
        ))
    if unused and len(components) > 3:
        findings.append(Finding(
            "frontend", "Components never rendered",
            f"{len(unused):,} component(s) are not rendered by any scanned component or route: "
            + ", ".join(unused[:30]) + ". Dynamic imports, string-based registration and external consumers are not "
            "visible, so confirm before removing them.", confidence="INFERRED", analyzer="code-index",
        ))
    if routes:
        findings.append(Finding(
            "frontend", "Application routes",
            "; ".join(f"{framework}: {len(paths):,} route(s) ({', '.join(sorted(paths)[:12])})"
                      for framework, paths in sorted(routes.items())) + ".",
            confidence="INFERRED", analyzer="code-index",
        ))
    if libraries or tools:
        findings.append(Finding(
            "frontend", "Frontend stack",
            "; ".join(f"{kind}: " + ", ".join(f"{name} ({count} file(s))" for name, count in counter.most_common(6))
                      for kind, counter in sorted(libraries.items()))
            + (("; build tools: " + ", ".join(sorted(tools))) if tools else "") + ".",
            confidence="CONFIRMED", analyzer="code-index",
        ))
    return value, findings


MAX_RESOLVED_PACKAGES = 50_000


def _dependencies(context: _Context) -> tuple[dict, list[Finding]]:
    """Resolved package versions per lockfile, for comparing projects (``pdt compare``)."""
    lockfiles: dict[str, dict] = {}
    total = kept = 0
    for name, path, values in _fact_rows(context.db, "resolved_package"):
        total += 1
        if kept >= MAX_RESOLVED_PACKAGES:
            continue
        entry = lockfiles.setdefault(path, {"ecosystem": str(values.get("ecosystem", "")), "packages": {}})
        versions = entry["packages"].setdefault(name, [])
        version = str(values.get("version", ""))
        if version not in versions:
            versions.append(version)
            kept += 1
    partial = {path: int(values.get("omitted", 0)) for _, path, values in _fact_rows(context.db, "resolved_packages_truncated")}
    for path, omitted in partial.items():
        lockfiles.setdefault(path, {"ecosystem": "", "packages": {}})["omitted"] = omitted
    return {
        "lockfiles": dict(sorted(lockfiles.items())),
        # Entries left out at the scan-wide cap; per-lockfile omissions are under "omitted".
        "truncated": max(0, total - kept) if kept >= MAX_RESOLVED_PACKAGES else 0,
    }, []


MAX_ENDPOINT_ROUTES = 20_000
MAX_MOUNT_DEPTH = 8
_JS_ROUTE_EXTENSIONS = ("", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts", "/index.mjs")


def _js_target(importer: str, spec: str, paths: set[str]) -> str | None:
    """The scanned file a relative import specifier names, from the importing file."""
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
    return next((base + extension for extension in _JS_ROUTE_EXTENSIONS if base + extension in paths), None)


def _endpoint_routes(context: _Context) -> tuple[dict, list[Finding]]:
    """Served routes with the prefixes of routers mounted from other files: Django
    ``include("app.urls")``, FastAPI ``include_router`` and Flask ``register_blueprint`` of an
    imported router, aiohttp ``add_subapp``, and Express, Koa and Hono ``use()`` of a router
    imported from another module. A mounting file mounted in turn adds its own prefix."""
    from ..analyzers.api.route_structure import join_path

    db = context.db
    routes: list[dict] = []
    total = 0
    for name, path, values in _fact_rows(db, "api_endpoint", ordered=True):
        total += 1
        if len(routes) < MAX_ENDPOINT_ROUTES:
            method, _, route = name.partition(" ")
            routes.append({"method": method, "path": route, "file": path, "line": values.get("line"),
                           "framework": str(values.get("framework", "")), "receiver": str(values.get("receiver", "")),
                           "handler": str(values.get("handler", ""))})
    modules: dict[str, str] = {}
    for path, module in db.execute("SELECT path, module FROM files WHERE module IS NOT NULL ORDER BY path"):
        modules.setdefault(module, path)
    module_of = {path: module for module, path in modules.items()}
    paths = {row[0] for row in db.execute("SELECT path FROM files")}
    # (target file, router variable or "" for the whole file) -> (mounting file, its router, prefix)
    targets: dict[tuple[str, str], tuple[str, str, str]] = {}
    resolved_mounts: list[dict] = []
    unresolved: list[dict] = []
    for prefix, path, values in _fact_rows(db, "api_mount", ordered=True):
        if values.get("kind") == "js":
            spec = str(values.get("spec", ""))
            target, receiver, label = _js_target(path.replace("\\", "/"), spec, paths), "", spec
        else:
            written, level = str(values.get("target_module", "")), int(values.get("level", 0) or 0)
            module = written
            if level:
                importer = module_of.get(path, "")
                package = importer if path.endswith("__init__.py") else importer.rpartition(".")[0]
                try:
                    module = resolve_name("." * level + written, package) if importer else ""
                except (ImportError, ValueError):
                    module = ""
            receiver = str(values.get("target_name", ""))
            target = modules.get(module)
            label = "." * level + written + (f".{receiver}" if receiver else "")
        entry = {"file": path, "prefix": prefix, "target": label}
        if target is None:
            if len(unresolved) < MAX_LISTED:
                unresolved.append(entry)
            continue
        targets.setdefault((target, receiver), (path, str(values.get("receiver", "")), prefix))
        if len(resolved_mounts) < MAX_INTEGRATION_ITEMS:
            resolved_mounts.append({**entry, "resolved": target})

    def prefix_of(path: str, receiver: str, depth: int = 0) -> str:
        mount = targets.get((path, receiver)) or targets.get((path, ""))
        if mount is None or depth >= MAX_MOUNT_DEPTH:
            return ""
        outer = prefix_of(mount[0], mount[1], depth + 1)
        return join_path([outer, mount[2]]) if outer.strip("/") else mount[2]

    mounted = []
    for route in routes:
        prefix = prefix_of(route["file"], route["receiver"])
        if prefix.strip("/"):
            route["path"] = join_path([prefix, route["path"]])
            route["mounted_at"] = prefix
            mounted.append(route)
    context.endpoint_routes = routes
    value = {
        "routes": mounted[:MAX_INTEGRATION_ITEMS], "mounts": resolved_mounts, "unresolved_mounts": unresolved,
        "route_count": total, "truncated": max(0, total - len(routes)),
    }
    if not mounted:
        return value, []
    files = {route["file"] for route in mounted}
    return value, [Finding(
        "api", "Routes mounted from other files",
        f"{len(mounted):,} route(s) in {len(files):,} file(s) take the prefix of a router mounted in another file "
        "(Django include, FastAPI include_router, Flask register_blueprint, aiohttp add_subapp, Express use). "
        "Their full paths feed the integration summary.",
        confidence="INFERRED", analyzer="code-index",
        evidence=[f"{route['file']}:{route['line']} {route['method']} {route['path']}" for route in mounted[:MAX_LISTED]],
    )]


MAX_GRAPHQL_ITEMS = 5000
_GRAPHQL_ROOTS = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}


def _graphql(context: _Context) -> tuple[dict, list[Finding]]:
    """GraphQL across the scan: the root fields schemas declare, the resolvers code declares
    and the root fields client operations call, matched by type and field name."""
    db = context.db
    fields: dict[str, dict] = {}  # "Query.user" -> where a schema declares it
    for name, path, values in _fact_rows(db, "graphql_field", ordered=True):
        if name in fields or len(fields) < MAX_GRAPHQL_ITEMS:
            fields.setdefault(name, {"kind": str(values.get("kind", "")), "file": path, "line": values.get("line")})
    resolvers: dict[str, list[dict]] = defaultdict(list)
    for name, path, values in _fact_rows(db, "graphql_resolver", ordered=True):
        if (name in resolvers or len(resolvers) < MAX_GRAPHQL_ITEMS) and len(resolvers[name]) < 5:
            resolvers[name].append({"file": path, "line": values.get("line"), "framework": str(values.get("framework", ""))})
    operations: list[dict] = []
    for name, path, values in _fact_rows(db, "graphql_operation", ordered=True):
        if len(operations) < MAX_GRAPHQL_ITEMS:
            kind, _, operation = name.partition(" ")
            called = values.get("fields")
            operations.append({"kind": kind, "name": operation, "file": path, "line": values.get("line"),
                               "fields": [str(item) for item in called] if isinstance(called, list) else []})
    entities = [{"name": name, "file": path, "keys": values.get("keys", [])}
                for name, path, values in itertools.islice(_fact_rows(db, "graphql_entity", ordered=True), MAX_GRAPHQL_ITEMS)]
    value = {"schema_fields": len(fields), "resolvers": sum(len(items) for items in resolvers.values()),
             "operations": len(operations), "entities": entities}
    if not (fields or resolvers or operations):
        return value, []
    schema_roots = {name.split(".", 1)[0] for name in fields}
    resolver_roots = {name.split(".", 1)[0] for name in resolvers}
    # A schema field no resolver answers, on a root type the scan has resolvers for (with none
    # at all, the resolvers are not in the scan or come from a framework not recognized).
    unresolved = [name for name in sorted(fields) if name.split(".", 1)[0] in resolver_roots and name not in resolvers]
    # A resolver for a root field no schema declares, on a root type the scan has a schema for
    # (code-first frameworks have no schema file, so their resolvers are not compared).
    orphans = [name for name in sorted(resolvers) if name.split(".", 1)[0] in schema_roots & set(_GRAPHQL_ROOTS.values())
               and name not in fields]
    # Client operations calling root fields the scan's schemas do not declare.
    unknown = []
    for operation in operations:
        root = _GRAPHQL_ROOTS.get(operation["kind"])
        absent = [item for item in operation["fields"] if root in schema_roots and f"{root}.{item}" not in fields
                  and not item.startswith("__")]
        if absent:
            unknown.append({**operation, "missing": absent})
    kinds = Counter(field["kind"] for field in fields.values())
    frameworks = Counter(item["framework"] for items in resolvers.values() for item in items)
    value.update({
        "fields": {kind: sorted(name.split(".", 1)[1] for name, field in fields.items() if field["kind"] == kind)[:MAX_LISTED * 10]
                   for kind in _GRAPHQL_ROOTS},
        "resolver_frameworks": dict(frameworks), "unresolved_fields": unresolved[:MAX_GRAPHQL_ITEMS],
        "orphan_resolvers": orphans[:MAX_GRAPHQL_ITEMS], "unknown_operation_fields": unknown[:MAX_LISTED * 10],
    })
    parts = []
    if fields:
        parts.append(f"{len(fields):,} root field(s) in schemas ("
                     + ", ".join(f"{kinds[kind]:,} {kind}" for kind in _GRAPHQL_ROOTS if kinds[kind]) + ")")
    if resolvers:
        parts.append(f"{value['resolvers']:,} resolver(s) in code (" + ", ".join(sorted(frameworks)) + ")")
    if operations:
        parts.append(f"{len(operations):,} client operation(s)")
    if entities:
        parts.append(f"{len(entities):,} federation entit(ies)")
    evidence = []
    for name in sorted(fields)[:MAX_LISTED]:
        field = fields[name]
        answered = resolvers.get(name, [])
        evidence.append(f"{name}: schema {field['file']}:{field['line']}" + (
            f"; resolver {answered[0]['file']}:{answered[0]['line']} ({answered[0]['framework']})" if answered else ""))
    findings = [Finding("api", "GraphQL API", "; ".join(parts) + ". Fields are matched by type and name across every "
                        "scanned file.", confidence="INFERRED", analyzer="code-index", evidence=evidence)]
    if unresolved:
        findings.append(Finding(
            "api", "GraphQL fields without a resolver",
            f"{len(unresolved):,} root field(s) a schema declares have no resolver in code, on root types that have "
            "resolvers: the field is unimplemented, answered by a default resolver, or implemented in code the "
            "scan does not recognize.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{name}: {fields[name]['file']}:{fields[name]['line']}" for name in unresolved[:MAX_LISTED]],
        ))
    if orphans:
        findings.append(Finding(
            "api", "GraphQL resolvers for fields no schema declares",
            f"{len(orphans):,} resolver(s) answer root fields the scan's schemas do not declare: a field removed from "
            "the schema, a misspelled name, or a schema built elsewhere.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{name}: {resolvers[name][0]['file']}:{resolvers[name][0]['line']}" for name in orphans[:MAX_LISTED]],
        ))
    if unknown:
        findings.append(Finding(
            "api", "GraphQL operations calling fields no schema declares",
            f"{len(unknown):,} client operation(s) select root fields the scan's schemas do not declare: they call "
            "another service's API, or the schema no longer has the field.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['file']}:{item['line']} {item['kind']} {item['name'] or '(anonymous)'}: "
                      f"{', '.join(item['missing'][:8])}" for item in unknown[:MAX_LISTED]],
        ))
    return value, findings


MAX_RPC_ITEMS = 5000
_RPC_UNSERVED = frozenset({"Avro IPC"})  # frameworks whose servers the scan does not look for


def _rpc_key(name: str) -> str:
    """The name RPC services are matched by: the last part, case-folded (``helloworld.Greeter``
    is ``greeter``; Kitex packages are lowercase)."""
    return name.rsplit(".", 1)[-1].casefold()


def _count(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _rpc(context: _Context) -> tuple[dict, list[Finding]]:
    """RPC across the scan: the services IDL files define, matched by name to the generated code,
    servers and clients code declares."""
    db = context.db
    services: dict[str, dict] = {}
    for name, path, values in _fact_rows(db, "rpc_service", ordered=True):
        if name not in services and len(services) < MAX_RPC_ITEMS:
            methods = values.get("methods")
            services[name] = {"name": name, "framework": str(values.get("framework", "")), "file": path,
                              "line": values.get("line"),
                              "methods": [str(item) for item in methods] if isinstance(methods, list) else []}
    streaming: Counter = Counter()
    mapped: list[dict] = []
    for name, path, values in _fact_rows(db, "rpc_method", ordered=True):
        streaming[str(values.get("streaming", ""))] += 1
        http = values.get("http")
        if isinstance(http, list) and http and len(mapped) < MAX_RPC_ITEMS:
            mapped.append({"method": name, "file": path, "line": values.get("line"), "http": [str(item) for item in http]})
    schemas = {"files": 0, "messages": 0, "enums": 0}
    for _, _, values in _fact_rows(db, "rpc_schema"):
        schemas["files"] += 1
        schemas["messages"] += _count(values.get("messages"))
        schemas["enums"] += _count(values.get("enums"))
    generators: Counter = Counter()
    generated: dict[str, list[dict]] = {}
    for name, path, values in _fact_rows(db, "rpc_generated", ordered=True):
        generators[name] += 1
        listed = values.get("services")
        for service in listed if isinstance(listed, list) else []:
            key = _rpc_key(str(service))
            if key in generated or len(generated) < MAX_RPC_ITEMS:
                items = generated.setdefault(key, [])
                if len(items) < 5:
                    items.append({"file": path, "generator": name})
    code: dict[str, dict[str, list[dict]]] = {"server": {}, "client": {}}
    frameworks: Counter = Counter()
    unnamed: Counter = Counter()  # frameworks whose servers and clients name no service (Dubbo, net/rpc, tRPC)
    for role in ("server", "client"):
        for _, path, values in _fact_rows(db, f"rpc_{role}", ordered=True):
            framework = str(values.get("framework", ""))
            frameworks[framework] += 1
            service = str(values.get("service", ""))
            if not service:
                unnamed[f"{framework} {role}"] += 1
                continue
            key = _rpc_key(service)
            if key in code[role] or len(code[role]) < MAX_RPC_ITEMS:
                items = code[role].setdefault(key, [])
                if len(items) < 5:
                    items.append({"service": service, "file": path, "line": values.get("line"), "framework": framework})
    procedures = Counter(str(values.get("role", "")).split(" ", 1)[0] for _, _, values in _fact_rows(db, "rpc_procedure"))
    value = {"service_total": len(services), "methods": sum(streaming.values()), "streaming": dict(streaming),
             "schemas": schemas, "generated_files": dict(generators), "frameworks": dict(frameworks),
             "procedures": dict(procedures)}
    if not (services or generators or frameworks or procedures):
        return value, []
    defined = {_rpc_key(name) for name in services}
    listed = [{**service, "generated": generated.get(_rpc_key(name), []), "servers": code["server"].get(_rpc_key(name), []),
               "clients": code["client"].get(_rpc_key(name), [])} for name, service in sorted(services.items())]
    # Services no server in the scan implements, when the scan has servers for others (with none at
    # all, the project only defines or calls them).
    unimplemented = [item for item in listed if code["server"] and not item["servers"]
                     and item["framework"] not in _RPC_UNSERVED]
    # Servers and clients of services no definition and no generated code in the scan declares:
    # the definition is outside the scan, or the code names the service differently.
    undeclared = [{"role": role, **items[0]} for role in ("server", "client") for key, items in sorted(code[role].items())
                  if services and key not in defined and key not in generated]
    value.update({
        "services": listed[:MAX_LISTED * 10], "http_mapped": mapped[:MAX_LISTED * 10],
        "unimplemented": [item["name"] for item in unimplemented][:MAX_RPC_ITEMS],
        "undeclared": undeclared[:MAX_RPC_ITEMS], "unnamed": dict(unnamed),
    })
    parts = []
    if services:
        by_framework = Counter(item["framework"] for item in services.values())
        parts.append(f"{len(services):,} service(s) defined (" + ", ".join(
            f"{count:,} {name}" for name, count in sorted(by_framework.items())) + ")" + (
            f" with {value['methods']:,} gRPC method(s): " + ", ".join(
                f"{count:,} {kind}" for kind, count in sorted(streaming.items(), key=lambda item: (-item[1], item[0])))
            if streaming else ""))
    if schemas["files"]:
        parts.append(f"{schemas['messages']:,} protobuf message(s) and {schemas['enums']:,} enum(s) in "
                     f"{schemas['files']:,} schema file(s)")
    if mapped:
        parts.append(f"{len(mapped):,} method(s) mapped to HTTP routes")
    if generators:
        parts.append(f"{sum(generators.values()):,} generated file(s) ({', '.join(sorted(generators))})")
    if frameworks:
        parts.append(f"servers for {len(code['server']):,} service(s) and clients for {len(code['client']):,} in code "
                     f"({', '.join(sorted(frameworks))})")
    if procedures:
        parts.append("tRPC procedures: " + ", ".join(f"{count:,} {kind}" for kind, count in sorted(procedures.items())))
    evidence = []
    for item in listed[:MAX_LISTED]:
        line = f"{item['name']} ({item['framework']}): defined {item['file']}:{item['line']}"
        if item["generated"]:
            line += f"; generated {item['generated'][0]['file']} ({item['generated'][0]['generator']})"
        for role in ("servers", "clients"):
            if item[role]:
                line += f"; {role[:-1]} {item[role][0]['file']}:{item[role][0]['line']} ({item[role][0]['framework']})"
        evidence.append(line)
    findings = [Finding("api", "RPC services", "; ".join(parts) + ". Services are matched to code by name across every "
                        "scanned file.", confidence="INFERRED", analyzer="code-index", evidence=evidence)]
    if unimplemented:
        findings.append(Finding(
            "api", "RPC services without a server",
            f"{len(unimplemented):,} service(s) a definition declares have no server in the scan, which has servers for "
            "other services: the service is implemented in another repository, not yet implemented, or registered in a "
            "form the scan does not recognize.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['name']}: {item['file']}:{item['line']}" for item in unimplemented[:MAX_LISTED]],
        ))
    if undeclared:
        findings.append(Finding(
            "api", "RPC servers and clients for services no definition declares",
            f"{len(undeclared):,} server(s) or client(s) use services that no definition or generated code in the scan "
            "declares: the definition lives in another repository or a dependency, or the service was renamed.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['file']}:{item['line']} {item['framework']} {item['role']} {item['service']}"
                      for item in undeclared[:MAX_LISTED]],
        ))
    return value, findings


MAX_PROTOCOL_ITEMS = 5000
MAX_TOPIC_COMPARISONS = 2_000_000
# Route paths that receive webhooks: /webhook, /webhooks/stripe, /hooks/github, /api/callback.
_WEBHOOK_ROUTE = re.compile(r"(?i)web-?hooks?|(?:^|/)(?:hooks?|callbacks?)(?:/|$)")
_TOPIC_PARAMETER = re.compile(r"\{[^{}/]{0,100}+\}|<[^<>/]{0,100}+>|(?<=/):[A-Za-z_]\w{0,60}+|(?<![^/])\+(?![^/])")


def _topic_levels(name: str) -> list[str]:
    """A channel, topic or queue name as matched across contracts and code, by level: parameters
    (``{id}``, ``<id>``, ``:id``) and MQTT's ``+`` are ``*``, a trailing MQTT ``#`` is ``**``."""
    levels = _TOPIC_PARAMETER.sub("*", name.strip()).split("/")
    if levels[-1] == "#":
        levels[-1] = "**"
    return levels


def _levels_match(left: list[str], right: list[str]) -> bool:
    """Whether two names cover each other, level by level (``*`` one level, ``**`` the rest)."""
    for index in range(max(len(left), len(right))):
        first = left[index] if index < len(left) else None
        second = right[index] if index < len(right) else None
        if first == "**" or second == "**":
            return True
        if first is None or second is None or (first != second and "*" not in (first, second)):
            return False
    return True


def _soap_key(name: str) -> str:
    """A SOAP operation's name as matched between WSDL and code: case-folded, without the
    ``Request`` of Spring-WS payload roots or the ``Async`` of .NET methods."""
    key = name.casefold()
    for suffix in ("request", "async"):
        if key.endswith(suffix) and len(key) > len(suffix):
            key = key[:-len(suffix)]
    return key


def _protocols(context: _Context) -> tuple[dict, list[Finding]]:
    """JSON-RPC, SOAP, WebSocket, SSE, webhook, MQTT and message-driven endpoints across the scan:
    AsyncAPI channels matched to the topics code sends and receives, OpenRPC methods to the
    methods JSON-RPC servers register, and webhook routes to the signature checks in their files."""
    db = context.db
    endpoints: list[dict] = []
    counts: dict[str, Counter] = defaultdict(Counter)
    frameworks: dict[str, set[str]] = defaultdict(set)
    for _, path, values in _fact_rows(db, "protocol_endpoint", ordered=True):
        protocol, role = str(values.get("protocol", "")), str(values.get("role", ""))
        counts[protocol][role] += 1
        frameworks[protocol].add(str(values.get("framework", "")))
        if len(endpoints) < MAX_PROTOCOL_ITEMS:
            endpoints.append({"protocol": protocol, "role": role, "what": str(values.get("what", "")),
                              "name": str(values.get("target", "")), "framework": str(values.get("framework", "")),
                              "file": path, "line": values.get("line"),
                              **({"qos": str(values["qos"])} if values.get("qos") else {})})
    channels = [{"address": name, "file": path, "actions": values.get("actions", []),
                 "messages": values.get("messages", []), "protocols": values.get("protocols", [])}
                for name, path, values in itertools.islice(_fact_rows(db, "async_channel", ordered=True), MAX_PROTOCOL_ITEMS)]
    contract_methods: dict[str, str] = {}
    for name, path, _ in _fact_rows(db, "jsonrpc_method", ordered=True):
        if name not in contract_methods and len(contract_methods) < MAX_PROTOCOL_ITEMS:
            contract_methods[name] = path
    sent = [{"name": name, "file": path, "methods": values.get("methods", [])}
            for name, path, values in itertools.islice(_fact_rows(db, "webhook_contract", ordered=True), MAX_PROTOCOL_ITEMS)]
    wsdl: dict[str, tuple[str, str]] = {}  # matching key -> (operation, file)
    for name, path, _ in _fact_rows(db, "wsdl_operation", ordered=True):
        if len(wsdl) < MAX_PROTOCOL_ITEMS:
            wsdl.setdefault(_soap_key(name), (name, path))
    value = {"counts": {protocol: dict(roles) for protocol, roles in sorted(counts.items())},
             "frameworks": {protocol: sorted(names) for protocol, names in sorted(frameworks.items())},
             "asyncapi_channels": len(channels), "openrpc_methods": len(contract_methods), "openapi_webhooks": len(sent),
             "wsdl_operations": len(wsdl)}
    if not (endpoints or channels or contract_methods or sent or wsdl):
        return value, []
    # The topics, queues and channels code uses: this pass's message and MQTT endpoints and the
    # integration analyzer's topics.
    topics: dict[str, dict] = {}
    for item in endpoints:
        if item["protocol"] in {"MQTT", "Messaging"} and item["role"] in {"consume", "produce"} and item["name"]:
            topics.setdefault(item["name"], item)
    for name, path, values in _fact_rows(db, "message_topic", ordered=True):
        if name not in topics and len(topics) < MAX_PROTOCOL_ITEMS:
            topics[name] = {"name": name, "file": path, "line": None, "role": str(values.get("role", "")),
                            "framework": str(values.get("system", ""))}
    unused: list[dict] = []
    undeclared: list[dict] = []
    partial = False
    if channels and topics:
        topic_levels = [(_topic_levels(name), name) for name in topics]
        by_name: dict[str, list[str]] = defaultdict(list)
        for levels, name in topic_levels:
            by_name["/".join(levels)].append(name)
        wild_topics = [(levels, name) for levels, name in topic_levels if {"*", "**"} & set(levels)]
        used: set[str] = set()
        comparisons = 0
        for channel in channels:
            levels = _topic_levels(channel["address"])
            hits = list(by_name.get("/".join(levels), []))
            candidates = topic_levels if {"*", "**"} & set(levels) else wild_topics
            if comparisons + len(candidates) > MAX_TOPIC_COMPARISONS:
                partial = True
            else:
                comparisons += len(candidates)
                hits += [name for other, name in candidates if _levels_match(levels, other)]
            used.update(hits)
            if not hits:
                unused.append(channel)
        undeclared = [topics[name] for name in sorted(topics) if name not in used]
        if partial:  # unmatched wildcard comparisons would read as unused channels and undeclared topics
            unused, undeclared = [], []
    servers = {item["name"]: item for item in endpoints
               if item["protocol"] == "JSON-RPC" and item["role"] == "server" and item["what"] == "method" and item["name"]}
    unimplemented = sorted(name for name in contract_methods if servers and name not in servers)
    undocumented = sorted(name for name in servers if contract_methods and name not in contract_methods)
    operations = {}
    for item in endpoints:
        if item["protocol"] == "SOAP" and item["role"] == "server" and item["what"] == "operation" and item["name"]:
            operations.setdefault(_soap_key(item["name"]), item)
    soap_unimplemented = [wsdl[key] for key in sorted(wsdl) if operations and key not in operations]
    soap_undeclared = [operations[key] for key in sorted(operations) if wsdl and key not in wsdl]
    # Webhook routes (the endpoints pass's routes with mounts resolved, or the routes as declared)
    # and the files that check a provider's signature.
    verified = {item["file"] for item in endpoints if item["protocol"] == "Webhook" and item["role"] == "server"}
    served = context.endpoint_routes if context.endpoint_routes is not None else [
        {"method": name.partition(" ")[0], "path": name.partition(" ")[2], "file": path, "line": values.get("line")}
        for name, path, values in _fact_rows(db, "api_endpoint", ordered=True)]
    routes = [item for item in served if _WEBHOOK_ROUTE.search(str(item.get("path", "")))
              and str(item.get("method", "")).upper() in {"POST", "PUT", "ANY", "*", "ALL"}][:MAX_PROTOCOL_ITEMS]
    unverified = [item for item in routes if item["file"] not in verified]
    value.update({
        "endpoints": endpoints[:MAX_LISTED * 10],
        "unused_channels": [{"address": item["address"], "file": item["file"]} for item in unused[:MAX_PROTOCOL_ITEMS]],
        "undeclared_topics": [{"name": item["name"], "role": item["role"], "file": item["file"]}
                              for item in undeclared[:MAX_PROTOCOL_ITEMS]],
        "topic_matching": "partial" if partial else "complete",
        "unimplemented_methods": unimplemented[:MAX_PROTOCOL_ITEMS], "undocumented_methods": undocumented[:MAX_PROTOCOL_ITEMS],
        "unimplemented_operations": [{"operation": name, "file": path} for name, path in soap_unimplemented],
        "undeclared_operations": [{"operation": item["name"], "file": item["file"], "line": item["line"]}
                                  for item in soap_undeclared],
        "webhook_routes": [{"method": item["method"], "path": item["path"], "file": item["file"],
                            "verified": item["file"] in verified} for item in routes[:MAX_LISTED * 10]],
        "webhooks_sent": sent[:MAX_LISTED * 10],
    })
    parts = [f"{protocol}: " + ", ".join(f"{count:,} {role}" for role, count in sorted(roles.items()))
             + f" ({', '.join(sorted(frameworks[protocol])[:6])})" for protocol, roles in sorted(counts.items())]
    if channels:
        parts.append(f"{len(channels):,} AsyncAPI channel(s)")
    if contract_methods:
        parts.append(f"{len(contract_methods):,} OpenRPC method(s)")
    if sent:
        parts.append(f"{len(sent):,} webhook(s) OpenAPI documents send")
    if wsdl:
        parts.append(f"{len(wsdl):,} WSDL operation(s)")
    if routes:
        parts.append(f"{len(routes):,} webhook route(s), {len(routes) - len(unverified):,} in files that check a signature")
    findings = [Finding(
        "api", "Protocol endpoints", "; ".join(parts) + ". Declarations, not proof that an endpoint is deployed or "
        "reachable.", confidence="INFERRED", analyzer="code-index",
        evidence=[f"{item['protocol']} {item['role']} {item['what']}" + (f" {item['name']}" if item["name"] else "")
                  + f": {item['file']}" + (f":{item['line']}" if item["line"] else "") + f" ({item['framework']})"
                  for item in endpoints[:MAX_LISTED]],
    )]
    if unused:
        findings.append(Finding(
            "api", "AsyncAPI channels no code uses",
            f"{len(unused):,} channel(s) AsyncAPI documents declare match no topic, queue or channel the scanned code "
            "sends to or receives from (parameters and MQTT wildcards are matched by level): another service "
            "implements them, or the code uses names the scan cannot read.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['address']}: {item['file']}" for item in unused[:MAX_LISTED]],
        ))
    if undeclared:
        findings.append(Finding(
            "api", "Topics no AsyncAPI document declares",
            f"{len(undeclared):,} topic(s), queue(s) or channel(s) code uses are declared by none of the scan's AsyncAPI "
            "documents: the contract is incomplete, or they belong to another service's contract.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['name']} ({item['role'] or 'used'}): {item['file']}" for item in undeclared[:MAX_LISTED]],
        ))
    if unimplemented:
        findings.append(Finding(
            "api", "OpenRPC methods no JSON-RPC server registers",
            f"{len(unimplemented):,} method(s) OpenRPC documents declare are registered by none of the scan's JSON-RPC "
            "servers, which register others: unimplemented, or registered in a form the scan does not recognize.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{name}: {contract_methods[name]}" for name in unimplemented[:MAX_LISTED]],
        ))
    if undocumented:
        findings.append(Finding(
            "api", "JSON-RPC methods no OpenRPC document declares",
            f"{len(undocumented):,} method(s) JSON-RPC servers register are missing from the scan's OpenRPC documents.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{name}: {servers[name]['file']}:{servers[name]['line']}" for name in undocumented[:MAX_LISTED]],
        ))
    if soap_unimplemented:
        findings.append(Finding(
            "api", "WSDL operations no SOAP server implements",
            f"{len(soap_unimplemented):,} operation(s) WSDL documents declare are implemented by none of the scan's SOAP "
            "services, which implement others (names are compared case-folded, without Request and Async): another "
            "service implements them, or the code names them differently.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{name}: {path}" for name, path in soap_unimplemented[:MAX_LISTED]],
        ))
    if soap_undeclared:
        findings.append(Finding(
            "api", "SOAP operations no WSDL declares",
            f"{len(soap_undeclared):,} operation(s) SOAP services implement are missing from the scan's WSDL documents.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['name']}: {item['file']}:{item['line']}" for item in soap_undeclared[:MAX_LISTED]],
        ))
    if unverified:
        findings.append(Finding(
            "api", "Webhook routes without a signature check in their file",
            f"{len(unverified):,} route(s) that look like webhook receivers are in files where no provider signature "
            "check was found. The check may be in middleware or another module; without one, anyone who knows the "
            "URL can send forged events.",
            confidence="INFERRED", severity="LOW", analyzer="code-index",
            evidence=[f"{item['method']} {item['path']}: {item['file']}" for item in unverified[:MAX_LISTED]],
        ))
    return value, findings


MAX_CONTRACT_LINK_ITEMS = 5000


def _contract_links(context: _Context) -> tuple[dict, list[Finding]]:
    """OpenAPI operations cross-referenced with the routes that serve them, the generated clients
    that call them and the HTTP calls code makes, by method and path template."""
    from ..analyzers.api.integration import EndpointIndex, normalize_route

    db = context.db
    operations: dict[tuple[str, str], dict] = {}
    for name, path, values in _fact_rows(db, "openapi_operation", ordered=True):
        method, _, route = name.partition(" ")
        base = str(values.get("base", "") or "")
        for template in dict.fromkeys((normalize_route(route), normalize_route(base + route) if base else "")):
            if template and (method, template) not in operations and len(operations) < MAX_CONTRACT_LINK_ITEMS:
                operations[(method, template)] = {
                    "method": method, "path": route, "operation_id": str(values.get("operation_id", "")), "file": path,
                    "routes": [], "clients": [], "calls": 0}
    served = context.endpoint_routes if context.endpoint_routes is not None else [
        {"method": name.partition(" ")[0], "path": name.partition(" ")[2], "file": path, "line": values.get("line"),
         "framework": str(values.get("framework", ""))} for name, path, values in _fact_rows(db, "api_endpoint", ordered=True)]
    clients: dict[str, dict] = {}
    for name, path, _ in _fact_rows(db, "api_client", ordered=True):
        if len(clients) < MAX_CONTRACT_LINK_ITEMS:
            clients.setdefault(path, {"file": path, "generator": name, "operations": 0, "matched": 0, "unmatched": []})
    value = {"operations": len({(item["method"], item["path"], item["file"]) for item in operations.values()}),
             "routes": len(served), "generated_clients": len(clients)}
    if not operations and not clients:
        return value, []
    index = EndpointIndex(operations)
    undeclared = []
    contract_files_served: set[str] = set()
    for route in served:
        hit = index.match(str(route.get("method", "")), normalize_route(str(route.get("path", ""))))
        if hit is None:
            undeclared.append(route)
            continue
        operation = operations[(hit[0], hit[1])]
        contract_files_served.add(operation["file"])
        context.route_contracts = context.route_contracts or {}
        context.route_contracts[(route["file"], route.get("line"), route.get("method"))] = \
            f"{operation['operation_id'] or operation['method'] + ' ' + operation['path']} ({operation['file']})"
        if len(operation["routes"]) < 5:
            operation["routes"].append({"method": route.get("method"), "path": route.get("path"), "file": route["file"],
                                        "line": route.get("line"), "framework": route.get("framework", ""),
                                        "match": hit[2]})
    for name, path, values in _fact_rows(db, "api_client_operation", ordered=True):
        method, _, route = name.partition(" ")
        client = clients.setdefault(path, {"file": path, "generator": str(values.get("generator", "")), "operations": 0,
                                           "matched": 0, "unmatched": []})
        client["operations"] += 1
        hit = index.match("" if method == "?" else method, normalize_route(route))
        if hit is None:
            if len(client["unmatched"]) < MAX_LISTED:
                client["unmatched"].append({"method": method, "path": route, "line": values.get("line")})
            continue
        client["matched"] += 1
        operation = operations[(hit[0], hit[1])]
        if path not in operation["clients"] and len(operation["clients"]) < 5:
            operation["clients"].append(path)
    calls = 0
    for name, _, _ in itertools.islice(_fact_rows(db, "http_call"), MAX_CONTRACT_LINK_ITEMS * 10):
        method, _, route = name.partition(" ")
        hit = index.match(method, route)
        if hit is not None:
            operations[(hit[0], hit[1])]["calls"] += 1
            calls += 1
    # Each operation once: an operation indexed with and without its base path is merged.
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for item in operations.values():
        groups[(item["method"], item["path"], item["file"])].append(item)
    listed = []
    for item, *twins in groups.values():
        for twin in twins:
            item["routes"] += [route for route in twin["routes"] if route not in item["routes"]][:max(0, 5 - len(item["routes"]))]
            item["clients"] += [client for client in twin["clients"] if client not in item["clients"]][
                :max(0, 5 - len(item["clients"]))]
            item["calls"] += twin["calls"]
        listed.append(item)
    # Operations no route serves, in contracts the scan serves other operations of (a contract of
    # an API the project only calls is not compared).
    unimplemented = [item for item in listed if item["file"] in contract_files_served and not item["routes"]]
    # Routes no contract declares, when the scan serves a contract.
    undeclared = undeclared[:MAX_CONTRACT_LINK_ITEMS] if contract_files_served else []
    # Generated clients' operations no contract declares, for clients generated from a scanned contract.
    stale = [client for client in clients.values() if client["matched"] and client["unmatched"]]
    value.update({
        "implemented": sum(1 for item in listed if item["routes"]),
        "called_by_clients": sum(1 for item in listed if item["clients"]), "calls_matched": calls,
        "links": [{key: item[key] for key in ("method", "path", "operation_id", "file", "routes", "clients", "calls")}
                  for item in listed[:MAX_LISTED * 10]],
        "unimplemented": [{"method": item["method"], "path": item["path"], "operation_id": item["operation_id"],
                           "file": item["file"]} for item in unimplemented[:MAX_CONTRACT_LINK_ITEMS]],
        "undeclared_routes": [{"method": item.get("method"), "path": item.get("path"), "file": item["file"],
                               "line": item.get("line")} for item in undeclared],
        "clients": sorted(clients.values(), key=lambda client: client["file"])[:MAX_LISTED * 10],
    })
    parts = []
    if listed:
        parts.append(f"{len(listed):,} contract operation(s), {value['implemented']:,} served by routes in code")
    if clients:
        parts.append(f"{len(clients):,} generated client(s) ({', '.join(sorted({client['generator'] for client in clients.values()}))}) "
                     f"calling {value['called_by_clients']:,} contract operation(s)")
    if calls:
        parts.append(f"{calls:,} HTTP call site(s) matching contract operations")
    evidence = []
    for item in listed[:MAX_LISTED]:
        line = f"{item['method']} {item['path']}" + (f" ({item['operation_id']})" if item["operation_id"] else "") \
            + f": {item['file']}"
        if item["routes"]:
            route = item["routes"][0]
            line += f"; route {route['file']}" + (f":{route['line']}" if route["line"] else "") \
                + (f" ({route['framework']})" if route["framework"] else "")
        if item["clients"]:
            line += f"; client {item['clients'][0]}"
        evidence.append(line)
    findings = [Finding("api", "API contracts and code", "; ".join(parts) + ". Operations are matched by method and "
                        "path template, with base paths and mount prefixes.", confidence="INFERRED", analyzer="code-index",
                        evidence=evidence or [client["file"] for client in list(clients.values())[:MAX_LISTED]])]
    if unimplemented:
        findings.append(Finding(
            "api", "Contract operations no route serves",
            f"{len(unimplemented):,} operation(s) of contracts whose other operations the scan serves have no route in "
            "code: not implemented yet, served by another service, or declared in a form the scan does not read.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item['method']} {item['path']}" + (f" ({item['operation_id']})" if item["operation_id"] else "")
                      + f": {item['file']}" for item in unimplemented[:MAX_LISTED]],
        ))
    if undeclared:
        findings.append(Finding(
            "api", "Routes no contract declares",
            f"{len(undeclared):,} route(s) in code are in none of the scan's API contracts, which describe the routes "
            "the scan serves: the contract is behind the code, or the routes are internal.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{item.get('method')} {item.get('path')}: {item['file']}" + (f":{item['line']}" if item.get("line") else "")
                      for item in undeclared[:MAX_LISTED]],
        ))
    if stale:
        findings.append(Finding(
            "api", "Generated client operations no contract declares",
            f"{len(stale):,} generated client(s) call operations the contracts they match no longer declare: the "
            "client is older than its contract and should be regenerated.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{client['file']} ({client['generator']}): " + ", ".join(
                f"{item['method']} {item['path']}" for item in client["unmatched"][:8]) for client in stale[:MAX_LISTED]],
        ))
    return value, findings


_VERSION_SEGMENT = re.compile(r"(?i)v\d{1,3}(?:\.\d{1,3})?")
_POLICY_LABELS = {"auth": "authentication and authorization", "versioning": "versioning", "rate_limit": "rate limiting",
                  "validation": "validation"}


def _policies(context: _Context) -> tuple[dict, list[Finding]]:
    """Authentication, authorization, versioning, rate-limit and validation declarations across the
    scan, and the API versions the routes' paths name."""
    db = context.db
    counts: dict[str, Counter] = defaultdict(Counter)
    frameworks: dict[str, set[str]] = defaultdict(set)
    files: dict[str, set[str]] = defaultdict(set)
    declared_versions: Counter = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    for _, path, values in _fact_rows(db, "api_policy", ordered=True):
        category, scope = str(values.get("category", "")), str(values.get("scope", ""))
        counts[category][scope] += 1
        frameworks[category].add(str(values.get("framework", "")))
        files[category].add(path)
        detail = str(values.get("detail", ""))
        if category == "versioning" and detail:
            declared_versions[detail] += 1
        if len(examples[category]) < 10:
            examples[category].append(f"{path}:{values.get('line')} {scope} {values.get('framework', '')}"
                                      + (f": {detail}" if detail else ""))
    served = context.endpoint_routes if context.endpoint_routes is not None else [
        {"path": name.partition(" ")[2]} for name, _, _ in _fact_rows(db, "api_endpoint")]
    versions: Counter = Counter()
    for route in served:
        for segment in str(route.get("path", "")).split("/"):
            if _VERSION_SEGMENT.fullmatch(segment):
                versions[segment.lower()] += 1
                break
    value = {"counts": {category: dict(scopes) for category, scopes in sorted(counts.items())},
             "frameworks": {category: sorted(names) for category, names in sorted(frameworks.items())},
             "files": {category: len(paths) for category, paths in sorted(files.items())},
             "route_versions": dict(sorted(versions.items())), "declared_versions": dict(declared_versions.most_common(50))}
    if not (counts or versions):
        return value, []
    findings = []
    if counts:
        parts = [f"{_POLICY_LABELS.get(category, category)}: {sum(scopes.values()):,} declaration(s) in {len(files[category]):,} "
                 f"file(s) (" + ", ".join(sorted(frameworks[category])[:6]) + ")" for category, scopes in sorted(counts.items())]
        findings.append(Finding(
            "api", "API policy declarations", "; ".join(parts) + ". Declarations show where policies are configured; which "
            "routes they cover is not established by them alone.", confidence="INFERRED", analyzer="code-index",
            evidence=[line for category in sorted(examples) for line in examples[category]][:MAX_LISTED]))
    if versions or declared_versions:
        findings.append(Finding(
            "api", "API versions",
            ("Route paths name " + ", ".join(f"{version} ({count:,} route(s))" for version, count in sorted(versions.items()))
             if versions else "No route path names a version")
            + (("; versioning declared as " + ", ".join(f"{name} ({count:,})" for name, count in declared_versions.most_common(8)))
               if declared_versions else "") + ".",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"{version}: {count:,} route(s)" for version, count in sorted(versions.items())][:MAX_LISTED]))
    return value, findings


MAX_CATALOG_ITEMS = 5000
# How many lines from a route a route-scoped policy (a decorator, annotation or attribute) may be.
_POLICY_LINES = 12
_CATALOG_CATEGORIES = ("auth", "rate_limit", "validation")


def _endpoint_catalog(context: _Context) -> tuple[dict, list[Finding]]:
    """Every route the scan declares, with its method, full path, framework, handler, contract
    operation, the authentication, rate-limit and validation declarations that apply to it as
    written, its source evidence and the confidence of the declaration. Nothing in it says that
    a route is deployed or reachable."""
    db = context.db
    served = context.endpoint_routes if context.endpoint_routes is not None else [
        {"method": name.partition(" ")[0], "path": name.partition(" ")[2], "file": path, "line": values.get("line"),
         "framework": str(values.get("framework", "")), "handler": str(values.get("handler", ""))}
        for name, path, values in _fact_rows(db, "api_endpoint", ordered=True)]
    catalog = []
    by_file: dict[str, list[dict]] = defaultdict(list)
    for route in served[:MAX_CATALOG_ITEMS]:
        entry = {"method": route.get("method", ""), "path": route.get("path", ""), "framework": route.get("framework", ""),
                 "handler": route.get("handler", ""), "file": route["file"], "line": route.get("line"),
                 "contract": (context.route_contracts or {}).get((route["file"], route.get("line"), route.get("method")), ""),
                 "auth": [], "rate_limit": [], "validation": [], "exemptions": [],
                 # The declaration is in the file as written; a prefix mounted from another file is inferred.
                 "confidence": "INFERRED" if route.get("mounted_at") else "CONFIRMED"}
        catalog.append(entry)
        by_file[entry["file"]].append(entry)
    for entries in by_file.values():
        entries.sort(key=lambda item: item["line"] or 0)
    global_policies: dict[str, list[str]] = defaultdict(list)
    for _, path, values in _fact_rows(db, "api_policy", ordered=True):
        category, scope = str(values.get("category", "")), str(values.get("scope", ""))
        detail, framework = str(values.get("detail", "")), str(values.get("framework", ""))
        label = f"{framework}: {detail}" if detail else framework
        if scope == "global":
            if len(global_policies[category]) < MAX_LISTED:
                global_policies[category].append(f"{label} ({path})")
            continue
        entries = by_file.get(path)
        if not entries or (category not in _CATALOG_CATEGORIES and scope != "exemption") or scope == "model":
            continue
        if scope in {"route", "exemption"}:
            # The nearest route of the file, a few lines from the declaration.
            line = values.get("line") or 0
            nearest = min(entries, key=lambda item: abs((item["line"] or 0) - line))
            if abs((nearest["line"] or 0) - line) <= _POLICY_LINES:
                nearest["exemptions" if scope == "exemption" else category].append(label)
            continue
        for entry in entries:  # a class, router or controller declaration: every route of its file
            if category in _CATALOG_CATEGORIES and len(entry[category]) < 10:
                entry[category].append(f"{label} ({scope})")
    counts = {category: sum(1 for entry in catalog if entry[category]) for category in _CATALOG_CATEGORIES}
    value = {"count": len(served), "truncated": max(0, len(served) - len(catalog)),
             "with_handler": sum(1 for entry in catalog if entry["handler"]),
             "with_contract": sum(1 for entry in catalog if entry["contract"]),
             **{f"with_{category}": count for category, count in counts.items()},
             "global_policies": {category: labels for category, labels in sorted(global_policies.items())},
             "endpoints": catalog[:MAX_LISTED * 10]}
    if not catalog:
        return value, []
    frameworks = Counter(entry["framework"] for entry in catalog)

    def describe(entry: dict) -> str:
        line = f"{entry['method']} {entry['path']} -> {entry['handler'] or '?'} ({entry['framework']}) {entry['file']}" \
            + (f":{entry['line']}" if entry["line"] else "")
        if entry["contract"]:
            line += f"; contract {entry['contract']}"
        for category, name in (("auth", "auth"), ("rate_limit", "rate limit"), ("validation", "validation")):
            if entry[category]:
                line += f"; {name} " + ", ".join(entry[category][:3])
        if entry["exemptions"]:
            line += "; exempt " + ", ".join(entry["exemptions"][:3])
        return line + (" [mount prefix inferred]" if entry["confidence"] == "INFERRED" else "")

    findings = [Finding(
        "api", "Endpoint catalog",
        f"{len(served):,} route(s) declared in {len(by_file):,} file(s) (" + ", ".join(
            f"{name} {count:,}" for name, count in frameworks.most_common(8)) + f"): {value['with_handler']:,} with a named "
        f"handler, {value['with_contract']:,} matched to a contract operation, {counts['auth']:,} with an authentication "
        f"declaration on the route, its class or its router, {counts['rate_limit']:,} with a rate limit and "
        f"{counts['validation']:,} with request validation"
        + ("; global policies: " + ", ".join(f"{_POLICY_LABELS.get(category, category)} ({len(labels)})"
                                             for category, labels in sorted(global_policies.items())) if global_policies else "")
        + ". The catalog lists declarations: it does not say that a route is deployed, mounted, enabled or reachable.",
        confidence="INFERRED", analyzer="code-index", evidence=[describe(entry) for entry in catalog[:MAX_LISTED]],
    )]
    # Routes no authentication declaration covers, in a project that declares authentication per
    # route, class or router and has no global authentication policy.
    if counts["auth"] and not global_policies.get("auth"):
        uncovered = [entry for entry in catalog if not entry["auth"] and not entry["exemptions"]]
        if uncovered:
            findings.append(Finding(
                "api", "Routes without an authentication declaration",
                f"{len(uncovered):,} route(s) have no authentication declaration on the route, its class or its router, "
                f"while {counts['auth']:,} other route(s) do and no global policy is declared. They may be public by "
                "design, or protected where the scan cannot see (a gateway, middleware in another file).",
                confidence="INFERRED", severity="LOW", analyzer="code-index",
                evidence=[describe(entry) for entry in uncovered[:MAX_LISTED]],
            ))
    return value, findings


MAX_INTEGRATION_ITEMS = 5000
MAX_INTEGRATION_PACKAGES = 500


def _integration(context: _Context) -> tuple[dict, list[Finding]]:
    """What the project provides (endpoints, topics, gRPC services, packages) and consumes."""
    from ..analyzers.api.integration import EndpointIndex, normalize_route

    db = context.db
    truncated: dict[str, int] = {}
    # Root and workspace manifests first, so a capped list keeps the project's own packages.
    all_packages = sorted({(name, str(values.get("ecosystem", "")), path)
                           for name, path, values in _fact_rows(db, "package_name")},
                          key=lambda item: (item[2].count("/"), item[2], item[0], item[1]))
    packages = all_packages[:MAX_INTEGRATION_PACKAGES]
    if len(all_packages) > len(packages):
        truncated["packages"] = len(all_packages) - len(packages)
    endpoints: dict[tuple[str, str], str] = {}
    # Routes with the prefixes of routers mounted from other files, when the endpoints pass ran.
    served = ((f"{item['method']} {item['path']}", item["file"], None) for item in context.endpoint_routes) \
        if context.endpoint_routes is not None else _fact_rows(db, "api_endpoint")
    for name, path, _ in served:
        method, _, route = name.partition(" ")
        key = (method.upper(), normalize_route(route))
        if key not in endpoints and len(endpoints) >= MAX_INTEGRATION_ITEMS:
            truncated["endpoints"] = truncated.get("endpoints", 0) + 1
            continue
        endpoints.setdefault(key, path)
    calls: dict[tuple[str, str, str], str] = {}
    hosts: Counter = Counter()
    for name, path, values in _fact_rows(db, "http_call"):
        method, _, route = name.partition(" ")
        host = str(values.get("host", ""))
        key = (method.upper(), route, host)
        if key in calls or len(calls) < MAX_INTEGRATION_ITEMS:
            calls.setdefault(key, path)
        else:
            truncated["http_calls"] = truncated.get("http_calls", 0) + 1
        if host:
            hosts[host] += 1
    topics: dict[tuple[str, str, str], str] = {}
    for name, path, values in _fact_rows(db, "message_topic"):
        key = (name, str(values.get("system", "")), str(values.get("role", "")))
        if key in topics or len(topics) < MAX_INTEGRATION_ITEMS:
            topics.setdefault(key, path)
        else:
            truncated["topics"] = truncated.get("topics", 0) + 1
    grpc = {
        kind: sorted({name for name, _, _ in _fact_rows(db, f"grpc_{kind}")})[:1000]
        for kind in ("service", "server", "client")
    }
    index = EndpointIndex(endpoints)
    internal = sum(
        1 for (method, route, host) in calls
        if (not host or host in {"localhost", "127.0.0.1"}) and index.match(method, route)
    )
    value = {
        "packages": [{"name": name, "ecosystem": ecosystem, "path": path} for name, ecosystem, path in packages],
        "endpoints": [{"method": method, "path": route, "file": path} for (method, route), path in sorted(endpoints.items())],
        "http_calls": [{"method": method, "path": route, "host": host, "file": path}
                       for (method, route, host), path in sorted(calls.items())],
        "topics": [{"name": name, "system": system, "role": role, "file": path}
                   for (name, system, role), path in sorted(topics.items())],
        "grpc": grpc, "hosts": dict(hosts.most_common(50)), "internal_calls_matched": internal,
        # Items left out at a cap, by list; `pdt compare` reports these lists as partial.
        "truncated": truncated,
    }
    coverage = [Finding(
        "analysis_coverage", "Integration points truncated",
        "Lists at their cap, with the items left out: "
        + ", ".join(f"{name} ({count:,})" for name, count in sorted(truncated.items()))
        + ". Integration maps built from this report can miss links.",
        confidence="UNKNOWN", analyzer="code-index", severity="LOW",
    )] if truncated else []
    if not (packages or endpoints or calls or topics or any(grpc.values())):
        return value, coverage
    produced = sorted({name for (name, _, role) in topics if role == "produce"})
    consumed = sorted({name for (name, _, role) in topics if role == "consume"})
    parts = []
    if packages:
        parts.append("packages " + ", ".join(f"{name} ({ecosystem})" for name, ecosystem, _ in packages[:8]))
    if endpoints:
        parts.append(f"{len(endpoints):,} HTTP endpoint(s) served")
    if calls:
        parts.append(f"{len(calls):,} outbound HTTP call site(s)"
                     + (" to " + ", ".join(f"{host} ({count})" for host, count in hosts.most_common(8)) if hosts else "")
                     + (f"; {internal:,} match this project's own endpoints" if internal else ""))
    if produced or consumed:
        parts.append(f"topics produced: {', '.join(produced[:10]) or 'none'}; consumed: {', '.join(consumed[:10]) or 'none'}")
    if any(grpc.values()):
        parts.append("gRPC " + "; ".join(f"{kind}s {', '.join(names[:8])}" for kind, names in grpc.items() if names))
    return value, [Finding(
        "multi_project", "Integration points", "; ".join(parts) + ". `pdt compare` joins these across scans into an "
        "integration map.", confidence="INFERRED", analyzer="code-index",
    ), *coverage]


# --------------------------------------------------------------------------- network services

MAX_SERVICE_PORTS = 1000
MAX_NETWORK_ITEMS = 1000
MAX_PER_PORT = 20
_DECLARATION_SOURCES = {"dockerfile": "Dockerfile", "compose": "Compose", "kubernetes": "Kubernetes",
                        "kubernetes-service": "Kubernetes Service", "terraform": "Terraform"}
# Caps that only shorten one port's evidence; the others leave items out of the map.
_PER_PORT_CAPS = frozenset({"declarations", "listeners"})


def _address_parts(address: str) -> tuple[str, int | None]:
    """(host, port) of "host:port", "[v6]:port", ":port" or a bare host, the host lower-cased."""
    if address.startswith("["):
        close = address.find("]")
        if close < 0:
            return address.lower(), None
        host, rest = address[1:close], address[close + 1:].removeprefix(":")
    else:
        head, separator, rest = address.rpartition(":")
        if not separator or ":" in head:  # a bare host, or an IPv6 address without a port
            return address.lower(), None
        host = head
    port = int(rest) if rest.isascii() and rest.isdigit() and len(rest) <= 5 and 0 < int(rest) < 65536 else None
    return host.lower(), port


def _loopback(address: str) -> bool:
    host = _address_parts(address)[0]
    return host in {"localhost", "::1"} or host.startswith("127.")


def _where(item: dict) -> str:
    return f"{item['file']}:{item['line']}" if item.get("line") else str(item["file"])


def _declaration_label(item: dict) -> str:
    """Where a port is declared and by what, for evidence."""
    source = item.get("source")
    if source == "dockerfile":
        what = "EXPOSE"
    elif source == "compose":
        what = f"Compose service {item.get('service')}" + (
            " expose" if item.get("internal") else f" published on {item['published']}" if item.get("published") else "")
    elif source == "kubernetes":
        what = f"{item.get('workload')} containerPort"
    elif source == "kubernetes-service":
        what = f"Service {item.get('service')} targetPort" + (f", port {item['port']}" if item.get("port") else "")
    else:
        what = str(item.get("resource") or source) + (" open to every address" if item.get("public") else "")
    return f"{_where(item)} ({what})"


def _listener_label(item: dict) -> str:
    return f"{_where(item)} ({item.get('api')}{' ' + item['address'] if item.get('address') else ''})"


def _k8s_service_host(host: str, name: str, namespace: str) -> bool:
    """Whether a host name reaches a Kubernetes Service: its name, ``name.namespace`` and the
    ``name.namespace.svc[.cluster.local]`` forms (any namespace when the manifest names none)."""
    if host == name:
        return True
    if not host.startswith(name + "."):
        return False
    labels = host[len(name) + 1:].split(".")
    if namespace and labels[0] != namespace:
        return False
    return (len(labels) == 1 and bool(namespace)) or (len(labels) > 1 and labels[1] == "svc")


def _network_services(context: _Context) -> tuple[dict, list[Finding]]:
    """The network service map: the ports Dockerfiles, Compose, Kubernetes and Terraform
    declare, joined by number with the ports code listens on, and the services code connects
    to by name. Declarations and call sites from every file of the scan are joined."""
    db = context.db
    truncated: Counter = Counter()
    ports: dict[int, dict] = {}
    ranges: list[tuple[int, int, dict]] = []
    named: list[dict] = []

    def keep(items: list, value, key: str, limit: int = MAX_PER_PORT) -> None:
        if len(items) < limit:
            items.append(value)
        else:
            truncated[key] += 1

    def slot(port: int) -> dict | None:
        if port not in ports:
            if len(ports) >= MAX_SERVICE_PORTS:
                truncated["ports"] += 1
                return None
            ports[port] = {"declared": [], "listeners": []}
        return ports[port]

    for name, path, values in _fact_rows(db, "net_declared", ordered=True):
        item = {"file": path, **values}
        low, _, high = name.partition("-")
        if name == "?":
            keep(named, item, "named_target_ports", MAX_NETWORK_ITEMS)
        elif low.isdigit() and high.isdigit():
            keep(ranges, (int(low), int(high), item), "ranges", MAX_NETWORK_ITEMS)
        elif low.isdigit() and not high and (entry := slot(int(low))) is not None:
            keep(entry["declared"], item, "declarations")
    unknown: list[dict] = []
    unknown_live = 0
    for name, path, values in _fact_rows(db, "net_listen", ordered=True):
        item = {"file": path, "line": values.get("line"), "api": str(values.get("api", "")),
                "address": str(values.get("address", ""))}
        if is_test_path(path.replace("\\", "/")):
            item["test"] = True
        if name.isdigit() and len(name) <= 5 and 0 < int(name) < 65536:
            if (entry := slot(int(name))) is not None:
                keep(entry["listeners"], item, "listeners")
        else:
            unknown_live += not item.get("test")
            keep(unknown, item, "listeners_without_literal_port", MAX_NETWORK_ITEMS)
    services: list[dict] = []
    for name, path, values in _fact_rows(db, "net_service", ordered=True):
        keep(services, {"name": name, "file": path, **values}, "services", MAX_NETWORK_ITEMS)

    # A Service selects the pods whose labels hold its selector, in its namespace; its named
    # targetPorts resolve through those pods' container port names. Pods are indexed by label.
    pods_by_label: dict[tuple[str, str, str], list[tuple[int, dict]]] = defaultdict(list)
    for port, entry in ports.items():
        for item in entry["declared"]:
            if item.get("source") == "kubernetes" and isinstance(item.get("labels"), dict):
                for key, label in item["labels"].items():
                    pods_by_label[(str(item.get("namespace") or ""), key, label)].append((port, item))
    selections: dict[tuple, list[tuple[int, dict]]] = {}

    def selected(item: dict) -> list[tuple[int, dict]]:
        selector = item.get("selector")
        if not isinstance(selector, dict) or not selector:
            return []
        namespace = str(item.get("namespace") or "")
        key = (namespace, *sorted(selector.items()))
        if key not in selections:
            first = next(iter(selector.items()))
            selections[key] = [(port, pod) for port, pod in pods_by_label.get((namespace, *first), ())
                               if all(pod["labels"].get(name) == label for name, label in selector.items())]
        return selections[key]

    def mismatch(item: dict, target: str, pods: list[tuple[int, dict]]) -> str:
        workloads = ", ".join(sorted({str(pod.get("workload")) for _, pod in pods}))
        declared_there = ", ".join(sorted({str(pod.get("port_name") or port) if target.startswith("name ") else str(port)
                                           for port, pod in pods}))
        return (f"{_where(item)}: Service {item.get('service')} port {item.get('port')} targets {target}; "
                f"{workloads} declare(s) {declared_there}")

    mismatched: list[str] = []
    unresolved: list[dict] = []
    for item in named:
        pods = selected(item)
        target = [port for port, pod in pods if pod.get("port_name") == item.get("target_name")]
        if target and (entry := slot(target[0])) is not None:
            keep(entry["declared"], item, "declarations")
            continue
        unresolved.append(item)
        if pods:
            mismatched.append(mismatch(item, f"name {item.get('target_name')!r}", pods))
    for port, entry in sorted(ports.items()):
        for item in entry["declared"]:
            pods = selected(item) if item.get("source") == "kubernetes-service" and "target_name" not in item else []
            if pods and all(pod_port != port for pod_port, _ in pods):
                mismatched.append(mismatch(item, str(port), pods))

    # The ports clients use to reach a service by name: a Compose service's container ports,
    # a Kubernetes Service's own ports.
    spans: dict[tuple[str, str, str], list[tuple[int, int]]] = defaultdict(list)
    for first, last, item in [*((port, port, item) for port, entry in ports.items() for item in entry["declared"]),
                              *ranges, *((0, 0, item) for item in named)]:
        if item.get("source") == "compose":
            spans[("compose", str(item.get("service")), "")].append((first, last))
        elif item.get("source") == "kubernetes-service" and isinstance(item.get("port"), int):
            key = ("kubernetes", str(item.get("service")).lower(), str(item.get("namespace") or "").lower())
            spans[key].append((item["port"], item["port"]))
    compose_hosts: dict[str, str] = {}
    k8s_names: dict[str, list[str]] = defaultdict(list)
    for service in services:
        if service.get("source") == "compose":
            for alias in [service["name"], *service.get("aliases", [])]:
                compose_hosts.setdefault(str(alias).lower(), service["name"])
        elif service.get("source") == "kubernetes":
            k8s_names[service["name"].lower()].append(str(service.get("namespace") or "").lower())

    def reached(host: str) -> tuple[str, str, str] | None:
        if host in compose_hosts:
            return "compose", compose_hosts[host], ""
        name = host.split(".", 1)[0]
        for namespace in k8s_names.get(name, ()):
            if _k8s_service_host(host, name, namespace):
                return "kubernetes", name, namespace
        return None

    connections: list[dict] = []
    wrong_port: list[str] = []
    for name, path, values in _fact_rows(db, "net_connect", ordered=True):
        host, port = _address_parts(name)
        item = {"address": name, "file": path, "line": values.get("line"), "api": str(values.get("api", ""))}
        service = reached(host)
        if service is not None:
            item["service"] = f"{service[0]} {service[1]}"
            known = spans.get(service)
            if port is not None and known and not any(first <= port <= last for first, last in known) \
                    and not is_test_path(path.replace("\\", "/")):
                wrong_port.append(f"{_where(item)} connects to {name}; {service[0]} service {service[1]} declares "
                                  + ", ".join(sorted({str(first) if first == last else f"{first}-{last}"
                                                      for first, last in known})))
        keep(connections, item, "connections", MAX_NETWORK_ITEMS)
    seen: set[tuple[str, str]] = set()
    for name, path, values in _fact_rows(db, "http_call", ordered=True):
        host = str(values.get("host", "")).lower()
        service = reached(host) if host and (host, path) not in seen else None
        if service is not None:
            seen.add((host, path))
            keep(connections, {"address": host, "file": path, "api": f"HTTP {name}"[:200],
                               "service": f"{service[0]} {service[1]}"}, "connections", MAX_NETWORK_ITEMS)

    def live(entry: dict, reachable: bool = False) -> list[dict]:
        """Listeners outside tests (bound beyond loopback, with ``reachable``)."""
        return [item for item in entry["listeners"]
                if not item.get("test") and not (reachable and _loopback(item["address"]))]

    served = {port for port, entry in ports.items() if live(entry)}
    reachable = {port for port, entry in ports.items() if live(entry, reachable=True)}
    workload = sorted(port for port, entry in ports.items()
                      if any(item.get("scope") == "workload" for item in entry["declared"]))
    declared = sorted(port for port, entry in ports.items() if entry["declared"])
    listened = sorted(port for port, entry in ports.items() if entry["listeners"])

    def shown(item: dict) -> dict:
        return {key: value for key, value in item.items() if key not in {"labels", "selector"}}

    value = {
        "ports": [{"port": port, "protocols": sorted({str(item.get("protocol")) for item in entry["declared"]}),
                   "declared": [shown(item) for item in entry["declared"]], "listeners": entry["listeners"]}
                  for port, entry in sorted(ports.items())],
        "ranges": [{"ports": f"{first}-{last}", **shown(item),
                    "served_ports": sorted(port for port in served if first <= port <= last)[:MAX_PER_PORT]}
                   for first, last, item in ranges],
        "unresolved_target_ports": [shown(item) for item in unresolved],
        "listeners_without_literal_port": unknown,
        "services": services,
        "connections": connections,
        "truncated": dict(truncated),
    }
    left_out = {key: count for key, count in truncated.items() if key not in _PER_PORT_CAPS}
    findings = [Finding(
        "analysis_coverage", "Network service map truncated",
        "Lists at their cap, with the items left out: "
        + ", ".join(f"{key} ({count:,})" for key, count in sorted(left_out.items()))
        + ". The service map and the findings built from it can miss ports and services.",
        confidence="UNKNOWN", analyzer="code-index", severity="LOW",
    )] if left_out else []
    if not (declared or ranges or listened or unknown or services):
        return value, findings

    parts = []
    if declared or ranges:
        sources = Counter(str(item.get("source")) for entry in ports.values() for item in entry["declared"])
        sources.update(str(item.get("source")) for _, _, item in ranges)
        parts.append(f"{len(declared):,} port(s)" + (f" and {len(ranges):,} port range(s)" if ranges else "")
                     + " declared (" + ", ".join(f"{_DECLARATION_SOURCES.get(source, source)} {count:,}"
                                                 for source, count in sorted(sources.items())) + ")")
    if listened or unknown:
        parts.append(f"{len(listened):,} port(s) code listens on"
                     + (f", and {len(unknown):,} listener(s) whose port is not a literal" if unknown else ""))
    both = sorted(set(declared) & set(listened))
    if both:
        parts.append(f"declared and listened on: {', '.join(map(str, both[:20]))}")
    resolved = [item for item in connections if item.get("service")]
    if resolved:
        parts.append(f"{len(resolved):,} connection(s) in code reach services the deployment files name")
    evidence = [
        f"port {port}: " + "; ".join([_declaration_label(item) for item in entry["declared"][:5]]
                                     + [_listener_label(item) for item in entry["listeners"][:5]])
        for port, entry in itertools.islice(sorted(ports.items()), MAX_LISTED)
    ]
    findings.append(Finding(
        "network", "Network service map",
        "; ".join(parts) + ". Ports are joined by number across every scanned file; nothing was connected to.",
        confidence="INFERRED", evidence=evidence, analyzer="code-index",
    ))
    unserved = [port for port in workload if port not in served]
    if unserved and served and not unknown_live:
        findings.append(Finding(
            "network", "Declared ports no code listener uses",
            f"{len(unserved):,} port(s) deployment files declare for a workload are used by no listener in code "
            f"({', '.join(map(str, unserved[:20]))}), while code listens on "
            f"{', '.join(map(str, sorted(served)[:20]))}. The program may take the port from configuration, an "
            "environment variable or a framework default, or the declaration is stale.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"port {port}: " + "; ".join(_declaration_label(item) for item in ports[port]["declared"][:5])
                      for port in unserved[:MAX_LISTED]],
        ))
    undeclared = [port for port in sorted(reachable)
                  if not ports[port]["declared"] and not any(first <= port <= last for first, last, _ in ranges)]
    if undeclared and (declared or ranges):
        findings.append(Finding(
            "network", "Listeners no deployment file declares",
            f"{len(undeclared):,} port(s) code listens on beyond loopback are declared by no Dockerfile, Compose file, "
            f"Kubernetes manifest or Terraform rule ({', '.join(map(str, undeclared[:20]))}). A listener the "
            "deployment files do not name (a debug or admin port, for example) is easy to miss in reviews, "
            "firewall rules and network policies.",
            confidence="INFERRED", analyzer="code-index",
            evidence=[f"port {port}: " + "; ".join(_listener_label(item) for item in live(ports[port], True)[:5])
                      for port in undeclared[:MAX_LISTED]],
        ))
    public_ranges = [(first, last, item) for first, last, item in ranges if item.get("public")]
    exposed = []
    for port in sorted(reachable):
        rules = [item for item in ports[port]["declared"] if item.get("public")]
        rules += [item for first, last, item in public_ranges if first <= port <= last]
        if rules:
            exposed.append(f"port {port}: " + "; ".join([_declaration_label(item) for item in rules[:3]]
                                                         + [_listener_label(item) for item in live(ports[port], True)[:3]]))
    if exposed:
        findings.append(Finding(
            "security", "Ports open to every address that code listens on",
            f"{len(exposed):,} port(s) that code listens on are opened to every address (0.0.0.0/0, ::/0, * or "
            "Internet) by a Terraform firewall or security group rule, so the service is reachable from the "
            "internet wherever the rule applies.",
            confidence="INFERRED", severity="MEDIUM", analyzer="code-index", evidence=exposed[:MAX_LISTED],
            recommendation="Limit the rule's sources to the networks that need the service, or serve it through "
                           "a load balancer.",
        ))
    if mismatched:
        findings.append(Finding(
            "orchestration", "Kubernetes Services targeting ports their pods do not declare",
            f"{len(mismatched):,} Service port(s) send traffic to a targetPort that no container of the pods they "
            "select declares. Connections to them fail unless a container listens there without declaring it.",
            confidence="INFERRED", severity="LOW", analyzer="code-index", evidence=mismatched[:MAX_LISTED],
        ))
    if wrong_port:
        findings.append(Finding(
            "network", "Connections to ports a service does not declare",
            f"{len(wrong_port):,} connection(s) in code reach a Compose or Kubernetes service by name on a port that "
            "service does not declare; the code or the deployment file has the wrong port.",
            confidence="INFERRED", severity="LOW", analyzer="code-index", evidence=wrong_port[:MAX_LISTED],
        ))
    return value, findings


QUERY_KINDS = ("symbol", "callers", "callees", "references")


def _shown(row: dict) -> dict:
    """A call row with its stored resolution hint as a name and a resolution label.

    ``@Engine.run`` (resolved in its own file) and ``~items.size`` (a call through a
    receiver the index did not resolve) are internal markers, not names.
    """
    target = row.get("target") or ""
    if target.startswith("@"):
        return {**row, "target": target[1:], "resolution": "same file"}
    if target.startswith("~"):
        return {**row, "target": target[1:], "resolution": "receiver not resolved"}
    if "()" in target:
        # ``.store.make_store().run``: a call on a value another function returns; the call
        # graph completes it across modules.
        return {**row, "resolution": "through a returned value"}
    return {**row, "resolution": "resolved" if target else "by name"}


def code_index_state(inventory_path: Path) -> dict:
    """Whether a scan's inventory holds a code index, and whether it was cut at a limit."""
    db = _connect(inventory_path)
    try:
        rows = sum(
            db.execute(f"SELECT EXISTS (SELECT 1 FROM {table})").fetchone()[0]
            for table in ("code_symbols", "code_calls", "code_references")
        )
        row = db.execute("SELECT value FROM inventory_metadata WHERE key='code_index_truncated'").fetchone()
        truncated = json.loads(row[0]) if row else {"tables": [], "files": 0}
    except sqlite3.Error:
        return {"built": False, "truncated": {}}
    finally:
        db.close()
    return {"built": bool(rows), "truncated": truncated}


def _limited(items, limit: int) -> list[dict]:
    result = []
    for item in items:
        if len(result) >= limit:
            break
        result.append(item)
    return result


def _dotted_module(path: str) -> str:
    """``src/pkg/engine.py`` -> ``src.pkg.engine`` (``pkg/__init__.py`` -> ``pkg``)."""
    dotted = posixpath.splitext(path.replace("\\", "/"))[0].replace("/", ".")
    return dotted[: -len(".__init__")] if dotted.endswith(".__init__") else dotted


def _names(query: str, qualified: str, path: str) -> bool:
    """Whether ``query`` names the symbol ``qualified`` defined in ``path``.

    Exactly (``Engine.run``), by a qualified suffix, or with the defining module in front
    as the call graph prints it (``pkg.engine.Engine.run`` for ``Engine.run`` in
    ``pkg/engine.py`` or ``src/pkg/engine.py``).
    """
    if qualified == query or qualified.endswith("." + query):
        return True
    if not query.endswith("." + qualified):
        return False
    module = query[: -len(qualified) - 1]
    dotted = _dotted_module(path)
    return dotted == module or dotted.endswith("." + module)


def _call_names(query: str, target: str, path: str) -> bool:
    """Whether a call's resolved ``target`` is the function ``query`` names.

    ``@Engine.run`` is a call resolved inside its own file (``self.run()``,
    ``this.run()``); the condition that should have matched it bound the same pattern
    twice, so same-file callers of a qualified name were never found.
    """
    if target.startswith("@"):
        return _names(query, target[1:], path)
    if target.startswith("~"):  # ``items.size()``: a call through another receiver
        return False
    return target == query or target.endswith("." + query)


def query_code_index(inventory_path: Path, kind: str, name: str, limit: int = 200) -> list[dict]:
    """Look up a scan's code index. ``name`` may be bare (``run``) or qualified (``Engine.run``)."""
    if kind not in QUERY_KINDS:
        raise ValueError(f"query kind must be one of: {', '.join(QUERY_KINDS)}")
    if not Path(inventory_path).is_file():
        raise FileNotFoundError(f"no code index at {inventory_path}; run `pdt scan --output` first")
    simple = name.rsplit(".", 1)[-1]
    qualified = name if "." in name else None
    db = _connect(inventory_path)
    try:
        if kind == "symbol":
            keys = ("path", "line", "end_line", "language", "kind", "qualified", "exported")
            rows = db.execute(
                """SELECT path, line, end_line, language, kind, qualified, exported FROM code_symbols
                   WHERE name = ? ORDER BY path, line""",
                (simple,),
            )
            return _limited(
                (dict(zip(keys, row, strict=True)) for row in rows
                 if qualified is None or _names(qualified, row[5], row[0])),
                limit,
            )
        elif kind == "callers":
            keys = ("path", "line", "caller", "target")
            rows = db.execute(
                "SELECT path, line, caller, target FROM code_calls WHERE callee = ? ORDER BY path, line",
                (simple,),
            )
            return _limited(
                (_shown(dict(zip(keys, row, strict=True))) for row in rows
                 if qualified is None or _call_names(qualified, row[3] or "", row[0])),
                limit,
            )
        elif kind == "callees":
            keys = ("path", "line", "callee", "target", "caller")
            # Candidates by the last name segment, then the full name: bare, qualified or
            # module-qualified (``app.main``, as the call graph prints it).
            rows = db.execute(
                """SELECT path, line, callee, target, caller FROM code_calls
                   WHERE caller = ? OR caller LIKE '%.' || ? ORDER BY path, line""",
                (simple, simple),
            )
            return _limited(
                (_shown(dict(zip(keys, row, strict=True))) for row in rows if _names(name, row[4], row[0])),
                limit,
            )
        else:
            rows = db.execute(
                "SELECT path FROM code_references WHERE name = ? ORDER BY path LIMIT ?", (simple, limit),
            )
            keys = ("path",)
        return [dict(zip(keys, row, strict=True)) for row in rows]
    finally:
        db.close()


MAX_PROVENANCE_ITEMS = 2_000
# Public registries by the hosts they serve packages from: one registry, several hosts.
_PUBLIC_REGISTRIES = {
    "registry.npmjs.org": "npm registry", "registry.yarnpkg.com": "npm registry", "pypi.org": "PyPI",
    "files.pythonhosted.org": "PyPI", "pypi.python.org": "PyPI", "crates.io": "crates.io", "static.crates.io": "crates.io",
    "rubygems.org": "RubyGems", "index.rubygems.org": "RubyGems", "repo.packagist.org": "Packagist",
    "repo.hex.pm": "Hex", "pub.dev": "pub.dev", "pub.dartlang.org": "pub.dev",
}
_RELATIONS = {
    "hosted-at": "hosted at", "includes-submodule-from": "submodules from", "resolves-packages-from": "packages from",
    "built-by": "built by", "runs-on": "runs on", "uses": "uses", "publishes-to": "publishes to",
    "deploys-to": "deploys to", "pulls-images-from": "images from",
}


def _provenance(context: _Context) -> tuple[dict, list[Finding]]:
    """Where the project comes from and goes to, as its files declare it: the hosts its
    repository and submodules are at, the registries its packages resolve from, the CI
    workflows that build it with the actions they use and what they publish and deploy, the
    registries of the container images it uses, and the platforms its manifests deploy to."""
    db = context.db
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    truncated = 0

    def node(kind: str, label: str, **attributes) -> str | None:
        nonlocal truncated
        key = f"{kind}:{label}"
        if key not in nodes:
            if len(nodes) >= MAX_PROVENANCE_ITEMS:
                truncated += 1
                return None
            nodes[key] = {"id": key, "kind": kind, "label": label, **{
                name: value for name, value in attributes.items() if value not in (None, "")}}
        return key

    def edge(source: str | None, target: str | None, relation: str, path: str | None = None, **attributes) -> None:
        nonlocal truncated
        if source is None or target is None:
            return
        key = (source, target, relation)
        entry = edges.get(key)
        if entry is None:
            if len(edges) >= MAX_PROVENANCE_ITEMS:
                truncated += 1
                return
            entry = edges[key] = {"from": source, "to": target, "relation": relation, "count": 0, "files": []}
        entry["count"] += 1
        if path and path not in entry["files"] and len(entry["files"]) < 5:
            entry["files"].append(path)
        for name, value in attributes.items():
            if isinstance(value, int) and not isinstance(value, bool):
                entry[name] = entry.get(name, 0) + value
            elif value not in (None, "", [], False):
                values = entry.setdefault(name, [])
                if value not in values and len(values) < 10:
                    values.append(value)

    project = node("project", "this project")
    insecure: list[str] = []
    for kind, relation in (("vcs_remote", "hosted-at"), ("vcs_submodule", "includes-submodule-from")):
        for name, path, values in _fact_rows(db, kind, ordered=True):
            host = str(values.get("host") or "") or "unresolved host"
            target = node("source_host", host, provider=str(values.get("provider", "")))
            edge(project, target, relation, path, **({"remote": name} if kind == "vcs_remote" else {"submodule": name}),
                 vcs=str(values.get("vcs", "")))
            locator = str(values.get("locator", ""))
            if locator.split("://", 1)[0].lower() in {"http", "git"} and len(insecure) < MAX_LISTED:
                insecure.append(f"{'remote' if kind == 'vcs_remote' else 'submodule'} {name} -> {locator} ({path})")
    ecosystems: dict[str, dict[str, int]] = defaultdict(dict)
    for host, path, values in _fact_rows(db, "package_registry", ordered=True):
        ecosystem, count = str(values.get("ecosystem", "")), int(values.get("packages") or 0)
        target = node("package_registry", host, registry=_PUBLIC_REGISTRIES.get(host, ""))
        edge(project, target, "resolves-packages-from", path, ecosystem=ecosystem, packages=count)
        identity = _PUBLIC_REGISTRIES.get(host, host)
        ecosystems[ecosystem][identity] = ecosystems[ecosystem].get(identity, 0) + count
    workflow_files: set[str] = set()
    unpinned = actions = 0
    for provider, path, values in _fact_rows(db, "ci_workflow", ordered=True):
        workflow_files.add(path)
        workflow = node("ci_workflow", path, provider=provider, jobs=values.get("jobs"))
        edge(project, workflow, "built-by", path)
        edge(workflow, node("ci_system", provider), "runs-on", path)
        for action in values.get("actions") or []:
            action = str(action)
            reference, _, ref = action.partition("@")
            pinned = bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))
            local = reference.startswith(("./", "docker://"))
            actions += 1
            unpinned += bool(ref) and not pinned and not local
            edge(workflow, node("ci_action", reference), "uses", path, ref=ref[:64], pinned=pinned)
        for target in values.get("publishes") or []:
            edge(workflow, node("publish_target", str(target)), "publishes-to", path)
        for platform in values.get("deploys") or []:
            edge(workflow, node("deploy_target", str(platform)), "deploys-to", path)
    for provider, path, _ in _fact_rows(db, "ci_system", ordered=True):
        if path not in workflow_files:  # a CI system only its configuration file names
            workflow = node("ci_workflow", path, provider=provider)
            edge(project, workflow, "built-by", path)
            edge(workflow, node("ci_system", provider), "runs-on", path)
    images: Counter = Counter()
    for image, path, values in _fact_rows(db, "container_image", ordered=True):
        registry = str(values.get("registry") or "") or "unresolved registry"
        images[registry] += 1
        edge(project, node("image_registry", registry), "pulls-images-from", path, images=1,
             pinned_images=1 if values.get("pinned") else 0, role=str(values.get("role", "")), image=image[:120])
    for platform, path, values in _fact_rows(db, "deploy_target", ordered=True):
        edge(project, node("deploy_target", platform), "deploys-to", path, via=str(values.get("source", "")))
    value = {
        "nodes": list(nodes.values()), "edges": list(edges.values()), "truncated": truncated,
        "counts": dict(sorted(Counter(item["kind"] for item in nodes.values()).items())),
    }
    if len(nodes) <= 1:
        return value, []

    def labels(relation: str, describe) -> str:
        found = [describe(entry) for entry in edges.values() if entry["relation"] == relation]
        return ", ".join(found[:8]) + (f" and {len(found) - 8:,} more" if len(found) > 8 else "") if found else ""

    def target(entry: dict) -> dict:
        return nodes[entry["to"]]

    parts = [
        ("hosted at", labels("hosted-at", lambda entry: f"{target(entry).get('provider') or target(entry)['label']} "
                                                       f"({target(entry)['label']}: {', '.join(entry.get('remote', []))})")),
        ("submodules from", labels("includes-submodule-from", lambda entry: f"{target(entry)['label']} "
                                                                           f"({entry['count']:,})")),
        ("packages from", labels("resolves-packages-from", lambda entry: f"{target(entry)['label']} "
                                 f"({', '.join(entry.get('ecosystem', []))}: {entry.get('packages', 0):,})")),
        ("built by", ", ".join(f"{provider} ({count:,} workflow{'s' if count != 1 else ''})" for provider, count in Counter(
            nodes[entry["to"]].get("provider", "") for entry in edges.values() if entry["relation"] == "built-by").items())),
        ("CI actions", f"{actions:,} reference(s), {unpinned:,} not pinned to a commit" if actions else ""),
        ("publishes to", ", ".join(sorted({nodes[entry["to"]]["label"] for entry in edges.values()
                                           if entry["relation"] == "publishes-to"}))),
        ("images from", ", ".join(f"{registry} ({count:,})" for registry, count in images.most_common(8))),
        ("deploys to", ", ".join(sorted({nodes[entry["to"]]["label"] for entry in edges.values()
                                         if entry["relation"] == "deploys-to"}))),
    ]
    summary = "; ".join(f"{name}: {text}" for name, text in parts if text)
    evidence = [f"{nodes[entry['from']]['label']} {_RELATIONS[entry['relation']]} {nodes[entry['to']]['label']}"
                + (f" ({', '.join(entry['files'])})" if entry["files"] else "") for entry in edges.values()][:MAX_LISTED]
    findings = [Finding(
        "supply_chain", "Software provenance",
        summary + ". The graph records what the scanned files declare; it does not prove where releases are "
        "actually built, published or deployed." + (f" {truncated:,} node(s) or edge(s) past the "
                                                     f"{MAX_PROVENANCE_ITEMS:,}-item cap are not listed." if truncated else ""),
        confidence="INFERRED", analyzer="code-index", evidence=evidence,
    )]
    mixed = {ecosystem: hosts for ecosystem, hosts in ecosystems.items() if len(hosts) > 1}
    if mixed:
        findings.append(Finding(
            "supply_chain", "Packages of one ecosystem from several registries",
            "Packages of " + ", ".join(sorted(mixed)) + " resolve from more than one registry. When a private and a "
            "public registry serve the same names, a package published under an internal name on the public "
            "registry can be installed instead (dependency confusion).",
            confidence="INFERRED", severity="LOW", analyzer="code-index",
            evidence=[f"{ecosystem}: " + ", ".join(f"{host} ({count:,})" for host, count in sorted(hosts.items()))
                      for ecosystem, hosts in sorted(mixed.items())],
            recommendation="Scope private packages to the private registry (npm scopes, a pip index per package or "
                           "PEP 708 tracking, Cargo registries per dependency) and reserve internal names on public "
                           "registries.",
        ))
    if insecure:
        findings.append(Finding(
            "supply_chain", "Source locations over an unencrypted transport",
            f"{len(insecure):,} remote(s) or submodule(s) are fetched over http:// or git://, which neither "
            "encrypts nor authenticates the server: a network attacker can change the code fetched.",
            confidence="CONFIRMED", severity="LOW", analyzer="code-index", evidence=insecure,
            recommendation="Use https:// or ssh:// locations.",
        ))
    return value, findings


_PASSES = (
    ("dependencies", _dependencies),
    ("symbols", _symbols),
    ("call_graph", _call_graph),
    ("unreferenced", _unreferenced),
    ("test_links", _test_links),
    ("module_graph", _module_graph),
    ("complexity", _complexity),
    ("type_systems", _type_summary),
    ("concurrency", _concurrency_summary),
    ("memory", _memory_summary),
    ("dataflow", _dataflow),
    ("embedded", _embedded_summary),
    ("firmware", _firmware_summary),
    ("hdl", _hdl_hierarchy),
    ("shaders", _shader_inventory),
    ("frontend", _component_graph),
    ("endpoints", _endpoint_routes),
    ("graphql", _graphql),
    ("rpc", _rpc),
    ("protocols", _protocols),
    ("contract_links", _contract_links),
    ("policies", _policies),
    ("endpoint_catalog", _endpoint_catalog),
    ("integration", _integration),
    ("network_services", _network_services),
    ("provenance", _provenance),
    ("reachability", _reachability),
)
