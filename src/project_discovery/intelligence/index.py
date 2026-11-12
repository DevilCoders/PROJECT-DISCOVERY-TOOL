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
            SELECT s.name AS name, f.grp AS grp, COUNT(*) AS n, MIN(s.path) AS path,
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
            resolved = _python_target(target, module, bool(package))
            if resolved:
                resolved = _disambiguated(_namespace_resolved(resolved, context.namespace_aliases), path, ambiguous)
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

def _fact_rows(db: sqlite3.Connection, kind: str):
    """(name, path, detail dict) rows of one fact kind."""
    for name, path, detail in db.execute("SELECT name, path, detail FROM code_facts WHERE kind = ?", (kind,)):
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

    top_details = []
    for key in tops[:MAX_LISTED]:
        depth, total = measure(key, frozenset({key}))
        top_details.append((modules[key][0], modules[key][1], depth, total))
    top_details.sort(key=lambda item: (-item[3], item[0]))
    clocks = sum(1 for _ in _fact_rows(db, "hdl_clock_constraint"))
    parts = sorted({(name, str(values.get("family", ""))) for name, _, values in _fact_rows(db, "fpga_part")})
    testbenches = sum(1 for _, _, testbench, _ in modules.values() if testbench)
    value = {
        "units": len(modules), "testbenches": testbenches,
        "tops": [{"name": name, "path": path, "depth": depth, "instances": total} for name, path, depth, total in top_details],
        "unresolved_types": dict(unresolved.most_common(50)), "cycles": [component[:10] for component in cycles[:10]],
        "clock_constraints": clocks, "fpga_parts": [{"part": part, "family": family} for part, family in parts],
    }
    detail = (f"{len(modules):,} design unit(s) ({testbenches:,} testbench(es)); {len(tops):,} top-level unit(s): "
              + ", ".join(f"{name} (depth {depth}, {total:,} instances)" for name, _, depth, total in top_details[:10])
              + "." + (" Unresolved instance types (vendor primitives or IP not in the scan): "
                       + ", ".join(f"{name} ({count})" for name, count in unresolved.most_common(15)) + "."
                       if unresolved else "")
              + (" Targets: " + ", ".join(f"{part} ({family})" if family else part for part, family in parts[:8]) + "."
                 if parts else ""))
    findings = [Finding("hardware_description", "HDL design hierarchy", detail, confidence="INFERRED",
                        analyzer="code-index", evidence=[f"{path}: {name}" for name, path, _, _ in top_details[:15]])]
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
    for name, path, _ in _fact_rows(db, "api_endpoint"):
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
    ("integration", _integration),
)
