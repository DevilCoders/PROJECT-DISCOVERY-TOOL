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
import sqlite3
from collections import Counter, defaultdict
from importlib.util import resolve_name
from pathlib import Path, PurePosixPath
from typing import Iterable

from .analyzers.test_analyzer import is_test_path
from .code_model import supports_language
from .inventory_store import sqlite_text
from .models import FileRecord, Finding
from .python_graph import _import_name, _strongly_connected_components

MAX_GRAPH_EDGES = 500_000
MAX_LISTED = 100
MAX_CYCLES_LISTED = 20
_FUNCTION_KINDS = ("function", "method", "constructor")
_CALLABLE_KINDS = _FUNCTION_KINDS + ("class", "struct", "record", "object", "type", "macro")
# Languages whose definitions can call each other, for lexical name resolution.
_LANGUAGE_GROUPS = {
    "C": "c-family", "C++": "c-family", "C/C++ Header": "c-family", "Objective-C": "c-family",
    "Objective-C++": "c-family", "CUDA": "c-family", "OpenCL": "c-family",
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
        for record in records:
            if not supports_language(record.language):
                continue
            posix = record.path.replace("\\", "/")
            module = _import_name(posix, package_dirs) if record.language == "Python" else None
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
    value = {"symbol_count": total, "files_with_symbols": files, "by_language": dict(by_language)}
    if not total:
        return value, []
    summary = "; ".join(
        f"{language}: " + ", ".join(f"{count:,} {kind}" for kind, count in sorted(kinds.items()))
        for language, kinds in sorted(by_language.items(), key=lambda item: -sum(item[1].values()))[:12]
    )
    return value, [Finding(
        "symbol_index", "Symbol index",
        f"{total:,} definitions in {files:,} files. {summary}. Python symbols come from the "
        "syntax tree; other languages from PDT's structural lexer. Query the index with "
        "`pdt query OUTPUT --symbol NAME`.",
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


def _call_graph(context: _Context) -> tuple[dict, list[Finding]]:
    db = context.db
    kinds = _placeholders(_CALLABLE_KINDS)
    db.execute("CREATE TEMP TABLE py_defs (fq TEXT PRIMARY KEY, path TEXT, kind TEXT) WITHOUT ROWID")
    db.execute(
        f"""INSERT OR IGNORE INTO py_defs
            SELECT f.module || '.' || s.qualified, s.path, s.kind FROM code_symbols s
            JOIN files f ON f.path = s.path
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
    db.execute(
        f"""CREATE TEMP TABLE lex_calls AS
            SELECT c.path AS path, c.caller AS caller, c.callee AS callee, c.line AS line, f.grp AS grp,
                   CASE
                     WHEN EXISTS (SELECT 1 FROM code_symbols s WHERE s.path = c.path AND s.name = c.callee
                                  AND s.kind IN ({kinds})) THEN 'local'
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
        AND NOT EXISTS (SELECT 1 FROM code_references r WHERE r.name = s.name)"""
    parameters = (*_FUNCTION_KINDS, *entries)
    count = db.execute(
        f"SELECT COUNT(*) FROM code_symbols s JOIN files f ON f.path = s.path WHERE {where}", parameters,
    ).fetchone()[0]
    value = {"unreferenced_private_functions": count}
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
        "framework registration and code outside the scan are not visible, so confirm before removal.",
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
    # Every directory suffix of a Go package ("a/b/c", "b/c", "c") maps to its directory,
    # so an import path such as github.com/org/repo/b/c resolves without a module file.
    go_suffixes: dict[str, str] = {}
    for (directory,) in db.execute("SELECT DISTINCT dir FROM files WHERE language = 'Go'"):
        parts = directory.split("/") if directory else []
        for start in range(len(parts)):
            go_suffixes.setdefault("/".join(parts[start:]), directory)

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
            for start in range(len(segments)):
                match = go_suffixes.get("/".join(segments[start:]))
                if match is not None:
                    found = f"{match}/"  # Go packages are directories
                    break
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


QUERY_KINDS = ("symbol", "callers", "callees", "references")


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
            rows = db.execute(
                """SELECT path, line, end_line, language, kind, qualified, exported FROM code_symbols
                   WHERE name = ? AND (? IS NULL OR qualified = ? OR qualified LIKE '%.' || ?)
                   ORDER BY path, line LIMIT ?""",
                (simple, qualified, qualified, qualified, limit),
            )
            keys = ("path", "line", "end_line", "language", "kind", "qualified", "exported")
        elif kind == "callers":
            rows = db.execute(
                """SELECT path, line, caller, target FROM code_calls WHERE callee = ?
                   AND (? IS NULL OR target = ? OR target LIKE '%.' || ? OR target LIKE '%' || ?)
                   ORDER BY path, line LIMIT ?""",
                (simple, qualified, qualified, qualified, qualified and "." + qualified, limit),
            )
            keys = ("path", "line", "caller", "target")
        elif kind == "callees":
            rows = db.execute(
                """SELECT path, line, callee, target, caller FROM code_calls
                   WHERE caller = ? OR caller LIKE '%.' || ? ORDER BY path, line LIMIT ?""",
                (name, name, limit),
            )
            keys = ("path", "line", "callee", "target", "caller")
        else:
            rows = db.execute(
                "SELECT path FROM code_references WHERE name = ? ORDER BY path LIMIT ?", (simple, limit),
            )
            keys = ("path",)
        return [dict(zip(keys, row, strict=True)) for row in rows]
    finally:
        db.close()


_PASSES = (
    ("symbols", _symbols),
    ("call_graph", _call_graph),
    ("unreferenced", _unreferenced),
    ("test_links", _test_links),
    ("module_graph", _module_graph),
    ("complexity", _complexity),
    ("type_systems", _type_summary),
    ("concurrency", _concurrency_summary),
    ("memory", _memory_summary),
)
