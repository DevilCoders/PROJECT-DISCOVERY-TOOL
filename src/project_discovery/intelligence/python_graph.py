"""Static Python module and import graph extraction.

Target source is parsed with :mod:`ast`; it is never imported or executed.
Only imports resolved to inventoried modules become confirmed graph edges.
"""
from __future__ import annotations

import ast
from array import array
from collections.abc import Callable, Iterable, Sequence
from importlib.util import resolve_name
from pathlib import Path, PurePosixPath
from typing import Any

from ..core.source_utils import SourceBudgetExceeded, parse_python, read_python_source_bounded
from ..models import FileRecord, Finding

MAX_GRAPH_AST_FILE_BYTES = 4 * 1024 * 1024  # the syntax-tree budget
# Without a scan store (library callers) the graph's lists are held in memory under these
# ceilings. With one (pdt scan), only the module indexes are: edges, unresolved imports,
# skipped modules and the module list are store rows, read back lazily by the reports.
STORE_MAX_GRAPH_MODULES = 250_000
STORE_MAX_GRAPH_EDGES = 10_000_000
STORE_MAX_GRAPH_UNRESOLVED = 5_000_000
STORE_MAX_GRAPH_SKIPPED_MODULES = 1_000_000
MAX_GRAPH_MODULES = 25_000
MAX_GRAPH_EDGES = 100_000
MAX_GRAPH_UNRESOLVED = 100_000
MAX_GRAPH_SKIPPED_MODULES = 25_000
MAX_DUPLICATE_MODULE_PATHS = 8


def _module_name(relative_path: str) -> str | None:
    path = Path(relative_path)
    if path.suffix not in {".py", ".pyi"}:
        return None
    parts = list(path.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _import_name(relative_path: str, package_dirs: set[str]) -> str | None:
    """Return the absolute import name implied by the enclosing package chain.

    Python resolves ``import pkg.mod`` from the directory above the topmost package
    (a directory with ``__init__.py``), so ``src/pkg/mod.py`` imports as ``pkg.mod``.
    The walk stops at the scan root: when the root itself is a package, its modules are
    named relative to it (``core``, ``sub.mod``).
    """
    path = PurePosixPath(relative_path)
    parts = [] if path.stem == "__init__" else [path.stem]
    directory = path.parent
    # ``PurePosixPath(".").parent`` is ``.`` again, so the root must end the walk.
    while directory.as_posix() != "." and directory.as_posix() in package_dirs:
        parts.insert(0, directory.name)
        directory = directory.parent
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _strongly_connected_components(
    nodes: list[str], adjacency: dict[str, set[str]]
) -> list[list[str]]:
    """Return cyclic SCCs using iterative Kosaraju traversal."""
    visited: set[str] = set()
    finished: list[str] = []
    for start in sorted(nodes):
        if start in visited:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finished.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for neighbor in sorted(adjacency.get(node, set()), reverse=True):
                if neighbor not in visited:
                    stack.append((neighbor, False))

    reverse: dict[str, set[str]] = {node: set() for node in nodes}
    for source, targets in adjacency.items():
        for target in targets:
            reverse.setdefault(target, set()).add(source)

    assigned: set[str] = set()
    components: list[list[str]] = []
    for start in reversed(finished):
        if start in assigned:
            continue
        component: list[str] = []
        stack = [start]
        assigned.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for neighbor in sorted(reverse.get(node, set()), reverse=True):
                if neighbor not in assigned:
                    assigned.add(neighbor)
                    stack.append(neighbor)
        component.sort()
        if len(component) > 1 or start in adjacency.get(start, set()):
            components.append(component)
    return sorted(components)


def _cyclic_components(count: int, targets_of: list) -> list[list[int]]:
    """Cyclic strongly connected components of an integer graph (iterative Kosaraju).

    ``targets_of[node]`` is an ascending array of target ids, or None. Ids are assigned in
    module-name order, so the traversal and the result match the name-based version.
    """
    empty = array("I")
    visited = bytearray(count)
    finished = array("I")
    for start in range(count):
        if visited[start]:
            continue
        stack = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finished.append(node)
                continue
            if visited[node]:
                continue
            visited[node] = 1
            stack.append((node, True))
            for neighbor in reversed(targets_of[node] or empty):
                if not visited[neighbor]:
                    stack.append((neighbor, False))
    # The reverse graph as compressed rows: sources of each target, ascending.
    starts = array("Q", bytes(8 * (count + 1)))
    for targets in targets_of:
        for target in targets or empty:
            starts[target + 1] += 1
    for node in range(count):
        starts[node + 1] += starts[node]
    sources = array("I", bytes(4 * starts[count]))
    fill = array("Q", starts)
    for source, targets in enumerate(targets_of):
        for target in targets or empty:
            sources[fill[target]] = source
            fill[target] += 1
    assigned = bytearray(count)
    components: list[list[int]] = []
    for start in reversed(finished):
        if assigned[start]:
            continue
        component: list[int] = []
        stack_ids = [start]
        assigned[start] = 1
        while stack_ids:
            node = stack_ids.pop()
            component.append(node)
            for neighbor in reversed(sources[starts[node]:starts[node + 1]]):
                if not assigned[neighbor]:
                    assigned[neighbor] = 1
                    stack_ids.append(neighbor)
        component.sort()
        own = targets_of[start]
        if len(component) > 1 or (own is not None and start in own):
            components.append(component)
    return sorted(components)


class _Rows:
    """One of the graph's lists: in memory, or rows of the scan store read back lazily."""

    def __init__(self, store, kind: str) -> None:
        self.store, self.kind, self.count = store, kind, 0
        self.items: list[tuple[str, dict[str, Any]]] = []
        if store is not None:
            store.discard(kind)  # an earlier or interrupted scan's rows

    def __len__(self) -> int:
        return self.count

    def append(self, sort_key: str, key: str, item: dict[str, Any]) -> None:
        self.count += 1
        if self.store is None:
            self.items.append((sort_key, item))
        else:
            from ..inventory.store import sqlite_text

            self.store.append(self.kind, {"path": sqlite_text(key), "row": item}, sort_key=sqlite_text(sort_key))

    def result(self):
        if self.store is None:
            return [item for _, item in sorted(self.items, key=lambda pair: pair[0])]
        from ..inventory.store import StoredRows

        self.store.flush()
        return StoredRows(self.store.path, self.kind)


_SEP = "\x1f"  # sort-key field separator: below every printable character


def parse_python_imports(root: Path, record: FileRecord) -> tuple:
    """Read and parse one module; return a compact, picklable import summary.

    Results: ("ok", [(line, level, module, names, is_import), ...]),
    ("budget", detail), ("read_error", exc_name, line) or ("parse_error", exc_name, line).
    """
    try:
        source_text = read_python_source_bounded(
            root / record.path, MAX_GRAPH_AST_FILE_BYTES,
            expected_identity=record.analysis_identity,
        )
    except SourceBudgetExceeded as exc:
        return ("budget", str(exc))
    except (OSError, ValueError, SyntaxError, LookupError) as exc:
        return ("read_error", type(exc).__name__, getattr(exc, "lineno", None))
    try:
        tree = parse_python(source_text, filename=record.path)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return ("parse_error", type(exc).__name__, getattr(exc, "lineno", None))
    statements = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            statements.append((node.lineno, 0, None, tuple(a.name for a in node.names), True))
        elif isinstance(node, ast.ImportFrom):
            statements.append((
                node.lineno, node.level, node.module, tuple(a.name for a in node.names), False,
            ))
    return ("ok", statements)


def analyze_python_dependencies(
    root: Path,
    records: Sequence[FileRecord],
    *,
    finding_sink: Callable[[Finding], None] | None = None,
    import_parser: Callable[[list[FileRecord]], Iterable[tuple]] | None = None,
    store=None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Build a local Python import graph under explicit memory ceilings.

    Module indexes, emitted edges, unresolved imports and skipped-file evidence are
    capped independently. When a cap is reached, the graph marks itself partial and
    emits an UNKNOWN finding rather than silently presenting truncated results.
    A caller may provide a sink to persist findings as they are produced, and the scan's
    InventoryStore (``store``): the graph's lists then become store rows, the returned
    graph holds lazy StoredRows sequences, and the much higher STORE_* ceilings apply.
    """
    if store is None:
        max_modules, max_edges = MAX_GRAPH_MODULES, MAX_GRAPH_EDGES
        max_unresolved, max_skipped = MAX_GRAPH_UNRESOLVED, MAX_GRAPH_SKIPPED_MODULES
    else:
        max_modules, max_edges = STORE_MAX_GRAPH_MODULES, STORE_MAX_GRAPH_EDGES
        max_unresolved, max_skipped = STORE_MAX_GRAPH_UNRESOLVED, STORE_MAX_GRAPH_SKIPPED_MODULES
    module_paths: dict[str, list[str]] = {}
    module_path_counts: dict[str, int] = {}
    package_dirs: set[str] = set()
    eligible: dict[str, FileRecord] = {}
    skipped_rows = _Rows(store, "graph_skipped")
    omitted_module_record_count = 0
    omitted_skipped_module_count = 0
    findings: list[Finding] = []

    def emit(finding: Finding) -> None:
        if finding_sink is None:
            findings.append(finding)
        else:
            finding_sink(finding)

    for record in records:
        if record.extension not in {".py", ".pyi"} or record.error:
            continue
        if PurePosixPath(record.path).stem == "__init__" and len(package_dirs) < max_modules:
            package_dirs.add(PurePosixPath(record.path).parent.as_posix())
        module = _module_name(record.path)
        if module is None:
            continue
        if record.content_skipped_reason or record.size_bytes > MAX_GRAPH_AST_FILE_BYTES:
            reason = record.content_skipped_reason or (
                f"exceeds {MAX_GRAPH_AST_FILE_BYTES} byte graph AST budget"
            )
            if len(skipped_rows) < max_skipped:
                skipped_rows.append(f"{module}{_SEP}{record.path}", record.path, {
                    "name": module, "path": record.path, "reason": reason,
                    "confidence": "UNKNOWN",
                })
                emit(Finding(
                    "architecture",
                    f"Python dependency graph skipped: {record.path}",
                    "The module is inventoried, but its import graph could not be extracted: " + reason,
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer="python-module-graph",
                    severity="LOW",
                ))
            else:
                omitted_skipped_module_count += 1
            continue

        paths = module_paths.get(module)
        if paths is None:
            if len(module_paths) >= max_modules:
                omitted_module_record_count += 1
                continue
            module_paths[module] = [record.path]
            module_path_counts[module] = 1
            eligible[module] = record
        elif (
            module_path_counts[module] == 1
            and PurePosixPath(paths[0]).with_suffix("").as_posix() == PurePosixPath(record.path).with_suffix("").as_posix()
            and {PurePosixPath(paths[0]).suffix, record.extension} == {".py", ".pyi"}
        ):
            # mod.py with its inline stub mod.pyi is one module: the source is the module.
            if record.extension == ".py":
                module_paths[module] = [record.path]
                eligible[module] = record
        else:
            module_path_counts[module] += 1
            if len(paths) < MAX_DUPLICATE_MODULE_PATHS:
                paths.append(record.path)

    unique_modules = {
        name: paths[0] for name, paths in module_paths.items()
        if module_path_counts[name] == 1
    }
    duplicate_modules = {
        name: sorted(paths) for name, paths in module_paths.items()
        if module_path_counts[name] > 1
    }
    duplicate_module_path_counts = {
        name: module_path_counts[name] for name in duplicate_modules
    }
    duplicate_module_candidate_omitted_count = sum(
        max(0, module_path_counts[name] - len(duplicate_modules[name]))
        for name in duplicate_modules
    )
    known_modules = set(unique_modules) | set(duplicate_modules)
    # Absolute-import aliases from package roots (src/ layouts, monorepo subprojects).
    package_aliases: dict[str, set[str]] = {}
    for name, paths in module_paths.items():
        import_name = _import_name(paths[0], package_dirs)
        if import_name and import_name != name and import_name not in known_modules:
            package_aliases.setdefault(import_name, set()).add(name)

    # PEP 420 namespace packages have no __init__.py, so the package walk stops below them:
    # src/ns/pkg/mod.py is "src.ns.pkg.mod" by path and "pkg.mod" by package chain, while
    # code imports "ns.pkg.mod". A suffix of two or more segments that starts at a
    # directory without __init__.py resolves such imports when exactly one module has it.
    # (One segment never does: inside a package, ``import utils`` means a top-level utils.)
    suffix_owners: dict[str, set[str]] = {}
    for name in known_modules:
        parts = name.split(".")
        for start in range(1, len(parts) - 1):
            if "/".join(parts[:start + 1]) not in package_dirs:
                suffix_owners.setdefault(".".join(parts[start:]), set()).add(name)

    def canonical(target: str) -> str | None:
        if target in known_modules:
            return target
        owners = package_aliases.get(target)
        if owners:
            return next(iter(owners)) if len(owners) == 1 else None
        owners = suffix_owners.get(target)
        return next(iter(owners)) if owners and len(owners) == 1 else None

    # Reports name modules as Python imports them (pkg.mod, not src.pkg.mod), as the code
    # index does, so the two graphs and `pdt compare` agree on src/ and flat layouts. A
    # name that more than one module would get keeps the path-based name.
    import_names = {
        name: _import_name(paths[0], package_dirs) or name for name, paths in module_paths.items()
        if module_path_counts[name] == 1
    }
    import_name_counts: dict[str, int] = {}
    for alias in import_names.values():
        import_name_counts[alias] = import_name_counts.get(alias, 0) + 1
    display = {
        name: alias for name, alias in import_names.items()
        if import_name_counts[alias] == 1 and (alias == name or alias not in known_modules)
    }

    def shown(name: str) -> str:
        return display.get(name, name)
    edge_rows = _Rows(store, "graph_edge")
    edge_count = 0
    omitted_edge_candidate_count = 0
    unresolved_rows = _Rows(store, "graph_unresolved")
    omitted_unresolved_count = 0
    extraction_gap = False  # a module whose imports could not be read or parsed
    # Module ids in name order; each module's targets as an ascending array of ids.
    module_names = sorted(unique_modules)
    module_ids = {name: index for index, name in enumerate(module_names)}
    targets_of: list = [None] * len(module_names)

    def add_unresolved(item: dict[str, Any]) -> None:
        nonlocal omitted_unresolved_count, extraction_gap
        reason = str(item["reason"])
        extraction_gap = extraction_gap or reason == "source_budget_exceeded" or reason.startswith(
            "source_parse_error:")
        if len(unresolved_rows) < max_unresolved:
            sort_key = _SEP.join((item["source"], item["path"], f"{item['line'] or 0:012d}", item["import"] or ""))
            unresolved_rows.append(sort_key, f"{len(unresolved_rows):012d}",
                                   item | {"source": shown(item["source"])})
        else:
            omitted_unresolved_count += 1

    def record_unresolved(
        source: str, path: str, line: int | None, target: str | None, reason: str
    ) -> None:
        item: dict[str, Any] = {
            "source": source, "path": path, "line": line, "import": target,
            "reason": reason, "confidence": "UNKNOWN",
        }
        if target in duplicate_modules:
            item["candidates"] = duplicate_modules[target]
        add_unresolved(item)

    work = [
        (module, record)
        for module, record in sorted(eligible.items(), key=lambda item: item[1].path)
        if module in unique_modules
    ]
    # Parsing can be farmed out (the CLI uses its worker pool); results arrive in order.
    parsed_results = (
        import_parser([record for _, record in work]) if import_parser is not None
        else (parse_python_imports(root, record) for _, record in work)
    )
    for (source_module, record), parsed in zip(work, parsed_results, strict=True):
        status = parsed[0]
        if status == "budget":
            add_unresolved({
                "source": source_module,
                "path": record.path,
                "line": None,
                "import": None,
                "reason": "source_budget_exceeded",
                "detail": parsed[1],
                "confidence": "UNKNOWN",
            })
            emit(Finding(
                "architecture",
                f"Python dependency graph budget reached: {record.path}",
                "The module was inventoried but its import graph could not be extracted: "
                + parsed[1],
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer="python-module-graph",
                severity="LOW",
            ))
            continue
        if status in {"read_error", "parse_error"}:
            add_unresolved({
                "source": source_module,
                "path": record.path,
                "line": parsed[2],
                "import": None,
                "reason": f"source_parse_error: {parsed[1]}",
                "confidence": "UNKNOWN",
            })
            emit(Finding(
                "architecture",
                f"Python dependency graph {'source unavailable' if status == 'read_error' else 'parse unavailable'}: {record.path}",
                (
                    "The inventoried source could not be read or decoded for graph extraction: "
                    if status == "read_error" else
                    "The module could not be parsed within interpreter limits: "
                ) + parsed[1],
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer="python-module-graph",
                severity="LOW",
            ))
            continue

        is_package = Path(record.path).stem == "__init__"
        package = source_module if is_package else source_module.rpartition(".")[0]
        # An edge's source and source path are this module's: de-duplicate within it.
        seen_edges: set[tuple[str, int, str]] = set()
        targets: set[int] = set()
        for lineno, level, module, names, is_import in parsed[1]:
            imports: list[tuple[str, str]] = []
            if is_import:
                imports.extend((name, name) for name in names)
            else:
                import_text = "." * level + (module or "")
                if level:
                    if not package:
                        record_unresolved(
                            source_module, record.path, lineno, import_text,
                            "relative_import_without_package_context",
                        )
                        continue
                    try:
                        base = resolve_name(import_text, package)
                    except ImportError:
                        record_unresolved(
                            source_module, record.path, lineno, import_text,
                            "relative_import_resolution_failed",
                        )
                        continue
                else:
                    base = module or ""

                candidates: list[str] = []
                resolved_base = canonical(base) if base else None
                if resolved_base and resolved_base != source_module:
                    candidates.append(resolved_base)
                child_names = [
                    f"{base}.{name}" if base else name
                    for name in names if name != "*"
                ]
                candidates.extend(
                    resolved for name in child_names if (resolved := canonical(name))
                )
                if not candidates:
                    record_unresolved(
                        source_module, record.path, lineno, base or import_text,
                        "not_resolved_to_inventoried_module",
                    )
                    continue
                imports.extend((target, import_text) for target in sorted(set(candidates)))

            for target, import_text in imports:
                if target in package_aliases and canonical(target) is None:
                    item_candidates = sorted(package_aliases[target])
                    add_unresolved({
                        "source": source_module, "path": record.path, "line": lineno,
                        "import": target, "reason": "ambiguous_package_alias",
                        "candidates": item_candidates[:MAX_DUPLICATE_MODULE_PATHS],
                        "confidence": "UNKNOWN",
                    })
                    continue
                target = canonical(target) or target
                if target in duplicate_modules:
                    record_unresolved(
                        source_module, record.path, lineno, target,
                        "ambiguous_duplicate_module",
                    )
                    continue
                if target not in unique_modules:
                    record_unresolved(
                        source_module, record.path, lineno, target,
                        "not_resolved_to_inventoried_module",
                    )
                    continue
                edge_key = (target, lineno, import_text)
                if edge_key not in seen_edges:
                    if edge_count >= max_edges:
                        omitted_edge_candidate_count += 1
                        continue
                    seen_edges.add(edge_key)
                    edge_count += 1
                    edge_rows.append(
                        _SEP.join((source_module, target, record.path, f"{lineno:012d}")),
                        _SEP.join((record.path, str(lineno), target, import_text)),
                        {
                            "source": shown(source_module), "target": shown(target),
                            "source_path": record.path, "target_path": unique_modules[target],
                            "line": lineno, "import": import_text, "confidence": "CONFIRMED",
                        },
                    )
                    targets.add(module_ids[target])
                    emit(Finding(
                        "dependency",
                        f"Internal Python dependency: {shown(source_module)} -> {shown(target)}",
                        f"Static import resolves to an inventoried module at line {lineno}.",
                        confidence="CONFIRMED",
                        evidence=[f"{record.path}:{lineno}", unique_modules[target]],
                        analyzer="python-module-graph",
                    ))
        if targets:
            targets_of[module_ids[source_module]] = array("I", sorted(targets))

    edges = edge_rows.result()
    cyclic = _cyclic_components(len(module_names), targets_of)
    cycles = [[module_names[node] for node in component] for component in cyclic]
    # The evidence of each cycle: its internal edges, from one pass over the edge list.
    component_of = {unique_modules[module_names[node]]: number
                    for number, component in enumerate(cyclic) for node in component}
    cycle_evidence: list[set[str]] = [set() for _ in cyclic]
    if cyclic:
        for edge in edges:
            number = component_of.get(edge["source_path"])
            if number is not None and component_of.get(edge["target_path"]) == number:
                cycle_evidence[number].add(f'{edge["source_path"]}:{edge["line"]}')
    for component, found in zip(cycles, cycle_evidence, strict=True):
        evidence = sorted(found)
        emit(Finding(
            "architecture",
            "Python circular dependency: " + " <-> ".join(shown(name) for name in component),
            f"Static import graph contains a strongly connected component of {len(component)} modules.",
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer="python-module-graph",
        ))

    if (
        omitted_module_record_count
        or omitted_edge_candidate_count
        or omitted_unresolved_count
        or omitted_skipped_module_count
        or duplicate_module_candidate_omitted_count
    ):
        emit(Finding(
            "architecture",
            "Python dependency graph reached a resource limit",
            "The graph is partial because one or more explicit module, edge, unresolved-import, "
            "or skipped-module evidence limits were reached. Review the graph summary before "
            "treating absent edges or imports as evidence of absence.",
            confidence="UNKNOWN",
            evidence=[
                f"omitted_modules: {omitted_module_record_count}",
                f"omitted_edge_candidates: {omitted_edge_candidate_count}",
                f"omitted_unresolved_imports: {omitted_unresolved_count}",
                f"omitted_skipped_modules: {omitted_skipped_module_count}",
                f"omitted_duplicate_module_paths: {duplicate_module_candidate_omitted_count}",
            ],
            analyzer="python-module-graph",
            severity="LOW",
        ))

    cycles = [[shown(name) for name in component] for component in cycles]
    module_rows = _Rows(store, "graph_module")
    for name, module_path in unique_modules.items():
        module_rows.append(shown(name), name, {"name": shown(name), "path": module_path, "confidence": "CONFIRMED"})
    skipped_count = len(skipped_rows)
    unresolved_count = len(unresolved_rows)
    graph = {
        "modules": module_rows.result(),
        "skipped_modules": skipped_rows.result(),
        "omitted_skipped_module_count": omitted_skipped_module_count,
        "duplicate_modules": duplicate_modules,
        "duplicate_module_path_counts": duplicate_module_path_counts,
        "edges": edges,
        "unresolved_imports": unresolved_rows.result(),
        "cycles": cycles,
        "summary": {
            "module_count": len(unique_modules),
            "skipped_module_count": skipped_count + omitted_skipped_module_count,
            "skipped_module_detail_count": skipped_count,
            "duplicate_module_count": len(duplicate_modules),
            "duplicate_module_candidate_omitted_count": duplicate_module_candidate_omitted_count,
            "edge_count": edge_count,
            "unresolved_import_count": unresolved_count,
            "cycle_count": len(cycles),
            "module_limit_reached": omitted_module_record_count > 0,
            "omitted_module_record_count": omitted_module_record_count,
            "edge_limit_reached": omitted_edge_candidate_count > 0,
            "omitted_edge_candidate_count": omitted_edge_candidate_count,
            "unresolved_limit_reached": omitted_unresolved_count > 0,
            "omitted_unresolved_import_count": omitted_unresolved_count,
            "graph_complete": not any((
                omitted_module_record_count, omitted_edge_candidate_count,
                omitted_unresolved_count, omitted_skipped_module_count,
                duplicate_module_candidate_omitted_count,
            )) and not skipped_count and not extraction_gap,
        },
    }
    return graph, findings
