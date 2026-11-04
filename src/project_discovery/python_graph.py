"""Static Python module and import graph extraction.

Target source is parsed with :mod:`ast`; it is never imported or executed.
Only imports resolved to inventoried modules become confirmed graph edges.
"""
from __future__ import annotations

import ast
from collections.abc import Callable, Sequence
from importlib.util import resolve_name
from pathlib import Path
from typing import Any

from .models import FileRecord, Finding
from .source_utils import SourceBudgetExceeded, read_python_source_bounded

MAX_GRAPH_AST_FILE_BYTES = 16 * 1024 * 1024
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


def analyze_python_dependencies(
    root: Path,
    records: Sequence[FileRecord],
    *,
    finding_sink: Callable[[Finding], None] | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Build a local Python import graph under explicit memory ceilings.

    Module indexes, emitted edges, unresolved imports and skipped-file evidence are
    capped independently. When a cap is reached, the graph marks itself partial and
    emits an UNKNOWN finding rather than silently presenting truncated results.
    A caller may provide a sink to persist findings as they are produced.
    """
    module_paths: dict[str, list[str]] = {}
    module_path_counts: dict[str, int] = {}
    eligible: dict[str, FileRecord] = {}
    skipped_modules: list[dict[str, str | int]] = []
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
        module = _module_name(record.path)
        if module is None:
            continue
        if record.content_skipped_reason or record.size_bytes > MAX_GRAPH_AST_FILE_BYTES:
            reason = record.content_skipped_reason or (
                f"exceeds {MAX_GRAPH_AST_FILE_BYTES} byte graph AST budget"
            )
            if len(skipped_modules) < MAX_GRAPH_SKIPPED_MODULES:
                skipped_modules.append({
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
            if len(module_paths) >= MAX_GRAPH_MODULES:
                omitted_module_record_count += 1
                continue
            module_paths[module] = [record.path]
            module_path_counts[module] = 1
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
    known_modules = set(unique_modules) | set(duplicate_modules)
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, str, int, str]] = set()
    omitted_edge_count = 0
    unresolved: list[dict[str, Any]] = []
    omitted_unresolved_count = 0
    adjacency: dict[str, set[str]] = {name: set() for name in unique_modules}

    def add_unresolved(item: dict[str, Any]) -> None:
        nonlocal omitted_unresolved_count
        if len(unresolved) < MAX_GRAPH_UNRESOLVED:
            unresolved.append(item)
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

    for source_module, record in sorted(eligible.items(), key=lambda item: item[1].path):
        if source_module not in unique_modules:
            continue
        if source_module not in unique_modules:
            continue
        try:
            source_text = read_python_source_bounded(
                root / record.path, MAX_GRAPH_AST_FILE_BYTES,
                expected_identity=record.analysis_identity,
            )
        except SourceBudgetExceeded as exc:
            add_unresolved({
                "source": source_module,
                "path": record.path,
                "line": None,
                "import": None,
                "reason": "source_budget_exceeded",
                "detail": str(exc),
                "confidence": "UNKNOWN",
            })
            emit(Finding(
                "architecture",
                f"Python dependency graph budget reached: {record.path}",
                "The module was inventoried but its import graph could not be extracted: "
                + str(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer="python-module-graph",
                severity="LOW",
            ))
            continue
        except (OSError, UnicodeDecodeError, SyntaxError, LookupError) as exc:
            add_unresolved({
                "source": source_module,
                "path": record.path,
                "line": getattr(exc, "lineno", None),
                "import": None,
                "reason": f"source_parse_error: {type(exc).__name__}",
                "confidence": "UNKNOWN",
            })
            continue
        try:
            tree = ast.parse(source_text, filename=record.path)
        except (SyntaxError, RecursionError, MemoryError) as exc:
            add_unresolved({
                "source": source_module,
                "path": record.path,
                "line": getattr(exc, "lineno", None),
                "import": None,
                "reason": f"source_parse_error: {type(exc).__name__}",
                "confidence": "UNKNOWN",
            })
            emit(Finding(
                "architecture",
                f"Python dependency graph parse unavailable: {record.path}",
                "The module could not be parsed within interpreter limits: "
                + type(exc).__name__,
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer="python-module-graph",
                severity="LOW",
            ))
            continue

        is_package = Path(record.path).stem == "__init__"
        package = source_module if is_package else source_module.rpartition(".")[0]
        for node in ast.walk(tree):
            imports: list[tuple[str, str]] = []
            if isinstance(node, ast.Import):
                imports.extend((alias.name, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                import_text = "." * node.level + (node.module or "")
                if node.level:
                    if not package:
                        record_unresolved(
                            source_module, record.path, node.lineno, import_text,
                            "relative_import_without_package_context",
                        )
                        continue
                    try:
                        base = resolve_name(import_text, package)
                    except ImportError:
                        record_unresolved(
                            source_module, record.path, node.lineno, import_text,
                            "relative_import_resolution_failed",
                        )
                        continue
                else:
                    base = node.module or ""

                candidates: list[str] = []
                if base and base in known_modules and base != source_module:
                    candidates.append(base)
                child_modules = [
                    f"{base}.{alias.name}" for alias in node.names
                    if alias.name != "*" and f"{base}.{alias.name}" in known_modules
                ] if base else [
                    alias.name for alias in node.names if alias.name in known_modules
                ]
                candidates.extend(child_modules)
                if not candidates and base in known_modules and base != source_module:
                    candidates.append(base)
                if not candidates:
                    record_unresolved(
                        source_module, record.path, node.lineno, base or import_text,
                        "not_resolved_to_inventoried_module",
                    )
                    continue
                imports.extend((target, import_text) for target in sorted(set(candidates)))

            for target, import_text in imports:
                if target in duplicate_modules:
                    record_unresolved(
                        source_module, record.path, node.lineno, target,
                        "ambiguous_duplicate_module",
                    )
                    continue
                if target not in unique_modules:
                    record_unresolved(
                        source_module, record.path, node.lineno, target,
                        "not_resolved_to_inventoried_module",
                    )
                    continue
                edge = {
                    "source": source_module,
                    "target": target,
                    "source_path": record.path,
                    "target_path": unique_modules[target],
                    "line": node.lineno,
                    "import": import_text,
                    "confidence": "CONFIRMED",
                }
                edge_key = (
                    edge["source"], edge["target"], edge["source_path"],
                    edge["line"], edge["import"],
                )
                if edge_key not in edge_keys:
                    if len(edges) >= MAX_GRAPH_EDGES:
                        omitted_edge_count += 1
                        continue
                    edge_keys.add(edge_key)
                    edges.append(edge)
                    adjacency[source_module].add(target)
                    emit(Finding(
                        "dependency",
                        f"Internal Python dependency: {source_module} -> {target}",
                        f"Static import resolves to an inventoried module at line {node.lineno}.",
                        confidence="CONFIRMED",
                        evidence=[f"{record.path}:{node.lineno}", unique_modules[target]],
                        analyzer="python-module-graph",
                    ))

    edges.sort(key=lambda edge: (
        edge["source"], edge["target"], edge["source_path"], edge["line"]
    ))
    unresolved.sort(key=lambda item: (
        item["source"], item["path"], item["line"] or 0, item["import"] or ""
    ))
    cycles = _strongly_connected_components(list(unique_modules), adjacency)
    for component in cycles:
        cycle_edges = [
            edge for edge in edges
            if edge["source"] in component and edge["target"] in component
        ]
        evidence = sorted({
            f'{edge["source_path"]}:{edge["line"]}' for edge in cycle_edges
        })
        emit(Finding(
            "architecture",
            "Python circular dependency: " + " <-> ".join(component),
            f"Static import graph contains a strongly connected component of {len(component)} modules.",
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer="python-module-graph",
        ))

    if omitted_module_record_count or omitted_edge_count or omitted_unresolved_count or omitted_skipped_module_count:
        emit(Finding(
            "architecture",
            "Python dependency graph reached a resource limit",
            "The graph is partial because one or more explicit module, edge, unresolved-import, "
            "or skipped-module evidence limits were reached. Review the graph summary before "
            "treating absent edges or imports as evidence of absence.",
            confidence="UNKNOWN",
            evidence=[
                f"omitted_modules: {omitted_module_record_count}",
                f"omitted_edges: {omitted_edge_count}",
                f"omitted_unresolved_imports: {omitted_unresolved_count}",
                f"omitted_skipped_modules: {omitted_skipped_module_count}",
            ],
            analyzer="python-module-graph",
            severity="LOW",
        ))

    graph = {
        "modules": [
            {"name": name, "path": path, "confidence": "CONFIRMED"}
            for name, path in sorted(unique_modules.items())
        ],
        "skipped_modules": skipped_modules,
        "omitted_skipped_module_count": omitted_skipped_module_count,
        "duplicate_modules": duplicate_modules,
        "edges": edges,
        "unresolved_imports": unresolved,
        "cycles": cycles,
        "summary": {
            "module_count": len(unique_modules),
            "skipped_module_count": len(skipped_modules),
            "duplicate_module_count": len(duplicate_modules),
            "edge_count": len(edges),
            "unresolved_import_count": len(unresolved),
            "cycle_count": len(cycles),
            "module_limit_reached": omitted_module_record_count > 0,
            "omitted_module_record_count": omitted_module_record_count,
            "edge_limit_reached": omitted_edge_count > 0,
            "omitted_edge_count": omitted_edge_count,
            "unresolved_limit_reached": omitted_unresolved_count > 0,
            "omitted_unresolved_import_count": omitted_unresolved_count,
            "graph_complete": not any((
                omitted_module_record_count, omitted_edge_count,
                omitted_unresolved_count, omitted_skipped_module_count,
            )) and not skipped_modules,
        },
    }
    skipped_modules.sort(key=lambda item: (str(item["name"]), str(item["path"])))
    return graph, findings
