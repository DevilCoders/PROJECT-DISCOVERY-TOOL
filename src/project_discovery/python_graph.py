"""Static Python module and import graph extraction.

This module parses source with :mod:`ast`; it never imports or executes target code.
Only imports that resolve unambiguously to an inventoried project module become
confirmed graph edges. Unresolved imports are retained as UNKNOWN evidence.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from importlib.util import resolve_name
from pathlib import Path
from typing import Any

from .models import FileRecord, Finding


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
    """Return deterministic Tarjan SCCs, including only cyclic components."""
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for neighbor in sorted(adjacency.get(node, set())):
            if neighbor not in indices:
                visit(neighbor)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[neighbor])

        if lowlinks[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            component.sort()
            if len(component) > 1 or node in adjacency.get(node, set()):
                components.append(component)

    for node in sorted(nodes):
        if node not in indices:
            visit(node)
    return sorted(components)


def analyze_python_dependencies(
    root: Path, records: list[FileRecord]
) -> tuple[dict[str, Any], list[Finding]]:
    """Build a local Python import graph from inventoried source files."""
    module_paths: dict[str, list[str]] = defaultdict(list)
    eligible: list[tuple[FileRecord, str]] = []
    for record in records:
        if record.extension not in {".py", ".pyi"} or record.error:
            continue
        module = _module_name(record.path)
        if module is not None:
            module_paths[module].append(record.path)
            eligible.append((record, module))

    unique_modules = {
        name: paths[0] for name, paths in module_paths.items() if len(paths) == 1
    }
    duplicate_modules = {
        name: sorted(paths) for name, paths in module_paths.items() if len(paths) > 1
    }
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    adjacency: dict[str, set[str]] = {name: set() for name in unique_modules}
    findings: list[Finding] = []

    for record, source_module in sorted(eligible, key=lambda item: item[0].path):
        if source_module not in unique_modules:
            continue
        source_path = root / record.path
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=record.path)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            unresolved.append({
                "source": source_module,
                "path": record.path,
                "line": getattr(exc, "lineno", None),
                "import": None,
                "reason": f"source_parse_error: {type(exc).__name__}",
                "confidence": "UNKNOWN",
            })
            continue

        is_package = Path(record.path).stem == "__init__"
        package = source_module if is_package else source_module.rpartition(".")[0]
        for node in ast.walk(tree):
            targets: list[str] = []
            import_text = ""
            if isinstance(node, ast.Import):
                for alias in node.names:
                    import_text = alias.name
                    targets.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                import_text = "." * node.level + (node.module or "")
                if node.level:
                    if not package:
                        unresolved.append({
                            "source": source_module, "path": record.path,
                            "line": node.lineno, "import": import_text,
                            "reason": "relative_import_without_package_context",
                            "confidence": "UNKNOWN",
                        })
                        continue
                    try:
                        base = resolve_name(import_text, package)
                    except ImportError:
                        unresolved.append({
                            "source": source_module, "path": record.path,
                            "line": node.lineno, "import": import_text,
                            "reason": "relative_import_resolution_failed",
                            "confidence": "UNKNOWN",
                        })
                        continue
                else:
                    base = node.module or ""
                if base:
                    targets.append(base)
                # "from package import child" may refer to a real local submodule.
                for alias in node.names:
                    if alias.name != "*":
                        targets.append(f"{base}.{alias.name}" if base else alias.name)

            for target in sorted(set(targets)):
                if target in unique_modules:
                    target_module = target
                elif target in duplicate_modules:
                    unresolved.append({
                        "source": source_module, "path": record.path,
                        "line": node.lineno, "import": target,
                        "reason": "ambiguous_duplicate_module",
                        "candidates": duplicate_modules[target],
                        "confidence": "UNKNOWN",
                    })
                    continue
                else:
                    unresolved.append({
                        "source": source_module, "path": record.path,
                        "line": node.lineno, "import": target or import_text,
                        "reason": "not_resolved_to_inventoried_module",
                        "confidence": "UNKNOWN",
                    })
                    continue
                edge = {
                    "source": source_module,
                    "target": target_module,
                    "source_path": record.path,
                    "target_path": unique_modules[target_module],
                    "line": node.lineno,
                    "import": import_text,
                    "confidence": "CONFIRMED",
                }
                if edge not in edges:
                    edges.append(edge)
                    adjacency[source_module].add(target_module)
                    findings.append(Finding(
                        "dependency",
                        f"Internal Python dependency: {source_module} -> {target_module}",
                        f"Static import resolves to an inventoried module at line {node.lineno}.",
                        confidence="CONFIRMED",
                        evidence=[f"{record.path}:{node.lineno}", unique_modules[target_module]],
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
        findings.append(Finding(
            "architecture",
            "Python circular dependency: " + " <-> ".join(component),
            f"Static import graph contains a strongly connected component of {len(component)} modules.",
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer="python-module-graph",
        ))

    graph = {
        "modules": [
            {"name": name, "path": path, "confidence": "CONFIRMED"}
            for name, path in sorted(unique_modules.items())
        ],
        "duplicate_modules": duplicate_modules,
        "edges": edges,
        "unresolved_imports": unresolved,
        "cycles": cycles,
        "summary": {
            "module_count": len(unique_modules),
            "duplicate_module_count": len(duplicate_modules),
            "edge_count": len(edges),
            "unresolved_import_count": len(unresolved),
            "cycle_count": len(cycles),
        },
    }
    return graph, findings
