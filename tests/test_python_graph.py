from pathlib import Path

from project_discovery.models import FileRecord
from project_discovery.python_graph import (
    _strongly_connected_components,
    analyze_python_dependencies,
)


def _record(root: Path, relative: str) -> FileRecord:
    path = root / relative
    return FileRecord(relative, path.stat().st_size, path.suffix, "Python")


def test_graph_resolves_absolute_and_relative_imports(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("from . import service\n", encoding="utf-8")
    (package / "service.py").write_text("from pkg.helpers import work\n", encoding="utf-8")
    (package / "helpers.py").write_text("def work():\n    return None\n", encoding="utf-8")
    records = [
        _record(tmp_path, "pkg/__init__.py"),
        _record(tmp_path, "pkg/service.py"),
        _record(tmp_path, "pkg/helpers.py"),
    ]

    graph, findings = analyze_python_dependencies(tmp_path, records)

    assert graph["summary"]["module_count"] == 3
    assert graph["summary"]["edge_count"] == 2
    assert {edge["target"] for edge in graph["edges"]} == {"pkg.service", "pkg.helpers"}
    assert all(edge["confidence"] == "CONFIRMED" for edge in graph["edges"])
    assert any(item.title.startswith("Internal Python dependency:") for item in findings)


def test_graph_detects_cycles_and_preserves_unknown_imports(tmp_path: Path):
    (tmp_path / "alpha.py").write_text("import beta\nimport requests\n", encoding="utf-8")
    (tmp_path / "beta.py").write_text("from alpha import run\n", encoding="utf-8")
    records = [_record(tmp_path, "alpha.py"), _record(tmp_path, "beta.py")]

    graph, findings = analyze_python_dependencies(tmp_path, records)

    assert graph["cycles"] == [["alpha", "beta"]]
    assert graph["summary"]["edge_count"] == 2
    assert any(item["import"] == "requests" for item in graph["unresolved_imports"])
    assert any(item.title.startswith("Python circular dependency:") for item in findings)


def test_graph_skips_oversized_or_unreadable_records(tmp_path: Path):
    (tmp_path / "ignored.py").write_text("import os\n", encoding="utf-8")
    record = _record(tmp_path, "ignored.py")
    record.error = "oversized"

    graph, findings = analyze_python_dependencies(tmp_path, [record])

    assert graph["modules"] == []
    assert graph["edges"] == []
    assert findings == []


def test_scc_traversal_handles_deep_graphs_without_recursion():
    nodes = [f"module_{index}" for index in range(1500)]
    adjacency = {node: set() for node in nodes}
    for index in range(len(nodes) - 1):
        adjacency[nodes[index]].add(nodes[index + 1])
    adjacency[nodes[-1]].add(nodes[0])

    components = _strongly_connected_components(nodes, adjacency)
    assert len(components) == 1
    assert set(components[0]) == set(nodes)



def test_graph_records_explicitly_skipped_modules_as_unknown(tmp_path: Path):
    path = tmp_path / "large.py"
    path.write_text("import os\n", encoding="utf-8")
    record = _record(tmp_path, "large.py")
    record.content_skipped_reason = "Explicit --skip"
    result, findings = analyze_python_dependencies(tmp_path, [record])
    assert result["modules"] == []
    assert result["skipped_modules"][0]["name"] == "large"
    assert result["summary"]["skipped_module_count"] == 1
    assert findings[0].confidence == "UNKNOWN"


def test_graph_applies_independent_ast_resource_budget(tmp_path: Path):
    path = tmp_path / "large.py"
    path.write_text("import os\n", encoding="utf-8")
    record = _record(tmp_path, "large.py")
    record.size_bytes = 20 * 1024 * 1024
    result, findings = analyze_python_dependencies(tmp_path, [record])
    assert result["summary"]["skipped_module_count"] == 1
    assert findings[0].confidence == "UNKNOWN"
