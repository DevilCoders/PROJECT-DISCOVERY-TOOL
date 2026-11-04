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
    assert result["summary"]["graph_complete"] is False
    assert result["summary"]["graph_complete"] is False
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

def test_graph_detects_source_growth_after_inventory(tmp_path: Path, monkeypatch):
    from project_discovery import python_graph

    path = tmp_path / "growing.py"
    path.write_text("import os\\n", encoding="utf-8")
    monkeypatch.setattr(python_graph, "MAX_GRAPH_AST_FILE_BYTES", 8)
    record = FileRecord(path.name, 1, ".py", "Python")
    graph, findings = analyze_python_dependencies(tmp_path, [record])
    assert graph["unresolved_imports"][0]["reason"] == "source_budget_exceeded"
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)


def test_graph_reports_unknown_when_source_grows_after_inventory(tmp_path: Path, monkeypatch):
    from project_discovery import python_graph

    path = tmp_path / "growing.py"
    path.write_text("import os\n", encoding="utf-8")
    record = _record(tmp_path, "growing.py")
    record.size_bytes = 1
    monkeypatch.setattr(python_graph, "MAX_GRAPH_AST_FILE_BYTES", 4)

    graph, findings = analyze_python_dependencies(tmp_path, [record])

    assert graph["summary"]["edge_count"] == 0
    assert any(
        item["reason"] == "source_budget_exceeded"
        for item in graph["unresolved_imports"]
    )
    assert any(item.confidence == "UNKNOWN" for item in findings)



def test_graph_marks_partial_when_module_budget_is_reached(tmp_path: Path, monkeypatch):
    from project_discovery import python_graph

    (tmp_path / "alpha.py").write_text("import beta\n", encoding="utf-8")
    (tmp_path / "beta.py").write_text("value = 1\n", encoding="utf-8")
    records = [_record(tmp_path, "alpha.py"), _record(tmp_path, "beta.py")]
    monkeypatch.setattr(python_graph, "MAX_GRAPH_MODULES", 1)

    graph, findings = analyze_python_dependencies(tmp_path, records)

    assert graph["summary"]["module_limit_reached"] is True
    assert graph["summary"]["omitted_module_record_count"] == 1
    assert graph["summary"]["graph_complete"] is False
    assert any(
        item.confidence == "UNKNOWN"
        and "resource limit" in item.title.lower()
        for item in findings
    )


def test_graph_marks_partial_when_edge_budget_is_reached(tmp_path: Path, monkeypatch):
    from project_discovery import python_graph

    (tmp_path / "alpha.py").write_text("import beta\nimport gamma\n", encoding="utf-8")
    (tmp_path / "beta.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "gamma.py").write_text("value = 2\n", encoding="utf-8")
    records = [
        _record(tmp_path, "alpha.py"),
        _record(tmp_path, "beta.py"),
        _record(tmp_path, "gamma.py"),
    ]
    monkeypatch.setattr(python_graph, "MAX_GRAPH_EDGES", 1)

    graph, findings = analyze_python_dependencies(tmp_path, records)

    assert graph["summary"]["edge_count"] == 1
    assert graph["summary"]["edge_limit_reached"] is True
    assert graph["summary"]["omitted_edge_candidate_count"] == 1
    assert graph["summary"]["graph_complete"] is False
    assert any(item.confidence == "UNKNOWN" for item in findings)


def test_graph_streams_findings_to_sink_without_returning_local_list(tmp_path: Path):
    (tmp_path / "alpha.py").write_text("import beta\n", encoding="utf-8")
    (tmp_path / "beta.py").write_text("value = 1\n", encoding="utf-8")
    records = [_record(tmp_path, "alpha.py"), _record(tmp_path, "beta.py")]
    persisted = []

    graph, returned_findings = analyze_python_dependencies(
        tmp_path, records, finding_sink=persisted.append,
    )

    assert graph["summary"]["edge_count"] == 1
    assert returned_findings == []
    assert any(
        item.title == "Internal Python dependency: alpha -> beta"
        for item in persisted
    )



def test_graph_marks_partial_when_unresolved_import_budget_is_reached(
    tmp_path: Path, monkeypatch,
):
    from project_discovery import python_graph

    path = tmp_path / "alpha.py"
    path.write_text("import external_one\nimport external_two\n", encoding="utf-8")
    record = _record(tmp_path, "alpha.py")
    monkeypatch.setattr(python_graph, "MAX_GRAPH_UNRESOLVED", 1)

    graph, findings = analyze_python_dependencies(tmp_path, [record])

    assert graph["summary"]["unresolved_limit_reached"] is True
    assert graph["summary"]["unresolved_import_count"] == 1
    assert graph["summary"]["omitted_unresolved_import_count"] == 1
    assert graph["summary"]["graph_complete"] is False
    assert any(item.confidence == "UNKNOWN" for item in findings)



def test_graph_marks_partial_when_duplicate_module_candidates_are_capped(
    tmp_path: Path, monkeypatch,
):
    from project_discovery import python_graph

    (tmp_path / "pkg.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("value = 2\n", encoding="utf-8")
    records = [
        _record(tmp_path, "pkg.py"),
        _record(tmp_path, "pkg/__init__.py"),
    ]
    monkeypatch.setattr(python_graph, "MAX_DUPLICATE_MODULE_PATHS", 1)

    graph, findings = analyze_python_dependencies(tmp_path, records)

    assert graph["summary"]["duplicate_module_count"] == 1
    assert graph["summary"]["duplicate_module_candidate_omitted_count"] == 1
    assert graph["summary"]["graph_complete"] is False
    assert any(
        item.confidence == "UNKNOWN" and "resource limit" in item.title.lower()
        for item in findings
    )


def _write(root: Path, files: dict[str, str]) -> list[FileRecord]:
    for relative, text in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    return [_record(root, relative) for relative in files]


def test_absolute_imports_resolve_through_src_layout_package_roots(tmp_path: Path):
    # Regression: module names were derived from the repository root ("src.pkg.a"), so
    # absolute imports of "pkg.a" in a src/ layout never resolved.
    records = _write(tmp_path, {
        "src/pkg/__init__.py": "",
        "src/pkg/a.py": "from pkg import b\nfrom pkg.b import helper\n",
        "src/pkg/b.py": "def helper():\n    return 1\n",
        "tests/test_a.py": "import pkg.a\nfrom pkg.b import helper\nimport json\n",
    })
    graph, _ = analyze_python_dependencies(tmp_path, records)
    edges = {(edge["source"], edge["target"]) for edge in graph["edges"]}
    assert ("src.pkg.a", "src.pkg.b") in edges
    assert ("tests.test_a", "src.pkg.a") in edges
    assert ("tests.test_a", "src.pkg.b") in edges
    unresolved = {item["import"] for item in graph["unresolved_imports"]}
    assert unresolved == {"json"}


def test_package_aliases_shared_by_several_subprojects_are_ambiguous(tmp_path: Path):
    records = _write(tmp_path, {
        "one/pkgx/__init__.py": "",
        "one/pkgx/mod.py": "",
        "two/pkgx/__init__.py": "",
        "two/pkgx/mod.py": "",
        "app.py": "import pkgx.mod\n",
    })
    graph, _ = analyze_python_dependencies(tmp_path, records)
    assert not [edge for edge in graph["edges"] if edge["source"] == "app"]
    ambiguous = [item for item in graph["unresolved_imports"] if item["reason"] == "ambiguous_package_alias"]
    assert ambiguous and ambiguous[0]["candidates"] == ["one.pkgx.mod", "two.pkgx.mod"]
