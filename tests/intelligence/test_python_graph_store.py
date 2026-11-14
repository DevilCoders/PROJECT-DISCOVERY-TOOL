"""The Python dependency graph backed by the scan store: same graph, no in-memory lists, no low caps."""
from __future__ import annotations

import json
from pathlib import Path

from project_discovery.intelligence import python_graph
from project_discovery.intelligence.python_graph import analyze_python_dependencies
from project_discovery.inventory.store import InventoryStore, StoredRows
from project_discovery.models import FileRecord, ScanResult


def _records(paths: list[str]) -> list[FileRecord]:
    return [FileRecord(path, 10, Path(path).suffix, "Python") for path in paths]


def _materialized(graph: dict) -> dict:
    return {key: list(value) if isinstance(value, StoredRows) else value for key, value in graph.items()}


def _parser(imports: dict[str, list[tuple]]):
    # (line, level, module, names, is_import) statements per path; anything else unreadable.
    def parse(items):
        for record in items:
            statements = imports.get(record.path)
            yield ("ok", statements) if statements is not None else ("parse_error", "SyntaxError", 3)
    return parse


def test_the_store_backed_graph_equals_the_in_memory_graph(tmp_path: Path):
    paths = ["pkg/__init__.py", "pkg/alpha.py", "pkg/beta.py", "pkg/gamma.py", "pkg/broken.py",
             "one/util.py", "two/util.py", "big.py"]
    imports = {
        "pkg/__init__.py": [(1, 1, None, ("alpha",), False)],
        "pkg/alpha.py": [(1, 0, None, ("pkg.beta",), True), (2, 0, None, ("requests",), True),
                         (3, 0, None, ("pkg.beta",), True)],
        "pkg/beta.py": [(1, 0, None, ("pkg.alpha",), True), (2, 0, None, ("pkg.gamma",), True),
                        (4, 0, None, ("one.util",), True)],
        "pkg/gamma.py": [(7, 2, None, ("x",), False)],
        "one/util.py": [],
        "two/util.py": [],
    }
    records = _records(paths)
    records[-1].size_bytes = python_graph.MAX_GRAPH_AST_FILE_BYTES + 1  # skipped by its budget
    memory_graph, memory_findings = analyze_python_dependencies(tmp_path, records, import_parser=_parser(imports))
    stored_findings = []
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        stored_graph, _ = analyze_python_dependencies(
            tmp_path, records, import_parser=_parser(imports), store=store, finding_sink=stored_findings.append)
        assert isinstance(stored_graph["edges"], StoredRows) and isinstance(stored_graph["modules"], StoredRows)
        assert _materialized(stored_graph) == memory_graph
    assert [item.title for item in stored_findings] == [item.title for item in memory_findings]
    assert memory_graph["cycles"] == [["pkg.alpha", "pkg.beta"]]
    assert memory_graph["summary"]["graph_complete"] is False  # big.py and broken.py
    # A rebuilt graph replaces the store's rows of an earlier scan instead of adding to them.
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        again, _ = analyze_python_dependencies(tmp_path, records, import_parser=_parser(imports), store=store,
                                               finding_sink=lambda finding: None)
        assert len(again["edges"]) == memory_graph["summary"]["edge_count"]


def test_a_store_backed_graph_is_complete_past_the_in_memory_ceilings(tmp_path: Path):
    count = python_graph.MAX_GRAPH_MODULES + 5_000
    paths = [f"pkg/m{index:05d}.py" for index in range(count)]
    imports = {
        path: [(line, 0, None, (f"pkg.m{target:05d}",), True)
               for line, target in enumerate(range(index + 1, min(index + 4, count)), start=1)]
        for index, path in enumerate(paths)
    }
    imports[paths[1]].append((9, 0, None, ("pkg.m00000",), True))  # m0 <-> m1
    expected_edges = sum(len(statements) for statements in imports.values())
    findings = []
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        graph, _ = analyze_python_dependencies(tmp_path, _records(paths), import_parser=_parser(imports),
                                               store=store, finding_sink=findings.append)
        summary = graph["summary"]
        assert (summary["module_count"], summary["edge_count"], summary["graph_complete"]) == (count, expected_edges, True)
        # Without pkg/__init__.py the modules are shown by their import names (m00000).
        assert len(graph["edges"]) == expected_edges and graph["cycles"] == [["m00000", "m00001"]]
        first = next(iter(graph["edges"]))
        assert (first["source"], first["target"], first["line"]) == ("m00000", "m00001", 1)
    cycle = [item for item in findings if item.title.startswith("Python circular dependency")]
    assert len(cycle) == 1 and cycle[0].evidence == ["pkg/m00000.py:1", "pkg/m00001.py:9"]
    # Without a store the same input reaches the in-memory module ceiling and says so.
    memory, _ = analyze_python_dependencies(tmp_path, _records(paths), import_parser=_parser(imports),
                                            finding_sink=lambda finding: None)
    assert memory["summary"]["module_limit_reached"] is True and memory["summary"]["graph_complete"] is False


def test_reports_stream_the_stored_graph_and_bound_it_in_html(tmp_path: Path, monkeypatch):
    from project_discovery.cli import run_scan
    from project_discovery.reporting import writers

    project = tmp_path / "project"
    (project / "pkg").mkdir(parents=True)
    (project / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (project / "pkg" / "a.py").write_text("import pkg.b\nimport pkg.c\n", encoding="utf-8")
    (project / "pkg" / "b.py").write_text("import pkg.c\n", encoding="utf-8")
    (project / "pkg" / "c.py").write_text("", encoding="utf-8")
    monkeypatch.setitem(writers.HTML_MAX_EMBEDDED, "graph_rows", 1)
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "html"}, 128, quiet=True) == 0
    graph = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["python_dependency_graph"]
    assert [(edge["source"], edge["target"]) for edge in graph["edges"]] == [
        ("pkg.a", "pkg.b"), ("pkg.a", "pkg.c"), ("pkg.b", "pkg.c")]
    assert graph["summary"]["edge_count"] == 3 and len(graph["modules"]) == 4
    html = (output / "discovery-report.html").read_text(encoding="utf-8")
    payload, _ = json.JSONDecoder().raw_decode(html.split("const REPORT = ", 1)[1])
    embedded = payload["metrics"]["python_dependency_graph"]
    assert len(embedded["edges"]) == 1 and embedded["summary"]["edge_count"] == 3
    assert payload["embedded_limits"]["graph_rows"] == 1


def test_scan_results_materialize_stored_rows_for_to_dict(tmp_path: Path):
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        store.append("graph_edge", {"path": "k", "row": {"source": "a", "target": "b"}}, sort_key="a")
        store.flush()
    rows = StoredRows(tmp_path / "inventory.sqlite3", "graph_edge")
    result = ScanResult(root="r", started_at="s", finished_at="f", files=[], findings=[],
                        metrics={"python_dependency_graph": {"edges": rows, "summary": {"edge_count": 1}}})
    data = result.to_dict()
    assert json.loads(json.dumps(data["metrics"]))["python_dependency_graph"]["edges"] == [{"source": "a", "target": "b"}]
    assert rows[0] == {"source": "a", "target": "b"} and rows[-1] == rows[0] and rows[0:1] == [rows[0]]
