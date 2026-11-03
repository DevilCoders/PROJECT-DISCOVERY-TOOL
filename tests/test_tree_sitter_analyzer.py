from pathlib import Path
from types import SimpleNamespace

from project_discovery.analyzers.tree_sitter_analyzer import (
    GRAMMARS,
    TreeSitterAnalyzer,
)
from project_discovery.models import FileRecord


def _record(language: str) -> FileRecord:
    return FileRecord("sample.src", 12, ".src", language)


def test_polyglot_adapter_maps_more_than_forty_languages():
    assert len(GRAMMARS) >= 40
    assert GRAMMARS["Rust"] == "rust"
    assert GRAMMARS["TypeScript"] == "typescript"
    assert GRAMMARS["C++"] == "cpp"
    assert GRAMMARS["CUDA"] == "cuda"


def test_analyzer_reports_missing_optional_dependency(tmp_path: Path, monkeypatch):
    import builtins

    path = tmp_path / "sample.rs"
    path.write_text("fn main() {}", encoding="utf-8")
    record = _record("Rust")
    record.path = "sample.rs"
    analyzer = TreeSitterAnalyzer()
    original_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "tree_sitter_language_pack":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    findings = analyzer.analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "does not download" in findings[0].detail


def test_analyzer_reports_unprovisioned_grammar_without_network(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.tree_sitter_analyzer as module

    path = tmp_path / "sample.rs"
    path.write_text("fn main() {}", encoding="utf-8")
    record = _record("Rust")
    pack = SimpleNamespace(has_parser=lambda _: False)
    monkeypatch.setattr(module.importlib, "import_module", lambda _: pack)
    findings = module.TreeSitterAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "No network download" in findings[0].detail


def test_iterative_tree_walker_summarizes_nested_nodes():
    from project_discovery.analyzers.tree_sitter_analyzer import _walk_tree

    point = SimpleNamespace(row=0, column=0)
    leaf = SimpleNamespace(
        type="identifier", children=[], is_error=False, is_missing=False,
        start_point=point,
    )
    root = SimpleNamespace(
        type="module", children=[leaf], is_error=False, is_missing=False,
        start_point=point,
    )
    node_count, max_depth, errors, top_level = _walk_tree(root)
    assert node_count == 2
    assert max_depth == 1
    assert errors == []
    assert top_level == ["identifier"]
