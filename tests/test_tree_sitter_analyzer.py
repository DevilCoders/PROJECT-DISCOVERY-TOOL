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
    import project_discovery.analyzers.tree_sitter_analyzer as module

    module._CAPABILITY_CACHE.clear()
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
    assert analyzer.supports(record) is False
    findings = analyzer.analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "does not download" in findings[0].detail


def test_analyzer_reports_unprovisioned_grammar_without_network(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.tree_sitter_analyzer as module

    module._CAPABILITY_CACHE.clear()
    path = tmp_path / "sample.rs"
    path.write_text("fn main() {}", encoding="utf-8")
    record = _record("Rust")
    pack = SimpleNamespace(has_parser=lambda _: False)
    monkeypatch.setattr(module.importlib, "import_module", lambda _: pack)
    assert module.TreeSitterAnalyzer().supports(record) is False
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


def test_parser_capability_check_does_not_download(monkeypatch):
    import project_discovery.analyzers.tree_sitter_analyzer as module

    module._CAPABILITY_CACHE.clear()

    class OfflinePack:
        @staticmethod
        def has_parser(_grammar):
            return False

    monkeypatch.setattr(module.importlib, "import_module", lambda _: OfflinePack)
    capabilities = module.parser_capabilities({"Rust"})
    assert capabilities["Rust"] == "grammar_not_provisioned"


def test_language_specific_declaration_extraction():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_declarations

    point = SimpleNamespace(row=4, column=0)
    name = SimpleNamespace(type="identifier", text=b"run", children=[])
    declaration = SimpleNamespace(
        type="function_item",
        children=[name],
        start_point=point,
        child_by_field_name=lambda field: name if field == "name" else None,
    )
    root = SimpleNamespace(type="source_file", children=[declaration])
    symbols = _extract_declarations(root, "rust")
    assert symbols == [{
        "kind": "function",
        "name": "run",
        "node_type": "function_item",
        "line": 5,
    }]


def test_unmapped_grammar_returns_no_semantic_claims():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_declarations

    root = SimpleNamespace(type="program", children=[])
    assert _extract_declarations(root, "unmapped_grammar") == []


def test_generic_declaration_fallback_covers_unmapped_grammar():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_declarations

    point = SimpleNamespace(row=0, column=0)
    name = SimpleNamespace(type="identifier", text=b"Widget", children=[])
    declaration = SimpleNamespace(
        type="class_declaration",
        children=[name],
        start_point=point,
        child_by_field_name=lambda _field: None,
    )
    root = SimpleNamespace(type="program", children=[declaration])
    symbols = _extract_declarations(root, "unmapped_language")
    assert symbols[0]["name"] == "Widget"
    assert symbols[0]["kind"] == "class_declaration"


def test_generic_import_inventory_keeps_resolution_unconfirmed():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_imports

    point = SimpleNamespace(row=2, column=0)
    leaf = SimpleNamespace(type="string", text=b'"react"', children=[])
    statement = SimpleNamespace(
        type="import_statement",
        text=b'import React from "react";',
        children=[leaf],
        start_point=point,
    )
    root = SimpleNamespace(type="program", children=[statement])
    imports = _extract_imports(root, "javascript")
    assert imports == [{
        "target": "react",
        "line": 3,
        "node_type": "import_statement",
    }]


def test_import_inventory_skips_unmapped_language():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_imports

    root = SimpleNamespace(type="program", children=[])
    assert _extract_imports(root, "unknown") == []


def test_generic_import_node_fallback_supports_additional_grammars():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_imports

    point = SimpleNamespace(row=0, column=0)
    imported = SimpleNamespace(
        type="module_import",
        text=b'import "std/io";',
        children=[],
        start_point=point,
    )
    use = SimpleNamespace(
        type="use_declaration",
        text=b"use std::collections;",
        children=[],
        start_point=point,
    )
    include = SimpleNamespace(
        type="include_directive",
        text=b'include "config.inc"',
        children=[],
        start_point=point,
    )
    root = SimpleNamespace(type="source_file", children=[imported, use, include])

    imports = _extract_imports(root, "grammar_not_in_explicit_map")

    assert {item["target"] for item in imports} == {
        "std/io", "std::collections", "config.inc"
    }


def test_grammar_mapping_covers_sixty_plus_languages_and_matches_recognition_catalog():
    from project_discovery.language_catalog import language_catalog

    recognized = {item["name"] for item in language_catalog()}
    assert len(GRAMMARS) >= 60
    assert set(GRAMMARS) <= recognized


def test_generic_import_inventory_covers_use_statement_nodes():
    from types import SimpleNamespace
    from project_discovery.analyzers.tree_sitter_analyzer import _extract_imports

    point = SimpleNamespace(row=4, column=0)
    statement = SimpleNamespace(
        type="use_statement", text=b"use Ada.Text_IO;", children=[], start_point=point,
    )
    root = SimpleNamespace(type="source_file", children=[statement])

    imports = _extract_imports(root, "grammar_without_explicit_import_map")

    assert imports == [{
        "target": "Ada.Text_IO", "line": 5, "node_type": "use_statement",
    }]
