from project_discovery.language_catalog import detect_language, language_catalog


def test_ambiguous_extensions_are_not_misclassified():
    assert detect_language("legacy/module.m") == "Objective-C / MATLAB (ambiguous)"
    assert detect_language("rtl/top.v") == "V / Verilog (ambiguous)"


def test_catalog_reports_optional_parser_backend():
    entries = {item["name"]: item for item in language_catalog()}
    assert entries["Python"]["analysis_status"] == "implemented"
    assert entries["Rust"]["parser_backend"] == "optional:tree-sitter-language-pack"
    assert entries["Rust"]["analysis_status"] == "optional_parser"
