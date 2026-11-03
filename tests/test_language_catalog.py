from project_discovery.language_catalog import detect_language, language_catalog


def test_ambiguous_extensions_are_not_misclassified():
    assert detect_language("legacy/module.m") == "Objective-C / MATLAB (ambiguous)"
    assert detect_language("rtl/top.v") == "V / Verilog (ambiguous)"
    assert detect_language("game/player.gd") == "GDScript"
    assert detect_language("game/Scenes/Main.tscn") == "Godot Scene"
    assert detect_language("Unreal/Content/Map.umap") == "Unreal Binary Asset"


def test_catalog_reports_optional_parser_backend():
    entries = {item["name"]: item for item in language_catalog()}
    assert entries["Python"]["analysis_status"] == "implemented"
    assert entries["Rust"]["parser_backend"] == "optional:tree-sitter-language-pack"
    assert entries["Rust"]["analysis_status"] == "optional_parser"



def test_source_and_text_families_are_explicit_and_broad():
    from project_discovery.language_catalog import (
        is_source_path,
        is_textual_path,
        source_extensions,
        source_language_names,
    )

    assert len(source_language_names()) >= 40
    assert len(source_extensions()) >= 40
    for path in (
        "src/core.rs", "src/agent.jl", "firmware/main.cob",
        "gpu/kernel.cu", "shaders/main.wgsl", "contracts/token.sol",
        "rtl/top.vhd", "src/runtime.ex",
    ):
        assert is_source_path(path), path
        assert is_textual_path(path), path


def test_binary_document_formats_are_not_selected_for_text_scanning():
    from project_discovery.language_catalog import is_textual_path

    assert is_textual_path("docs/guide.md")
    assert is_textual_path("config/settings.yaml")
    assert not is_textual_path("docs/manual.pdf")
    assert not is_textual_path("docs/specification.docx")
    assert not is_textual_path("Unreal/Content/Map.umap")
    assert is_textual_path("Unreal/Config/Game.uproject")


def test_component_and_localization_formats_are_recognized_as_text():
    from project_discovery.language_catalog import is_source_path, is_textual_path

    assert detect_language("web/App.vue") == "Vue"
    assert detect_language("web/Widget.svelte") == "Svelte"
    assert detect_language("web/Page.astro") == "Astro"
    assert is_source_path("web/App.vue")
    assert is_source_path("web/Widget.svelte")
    assert is_source_path("web/Page.astro")
    for path in (
        "locale/fr/app.po", "lib/l10n/app_en.arb",
        "Resources/en.lproj/Localizable.strings", "locales/en/app.ftl",
    ):
        assert is_textual_path(path), path
