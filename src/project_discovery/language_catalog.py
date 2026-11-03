"""Central language and file-format recognition catalog.

Recognition is deliberately separate from parser support: identifying a file's
language does not imply that PDT can fully parse or semantically analyze it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    name: str
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()
    family: str = "source"
    parser_backend: str | None = None


_SPECS = (
    LanguageSpec("Python", (".py", ".pyi"), parser_backend="stdlib:ast"),
    LanguageSpec("Prisma", (".prisma",), family="schema"),
    LanguageSpec("JavaScript", (".js", ".jsx", ".mjs", ".cjs"), parser_backend="optional:tree-sitter"),
    LanguageSpec("TypeScript", (".ts", ".tsx", ".mts", ".cts"), parser_backend="optional:tree-sitter"),
    LanguageSpec("Rust", (".rs",), parser_backend="optional:tree-sitter"),
    LanguageSpec("Go", (".go",), parser_backend="optional:tree-sitter"),
    LanguageSpec("C", (".c",), parser_backend="optional:tree-sitter"),
    LanguageSpec("C++", (".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ipp")),
    LanguageSpec("C/C++ Header", (".h", ".inc")),
    LanguageSpec("Objective-C", (".m",)),
    LanguageSpec("Objective-C++", (".mm",)),
    LanguageSpec("Java", (".java",), parser_backend="optional:tree-sitter"),
    LanguageSpec("Kotlin", (".kt", ".kts")),
    LanguageSpec("Swift", (".swift",)),
    LanguageSpec("C#", (".cs",)),
    LanguageSpec("F#", (".fs", ".fsi", ".fsx")),
    LanguageSpec("Visual Basic .NET", (".vb",)),
    LanguageSpec("Dart", (".dart",)),
    LanguageSpec("Ruby", (".rb", ".rake", ".gemspec")),
    LanguageSpec("PHP", (".php", ".phtml")),
    LanguageSpec("Perl", (".pl", ".pm", ".t")),
    LanguageSpec("R", (".r", ".R")),
    LanguageSpec("Julia", (".jl",)),
    LanguageSpec("Lua", (".lua",)),
    LanguageSpec("Shell", (".sh", ".bash", ".zsh", ".fish")),
    LanguageSpec("PowerShell", (".ps1", ".psm1", ".psd1")),
    LanguageSpec("Batch", (".bat", ".cmd")),
    LanguageSpec("Elixir", (".ex", ".exs")),
    LanguageSpec("Erlang", (".erl", ".hrl")),
    LanguageSpec("Haskell", (".hs", ".lhs")),
    LanguageSpec("OCaml", (".ml", ".mli")),
    LanguageSpec("ReasonML", (".re", ".rei")),
    LanguageSpec("Clojure", (".clj", ".cljs", ".cljc", ".edn")),
    LanguageSpec("Scala", (".scala", ".sc")),
    LanguageSpec("Groovy", (".groovy", ".gradle")),
    LanguageSpec("C", (".h",), family="header"),
    LanguageSpec("Fortran", (".f", ".for", ".f90", ".f95", ".f03", ".f08")),
    LanguageSpec("COBOL", (".cob", ".cbl", ".cpy")),
    LanguageSpec("Pascal", (".pas", ".pp")),
    LanguageSpec("Ada", (".adb", ".ads")),
    LanguageSpec("Zig", (".zig",)),
    LanguageSpec("Nim", (".nim", ".nims")),
    LanguageSpec("Crystal", (".cr",)),
    LanguageSpec("D", (".d", ".di")),
    LanguageSpec("Odin", (".odin",)),
    LanguageSpec("V", (".v",)),
    LanguageSpec("Verilog", (".v", ".vh")),
    LanguageSpec("SystemVerilog", (".sv", ".svh")),
    LanguageSpec("VHDL", (".vhd", ".vhdl")),
    LanguageSpec("Solidity", (".sol",)),
    LanguageSpec("Move", (".move",)),
    LanguageSpec("SQL", (".sql",)),
    LanguageSpec("PL/SQL", (".pls", ".pks", ".pkb")),
    LanguageSpec("HTML", (".html", ".htm"), family="markup"),
    LanguageSpec("Vue", (".vue",), family="source"),
    LanguageSpec("Svelte", (".svelte",), family="source"),
    LanguageSpec("Astro", (".astro",), family="source"),
    LanguageSpec("CSS", (".css",), family="stylesheet"),
    LanguageSpec("SCSS", (".scss",), family="stylesheet"),
    LanguageSpec("Sass", (".sass",), family="stylesheet"),
    LanguageSpec("Less", (".less",), family="stylesheet"),
    LanguageSpec("XML", (".xml", ".xsd", ".xsl", ".xslt"), family="markup"),
    LanguageSpec("XAML", (".xaml",), family="markup"),
    LanguageSpec("Markdown", (".md", ".markdown"), family="documentation"),
    LanguageSpec("Gettext PO", (".po", ".pot"), family="localization"),
    LanguageSpec("XLIFF", (".xlf", ".xliff"), family="localization"),
    LanguageSpec("ARB", (".arb",), family="localization"),
    LanguageSpec("Apple Strings", (".strings",), family="localization"),
    LanguageSpec("Fluent", (".ftl",), family="localization"),
    LanguageSpec("RESX", (".resx",), family="localization"),
    LanguageSpec("reStructuredText", (".rst",), family="documentation"),
    LanguageSpec("AsciiDoc", (".adoc", ".asciidoc"), family="documentation"),
    LanguageSpec("LaTeX", (".tex", ".sty", ".cls"), family="documentation"),
    LanguageSpec("JSON", (".json", ".jsonc", ".json5"), family="data"),
    LanguageSpec("YAML", (".yaml", ".yml"), family="data"),
    LanguageSpec("TOML", (".toml",), family="data"),
    LanguageSpec("INI", (".ini", ".cfg"), family="configuration"),
    LanguageSpec("Protocol Buffers", (".proto",), family="schema"),
    LanguageSpec("GraphQL", (".graphql", ".gql"), family="schema"),
    LanguageSpec("Thrift", (".thrift",), family="schema"),
    LanguageSpec("Avro IDL", (".avdl",), family="schema"),
    LanguageSpec("HCL", (".hcl", ".tf", ".tfvars"), family="configuration"),
    LanguageSpec("Nix", (".nix",), family="configuration"),
    LanguageSpec("Dockerfile", filenames=("Dockerfile", "Containerfile"), family="configuration"),
    LanguageSpec("Makefile", filenames=("Makefile", "GNUmakefile"), family="build"),
    LanguageSpec("CMake", (".cmake",), filenames=("CMakeLists.txt",), family="build"),
    LanguageSpec("Meson", (".build",), filenames=("meson.build",), family="build"),
    LanguageSpec("Assembly", (".s", ".S", ".asm"), family="low_level"),
    LanguageSpec("CUDA", (".cu", ".cuh"), family="gpu"),
    LanguageSpec("OpenCL", (".cl",), family="gpu"),
    LanguageSpec("GLSL", (".glsl", ".vert", ".frag", ".geom", ".tesc", ".tese"), family="shader"),
    LanguageSpec("HLSL", (".hlsl", ".fx", ".fxh"), family="shader"),
    LanguageSpec("WGSL", (".wgsl",), family="shader"),
    LanguageSpec("Metal Shading Language", (".metal",), family="shader"),
    LanguageSpec("Jupyter Notebook", (".ipynb",), family="notebook"),
    LanguageSpec("PDF", (".pdf",), family="document"),
    LanguageSpec("Word Document", (".docx",), family="document"),
    LanguageSpec("Text", (".txt",), family="documentation"),
    LanguageSpec("GDScript", (".gd",), family="game_source"),
    LanguageSpec("Godot Scene", (".tscn",), family="game_source"),
    LanguageSpec("Godot Resource", (".tres",), family="game_source"),
    LanguageSpec("Godot Shader", (".gdshader",), family="shader"),
    LanguageSpec("Unity Scene", (".unity",), family="game_source"),
    LanguageSpec("Unity Prefab", (".prefab",), family="game_source"),
    LanguageSpec("Unity Asset YAML", (".asset",), family="game_source"),
    LanguageSpec("Unreal Project", (".uproject", ".uplugin"), family="configuration"),
    LanguageSpec("Unreal Binary Asset", (".uasset", ".umap"), family="binary_asset"),
    LanguageSpec("GameMaker Language", (".gml",), family="game_source"),
    LanguageSpec("GameMaker Project", (".yyp", ".yy"), family="game_source"),
    LanguageSpec("Defold Script", (".script",), family="game_source"),
    LanguageSpec("Defold Collection", (".collection",), family="game_source"),
    LanguageSpec("Ren'Py", (".rpy",), family="game_source"),
    LanguageSpec("Roblox XML Model", (".rbxlx", ".rbxmx"), family="game_source"),
    LanguageSpec("LÖVE Configuration", filenames=("conf.lua",), family="build"),
)

_BY_EXTENSION: dict[str, LanguageSpec] = {}
_BY_FILENAME: dict[str, LanguageSpec] = {}
for spec in _SPECS:
    for extension in spec.extensions:
        # Prefer the first unambiguous primary mapping for shared extensions.
        _BY_EXTENSION.setdefault(extension.lower(), spec)
    for filename in spec.filenames:
        _BY_FILENAME.setdefault(filename.lower(), spec)


def detect_language(path: str) -> str:
    """Return a best-effort language/format label for a project-relative path."""
    name = PurePosixPath(path).name
    by_name = _BY_FILENAME.get(name.lower())
    if by_name:
        return by_name.name
    extension = PurePosixPath(name).suffix.lower()
    if extension == ".m":
        return "Objective-C / MATLAB (ambiguous)"
    if extension == ".v":
        return "V / Verilog (ambiguous)"
    return _BY_EXTENSION.get(extension, LanguageSpec("Other")).name


def language_catalog() -> list[dict[str, str | None]]:
    """Return recognition and parser integration metadata."""
    from .analyzers.tree_sitter_analyzer import GRAMMARS

    result = []
    for spec in _SPECS:
        backend = (
            "stdlib:ast" if spec.name == "Python"
            else "optional:tree-sitter-language-pack" if spec.name in GRAMMARS
            else spec.parser_backend
        )
        result.append({
            "name": spec.name,
            "family": spec.family,
            "parser_backend": backend,
            "recognition": "CONFIRMED",
            "analysis_status": (
                "implemented" if spec.name == "Python"
                else "optional_parser" if spec.name in GRAMMARS
                else "inventory_only"
            ),
        })
    return result


def recognized_language_count() -> int:
    return len({spec.name for spec in _SPECS})


# Shared language-family selectors. Recognition does not imply semantic parser support.
_SOURCE_FAMILIES = frozenset({"source", "schema", "low_level", "gpu", "shader", "game_source"})
_TEXT_FAMILIES = frozenset({
    "source", "schema", "markup", "stylesheet", "documentation", "data",
    "configuration", "build", "low_level", "gpu", "shader", "notebook", "game_source", "localization",
})
_EXTRA_TEXT_FILENAMES = frozenset({
    ".env", ".npmrc", ".yarnrc", ".editorconfig", ".gitignore", ".gitattributes",
    ".dockerignore", ".npmignore", ".browserslistrc", ".prettierrc", ".eslintrc",
})
_EXTRA_TEXT_EXTENSIONS = frozenset({".pem", ".key", ".env", ".properties"})


def _spec_for_path(path: str) -> LanguageSpec | None:
    normalized = path.replace("\\", "/")
    name = PurePosixPath(normalized).name
    return _BY_FILENAME.get(name.lower()) or _BY_EXTENSION.get(
        PurePosixPath(name).suffix.lower()
    )


def source_extensions() -> set[str]:
    """Extensions belonging to recognized source, schema, low-level and compute languages."""
    return {
        extension.lower()
        for spec in _SPECS if spec.family in _SOURCE_FAMILIES
        for extension in spec.extensions
    }


def source_language_names() -> tuple[str, ...]:
    """Unique recognized source-language names, excluding documentation and binary formats."""
    return tuple(sorted({
        spec.name for spec in _SPECS if spec.family in _SOURCE_FAMILIES
    }))


def is_source_path(path: str) -> bool:
    """Whether a path maps to a recognized source-like language family."""
    spec = _spec_for_path(path)
    return spec is not None and spec.family in _SOURCE_FAMILIES


def is_textual_path(path: str) -> bool:
    """Whether a recognized path is suitable for bounded UTF-8 text scanning."""
    normalized = path.replace("\\", "/")
    name = PurePosixPath(normalized).name.lower()
    if name in _EXTRA_TEXT_FILENAMES or name.startswith(".env."):
        return True
    if PurePosixPath(name).suffix.lower() in _EXTRA_TEXT_EXTENSIONS:
        return True
    spec = _spec_for_path(normalized)
    return spec is not None and spec.family in _TEXT_FAMILIES


def textual_language_names() -> tuple[str, ...]:
    """Unique recognized textual language and format names."""
    return tuple(sorted({
        spec.name for spec in _SPECS if spec.family in _TEXT_FAMILIES
    }))
