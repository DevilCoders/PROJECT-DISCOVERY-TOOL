"""Offline-first generic syntax analysis through optional Tree-sitter grammars.

The analyzer never downloads grammars. It checks local provisioning before constructing
a parser; users must provision grammar libraries separately before scanning.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

from ...core.source_utils import SourceBudgetExceeded, read_text_bounded, redact_source_excerpt
from ...models import FileRecord, Finding
from ..base import Analyzer

_CAPABILITY_CACHE: dict[str, str] = {}
_MAX_TREE_SITTER_FILE_BYTES = 16 * 1024 * 1024


GRAMMARS = {
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "Rust": "rust",
    "Go": "go",
    "C": "c",
    "C++": "cpp",
    "Java": "java",
    "Kotlin": "kotlin",
    "Swift": "swift",
    "C#": "csharp",
    "F#": "fsharp",
    "Dart": "dart",
    "Ruby": "ruby",
    "PHP": "php",
    "Perl": "perl",
    "R": "r",
    "Julia": "julia",
    "Lua": "lua",
    "Shell": "bash",
    "PowerShell": "powershell",
    "Elixir": "elixir",
    "Erlang": "erlang",
    "Haskell": "haskell",
    "OCaml": "ocaml",
    "Clojure": "clojure",
    "Scala": "scala",
    "Groovy": "groovy",
    "Fortran": "fortran",
    "COBOL": "cobol",
    "Pascal": "pascal",
    "Ada": "ada",
    "Zig": "zig",
    "Nim": "nim",
    "Crystal": "crystal",
    "D": "d",
    "Odin": "odin",
    "Verilog": "verilog",
    "SystemVerilog": "systemverilog",
    "VHDL": "vhdl",
    "Solidity": "solidity",
    "SQL": "sql",
    "HTML": "html",
    "CSS": "css",
    "SCSS": "scss",
    "XML": "xml",
    "JSON": "json",
    "YAML": "yaml",
    "TOML": "toml",
    "Dockerfile": "dockerfile",
    "Makefile": "make",
    "CMake": "cmake",
    "Assembly": "asm",
    "CUDA": "cuda",
    "GLSL": "glsl",
    "HLSL": "hlsl",
    "WGSL": "wgsl",
    "Markdown": "markdown",
    "Protocol Buffers": "proto",
    "GraphQL": "graphql",
    "Nix": "nix",
    "HCL": "hcl",
}



DECLARATION_NODE_TYPES = {
    "javascript": {"function_declaration": "function", "class_declaration": "class", "method_definition": "method"},
    "typescript": {"function_declaration": "function", "class_declaration": "class", "interface_declaration": "interface", "type_alias_declaration": "type", "method_definition": "method"},
    "tsx": {"function_declaration": "function", "class_declaration": "class", "interface_declaration": "interface", "type_alias_declaration": "type"},
    "rust": {"function_item": "function", "struct_item": "struct", "enum_item": "enum", "trait_item": "trait", "type_item": "type", "mod_item": "module", "const_item": "constant"},
    "go": {"function_declaration": "function", "method_declaration": "method", "type_declaration": "type", "const_declaration": "constant", "var_declaration": "variable"},
    "c": {"function_definition": "function", "struct_specifier": "struct", "enum_specifier": "enum", "type_definition": "typedef"},
    "cpp": {"function_definition": "function", "class_specifier": "class", "struct_specifier": "struct", "enum_specifier": "enum", "namespace_definition": "namespace"},
    "java": {"class_declaration": "class", "interface_declaration": "interface", "enum_declaration": "enum", "record_declaration": "record", "method_declaration": "method", "constructor_declaration": "constructor"},
    "kotlin": {"class_declaration": "class", "object_declaration": "object", "function_declaration": "function", "property_declaration": "property"},
    "swift": {"class_declaration": "class", "struct_declaration": "struct", "enum_declaration": "enum", "protocol_declaration": "protocol", "function_declaration": "function"},
    "csharp": {"class_declaration": "class", "struct_declaration": "struct", "interface_declaration": "interface", "enum_declaration": "enum", "method_declaration": "method"},
    "ruby": {"class": "class", "module": "module", "method": "method", "singleton_method": "method"},
    "php": {"class_declaration": "class", "interface_declaration": "interface", "trait_declaration": "trait", "function_definition": "function", "method_declaration": "method"},
    "perl": {"subroutine_declaration_statement": "function"},
    "r": {"function_definition": "function"},
    "julia": {"function_definition": "function", "struct_definition": "struct", "module_definition": "module"},
    "lua": {"function_declaration": "function"},
    "scala": {"class_definition": "class", "object_definition": "object", "trait_definition": "trait", "function_definition": "function"},
    "fortran": {"function_subprogram": "function", "subroutine_subprogram": "subroutine", "module": "module"},
    "zig": {"function_declaration": "function", "variable_declaration": "variable", "container_declaration": "type"},
    "solidity": {"contract_declaration": "contract", "function_definition": "function", "modifier_definition": "modifier", "event_definition": "event", "struct_declaration": "struct"},
    "graphql": {"object_type_definition": "type", "interface_type_definition": "interface", "enum_type_definition": "enum", "scalar_type_definition": "scalar"},
    "proto": {"message": "message", "enum": "enum", "service": "service", "rpc": "rpc"},
}
_IDENTIFIER_TYPES = {
    "identifier", "type_identifier", "field_identifier", "namespace_identifier",
    "simple_identifier", "constant",
}


def _extract_declarations(root_node, grammar: str) -> list[dict[str, str | int]]:
    """Extract conservative declaration names for grammars with known node schemas."""
    node_kinds = DECLARATION_NODE_TYPES.get(grammar, {})
    declarations: list[dict[str, str | int]] = []
    stack = [root_node]
    while stack:
        node = stack.pop()
        kind = node_kinds.get(node.type)
        if kind is None and node.type.endswith(("_declaration", "_definition", "_item")):
            if not node.type.startswith(("import_", "use_", "include_")):
                kind = node.type
        if kind:
            try:
                name_node = node.child_by_field_name("name")
            except (AttributeError, TypeError):
                name_node = None
            if name_node is None:
                name_node = next(
                    (child for child in node.children if child.type in _IDENTIFIER_TYPES),
                    None,
                )
            if name_node is not None:
                raw_name = name_node.text
                symbol_name = (
                    raw_name.decode("utf-8", errors="replace")
                    if isinstance(raw_name, bytes) else str(raw_name)
                )
                declarations.append({
                    "kind": kind,
                    "name": symbol_name,
                    "node_type": node.type,
                    "line": node.start_point.row + 1,
                })
        stack.extend(reversed(node.children))
    return declarations



IMPORT_NODE_TYPES = {
    "javascript": {"import_statement", "export_statement"},
    "typescript": {"import_statement", "export_statement"},
    "tsx": {"import_statement", "export_statement"},
    "go": {"import_declaration", "import_spec"},
    "rust": {"use_declaration"},
    "c": {"preproc_include"},
    "cpp": {"preproc_include"},
    "java": {"import_declaration"},
    "kotlin": {"import_header"},
    "swift": {"import_declaration"},
    "csharp": {"using_directive"},
    "ruby": {"call"},
    "php": {"namespace_use_declaration"},
    "dart": {"import_or_export"},
    "scala": {"import_declaration"},
    "haskell": {"import_declaration"},
    "elixir": {"call"},
}
_IMPORT_TARGET_PATTERNS = (
    re.compile(r"""(?i)\bfrom\s+["']?([\w./:@-]+)"""),
    re.compile(r"""(?i)\bimport\s+(?:static\s+)?["']?([\w./:@-]+)"""),
    re.compile(r"""(?i)\b(?:require|include)\s*\(?\s*["']([\w./:@-]+)"""),
    re.compile(r"""(?i)#\s*include\s*[<"]([^>"]+)"""),
    re.compile(r"""(?i)\buse\s+([A-Za-z_][\w:.]*)"""),
    re.compile(r"""(?i)\busing\s+([A-Za-z_][\w.]*)"""),
)


def _extract_imports(root_node, grammar: str) -> list[dict[str, str | int]]:
    """Extract import targets as references; does not claim internal resolution."""
    node_types = IMPORT_NODE_TYPES.get(grammar, set())
    imports: list[dict[str, str | int]] = []
    stack = [root_node]
    while stack:
        node = stack.pop()
        node_type = node.type.lower()
        generic_import_node = (
            "import" in node_type
            or "include" in node_type
            or node_type.startswith("use_")
            or node_type == "using_directive"
        )
        if node.type in node_types or generic_import_node:
            raw = node.text
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            for pattern in _IMPORT_TARGET_PATTERNS:
                match = pattern.search(text)
                if match:
                    imports.append({
                        "target": match.group(1),
                        "line": node.start_point.row + 1,
                        "node_type": node.type,
                    })
                    break
        stack.extend(reversed(node.children))
    unique = {
        (item["target"], item["line"], item["node_type"]): item for item in imports
    }
    return sorted(
        unique.values(),
        key=lambda item: (item["line"], item["target"], item["node_type"]),
    )


_MAX_ERROR_LOCATIONS = 10_000


def _walk_tree(root_node, data: bytes = b""):
    """Iteratively summarize a syntax tree without recursion-depth risk.

    Tree-sitter columns are byte offsets in the line; error locations are reported as
    1-based character columns, so they match what an editor shows on non-ASCII lines.
    """
    stack = [(root_node, 0)]
    node_count = 0
    max_depth = 0
    errors: list[tuple[str, int, int, bool]] = []
    error_count = 0
    top_level = [child.type for child in root_node.children]
    while stack:
        node, depth = stack.pop()
        node_count += 1
        max_depth = max(max_depth, depth)
        if node.is_error or node.is_missing:
            error_count += 1
        if (node.is_error or node.is_missing) and len(errors) < _MAX_ERROR_LOCATIONS:
            point = node.start_point
            line_start = node.start_byte - point.column
            column = len(data[line_start:node.start_byte].decode("utf-8", "replace")) if data else point.column
            errors.append((node.type, point.row + 1, column + 1, node.is_missing))
        for child in reversed(node.children):
            stack.append((child, depth + 1))
    return node_count, max_depth, errors, top_level, error_count


def _grammar_provisioned(pack, grammar: str) -> bool:
    """True only when the grammar is already on disk; this check never downloads.

    tree-sitter-language-pack 1.23+ downloads grammars on demand inside get_parser(),
    and has_language() reports manifest membership rather than local availability, so
    downloaded_languages() is the only offline-safe check there. Older packs that bundle
    their grammars expose has_parser().
    """
    if hasattr(pack, "downloaded_languages"):
        return grammar in set(pack.downloaded_languages())
    if hasattr(pack, "has_parser"):
        return bool(pack.has_parser(grammar))
    return False


def parser_capabilities(languages: set[str] | None = None) -> dict[str, str]:
    """Report local parser availability without downloading grammars."""
    requested = set(GRAMMARS) if languages is None else set(languages) & set(GRAMMARS)
    pending = requested - set(_CAPABILITY_CACHE)
    if pending:
        try:
            pack = importlib.import_module("tree_sitter_language_pack")
        except ImportError:
            _CAPABILITY_CACHE.update({
                name: "optional_dependency_missing" for name in pending
            })
        else:
            for name in sorted(pending):
                try:
                    _CAPABILITY_CACHE[name] = (
                        "available" if _grammar_provisioned(pack, GRAMMARS[name])
                        else "grammar_not_provisioned"
                    )
                except Exception:
                    _CAPABILITY_CACHE[name] = "parser_check_error"
    return {name: _CAPABILITY_CACHE[name] for name in sorted(requested)}


class TreeSitterAnalyzer(Analyzer):
    """Provide generic syntax-tree metrics for any locally provisioned grammar."""

    name = "tree-sitter-polyglot"
    domains = ("source_structure", "symbol_index", "imports")
    languages = tuple(GRAMMARS)

    def supports(self, record: FileRecord) -> bool:
        return (
            record.error is None
            and record.language in GRAMMARS
            and parser_capabilities({record.language}).get(record.language) == "available"
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > _MAX_TREE_SITTER_FILE_BYTES:
            return [Finding(
                "code",
                f"Tree-sitter resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the Tree-sitter parser's "
                f"{_MAX_TREE_SITTER_FILE_BYTES:,}-byte content budget.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]
        try:
            # Undecodable bytes become U+FFFD: the parse is structural, and a strict decode
            # would turn every non-UTF-8 source file into an analysis error.
            source = read_text_bounded(
                path, _MAX_TREE_SITTER_FILE_BYTES, errors="replace",
                expected_identity=record.analysis_identity,
            )
        except SourceBudgetExceeded as exc:
            return [Finding(
                "code",
                f"Tree-sitter resource limit: {record.path}",
                str(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]
        grammar = GRAMMARS[record.language]
        try:
            pack = importlib.import_module("tree_sitter_language_pack")
        except ImportError:
            return [Finding(
                "code",
                f"Optional parser unavailable: {record.language}",
                "Install PDT's optional polyglot parser extra and provision this grammar "
                "before scanning. PDT does not download parsers during analysis.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        try:
            # Never call get_parser() for an unprovisioned grammar: it would download one.
            if not _grammar_provisioned(pack, grammar):
                return [Finding(
                    "code",
                    f"Grammar not provisioned offline: {record.language}",
                    f"Tree-sitter recognizes grammar '{grammar}', but it is not available "
                    "in the local parser cache. No network download was attempted; "
                    "provision grammars explicitly before scanning.",
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                )]
            parser = pack.get_parser(grammar)
            # py-tree-sitter parses bytes only; a str argument raises TypeError.
            data = source.encode("utf-8")
            tree = parser.parse(data)
            if tree is None:
                raise RuntimeError("Tree-sitter parser returned no syntax tree")
            root = tree.root_node
            node_count, max_depth, errors, top_level, error_count = _walk_tree(root, data)
            declarations = _extract_declarations(root, grammar)
            imports = _extract_imports(root, grammar)
        except SourceBudgetExceeded as exc:
            return [Finding(
                "code",
                f"Tree-sitter resource limit: {record.path}",
                str(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]
        except Exception as exc:
            return [Finding(
                "code",
                f"Tree-sitter analysis error: {record.language}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        findings = [Finding(
            "code_structure",
            f"Syntax tree: {record.path}",
            f"Grammar: {grammar}; root node: {root.type}; nodes: {node_count}; "
            f"maximum depth: {max_depth}; top-level node kinds: "
            f"{', '.join(top_level[:30]) or 'none'}.",
            confidence="CONFIRMED",
            evidence=[record.path],
            analyzer=self.name,
        )]


        if imports:
            evidence = [
                "{}:{} imports {}".format(record.path, item["line"], item["target"])
                for item in imports[:100]
            ]
            findings.append(Finding(
                "dependency",
                f"Static import inventory: {record.path}",
                f"Extracted {len(imports)} import references. Internal/external target "
                "resolution is not yet established for this language adapter.",
                confidence="CONFIRMED",
                evidence=evidence,
                analyzer=self.name,
            ))
        if declarations:
            symbol_preview = [
                "{} {}".format(item["kind"], item["name"])
                for item in declarations[:40]
            ]
            evidence = [
                "{}:{}".format(record.path, item["line"])
                for item in declarations[:100]
            ]
            findings.append(Finding(
                "code_structure",
                f"Declarations: {record.path}",
                f"Extracted {len(declarations)} declaration names: "
                + ", ".join(symbol_preview)
                + ("; additional declarations omitted from preview." if len(declarations) > 40 else "."),
                confidence="CONFIRMED",
                evidence=evidence,
                analyzer=self.name,
            ))
        if errors:
            preview = errors[:50]
            evidence = [
                f"{record.path}:{line}:{column} ({'missing' if missing else 'error'} {kind})"
                for kind, line, column, missing in preview
            ]
            findings.append(Finding(
                "code",
                f"Parser diagnostics: {record.path}",
                f"Tree-sitter emitted {error_count:,} error or missing nodes. This is parser "
                "evidence, not by itself a compiler or runtime failure diagnosis.",
                confidence="CONFIRMED",
                evidence=evidence,
                analyzer=self.name,
            ))
        return findings
