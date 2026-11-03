"""Offline-first generic syntax analysis through optional Tree-sitter grammars.

The analyzer never downloads grammars. It checks has_parser() before constructing
a parser; users must provision grammar libraries separately before scanning.
"""
from __future__ import annotations

import importlib
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


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
    "C#": "c_sharp",
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


def _walk_tree(root_node):
    """Iteratively summarize a syntax tree without recursion-depth risk."""
    stack = [(root_node, 0)]
    node_count = 0
    max_depth = 0
    errors: list[tuple[str, int, int, bool]] = []
    top_level = [child.type for child in root_node.children]
    while stack:
        node, depth = stack.pop()
        node_count += 1
        max_depth = max(max_depth, depth)
        if node.is_error or node.is_missing:
            point = node.start_point
            errors.append((node.type, point.row + 1, point.column + 1, node.is_missing))
        for child in reversed(node.children):
            stack.append((child, depth + 1))
    return node_count, max_depth, errors, top_level


class TreeSitterAnalyzer(Analyzer):
    """Provide generic syntax-tree metrics for any locally provisioned grammar."""

    name = "tree-sitter-polyglot"

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.language in GRAMMARS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
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
            if not pack.has_parser(grammar):
                return [Finding(
                    "code",
                    f"Grammar not provisioned offline: {record.language}",
                    f"Tree-sitter recognizes grammar '{grammar}', but it is not available "
                    "in the local parser cache. No network download was attempted.",
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                )]
            parser = pack.get_parser(grammar)
            source = path.read_text(encoding="utf-8")
            tree = parser.parse(source)
            if tree is None:
                raise RuntimeError("Tree-sitter parser returned no syntax tree")
            root = tree.root_node
            node_count, max_depth, errors, top_level = _walk_tree(root)
        except (OSError, UnicodeDecodeError, Exception) as exc:
            return [Finding(
                "code",
                f"Tree-sitter analysis error: {record.language}",
                f"{type(exc).__name__}: {exc}",
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
        if errors:
            preview = errors[:50]
            evidence = [
                f"{record.path}:{line}:{column} ({'missing' if missing else 'error'} {kind})"
                for kind, line, column, missing in preview
            ]
            findings.append(Finding(
                "code",
                f"Parser diagnostics: {record.path}",
                f"Tree-sitter emitted {len(errors)} error or missing nodes. This is parser "
                "evidence, not by itself a compiler or runtime failure diagnosis.",
                confidence="CONFIRMED",
                evidence=evidence,
                analyzer=self.name,
            ))
        return findings
