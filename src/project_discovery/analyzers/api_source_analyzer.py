"""Source-level HTTP and RPC endpoint declaration discovery."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding
from ..language_catalog import source_extensions, source_language_names
from ..source_utils import (
    SourceBudgetExceeded, open_verified_text, read_python_source_bounded,
)


_SOURCE_EXTENSIONS = source_extensions()
MAX_PYTHON_ENDPOINT_AST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_ENDPOINT_SCAN_BYTES = 32 * 1024 * 1024
MAX_ENDPOINT_LINE_CHARS = 256 * 1024

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
_ROUTE_PATTERNS = (
    re.compile(
        r"""(?:app|router|server|fastify|r|mux)\s*\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""Route\s*::\s*(get|post|put|patch|delete|options|head)\s*\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""@(Get|Post|Put|Patch|Delete|PatchMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(\s*['"]([^'"]*)['"]""",
        re.I,
    ),
    re.compile(
        r"""@(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\(\s*['"]?([^'")\s]+)?""",
        re.I,
    ),
    re.compile(
        r"""\[\s*Http(Get|Post|Put|Patch|Delete|Options|Head)(?:\s*\(\s*['"]([^'"]*)['"]\s*\))?\s*\]""",
        re.I,
    ),
    re.compile(
        r"""(?m)^\s*(get|post|put|patch|delete|options|head)\s+['"]([^'"]+)['"]\s+do\b""",
        re.I,
    ),
    re.compile(
        r"""#\s*\[\s*(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""(?:app|group|router)\s*\.\s*Map(Get|Post|Put|Patch|Delete)\s*\(\s*['"]([^'"]+)['"]""",
        re.I,
    ),
    re.compile(
        r"""\b(?:http\.)?HandleFunc\s*\(\s*(['"])([^'"]+)\1""",
        re.I,
    ),
    re.compile(
        r"""\bCROW_ROUTE\s*\([^,]+,\s*(['"])([^'"]+)\1""",
        re.I,
    ),
)


def _literal(node: ast.AST) -> str | None:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


def _python_routes(source: str, relative: str) -> list[tuple[str, str, int]]:
    tree = ast.parse(source, filename=relative)
    routes: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                method = func.attr.lower() if isinstance(func, ast.Attribute) else ""
                if method not in _HTTP_METHODS | {"route", "api_route", "websocket"}:
                    continue
                path = _literal(decorator.args[0]) if decorator.args else None
                if path is None:
                    continue
                if method in {"route", "api_route"}:
                    methods = next(
                        (keyword.value for keyword in decorator.keywords if keyword.arg == "methods"),
                        None,
                    )
                    if isinstance(methods, (ast.List, ast.Tuple)):
                        values = [
                            _literal(item) for item in methods.elts
                            if _literal(item) is not None
                        ]
                        route_methods = [item.upper() for item in values] or ["ANY"]
                    else:
                        route_methods = ["ANY"]
                elif method == "websocket":
                    route_methods = ["WEBSOCKET"]
                else:
                    route_methods = [method.upper()]
                routes.extend((item, path, node.lineno) for item in route_methods)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"path", "re_path"} and node.args:
                path = _literal(node.args[0])
                if path is not None:
                    routes.append(("DJANGO", path, node.lineno))
    return sorted(set(routes), key=lambda item: (item[2], item[0], item[1]))


class APIEndpointAnalyzer(Analyzer):
    """Discover route declarations without starting web servers or resolving runtime routing."""

    name = "api-endpoints"
    domains = ("api_rest", "networking")
    languages = source_language_names()

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _SOURCE_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        routes: list[tuple[str, str, int]] = []
        truncated = False
        if record.extension in {".py", ".pyi"}:
            if record.size_bytes > MAX_PYTHON_ENDPOINT_AST_BYTES:
                return [Finding(
                    "api",
                    f"Python endpoint AST resource limit: {record.path}",
                    f"File size {record.size_bytes:,} bytes exceeds this endpoint parser's "
                    f"{MAX_PYTHON_ENDPOINT_AST_BYTES:,}-byte AST budget.",
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                    severity="LOW",
                )]
            try:
                source = read_python_source_bounded(
                    path, MAX_PYTHON_ENDPOINT_AST_BYTES,
                    expected_identity=record.analysis_identity,
                )
                routes = _python_routes(source, record.path)
            except SourceBudgetExceeded as exc:
                return [Finding(
                    "api", f"Python endpoint AST resource limit: {record.path}",
                    str(exc), confidence="UNKNOWN", evidence=[record.path],
                    analyzer=self.name, severity="LOW",
                )]
            except (OSError, UnicodeDecodeError, SyntaxError, LookupError, RecursionError, MemoryError) as exc:
                return [Finding(
                    "api", f"API endpoint scan unavailable: {record.path}",
                    f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                    evidence=[record.path], analyzer=self.name, severity="LOW",
                )]
        else:
            bytes_scanned = 0
            line_number = 1
            try:
                with open_verified_text(
                    path, encoding="utf-8", errors="replace",
                    expected_identity=record.analysis_identity,
                ) as stream:
                    while bytes_scanned < MAX_SOURCE_ENDPOINT_SCAN_BYTES:
                        line = stream.readline(min(
                            MAX_ENDPOINT_LINE_CHARS,
                            MAX_SOURCE_ENDPOINT_SCAN_BYTES - bytes_scanned,
                        ))
                        if not line:
                            break
                        bytes_scanned += len(line.encode("utf-8", errors="replace"))
                        for pattern in _ROUTE_PATTERNS:
                            for match in pattern.finditer(line):
                                groups = match.groups()
                                if pattern.pattern.startswith(r"""@(?:GET"""):
                                    method, route = "ANY", groups[0] or ""
                                elif pattern.pattern.startswith(r"""\[\s*Http"""):
                                    method = groups[0].upper()
                                    route = groups[1] or ""
                                elif pattern.pattern.startswith(r"""(?:app|group|router)"""):
                                    method, route = groups[0].upper(), groups[1]
                                elif pattern.pattern.startswith(r"""\b(?:http\.)?HandleFunc""") or pattern.pattern.startswith(r"""\bCROW_ROUTE"""):
                                    method, route = "ANY", groups[1]
                                elif len(groups) >= 2:
                                    method, route = groups[0].upper().removesuffix("MAPPING"), groups[1]
                                else:
                                    continue
                                routes.append((method, route, line_number))
                        if line.endswith(("\n", "\r")):
                            line_number += 1
                truncated = record.size_bytes > bytes_scanned
            except OSError as exc:
                return [Finding(
                    "api", f"API endpoint scan unavailable: {record.path}",
                    f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                    evidence=[record.path], analyzer=self.name,
                )]

        unique = sorted(set(routes), key=lambda item: (item[2], item[0], item[1]))
        findings: list[Finding] = []
        if unique:
            findings.append(Finding(
                "api",
                f"API route declarations: {record.path}",
                f"Detected {len(unique)} statically recognizable endpoint declaration(s). "
                "Route prefixes, middleware, runtime registration, and deployed reachability "
                "are not resolved.",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{line} {method} {route}"
                    for method, route, line in unique[:150]
                ],
                analyzer=self.name,
            ))
        if truncated:
            findings.append(Finding(
                "api",
                f"API endpoint scan budget reached: {record.path}",
                f"Only the first {MAX_SOURCE_ENDPOINT_SCAN_BYTES:,} bytes were scanned. "
                "Later route declarations may not appear in this report.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
