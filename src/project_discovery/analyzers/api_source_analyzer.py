"""Source-level HTTP and RPC endpoint declaration discovery."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding
from ..language_catalog import source_extensions, source_language_names


_SOURCE_EXTENSIONS = source_extensions()

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
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError:
        return []
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
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "api", f"API endpoint scan unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        if record.extension in {".py", ".pyi"}:
            routes = _python_routes(source, record.path)
        else:
            routes = []
            for number, line in enumerate(source.splitlines(), 1):
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
                        routes.append((method, route, number))
        unique = sorted(set(routes), key=lambda item: (item[2], item[0], item[1]))
        if not unique:
            return []
        return [Finding(
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
        )]
