"""Static API contract discovery for OpenAPI, GraphQL, Protocol Buffers and Thrift."""
from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding


_OPENAPI_NAMES = {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"}
_GRAPHQL_DEFINITION = re.compile(
    r"(?m)^\s*(type|interface|input|enum|scalar|union|schema|directive)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_GRAPHQL_OPERATION = re.compile(
    r"(?m)^\s*(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_PROTO_DECLARATION = re.compile(
    r"(?m)\b(service|rpc|message|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_THRIFT_DECLARATION = re.compile(
    r"(?m)^\s*(service|struct|exception|enum|typedef)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_HTTP_METHOD = re.compile(r"(?i)^\s{2,}(get|post|put|patch|delete|options|head|trace)\s*:")
_PATH_LINE = re.compile(r"^\s{2,}(/[^\s:]+)\s*:")
_OPERATION_ID = re.compile(r"^\s+operationId\s*:\s*([A-Za-z0-9_.-]+)")


def _flatten_openapi(data: Any) -> tuple[list[tuple[str, str]], list[str]]:
    paths: list[tuple[str, str]] = []
    schemas: list[str] = []
    if not isinstance(data, dict):
        return paths, schemas
    raw_paths = data.get("paths", {})
    if isinstance(raw_paths, dict):
        for route, operations in raw_paths.items():
            if isinstance(operations, dict):
                for method, operation in operations.items():
                    if method.lower() in {
                        "get", "post", "put", "patch", "delete", "options", "head", "trace"
                    }:
                        operation_id = (
                            str(operation.get("operationId", ""))
                            if isinstance(operation, dict) else ""
                        )
                        paths.append((method.upper(), str(route) + (
                            f" ({operation_id})" if operation_id else ""
                        )))
    components = data.get("components", {})
    if isinstance(components, dict):
        schemas_raw = components.get("schemas", {})
        if isinstance(schemas_raw, dict):
            schemas.extend(str(name) for name in schemas_raw)
    return paths, schemas


class APIContractAnalyzer(Analyzer):
    """Inventory API schemas and operations without making network requests."""

    name = "api-contracts"
    domains = ("api_rest", "api_graphql", "api_rpc",)

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            name in _OPENAPI_NAMES
            or record.extension in {".graphql", ".gql", ".proto", ".thrift"}
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            content = path.read_text(encoding="utf-8")
            name = Path(record.path).name.lower()
            if name in _OPENAPI_NAMES:
                return self._openapi(path, record, content)
            if record.extension in {".graphql", ".gql"}:
                return self._graphql(record, content)
            if record.extension == ".proto":
                return self._declarations(record, content, _PROTO_DECLARATION, "Protocol Buffers")
            return self._declarations(record, content, _THRIFT_DECLARATION, "Thrift")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [Finding(
                "api",
                f"API contract parse error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

    def _openapi(
        self, path: Path, record: FileRecord, content: str
    ) -> list[Finding]:
        if record.extension == ".json":
            data = json.loads(content)
            routes, schemas = _flatten_openapi(data)
        else:
            try:
                yaml = importlib.import_module("yaml")
            except ImportError:
                routes = []
                schemas = []
                current_route = None
                current_method = None
                for line in content.splitlines():
                    route_match = _PATH_LINE.match(line)
                    if route_match:
                        current_route = route_match.group(1)
                        current_method = None
                        continue
                    method_match = _HTTP_METHOD.match(line)
                    if method_match and current_route:
                        current_method = method_match.group(1).upper()
                        routes.append((current_method, current_route))
                        continue
                    operation_match = _OPERATION_ID.match(line)
                    if operation_match and current_method and routes:
                        method, route = routes[-1]
                        routes[-1] = (method, route + f" ({operation_match.group(1)})")
            else:
                data = yaml.safe_load(content)
                routes, schemas = _flatten_openapi(data)
        return [Finding(
            "api",
            f"OpenAPI contract: {record.path}",
            f"Detected {len(routes)} HTTP operations and {len(schemas)} component schemas. "
            "This is a static contract inventory; it does not verify a running service.",
            confidence="CONFIRMED",
            evidence=[f"{method} {route}" for method, route in routes[:100]] or [record.path],
            analyzer=self.name,
        )]

    def _graphql(self, record: FileRecord, content: str) -> list[Finding]:
        definitions = _GRAPHQL_DEFINITION.findall(content)
        operations = _GRAPHQL_OPERATION.findall(content)
        return [Finding(
            "api",
            f"GraphQL contract: {record.path}",
            f"Detected {len(definitions)} schema/type definitions and "
            f"{len(operations)} named operations.",
            confidence="CONFIRMED",
            evidence=[
                f"{kind} {name}" for kind, name in definitions[:80]
            ] + [f"operation {name}" for name in operations[:80]] or [record.path],
            analyzer=self.name,
        )]

    def _declarations(
        self, record: FileRecord, content: str, pattern: re.Pattern, contract: str
    ) -> list[Finding]:
        declarations = pattern.findall(content)
        counts: dict[str, int] = {}
        for kind, _ in declarations:
            counts[kind] = counts.get(kind, 0) + 1
        summary = ", ".join(
            f"{count} {kind}" for kind, count in sorted(counts.items())
        ) or "no recognized declarations"
        return [Finding(
            "api",
            f"{contract} contract: {record.path}",
            f"Detected {summary}. This is a static interface inventory.",
            confidence="CONFIRMED",
            evidence=[
                f"{kind} {name}" for kind, name in declarations[:100]
            ] or [record.path],
            analyzer=self.name,
        )]
