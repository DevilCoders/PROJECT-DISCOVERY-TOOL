"""Static API contract discovery across REST, event, RPC, SOAP and collection formats."""
from __future__ import annotations

import importlib
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ...core.safe_parsers import safe_xml_fromstring, safe_yaml_load
from ...core.source_utils import SourceBudgetExceeded, describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_OPENAPI_NAMES = {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"}
_ASYNCAPI_NAMES = {"asyncapi.yaml", "asyncapi.yml", "asyncapi.json"}
_OPENRPC_NAMES = {"openrpc.yaml", "openrpc.yml", "openrpc.json"}
_WSDL_NAMES = {"service.wsdl", "services.wsdl", "definitions.wsdl"}
_GRAPHQL_DEFINITION = re.compile(
    r"(?m)^[ \t]*(type|interface|input|enum|scalar|union|schema|directive)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_GRAPHQL_OPERATION = re.compile(
    r"(?m)^[ \t]*(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_PROTO_DECLARATION = re.compile(
    r"(?m)\b(service|rpc|message|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_THRIFT_DECLARATION = re.compile(
    r"(?m)^[ \t]*(service|struct|exception|enum|typedef)\s+([A-Za-z_][A-Za-z0-9_]*)"
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


_MAX_API_CONTRACT_BYTES = 16 * 1024 * 1024


class APIContractAnalyzer(Analyzer):
    """Inventory API schemas and operations without making network requests."""

    name = "api-contracts"
    domains = ("api_rest", "api_graphql", "api_rpc", "api_event", "api_soap", "api_collections")

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            name in (_OPENAPI_NAMES | _ASYNCAPI_NAMES | _OPENRPC_NAMES | _WSDL_NAMES)
            or name.endswith(".postman_collection.json")
            or record.extension in {
                ".graphql", ".gql", ".proto", ".thrift", ".wsdl", ".raml",
            }
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > _MAX_API_CONTRACT_BYTES:
            return [Finding(
                "api", f"API contract resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the API contract parser's "
                f"{_MAX_API_CONTRACT_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            content = read_text_bounded(
                path, _MAX_API_CONTRACT_BYTES,
                expected_identity=record.analysis_identity,
            )
            name = Path(record.path).name.lower()
            if name in _OPENAPI_NAMES:
                return self._openapi(path, record, content)
            if name in _ASYNCAPI_NAMES:
                return self._asyncapi(record, content)
            if name in _OPENRPC_NAMES:
                return self._openrpc(record, content)
            if name.endswith(".postman_collection.json"):
                return self._postman(record, content)
            if record.extension == ".wsdl" or name in _WSDL_NAMES:
                return self._wsdl(record, content)
            if record.extension == ".raml":
                return self._raml(record, content)
            if record.extension in {".graphql", ".gql"}:
                return self._graphql(record, content)
            if record.extension == ".proto":
                return self._declarations(record, content, _PROTO_DECLARATION, "Protocol Buffers")
            return self._declarations(record, content, _THRIFT_DECLARATION, "Thrift")
        except SourceBudgetExceeded as exc:
            return [Finding(
                "api", f"API contract resource limit: {record.path}", str(exc),
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ET.ParseError, ValueError, RecursionError, MemoryError) as exc:
            return [Finding(
                "api",
                f"API contract parse error: {record.path}",
                describe_error(exc),
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
                importlib.import_module("yaml")  # optional-extra availability check
            except ImportError:
                routes = []
                schemas = []
                current_route = None
                current_method = None
                for line in io.StringIO(content, newline=None):
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
                data = safe_yaml_load(content)
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

    def _structured_document(self, record: FileRecord, content: str) -> Any:
        if record.extension == ".json":
            return json.loads(content)
        try:
            importlib.import_module("yaml")  # optional-extra availability check
        except ImportError:
            return None
        return safe_yaml_load(content)

    def _asyncapi(self, record: FileRecord, content: str) -> list[Finding]:
        data = self._structured_document(record, content)
        if not isinstance(data, dict):
            return [Finding(
                "api",
                f"AsyncAPI contract unavailable: {record.path}",
                "A structured YAML parser is required for this AsyncAPI document; "
                "install the optional infrastructure extra. No network access was attempted.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]
        channels = data.get("channels", {})
        channels = channels if isinstance(channels, dict) else {}
        operations = data.get("operations", {})
        operations = operations if isinstance(operations, dict) else {}
        operation_evidence: list[str] = []
        for channel_name, channel in channels.items():
            if isinstance(channel, dict):
                for action in ("publish", "subscribe"):
                    if action in channel:
                        operation_evidence.append(f"{action}: {channel_name}")
        for operation_name, operation in operations.items():
            if isinstance(operation, dict):
                action = operation.get("action", "operation")
                channel_ref = operation.get("channel", {})
                address = channel_ref.get("$ref", "") if isinstance(channel_ref, dict) else ""
                operation_evidence.append(
                    f"{action}: {operation_name}" + (f" -> {address}" if address else "")
                )
        components = data.get("components", {})
        messages = components.get("messages", {}) if isinstance(components, dict) else {}
        messages = messages if isinstance(messages, dict) else {}
        evidence = (
            [f"channel: {name}" for name in list(channels)[:60]]
            + operation_evidence[:100]
            + [f"message: {name}" for name in list(messages)[:60]]
        )
        return [Finding(
            "api",
            f"AsyncAPI contract: {record.path}",
            f"Detected {len(channels)} channels, {len(operation_evidence)} publish/subscribe "
            f"operations and {len(messages)} component messages. Static contract inventory "
            "does not verify broker connectivity or runtime delivery.",
            confidence="CONFIRMED",
            evidence=evidence or [record.path],
            analyzer=self.name,
        )]

    def _openrpc(self, record: FileRecord, content: str) -> list[Finding]:
        data = self._structured_document(record, content)
        if not isinstance(data, dict):
            return [Finding(
                "api",
                f"OpenRPC contract unavailable: {record.path}",
                "A structured YAML parser is required for this OpenRPC document.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]
        methods = data.get("methods", [])
        methods = methods if isinstance(methods, list) else []
        components = data.get("components", {})
        schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
        schemas = schemas if isinstance(schemas, dict) else {}
        names = [
            str(item.get("name")) for item in methods
            if isinstance(item, dict) and item.get("name")
        ]
        evidence = (
            [f"method: {name}" for name in names[:100]]
            + [f"schema: {name}" for name in list(schemas)[:60]]
        )
        return [Finding(
            "api",
            f"OpenRPC contract: {record.path}",
            f"Detected {len(names)} JSON-RPC methods and {len(schemas)} component schemas.",
            confidence="CONFIRMED",
            evidence=evidence or [record.path],
            analyzer=self.name,
        )]

    def _postman(self, record: FileRecord, content: str) -> list[Finding]:
        data = json.loads(content)
        requests: list[str] = []

        def walk(items: Any, prefix: str = "") -> None:
            if not isinstance(items, list):
                return
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", "unnamed"))
                current = f"{prefix}/{name}" if prefix else name
                request = item.get("request")
                if isinstance(request, dict):
                    method = str(request.get("method", "UNKNOWN")).upper()
                    requests.append(f"{method} {current}")
                walk(item.get("item"), current)

        walk(data.get("item", []))
        return [Finding(
            "api",
            f"Postman collection: {record.path}",
            f"Detected {len(requests)} request definitions. URLs and parameter values are "
            "intentionally omitted from evidence to avoid leaking collection secrets.",
            confidence="CONFIRMED",
            evidence=requests[:100] or [record.path],
            analyzer=self.name,
        )]

    def _wsdl(self, record: FileRecord, content: str) -> list[Finding]:
        root = safe_xml_fromstring(content)
        services: list[str] = []
        port_types: list[str] = []
        operations: set[str] = set()
        bindings: list[str] = []
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            name = element.attrib.get("name")
            if not name:
                continue
            if tag == "service":
                services.append(name)
            elif tag in {"portType", "interface"}:
                port_types.append(name)
            elif tag == "operation":
                operations.add(name)
            elif tag == "binding":
                bindings.append(name)
        evidence = (
            [f"service: {name}" for name in services[:40]]
            + [f"portType: {name}" for name in port_types[:40]]
            + [f"operation: {name}" for name in sorted(operations)[:100]]
            + [f"binding: {name}" for name in bindings[:40]]
        )
        return [Finding(
            "api",
            f"WSDL contract: {record.path}",
            f"Detected {len(services)} services, {len(port_types)} port types/interfaces, "
            f"{len(operations)} unique operations and {len(bindings)} bindings.",
            confidence="CONFIRMED",
            evidence=evidence or [record.path],
            analyzer=self.name,
        )]

    def _raml(self, record: FileRecord, content: str) -> list[Finding]:
        routes = re.findall(r"(?m)^(/[^\s:]+)\s*:\s*$", content)
        methods = re.findall(
            r"(?im)^[ \t]{2,}(get|post|put|patch|delete|options|head)\s*:\s*$",
            content,
        )
        evidence = (
            [f"resource: {route}" for route in routes[:80]]
            + [f"method: {method.upper()}" for method in methods[:100]]
        )
        return [Finding(
            "api",
            f"RAML contract: {record.path}",
            f"Detected {len(routes)} resource paths and {len(methods)} HTTP method declarations.",
            confidence="CONFIRMED",
            evidence=evidence or [record.path],
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
