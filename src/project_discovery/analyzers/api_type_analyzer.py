"""Static API-style classification from contracts and source framework markers."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..language_catalog import is_textual_path, source_extensions
from ..models import FileRecord, Finding


_PATTERNS = {
    "RESTful HTTP": re.compile(r"(?i)(?:\b(?:GET|POST|PUT|PATCH|DELETE)\s+/|\.(?:get|post|put|patch|delete)\s*\(|@(?:Get|Post|Put|Patch|Delete)Mapping\b|\.map(?:Get|Post|Put|Patch|Delete)\s*\(|openapi:|swagger:|fastapi|flask\.route|express\.Router)"),
    "GraphQL": re.compile(r"(?i)(?:\b(?:query|mutation|subscription)\s+[A-Za-z_]|\bgraphql\b|@apollo/client|type\s+Query\s*\{)"),
    "gRPC/Protocol Buffers": re.compile(r"(?i)(?:\bsyntax\s*=\s*['\"]proto|service\s+[A-Za-z_]\w*\s*\{|grpc\.|grpcio|@GrpcService)"),
    "JSON-RPC": re.compile(r"(?i)(?:jsonrpc|json-rpc|application/json-rpc|rpc\.discover)"),
    "SOAP/WSDL": re.compile(r"(?i)(?:<definitions\b|<soap:|wsdl:|SoapClient|javax\.xml\.ws)"),
    "WebSocket": re.compile(r"(?i)(?:websocket|socket\.io|ws://|wss://|@WebSocket)"),
    "Event-driven API": re.compile(r"(?i)(?:asyncapi:|@KafkaListener|KafkaTemplate|basic_publish|basic_consume|publish\(|subscribe\()"),
    "Webhooks": re.compile(r"(?i)\bwebhooks?\b"),
}
_CONTRACT_EXTENSIONS = {".graphql", ".gql", ".proto", ".thrift", ".wsdl", ".raml", ".avdl"}
_MAX_LINE_CHARS = 256 * 1024


class APITypeAnalyzer(Analyzer):
    """Classify common API styles without contacting any endpoint."""

    name = "api-type-classifier"
    domains = ("api_rest", "api_graphql", "api_rpc", "api_event", "networking")
    languages = ("Polyglot source and API contract formats")

    def supports(self, record: FileRecord) -> bool:
        return (
            record.error is None
            and record.content_skipped_reason is None
            and (
                record.extension in source_extensions()
                or record.extension in _CONTRACT_EXTENSIONS
                or Path(record.path).name.lower() in {
                    "openapi.yaml", "openapi.yml", "openapi.json",
                    "swagger.yaml", "swagger.yml", "swagger.json",
                    "asyncapi.yaml", "asyncapi.yml", "asyncapi.json",
                    "openrpc.yaml", "openrpc.yml", "openrpc.json",
                }
            )
            and (record.file_type == "text" or is_textual_path(record.path))
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        line_hits: dict[str, set[int]] = {}
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                line_number = 1
                while True:
                    line = stream.readline(_MAX_LINE_CHARS)
                    if not line:
                        break
                    current_line = line_number
                    for api_type, pattern in _PATTERNS.items():
                        if pattern.search(line):
                            line_hits.setdefault(api_type, set()).add(current_line)
                    if line.endswith(("\n", "\r")):
                        line_number += 1
        except OSError as exc:
            return [Finding(
                "api", f"API classification unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        if not line_hits:
            return []
        names = sorted(line_hits)
        evidence = [
            f"{record.path}:{line} ({name})"
            for name, lines in sorted(line_hits.items())
            for line in sorted(lines)[:20]
        ]
        return [Finding(
            "api",
            f"API styles detected: {record.path}",
            "Observed static API-style markers: " + ", ".join(names)
            + ". A marker does not prove a deployed or reachable API implementation.",
            confidence="INFERRED", evidence=evidence[:100], analyzer=self.name,
        )]
