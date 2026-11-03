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
_MAX_LINE_BYTES = 256 * 1024
_MAX_API_TYPE_FILE_BYTES = 32 * 1024 * 1024
_MAX_API_TYPE_EVIDENCE_PER_STYLE = 20


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
        if record.size_bytes > _MAX_API_TYPE_FILE_BYTES:
            return [Finding(
                "api",
                f"API type analysis resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the API-type analyzer's "
                f"{_MAX_API_TYPE_FILE_BYTES:,}-byte scan budget.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]

        line_samples: dict[str, list[int]] = {}
        line_counts: dict[str, int] = {}
        line_number = 1
        bytes_scanned = 0
        budget_reached = False
        try:
            with path.open("rb") as stream:
                while bytes_scanned < _MAX_API_TYPE_FILE_BYTES:
                    remaining = _MAX_API_TYPE_FILE_BYTES - bytes_scanned
                    raw_line = stream.readline(min(_MAX_LINE_BYTES, remaining + 1))
                    if not raw_line:
                        break
                    if len(raw_line) > remaining:
                        budget_reached = True
                        break
                    bytes_scanned += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace")
                    for api_type, pattern in _PATTERNS.items():
                        if pattern.search(line):
                            line_counts[api_type] = line_counts.get(api_type, 0) + 1
                            samples = line_samples.setdefault(api_type, [])
                            if len(samples) < _MAX_API_TYPE_EVIDENCE_PER_STYLE:
                                samples.append(line_number)
                    if line.endswith(("\n", "\r")):
                        line_number += 1
                if bytes_scanned >= _MAX_API_TYPE_FILE_BYTES and stream.read(1):
                    budget_reached = True
        except OSError as exc:
            return [Finding(
                "api", f"API classification unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]

        findings: list[Finding] = []
        if line_counts:
            names = sorted(line_counts)
            evidence = [
                f"{record.path}:{line} ({name})"
                for name in names
                for line in line_samples.get(name, [])
            ][:100]
            findings.append(Finding(
                "api",
                f"API styles detected: {record.path}",
                "Observed static API-style markers: "
                + ", ".join(
                    f"{name} ({line_counts[name]:,} line(s))" for name in names
                )
                + ". A marker does not prove a deployed or reachable API implementation.",
                confidence="INFERRED", evidence=evidence, analyzer=self.name,
            ))
        if budget_reached:
            findings.append(Finding(
                "api",
                f"API type scan budget reached: {record.path}",
                f"Analysis stopped after {_MAX_API_TYPE_FILE_BYTES:,} bytes. "
                "Findings collected before the limit are partial; remaining content "
                "was not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path, f"bytes_scanned: {bytes_scanned:,}"],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
