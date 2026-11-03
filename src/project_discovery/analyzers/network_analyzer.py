"""Static network, URL/URI, address, port and service-protocol discovery."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from .base import Analyzer
from ..language_catalog import is_textual_path
from ..models import FileRecord, Finding


_URI = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s<>\"']+", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])")
_IPV6_MAPPED = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,6}(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_CIDR = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|(?<![\w:])[0-9A-Fa-f:]{3,}/\d{1,3}\b")
_PORT_KEY = re.compile(
    r"""(?i)\b(?:port|listen|expose|target_port|containerPort|hostPort|bind_port)\s*(?:=|:)\s*['"]?(\d{1,5})\b"""
)
_HOST_PORT = re.compile(
    r"""(?i)(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\])\s*:\s*(\d{1,5})\b"""
)
_BARE_PORT = re.compile(r"""(?im)^\s*(?:EXPOSE|listen)\s+(\d{1,5})\b""")
_DOMAIN = re.compile(
    r"(?<![@\w-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)
_PROTOCOL_PATTERNS = {
    "REST/HTTP": re.compile(r"\b(?:https?://|HTTP(?:S)?\s+(?:GET|POST|PUT|PATCH|DELETE)|application/json)\b", re.I),
    "WebSocket": re.compile(r"\b(?:websocket|websockets|socket\.io|ws://|wss://)\b", re.I),
    "gRPC": re.compile(r"\b(?:grpc|protobuf|protocol buffers|proto3?)\b", re.I),
    "GraphQL": re.compile(r"\b(?:graphql|GraphQLClient|ApolloClient)\b", re.I),
    "SOAP": re.compile(r"\b(?:soap|wsdl|SoapClient|WebService)\b", re.I),
    "MQTT": re.compile(r"\b(?:mqtt|paho-mqtt)\b", re.I),
    "AMQP": re.compile(r"\b(?:amqp|rabbitmq)\b", re.I),
    "Kafka": re.compile(r"\b(?:kafka|KafkaProducer|KafkaConsumer)\b", re.I),
    "SSH": re.compile(r"\b(?:ssh|sftp|scp)\b", re.I),
    "DNS": re.compile(r"\b(?:dns|nameserver|resolve\(\))\b", re.I),
}
_COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MS-SQL",
    1521: "Oracle", 1883: "MQTT", 2375: "Docker-API", 2376: "Docker-TLS",
    3000: "development-web", 3306: "MySQL", 5432: "PostgreSQL",
    5672: "AMQP", 6379: "Redis", 6443: "Kubernetes-API",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9092: "Kafka", 9200: "Elasticsearch",
    27017: "MongoDB",
}


def _bounded_lines(path: Path, max_chunk_chars: int = 256 * 1024):
    """Yield bounded line chunks while preserving line numbers for huge minified files."""
    line_number = 1
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        while True:
            chunk = stream.readline(max_chunk_chars)
            if not chunk:
                break
            yield line_number, chunk
            if chunk.endswith(("\n", "\r")):
                line_number += 1


def _safe_uri(value: str) -> str | None:
    value = value.rstrip(".,;:)]}")
    try:
        parsed = urlsplit(value)
        if not parsed.scheme:
            return None
        host = parsed.hostname
        if not host:
            return f"{parsed.scheme.lower()}:<non-network URI>"
        host_text = f"[{host}]" if ":" in host else host
        try:
            port = parsed.port
        except ValueError:
            port = None
        suffix = f":{port}" if port is not None else ""
        return f"{parsed.scheme.lower()}://{host_text}{suffix}/<redacted-path>"
    except ValueError:
        return None


class NetworkIndicatorAnalyzer(Analyzer):
    """Extract static network indicators; never probes or connects to discovered hosts."""

    name = "network-indicators"
    domains = ("networking",)
    languages = ("Polyglot text/source/configuration")

    def supports(self, record: FileRecord) -> bool:
        return (
            record.error is None
            and record.content_skipped_reason is None
            and (record.file_type == "text" or is_textual_path(record.path))
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        addresses: dict[str, set[tuple[str, int]]] = {"IPv4": set(), "IPv6": set()}
        cidrs: set[tuple[str, int]] = set()
        ports: set[tuple[int, int]] = set()
        uris: set[tuple[str, int]] = set()
        domains: set[tuple[str, int]] = set()
        protocols: dict[str, set[int]] = {}
        for number, line in _bounded_lines(path):
            for candidate in _CIDR.findall(line):
                try:
                    network = ipaddress.ip_network(candidate, strict=False)
                    cidrs.add((str(network), number))
                except ValueError:
                    pass
            for candidate in _IPV4.findall(line):
                try:
                    parsed = ipaddress.ip_address(candidate)
                    addresses["IPv4"].add((str(parsed), number))
                except ValueError:
                    pass
            for pattern in (_IPV6, _IPV6_MAPPED):
                for candidate in pattern.findall(line):
                    try:
                        parsed = ipaddress.ip_address(candidate)
                        if parsed.version == 6:
                            addresses["IPv6"].add((str(parsed), number))
                    except ValueError:
                        pass
            for match in _PORT_KEY.finditer(line):
                value = int(match.group(1))
                if 1 <= value <= 65535:
                    ports.add((value, number))
            for pattern in (_HOST_PORT, _BARE_PORT):
                for match in pattern.finditer(line):
                    value = int(match.group(1))
                    if 1 <= value <= 65535:
                        ports.add((value, number))
            for match in _URI.finditer(line):
                raw_uri = match.group(0).rstrip(".,;:)]}")
                safe = _safe_uri(raw_uri)
                if safe:
                    uris.add((safe, number))
                    try:
                        host = urlsplit(raw_uri).hostname
                    except ValueError:
                        host = None
                    if host:
                        try:
                            ipaddress.ip_address(host)
                        except ValueError:
                            domains.add((host.lower().rstrip("."), number))
                    try:
                        uri_port = urlsplit(raw_uri).port
                    except ValueError:
                        uri_port = None
                    if uri_port is not None and 1 <= uri_port <= 65535:
                        ports.add((uri_port, number))
            for match in _DOMAIN.finditer(line):
                domain = match.group(0).lower().rstrip(".")
                if domain not in {"example.com", "example.org", "example.net", "localhost.localdomain"}:
                    domains.add((domain, number))
            for label, pattern in _PROTOCOL_PATTERNS.items():
                if pattern.search(line):
                    protocols.setdefault(label, set()).add(number)

        findings: list[Finding] = []
        for version, values in addresses.items():
            if values:
                unique = sorted({value for value, _ in values})
                findings.append(Finding(
                    "network",
                    f"{version} address indicators: {record.path}",
                    f"Detected {len(unique)} distinct {version} literal(s). These are static "
                    "references, not evidence of active interfaces or reachability.",
                    confidence="CONFIRMED",
                    evidence=[
                        f"{record.path}:{line} ({value})"
                        for value, line in sorted(values)[:100]
                    ],
                    analyzer=self.name,
                ))
        if cidrs:
            findings.append(Finding(
                "network",
                f"CIDR network indicators: {record.path}",
                f"Detected {len({value for value, _ in cidrs})} distinct CIDR range(s).",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{line} ({value})"
                    for value, line in sorted(cidrs)[:100]
                ],
                analyzer=self.name,
            ))
        if ports:
            values = sorted({value for value, _ in ports})
            descriptions = [
                f"{value}/{_COMMON_PORTS[value]}" if value in _COMMON_PORTS else str(value)
                for value in values
            ]
            findings.append(Finding(
                "network",
                f"Port indicators: {record.path}",
                f"Detected {len(values)} distinct port number(s): " + ", ".join(descriptions[:50])
                + ". A port declaration does not prove a listener is active.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} (port {value})"
                    for value, line in sorted(ports)[:100]
                ],
                analyzer=self.name,
            ))
        if uris:
            findings.append(Finding(
                "network",
                f"URL/URI indicators: {record.path}",
                f"Detected {len(uris)} URI references. Userinfo, paths, query strings and "
                "fragments are redacted from evidence.",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{line} ({value})"
                    for value, line in sorted(uris)[:100]
                ],
                analyzer=self.name,
            ))
        if domains:
            domain_values = {value for value, _ in domains}
            subdomains = {value for value in domain_values if len(value.split(".")) > 2}
            findings.append(Finding(
                "network",
                f"Hostname and domain indicators: {record.path}",
                f"Detected {len(domain_values)} distinct FQDN/domain candidate(s), including "
                f"{len(subdomains)} probable subdomain(s). Public suffixes and DNS ownership "
                "are not resolved.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} ({value})"
                    for value, line in sorted(domains)[:100]
                ],
                analyzer=self.name,
            ))
        if protocols:
            detected = sorted(protocols)
            findings.append(Finding(
                "network",
                f"Network protocol references: {record.path}",
                "Detected protocol/API markers: " + ", ".join(detected)
                + ". Marker presence does not confirm protocol implementation or use.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} ({label})"
                    for label, lines in sorted(protocols.items())
                    for line in sorted(lines)[:20]
                ][:100],
                analyzer=self.name,
            ))
        return findings
