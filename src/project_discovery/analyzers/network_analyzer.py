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
_MAX_NETWORK_FILE_BYTES = 64 * 1024 * 1024
_MAX_NETWORK_LINE_BYTES = 256 * 1024
_MAX_NETWORK_INDICATORS = 25_000
_MAX_NETWORK_EVIDENCE = 100
_MAX_NETWORK_PROTOCOL_LINES = 20

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
        if record.size_bytes > _MAX_NETWORK_FILE_BYTES:
            return [Finding(
                "network",
                f"Network indicator resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the network analyzer's "
                f"{_MAX_NETWORK_FILE_BYTES:,}-byte scan budget.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]

        addresses: dict[str, set[tuple[str, int]]] = {"IPv4": set(), "IPv6": set()}
        cidrs: set[tuple[str, int]] = set()
        ports: set[tuple[int, int]] = set()
        uris: set[tuple[str, int]] = set()
        domains: set[tuple[str, int]] = set()
        protocols: dict[str, list[int]] = {}
        protocol_counts: dict[str, int] = {}
        unique_indicator_count = 0
        bytes_scanned = 0
        budget_reason: str | None = None

        def retain(bucket: set, value: tuple) -> bool:
            nonlocal unique_indicator_count, budget_reason
            if value in bucket:
                return True
            if unique_indicator_count >= _MAX_NETWORK_INDICATORS:
                budget_reason = (
                    f"unique indicator cap of {_MAX_NETWORK_INDICATORS:,} reached"
                )
                return False
            bucket.add(value)
            unique_indicator_count += 1
            return True

        def retain_protocol(label: str, line_number: int) -> None:
            protocol_counts[label] = protocol_counts.get(label, 0) + 1
            samples = protocols.setdefault(label, [])
            if len(samples) < _MAX_NETWORK_PROTOCOL_LINES:
                samples.append(line_number)

        line_number = 1
        try:
            with path.open("rb") as stream:
                while bytes_scanned < _MAX_NETWORK_FILE_BYTES:
                    remaining = _MAX_NETWORK_FILE_BYTES - bytes_scanned
                    raw_line = stream.readline(
                        min(_MAX_NETWORK_LINE_BYTES, remaining + 1)
                    )
                    if not raw_line:
                        break
                    if len(raw_line) > remaining:
                        budget_reason = "file byte budget reached"
                        break
                    bytes_scanned += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace")

                    for candidate in _CIDR.findall(line):
                        try:
                            network = ipaddress.ip_network(candidate, strict=False)
                            if not retain(cidrs, (str(network), line_number)):
                                break
                        except ValueError:
                            pass
                    if budget_reason:
                        break

                    for candidate in _IPV4.findall(line):
                        try:
                            parsed = ipaddress.ip_address(candidate)
                            if not retain(addresses["IPv4"], (str(parsed), line_number)):
                                break
                        except ValueError:
                            pass
                    if budget_reason:
                        break

                    for pattern in (_IPV6, _IPV6_MAPPED):
                        for candidate in pattern.findall(line):
                            try:
                                parsed = ipaddress.ip_address(candidate)
                                if parsed.version == 6 and parsed.ipv4_mapped is not None:
                                    mapped = int(parsed.ipv4_mapped)
                                    normalized = f"::ffff:{mapped >> 16:x}:{mapped & 0xFFFF:x}"
                                else:
                                    normalized = parsed.compressed
                                if not retain(addresses["IPv6"], (normalized, line_number)):
                                    break
                            except ValueError:
                                pass
                        if budget_reason:
                            break
                    if budget_reason:
                        break

                    for match in _PORT_KEY.finditer(line):
                        value = int(match.group(1))
                        if 1 <= value <= 65535 and not retain(ports, (value, line_number)):
                            break
                    if budget_reason:
                        break
                    for pattern in (_HOST_PORT, _BARE_PORT):
                        for match in pattern.finditer(line):
                            value = int(match.group(1))
                            if 1 <= value <= 65535 and not retain(ports, (value, line_number)):
                                break
                        if budget_reason:
                            break
                    if budget_reason:
                        break

                    for match in _URI.finditer(line):
                        raw_uri = match.group(0).rstrip(".,;:)]}")
                        safe = _safe_uri(raw_uri)
                        if safe:
                            if not retain(uris, (safe, line_number)):
                                break
                            try:
                                host = urlsplit(raw_uri).hostname
                            except ValueError:
                                host = None
                            if host:
                                try:
                                    ipaddress.ip_address(host)
                                except ValueError:
                                    if not retain(domains, (host.lower().rstrip("."), line_number)):
                                        break
                            try:
                                uri_port = urlsplit(raw_uri).port
                            except ValueError:
                                uri_port = None
                            if uri_port is not None and 1 <= uri_port <= 65535:
                                if not retain(ports, (uri_port, line_number)):
                                    break
                        if budget_reason:
                            break
                    if budget_reason:
                        break

                    for match in _DOMAIN.finditer(line):
                        domain = match.group(0).lower().rstrip(".")
                        if domain not in {
                            "example.com", "example.org", "example.net",
                            "localhost.localdomain",
                        }:
                            if not retain(domains, (domain, line_number)):
                                break
                    if budget_reason:
                        break

                    for label, pattern in _PROTOCOL_PATTERNS.items():
                        if pattern.search(line):
                            retain_protocol(label, line_number)

                    if raw_line.endswith((b"\n", b"\r")):
                        line_number += 1

                if budget_reason is None and bytes_scanned >= _MAX_NETWORK_FILE_BYTES:
                    if stream.read(1):
                        budget_reason = "file byte budget reached"
        except OSError as exc:
            return [Finding(
                "network",
                f"Network indicator scan unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        findings: list[Finding] = []
        for version, values in addresses.items():
            if values:
                unique = {value for value, _ in values}
                findings.append(Finding(
                    "network",
                    f"{version} address indicators: {record.path}",
                    f"Detected at least {len(unique):,} distinct {version} literal(s) "
                    "within the scanned portion. These are static references, not evidence "
                    "of active interfaces or reachability.",
                    confidence="CONFIRMED",
                    evidence=[
                        f"{record.path}:{line} ({value})"
                        for value, line in sorted(values)[:_MAX_NETWORK_EVIDENCE]
                    ],
                    analyzer=self.name,
                ))
        if cidrs:
            findings.append(Finding(
                "network",
                f"CIDR network indicators: {record.path}",
                f"Detected at least {len({value for value, _ in cidrs}):,} distinct CIDR range(s) "
                "within the scanned portion.",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{line} ({value})"
                    for value, line in sorted(cidrs)[:_MAX_NETWORK_EVIDENCE]
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
                f"Detected at least {len(values):,} distinct port number(s): "
                + ", ".join(descriptions[:50])
                + ". A port declaration does not prove a listener is active.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} (port {value})"
                    for value, line in sorted(ports)[:_MAX_NETWORK_EVIDENCE]
                ],
                analyzer=self.name,
            ))
        if uris:
            findings.append(Finding(
                "network",
                f"URL/URI indicators: {record.path}",
                f"Detected at least {len(uris):,} URI reference(s) within the scanned portion. "
                "Userinfo, paths, query strings and fragments are redacted from evidence.",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{line} ({value})"
                    for value, line in sorted(uris)[:_MAX_NETWORK_EVIDENCE]
                ],
                analyzer=self.name,
            ))
        if domains:
            domain_values = {value for value, _ in domains}
            subdomains = {value for value in domain_values if len(value.split(".")) > 2}
            findings.append(Finding(
                "network",
                f"Hostname and domain indicators: {record.path}",
                f"Detected at least {len(domain_values):,} distinct FQDN/domain candidate(s), "
                f"including {len(subdomains):,} probable subdomain(s) within the scanned portion. "
                "Public suffixes and DNS ownership are not resolved.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} ({value})"
                    for value, line in sorted(domains)[:_MAX_NETWORK_EVIDENCE]
                ],
                analyzer=self.name,
            ))
        if protocols:
            detected = sorted(protocols)
            findings.append(Finding(
                "network",
                f"Network protocol references: {record.path}",
                "Detected protocol/API markers: " + ", ".join(
                    f"{label} ({protocol_counts.get(label, 0):,} line(s))"
                    for label in detected
                )
                + ". Marker presence does not confirm protocol implementation or use.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} ({label})"
                    for label, lines in sorted(protocols.items())
                    for line in lines
                ][:_MAX_NETWORK_EVIDENCE],
                analyzer=self.name,
            ))
        if budget_reason:
            findings.append(Finding(
                "network",
                f"Network indicator scan budget reached: {record.path}",
                f"Analysis stopped after {bytes_scanned:,} bytes because the {budget_reason}. "
                "Indicators collected before the limit are partial; remaining content was "
                "not inspected.",
                confidence="UNKNOWN",
                evidence=[
                    record.path,
                    f"bytes_scanned: {bytes_scanned:,}",
                    f"unique_indicators_retained: {unique_indicator_count:,}",
                ],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
