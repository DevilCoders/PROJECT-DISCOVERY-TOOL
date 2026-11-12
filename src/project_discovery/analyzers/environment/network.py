"""Static network, URL/URI, address, port and service-protocol discovery."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from importlib.resources import files as resource_files
from pathlib import Path
from urllib.parse import urlsplit

from ...catalog.languages import is_source_path, is_textual_path, known_extensions
from ...core.source_utils import describe_error, open_verified_binary
from ...models import FileRecord, Finding
from ..base import Analyzer

_URI = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s<>\"']+", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# Identifier characters on either side mean a scope operator or symbol, not an address.
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])")
# Generic TLDs accepted for bare two-label names; other TLDs need a subdomain or URL.
_COMMON_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "ai", "dev", "app", "cloud",
    "co", "me", "info", "biz", "xyz", "tech", "online", "site", "store", "us", "uk",
    "de", "fr", "eu", "nl", "ca", "au", "jp", "cn", "ru", "br", "in", "ch", "se", "local",
    "internal", "test", "example", "invalid", "localhost", "corp", "lan", "home",
})
_REVERSE_DNS_ROOTS = frozenset({
    "com", "org", "net", "edu", "gov", "io", "de", "fr", "uk", "nl", "eu", "ch", "jp",
})
# Reserved/special-use names are not public DNS TLDs but are meaningful in configuration.
_SPECIAL_USE_TLDS = frozenset({"local", "internal", "test", "example", "invalid", "localhost", "corp", "lan", "home"})


@lru_cache(maxsize=1)
def iana_tlds() -> frozenset[str]:
    """Lower-cased IANA root-zone TLDs from the bundled snapshot (data/tlds.txt)."""
    text = resource_files("project_discovery").joinpath("data/tlds.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


@lru_cache(maxsize=1)
def _extension_labels() -> frozenset[str]:
    # File names such as setup.py, README.md and app.zip end in real ccTLDs/gTLDs.
    return known_extensions() | {"zip", "mov", "exe", "dll", "so", "bin", "log", "lock", "bak", "tmp"}


def _plausible_hostname(domain: str) -> bool:
    labels = domain.split(".")
    tld = labels[-1]
    if tld not in iana_tlds() and tld not in _SPECIAL_USE_TLDS:
        return False
    if tld in _extension_labels():
        return False
    if len(labels) >= 3 and labels[0] in _REVERSE_DNS_ROOTS:
        return False  # reverse-DNS identifiers such as com.example.app
    return len(labels) >= 3 or tld in _COMMON_TLDS


def _plausible_ipv6(candidate: str, line: str, start: int) -> bool:
    """Reject bare "::" and single-group forms unless they appear bracketed or as ::1."""
    groups = [group for group in candidate.split(":") if group]
    if len(groups) >= 2 or candidate.lower() == "::1":
        return True
    return start > 0 and line[start - 1] == "["


_QUOTE_CHARS = re.compile(r"""["'`]""")
_LITERAL_REST = {
    quote: re.compile(r"(?:\\.|[^\\\r\n" + quote + r"])*+" + quote) for quote in "\"'`"
}


def _literal_spans(line: str) -> list[tuple[int, int]]:
    """Body spans of escape-aware quoted literals on one line.

    A single-regex scan restarts at every later quote after an unterminated one, which
    is quadratic on lines such as ``'\\'\\'\\'...``. Once a quote kind finds no closing
    quote, every later quote of that kind parses the same remainder and fails too, so
    the kind is skipped for the rest of the line and the scan stays linear.
    """
    spans: list[tuple[int, int]] = []
    unclosed: set[str] = set()
    position = 0
    while (quote := _QUOTE_CHARS.search(line, position)) is not None:
        kind, start = quote.group(), quote.end()
        position = start
        if kind in unclosed:
            continue
        rest = _LITERAL_REST[kind].match(line, start)
        if rest is None:
            unclosed.add(kind)
            continue
        spans.append((start, rest.end() - 1))
        position = rest.end()
    return spans


def _in_spans(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(left <= start and end <= right for left, right in spans)
_IPV6_MAPPED = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,6}(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_CIDR = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|(?<![\w:])[0-9A-Fa-f:]{3,}/\d{1,3}\b")
_PORT_KEY = re.compile(
    r"""(?i)\b(?:port|listen|expose|target_port|containerPort|hostPort|bind_port)\s*(?:=|:)\s*['"]?(\d{1,5})\b"""
)
_HOST_PORT = re.compile(
    r"""(?i)(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\])\s*:\s*(\d{1,5})\b"""
)
_BARE_PORT = re.compile(r"""(?im)^[ \t]*(?:EXPOSE|listen)\s+(\d{1,5})\b""")
# Matches start only where a dotted name begins (not after "label."), so a long dotted
# run such as "a.a.a..." is tried once instead of once per label (quadratic).
_DOMAIN = re.compile(
    r"(?<![@\w-])(?<![A-Za-z0-9]\.)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
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
# One pass per line over all protocol markers; group names map back to labels.
_PROTOCOL_LABELS = {f"p{index}": label for index, label in enumerate(_PROTOCOL_PATTERNS)}
_PROTOCOL_ANY = re.compile(
    "|".join(f"(?P<p{index}>{pattern.pattern})" for index, pattern in enumerate(_PROTOCOL_PATTERNS.values())),
    re.IGNORECASE,
)
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


_HOST_NAME = re.compile(r"\w(?:[\w.-]{0,251}\w)?")


def _authority(netloc: str) -> tuple[str | None, int | None]:
    """(host, port) of a URI authority, without userinfo, properties or other hosts.

    urlsplit takes everything up to the first ``/`` as the host, so Microsoft's JDBC form
    ``sqlserver://db01;user=sa;password=...``, a named instance ``db01\\SQLEXPRESS`` and
    a replica list ``h1:27017,h2:27017`` became "host names" that carried their
    properties, password included, into the report.
    """
    authority = re.split(r"[;\\,]", netloc, maxsplit=1)[0]
    try:
        parts = urlsplit("//" + authority)
        host = parts.hostname
    except ValueError:
        return None, None
    if not host:
        return None, None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_NAME.fullmatch(host):
            return None, None
    try:
        port = parts.port
    except ValueError:
        port = None
    return host, port


def _safe_uri(value: str) -> str | None:
    value = value.rstrip(".,;:)]}")
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if not parsed.scheme:
        return None
    host, port = _authority(parsed.netloc)
    if not host:
        return f"{parsed.scheme.lower()}:<non-network URI>"
    host_text = f"[{host}]" if ":" in host else host
    suffix = f":{port}" if port is not None else ""
    return f"{parsed.scheme.lower()}://{host_text}{suffix}/<redacted-path>"


@lru_cache(maxsize=8192)
def _parse_uri(raw_uri: str) -> tuple[str | None, str | None, int | None]:
    """Return (redacted URI, non-IP host, port); memoized because URLs repeat heavily."""
    safe = _safe_uri(raw_uri)
    if not safe:
        return None, None, None
    try:
        host, port = _authority(urlsplit(raw_uri.rstrip(".,;:)]}")).netloc)
    except ValueError:
        return safe, None, None
    if host:
        try:
            ipaddress.ip_address(host)
            host = None  # IP literals are reported as addresses, not hostnames
        except ValueError:
            host = host.lower().rstrip(".")
    return safe, host, port


class NetworkIndicatorAnalyzer(Analyzer):
    """Extract static network indicators; never probes or connects to discovered hosts."""

    name = "network-indicators"
    domains = ("networking",)
    languages = ("Polyglot text/source/configuration",)

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
        line_limit_exceeded = 0
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
        source_code = is_source_path(record.path)
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
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
                    if (
                        len(raw_line) == _MAX_NETWORK_LINE_BYTES
                        and not raw_line.endswith(b"\n")
                    ):
                        next_byte = stream.read(1)
                        if next_byte == b"\n":
                            raw_line += next_byte
                        elif next_byte:
                            # Skip an overlong physical line with bounded reads, then
                            # continue scanning subsequent lines. Its content remains
                            # explicitly uninspected in the UNKNOWN diagnostic below.
                            line_limit_exceeded += 1
                            bytes_scanned += len(raw_line) + 1
                            while bytes_scanned < _MAX_NETWORK_FILE_BYTES:
                                remaining = _MAX_NETWORK_FILE_BYTES - bytes_scanned
                                discarded = stream.readline(
                                    min(_MAX_NETWORK_LINE_BYTES, remaining + 1)
                                )
                                if not discarded:
                                    break
                                if len(discarded) > remaining:
                                    bytes_scanned = _MAX_NETWORK_FILE_BYTES
                                    budget_reason = (
                                        "file byte budget reached while skipping an overlong physical line"
                                    )
                                    break
                                bytes_scanned += len(discarded)
                                if discarded.endswith(b"\n"):
                                    line_number += 1
                                    break
                            if budget_reason:
                                break
                            continue
                    bytes_scanned += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace")
                    # Cheap substring gates skip regex families that cannot match.
                    has_dot = "." in line
                    colons = line.count(":")
                    lower = line.lower()
                    port_words = "port" in lower or "listen" in lower or "expose" in lower

                    for candidate in (_CIDR.findall(line) if "/" in line else ()):
                        try:
                            network = ipaddress.ip_network(candidate, strict=False)
                            if not retain(cidrs, (str(network), line_number)):
                                break
                        except ValueError:
                            pass
                    if budget_reason:
                        break

                    for candidate in (_IPV4.findall(line) if has_dot else ()):
                        try:
                            parsed = ipaddress.ip_address(candidate)
                            if not retain(addresses["IPv4"], (str(parsed), line_number)):
                                break
                        except ValueError:
                            pass
                    if budget_reason:
                        break

                    # In source code, bare hosts and IPv6 forms only count inside string
                    # literals; elsewhere "a.b" and "x::y" are member access and scopes.
                    spans = _literal_spans(line) if source_code and (has_dot or colons) else None
                    for pattern in ((_IPV6, _IPV6_MAPPED) if colons >= 2 else ()):
                        for match in pattern.finditer(line):
                            candidate = match.group(0)
                            if spans is not None and not _in_spans(spans, match.start(), match.end()):
                                continue
                            if pattern is _IPV6 and not _plausible_ipv6(candidate, line, match.start()):
                                continue
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

                    for match in (_PORT_KEY.finditer(line) if port_words else ()):
                        value = int(match.group(1))
                        if 1 <= value <= 65535 and not retain(ports, (value, line_number)):
                            break
                    if budget_reason:
                        break
                    for pattern in (
                        ((_HOST_PORT,) if colons else ()) + ((_BARE_PORT,) if port_words else ())
                    ):
                        for match in pattern.finditer(line):
                            value = int(match.group(1))
                            if 1 <= value <= 65535 and not retain(ports, (value, line_number)):
                                break
                        if budget_reason:
                            break
                    if budget_reason:
                        break

                    for match in (_URI.finditer(line) if "://" in line else ()):
                        safe, host, uri_port = _parse_uri(match.group(0).rstrip(".,;:)]}"))
                        if safe:
                            if not retain(uris, (safe, line_number)):
                                break
                            if host and not retain(domains, (host, line_number)):
                                break
                            if uri_port is not None and 1 <= uri_port <= 65535:
                                if not retain(ports, (uri_port, line_number)):
                                    break
                        if budget_reason:
                            break
                    if budget_reason:
                        break

                    for match in (_DOMAIN.finditer(line) if has_dot else ()):
                        domain = match.group(0).lower().rstrip(".")
                        if domain in {
                            "example.com", "example.org", "example.net",
                            "localhost.localdomain",
                        } or not _plausible_hostname(domain):
                            continue
                        if spans is not None and not _in_spans(spans, match.start(), match.end()):
                            continue
                        if not retain(domains, (domain, line_number)):
                            break
                    if budget_reason:
                        break

                    for label in {_PROTOCOL_LABELS[m.lastgroup] for m in _PROTOCOL_ANY.finditer(line)}:
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
                describe_error(exc),
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
        if line_limit_exceeded:
            findings.append(Finding(
                "network",
                f"Network indicator scan skipped overlong line(s): {record.path}",
                f"Skipped {line_limit_exceeded:,} physical line(s) exceeding the "
                f"{_MAX_NETWORK_LINE_BYTES:,}-byte line budget to keep memory bounded. "
                "Other lines were still inspected; the skipped content remains unknown.",
                confidence="UNKNOWN",
                evidence=[
                    record.path,
                    f"overlong_lines_skipped: {line_limit_exceeded:,}",
                    f"bytes_scanned: {bytes_scanned:,}",
                ],
                analyzer=self.name,
                severity="LOW",
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
