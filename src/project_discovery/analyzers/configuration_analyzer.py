"""Local configuration inventory and conservative risky-setting detection."""
from __future__ import annotations

import configparser
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import CodeEvidence, FileRecord, Finding
from ..source_utils import redact_source_excerpt


_CONFIG_FILENAMES = {
    ".env", ".envrc", "dockerfile", "containerfile", "docker-compose.yml", "compose.yml",
    "nginx.conf", "config.ini", "settings.ini", "appsettings.json", "web.config",
    "application.properties", "application.yml", "application.yaml", "bootstrap.yml",
    "bootstrap.yaml", "sshd_config", "my.cnf", "php.ini", "redis.conf",
    "postgresql.conf", "haproxy.cfg", "supervisord.conf", "logback.xml",
    "log4j2.xml", "cloud.cfg",
}
_CONFIG_EXTENSIONS = {
    ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".tf", ".tfvars", ".hcl", ".nix", ".xml", ".plist", ".service", ".desktop", ".rc", ".cnf", ".json5", ".jsonc",
}
_KEY_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(.*?)\s*$")
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_RISK_PATTERNS = (
    ("debug_enabled", re.compile(r"(?i)^\s*(?:debug|debug_mode)\s*[:=]\s*(?:true|1|yes|on)\b")),
    ("tls_verification_disabled", re.compile(
        r"(?i)^\s*(?:verify|ssl_verify|tls_verify|rejectUnauthorized|insecure_skip_verify)\s*[:=]\s*(?:false|0|no|off|true)\b"
    )),
    ("privileged_container", re.compile(r"(?i)^\s*privileged\s*:\s*true\b")),
    ("privilege_escalation_enabled", re.compile(
        r"(?i)^\s*allowPrivilegeEscalation\s*:\s*true\b"
    )),
    ("root_user_allowed", re.compile(r"(?i)^\s*runAsNonRoot\s*:\s*false\b")),
    ("host_network_enabled", re.compile(r"(?i)^\s*hostNetwork\s*:\s*true\b")),
    ("root_container_user", re.compile(r"(?i)^\s*USER\s+root\b")),
    ("nginx_client_verification_disabled", re.compile(r"(?i)\bssl_verify_client\s+off\b")),
    ("wildcard_cors", re.compile(
        r"(?i)(?:allow[_-]?origins?|access-control-allow-origin)\s*[:=]\s*(?:\[\s*)?\*",
    )),
)
_SECRET_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)")

_RISK_IMPACTS = {
    "debug_enabled": (
        "If enabled in a deployed environment, debug behavior may expose stack traces, "
        "internal paths, diagnostic data or secrets and may weaken production protections.",
        "Disable debug mode in production and gate diagnostic endpoints behind access controls."
    ),
    "tls_verification_disabled": (
        "A network attacker may impersonate the remote peer and intercept or modify traffic, "
        "including credentials and application data.",
        "Enable certificate and hostname verification; install the correct trust chain instead of bypassing validation."
    ),
    "privileged_container": (
        "A compromised privileged container may gain broad host-device and kernel access, "
        "increasing the chance of host compromise.",
        "Remove privileged mode and grant only the specific capabilities and devices the workload requires."
    ),
    "privilege_escalation_enabled": (
        "A compromised process may gain additional Linux capabilities or elevate privileges "
        "inside its container, depending on the runtime and security context.",
        "Set allowPrivilegeEscalation to false unless a documented requirement justifies it."
    ),
    "root_user_allowed": (
        "If the workload runs as root, code execution in the container may provide elevated "
        "access to mounted files and services.",
        "Run as a dedicated non-root user and set runAsNonRoot with an explicit user ID."
    ),
    "host_network_enabled": (
        "The workload shares the host network namespace, which can expose host-bound services "
        "and bypass intended network isolation.",
        "Disable host networking and declare only the required service ports and network policies."
    ),
    "root_container_user": (
        "If the container process is compromised, it may have root privileges within the "
        "container and broader access to mounted resources.",
        "Use a dedicated non-root USER and drop unnecessary Linux capabilities."
    ),
    "nginx_client_verification_disabled": (
        "If mutual TLS is required, disabling client-certificate verification may allow clients "
        "without a trusted certificate to connect.",
        "Enable and configure client certificate verification with a trusted CA where mTLS is required."
    ),
    "wildcard_cors": (
        "A wildcard origin policy may allow arbitrary websites to make cross-origin requests; "
        "if sensitive responses are otherwise exposed, this can increase data-disclosure risk.",
        "Use an explicit origin allowlist and review credentialed CORS behavior."
    ),
}

_NIX_ASSIGNMENT = re.compile(r"(?m)\b([A-Za-z_][A-Za-z0-9_.-]*)\s*=")


def _flatten(data: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.append(path)
            keys.extend(_flatten(value, path))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            keys.extend(_flatten(value, f"{prefix}[{index}]"))
    return keys


def _xml_keys(content: str) -> list[str]:
    root = ET.fromstring(content)
    keys: list[str] = []

    def visit(element: ET.Element, prefix: str = "") -> None:
        tag = element.tag.rsplit("}", 1)[-1]
        current = f"{prefix}.{tag}" if prefix else tag
        keys.append(current)
        keys.extend(f"{current}@{name}" for name in element.attrib)
        for child in element:
            visit(child, current)

    visit(root)
    return keys


def _directive_keys(content: str) -> list[str]:
    pattern = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s+(?![=:])([^;#]+?);?\s*$")
    return [
        match.group(1) for line in content.splitlines()
        if not line.lstrip().startswith(("#", ";", "//"))
        and (match := pattern.match(line))
    ]


def _parse_config(path: Path, record: FileRecord) -> tuple[list[str], list[tuple[int, str]]]:
    name = Path(record.path).name.lower()
    content = path.read_text(encoding="utf-8")
    risks: list[tuple[int, str]] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        for risk_name, pattern in _RISK_PATTERNS:
            if pattern.search(line):
                risks.append((line_number, risk_name))

    if name in {".env", ".envrc"} or name.startswith(".env."):
        keys = [
            match.group(1) for line in content.splitlines()
            if (match := _ENV_LINE.match(line)) and not line.lstrip().startswith("#")
        ]
    elif record.extension == ".json":
        keys = _flatten(json.loads(content))
    elif record.extension in {".json5", ".jsonc"}:
        keys = sorted(set(re.findall(r"""["']([^"']+)["']\s*:""", content)))
    elif record.extension == ".toml":
        keys = _flatten(tomllib.loads(content))
    elif record.extension in {".ini", ".cfg"}:
        parser = configparser.ConfigParser()
        parser.read_string(content)
        keys = [
            f"{section}.{key}" for section in parser.sections()
            for key, _ in parser.items(section)
        ]
    elif record.extension in {".xml", ".plist"} or name == "web.config" or name.endswith(".xml"):
        keys = _xml_keys(content)
    elif record.extension in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError:
            keys = [
                match.group(1) for line in content.splitlines()
                if (match := _KEY_LINE.match(line))
                and not line.lstrip().startswith(("#", "//"))
            ]
        else:
            try:
                keys = _flatten(yaml.safe_load(content))
            except yaml.YAMLError as exc:
                raise ValueError(f"YAML parse error: {exc}") from exc
    elif name in {"dockerfile", "containerfile"}:
        keys = [
            match.group(1).upper() for line in content.splitlines()
            if (match := re.match(
                r"(?i)^\s*(FROM|ARG|ENV|USER|WORKDIR|EXPOSE|ENTRYPOINT|CMD|HEALTHCHECK|SHELL)\b",
                line,
            ))
        ]
    elif name == "nginx.conf":
        keys = _directive_keys(content)
    elif record.extension == ".nix":
        keys = _NIX_ASSIGNMENT.findall(content)
    elif record.extension in {
        ".conf", ".properties", ".tf", ".tfvars", ".hcl", ".nix",
        ".service", ".desktop", ".rc", ".cnf",
    } or name in _CONFIG_FILENAMES:
        keys = [
            match.group(1) for line in content.splitlines()
            if (match := _KEY_LINE.match(line))
            and not line.lstrip().startswith(("#", "//", "!"))
        ]
        if name == "sshd_config":
            keys.extend(_directive_keys(content))
    else:
        keys = []
    return sorted(set(keys)), risks


class ConfigurationAnalyzer(Analyzer):
    """Inventory configuration keys without exposing their values."""

    name = "configuration-intelligence"
    domains = ("configuration",)

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            record.extension in _CONFIG_EXTENSIONS or name in _CONFIG_FILENAMES
            or name == ".env" or name == ".envrc" or name.startswith(".env.")
            or name.startswith("appsettings.") and name.endswith(".json")
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            keys, risks = _parse_config(path, record)
            source_lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, configparser.Error, ET.ParseError, ValueError) as exc:
            return [Finding(
                "configuration",
                f"Configuration parse error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        findings: list[Finding] = []
        if keys:
            sensitive_key_count = sum(bool(_SECRET_KEY.search(key)) for key in keys)
            findings.append(Finding(
                "configuration",
                f"Configuration inventory: {record.path}",
                f"Observed {len(keys)} configuration keys; {sensitive_key_count} key names "
                "appear credential-related. Values are not included in the report.",
                confidence="CONFIRMED",
                evidence=[record.path] + [f"key: {key}" for key in keys[:100]],
                analyzer=self.name,
            ))
        for line_number, risk_name in risks:
            findings.append(Finding(
                "security",
                f"Potential risky configuration: {risk_name}",
                "A configuration pattern associated with a security risk was observed. "
                "Context and deployment intent must be reviewed; the raw value is not reported.",
                confidence="INFERRED",
                evidence=[f"{record.path}:{line_number}"],
                analyzer=self.name,
                severity=(
                    "HIGH" if risk_name in {
                        "tls_verification_disabled", "privileged_container",
                        "privilege_escalation_enabled", "host_network_enabled", "wildcard_cors",
                        "root_container_user", "nginx_client_verification_disabled"
                    } else "MEDIUM"
                ),
                code_evidence=(
                    [CodeEvidence(
                        line_number=line_number,
                        code=redact_source_excerpt(source_lines[line_number - 1]),
                    )]
                    if 0 < line_number <= len(source_lines) else []
                ),
                impact=_RISK_IMPACTS.get(
                    risk_name,
                    (
                        "If this configuration is active in a deployed environment, it may "
                        "weaken a security boundary or expose additional diagnostic information.",
                        "Review the effective runtime configuration and apply the least-privilege setting."
                    )
                )[0],
                recommendation=_RISK_IMPACTS.get(
                    risk_name,
                    (
                        "If this configuration is active in a deployed environment, it may "
                        "weaken a security boundary or expose additional diagnostic information.",
                        "Review the effective runtime configuration and apply the least-privilege setting."
                    )
                )[1],
            ))
        return findings
