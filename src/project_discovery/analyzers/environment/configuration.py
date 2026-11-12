"""Local configuration inventory and conservative risky-setting detection."""
from __future__ import annotations

import configparser
import io
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ...core.safe_parsers import safe_xml_fromstring, safe_yaml_load
from ...core.source_utils import describe_error, open_verified_binary, redact_source_excerpt, text_encoding
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer

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
# Only the key is read; values are never part of the inventory.
_KEY_LINE = re.compile(r"^\s*+([A-Za-z_][A-Za-z0-9_.-]*+)\s*+[:=]")
_ENV_LINE = re.compile(r"^\s*+(?:export\s++)?([A-Za-z_][A-Za-z0-9_]*+)\s*+=")
# Keys and values may be quoted (JSON, YAML, TOML): "debug": true, verify: 'false'.
_Q = "[\"']?"
_RISK_PATTERNS = (
    ("debug_enabled", re.compile(rf"(?i)^\s*{_Q}(?:debug|debug_mode){_Q}\s*[:=]\s*{_Q}(?:true|1|yes|on)\b")),
    ("tls_verification_disabled", re.compile(
        rf"(?i)^\s*{_Q}(?:(?:verify|ssl_?verify|tls_?verify|rejectUnauthorized){_Q}\s*[:=]\s*{_Q}(?:false|0|no|off)"
        rf"|(?:insecure_skip_verify|insecureSkipVerify){_Q}\s*[:=]\s*{_Q}(?:true|1|yes|on))\b"
    )),
    ("privileged_container", re.compile(rf"(?i)^\s*{_Q}privileged{_Q}\s*:\s*true\b")),
    ("privilege_escalation_enabled", re.compile(
        rf"(?i)^\s*{_Q}allowPrivilegeEscalation{_Q}\s*:\s*true\b"
    )),
    ("root_user_allowed", re.compile(rf"(?i)^\s*{_Q}runAsNonRoot{_Q}\s*:\s*false\b")),
    ("host_network_enabled", re.compile(rf"(?i)^\s*{_Q}hostNetwork{_Q}\s*:\s*true\b")),
    ("root_container_user", re.compile(r"(?i)^\s*USER\s+root\b")),
    ("nginx_client_verification_disabled", re.compile(r"(?i)\bssl_verify_client\s+off\b")),
    # allow_origins: ['*'], "allowedOrigins": "*", allowed-origins=*, and nginx's
    # add_header Access-Control-Allow-Origin *; the wildcard must be the whole value.
    ("wildcard_cors", re.compile(
        rf"(?i)(?:allow(?:ed)?[_-]?origins?|access-control-allow-origin){_Q}(?:\s*[:=]\s*|\s+)(?:\[\s*)?{_Q}\*(?![\w.*-])",
    )),
)
_SECRET_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)")
_MAX_CONFIG_FILE_BYTES = 16 * 1024 * 1024
_MAX_CONFIG_KEYS = 100_000
_MAX_CONFIG_RISK_LINES = 100


class ConfigurationKeyBudgetExceeded(ValueError):
    """Raised when a configuration file contains too many distinct key entries."""


def _append_key(keys: list[str], key: str) -> None:
    if len(keys) >= _MAX_CONFIG_KEYS:
        raise ConfigurationKeyBudgetExceeded(
            f"configuration exceeded the {_MAX_CONFIG_KEYS:,}-key inventory budget"
        )
    keys.append(str(key))


def _collect_keys(values) -> list[str]:
    keys: list[str] = []
    for value in values:
        _append_key(keys, str(value))
    return keys


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

# Starts only where an attribute path begins; \b also matched after every "-" and ".",
# rescanning the same path once per segment (quadratic on "a-a-a-...").
_NIX_ASSIGNMENT = re.compile(r"(?m)(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]*+)\s*+=")


def _flatten(data: Any, prefix: str = "", keys: list[str] | None = None) -> list[str]:
    """Flatten nested mapping/list keys while enforcing the configuration key budget."""
    if keys is None:
        keys = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            _append_key(keys, path)
            _flatten(value, path, keys)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            _flatten(value, f"{prefix}[{index}]", keys)
    return keys


def _xml_keys(content: str) -> list[str]:
    root = safe_xml_fromstring(content)
    keys: list[str] = []
    stack: list[tuple[ET.Element, str]] = [(root, "")]
    while stack:
        element, prefix = stack.pop()
        tag = element.tag.rsplit("}", 1)[-1]
        current = f"{prefix}.{tag}" if prefix else tag
        _append_key(keys, current)
        for name in element.attrib:
            _append_key(keys, f"{current}@{name}")
        for child in element:
            if len(stack) >= _MAX_CONFIG_KEYS:
                raise ConfigurationKeyBudgetExceeded(
                    f"XML configuration exceeded the {_MAX_CONFIG_KEYS:,}-node traversal budget"
                )
            stack.append((child, current))
    return keys


_DIRECTIVE = re.compile(r"[ \t]*+([A-Za-z_][A-Za-z0-9_.-]*+)[ \t]++(?![=:])")


def _directive_keys(content: str) -> list[str]:
    """Directive names of nginx- and sshd-style lines (``name value;``).

    A directive is a name, whitespace and a value with no ``;`` or ``#`` except one
    trailing ``;``. The former single regex let its whitespace and value runs trade
    characters, which was cubic on a long line of spaces.
    """
    keys: list[str] = []
    for line in io.StringIO(content, newline=None):
        if line.lstrip().startswith(("#", ";", "//")):
            continue
        match = _DIRECTIVE.match(line)
        if not match:
            continue
        value = line[match.end():].rstrip()
        if value.endswith(";"):
            value = value[:-1]
        if value.strip() and ";" not in value and "#" not in value:
            _append_key(keys, match.group(1))
    return keys


def _line_keys(content: str) -> list[str]:
    return _collect_keys(
        match.group(1)
        for line in io.StringIO(content, newline=None)
        if (match := _KEY_LINE.match(line)) and not line.lstrip().startswith(("#", ";", "//", "!"))
    )


def _yaml_keys(content: str) -> list[str]:
    try:
        import yaml
    except ImportError:
        return _line_keys(content)
    try:
        return _flatten(safe_yaml_load(content))
    except yaml.YAMLError as exc:
        raise ValueError("YAML parse error") from exc


# Names whose format their extension does not tell (checked before the extension).
_DIRECTIVE_FILES = frozenset({"haproxy.cfg", "nginx.conf", "sshd_config"})
_YAML_FILES = frozenset({"cloud.cfg"})
_JSONC_NAMES = frozenset({"jsconfig.json", "devcontainer.json", ".devcontainer.json", "settings.json",
                          "launch.json", "tasks.json", "extensions.json"})


def _jsonc_file(record: FileRecord, name: str) -> bool:
    """tsconfig.json and editor settings carry comments (tsc --init writes them)."""
    path = record.path.replace("\\", "/").lower()
    return name.endswith(".json") and (
        name.startswith("tsconfig") or (name in _JSONC_NAMES and (
            name in {"jsconfig.json", "devcontainer.json", ".devcontainer.json"}
            or "/.vscode/" in f"/{path}" or "/.devcontainer/" in f"/{path}"
        ))
    )


def _parse_config(
    content: str, record: FileRecord
) -> tuple[list[str], list[tuple[int, str]], dict[int, str]]:
    name = Path(record.path).name.lower()
    risks: list[tuple[int, str]] = []
    risk_source: dict[int, str] = {}
    risk_counts: dict[str, int] = {}
    for line_number, line in enumerate(io.StringIO(content, newline=None), 1):
        for risk_name, pattern in _RISK_PATTERNS:
            if pattern.search(line) and risk_counts.get(risk_name, 0) < _MAX_CONFIG_RISK_LINES:
                risks.append((line_number, risk_name))
                risk_source[line_number] = redact_source_excerpt(line)
                risk_counts[risk_name] = risk_counts.get(risk_name, 0) + 1

    if name in _DIRECTIVE_FILES:
        keys = _directive_keys(content)
        if name == "sshd_config":
            for key in _line_keys(content):
                _append_key(keys, key)
    elif name in _YAML_FILES:
        keys = _yaml_keys(content)
    elif _jsonc_file(record, name):
        keys = _collect_keys(
            match.group(1) for match in re.finditer(r"""["']([^"'\n]{1,200}+)["']\s*:""", content)
        )
    elif name in {".env", ".envrc"} or name.startswith(".env."):
        keys = _collect_keys(
            match.group(1)
            for line in io.StringIO(content, newline=None)
            if (match := _ENV_LINE.match(line)) and not line.lstrip().startswith("#")
        )
    elif record.extension == ".json":
        keys = _flatten(json.loads(content))
    elif record.extension in {".json5", ".jsonc"}:
        keys = _collect_keys(
            match.group(1) for match in re.finditer(r"""["']([^"']+)["']\s*:""", content)
        )
    elif record.extension == ".toml":
        keys = _flatten(tomllib.loads(content))
    elif record.extension in {".ini", ".cfg"}:
        # Values are never read, so nothing is interpolated: interpolation raised on
        # logging-style "%(asctime)s" values (alembic.ini, logging.ini) and quoted the raw
        # value in its error. Duplicate keys are merged rather than refused.
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(content)
        except configparser.MissingSectionHeaderError:
            keys = _line_keys(content)  # key = value files without [sections], such as pyvenv.cfg
        else:
            keys = _collect_keys(
                f"{section}.{key}" for section in parser.sections() for key in parser.options(section)
            )
    elif record.extension in {".xml", ".plist"} or name == "web.config" or name.endswith(".xml"):
        keys = _xml_keys(content)
    elif record.extension in {".yaml", ".yml"}:
        keys = _yaml_keys(content)
    elif name in {"dockerfile", "containerfile"}:
        keys = _collect_keys(
            match.group(1).upper()
            for line in io.StringIO(content, newline=None)
            if (match := re.match(
                r"(?i)^\s*(FROM|ARG|ENV|USER|WORKDIR|EXPOSE|ENTRYPOINT|CMD|HEALTHCHECK|SHELL)\b",
                line,
            ))
        )
    elif record.extension == ".nix":
        keys = _collect_keys(match.group(1) for match in _NIX_ASSIGNMENT.finditer(content))
    elif record.extension in {
        ".conf", ".properties", ".tf", ".tfvars", ".hcl", ".nix",
        ".service", ".desktop", ".rc", ".cnf",
    } or name in _CONFIG_FILENAMES:
        keys = _collect_keys(
            match.group(1)
            for line in io.StringIO(content, newline=None)
            if (match := _KEY_LINE.match(line))
            and not line.lstrip().startswith(("#", "//", "!"))
        )
    else:
        keys = []
    return sorted(set(keys)), risks, risk_source


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
        if record.size_bytes > _MAX_CONFIG_FILE_BYTES:
            return [Finding(
                "configuration",
                f"Configuration analysis resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the configuration analyzer's "
                f"{_MAX_CONFIG_FILE_BYTES:,}-byte content budget. This is not a clean result.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                raw_content = stream.read(_MAX_CONFIG_FILE_BYTES + 1)
            if len(raw_content) > _MAX_CONFIG_FILE_BYTES:
                return [Finding(
                    "configuration",
                    f"Configuration analysis resource limit: {record.path}",
                    f"Content grew beyond the {_MAX_CONFIG_FILE_BYTES:,}-byte configuration "
                    "budget while reading. This is not a clean result.",
                    confidence="UNKNOWN",
                    evidence=[record.path, f"read_limit: {_MAX_CONFIG_FILE_BYTES} bytes"],
                    analyzer=self.name,
                    severity="LOW",
                )]
            content = raw_content.decode(text_encoding(raw_content))
            keys, risks, risk_source = _parse_config(content, record)
        except ConfigurationKeyBudgetExceeded as exc:
            return [Finding(
                "configuration",
                f"Configuration inventory resource limit: {record.path}",
                redact_source_excerpt(str(exc)),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, configparser.Error, ET.ParseError, ValueError, RecursionError, MemoryError) as exc:
            return [Finding(
                "configuration",
                f"Configuration parse error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
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
                        code=risk_source[line_number],
                    )]
                    if line_number in risk_source else []
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
