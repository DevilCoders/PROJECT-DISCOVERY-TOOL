"""Local configuration inventory and conservative risky-setting detection."""
from __future__ import annotations

import configparser
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding


_CONFIG_FILENAMES = {
    ".env", "dockerfile", "containerfile", "docker-compose.yml", "compose.yml",
    "nginx.conf", "config.ini", "settings.ini", "appsettings.json",
}
_CONFIG_EXTENSIONS = {
    ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".tf", ".tfvars", ".hcl",
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
    ("wildcard_cors", re.compile(
        r"(?i)(?:allow[_-]?origins?|access-control-allow-origin)\s*[:=]\s*(?:\[\s*)?["']?\*["']?"
    )),
)
_SECRET_KEY = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)")


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


def _parse_config(path: Path, record: FileRecord) -> tuple[list[str], list[tuple[int, str]]]:
    name = Path(record.path).name.lower()
    content = path.read_text(encoding="utf-8")
    risks: list[tuple[int, str]] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        for risk_name, pattern in _RISK_PATTERNS:
            if pattern.search(line):
                risks.append((line_number, risk_name))

    if name in {".env"} or name.startswith(".env."):
        keys = [
            match.group(1) for line in content.splitlines()
            if (match := _ENV_LINE.match(line)) and not line.lstrip().startswith("#")
        ]
    elif record.extension == ".json" and name not in {"package.json", "composer.json"}:
        keys = _flatten(json.loads(content))
    elif record.extension == ".toml" and name not in {"pyproject.toml", "cargo.toml"}:
        keys = _flatten(tomllib.loads(content))
    elif record.extension in {".ini", ".cfg"}:
        parser = configparser.ConfigParser()
        parser.read_string(content)
        keys = [
            f"{section}.{key}" for section in parser.sections()
            for key, _ in parser.items(section)
        ]
    elif record.extension in {".yaml", ".yml", ".conf", ".properties", ".tf", ".tfvars", ".hcl"} or name in _CONFIG_FILENAMES:
        keys = [
            match.group(1) for line in content.splitlines()
            if (match := _KEY_LINE.match(line)) and not line.lstrip().startswith(("#", "//"))
        ]
    else:
        keys = []
    return sorted(set(keys)), risks


class ConfigurationAnalyzer(Analyzer):
    """Inventory configuration keys without exposing their values."""

    name = "configuration-intelligence"

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            record.extension in _CONFIG_EXTENSIONS or name in _CONFIG_FILENAMES
            or name == ".env" or name.startswith(".env.")
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            keys, risks = _parse_config(path, record)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, configparser.Error) as exc:
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
                evidence=[record.path],
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
            ))
        return findings
