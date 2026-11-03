"""Conservative local secret-pattern detection with strict value redaction."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("github_fine_grained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("credential_url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@")),
    (
        "credential_assignment",
        re.compile(
            r"""(?ix)\b(?:api[_-]?key|client[_-]?secret|service[_-]?token|access[_-]?(?:token|key)|auth[_-]?token|refresh[_-]?token|password|passwd|secret[_-]?(?:access[_-]?)?key|secret|token|encryption[_-]?key|signing[_-]?key)\b\s*[:=]\s*["']?([^\s"'#,;]{6,})"""
        ),
    ),
)
_PLACEHOLDERS = {
    "changeme", "change_me", "example", "example_key", "your_token",
    "your_api_key", "placeholder", "dummy", "redacted", "null", "none",
    "password", "secret", "xxx", "xxxx", "***",
}
_SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".rs",
    ".go", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".java", ".kt",
    ".swift", ".cs", ".rb", ".php", ".sh", ".bash", ".ps1", ".pem", ".key", ".yaml",
    ".yml", ".json", ".toml", ".ini", ".cfg", ".xml", ".sql", ".env",
    ".properties", ".gradle", ".tf", ".hcl",
}


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    return (
        normalized in _PLACEHOLDERS
        or normalized.startswith("$" + "{")
        or normalized.startswith("$env:")
        or normalized.startswith("os.getenv")
        or normalized.startswith("getenv(")
        or (normalized.startswith("<") and normalized.endswith(">"))
    )


class SecretPatternAnalyzer(Analyzer):
    """Detect likely embedded credentials; never persist matched secret values."""

    name = "secret-patterns"

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        is_env_file = name == ".env" or name.startswith(".env.")
        return (
            record.error is None
            and (record.extension in _SOURCE_EXTENSIONS or is_env_file)
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "security",
                "Secret scan could not read file",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for line_number, line in enumerate(lines, 1):
            for pattern_name, pattern in _PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                if pattern_name == "credential_assignment" and _is_placeholder(match.group(1)):
                    continue
                key = (pattern_name, line_number)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    "security",
                    f"Potential hardcoded credential: {pattern_name}",
                    "A secret-like pattern was detected. The matched value is intentionally "
                    "redacted; validate whether it is a real credential and rotate it if exposed.",
                    confidence="INFERRED",
                    evidence=[f"{record.path}:{line_number}"],
                    analyzer=self.name,
                ))
        return findings
