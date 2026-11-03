"""Streaming local secret-pattern detection with strict value redaction and budgets."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..language_catalog import is_textual_path, textual_language_names
from ..models import CodeEvidence, FileRecord, Finding
from ..source_utils import redact_source_excerpt
from ..native_backend import count_byte as native_count_byte


_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("github_fine_grained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b")),
    ("docker_pat", re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credential_url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@")),
    (
        "credential_assignment",
        re.compile(
            r"""(?ix)\b[A-Za-z0-9_]*(?:api[_-]?key|client[_-]?secret|service[_-]?token|access[_-]?(?:token|key)|auth[_-]?token|refresh[_-]?token|password|passwd|passphrase|secret[_-]?(?:access[_-]?)?key|secret|token|encryption[_-]?key|signing[_-]?key|aws_secret_access_key|database_url)[A-Za-z0-9_]*\b\s*[:=]\s*(?:"([^"\r\n]{6,})"|'([^'\r\n]{6,})'|([^\s"'#,;]{6,}))"""
        ),
    ),
)
_PLACEHOLDERS = {
    "changeme", "change_me", "example", "example_key", "your_token",
    "your_api_key", "your_password", "your_secret", "placeholder", "dummy",
    "redacted", "null", "none", "password", "secret", "xxx", "xxxx",
    "***", "todo", "replace_me", "replace-this", "set_me",
}
_SENSITIVE_FILENAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519",
    "id_ecdsa", "id_dsa", "credentials",
}
_SENSITIVE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx"}
_CHUNK_BYTES = 8 * 1024 * 1024
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_OVERLAP_CHARS = 4096
_MAX_FINDINGS = 10_000


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").strip().lower()
    return (
        normalized in _PLACEHOLDERS
        or normalized.startswith(("$" + "{", "$env:", "$(", "os.getenv", "os.environ",
                                  "process.env", "getenv(", "env("))
        or normalized.startswith(("your_", "replace_me", "placeholder"))
        or (normalized.startswith("<") and normalized.endswith(">"))
    )


def _assignment_value(match: re.Match[str]) -> str:
    return next((value for value in match.groups() if value is not None), "")

def _credential_impact(pattern_name: str) -> str:
    if pattern_name == "private_key":
        return (
            "If the private key is valid and trusted, an attacker may impersonate the "
            "associated user or service, sign forged data, decrypt protected material or "
            "access connected systems."
        )
    if pattern_name == "jwt":
        return (
            "If the token is live and accepted, an attacker may replay it as the represented "
            "user or service and inherit its permissions until expiry or revocation."
        )
    return (
        "If the credential is valid and active, an attacker who obtains it may access the "
        "linked API, cloud account or database, read or alter data, invoke privileged "
        "operations, incur charges or pivot into connected services."
    )


class SecretPatternAnalyzer(Analyzer):
    """Detect likely embedded credentials; never persist matched values."""

    name = "secret-patterns"
    domains = ("secrets",)
    languages = textual_language_names()

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        is_env_or_credential_file = (
            name in _SENSITIVE_FILENAMES
            or name.startswith(".env.")
            or Path(record.path).suffix.lower() in _SENSITIVE_EXTENSIONS
        )
        return (
            record.error is None
            and record.content_skipped_reason is None
            and (is_textual_path(record.path) or is_env_or_credential_file)
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        bytes_scanned = 0
        total_newlines = 0
        tail = ""
        stop_reason: str | None = None
        try:
            with path.open("rb") as stream:
                while bytes_scanned < _MAX_SCAN_BYTES:
                    raw_chunk = stream.read(min(
                        _CHUNK_BYTES, _MAX_SCAN_BYTES - bytes_scanned
                    ))
                    if not raw_chunk:
                        break
                    bytes_scanned += len(raw_chunk)
                    chunk = raw_chunk.decode("utf-8", errors="replace")
                    combined = tail + chunk
                    prefix_length = len(tail)
                    base_line = total_newlines - native_count_byte(
                        tail.encode("utf-8", errors="replace"), 10
                    )
                    for pattern_name, pattern in _PATTERNS:
                        for match in pattern.finditer(combined):
                            if match.end() <= prefix_length:
                                continue
                            if (
                                pattern_name == "credential_assignment"
                                and _is_placeholder(_assignment_value(match))
                            ):
                                continue
                            line_number = (
                                base_line + combined.count("\n", 0, match.start()) + 1
                            )
                            key = (pattern_name, line_number)
                            if key in seen:
                                continue
                            seen.add(key)
                            severity = (
                                "CRITICAL" if pattern_name == "private_key"
                                else "HIGH" if pattern_name in {
                                    "github_token", "github_fine_grained_token",
                                    "gitlab_token", "aws_access_key_id", "google_api_key",
                                    "slack_token", "stripe_secret_key", "sendgrid_api_key",
                                    "openai_api_key", "anthropic_api_key",
                                    "huggingface_token", "npm_token", "pypi_token",
                                    "docker_pat", "jwt", "credential_url",
                                    "credential_assignment",
                                }
                                else "MEDIUM"
                            )
                            line_start = combined.rfind("\n", 0, match.start()) + 1
                            line_end = combined.find("\n", match.start())
                            if line_end < 0:
                                line_end = len(combined)
                            excerpt = redact_source_excerpt(combined[line_start:line_end])
                            findings.append(Finding(
                                "security",
                                f"Potential hardcoded credential: {pattern_name}",
                                "A secret-like pattern was detected. The matched value is "
                                "intentionally redacted; validate whether it is a real "
                                "credential and rotate it if exposed.",
                                confidence="INFERRED",
                                evidence=[f"{record.path}:{line_number}"],
                                analyzer=self.name,
                                severity=severity,
                                code_evidence=[
                                    CodeEvidence(line_number=line_number, code=excerpt)
                                ],
                                impact=_credential_impact(pattern_name),
                                recommendation=(
                                    "Revoke and rotate the credential, move the replacement "
                                    "to an approved secret manager or protected environment "
                                    "injection path, remove it from active source/configuration "
                                    "and repository history where appropriate, then audit "
                                    "access logs for possible use."
                                ),
                            ))
                            if len(findings) >= _MAX_FINDINGS:
                                stop_reason = "finding limit reached"
                                break
                        if stop_reason:
                            break
                    total_newlines += native_count_byte(raw_chunk, 10)
                    tail = combined[-_OVERLAP_CHARS:]
                    if stop_reason:
                        break
        except OSError as exc:
            return [Finding(
                "security", "Secret scan could not read file",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]

        if stop_reason or (record.size_bytes > bytes_scanned and bytes_scanned >= _MAX_SCAN_BYTES):
            reason = stop_reason or f"byte budget {_MAX_SCAN_BYTES:,} reached"
            findings.append(Finding(
                "secrets",
                f"Secret scan resource budget reached: {record.path}",
                f"Scanning stopped because the {reason}. Unread content was not inspected; "
                "absence of further findings cannot be inferred.",
                confidence="UNKNOWN",
                evidence=[record.path, f"scanned_bytes: {bytes_scanned}"],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
