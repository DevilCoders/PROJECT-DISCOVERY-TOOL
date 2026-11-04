"""Streaming local secret-pattern detection with strict value redaction and budgets."""
from __future__ import annotations

import codecs
import re
from pathlib import Path, PurePosixPath

from .base import Analyzer
from ..language_catalog import is_textual_path, textual_language_names
from ..models import CodeEvidence, FileRecord, Finding
from ..native_backend import count_byte as native_count_byte
from ..secret_patterns import COMPILED_FORMATS, PRIVATE_KEY_MARKER
from ..source_utils import open_verified_binary, redact_source_excerpt


_PATTERNS = (
    ("private_key", PRIVATE_KEY_MARKER),
    *((item.name, pattern) for item, pattern in COMPILED_FORMATS),
    ("credential_url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@")),
    (
        "credential_assignment",
        re.compile(
            r"""(?ix)\b[A-Za-z0-9_]*(?:api[_-]?key|client[_-]?secret|service[_-]?token|access[_-]?(?:token|key)|auth[_-]?token|refresh[_-]?token|password|passwd|passphrase|secret[_-]?(?:access[_-]?)?key|secret|token|encryption[_-]?key|signing[_-]?key|aws_secret_access_key|database_url)[A-Za-z0-9_]*\b\s*[:=]\s*(?:"([^"\r\n]{6,})"|'([^'\r\n]{6,})'|([^\s"'#,;]{6,}))"""
        ),
    ),
)
_SEVERITY = {
    "private_key": "CRITICAL",
    **{item.name: item.severity for item, _ in COMPILED_FORMATS},
    "credential_url": "HIGH",
    "credential_assignment": "HIGH",
}
_PLACEHOLDERS = {
    "changeme", "change_me", "example", "example_key", "your_token",
    "your_api_key", "your_password", "your_secret", "placeholder", "dummy",
    "redacted", "null", "none", "password", "secret", "xxx", "xxxx",
    "***", "todo", "replace_me", "replace-this", "set_me", "notasecret", "not-a-secret",
    "fake", "test", "testing", "sample", "foobar", "secret123", "password123",
}
_SENSITIVE_FILENAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519",
    "id_ecdsa", "id_dsa", "credentials",
}
_SENSITIVE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx"}
# Paths whose credentials are usually fixtures or documentation; findings are kept but
# downgraded one severity level and labeled so real exposures stand out.
_LOW_RISK_PATH_PARTS = {
    "test", "tests", "testing", "__tests__", "spec", "specs", "fixture", "fixtures",
    "testdata", "test_data", "example", "examples", "sample", "samples", "mock", "mocks",
    "doc", "docs", "documentation",
}
_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
_CHUNK_BYTES = 8 * 1024 * 1024
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_OVERLAP_CHARS = 4096
_MAX_FINDINGS = 10_000


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").strip().lower()
    return (
        normalized in _PLACEHOLDERS
        or normalized.startswith(("$" + "{", "$env:", "$(", "os.getenv", "os.environ",
                                  "process.env", "getenv(", "env(", "{{", "%(", "<%"))
        or normalized.startswith(("your_", "your-", "replace_me", "placeholder", "example"))
        or (normalized.startswith("<") and normalized.endswith(">"))
        or len(set(normalized)) <= 2  # "xxxxxxxx", "********", "00000000"
    )


def _low_risk_path(relative: str) -> bool:
    path = PurePosixPath(relative.replace("\\", "/"))
    parts = {part.lower() for part in path.parts[:-1]}
    stem = path.name.lower()
    return bool(parts & _LOW_RISK_PATH_PARTS) or stem.startswith(("test_", "example", "sample")) or (
        stem.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go"))
    ) or path.suffix.lower() in {".md", ".rst", ".adoc", ".txt"}


def _assignment_value(match: re.Match[str]) -> str:
    return next((value for value in match.groups() if value is not None), "")


def _credential_impact(pattern_name: str) -> str:
    if pattern_name in {"private_key", "age_secret_key"}:
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
    if pattern_name == "slack_webhook_url":
        return (
            "If the webhook is active, an attacker may post arbitrary messages into the "
            "connected workspace channel, enabling phishing or misinformation."
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
        specific_lines: set[int] = set()
        bytes_scanned = 0
        total_newlines = 0
        tail = ""
        stop_reason: str | None = None
        low_risk = _low_risk_path(record.path)
        # An incremental decoder keeps multi-byte characters intact across chunk edges.
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                while bytes_scanned < _MAX_SCAN_BYTES:
                    raw_chunk = stream.read(min(
                        _CHUNK_BYTES, _MAX_SCAN_BYTES - bytes_scanned
                    ))
                    final = not raw_chunk
                    chunk = decoder.decode(raw_chunk, final=final)
                    if final and not chunk:
                        break
                    bytes_scanned += len(raw_chunk)
                    combined = tail + chunk
                    prefix_length = len(tail)
                    base_line = total_newlines - tail.count("\n")
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
                            # A specific provider format on the line supersedes the generic
                            # assignment rule, so one secret yields one finding.
                            if pattern_name == "credential_assignment" and line_number in specific_lines:
                                continue
                            seen.add(key)
                            if pattern_name not in {"credential_assignment", "credential_url"}:
                                specific_lines.add(line_number)
                            severity = _SEVERITY.get(pattern_name, "MEDIUM")
                            if low_risk:
                                severity = _DOWNGRADE[severity]
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
                                "credential and rotate it if exposed."
                                + (
                                    " The file is in a test, fixture, example or "
                                    "documentation location, so severity was lowered "
                                    "one level; confirm it is not a live credential."
                                    if low_risk else ""
                                ),
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
                    total_newlines += native_count_byte(raw_chunk, 10) if raw_chunk else 0
                    tail = combined[-_OVERLAP_CHARS:]
                    if stop_reason or final:
                        break
        except OSError as exc:
            return [Finding(
                "secrets", f"Secret scan could not read file: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"), confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name, severity="LOW",
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
