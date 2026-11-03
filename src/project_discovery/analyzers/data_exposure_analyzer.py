"""Privacy and identity-data indicators with strict value redaction."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..language_catalog import is_textual_path
from ..models import CodeEvidence, FileRecord, Finding
from ..source_utils import redact_source_excerpt


_EMAIL = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b"
)
_PII_FIELDS = {
    "first_name": re.compile(r"(?i)\b(?:first_?name|given_?name|forename)\b"),
    "middle_name": re.compile(r"(?i)\bmiddle_?name\b"),
    "last_name": re.compile(r"(?i)\b(?:last_?name|surname|family_?name)\b"),
    "username": re.compile(r"(?i)\b(?:user_?name|login_?name|account_?name)\b"),
    "email": re.compile(r"(?i)\b(?:e-?mail|email_?address|mail_?address)\b"),
    "phone": re.compile(r"(?i)\b(?:phone|telephone|mobile|cell_?number)\b"),
    "address": re.compile(r"(?i)\b(?:street_?address|postal_?address|home_?address)\b"),
    "date_of_birth": re.compile(r"(?i)\b(?:date_?of_?birth|birth_?date|dob)\b"),
    "government_id": re.compile(r"(?i)\b(?:ssn|social_?security|passport_?number|national_?id)\b"),
}
_SECRET_FIELDS = re.compile(
    r"(?i)\b(?:password|passwd|passphrase|api[_-]?key|client[_-]?secret|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key|secret)\b"
)
_MAX_LINE_CHARS = 256 * 1024


class DataExposureAnalyzer(Analyzer):
    """Find PII/credential field names and email-shaped values without storing values."""

    name = "data-exposure-indicators"
    domains = ("privacy", "secrets")
    languages = ("Polyglot text/source/configuration",)

    def supports(self, record: FileRecord) -> bool:
        return (
            record.error is None
            and record.content_skipped_reason is None
            and (record.file_type == "text" or is_textual_path(record.path))
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        field_lines: dict[str, set[int]] = {}
        email_lines: set[int] = set()
        secret_field_lines: set[int] = set()
        field_excerpts: dict[tuple[str, int], str] = {}
        email_excerpts: dict[int, str] = {}
        secret_excerpts: dict[int, str] = {}
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                line_number = 1
                while True:
                    line = stream.readline(_MAX_LINE_CHARS)
                    if not line:
                        break
                    current_line = line_number
                    excerpt = redact_source_excerpt(line)
                    for field_name, pattern in _PII_FIELDS.items():
                        if pattern.search(line):
                            field_lines.setdefault(field_name, set()).add(current_line)
                            field_excerpts[(field_name, current_line)] = excerpt
                    if _EMAIL.search(line):
                        email_lines.add(current_line)
                        email_excerpts[current_line] = excerpt
                    if _SECRET_FIELDS.search(line):
                        secret_field_lines.add(current_line)
                        secret_excerpts[current_line] = excerpt
                    if line.endswith(("\n", "\r")):
                        line_number += 1
        except OSError as exc:
            return [Finding(
                "privacy", f"Data exposure scan unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
            )]

        findings = []
        if field_lines:
            names = sorted(field_lines)
            evidence = [
                f"{record.path}:{line} (field-name indicator: {name})"
                for name, lines in sorted(field_lines.items())
                for line in sorted(lines)[:20]
            ]
            findings.append(Finding(
                "privacy",
                f"Personal-data field indicators: {record.path}",
                "Observed field-name categories: " + ", ".join(names)
                + ". Field names do not prove that real personal data is present; values "
                "are intentionally excluded from findings.",
                confidence="INFERRED", evidence=evidence[:100], analyzer=self.name,
                severity="MEDIUM",
                code_evidence=[
                    CodeEvidence(line_number=line, code=field_excerpts[(name, line)])
                    for name, lines in sorted(field_lines.items())
                    for line in sorted(lines)[:20]
                    if (name, line) in field_excerpts
                ][:20],
                impact=(
                    "If these fields contain real user data, exposing the source or sample "
                    "records may reveal personal identifiers and increase privacy, phishing "
                    "or account-correlation risk. Field names alone do not prove data exposure."
                ),
                recommendation=(
                    "Keep real user records and personal identifiers out of source control; "
                    "use synthetic fixtures, data minimization and access-controlled storage."
                ),
            ))
        if email_lines:
            findings.append(Finding(
                "privacy",
                f"Email-shaped value indicators: {record.path}",
                f"Detected email-address-shaped value(s) on {len(email_lines)} line(s). "
                "Address values are not stored or printed.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} (email value redacted)"
                    for line in sorted(email_lines)[:100]
                ],
                analyzer=self.name,
                severity="MEDIUM",
                code_evidence=[
                    CodeEvidence(line_number=line, code=email_excerpts[line])
                    for line in sorted(email_lines)[:20] if line in email_excerpts
                ],
                impact=(
                    "If these are real addresses in a repository or public artifact, they may "
                    "expose contact identities for unsolicited contact, phishing or correlation."
                ),
                recommendation=(
                    "Replace real addresses in fixtures and examples with reserved example "
                    "addresses; remove exposed personal data from tracked files and history."
                ),
            ))
        if secret_field_lines:
            findings.append(Finding(
                "secrets",
                f"Credential field-name indicators: {record.path}",
                f"Detected credential-related field names on {len(secret_field_lines)} line(s). "
                "This is a key-name inventory, not evidence that a non-placeholder secret is embedded.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} (credential key name only)"
                    for line in sorted(secret_field_lines)[:100]
                ],
                analyzer=self.name,
                severity="LOW",
                code_evidence=[
                    CodeEvidence(line_number=line, code=secret_excerpts[line])
                    for line in sorted(secret_field_lines)[:20] if line in secret_excerpts
                ],
                impact=(
                    "A credential-related key name alone is not a secret. If a live value is "
                    "present on the line or supplied through adjacent configuration, exposure "
                    "could enable unauthorized API, cloud or database access."
                ),
                recommendation=(
                    "Check whether the setting is assigned a real value. Keep live credentials "
                    "in an approved secret manager or protected runtime injection path and rotate "
                    "any credential already committed."
                ),
            ))
        return findings
