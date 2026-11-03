"""Privacy and identity-data indicators with strict value redaction."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..language_catalog import is_textual_path
from ..models import FileRecord, Finding


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
    languages = ("Polyglot text/source/configuration")

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
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                line_number = 1
                while True:
                    line = stream.readline(_MAX_LINE_CHARS)
                    if not line:
                        break
                    current_line = line_number
                    for field_name, pattern in _PII_FIELDS.items():
                        if pattern.search(line):
                            field_lines.setdefault(field_name, set()).add(current_line)
                    if _EMAIL.search(line):
                        email_lines.add(current_line)
                    if _SECRET_FIELDS.search(line):
                        secret_field_lines.add(current_line)
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
            ))
        if email_lines:
            findings.append(Finding(
                "privacy",
                f"Email-shaped value indicators: {record.path}",
                f"Detected email-address-shaped value(s) on {len(email_lines)} line(s). "
                "Address values are not stored or printed.",
                confidence="INFERRED",
                evidence=[f"{record.path}:{line} (email value redacted)" for line in sorted(email_lines)[:100]],
                analyzer=self.name,
                severity="MEDIUM",
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
            ))
        return findings
