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
_MAX_LINE_BYTES = 256 * 1024
_MAX_DATA_EXPOSURE_FILE_BYTES = 64 * 1024 * 1024
_MAX_EVIDENCE_LINES = 100
_MAX_CODE_EXCERPTS = 20


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
        if record.size_bytes > _MAX_DATA_EXPOSURE_FILE_BYTES:
            return [Finding(
                "privacy",
                f"Data exposure analysis resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the data-exposure analyzer's "
                f"{_MAX_DATA_EXPOSURE_FILE_BYTES:,}-byte content budget. This is not a clean result.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]

        field_line_samples: dict[str, list[int]] = {}
        field_line_counts: dict[str, int] = {}
        field_last_line: dict[str, int] = {}
        field_excerpts: dict[tuple[str, int], str] = {}
        email_lines: list[int] = []
        email_line_count = 0
        email_last_line = 0
        email_excerpts: dict[int, str] = {}
        secret_field_lines: list[int] = []
        secret_field_line_count = 0
        secret_last_line = 0
        secret_excerpts: dict[int, str] = {}
        bytes_scanned = 0
        budget_reached = False
        try:
            with path.open("rb") as stream:
                line_number = 1
                while bytes_scanned < _MAX_DATA_EXPOSURE_FILE_BYTES:
                    remaining = _MAX_DATA_EXPOSURE_FILE_BYTES - bytes_scanned
                    raw_line = stream.readline(min(_MAX_LINE_BYTES, remaining + 1))
                    if not raw_line:
                        break
                    if len(raw_line) > remaining:
                        budget_reached = True
                        break
                    bytes_scanned += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace")
                    current_line = line_number
                    excerpt = redact_source_excerpt(line)

                    for field_name, pattern in _PII_FIELDS.items():
                        if (
                            pattern.search(line)
                            and field_last_line.get(field_name) != current_line
                        ):
                            field_last_line[field_name] = current_line
                            field_line_counts[field_name] = field_line_counts.get(field_name, 0) + 1
                            samples = field_line_samples.setdefault(field_name, [])
                            if len(samples) < _MAX_EVIDENCE_LINES:
                                samples.append(current_line)
                            if len(samples) <= _MAX_CODE_EXCERPTS:
                                field_excerpts[(field_name, current_line)] = excerpt

                    if _EMAIL.search(line) and email_last_line != current_line:
                        email_last_line = current_line
                        email_line_count += 1
                        if len(email_lines) < _MAX_EVIDENCE_LINES:
                            email_lines.append(current_line)
                        if len(email_excerpts) < _MAX_CODE_EXCERPTS:
                            email_excerpts[current_line] = excerpt

                    if _SECRET_FIELDS.search(line) and secret_last_line != current_line:
                        secret_last_line = current_line
                        secret_field_line_count += 1
                        if len(secret_field_lines) < _MAX_EVIDENCE_LINES:
                            secret_field_lines.append(current_line)
                        if len(secret_excerpts) < _MAX_CODE_EXCERPTS:
                            secret_excerpts[current_line] = excerpt

                    if line.endswith(("\n", "\r")):
                        line_number += 1

                if bytes_scanned >= _MAX_DATA_EXPOSURE_FILE_BYTES and stream.read(1):
                    budget_reached = True
        except OSError as exc:
            return [Finding(
                "privacy", f"Data exposure scan unavailable: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
            )]

        findings: list[Finding] = []
        if field_line_counts:
            names = sorted(field_line_counts)
            evidence = [
                f"{record.path}:{line} (field-name indicator: {name})"
                for name in names
                for line in field_line_samples.get(name, [])
            ]
            code_evidence = [
                CodeEvidence(line_number=line, code=field_excerpts[(name, line)])
                for name in names
                for line in field_line_samples.get(name, [])[:_MAX_CODE_EXCERPTS]
                if (name, line) in field_excerpts
            ][: _MAX_CODE_EXCERPTS]
            findings.append(Finding(
                "privacy",
                f"Personal-data field indicators: {record.path}",
                "Observed field-name categories: " + ", ".join(names)
                + ". Field names do not prove that real personal data is present; values "
                "are intentionally excluded from findings.",
                confidence="INFERRED",
                evidence=evidence[:_MAX_EVIDENCE_LINES],
                analyzer=self.name,
                severity="MEDIUM",
                code_evidence=code_evidence,
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
        if email_line_count:
            findings.append(Finding(
                "privacy",
                f"Email-shaped value indicators: {record.path}",
                f"Detected email-address-shaped value(s) on {email_line_count:,} line(s). "
                "Address values are not stored or printed.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} (email value redacted)"
                    for line in email_lines
                ],
                analyzer=self.name,
                severity="MEDIUM",
                code_evidence=[
                    CodeEvidence(line_number=line, code=email_excerpts[line])
                    for line in email_lines[:_MAX_CODE_EXCERPTS]
                    if line in email_excerpts
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
        if secret_field_line_count:
            findings.append(Finding(
                "secrets",
                f"Credential field-name indicators: {record.path}",
                f"Detected credential-related field names on {secret_field_line_count:,} line(s). "
                "This is a key-name inventory, not evidence that a non-placeholder secret is embedded.",
                confidence="INFERRED",
                evidence=[
                    f"{record.path}:{line} (credential key name only)"
                    for line in secret_field_lines
                ],
                analyzer=self.name,
                severity="LOW",
                code_evidence=[
                    CodeEvidence(line_number=line, code=secret_excerpts[line])
                    for line in secret_field_lines[:_MAX_CODE_EXCERPTS]
                    if line in secret_excerpts
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
        if budget_reached:
            findings.append(Finding(
                "privacy",
                f"Data exposure scan budget reached: {record.path}",
                f"Analysis stopped after {_MAX_DATA_EXPOSURE_FILE_BYTES:,} bytes. Findings "
                "collected before the limit are partial; remaining content was not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path, f"bytes_scanned: {bytes_scanned:,}"],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings
