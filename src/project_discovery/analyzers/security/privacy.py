"""Privacy and identity-data indicators with strict value redaction."""
from __future__ import annotations

import re
from pathlib import Path

from ...catalog.languages import is_documentation_path, is_textual_path
from ...core.source_utils import describe_error, open_verified_binary, redact_source_excerpt, utf8_stream
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer
from ..environment.network import _literal_spans, iana_tlds

# The RFC 5321 64-character local-part limit also keeps scanning linear on long
# dotted runs without an "@" nearby.
_EMAIL = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_\x60{|}~-]{1,64}@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)\b"
)
# RFC 2606 / RFC 6761 names can never identify a real mailbox.
_RESERVED_EMAIL_DOMAINS = ("example.com", "example.net", "example.org")
_RESERVED_EMAIL_TLDS = frozenset({"example", "test", "invalid", "localhost"})
# A field name ends with the keyword: DB_PASSWORD, user_email and userEmail count;
# email_verified, password_hash and tokenizer do not. The left edge is a non-alphanumeric
# character or a camelCase boundary; the right edge ends the identifier.
_L = r"(?:(?<![A-Za-z0-9])|(?<=[a-z0-9])(?-i:(?=[A-Z])))"
_R = r"(?![A-Za-z0-9_])"
_PII_FIELDS = {
    "first_name": re.compile(rf"(?i){_L}(?:first_?name|given_?name|forename){_R}"),
    "middle_name": re.compile(rf"(?i){_L}middle_?name{_R}"),
    "last_name": re.compile(rf"(?i){_L}(?:last_?name|surname|family_?name){_R}"),
    "username": re.compile(rf"(?i){_L}(?:user_?name|login_?name|account_?name){_R}"),
    "email": re.compile(rf"(?i){_L}(?:e-?mail|email_?address|mail_?address){_R}"),
    # A bare "mobile" names a platform far more often than a phone number.
    "phone": re.compile(
        rf"(?i){_L}(?:phone(?:_?(?:number|no))?|telephone|mobile_?(?:phone|number|no)|cell_?(?:phone|number)){_R}"
    ),
    "address": re.compile(rf"(?i){_L}(?:street_?address|postal_?address|home_?address){_R}"),
    "date_of_birth": re.compile(rf"(?i){_L}(?:date_?of_?birth|birth_?date|dob){_R}"),
    "government_id": re.compile(rf"(?i){_L}(?:ssn|social_?security|passport_?number|national_?id){_R}"),
}
# One pass per line: a named-group alternation reports which PII categories appear.
_PII_ANY = re.compile(
    "|".join(f"(?P<{name}>{pattern.pattern.removeprefix('(?i)')})" for name, pattern in _PII_FIELDS.items()),
    re.IGNORECASE,
)
_SECRET_FIELDS = re.compile(
    rf"(?i){_L}(?:password|passwd|passphrase|api[_-]?key|client[_-]?secret|access[_-]?token|"
    rf"refresh[_-]?token|auth[_-]?token|private[_-]?key|secret[_-]?key|signing[_-]?key|"
    rf"encryption[_-]?key|secret|token){_R}"
)
_MAX_LINE_BYTES = 256 * 1024
_MAX_DATA_EXPOSURE_FILE_BYTES = 64 * 1024 * 1024
_MAX_EVIDENCE_LINES = 100
_MAX_CODE_EXCERPTS = 20


def _line_excerpt(line: str) -> str:
    """A redacted excerpt of one line, shared by every finding that cites it.

    On a line that names a credential field every literal is hidden, because any of them
    may be that field's value: the redactor only knows ``key = value`` shapes, so an SQL
    ``INSERT ... (email, password) VALUES ('...', 'plaintext')`` row kept the password.
    """
    if _SECRET_FIELDS.search(line):
        # The network analyzer's linear quote scanner: a regex over quoted literals
        # restarts at every quote after an unterminated one, which is quadratic.
        parts, last = [], 0
        for start, end in _literal_spans(line):
            parts += [line[last:start], "[REDACTED]"]
            last = end
        line = "".join(parts) + line[last:]
    return redact_source_excerpt(line)


def personal_email_matches(text: str):
    """Email-shaped values that could reach a real mailbox, as this analyzer reports them.

    The archive member scanner uses this too, so members and files get the same rules.
    """
    for match in _EMAIL.finditer(text):
        domain = match.group(1).lower()
        tld = domain.rsplit(".", 1)[-1]
        if tld in _RESERVED_EMAIL_TLDS or tld not in iana_tlds():
            continue  # pkg@1.0.0, icon@2x.png and reserved names are not mailboxes
        if domain in _RESERVED_EMAIL_DOMAINS or domain.endswith(
            tuple("." + reserved for reserved in _RESERVED_EMAIL_DOMAINS)
        ):
            continue
        if text.startswith(":", match.end()):
            continue  # SCP-style remotes such as git@github.com:org/repo.git
        line_start = text.rfind("\n", 0, match.start()) + 1
        scheme = text.rfind("://", line_start, match.start())
        if scheme >= 0 and not any(
            char.isspace() or char in "\"'<>(),;" for char in text[scheme:match.start()]
        ):
            continue  # URL user info, as in ssh://git@host/org/repo
        yield match


def _has_personal_email(line: str) -> bool:
    """Whether the line holds an address that could reach a real mailbox."""
    return next(personal_email_matches(line), None) is not None


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
        line_budget_reached = False
        # Field names in prose describe data rather than define it; values still count.
        inventory_field_names = not is_documentation_path(record.path)
        try:
            with open_verified_binary(path, record.analysis_identity) as raw_stream:
                # UTF-16 and UTF-32 text is transcoded so its lines are scanned too.
                stream, transcoded_over_budget = utf8_stream(raw_stream, _MAX_DATA_EXPOSURE_FILE_BYTES)
                budget_reached = budget_reached or transcoded_over_budget
                line_number = 1
                while bytes_scanned < _MAX_DATA_EXPOSURE_FILE_BYTES:
                    remaining = _MAX_DATA_EXPOSURE_FILE_BYTES - bytes_scanned
                    raw_line = stream.readline(min(_MAX_LINE_BYTES, remaining + 1))
                    if not raw_line:
                        break
                    if len(raw_line) > remaining:
                        budget_reached = True
                        break
                    if (
                        len(raw_line) == _MAX_LINE_BYTES
                        and not raw_line.endswith((b"\n", b"\r"))
                    ):
                        next_byte = stream.read(1)
                        if next_byte:
                            bytes_scanned += 1
                            if next_byte in (b"\n",):
                                raw_line += next_byte
                            else:
                                line_budget_reached = True
                                break
                    bytes_scanned += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace")
                    current_line = line_number
                    # Redaction is the costliest step; only redact lines that are kept.
                    excerpt: str | None = None

                    field_names = (
                        {match.lastgroup for match in _PII_ANY.finditer(line)}
                        if inventory_field_names else ()
                    )
                    for field_name in field_names:
                        if field_last_line.get(field_name) != current_line:
                            field_last_line[field_name] = current_line
                            field_line_counts[field_name] = field_line_counts.get(field_name, 0) + 1
                            samples = field_line_samples.setdefault(field_name, [])
                            if len(samples) < _MAX_EVIDENCE_LINES:
                                samples.append(current_line)
                            if len(samples) <= _MAX_CODE_EXCERPTS:
                                excerpt = excerpt or _line_excerpt(line)
                                field_excerpts[(field_name, current_line)] = excerpt

                    if "@" in line and email_last_line != current_line and _has_personal_email(line):
                        email_last_line = current_line
                        email_line_count += 1
                        if len(email_lines) < _MAX_EVIDENCE_LINES:
                            email_lines.append(current_line)
                        if len(email_excerpts) < _MAX_CODE_EXCERPTS:
                            excerpt = excerpt or _line_excerpt(line)
                            email_excerpts[current_line] = excerpt

                    if (
                        inventory_field_names
                        and secret_last_line != current_line
                        and _SECRET_FIELDS.search(line)
                    ):
                        secret_last_line = current_line
                        secret_field_line_count += 1
                        if len(secret_field_lines) < _MAX_EVIDENCE_LINES:
                            secret_field_lines.append(current_line)
                        if len(secret_excerpts) < _MAX_CODE_EXCERPTS:
                            excerpt = excerpt or _line_excerpt(line)
                            secret_excerpts[current_line] = excerpt

                    if line.endswith(("\n", "\r")):
                        line_number += 1

                if bytes_scanned >= _MAX_DATA_EXPOSURE_FILE_BYTES and stream.read(1):
                    budget_reached = True
        except OSError as exc:
            return [Finding(
                "privacy", f"Data exposure scan unavailable: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name,
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
                # A name inventory, like the credential key-name inventory below.
                severity="LOW",
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
        if line_budget_reached:
            findings.append(Finding(
                "privacy",
                f"Data exposure line-length budget reached: {record.path}",
                f"Analysis stopped because a physical line exceeded the {_MAX_LINE_BYTES:,}-byte "
                "line budget. The remainder of that line and following content were not inspected.",
                confidence="UNKNOWN",
                evidence=[record.path, f"bytes_scanned: {bytes_scanned:,}"],
                analyzer=self.name,
                severity="LOW",
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
