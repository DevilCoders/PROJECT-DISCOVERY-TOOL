"""Streaming local secret-pattern detection with strict value redaction and budgets."""
from __future__ import annotations

import codecs
import re
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, limit_reached
from ...catalog.languages import (
    detect_language,
    is_source_path,
    is_textual_path,
    textual_language_names,
)
from ...core.secret_patterns import (
    ASSIGNMENT_OPERATOR,
    COMPILED_FORMATS,
    CREDENTIAL_KEYWORDS,
    PRIVATE_KEY_ANCHORS,
    PRIVATE_KEY_MARKER,
)
from ...core.source_utils import (
    describe_error,
    keyed_identifier,
    open_verified_binary,
    redact_source_excerpt,
    text_encoding,
)
from ...engine.native import count_byte as native_count_byte
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer

_CREDENTIAL_KEY = keyed_identifier(CREDENTIAL_KEYWORDS)
# Shared with the excerpt redactor, so every syntax detected here is also redacted.
_ASSIGNMENT_OPERATOR = ASSIGNMENT_OPERATOR
_QUOTED_VALUE = r""""(?P<double>[^"\r\n]{6,})"|'(?P<single>[^'\r\n]{6,})'"""
_UNQUOTED_VALUE = r"""(?P<bare>[^\s"'#,;]{6,})"""
# Configuration, environment and shell files hold literal unquoted values (TOKEN=abc123).
_ASSIGNMENT_ANY = re.compile(
    rf"(?i)(?P<key>{_CREDENTIAL_KEY}){_ASSIGNMENT_OPERATOR}(?:{_QUOTED_VALUE}|{_UNQUOTED_VALUE})"
)
# In programming languages an unquoted right-hand side is an expression
# (secret = load_secret(), token: list[str] = []), so only string literals count.
_ASSIGNMENT_QUOTED = re.compile(rf"(?i)(?P<key>{_CREDENTIAL_KEY}){_ASSIGNMENT_OPERATOR}(?:{_QUOTED_VALUE})")
# Source-family languages whose assignments are literal key/value data, not expressions.
_LITERAL_ASSIGNMENT_LANGUAGES = frozenset({
    "Shell", "Batch", "Unity Scene", "Unity Prefab", "Unity Asset YAML", "Godot Scene",
    "Godot Resource", "GameMaker Project", "Defold Collection", "Roblox XML Model",
})
# (name, pattern, anchors): a pattern only runs on text containing one of its anchors.
_SPECIFIC_PATTERNS = (
    ("private_key", PRIVATE_KEY_MARKER, PRIVATE_KEY_ANCHORS),
    *((item.name, pattern, item.anchors) for item, pattern in COMPILED_FORMATS),
    ("credential_url", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s/:@]+:(?P<password>[^\s/@]+)@"), ("://",)),
)
_PATTERNS = (*_SPECIFIC_PATTERNS, ("credential_assignment", _ASSIGNMENT_ANY, ()))
_EXPRESSION_PATTERNS = (*_SPECIFIC_PATTERNS, ("credential_assignment", _ASSIGNMENT_QUOTED, ()))
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
# Credential stores and secret-bearing files whatever the inventory typed them.
_SENSITIVE_FILENAMES = {
    ".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519",
    "id_ecdsa", "id_dsa", "credentials", ".git-credentials", ".pgpass", ".htpasswd", ".s3cfg",
    ".boto", ".dockercfg", "kubeconfig", ".bash_history", ".zsh_history", ".psql_history",
    ".mysql_history",
}
_SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".bks", ".tfstate", ".tfvars", ".ppk",
    ".ovpn", ".har", ".log", ".conf", ".cnf", ".config", ".bak",
}
# Binary key containers (PKCS#12, Java keystores): reported by name, never text-scanned.
_KEY_CONTAINERS = {".p12", ".pfx", ".jks", ".keystore", ".bks"}
# Paths whose credentials are usually fixtures or documentation; findings are kept but
# downgraded one severity level and labeled so real exposures stand out.
_LOW_RISK_PATH_PARTS = {
    "test", "tests", "testing", "__tests__", "spec", "specs", "fixture", "fixtures",
    "testdata", "test_data", "example", "examples", "sample", "samples", "mock", "mocks",
    "doc", "docs", "documentation",
}
_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
_PLAIN_URL = re.compile(r"[a-z][a-z0-9+.-]{0,31}://")
_CHUNK_BYTES = 8 * 1024 * 1024
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_OVERLAP_CHARS = 4096
_MAX_FINDINGS = 10_000


# Type names in schemas, interfaces and docs (password: string, token: String!) describe a
# value; they are not one.
_TYPE_WORDS = frozenset({
    "string", "str", "number", "boolean", "bool", "integer", "int", "object", "array", "any",
    "undefined", "required", "optional", "secretstr", "bytes", "text", "varchar",
})


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").strip().lower()
    return (
        normalized in _PLACEHOLDERS
        or normalized.rstrip("!?;,") in _TYPE_WORDS
        or "..." in normalized or "…" in normalized  # elided examples: ghp_..., sk-…
        or normalized.startswith(("$" + "{", "$env:", "$(", "os.getenv", "os.environ",
                                  "process.env", "getenv(", "env(", "{{", "%(", "<%"))
        or normalized.startswith(("your_", "your-", "replace_me", "placeholder", "example"))
        or (normalized.startswith("<") and normalized.endswith(">"))
        or len(set(normalized)) <= 2  # "xxxxxxxx", "********", "00000000"
        # token_url: https://auth/token, secret_file: /run/secrets/db name locations, not
        # secrets; URLs with user info are reported by the credential_url rule instead.
        or (_PLAIN_URL.match(normalized) is not None and "@" not in normalized)
        or normalized.startswith(("/", "./", "../", "~/"))
    )


def _low_risk_path(relative: str) -> bool:
    path = PurePosixPath(relative.replace("\\", "/"))
    parts = {part.lower() for part in path.parts[:-1]}
    stem = path.name.lower()
    # .env.example, config.example.yml, settings.sample.json, app.yml.dist
    segments = set(stem.split("."))
    return bool(parts & _LOW_RISK_PATH_PARTS) or stem.startswith(("test_", "example", "sample")) or bool(
        segments & {"example", "sample", "template", "tmpl", "dist", "defaults"}
    ) or (
        stem.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go"))
    ) or path.suffix.lower() in {".md", ".rst", ".adoc", ".txt"}


def _assignment_value(match: re.Match[str]) -> str:
    groups = match.groupdict()
    return next((groups[name] for name in ("double", "single", "bare") if groups.get(name) is not None), "")


# A name holds a credential when its last word is a credential noun: db_password, apiKey,
# SECRET_KEY, auth_token. Names that merely contain the word describe something else:
# tokenizer, token_type, secret_name, password_hash_algorithm, TOKEN_HEADER, secretary.
_NAME_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_CREDENTIAL_WORDS = frozenset({
    "password", "passwd", "passphrase", "secret", "token", "apikey", "secretkey", "accesskey",
})
_KEY_QUALIFIERS = frozenset({"api", "access", "secret", "encryption", "signing", "client", "private"})


def _credential_key(name: str) -> bool:
    words = [word.lower() for word in _NAME_WORD.findall(name)]
    while len(words) > 1 and words[-1].isdigit():
        words.pop()  # PASSWORD2, token_1
    if not words:
        return False
    last = words[-1]
    if last in _CREDENTIAL_WORDS:
        return True
    if last == "key":
        return len(words) > 1 and words[-2] in _KEY_QUALIFIERS
    return words[-2:] == ["database", "url"]


def _placeholder_password(value: str) -> bool:
    """User-info passwords in documentation and templates: user:pass@, ${DB_PASSWORD}, %s."""
    lowered = value.lower()
    return _is_placeholder(value) or lowered in {"pass", "pwd", "pw", "passwd", "pass123"} or (
        value.startswith(("$", "%", "{"))
    )


def _reported(pattern_name: str, match: re.Match[str]) -> bool:
    """Whether a match is a credential the scanner reports (not a placeholder or descriptor)."""
    if pattern_name == "credential_assignment":
        value = _assignment_value(match)
        # A value that repeats its key names something ("insecure_random_for_secret":
        # "insecure_random_for_secret" in a rule table); it is not a secret.
        return (_credential_key(match.group("key")) and not _is_placeholder(value)
                and value.strip().lower() != match.group("key").lower())
    if pattern_name == "credential_url":
        return not _placeholder_password(match.group("password"))
    return True


def credential_matches(text: str, relative: str):
    """(pattern name, match) for every credential the scanner reports in ``text``.

    The archive member scanner uses this too, so members and files get the same rules.
    """
    patterns = _EXPRESSION_PATTERNS if _expression_language(relative) else _PATTERNS
    for pattern_name, pattern, anchors in patterns:
        if anchors and not any(anchor in text for anchor in anchors):
            continue
        for match in pattern.finditer(text):
            if _reported(pattern_name, match):
                yield pattern_name, match


def _expression_language(relative: str) -> bool:
    """Whether unquoted assignment values in this file are code expressions."""
    return is_source_path(relative) and detect_language(relative) not in _LITERAL_ASSIGNMENT_LANGUAGES


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
    limits = AnalyzerLimits(
        _MAX_SCAN_BYTES,
        "stream",
        {"chunk_bytes": _CHUNK_BYTES, "overlap_chars": _OVERLAP_CHARS, "findings": _MAX_FINDINGS},
        outcome="UNKNOWN or partial finding at the byte or finding limit",
    )
    domains = ("secrets",)
    languages = textual_language_names()

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        is_env_or_credential_file = (
            name in _SENSITIVE_FILENAMES
            or name.startswith(".env.")
            or Path(record.path).suffix.lower() in _SENSITIVE_EXTENSIONS
        )
        kube = "/.kube/" in "/" + record.path.replace("\\", "/").lower()
        return (
            record.error is None
            and record.content_skipped_reason is None
            and (is_textual_path(record.path) or is_env_or_credential_file or kube or record.file_type == "text")
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if Path(record.path).suffix.lower() in _KEY_CONTAINERS:
            low_risk = _low_risk_path(record.path)
            return [Finding(
                "security",
                f"Private-key container: {record.path}",
                "A PKCS#12 or Java keystore file is part of the repository. It usually holds a "
                "private key and certificate chain behind a password; its contents are not read."
                + (" The file is in a test, fixture, example or documentation location, so severity "
                   "was lowered one level." if low_risk else ""),
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
                severity=_DOWNGRADE["HIGH"] if low_risk else "HIGH",
                impact=_credential_impact("private_key"),
                recommendation=(
                    "Remove committed keystores, rotate the keys they hold, and load them at run time "
                    "from a secret manager."
                ),
            )]
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        specific_lines: set[int] = set()
        bytes_scanned = 0
        total_newlines = 0
        tail = ""
        stop_reason: str | None = None
        low_risk = _low_risk_path(record.path)
        patterns = _EXPRESSION_PATTERNS if _expression_language(record.path) else _PATTERNS
        # An incremental decoder keeps multi-byte characters intact across chunk edges.
        # UTF-16 and UTF-32 files are decoded as such (see text_encoding).
        decoder = None
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                while bytes_scanned < _MAX_SCAN_BYTES:
                    raw_chunk = stream.read(min(
                        _CHUNK_BYTES, _MAX_SCAN_BYTES - bytes_scanned
                    ))
                    final = not raw_chunk
                    if decoder is None:
                        decoder = codecs.getincrementaldecoder(text_encoding(raw_chunk))(errors="replace")
                    chunk = decoder.decode(raw_chunk, final=final)
                    if final and not chunk:
                        break
                    bytes_scanned += len(raw_chunk)
                    combined = tail + chunk
                    prefix_length = len(tail)
                    base_line = total_newlines - tail.count("\n")
                    for pattern_name, pattern, anchors in patterns:
                        if anchors and not any(anchor in combined for anchor in anchors):
                            continue
                        # Matches come in order, so newlines are counted from the previous
                        # match instead of from the chunk start (quadratic on long lines).
                        counted_to, counted_lines = 0, 0
                        for match in pattern.finditer(combined):
                            if match.end() <= prefix_length:
                                continue
                            if not _reported(pattern_name, match):
                                continue
                            counted_lines += combined.count("\n", counted_to, match.start())
                            counted_to = match.start()
                            line_number = base_line + counted_lines + 1
                            key = (pattern_name, line_number)
                            if key in seen:
                                continue
                            # A specific provider format on the line supersedes the generic
                            # assignment rule, so one secret yields one finding.
                            if pattern_name == "credential_assignment" and line_number in specific_lines:
                                continue
                            seen.add(key)
                            # A provider format or credential URL on the line supersedes the
                            # generic assignment (DATABASE_URL = postgres://user:pass@...).
                            if pattern_name != "credential_assignment":
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
                describe_error(exc), confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name, severity="LOW",
            )]

        if stop_reason or (record.size_bytes > bytes_scanned and bytes_scanned >= _MAX_SCAN_BYTES):
            if stop_reason:
                limit_reached("findings", _MAX_FINDINGS, len(findings))
            else:
                limit_reached("bytes", _MAX_SCAN_BYTES, record.size_bytes)
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
