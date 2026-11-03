"""Source-reading helpers that honor language declarations and redact report excerpts."""
from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path


_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)(["']?[A-Za-z0-9_]*(?:password|passwd|passphrase|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key|private[_-]?key|database[_-]?url|connection[_-]?string|credential|refresh[_-]?token|aws_secret_access_key)[A-Za-z0-9_]*["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
)
_IDENTITY_ASSIGNMENT = re.compile(
    r"""(?ix)(["']?[A-Za-z0-9_]*(?:first_?name|given_?name|middle_?name|last_?name|family_?name|surname|user_?name|login_?name|account_?name|email|e_mail|email_?address|phone|telephone|mobile|cell_?number|street_?address|postal_?address|home_?address|date_?of_?birth|birth_?date|dob|ssn|social_?security|passport_?number|national_?id)[A-Za-z0-9_]*["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
)
_CREDENTIAL_URL = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s/]+(@)")
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?[^,\r\n;]+"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[A-Za-z0-9-]{16,}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{12,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|"
    r"sk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"hf_[A-Za-z0-9]{24,}|npm_[A-Za-z0-9]{24,}|pypi-[A-Za-z0-9_-]{30,})\b"
)
_PRIVATE_KEY_BODY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.I)


def redact_source_excerpt(source_line: str, *, max_chars: int = 400) -> str:
    """Return a bounded source line with credentials and direct identifiers removed."""
    value = source_line.rstrip("\r\n")
    value = _PRIVATE_KEY_BODY.sub("[REDACTED PRIVATE KEY MATERIAL]", value)
    value = _AUTHORIZATION_HEADER.sub("Authorization: [REDACTED]", value)
    value = _SECRET_ASSIGNMENT.sub(r'\1"[REDACTED]"', value)
    value = _IDENTITY_ASSIGNMENT.sub(r'\1"[REDACTED]"', value)
    value = _CREDENTIAL_URL.sub(r"\1[REDACTED]\2", value)
    value = _TOKEN.sub("[REDACTED_TOKEN]", value)
    value = _EMAIL.sub("[REDACTED_EMAIL]", value)
    if len(value) > max_chars:
        value = value[:max_chars] + " … [truncated]"
    return value


def read_python_source(path: Path) -> str:
    """Read Python source using PEP 263 encoding-cookie detection."""
    with path.open("rb") as raw:
        encoding, _ = tokenize.detect_encoding(raw.readline)
    return path.read_text(encoding=encoding)

class SourceBudgetExceeded(ValueError):
    """Raised when a source file exceeds a parser's bounded read budget."""


def read_python_source_bounded(path: Path, max_bytes: int) -> str:
    """Read at most max_bytes + 1 and decode Python source using its PEP 263 cookie."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    with path.open("rb") as stream:
        raw_source = stream.read(max_bytes + 1)
    if len(raw_source) > max_bytes:
        raise SourceBudgetExceeded(
            f"source grew beyond the {max_bytes:,}-byte parser budget while being read"
        )
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_source).readline)
    return raw_source.decode(encoding)


def read_text_bounded(
    path: Path,
    max_bytes: int,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    """Read a text artifact with a race-safe max_bytes + 1 content budget."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    with path.open("rb") as stream:
        raw_content = stream.read(max_bytes + 1)
    if len(raw_content) > max_bytes:
        raise SourceBudgetExceeded(
            f"content grew beyond the {max_bytes:,}-byte analyzer budget while being read"
        )
    return raw_content.decode(encoding, errors=errors)

