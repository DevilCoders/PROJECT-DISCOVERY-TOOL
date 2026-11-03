from pathlib import Path

import pytest

from project_discovery.source_utils import (
    SourceBudgetExceeded,
    read_python_source_bounded,
)


def test_bounded_reader_honors_pep263_encoding_cookie(tmp_path: Path):
    path = tmp_path / "latin_source.py"
    path.write_bytes(
        b"# -*- coding: latin-1 -*-\n"
        + b"value = 'caf" + bytes([0xE9]) + b"'\n"
    )
    source = read_python_source_bounded(path, 128)
    assert "café" in source


def test_bounded_reader_raises_when_source_exceeds_budget(tmp_path: Path):
    path = tmp_path / "large_source.py"
    path.write_bytes(b"x" * 33)
    with pytest.raises(SourceBudgetExceeded, match="32-byte parser budget"):
        read_python_source_bounded(path, 32)


def test_bounded_reader_rejects_non_positive_budget(tmp_path: Path):
    path = tmp_path / "source.py"
    path.write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="positive"):
        read_python_source_bounded(path, 0)

@pytest.mark.parametrize(
    ("line", "sensitive"),
    [
        ('password = "hunter2"', "hunter2"),
        ('first_name = "Alice"', "Alice"),
        ('Authorization: Bearer super-secret-value', "super-secret-value"),
        ('DATABASE_URL = "postgres://admin:db-password@db.internal/app"', "db-password"),
        ('contact = "person@example.test"', "person@example.test"),
        ('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"', "ghp_"),
        ('key = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg"', "MIIEvQIBADANBg"),
        ("MIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", "MIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"),
    ],
)
def test_redact_source_excerpt_removes_sensitive_values(line: str, sensitive: str):
    from project_discovery.source_utils import redact_source_excerpt

    redacted = redact_source_excerpt(line)
    assert sensitive not in redacted
    assert "[REDACTED" in redacted


def test_redact_source_excerpt_bounds_output():
    from project_discovery.source_utils import redact_source_excerpt

    redacted = redact_source_excerpt("x" * 100, max_chars=20)
    assert len(redacted) <= 40
    assert "[truncated]" in redacted


def test_code_evidence_enforces_redaction_at_model_boundary():
    from project_discovery.models import CodeEvidence

    evidence = CodeEvidence(line_number=7, code='password = "never-print-this"')
    assert "never-print-this" not in evidence.to_dict()["code"]

