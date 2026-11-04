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

def test_verified_reader_accepts_original_inventory_identity(tmp_path: Path):
    from project_discovery.source_utils import open_verified_binary

    path = tmp_path / "stable.txt"
    path.write_text("stable content", encoding="utf-8")
    info = path.stat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    with open_verified_binary(path, identity) as stream:
        assert stream.read() == b"stable content"


def test_verified_reader_rejects_replaced_file_identity(tmp_path: Path):
    from project_discovery.source_utils import open_verified_binary

    path = tmp_path / "mutable.txt"
    replacement = tmp_path / "replacement.txt"
    path.write_text("original", encoding="utf-8")
    info = path.stat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    replacement.write_text("original", encoding="utf-8")
    replacement.replace(path)

    with pytest.raises(OSError, match="identity changed"):
        with open_verified_binary(path, identity):
            pass


def test_verified_reader_rejects_symlink_substitution(tmp_path: Path):
    from project_discovery.source_utils import open_verified_binary

    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    path = tmp_path / "source.txt"
    path.write_text("source", encoding="utf-8")
    path.unlink()
    try:
        path.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")

    with pytest.raises(OSError, match="non-regular"):
        with open_verified_binary(path):
            pass


def test_bounded_text_reader_rejects_changed_scan_identity(tmp_path: Path):
    from project_discovery.source_utils import read_text_bounded

    path = tmp_path / "config.yml"
    path.write_text("name: before\n", encoding="utf-8")
    info = path.stat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    path.write_text("name: after and changed\n", encoding="utf-8")

    with pytest.raises(OSError, match="identity changed"):
        read_text_bounded(path, 1024, expected_identity=identity)


def test_file_record_serialization_omits_private_scan_identity(tmp_path: Path):
    from project_discovery.models import FileRecord

    path = tmp_path / "source.py"
    path.write_text("pass\n", encoding="utf-8")
    info = path.stat()
    record = FileRecord(
        "source.py", info.st_size, ".py", "Python",
        analysis_identity=(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
    )
    assert "analysis_identity" not in record.to_dict()

