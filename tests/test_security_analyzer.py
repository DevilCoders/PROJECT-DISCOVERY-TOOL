from pathlib import Path

from project_discovery.analyzers.security_analyzer import SecretPatternAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, Path(filename).suffix, "Source")
    analyzer = SecretPatternAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_detects_secret_patterns_and_redacts_values(tmp_path: Path):
    token = "ghp_" + "A" * 36
    password = "correct horse battery staple"
    findings = _scan(
        tmp_path, "settings.py",
        f'API_KEY = "{token}"\n'
        f'password = "{password}"\n'
        'PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n',
    )
    serialized = repr([finding.to_dict() for finding in findings])
    assert len(findings) >= 3
    assert token not in serialized and password not in serialized
    assert all(finding.confidence == "INFERRED" for finding in findings)
    assert all("redacted" in finding.detail.lower() for finding in findings)
    assert all(finding.code_evidence for finding in findings)
    assert all(finding.impact and finding.recommendation for finding in findings)
    assert all(token not in repr(finding.code_evidence) for finding in findings for token in (password,))


def test_ignores_placeholders_and_environment_references(tmp_path: Path):
    findings = _scan(
        tmp_path, "config.py",
        'API_KEY = "YOUR_API_KEY"\n'
        'password = os.getenv("APP_PASSWORD")\n'
        'secret = "$" + "{SECRET_VALUE}"\n',
    )
    assert findings == []


def test_scans_env_file_without_extension_and_redacts_value(tmp_path: Path):
    findings = _scan(tmp_path, ".env.local", "SERVICE_TOKEN=real-token-value-123\n")
    assert findings and findings[0].evidence == [".env.local:1"]
    assert "real-token-value-123" not in repr([item.to_dict() for item in findings])


def test_global_skip_marker_disables_content_analysis():
    record = FileRecord(
        "settings.py", 100, ".py", "Python",
        content_skipped_reason="Explicit --skip: above configured limit",
    )
    assert SecretPatternAnalyzer().supports(record) is False


def test_provider_token_formats_are_redacted(tmp_path: Path):
    values = [
        "glpat-" + "g" * 30, "AIza" + "a" * 35,
        "sk_live_" + "s" * 24, "sk-ant-" + "a" * 32,
        "hf_" + "h" * 40, "npm_" + "n" * 40, "pypi-" + "p" * 45,
    ]
    findings = _scan(tmp_path, "tokens.env", "\n".join(values) + "\n")
    serialized = repr([item.to_dict() for item in findings])
    assert len(findings) >= len(values)
    assert all(value not in serialized for value in values)


def test_aws_access_key_and_credential_url_redaction(tmp_path: Path):
    aws_id = "AKIA" + "A" * 16
    findings = _scan(
        tmp_path, "config.env",
        f"AWS_ACCESS_KEY_ID={aws_id}\n"
        "DATABASE_URL=postgres://user:super-secret-pass@db.internal:5432/app\n",
    )
    serialized = repr([item.to_dict() for item in findings])
    assert aws_id not in serialized
    assert "super-secret-pass" not in serialized


def test_stream_budget_is_reported_as_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import security_analyzer

    path = tmp_path / "large.env"
    path.write_text("x" * 300 + "\nPASSWORD=late-secret-value-123\n", encoding="utf-8")
    monkeypatch.setattr(security_analyzer, "_MAX_SCAN_BYTES", 128)
    monkeypatch.setattr(security_analyzer, "_CHUNK_BYTES", 64)
    record = FileRecord("large.env", path.stat().st_size, ".env", "Other")
    findings = SecretPatternAnalyzer().analyze(path, record)
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)


def test_secret_findings_have_actionable_severity(tmp_path: Path):
    findings = _scan(tmp_path, "private.pem", "-----BEGIN PRIVATE KEY-----\n")
    assert findings[0].severity == "CRITICAL"


def test_secret_scanner_covers_polyglot_source_and_text_formats():
    analyzer = SecretPatternAnalyzer()
    for filename in (
        "agent.jl", "service.ex", "contract.sol", "kernel.cu",
        "shader.wgsl", "module.vhd", "controller.nim", "guide.md",
        "schema.graphql", "infra.tf", "deployment.env",
    ):
        record = FileRecord(filename, 10, Path(filename).suffix.lower(), "Other")
        assert analyzer.supports(record), filename


def test_private_key_names_without_extensions_are_supported():
    analyzer = SecretPatternAnalyzer()
    for name in ("id_rsa", "id_ed25519", "id_ecdsa", ".netrc", ".pypirc"):
        record = FileRecord(name, 50, "", "Unknown")
        assert analyzer.supports(record), name


def test_binary_office_documents_are_not_scanned_as_utf8_text():
    record = FileRecord("manual.docx", 1024, ".docx", "Word Document", file_type="document/docx")
    assert SecretPatternAnalyzer().supports(record) is False


def test_native_byte_counter_matches_reference_count():
    from project_discovery.native_backend import count_byte

    sample = b"line1\nline2\n" * 1000
    assert count_byte(sample, 10) == sample.count(b"\n")


def test_source_excerpt_redacts_secrets_identity_and_credential_urls():
    from project_discovery.source_utils import redact_source_excerpt

    sensitive = (
        'first_name = "Alice"; email = "alice@example.com"; '
        'password = "super-secret-value"; token = "ghp_' + "A" * 36 + '"; '
        'DATABASE_URL = "postgres://admin:db-password@db.internal/app"'
    )
    excerpt = redact_source_excerpt(sensitive)
    for value in (
        "Alice", "alice@example.com", "super-secret-value",
        "ghp_" + "A" * 36, "db-password",
    ):
        assert value not in excerpt
    assert excerpt.count("[REDACTED]") >= 3
