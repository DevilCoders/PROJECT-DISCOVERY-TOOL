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
        'DATABASE_URL = "postgres://admin:db-password@db.internal/app"; '
        'Authorization: Bearer bearer-secret-value'
    )
    excerpt = redact_source_excerpt(sensitive)
    assert "Authorization: [REDACTED]" in excerpt
    for value in (
        "Alice", "alice@example.com", "super-secret-value",
        "ghp_" + "A" * 36, "db-password", "Bearer", "bearer-secret-value",
    ):
        assert value not in excerpt
    assert excerpt.count("[REDACTED]") >= 3


def test_code_evidence_model_redacts_values_from_custom_analyzers():
    from project_discovery.models import CodeEvidence

    secret = "custom-secret-value-987"
    evidence = CodeEvidence(
        line_number=22,
        code=f'password = "{secret}"; email = "dev@example.com"',
    )
    assert secret not in evidence.code
    assert "dev@example.com" not in evidence.code
    assert "[REDACTED]" in evidence.code

def test_model_boundary_redacts_prefixed_secret_and_identity_keys():
    from project_discovery.models import CodeEvidence

    token = "real-token-value-123"
    email = "alice@example.invalid"
    evidence = CodeEvidence(
        line_number=4,
        code=f"SERVICE_TOKEN={token}; CUSTOMER_FIRST_NAME=Alice; OWNER_EMAIL={email}",
    )
    for value in (token, "Alice", email):
        assert value not in evidence.code
    assert "[REDACTED]" in evidence.code


def test_authorization_bearer_value_is_redacted_without_leaving_token_tail():
    from project_discovery.source_utils import redact_source_excerpt

    token = "bearer-secret-value-0123456789"
    excerpt = redact_source_excerpt(f"Authorization: Bearer {token}")
    assert token not in excerpt


def test_every_detected_token_format_is_redacted_from_report_excerpts(tmp_path: Path):
    # Regression: the detector and redactor kept separate lists, so Docker PATs, Stripe
    # restricted keys and Azure account keys were reported with the raw value.
    from project_discovery.secret_patterns import TOKEN_FORMATS

    samples = {
        "docker_pat": "docker login -p dckr_pat_" + "a1B2" * 7,
        "stripe_secret_key": "client = Stripe(rk_live_" + "Ab12" * 6 + ")",
        "azure_storage_account_key": "DefaultEndpointsProtocol=https;AccountKey=" + "Q0" * 43 + "==",
        "telegram_bot_token": "bot = Bot(123456789:AA" + "x1Y2" * 8 + "z)",
        "age_secret_key": "AGE-SECRET-KEY-1" + "QPZRY9X8GF" * 5 + "QPZRY9X8",
        "slack_webhook_url": "send(https://hooks.slack.com/services/T0ABCDEF1/B0ABCDEF1/" + "x" * 24 + ")",
    }
    assert set(samples) <= {item.name for item in TOKEN_FORMATS}
    lines = list(samples.values())
    path = tmp_path / "config.txt.cfg"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    record = FileRecord("deploy/config.cfg", path.stat().st_size, ".cfg", "INI", file_type="text")
    findings = SecretPatternAnalyzer().analyze(path, record)
    detected = {finding.title.rsplit(": ", 1)[-1] for finding in findings}
    assert set(samples) <= detected
    report = repr([finding.to_dict() for finding in findings])
    for value in ("dckr_pat_a1B2", "rk_live_Ab12", "Q0Q0Q0Q0Q0", "AAx1Y2", "SECRET-KEY-1QPZ", "B0ABCDEF1/xxxx"):
        assert value not in report, value


def test_pgp_private_key_headers_and_connection_string_passwords_are_redacted():
    from project_discovery.source_utils import redact_source_excerpt

    assert "PGP PRIVATE" not in redact_source_excerpt("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    redacted = redact_source_excerpt("Server=db;User Id=app;Pwd=Sup3rS3cret!;Encrypt=true")
    assert "Sup3rS3cret" not in redacted


def test_test_fixture_credentials_are_downgraded_and_placeholders_ignored(tmp_path: Path):
    path = tmp_path / "fixture.py"
    path.write_text(
        'API_KEY = "ghp_' + "Z" * 36 + '"\n'
        'password = "{{ secrets.DB_PASSWORD }}"\n'
        'token = "xxxxxxxxxxxx"\n',
        encoding="utf-8",
    )
    record = FileRecord("tests/fixtures/fixture.py", path.stat().st_size, ".py", "Python", file_type="text")
    findings = SecretPatternAnalyzer().analyze(path, record)
    assert [finding.title for finding in findings] == ["Potential hardcoded credential: github_token"]
    assert findings[0].severity == "MEDIUM" and "test, fixture" in findings[0].detail


def test_multibyte_characters_split_across_chunks_do_not_hide_tokens(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.security_analyzer as module

    monkeypatch.setattr(module, "_CHUNK_BYTES", 7)
    path = tmp_path / "notes.txt"
    token = "glpat-" + "k" * 24
    path.write_text("caf\u00e9 \u20ac\u20ac\u20ac " + token + "\n", encoding="utf-8")
    record = FileRecord("notes.txt", path.stat().st_size, ".txt", "Text", file_type="text")
    findings = module.SecretPatternAnalyzer().analyze(path, record)
    assert [finding.evidence for finding in findings] == [["notes.txt:1"]]
