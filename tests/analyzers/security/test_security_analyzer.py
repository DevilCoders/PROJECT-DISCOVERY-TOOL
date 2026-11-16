from pathlib import Path

from project_discovery.analyzers.security.secrets import SecretPatternAnalyzer
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
    from project_discovery.analyzers.security import secrets as security_analyzer

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
    from project_discovery.engine.native import count_byte

    sample = b"line1\nline2\n" * 1000
    assert count_byte(sample, 10) == sample.count(b"\n")


def test_source_excerpt_redacts_secrets_identity_and_credential_urls():
    from project_discovery.core.source_utils import redact_source_excerpt

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
    from project_discovery.core.source_utils import redact_source_excerpt

    token = "bearer-secret-value-0123456789"
    excerpt = redact_source_excerpt(f"Authorization: Bearer {token}")
    assert token not in excerpt


def test_every_detected_token_format_is_redacted_from_report_excerpts(tmp_path: Path):
    # Regression: the detector and redactor kept separate lists, so Docker PATs, Stripe
    # restricted keys and Azure account keys were reported with the raw value.
    from project_discovery.core.secret_patterns import TOKEN_FORMATS

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
    from project_discovery.core.source_utils import redact_source_excerpt

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
    import project_discovery.analyzers.security.secrets as module

    monkeypatch.setattr(module, "_CHUNK_BYTES", 7)
    path = tmp_path / "notes.txt"
    token = "glpat-" + "k" * 24
    path.write_text("caf\u00e9 \u20ac\u20ac\u20ac " + token + "\n", encoding="utf-8")
    record = FileRecord("notes.txt", path.stat().st_size, ".txt", "Text", file_type="text")
    findings = module.SecretPatternAnalyzer().analyze(path, record)
    assert [finding.evidence for finding in findings] == [["notes.txt:1"]]


_FORMAT_SAMPLES = {
    "github_token": "ghp_" + "A" * 36,
    "github_fine_grained_token": "github_pat_" + "a" * 82,
    "gitlab_token": "glpat-" + "x" * 20,
    "aws_access_key_id": "AKIAABCDEFGHIJKLMNOP",
    "google_api_key": "AIza" + "B" * 35,
    "google_oauth_client_secret": "GOCSPX-" + "c" * 28,
    "slack_token": "xoxb-" + "1" * 20,
    "slack_webhook_url": "https://hooks.slack.com/services/T0ABCDEF1/B0ABCDEF1/" + "x" * 24,
    "stripe_secret_key": "sk_live_" + "a" * 24,
    "sendgrid_api_key": "SG." + "a" * 22 + "." + "b" * 43,
    "anthropic_api_key": "sk-ant-api03-" + "a" * 40,
    "openai_api_key": "sk-proj-" + "a" * 40,
    "huggingface_token": "hf_" + "a" * 34,
    "npm_token": "npm_" + "a" * 36,
    "pypi_token": "pypi-" + "a" * 50,
    "docker_pat": "dckr_pat_" + "a" * 27,
    "digitalocean_token": "dop_v1_" + "a" * 64,
    "shopify_token": "shpat_" + "a" * 32,
    "twilio_api_key": "SK" + "a" * 32,
    "square_token": "sq0atp-" + "a" * 22,
    "telegram_bot_token": "123456789:AA" + "a" * 33,
    "discord_bot_token": "M" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27,
    "databricks_token": "dapi" + "a" * 32,
    "atlassian_api_token": "ATATT3" + "a" * 160,
    "linear_api_key": "lin_api_" + "a" * 40,
    "postman_api_key": "PMAK-" + "a" * 24 + "-" + "b" * 34,
    "grafana_token": "glsa_" + "a" * 32 + "_abcdef12",
    "new_relic_key": "NRAK-" + "A" * 27,
    "hashicorp_vault_token": "hvs." + "a" * 24,
    "doppler_token": "dp.pt." + "a" * 43,
    "age_secret_key": "AGE-SECRET-KEY-1" + "Q" * 58,
    "jwt": "eyJ" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10,
    "azure_storage_account_key": "AccountKey=" + "A" * 86 + "==",
    "azure_shared_access_key": "SharedAccessKey=" + "A" * 43 + "=",
    "azure_sas_signature": "?sv=2020-08-04&sig=" + "a" * 30,
}


def test_every_token_format_matches_its_sample_and_anchors_are_sound():
    # Anchors let the scanner skip regexes; a wrong anchor would silently hide secrets.
    from project_discovery.core.secret_patterns import ANY_TOKEN, COMPILED_FORMATS
    from project_discovery.core.source_utils import redact_source_excerpt

    assert set(_FORMAT_SAMPLES) == {item.name for item, _ in COMPILED_FORMATS}
    for item, pattern in COMPILED_FORMATS:
        sample = _FORMAT_SAMPLES[item.name]
        assert pattern.search(sample), item.name
        assert ANY_TOKEN.search(sample), item.name
        if item.anchors:
            assert any(anchor in sample for anchor in item.anchors), item.name
        assert "[REDACTED" in redact_source_excerpt(f"value {sample} end"), item.name


def _assignment_lines(tmp_path: Path, filename: str, content: str) -> list[int]:
    findings = _scan(tmp_path, filename, content)
    return [
        int(finding.evidence[0].rsplit(":", 1)[1])
        for finding in findings
        if finding.title.endswith("credential_assignment")
    ]


def test_code_expressions_and_line_breaks_are_not_credential_values(tmp_path: Path):
    # Self-scan regressions: each line assigns an expression, not a literal secret.
    source = (
        "_SECRET_ASSIGNMENT = re.compile(\n"
        "secret_field_lines: list[int] = []\n"
        "secret_excerpts: dict[int, str] = {}\n"
        "secret_last_line = current_line\n"
        "TOKEN_FORMATS: tuple[TokenFormat, ...] = (\n"
        "if secret_field_line_count:\n"
        "    summary = build_summary()\n"
        'if token == "abcdef123":\n'
    )
    for filename in ("analyzer.py", "analyzer.ts", "analyzer.go", "Analyzer.java"):
        assert _assignment_lines(tmp_path, filename, source) == [], filename


def test_literal_credential_assignments_are_detected_across_syntaxes(tmp_path: Path):
    python = (
        'password = "hunter22-lit"\n'
        'settings = {"password": "hunter22-lit"}\n'
        'secret_key: str = "dev-secret-123"\n'
        "token: Optional[str] = 'tok-123456'\n"
    )
    assert _assignment_lines(tmp_path, "settings.py", python) == [1, 2, 3, 4]
    assert _assignment_lines(tmp_path, "main.go", 'password := "hunter22-lit"\n') == [1]
    assert _assignment_lines(tmp_path, "app.php", "$db = ['password' => 'hunter22-lit'];\n") == [1]
    assert _assignment_lines(tmp_path, "app.ts", 'const apiKey: string = "abcdef123456";\n') == [1]
    # Unquoted values stay literal in configuration, environment and shell files.
    assert _assignment_lines(tmp_path, "deploy.sh", "export API_TOKEN=abc123def456\n") == [1]
    assert _assignment_lines(tmp_path, "app.yaml", "password: hunter22-lit\n") == [1]
    assert _assignment_lines(tmp_path, "settings.ini", "password = hunter22-lit\n") == [1]


def test_every_detected_assignment_syntax_is_redacted_from_findings(tmp_path: Path):
    # Regression: the detector learned :=, =>, typed defaults and signing/encryption keys,
    # but the redactor only knew "key = value", so the finding's own excerpt kept the value.
    import json

    samples = {
        "main.go": ('password := "FakeGoPass-9183"\n', "FakeGoPass-9183"),
        "app.php": ("$db = ['password' => 'FakePhpPass-5521'];\n", "FakePhpPass-5521"),
        "settings.py": ('secret_key: str = "FakePySecret-7731"\n', "FakePySecret-7731"),
        "app.ts": ('const apiKey: string = "FakeTsKey-4410";\n', "FakeTsKey-4410"),
        "App.kt": ('val password: String = "FakeKtPass-2208"\n', "FakeKtPass-2208"),
        "config.rb": ('config = { :password => "FakeRbPass-6652" }\n', "FakeRbPass-6652"),
        ".env": ("SIGNING_KEY=FakeSigningKey-3391\n", "FakeSigningKey-3391"),
        "crypto.py": ('encryption_key = "FakeEncKey-8820"\n', "FakeEncKey-8820"),
    }
    for filename, (content, value) in samples.items():
        findings = _scan(tmp_path, filename, content)
        assert any(item.title.endswith("credential_assignment") for item in findings), filename
        dumped = json.dumps([item.to_dict() for item in findings])
        assert value not in dumped, filename


def test_quoted_authorization_headers_and_identity_forms_are_redacted():
    from project_discovery.core.source_utils import redact_source_excerpt

    for line, value in (
        ('headers = {"Authorization": "Bearer FakeOpaqueBearer-7c1d"}', "FakeOpaqueBearer-7c1d"),
        ("headers['authorization'] = 'Token FakeOpaqueToken-9e2f'", "FakeOpaqueToken-9e2f"),
        ('forename = "Alicia"', "Alicia"),
        ('user = {"ssn" => "078-05-1120"}', "078-05-1120"),
        ('email := "someone@example.org"', "someone@example.org"),
    ):
        assert value not in redact_source_excerpt(line), line


def test_utf16_and_utf32_files_are_scanned(tmp_path: Path):
    # Regression: PowerShell 5.1 writes UTF-16LE; decoded as UTF-8 the file had a NUL between
    # every character and came back clean.
    from project_discovery.analyzers.security.privacy import DataExposureAnalyzer
    from project_discovery.core.source_utils import text_encoding

    token = "ghp_" + "C" * 36
    content = f"$env:GH_TOKEN = '{token}'\n$password = 'Fake-Utf16-Pass1'\n"
    for name, encoding in (("deploy.ps1", "utf-16"), ("bare.ps1", "utf-16-le"), ("wide.ps1", "utf-32")):
        path = tmp_path / name
        path.write_bytes(content.encode(encoding))
        record = FileRecord(name, path.stat().st_size, ".ps1", "Source")
        titles = [item.title for item in SecretPatternAnalyzer().analyze(path, record)]
        assert "Potential hardcoded credential: github_token" in titles, name
        privacy = DataExposureAnalyzer().analyze(path, FileRecord(name, path.stat().st_size, ".ps1", "PowerShell", file_type="text"))
        assert any("Credential field-name" in item.title for item in privacy), name
    assert text_encoding("abc".encode("utf-16-be")[2:] * 10) == "utf-16-be"
    assert text_encoding(b"plain ascii text here") == "utf-8"


def test_credential_keys_need_a_credential_noun_last(tmp_path: Path):
    # Regression: a keyword anywhere in a name was a HIGH credential (tokenizer, token_type).
    descriptors = (
        'tokenizer = "bert-base-uncased"\ntoken_type = "Bearer"\nsecret_name = "prod-db-creds"\n'
        'password_hash_algorithm = "argon2id"\nTOKEN_HEADER = "X-Auth-Token"\nsecretary = "Jane Fakename"\n'
        '"insecure_random_for_secret": "insecure_random_for_secret"\n'
    )
    assert _assignment_lines(tmp_path, "settings.py", descriptors) == []
    credentials = (
        'db_password = "Fake-Db-Pass1"\napiKey = "Fake-Api-Key2"\nSECRET_KEY = "Fake-Secret-3"\n'
        'auth_token = "Fake-Auth-Tok4"\nAWS_SECRET_ACCESS_KEY = "Fake-Aws-Key5"\n'
    )
    assert _assignment_lines(tmp_path, "settings.py", credentials) == [1, 2, 3, 4, 5]
    schema = "password: string\ntoken: String!\napi_key: ghp_...\n"
    assert _assignment_lines(tmp_path, "openapi.yaml", schema) == []


def test_credential_urls_skip_placeholder_passwords(tmp_path: Path):
    findings = _scan(tmp_path, "notes.txt", (
        "postgres://user:pass@db.internal/app\nmysql://root:${DB_PASSWORD}@db/app\n"
        "redis://app:%s@cache:6379\npostgres://svc:Fake-Real-Pw9@db.internal/app\n"
    ))
    lines = [item.evidence[0] for item in findings if item.title.endswith("credential_url")]
    assert lines == ["notes.txt:4"]


def test_one_secret_gives_one_finding_and_examples_are_downgraded(tmp_path: Path):
    # Regressions: an Anthropic key was also an OpenAI key, a database URL was both a
    # credential URL and an assignment, and .env.example stayed HIGH.
    anthropic = "sk-ant-" + "api03-" + "A1b2" * 6
    titles = [item.title for item in _scan(tmp_path, "keys.py", f'KEY = "{anthropic}"\n')]
    assert titles == ["Potential hardcoded credential: anthropic_api_key"]
    url = _scan(tmp_path, "settings.py", 'DATABASE_URL = "postgres://svc:Fake-Db-Pass9@db.internal/app"\n')
    assert [item.title for item in url] == ["Potential hardcoded credential: credential_url"]
    example = _scan(tmp_path, ".env.example", "DB_PASSWORD=Fake-Example-Pass1\n")
    assert [item.severity for item in example] == ["MEDIUM"]


def test_key_containers_are_reported_by_name(tmp_path: Path):
    path = tmp_path / "client.p12"
    path.write_bytes(b"\x30\x82\x05\x00" + b"\x00" * 64)
    record = FileRecord("certs/client.p12", path.stat().st_size, ".p12", "Binary")
    findings = SecretPatternAnalyzer().analyze(path, record)
    assert [(item.title, item.severity) for item in findings] == [("Private-key container: certs/client.p12", "HIGH")]
