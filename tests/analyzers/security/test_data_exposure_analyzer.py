from pathlib import Path

from project_discovery.analyzers.security.privacy import DataExposureAnalyzer
from project_discovery.models import FileRecord


def test_pii_and_credential_indicators_redact_all_values(tmp_path: Path):
    path = tmp_path / "users.json"
    path.write_text(
        '{ "first_name": "Alice", "last_name": "Example", '
        '"username": "alice-admin", "email": "alice@fixture-mailbox.net", '
        '"password": "very-secret-password" }',
        encoding="utf-8",
    )
    record = FileRecord("data/users.json", path.stat().st_size, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert any("Personal-data field" in item.title for item in findings)
    assert any("Email-shaped value" in item.title for item in findings)
    assert any("Credential field-name" in item.title for item in findings)
    serialized = repr([item.to_dict() for item in findings])
    for raw in ("Alice", "Example", "alice-admin", "alice@fixture-mailbox.net", "very-secret-password"):
        assert raw not in serialized


def test_unrelated_text_has_no_data_exposure_findings(tmp_path: Path):
    path = tmp_path / "plain.txt"
    path.write_text("print('hello world')\n", encoding="utf-8")
    record = FileRecord("plain.txt", path.stat().st_size, ".txt", "Text", file_type="text")
    assert DataExposureAnalyzer().analyze(path, record) == []


def test_data_exposure_findings_include_redacted_source_and_impact(tmp_path: Path):
    path = tmp_path / "customer.json"
    path.write_text(
        '{"first_name":"Alice","email":"alice@fixture-mailbox.net",'
        '"password":"secret-value-should-not-leak"}',
        encoding="utf-8",
    )
    record = FileRecord(
        "customer.json", path.stat().st_size, ".json", "JSON", file_type="text"
    )
    findings = DataExposureAnalyzer().analyze(path, record)
    assert len(findings) == 3
    assert all(item.code_evidence for item in findings)
    assert all(item.impact and item.recommendation for item in findings)
    rendered = repr([item.to_dict() for item in findings])
    for secret in ("Alice", "alice@fixture-mailbox.net", "secret-value-should-not-leak"):
        assert secret not in rendered

def test_data_exposure_large_file_returns_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.security import privacy as data_exposure_analyzer

    path = tmp_path / "large-users.json"
    path.write_text('{"email":"user@example.test"}', encoding="utf-8")
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_DATA_EXPOSURE_FILE_BYTES", 8)
    record = FileRecord(path.name, 100, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "resource limit" in findings[0].title.lower()


def test_data_exposure_detects_growth_and_reports_partial_budget(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.security import privacy as data_exposure_analyzer

    path = tmp_path / "growing-users.json"
    path.write_text('{"email":"user@example.test"}\n' * 4, encoding="utf-8")
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_DATA_EXPOSURE_FILE_BYTES", 32)
    record = FileRecord(path.name, 1, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)


def test_data_exposure_retains_only_bounded_evidence_samples(tmp_path: Path):
    path = tmp_path / "many-users.jsonl"
    path.write_text(
        "".join('{"email":"user%d@fixture-mailbox.net"}\n' % index for index in range(300)),
        encoding="utf-8",
    )
    record = FileRecord(
        path.name, path.stat().st_size, ".jsonl", "JSONL", file_type="text"
    )
    findings = DataExposureAnalyzer().analyze(path, record)
    email = next(item for item in findings if "Email-shaped value" in item.title)
    assert len(email.evidence) <= 100
    assert len(email.code_evidence) <= 20
    serialized = repr([item.to_dict() for item in findings])
    assert "user299@fixture-mailbox.net" not in serialized


def test_data_exposure_stops_on_overlong_physical_line_as_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.security import privacy as data_exposure_analyzer

    path = tmp_path / "long-line.json"
    path.write_text("x" * 65 + '{"email":"hidden@example.test"}', encoding="utf-8")
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_LINE_BYTES", 64)
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_DATA_EXPOSURE_FILE_BYTES", 1024)
    record = FileRecord(path.name, path.stat().st_size, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "line-length budget" in findings[0].title.lower()


def _scan(tmp_path: Path, name: str, content: str):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, Path(name).suffix, "Source", file_type="text")
    return DataExposureAnalyzer().analyze(path, record)


def test_non_mailbox_email_shapes_are_not_reported(tmp_path: Path):
    findings = _scan(
        tmp_path, "notes.js",
        "// keys look like /@scope/name/1.0.0_peer@1.0.0 and lodash@4.17.21\n"
        "const icon = 'logo@2x.png';\n"
        "const docs = 'alice@example.com, bob@mail.example.org, eve@corp.test';\n"
        "const remote = 'git@github.com:org/repo.git';\n"
        "const url = 'ssh://git@github.com/org/repo', other = 'https://user:pass@host.com/x';\n",
    )
    assert not any("Email-shaped value" in item.title for item in findings)


def test_real_mailbox_shapes_are_reported_per_line(tmp_path: Path):
    findings = _scan(
        tmp_path, "contacts.js",
        "const owner = 'alice@fixture-mailbox.net';\n"
        "const link = 'mailto:bob@fixture-mailbox.co.uk';\n",
    )
    email = next(item for item in findings if "Email-shaped value" in item.title)
    assert email.evidence == [
        "contacts.js:1 (email value redacted)",
        "contacts.js:2 (email value redacted)",
    ]
    assert email.severity == "MEDIUM"


def test_prose_documentation_skips_field_name_inventories_but_not_values(tmp_path: Path):
    findings = _scan(
        tmp_path, "GUIDE.md",
        "Reports never include the email, phone or password of a user.\n"
        "Contact alice@fixture-mailbox.net for access.\n",
    )
    assert [item.title for item in findings] == ["Email-shaped value indicators: GUIDE.md"]


def test_field_name_inventory_is_low_severity_and_bare_mobile_is_not_a_phone(tmp_path: Path):
    findings = _scan(
        tmp_path, "models.py",
        '"""Mobile platform inventory."""\n'
        "phone_number = models.CharField()\n"
        "mobile_number = models.CharField()\n",
    )
    fields = next(item for item in findings if "Personal-data field" in item.title)
    assert fields.severity == "LOW"
    assert fields.evidence == [
        "models.py:2 (field-name indicator: phone)",
        "models.py:3 (field-name indicator: phone)",
    ]


def test_credential_field_lines_hide_positional_literals(tmp_path: Path):
    # Regression: an SQL seed row names the password column, and every finding citing the
    # line (credential field names, personal-data fields) kept the password verbatim.
    path = tmp_path / "schema.sql"
    path.write_text(
        "INSERT INTO users (username, email, password) VALUES ('alice', 'alice@fixture-mailbox.net', 'plaintextpw');\n",
        encoding="utf-8",
    )
    record = FileRecord("db/schema.sql", path.stat().st_size, ".sql", "SQL", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert any("Credential field-name" in item.title for item in findings)
    serialized = repr([item.to_dict() for item in findings])
    for raw in ("plaintextpw", "alice@fixture-mailbox.net", "'alice'"):
        assert raw not in serialized


def test_field_names_end_with_the_keyword(tmp_path: Path):
    # Regression: \\b boundaries missed DB_PASSWORD, SECRET_KEY, GITHUB_TOKEN and user_email.
    path = tmp_path / "settings.env"
    path.write_text(
        "DB_PASSWORD=x\nSECRET_KEY=x\nGITHUB_TOKEN=x\ntoken=x\nuser_email=x\n"
        "email_verified=x\ntokenizer=x\npassword_hash_algorithm=x\n",
        encoding="utf-8",
    )
    record = FileRecord("settings.env", path.stat().st_size, ".env", "Text", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    secrets = next(item for item in findings if "Credential field-name" in item.title)
    assert [entry.split(":")[1].split(" ")[0] for entry in secrets.evidence] == ["1", "2", "3", "4"]
    assert any("email" in item.title.lower() or "email" in item.detail.lower() for item in findings)
