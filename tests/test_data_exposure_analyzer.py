from pathlib import Path

from project_discovery.analyzers.data_exposure_analyzer import DataExposureAnalyzer
from project_discovery.models import FileRecord


def test_pii_and_credential_indicators_redact_all_values(tmp_path: Path):
    path = tmp_path / "users.json"
    path.write_text(
        '{ "first_name": "Alice", "last_name": "Example", '
        '"username": "alice-admin", "email": "alice@example.net", '
        '"password": "very-secret-password" }',
        encoding="utf-8",
    )
    record = FileRecord("data/users.json", path.stat().st_size, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert any("Personal-data field" in item.title for item in findings)
    assert any("Email-shaped value" in item.title for item in findings)
    assert any("Credential field-name" in item.title for item in findings)
    serialized = repr([item.to_dict() for item in findings])
    for raw in ("Alice", "Example", "alice-admin", "alice@example.net", "very-secret-password"):
        assert raw not in serialized


def test_unrelated_text_has_no_data_exposure_findings(tmp_path: Path):
    path = tmp_path / "plain.txt"
    path.write_text("print('hello world')\n", encoding="utf-8")
    record = FileRecord("plain.txt", path.stat().st_size, ".txt", "Text", file_type="text")
    assert DataExposureAnalyzer().analyze(path, record) == []


def test_data_exposure_findings_include_redacted_source_and_impact(tmp_path: Path):
    path = tmp_path / "customer.json"
    path.write_text(
        '{"first_name":"Alice","email":"alice@example.com",'
        '"password":"secret-value-should-not-leak"}',
        encoding="utf-8",
    )
    record = FileRecord(
        "customer.json", path.stat().st_size, ".json", "JSON", file_type="text"
    )
    findings = DataExposureAnalyzer().analyze(path, record)
    assert findings
    assert all(item.code_evidence for item in findings)
    assert all(item.impact and item.recommendation for item in findings)
    rendered = repr([item.to_dict() for item in findings])
    for secret in ("Alice", "alice@example.com", "secret-value-should-not-leak"):
        assert secret not in rendered

def test_data_exposure_large_file_returns_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import data_exposure_analyzer

    path = tmp_path / "large-users.json"
    path.write_text('{"email":"user@example.test"}', encoding="utf-8")
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_DATA_EXPOSURE_FILE_BYTES", 8)
    record = FileRecord(path.name, 100, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "resource limit" in findings[0].title.lower()


def test_data_exposure_detects_growth_and_reports_partial_budget(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import data_exposure_analyzer

    path = tmp_path / "growing-users.json"
    path.write_text('{"email":"user@example.test"}\\n' * 4, encoding="utf-8")
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_DATA_EXPOSURE_FILE_BYTES", 32)
    record = FileRecord(path.name, 1, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)


def test_data_exposure_retains_only_bounded_evidence_samples(tmp_path: Path):
    path = tmp_path / "many-users.jsonl"
    path.write_text(
        "".join('{"email":"user%d@example.test"}\\n' % index for index in range(300)),
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
    assert "user299@example.test" not in serialized


def test_data_exposure_stops_on_overlong_physical_line_as_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import data_exposure_analyzer

    path = tmp_path / "long-line.json"
    path.write_text("x" * 65 + '{"email":"hidden@example.test"}', encoding="utf-8")
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_LINE_BYTES", 64)
    monkeypatch.setattr(data_exposure_analyzer, "_MAX_DATA_EXPOSURE_FILE_BYTES", 1024)
    record = FileRecord(path.name, path.stat().st_size, ".json", "JSON", file_type="text")
    findings = DataExposureAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "line-length budget" in findings[0].title.lower()
