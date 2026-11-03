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
