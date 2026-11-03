from pathlib import Path

from project_discovery.analyzers.security_analyzer import SecretPatternAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Source")
    analyzer = SecretPatternAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_detects_secret_patterns_and_redacts_values(tmp_path: Path):
    token = "ghp_" + "A" * 36
    findings = _scan(
        tmp_path,
        "settings.py",
        f'API_KEY = "{token}"\n'
        'password = "correct-horse-battery-staple"\n'
        'PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n',
    )
    assert len(findings) >= 3
    serialized = repr([finding.to_dict() for finding in findings])
    assert token not in serialized
    assert "correct-horse-battery-staple" not in serialized
    assert all(finding.confidence == "INFERRED" for finding in findings)
    assert all("redacted" in finding.detail.lower() for finding in findings)


def test_ignores_placeholders_and_environment_references(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "config.py",
        'API_KEY = "YOUR_API_KEY"\n'
        'password = os.getenv("APP_PASSWORD")\n'
        'secret = "$" + "{SECRET_VALUE}"\n',
    )
    assert findings == []


def test_scans_env_files_without_extension(tmp_path: Path):
    findings = _scan(tmp_path, ".env.local", "SERVICE_TOKEN=real-token-value-123\n")
    assert findings
    assert findings[0].evidence == [".env.local:1"]


def test_oversized_files_are_not_supported():
    record = FileRecord("settings.py", 100, ".py", "Python", error="oversized")
    assert SecretPatternAnalyzer().supports(record) is False
