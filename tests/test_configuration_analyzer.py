from pathlib import Path

from project_discovery.analyzers.configuration_analyzer import ConfigurationAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Configuration")
    analyzer = ConfigurationAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_json_inventory_does_not_expose_values(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "app-config.json",
        '{"service":{"port":8080,"api_token":"do-not-leak-this-value"}}',
    )
    assert len(findings) == 1
    assert "3 configuration keys" in findings[0].detail
    assert "do-not-leak-this-value" not in repr(findings[0].to_dict())


def test_detects_risky_yaml_settings_with_line_evidence(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "deployment.yaml",
        "debug: true\n"
        "securityContext:\n"
        "  privileged: true\n"
        "  runAsNonRoot: false\n"
        "cors:\n"
        "  allow_origins: ['*']\n",
    )
    risks = [item for item in findings if item.category == "security"]
    assert len(risks) >= 3
    assert all(item.confidence == "INFERRED" for item in risks)
    assert all(item.evidence[0].startswith("deployment.yaml:") for item in risks)


def test_env_inventory_reports_names_not_values(tmp_path: Path):
    findings = _scan(
        tmp_path,
        ".env",
        "DATABASE_URL=postgres://user:very-secret-password@localhost/db\n"
        "APP_MODE=production\n",
    )
    assert findings
    assert "DATABASE_URL" in findings[0].detail or "2 configuration keys" in findings[0].detail
    assert "very-secret-password" not in repr([item.to_dict() for item in findings])


def test_malformed_json_is_unknown(tmp_path: Path):
    findings = _scan(tmp_path, "broken.json", "{")
    assert findings[0].confidence == "UNKNOWN"
