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



def test_xml_and_plist_configuration_inventory_omits_values(tmp_path: Path):
    xml = _scan(
        tmp_path, "web.config",
        '<configuration><appSettings><add key="ApiToken" value="do-not-leak"/>'
        '</appSettings><system.web><compilation debug="true"/></system.web></configuration>',
    )
    serialized = repr([item.to_dict() for item in xml])
    assert "configuration.appSettings.add@key" in serialized
    assert "do-not-leak" not in serialized


def test_extended_application_and_platform_configuration_names(tmp_path: Path):
    analyzer = ConfigurationAnalyzer()
    for filename in (
        "appsettings.Development.json", "application.properties",
        "bootstrap.yaml", "sshd_config", "service.service",
        "launch.plist", "default.nix", ".envrc",
    ):
        record = FileRecord(filename, 10, Path(filename).suffix.lower(), "Configuration")
        assert analyzer.supports(record), filename


def test_nginx_and_dockerfile_risky_directives_are_reported(tmp_path: Path):
    nginx = _scan(
        tmp_path, "nginx.conf",
        "server {\n  listen 443 ssl;\n  ssl_verify_client off;\n}\n",
    )
    docker = _scan(
        tmp_path, "Dockerfile",
        "FROM alpine:3\nUSER root\nENV DEBUG=true\n",
    )
    risk_titles = [item.title for item in nginx + docker if item.category == "security"]
    assert any("nginx_client_verification_disabled" in title for title in risk_titles)
    assert any("root_container_user" in title for title in risk_titles)


def test_yaml_and_nix_config_keys_are_inventoried(tmp_path: Path):
    yaml = _scan(
        tmp_path, "application.yml",
        "server:\n  port: 8080\n  ssl:\n    enabled: true\n",
    )
    nix = _scan(
        tmp_path, "default.nix",
        "{\n  services.nginx.enable = true;\n  environment.systemPackages = [];\n}\n",
    )
    assert yaml
    assert nix


def test_configuration_security_findings_include_redacted_code_and_impact(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "compose.yaml",
        "services:\n"
        "  app:\n"
        "    privileged: true\n"
        "    environment:\n"
        "      API_TOKEN: super-secret-value-should-not-leak\n",
    )
    risky = next(item for item in findings if item.category == "security")
    assert risky.code_evidence
    assert risky.code_evidence[0].line_number == 3
    assert "privileged: true" in risky.code_evidence[0].code
    assert "privileges" in risky.impact or "host" in risky.impact
    assert risky.recommendation
    assert "super-secret-value-should-not-leak" not in repr([x.to_dict() for x in findings])

def test_tls_verification_risk_requires_insecure_setting(tmp_path: Path):
    secure = _scan(
        tmp_path, "secure.yaml", "\n".join([
            "verify: true",
            "rejectUnauthorized: true",
            "insecure_skip_verify: false",
        ]),
    )
    assert not any("tls_verification_disabled" in item.title for item in secure)

    insecure = _scan(
        tmp_path, "insecure.yaml", "\n".join([
            "verify: false",
            "rejectUnauthorized: false",
            "insecure_skip_verify: true",
        ]),
    )
    tls_risks = [item for item in insecure if "tls_verification_disabled" in item.title]
    assert len(tls_risks) == 3
    assert all(item.impact and item.recommendation for item in tls_risks)


def test_oversized_configuration_is_unknown_without_content_read(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import configuration_analyzer

    path = tmp_path / "large.json"
    path.write_text('{"debug":true}', encoding="utf-8")
    monkeypatch.setattr(configuration_analyzer, "_MAX_CONFIG_FILE_BYTES", 4)
    record = FileRecord(path.name, 100, ".json", "Configuration")
    findings = ConfigurationAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "resource limit" in findings[0].title.lower()

def test_configuration_budget_detects_growth_after_inventory(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import configuration_analyzer

    path = tmp_path / "growing.yaml"
    path.write_text("\\n".join(["debug: true"] * 20), encoding="utf-8")
    monkeypatch.setattr(configuration_analyzer, "_MAX_CONFIG_FILE_BYTES", 8)
    record = FileRecord(path.name, 1, ".yaml", "Configuration")
    findings = ConfigurationAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_configuration_parser_exception_diagnostics_are_redacted(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import configuration_analyzer

    secret = "exception-secret-value-432"
    path = tmp_path / "invalid.json"
    path.write_text("{}", encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, ".json", "Configuration")

    def fail_with_sensitive_context(content, record):
        raise ValueError(f"parser context API_TOKEN={secret}")

    monkeypatch.setattr(configuration_analyzer, "_parse_config", fail_with_sensitive_context)
    findings = ConfigurationAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert secret not in repr([item.to_dict() for item in findings])
    assert "[REDACTED]" in findings[0].detail


def test_configuration_key_count_budget_is_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import configuration_analyzer

    monkeypatch.setattr(configuration_analyzer, "_MAX_CONFIG_KEYS", 2)
    findings = _scan(
        tmp_path,
        "settings.json",
        '{"alpha":1,"beta":2,"gamma":3}',
    )
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "inventory resource limit" in findings[0].title.lower()


def test_configuration_risk_evidence_is_bounded_per_rule(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import configuration_analyzer

    monkeypatch.setattr(configuration_analyzer, "_MAX_CONFIG_RISK_LINES", 10)
    content = "\\n".join(["debug: true"] * 250)
    findings = _scan(tmp_path, "application.yml", content)
    risks = [item for item in findings if item.category == "security"]
    assert len(risks) == 10
    assert [item.code_evidence[0].line_number for item in risks] == list(range(1, 11))
