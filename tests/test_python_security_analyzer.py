from pathlib import Path

from project_discovery.analyzers.python_security_analyzer import PythonSecurityAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "service.py"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, ".py", "Python")
    return PythonSecurityAnalyzer().analyze(path, record)


def test_python_security_detects_multiple_dangerous_apis(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "import os, subprocess, pickle, yaml, ssl, hashlib\n"
        "eval(user_input)\n"
        "subprocess.run(user_input, shell=True)\n"
        "pickle.loads(payload)\n"
        "yaml.load(payload)\n"
        "ssl._create_unverified_context()\n"
        "hashlib.md5(data)\n",
    )
    rules = {item.title for item in findings}
    assert any("dynamic_code_execution" in item for item in rules)
    assert any("subprocess_shell_true" in item for item in rules)
    assert any("unsafe_pickle_deserialization" in item for item in rules)
    assert any("unsafe_yaml_load" in item for item in rules)
    assert any(item.severity == "CRITICAL" for item in findings)


def test_python_security_detects_sql_interpolation_and_tls_disabling(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "cursor.execute(f\"SELECT * FROM users WHERE name={name}\")\n"
        "requests.get(url, verify=False)\n",
    )
    assert any("possible_sql_injection" in item.title for item in findings)
    assert any("tls_verification_disabled" in item.title for item in findings)
    assert all(item.confidence == "INFERRED" for item in findings)


def test_python_security_never_executes_target_code(tmp_path: Path):
    marker = tmp_path / "executed.txt"
    findings = _scan(
        tmp_path,
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n",
    )
    assert findings == []
    assert not marker.exists()



def test_ast_security_budget_reports_unknown_not_clean_result(tmp_path: Path):
    path = tmp_path / "oversized.py"
    path.write_text("pass\n", encoding="utf-8")
    record = FileRecord(path.name, 20 * 1024 * 1024, ".py", "Python")
    findings = PythonSecurityAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "AST resource limit" in findings[0].title

def test_python_ast_findings_include_redacted_source_and_impact(tmp_path: Path):
    secret = "ast-evidence-secret-876"
    findings = _scan(
        tmp_path,
        "eval(user_input)  # SERVICE_TOKEN=ast-evidence-secret-876\\n",
    )
    assert findings
    finding = findings[0]
    assert finding.code_evidence
    assert secret not in repr(finding.to_dict())
    assert "[REDACTED]" in finding.code_evidence[0].code
    assert finding.impact
    assert finding.recommendation


def test_python_security_finding_includes_redacted_line_impact_and_fix(tmp_path: Path):
    source = (
        'password = "should-not-appear"\n'
        'eval(user_input)  # email = "developer@example.com"\n'
    )
    findings = _scan(tmp_path, source)
    finding = next(item for item in findings if "dynamic_code_execution" in item.title)
    assert finding.evidence == ["service.py:2"]
    assert finding.code_evidence[0].line_number == 2
    assert "eval(user_input)" in finding.code_evidence[0].code
    assert "developer@example.com" not in finding.code_evidence[0].code
    assert "should-not-appear" not in repr(finding.to_dict())
    assert "arbitrary Python code" in finding.impact
    assert finding.recommendation
