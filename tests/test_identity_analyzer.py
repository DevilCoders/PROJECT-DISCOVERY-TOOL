from pathlib import Path

from project_discovery.analyzers.identity_analyzer import IdentityIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix.lower(), "Source")
    analyzer = IdentityIntelligenceAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_python_authentication_framework_and_access_markers(tmp_path: Path):
    findings = _scan(
        tmp_path, "auth.py",
        "from fastapi.security import OAuth2PasswordBearer\n"
        "from passlib.context import CryptContext\n"
        "@login_required\ndef profile():\n    pass\n"
        "token = create_access_token(data)\n",
    )
    assert any("Identity framework references" in item.title for item in findings)
    assert any(item.category == "authorization" for item in findings)
    assert any(item.category == "authentication" for item in findings)


def test_java_and_typescript_identity_markers(tmp_path: Path):
    java = _scan(
        tmp_path, "SecurityConfig.java",
        "import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;\n"
        "@PreAuthorize(\"hasRole('ADMIN')\")\n",
    )
    assert any("Spring Security" in item.detail for item in java)
    assert any(item.category == "authorization" for item in java)

    ts = _scan(
        tmp_path, "auth.ts",
        "import { AuthGuard } from '@nestjs/passport';\n"
        "passport.authenticate('jwt');\n",
    )
    assert any(item.category == "authentication" for item in ts)


def test_unrelated_source_has_no_identity_findings(tmp_path: Path):
    assert _scan(tmp_path, "math.py", "def add(a, b):\n    return a + b\n") == []


def test_non_source_files_are_not_supported():
    record = FileRecord("settings.yaml", 10, ".yaml", "YAML")
    assert IdentityIntelligenceAnalyzer().supports(record) is False
