from pathlib import Path

from project_discovery.analyzers.test_analyzer import TestDiscoveryAnalyzer
from project_discovery.models import FileRecord


def test_python_test_file_declarations_are_counted(tmp_path: Path):
    path = tmp_path / "test_service.py"
    path.write_text(
        "def test_create():\n    pass\n\ndef test_delete():\n    pass\n",
        encoding="utf-8",
    )
    record = FileRecord(path.name, path.stat().st_size, ".py", "Python")
    findings = TestDiscoveryAnalyzer().analyze(path, record)
    assert "2 test declarations" in findings[0].detail
    assert findings[0].confidence == "CONFIRMED"


def test_go_test_file_is_discovered(tmp_path: Path):
    path = tmp_path / "service_test.go"
    path.write_text("func TestCreate(t *testing.T) {}\n", encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, ".go", "Go")
    analyzer = TestDiscoveryAnalyzer()
    assert analyzer.supports(record)
    findings = analyzer.analyze(path, record)
    assert "TestCreate" in findings[0].detail


def test_unknown_test_language_is_inferred(tmp_path: Path):
    path = tmp_path / "widget_test.nim"
    path.write_text("suite \"widgets\":\n", encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, ".nim", "Nim")
    findings = TestDiscoveryAnalyzer().analyze(path, record)
    assert findings[0].confidence == "INFERRED"
