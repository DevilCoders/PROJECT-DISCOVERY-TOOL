from pathlib import Path

from project_discovery.analyzers.api_type_analyzer import APITypeAnalyzer
from project_discovery.models import FileRecord


def test_multiple_api_styles_are_classified(tmp_path: Path):
    path = tmp_path / "service.ts"
    path.write_text(
        "app.get('/users', handler)\n"
        "const query = 'query Users { users { id } }'\n"
        "const socket = new WebSocket('wss://example.test')\n"
        "client.publish('events', payload)\n",
        encoding="utf-8",
    )
    record = FileRecord("src/service.ts", path.stat().st_size, ".ts", "TypeScript", file_type="text")
    findings = APITypeAnalyzer().analyze(path, record)
    assert len(findings) == 1
    for api_type in ("RESTful HTTP", "GraphQL", "WebSocket", "Event-driven API"):
        assert api_type in findings[0].detail


def test_api_classifier_ignores_non_api_source(tmp_path: Path):
    path = tmp_path / "math.py"
    path.write_text("def add(left, right):\n    return left + right\n", encoding="utf-8")
    record = FileRecord("math.py", path.stat().st_size, ".py", "Python", file_type="text")
    assert APITypeAnalyzer().analyze(path, record) == []

def test_api_type_analyzer_reports_oversized_and_growing_sources_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.api_type_analyzer as module

    path = tmp_path / "large.ts"
    path.write_text("app.get('/users', handler)\n" * 10, encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_API_TYPE_FILE_BYTES", 24)
    record = FileRecord(path.name, 1, ".ts", "TypeScript", file_type="text")
    findings = APITypeAnalyzer().analyze(path, record)
    assert findings
    assert findings[-1].confidence == "UNKNOWN"
    assert "budget reached" in findings[-1].title.lower()


def test_api_type_analyzer_caps_retained_evidence_lines(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.api_type_analyzer as module

    path = tmp_path / "routes.ts"
    path.write_text("".join("app.get('/route%d', handler)\n" % n for n in range(10)), encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_API_TYPE_EVIDENCE_PER_STYLE", 2)
    record = FileRecord(path.name, path.stat().st_size, ".ts", "TypeScript", file_type="text")
    findings = APITypeAnalyzer().analyze(path, record)
    assert findings
    assert len(findings[0].evidence) <= 2
    assert "10 line(s)" in findings[0].detail

def test_api_type_analyzer_reports_oversized_file_metadata_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.api_type_analyzer as module

    path = tmp_path / "large.ts"
    path.write_text("app.get('/users', handler)\n", encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_API_TYPE_FILE_BYTES", 8)
    record = FileRecord(path.name, 100, ".ts", "TypeScript", file_type="text")
    findings = APITypeAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "resource limit" in findings[0].title.lower()
