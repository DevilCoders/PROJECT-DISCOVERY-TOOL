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
