from pathlib import Path

from project_discovery.analyzers.environment.operating_systems import OperatingSystemAnalyzer
from project_discovery.models import FileRecord


def test_target_os_markers_are_inferred_not_host_facts(tmp_path: Path):
    path = tmp_path / "pipeline.yml"
    path.write_text(
        "runs-on: [ubuntu-latest, windows-latest, macos-latest]\n"
        "container: alpine:3.20\n",
        encoding="utf-8",
    )
    record = FileRecord(".github/workflows/ci.yml", path.stat().st_size, ".yml", "YAML", file_type="text")
    findings = OperatingSystemAnalyzer().analyze(path, record)
    assert len(findings) == 1
    assert findings[0].confidence == "INFERRED"
    for os_name in ("Linux", "Windows", "macOS"):
        assert os_name in findings[0].detail
    assert "host OS" in findings[0].detail


def test_non_target_text_without_os_markers_is_ignored(tmp_path: Path):
    path = tmp_path / "simple.txt"
    path.write_text("generic project metadata\n", encoding="utf-8")
    record = FileRecord("simple.txt", path.stat().st_size, ".txt", "Text", file_type="text")
    assert OperatingSystemAnalyzer().analyze(path, record) == []


def test_os_indicators_are_counted_and_bounded(tmp_path, monkeypatch):
    # Regression: every matching line number was kept (memory about 5x the file) and there
    # was no byte budget.
    from pathlib import Path

    from project_discovery.analyzers.environment import operating_systems
    from project_discovery.analyzers.environment.operating_systems import OperatingSystemAnalyzer
    from project_discovery.models import FileRecord

    path = Path(tmp_path) / "notes.txt"
    path.write_text("runs on linux\n" * 50, encoding="utf-8")
    record = FileRecord("notes.txt", path.stat().st_size, ".txt", "Text", file_type="text")
    finding = OperatingSystemAnalyzer().analyze(path, record)[0]
    assert "Linux (50 lines)" in finding.detail and len(finding.evidence) == 20
    monkeypatch.setattr(operating_systems, "_MAX_OS_FILE_CHARS", 100)
    titles = [item.title for item in OperatingSystemAnalyzer().analyze(path, record)]
    assert titles == ["Target operating-system indicators: notes.txt", "Platform analysis resource limit: notes.txt"]
