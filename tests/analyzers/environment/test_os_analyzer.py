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
