from pathlib import Path

from project_discovery.analyzers.build_analyzer import BuildManifestAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Build")
    analyzer = BuildManifestAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_makefile_targets_are_inventoried(tmp_path: Path):
    findings = _scan(tmp_path, "Makefile", ".PHONY: all test\nall: build\ntest: unit\n")
    assert "2 build targets/jobs" in findings[0].detail
    assert "all" in findings[0].evidence
    assert "test" in findings[0].evidence


def test_package_json_scripts_are_inventoried(tmp_path: Path):
    findings = _scan(
        tmp_path, "package.json",
        '{"name":"frontend","scripts":{"build":"vite build","test":"vitest"}}',
    )
    assert "2 build targets/jobs" in findings[0].detail
    assert "script: build" in findings[0].evidence


def test_dockerfile_instructions_are_inventoried(tmp_path: Path):
    findings = _scan(tmp_path, "Dockerfile", "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCMD [\"python\",\"app.py\"]\n")
    assert "4 build targets/jobs" in findings[0].detail
