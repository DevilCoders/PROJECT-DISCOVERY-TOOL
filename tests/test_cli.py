from pathlib import Path
import pytest
from project_discovery.cli import run_scan


def test_report_output_inside_target_is_rejected(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ValueError, match="outside"):
        run_scan(project, project / "reports", {"json"}, 1)


def test_default_report_output_is_sibling_of_target(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("def greet():\n    return 'hello'\n", encoding="utf-8")
    assert run_scan(project, None, {"json"}, 1) == 0
    report = tmp_path / "project-pdt-report" / "discovery-report.json"
    assert report.is_file()
    import json
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert "analyzer_registry" in payload["metrics"]
    assert "source_structure" in payload["metrics"]["active_analyzer_domains"]


def test_scan_writes_reports_without_touching_target(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    source.write_text("def greet():\n    return 'hello'\n", encoding="utf-8")
    before = source.read_bytes()
    output = tmp_path / "reports"
    assert run_scan(project, output, {"json", "markdown", "html"}, 1) == 0
    assert source.read_bytes() == before
    assert (output / "discovery-report.json").is_file()
    assert (output / "discovery-report.md").is_file()
    assert (output / "discovery-report.html").is_file()


def test_compare_cli_writes_independent_project_report(tmp_path: Path, monkeypatch):
    import json
    import sys
    from project_discovery.cli import main

    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    base = {
        "schema_version": "1.0",
        "root": "/project",
        "files": [],
        "findings": [],
        "metrics": {"languages": {}, "python_dependency_graph": {"modules": []}},
    }
    left.write_text(json.dumps({**base, "root": "/left"}), encoding="utf-8")
    right.write_text(json.dumps({**base, "root": "/right"}), encoding="utf-8")
    output = tmp_path / "comparison"
    monkeypatch.setattr(
        sys, "argv",
        ["pdt", "compare", str(left), str(right), "--output", str(output)],
    )
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 0
    assert (output / "project-comparison.json").is_file()


def test_catalog_list_cli_without_format_argument(tmp_path: Path, monkeypatch):
    import sys
    from project_discovery.cli import main

    monkeypatch.setattr(
        sys, "argv", ["pdt", "catalog-list", "--db", str(tmp_path / "catalog.sqlite3")]
    )
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 0


def test_large_file_content_skip_is_opt_in(tmp_path: Path):
    import json

    project = tmp_path / "project"
    project.mkdir()
    (project / "large.bin").write_bytes(b"x" * (1024 * 1024 + 1))
    default_output = tmp_path / "default-report"
    assert run_scan(project, default_output, {"json"}, 1) == 0
    default_payload = json.loads(
        (default_output / "discovery-report.json").read_text(encoding="utf-8")
    )
    assert default_payload["files"][0]["content_skipped_reason"] is None
    assert default_payload["metrics"]["content_skip_enabled"] is False

    skip_output = tmp_path / "skip-report"
    assert run_scan(
        project, skip_output, {"json"}, 1, skip_oversized=True
    ) == 0
    skip_payload = json.loads(
        (skip_output / "discovery-report.json").read_text(encoding="utf-8")
    )
    assert "Explicit --skip" in skip_payload["files"][0]["content_skipped_reason"]
    assert skip_payload["metrics"]["oversized_files"] == 1
    assert skip_payload["metrics"]["content_skip_enabled"] is True
