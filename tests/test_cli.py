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
    assert "native_backend" in payload["metrics"]
    assert "vcs_provider_signal_count" in payload["metrics"]


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



def test_scan_with_local_vulnerability_database_reports_advisory_match(tmp_path: Path):
    import json
    from project_discovery.vulnerability_db import VulnerabilityDatabase

    project = tmp_path / "vulnerable-project"
    project.mkdir()
    (project / "package-lock.json").write_text(
        json.dumps({
            "packages": {
                "": {"name": "fixture", "version": "1.0.0"},
                "node_modules/demo-lib": {"version": "1.9.0"},
            }
        }),
        encoding="utf-8",
    )
    feed = tmp_path / "osv-feed"
    feed.mkdir()
    (feed / "advisory.json").write_text(json.dumps({
        "id": "GHSA-cli-test-1234",
        "aliases": ["CVE-2025-77777"],
        "summary": "Fixture vulnerability for CLI integration",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "npm", "name": "demo-lib"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}],
            }],
        }],
    }), encoding="utf-8")
    database_path = tmp_path / "local-advisories.sqlite3"
    with VulnerabilityDatabase(database_path) as database:
        database.import_osv(feed)

    output = tmp_path / "report"
    assert run_scan(
        project, output, {"json", "markdown", "html"}, 1,
        vulnerability_db=database_path,
    ) == 0
    payload = json.loads(
        (output / "discovery-report.json").read_text(encoding="utf-8")
    )
    matches = [item for item in payload["findings"] if item["category"] == "vulnerabilities"]
    assert len(matches) == 1
    assert "GHSA-cli-test-1234" in matches[0]["title"]
    assert payload["metrics"]["vulnerability_intelligence"]["enabled"] is True
    html = (output / "discovery-report.html").read_text(encoding="utf-8")
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "GHSA-cli-test-1234" in html
    assert "GHSA-cli-test-1234" in markdown


def test_vuln_db_cli_import_and_status_are_local(tmp_path: Path, monkeypatch):
    import json
    import sys
    from project_discovery.cli import main

    feed = tmp_path / "osv"
    feed.mkdir()
    (feed / "advisory.json").write_text(json.dumps({
        "id": "GHSA-status-1234",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "pkg"},
            "versions": ["1.0.0"],
        }],
    }), encoding="utf-8")
    db = tmp_path / "advisories.sqlite3"
    monkeypatch.setattr(
        sys, "argv", ["pdt", "vuln-db", "import", str(feed), "--db", str(db)]
    )
    with pytest.raises(SystemExit) as imported:
        main()
    assert imported.value.code == 0

    monkeypatch.setattr(
        sys, "argv", ["pdt", "vuln-db", "status", "--db", str(db)]
    )
    with pytest.raises(SystemExit) as status:
        main()
    assert status.value.code == 0


def test_scan_uses_bounded_worker_count_and_reports_it(tmp_path: Path):
    import json

    project = tmp_path / "concurrent-project"
    project.mkdir()
    for index in range(12):
        (project / f"module_{index}.py").write_text(
            f"def value_{index}(): return {index}\n", encoding="utf-8"
        )
    output = tmp_path / "concurrent-report"
    assert run_scan(project, output, {"json"}, 1, jobs=2) == 0
    payload = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    execution = payload["metrics"]["execution"]
    assert execution["mode"] == "bounded-thread-pool"
    assert execution["worker_count"] == 2
    assert execution["max_pending_tasks"] == 4
    assert execution["ordering"] == "deterministic-submission-order"


def test_scan_rejects_unbounded_or_negative_job_counts(tmp_path: Path):
    project = tmp_path / "bad-jobs"
    project.mkdir()
    with pytest.raises(ValueError, match="--jobs"):
        run_scan(project, tmp_path / "bad-jobs-report", {"json"}, 1, jobs=65)
    with pytest.raises(ValueError, match="--jobs"):
        run_scan(project, tmp_path / "bad-jobs-report-2", {"json"}, 1, jobs=-1)
