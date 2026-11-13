from pathlib import Path

import pytest

from project_discovery.cli import _verified_regular_file_stat, run_scan


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
    assert payload["files"][0]["analyzed"] is True
    assert "vcs_provider_signal_count" in payload["metrics"]
    persistence = payload["metrics"]["inventory_persistence"]
    assert persistence["enabled"] is True
    assert persistence["integrity_check"] == "ok"
    assert persistence["status"] == "complete"
    assert persistence["record_count"] >= 2
    finding_persistence = payload["metrics"]["finding_persistence"]
    assert finding_persistence["backend"] == "sqlite"
    assert finding_persistence["record_count"] == len(payload["findings"])
    assert finding_persistence["deduplicate_identical"] is True
    assert finding_persistence["public_schema_unchanged"] is True
    database_path = tmp_path / "project-pdt-report" / ".pdt-cache" / "inventory.sqlite3"
    assert database_path.is_file()
    from project_discovery.inventory.store import InventoryStore
    with InventoryStore(database_path) as store:
        assert store.count("finding") == len(payload["findings"])


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
    from project_discovery.projects.catalog import ProjectCatalog

    # catalog-list never creates a catalog (a missing one is an error), so make one.
    ProjectCatalog(tmp_path / "catalog.sqlite3").close()
    monkeypatch.setattr(
        sys, "argv", ["pdt", "catalog-list", "--db", str(tmp_path / "catalog.sqlite3")]
    )
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 0


def test_commands_survive_a_console_encoding_that_cannot_show_the_path(tmp_path: Path, monkeypatch):
    # Regression: on Windows a redirected stdout uses the ANSI code page, so catalog-add
    # registered the project and then exited 2 with UnicodeEncodeError on a non-ANSI path.
    import io
    import json
    import sys

    from project_discovery.cli import main

    root = tmp_path / "проект"
    root.mkdir()
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "schema_version": "1.0", "root": str(root), "finished_at": "2026-11-12T10:00:00+00:00",
        "files": [], "findings": [], "metrics": {"languages": {}},
    }), encoding="utf-8")
    buffer = io.BytesIO()
    stdout = io.TextIOWrapper(buffer, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stdout)
    database = str(tmp_path / "catalog.sqlite3")
    for argv in (["catalog-add", str(report), "--db", database], ["catalog-list", "--db", database]):
        monkeypatch.setattr(sys, "argv", ["pdt", *argv])
        with pytest.raises(SystemExit) as result:
            main()
        assert result.value.code == 0, argv
    stdout.flush()
    # The path is printed escaped (backslashreplace), not dropped and not fatal.
    assert r"\u043f" in buffer.getvalue().decode("cp1252")


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

    from project_discovery.vulnerabilities.database import VulnerabilityDatabase

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


def test_cli_prints_redacted_source_impact_and_remediation():
    from io import StringIO

    from rich.console import Console

    from project_discovery.cli import _print_security_findings
    from project_discovery.models import CodeEvidence, Finding

    output = StringIO()
    console = Console(
        file=output, force_terminal=True, color_system="truecolor", width=160
    )
    finding = Finding(
        "security",
        "Shell command execution API: src/service.py",
        "Process execution receives untrusted input.",
        confidence="INFERRED",
        analyzer="secure-code-patterns",
        severity="HIGH",
        code_evidence=[
            CodeEvidence(41, 'os.system(command)  # password = "do-not-display-this"')
        ],
        impact="An attacker may execute operating-system commands with application privileges.",
        recommendation="Use an argument array and avoid shell interpretation.",
    )
    _print_security_findings(console, [finding])
    rendered = output.getvalue()
    assert "Shell command execution API" in rendered
    assert "L   41" in rendered
    assert "os.system(command)" in rendered
    assert "do-not-display-this" not in rendered
    assert "Attacker impact:" in rendered
    assert "Remediation:" in rendered
    assert "\x1b[" in rendered



def test_analysis_guard_rejects_symlink_substitution(tmp_path: Path):
    target = tmp_path / "outside.txt"
    target.write_text("must not be analyzed", encoding="utf-8")
    link = tmp_path / "project-file.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(OSError, match="non-regular or symlink"):
        _verified_regular_file_stat(link)


def test_analysis_guard_detects_file_identity_change(tmp_path: Path):
    original = tmp_path / "original.py"
    replacement = tmp_path / "replacement.py"
    original.write_text("print('original')", encoding="utf-8")
    replacement.write_text("print('replacement with different size')", encoding="utf-8")
    expected = original.lstat()
    with pytest.raises(OSError, match="identity changed"):
        _verified_regular_file_stat(replacement, expected)


def test_analysis_guard_accepts_unchanged_regular_file(tmp_path: Path):
    source = tmp_path / "stable.py"
    source.write_text("print('stable')", encoding="utf-8")
    expected = source.lstat()
    current = _verified_regular_file_stat(source, expected)
    assert current.st_ino == expected.st_ino


def _sample_project(root: Path) -> Path:
    root.mkdir()
    (root / "app.py").write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (root / "settings.env").write_text("API_TOKEN=ghp_" + "A" * 36 + "\n", encoding="utf-8")
    (root / "shared.txt").write_text("byte-identical content\n", encoding="utf-8")
    return root


def _json_report(output: Path) -> dict:
    import json

    return json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))


def test_scan_of_a_directory_that_is_a_python_package_completes(tmp_path: Path):
    # Regression: a scan root holding __init__.py made the package walk of the import
    # graph and the code index loop forever, so no report was ever written.
    import threading

    project = tmp_path / "pkg"
    (project / "sub").mkdir(parents=True)
    (project / "__init__.py").write_text("from . import core\n", encoding="utf-8")
    (project / "core.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (project / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (project / "sub" / "mod.py").write_text("import core\ncore.run()\n", encoding="utf-8")
    outcome = {}
    worker = threading.Thread(
        target=lambda: outcome.update(code=run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True)),
        daemon=True,
    )
    worker.start()
    worker.join(120)
    assert not worker.is_alive(), "scan of a package root did not finish"
    assert outcome["code"] == 0
    assert (tmp_path / "out" / "discovery-report.json").is_file()


def test_end_to_end_scan_runs_per_file_analyzers_and_fingerprints(tmp_path: Path):
    # Regression: the analysis guard rejected every file, so no per-file analyzer ever ran.
    project = _sample_project(tmp_path / "project")
    assert run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True) == 0
    report = _json_report(tmp_path / "out")
    analyzers = {finding["analyzer"] for finding in report["findings"]}
    assert {"python-ast", "secure-code-patterns", "secret-patterns"} <= analyzers
    assert report["errors"] == []
    assert all(len(item["sha256"] or "") == 64 for item in report["files"])
    assert all(item["analyzed"] for item in report["files"])


def test_real_scan_reports_can_be_compared(tmp_path: Path):
    from project_discovery.projects.comparison import compare_many_reports, load_report

    for name in ("alpha", "beta"):
        project = _sample_project(tmp_path / name)
        assert run_scan(project, tmp_path / f"{name}-out", {"json"}, 1, quiet=True) == 0
    comparison = compare_many_reports([
        load_report(tmp_path / f"{name}-out" / "discovery-report.json") for name in ("alpha", "beta")
    ])
    duplicated = {
        path for item in comparison["duplicate_file_content"]
        for paths in item["projects"].values() for path in paths
    }
    assert {"app.py", "shared.txt", "settings.env"} <= duplicated


class _ExplodingAnalyzer:
    name = "exploding-test-analyzer"
    version = "1.0"
    api_version = 1
    domains = ("tests",)
    languages = ("Python",)
    concurrent_safe = True

    def supports(self, record):
        return record.path == "app.py"

    def analyze(self, path, record):
        raise RuntimeError("synthetic analyzer failure password=hunter2hunter2")


def _with_exploding_analyzer(monkeypatch):
    import project_discovery.cli as cli
    from project_discovery.analyzers import load_analyzers

    def patched(**options):
        result = load_analyzers(**options)
        result.analyzers.append(_ExplodingAnalyzer())
        return result

    monkeypatch.setattr(cli, "load_analyzers", patched)


def test_analyzer_failure_is_visible_and_does_not_mark_the_file_unreadable(tmp_path: Path, monkeypatch):
    _with_exploding_analyzer(monkeypatch)
    project = _sample_project(tmp_path / "project")
    assert run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True) == 0
    report = _json_report(tmp_path / "out")
    failure = next(item for item in report["findings"] if item["title"].startswith("Analyzer failed:"))
    assert failure["confidence"] == "UNKNOWN"
    assert "hunter2hunter2" not in str(report)
    app = next(item for item in report["files"] if item["path"] == "app.py")
    assert app["error"] is None and app["sha256"]
    assert any("exploding-test-analyzer" in error for error in report["errors"])


def test_fail_on_and_strict_exit_codes(tmp_path: Path, monkeypatch):
    from project_discovery.cli import EXIT_FINDINGS, EXIT_INCOMPLETE

    project = _sample_project(tmp_path / "project")
    assert run_scan(project, tmp_path / "a", {"json"}, 1, quiet=True, fail_on="HIGH") == EXIT_FINDINGS
    assert run_scan(project, tmp_path / "b", {"json"}, 1, quiet=True, fail_on="CRITICAL") == 0
    assert run_scan(project, tmp_path / "c", {"json"}, 1, quiet=True, strict=True) == 0
    _with_exploding_analyzer(monkeypatch)
    assert run_scan(project, tmp_path / "d", {"json"}, 1, quiet=True, strict=True) == EXIT_INCOMPLETE
    with pytest.raises(ValueError, match="--fail-on"):
        run_scan(project, tmp_path / "e", {"json"}, 1, quiet=True, fail_on="SEVERE")


def test_cli_exit_codes_for_interrupt_and_usage_errors(tmp_path: Path, monkeypatch):
    import sys

    from project_discovery import cli

    def interrupted(*_args, **_kwargs):
        raise KeyboardInterrupt  # Ctrl-C during a scan

    monkeypatch.setattr(cli, "run_scan", interrupted)
    monkeypatch.setattr(sys, "argv", ["pdt", "scan", str(tmp_path), "--output", str(tmp_path / "out")])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == cli.EXIT_INTERRUPTED == 130

    def failing(*_args, **_kwargs):
        raise ValueError("bad option")

    monkeypatch.setattr(cli, "run_scan", failing)
    with pytest.raises(SystemExit) as failed:
        cli.main()
    assert failed.value.code == cli.EXIT_USAGE == 2


def test_missing_vulnerability_database_is_rejected_before_inventory(tmp_path: Path, monkeypatch):
    import project_discovery.cli as cli

    def forbidden(*_args, **_kwargs):
        raise AssertionError("inventory must not start with an invalid --vuln-db")

    monkeypatch.setattr(cli, "discover_inventory", forbidden)
    project = _sample_project(tmp_path / "project")
    with pytest.raises(FileNotFoundError):
        run_scan(project, tmp_path / "out", {"json"}, 1, vulnerability_db=tmp_path / "missing.sqlite3")


def test_security_summary_names_the_file_location(tmp_path: Path, capsys):
    project = _sample_project(tmp_path / "project")
    assert run_scan(project, tmp_path / "out", {"json"}, 1, no_color=True) == 0
    output = capsys.readouterr().err
    assert "at settings.env:1" in output
    assert "\x1b[" not in output


def test_escape_sequences_in_scanned_content_never_reach_the_terminal_or_reports(tmp_path: Path, capsys):
    # Regression: redacted excerpts, titles and evidence kept ESC, so a scanned line could
    # retitle the operator's terminal (OSC 0), clear it (CSI 2J) or forge links (OSC 8),
    # in the console summary and in discovery-report.md alike.
    import sys

    project = tmp_path / "project"
    project.mkdir()
    payload = "\x1b]0;owned\x07\x1b[2J\x1b]8;;https://evil.example\x07click\x1b]8;;\x07\x08\r"
    (project / "app.py").write_bytes(f"import os\nos.system('ls')  # {payload}\n".encode("utf-8"))
    if sys.platform != "win32":
        (project / f"name{chr(27)}[31m.py").write_bytes(b"import os\nos.system('id')\n")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 1, no_color=True) == 0
    console = capsys.readouterr()
    for stream in (console.out, console.err):
        assert "\x1b" not in stream and "\x07" not in stream
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "\x1b" not in markdown and "\x07" not in markdown and "\x08" not in markdown
    report = _json_report(output)
    for finding in report["findings"]:
        texts = [finding["title"], finding["detail"], *finding["evidence"]]
        texts += [item["code"] for item in finding["code_evidence"]]
        assert not any("\x1b" in text or "\x07" in text for text in texts), finding["title"]


def test_strict_counts_inventory_errors_and_names_the_entry(tmp_path: Path, monkeypatch):
    # Regression: an entry whose metadata failed during the walk was counted only in the
    # inventory metrics, so --strict exited 0 and every report said "no errors".
    from project_discovery.inventory import scanner

    project = tmp_path / "project"
    project.mkdir()
    entries = [("broken.", "entry_error", 0, None, None, False, "", "OSError: cannot stat", 1, None, None, None)]
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: iter(entries))
    assert run_scan(project, tmp_path / "out", {"json", "markdown"}, 1, quiet=True, strict=True) == 3
    report = _json_report(tmp_path / "out")
    assert any(item.startswith("broken.: inventory error: OSError") for item in report["errors"])
    assert "broken.: inventory error" in (tmp_path / "out" / "discovery-report.md").read_text(encoding="utf-8")


def test_strict_fails_on_unknown_coverage_findings(tmp_path: Path):
    # Regression: --strict, documented as the completeness gate, ignored UNKNOWN findings,
    # so a scan whose only lockfile could not be parsed passed it.
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text("{ not json", encoding="utf-8")
    assert run_scan(project, tmp_path / "plain", {"json"}, 1, quiet=True) == 0
    assert run_scan(project, tmp_path / "strict", {"json"}, 1, quiet=True, strict=True) == 3
    report = _json_report(tmp_path / "strict")
    assert any(item["confidence"] == "UNKNOWN" and item["severity"] != "INFO" for item in report["findings"])


def _finding_keys(report: dict) -> set[tuple]:
    return {(item["analyzer"], item["title"], tuple(item["evidence"])) for item in report["findings"]}


def test_process_and_thread_executors_produce_identical_results(tmp_path: Path):
    project = _sample_project(tmp_path / "project")
    (project / "pkg").mkdir()
    for index in range(12):
        (project / "pkg" / f"mod{index}.py").write_text(
            f"import os\nfrom pkg import mod{(index + 1) % 12}\nos.system('echo {index}')\n",
            encoding="utf-8",
        )
    (project / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    reports = {}
    for mode in ("thread", "process"):
        assert run_scan(project, tmp_path / mode, {"json"}, 1, quiet=True, executor=mode, jobs=2) == 0
        reports[mode] = _json_report(tmp_path / mode)
        assert reports[mode]["metrics"]["execution"]["executor"] == mode
    assert _finding_keys(reports["thread"]) == _finding_keys(reports["process"])
    assert reports["thread"]["errors"] == reports["process"]["errors"] == []
    graph = reports["process"]["metrics"]["python_dependency_graph"]["summary"]
    # "from pkg import modN" links each module to both pkg and pkg.modN.
    assert graph["edge_count"] == 24 and graph["cycle_count"] == 1


def test_inventory_only_scan_reads_no_contents(tmp_path: Path, monkeypatch):
    import project_discovery.engine.executor as engine

    def forbidden(*_args, **_kwargs):
        raise AssertionError("inventory-only scans must not analyze file contents")

    monkeypatch.setattr(engine, "analyze_file", forbidden)
    # Regression: the inventory still opened every file for a 512-byte signature probe.
    import project_discovery.inventory.scanner as scanner

    def no_sample(*_args, **_kwargs):
        raise AssertionError("inventory-only scans must not open files")

    monkeypatch.setattr(scanner, "_read_verified_sample", no_sample)
    project = _sample_project(tmp_path / "project")
    assert run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, inventory_only=True) == 0
    report = _json_report(tmp_path / "out")
    assert len(report["files"]) == 3
    assert all(item["sha256"] is None and not item["analyzed"] for item in report["files"])
    # Only path-based correlation may contribute findings; no content analyzer runs.
    assert {item["analyzer"] for item in report["findings"]} <= {"architecture-layout"}
    assert report["metrics"]["execution"]["analysis_mode"] == "inventory-only"


def test_inventory_only_reports_say_contents_were_not_analyzed(tmp_path: Path):
    # Regression: Markdown and HTML never said so, and with --vuln-db a local database
    # that never ran read as an active, clean 0-match result.
    from project_discovery.vulnerabilities.database import VulnerabilityDatabase

    database = tmp_path / "advisories.sqlite3"
    with VulnerabilityDatabase(database):
        pass
    project = _sample_project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 1, quiet=True, inventory_only=True,
                    vulnerability_db=database) == 0
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Analysis: inventory only; no file contents were read" in markdown
    assert "Skipped: --inventory-only reads no lockfile contents" in markdown
    assert _json_report(output)["metrics"]["vulnerability_intelligence"]["coverage"] == "skipped"
    html = (output / "discovery-report.html").read_text(encoding="utf-8")
    assert 'id="inventory-badge"' in html and "LOCAL DATABASE SKIPPED" in html


def test_resume_skips_completed_files_and_keeps_stored_findings(tmp_path: Path, capsys):
    from project_discovery.inventory.store import InventoryStore, StoredFileRecords

    project = _sample_project(tmp_path / "project")
    output = tmp_path / "out"
    # Not quiet: --quiet deliberately suppresses this warning as well.
    assert run_scan(project, output, {"json"}, 1, no_color=True, resume=True) == 0
    # Rich wraps console text to the terminal width.
    assert "starting a fresh scan" in " ".join(capsys.readouterr().err.split())
    first = _json_report(output)
    assert first["metrics"]["execution"]["resumed"] is False
    # Simulate an interruption after every file except app.py had completed.
    database = output / ".pdt-cache" / "inventory.sqlite3"
    records = StoredFileRecords(database)
    pending = next(record for record in records if record.path == "app.py")
    pending.sha256 = None
    records.update_records([pending])
    assert run_scan(project, output, {"json"}, 1, quiet=True, resume=True) == 0
    resumed = _json_report(output)
    execution = resumed["metrics"]["execution"]
    assert execution["resumed"] is True and execution["resumed_files_skipped"] == 2
    assert _finding_keys(resumed) == _finding_keys(first)
    assert all(item["sha256"] for item in resumed["files"])
    with InventoryStore(database) as store:
        assert store.get_metadata("root") == str(project.resolve())


class _InterruptingAnalyzer:
    name = "interrupting-test-analyzer"
    version = "1.0"
    api_version = 1
    domains = ("tests",)
    languages = ("Text",)
    concurrent_safe = True

    def supports(self, record):
        return record.path == "m6.env"

    def analyze(self, path, record):
        raise KeyboardInterrupt  # Ctrl-C arriving while this file is analyzed


def _secret_files(root: Path, count: int = 9) -> Path:
    root.mkdir()
    for index in range(count):
        (root / f"m{index}.env").write_text(f"API_TOKEN=ghp_{index}" + "A" * 35 + "\n", encoding="utf-8")
    return root


def test_interrupted_scan_resumes_without_losing_findings(tmp_path: Path, monkeypatch):
    import project_discovery.cli as cli
    from project_discovery.analyzers import load_analyzers

    project = _secret_files(tmp_path / "project")
    scan = {"executor": "thread", "jobs": 1, "quiet": True}
    assert run_scan(project, tmp_path / "reference", {"json"}, 1, **scan) == 0
    reference = _json_report(tmp_path / "reference")

    def interrupting(**options):
        result = load_analyzers(**options)
        result.analyzers.append(_InterruptingAnalyzer())
        return result

    # One file per batch and a record commit every two files, so the interrupt at m6
    # lands after several commits.
    monkeypatch.setattr(cli, "load_analyzers", interrupting)
    monkeypatch.setattr(cli, "BATCH_MAX_FILES", 1)
    monkeypatch.setattr(cli, "RECORD_UPDATE_BATCH", 2)
    output = tmp_path / "out"
    with pytest.raises(KeyboardInterrupt):
        run_scan(project, output, {"json"}, 1, **scan)

    monkeypatch.setattr(cli, "load_analyzers", load_analyzers)
    assert run_scan(project, output, {"json"}, 1, resume=True, **scan) == 0
    resumed = _json_report(output)
    assert resumed["metrics"]["execution"]["resumed_files_skipped"] == 6  # m0-m5
    assert _finding_keys(resumed) == _finding_keys(reference)
    assert len(resumed["findings"]) == len(reference["findings"])


def test_file_records_are_committed_only_after_their_findings(tmp_path: Path, monkeypatch):
    # A record with a sha256 is skipped by --resume, so its findings must already be
    # durable when it is committed; otherwise a crash between the two loses them.
    import project_discovery.cli as cli
    from project_discovery.inventory.store import InventoryStore, StoredFileRecords

    finding_stores = set()
    unflushed_at_commit = []
    append_finding = InventoryStore.append_finding
    update_records = StoredFileRecords.update_records

    def tracking_append_finding(self, finding):
        finding_stores.add(self)
        append_finding(self, finding)

    def checked_update_records(self, records):
        unflushed_at_commit.append(
            sum(len(store._pending) for store in finding_stores if not store._closed)
        )
        return update_records(self, records)

    monkeypatch.setattr(InventoryStore, "append_finding", tracking_append_finding)
    monkeypatch.setattr(StoredFileRecords, "update_records", checked_update_records)
    monkeypatch.setattr(cli, "RECORD_UPDATE_BATCH", 2)
    project = _secret_files(tmp_path / "project")
    assert run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, executor="thread", jobs=1) == 0
    assert unflushed_at_commit and set(unflushed_at_commit) == {0}



def test_capabilities_report_includes_remote_vcs_client_status(monkeypatch):
    from types import SimpleNamespace

    import project_discovery.cli as cli

    loaded = SimpleNamespace(analyzers=[], diagnostics=[], plugins=[], close=lambda: None)
    monkeypatch.setattr(cli, "load_analyzers", lambda: loaded)
    monkeypatch.setattr(cli, "analyzer_domain_catalog", lambda: [])
    monkeypatch.setattr(cli, "native_capabilities", lambda: {})
    monkeypatch.setattr(cli, "probe_sandbox", lambda: {})
    monkeypatch.setattr(cli, "recognized_language_count", lambda: 0)
    monkeypatch.setattr(
        cli.importlib, "import_module",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ImportError("optional package absent")),
    )
    monkeypatch.setattr(
        cli,
        "remote_vcs_capabilities",
        lambda: {
            "git": {"available": True, "executable": "/usr/bin/git", "alternatives": ["git"]},
            "fossil": {"available": False, "executable": None, "alternatives": ["fossil"]},
        },
    )

    report = cli.capabilities_report()

    assert report["remote_vcs_clients"]["git"]["available"] is True
    assert report["remote_vcs_clients"]["fossil"]["available"] is False


def test_local_snapshot_gaps_are_reported_not_read_as_clean(tmp_path: Path):
    # Regression (a ticked ROADMAP item that did not exist): a snapshot without the
    # lockfile's ecosystem cleared it silently, and an old snapshot was never flagged.
    import json
    import sqlite3

    from project_discovery.vulnerabilities.database import VulnerabilityDatabase

    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/demo-lib": {"version": "1.9.0"},
    }}), encoding="utf-8")
    feed = tmp_path / "feed"
    feed.mkdir()
    (feed / "pypi.json").write_text(json.dumps({
        "id": "PYSEC-2099-1", "summary": "PyPI only",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
    }), encoding="utf-8")
    database = tmp_path / "advisories.sqlite3"
    with VulnerabilityDatabase(database) as store:
        store.import_osv(feed)
    connection = sqlite3.connect(database)
    connection.execute("UPDATE metadata SET value = '2020-01-01T00:00:00+00:00' WHERE key = 'last_imported_at'")
    connection.commit()
    connection.close()
    assert run_scan(project, tmp_path / "out", {"json", "markdown"}, 1, quiet=True,
                    vulnerability_db=database, strict=True) == 3
    report = _json_report(tmp_path / "out")
    gaps = [item for item in report["findings"] if item["title"].startswith("Ecosystem not covered")]
    assert gaps and gaps[0]["confidence"] == "UNKNOWN"
    assert report["metrics"]["vulnerability_intelligence"]["stale"] is True
    markdown = (tmp_path / "out" / "discovery-report.md").read_text(encoding="utf-8")
    assert "**Stale snapshot:**" in markdown and "- Ecosystems: PyPI (1)" in markdown


def test_phase_timings_name_each_pass_and_quiet_keeps_gate_reasons(tmp_path, capsys):
    # Regressions: the architecture pass was billed to code_index and "architecture" timed
    # the pool shutdown; --quiet hid why --fail-on/--strict failed (a CI gate exited 1 silently).
    import json

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    output = tmp_path / "out"
    code = run_scan(project, output, {"json"}, 1, quiet=True, fail_on="INFO")
    assert code == 1
    assert "[ FAILED ] --fail-on INFO" in capsys.readouterr().err
    phases = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["performance"]["phase_seconds"]
    assert {"python_graph", "architecture", "code_index", "shutdown"} <= set(phases)


def test_query_shows_resolved_names_and_refuses_a_scan_without_an_index(tmp_path, monkeypatch, capsys):
    import sys

    from project_discovery.cli import main

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("def run():\n    return 1\n\ndef main():\n    return run()\n", encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    monkeypatch.setattr(sys, "argv", ["pdt", "query", str(output), "--callees", "app.main"])
    with pytest.raises(SystemExit) as exited:
        main()
    assert exited.value.code == 0
    out = capsys.readouterr().out
    assert "main calls run" in out and "@" not in out
    fast = tmp_path / "fast"
    assert run_scan(project, fast, {"json"}, 1, quiet=True, inventory_only=True) == 0
    monkeypatch.setattr(sys, "argv", ["pdt", "query", str(fast), "--symbol", "run"])
    with pytest.raises(SystemExit) as exited:
        main()
    assert exited.value.code == 3
    assert "no code index" in capsys.readouterr().err


def test_strict_fails_on_files_the_analyzers_could_not_parse(tmp_path: Path):
    # Regression: parse and read failures kept severity INFO, so --strict passed scans with
    # unparsed contracts, configuration, CI and coverage files.
    for name, content in (
        ("openapi.yaml", "openapi: 3.0.0\npaths: [\n"),
        ("config.ini", "[odbc]\nnot a key value line\n"),
        ("coverage.xml", "<coverage><unclosed>"),
    ):
        project = tmp_path / name.replace(".", "_")
        project.mkdir()
        (project / name).write_text(content, encoding="utf-8")
        assert run_scan(project, tmp_path / f"{project.name}-out", {"json"}, 1, quiet=True, strict=True) == 3, name
        report = _json_report(tmp_path / f"{project.name}-out")
        assert any(item["confidence"] == "UNKNOWN" and item["severity"] == "LOW" for item in report["findings"]), name


def test_a_second_scan_into_a_busy_output_is_refused(tmp_path: Path):
    # Regression: a second scan cleared the shared inventory under the first, and both
    # reports mixed two roots.
    import pytest

    from project_discovery.core.output_lock import OutputInUse, output_lock

    project = tmp_path / "project"
    project.mkdir()
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    with output_lock(output), pytest.raises(OutputInUse, match="Another PDT scan is writing"):
        run_scan(project, output, {"json"}, 1, quiet=True)
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0


def test_text_files_with_uncatalogued_names_are_secret_scanned(tmp_path: Path):
    # Regression: .git-credentials, .pgpass, kubeconfig and *.tfstate were typed binary,
    # never secret-scanned, and the report read clean.
    token = "ghp_" + "D" * 36
    project = tmp_path / "project"
    (project / ".kube").mkdir(parents=True)
    for name in (".git-credentials", ".pgpass", ".kube/config", "terraform.tfstate", "notes.unknownext"):
        (project / name).write_text(f"credential = {token}\n", encoding="utf-8")
    assert run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True) == 0
    report = _json_report(tmp_path / "out")
    found = {item["evidence"][0].rsplit(":", 1)[0] for item in report["findings"]
             if item["title"] == "Potential hardcoded credential: github_token"}
    assert found == {".git-credentials", ".pgpass", ".kube/config", "terraform.tfstate", "notes.unknownext"}


def _run_main(capsys, monkeypatch, argv):
    """Run ``pdt ARGV``; return the exit code and stderr."""
    import sys as _sys

    from project_discovery.cli import main as _main

    monkeypatch.setattr(_sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as raised:
        _main()
    return raised.value.code, capsys.readouterr().err


def test_resume_refuses_an_inventory_made_with_other_options(tmp_path, capsys, monkeypatch):
    # Regression: --resume reused an --inventory-only store (name-only file types), and
    # carried over --skip and --exclude-dir from the original command, without a warning.
    project = tmp_path / "project"
    (project / "web").mkdir(parents=True)
    (project / "web" / "app.js").write_text("export const a = 1;\n", encoding="utf-8")
    (project / "main.py").write_text("print(1)\n", encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, inventory_only=True, quiet=True) == 0
    code, err = _run_main(capsys, monkeypatch, ["scan", str(project), "--output", str(output), "--resume", "--quiet"])
    assert code == 2
    assert "stored --inventory-only, now full analysis" in err
    assert run_scan(project, output, {"json"}, 128, ignores={"web"}, quiet=True) == 0
    code, err = _run_main(capsys, monkeypatch, ["scan", str(project), "--output", str(output), "--resume", "--quiet"])
    assert code == 2 and "--exclude-dir: stored web, now none" in err
    # The same options resume, however they are spelled ("Web/" is the name web); ./web would
    # be a different exclusion (only the top-level directory).
    assert run_scan(project, output, {"json"}, 128, ignores={"Web/"}, resume=True, quiet=True) == 0


def test_exclude_dir_spellings_and_size_option_prerequisite(tmp_path, capsys, monkeypatch):
    # Regression: ./web and an absolute path inside the root pruned nothing, silently, and
    # --max-file-mb without --skip was accepted although it does nothing.
    import json

    from project_discovery.inventory.scanner import normalize_exclusions

    project = tmp_path / "project"
    (project / "web" / "src").mkdir(parents=True)
    assert normalize_exclusions({"./web", "web\\src\\", str(project / "lib"), "Node_Modules/"}, project) == (
        {"node_modules"}, {"web", "web/src", "lib"},
    )
    for value, message in (
        (str(tmp_path / "elsewhere"), "outside the scan root"), ("../x", "outside the scan root"),
        (".", "names the scan root itself"), (str(project), "names the scan root itself"),
    ):
        with pytest.raises(ValueError, match=message):
            normalize_exclusions({value}, project)
    with pytest.raises(ValueError, match="absolute path needs a local scan root"):
        normalize_exclusions({str(project / "web")}, None)

    (project / "web" / "src" / "app.js").write_text("export const a = 1;\n", encoding="utf-8")
    (project / "main.py").write_text("print(1)\n", encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, ignores={str(project / "web"), "missing"}, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert report["metrics"]["pruned_directory_count"] == 1
    assert [item["path"] for item in report["files"]] == ["main.py"]
    assert "--exclude-dir missing matched no directory" in json.dumps(report)
    code, err = _run_main(capsys, monkeypatch, ["scan", str(project), "--output", str(tmp_path / "o2"), "--max-file-mb", "5"])
    assert code == 2 and "--max-file-mb requires --skip" in err


def test_fatal_errors_name_the_problem(tmp_path, capsys, monkeypatch):
    # Regression: a file given as the root printed only its path, and a --vuln-db that is
    # not SQLite printed sqlite3's bare "file is not a database".
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    code, err = _run_main(capsys, monkeypatch, ["scan", str(project / "a.py"), "--output", str(tmp_path / "o1")])
    assert code == 2 and "The scan root is not a directory: " in err
    bogus = tmp_path / "bogus.sqlite3"
    bogus.write_bytes(b"not sqlite at all, just text" * 8)
    code, err = _run_main(
        capsys, monkeypatch, ["scan", str(project), "--output", str(tmp_path / "o2"), "--vuln-db", str(bogus)],
    )
    assert code == 2
    assert f"The local vulnerability database {bogus.resolve()} is not a readable PDT advisory database" in err


def test_unprovisioned_grammars_of_scanned_languages_are_reported(tmp_path, monkeypatch):
    # Regression: TreeSitterAnalyzer.supports() skips languages without a grammar, so the
    # documented UNKNOWN for unprovisioned grammars never appeared in a scan.
    import json

    from project_discovery import cli

    project = tmp_path / "project"
    project.mkdir()
    (project / "lib.rs").write_text("fn main() {}\n", encoding="utf-8")
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    states = {"Rust": "grammar_not_provisioned"}
    monkeypatch.setattr(cli, "parser_capabilities", lambda languages=None: {
        name: states[name] for name in (languages or ()) if name in states
    })
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    gap = next(item for item in report["findings"] if item["title"].startswith("Tree-sitter grammars not provisioned"))
    assert (gap["confidence"], gap["severity"]) == ("UNKNOWN", "INFO")
    assert gap["evidence"] == ["Rust: 1 file(s), grammar 'rust' not provisioned"]
    states.clear()  # pack not installed or every grammar provisioned: nothing to report
    assert run_scan(project, tmp_path / "out2", {"json"}, 128, quiet=True) == 0
    report = json.loads((tmp_path / "out2" / "discovery-report.json").read_text(encoding="utf-8"))
    assert not any(item["title"].startswith("Tree-sitter grammars") for item in report["findings"])


def test_text_capabilities_list_the_analyzers(capsys, monkeypatch):
    # Regression: the text table said only "47 loaded"; the guide says it lists them.
    import sys as _sys

    from project_discovery.cli import main as _main

    monkeypatch.setattr(_sys, "argv", ["pdt", "capabilities"])
    with pytest.raises(SystemExit) as raised:
        _main()
    assert raised.value.code == 0
    out = capsys.readouterr().out
    assert "loaded:" in out and "secret-patterns" in out


def test_security_metadata_reaches_every_report_and_strict(tmp_path: Path, capsys, monkeypatch):
    from project_discovery.inventory import scanner
    from project_discovery.inventory.entry_metadata import security_supported

    if not security_supported():
        pytest.skip("security metadata is read on Windows and Linux")
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print(1)\n", encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 128, quiet=True, security_metadata=True) == 0
    report = _json_report(output)
    assert report["schema_version"] == "1.17"
    security = report["metrics"]["security_metadata"]
    assert (security["enabled"], security["entries"], security["errors"]) == (True, 2, 0)
    for record in (report["files"][0], report["directories"][0]):
        assert set(record) >= {"uid", "gid", "attributes", "security"}
        assert record["security"] and "error" not in record["security"]
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Security metadata: 2 entries read, " in markdown
    assert '"security_metadata"' in (output / "discovery-report.html").read_text(encoding="utf-8")
    # Metadata that cannot be read leaves the scan incomplete for --strict; it is not fatal.
    monkeypatch.setattr(scanner, "read_security", lambda path, kind: {"error": "PermissionError: denied"})
    capsys.readouterr()
    assert run_scan(project, tmp_path / "strict", {"json"}, 128, quiet=True, strict=True, security_metadata=True) == 3
    assert "2 security metadata read error(s)" in " ".join(capsys.readouterr().err.split())
    assert _json_report(tmp_path / "strict")["files"][0]["security"] == {"error": "PermissionError: denied"}
    # Without the option nothing is read, and the reports say so.
    assert run_scan(project, tmp_path / "plain", {"json", "markdown"}, 128, quiet=True) == 0
    plain = _json_report(tmp_path / "plain")
    assert plain["metrics"]["security_metadata"] == {"enabled": False, "entries": 0, "explicit_acl_entries": 0, "errors": 0}
    assert plain["files"][0]["security"] is None
    assert "- Security metadata: not recorded" in (tmp_path / "plain" / "discovery-report.md").read_text(encoding="utf-8")


def test_security_metadata_option_is_validated(tmp_path: Path, capsys, monkeypatch):
    from project_discovery import cli

    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("print(1)\n", encoding="utf-8")
    output = tmp_path / "out"
    monkeypatch.setattr(cli, "security_supported", lambda: True)
    code, err = _run_main(capsys, monkeypatch, [
        "scan", "https://github.com/acme/widgets", "--no-download", "--security-metadata",
    ])
    assert code == 2 and "--security-metadata applies to the download mode, not --no-download" in err
    # --resume continues only an inventory made with the same --security-metadata setting.
    from project_discovery.inventory.entry_metadata import security_supported

    if security_supported():
        assert run_scan(project, output, {"json"}, 128, quiet=True) == 0
        code, err = _run_main(capsys, monkeypatch, [
            "scan", str(project), "--output", str(output), "--resume", "--security-metadata", "--quiet",
        ])
        assert code == 2 and "--security-metadata: stored off, now on" in err
    monkeypatch.setattr(cli, "security_supported", lambda: False)
    code, err = _run_main(capsys, monkeypatch, ["scan", str(project), "--security-metadata"])
    assert code == 2
    assert "--security-metadata reads Windows security descriptors and Linux POSIX ACLs" in err
