"""`pdt plugin-check`: plugins are checked the way a scan loads and validates them."""
import json
import sys

import pytest

from project_discovery.plugins.conformance import (
    assert_conformant,
    check_plugin,
    format_report,
    resolve_entry_point,
)

FIXTURES = '''
import random
from pathlib import Path
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import CodeEvidence, Finding


class Good(Analyzer):
    name = "fixture-good"
    version = "1.0"
    description = "Reports TODO markers."

    def supports(self, record):
        return record.extension == ".txt"

    def analyze(self, path, record):
        text = Path(path).read_text(encoding="utf-8")
        return [Finding("todo", "TODO in " + record.path, "", evidence=[record.path])] if "TODO" in text else []


class Bad(Analyzer):
    name = "fixture-bad"

    def supports(self, record):
        return True

    def analyze(self, path, record):
        return ["not a finding", Finding("not a category!", "Title", "")]


class Flaky(Analyzer):
    name = "fixture-flaky"
    version = "1.0"
    description = "Different every time."

    def supports(self, record):
        return True

    def analyze(self, path, record):
        return [Finding("flaky", "Run %f" % random.random(), "")]


class Raises(Analyzer):
    name = "fixture-raises"
    version = "1.0"
    description = "Fails in supports()."

    def supports(self, record):
        raise RuntimeError("boom")

    def analyze(self, path, record):
        return []


class Leaky(Analyzer):
    name = "fixture-leaky"
    version = "1.0"
    description = "Claims another analyzer and reports a secret."

    def supports(self, record):
        return True

    def analyze(self, path, record):
        return [Finding("leak", "Leak", "", analyzer="secret-patterns",
                        code_evidence=[CodeEvidence(1, "password = 'hunter2hunter2'")])]


class Impostor(Good):
    name = "secret-patterns"


class Fields(Analyzer):
    name = "fixture-fields"
    version = "1.0"
    description = "Decides on the record fields a scan fills in."

    def supports(self, record):
        return (record.size_bucket != "unknown" and record.permissions is not None
                and record.mtime_ns is not None and record.is_hidden == record.path.startswith(".")
                and record.file_type == ("source" if record.extension == ".py" else "text"))

    def analyze(self, path, record):
        return []


class Huge(Analyzer):
    name = "fixture-huge"
    version = "1.0"
    description = "Stays within every per-finding limit but not within one response frame."

    def supports(self, record):
        return True

    def analyze(self, path, record):
        # 7,000 characters of non-ASCII text encode as about 42 KB of JSON escapes.
        return [Finding("bulk", "Finding %d" % index, "\u00e9" * 7000) for index in range(1000)]
'''


@pytest.fixture
def fixtures(tmp_path, monkeypatch):
    modules = tmp_path / "modules"
    modules.mkdir()
    (modules / "pdt_conformance_fixtures.py").write_text(FIXTURES, encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "a.txt").write_text("TODO: check\n", encoding="utf-8")
    (samples / "b.md").write_text("# Notes\n", encoding="utf-8")
    yield samples
    sys.modules.pop("pdt_conformance_fixtures", None)


def _problems(report, severity):
    return {(problem.check, problem.path) for problem in report.problems if problem.severity == severity}


def test_a_conformant_plugin_passes_under_the_sandbox(fixtures):
    report = check_plugin("pdt_conformance_fixtures:Good", [fixtures])
    assert report.ok, format_report(report)
    assert report.problems == []
    assert report.metadata["name"] == "fixture-good"
    assert all(report.sandbox["restrictions"].values())
    assert [(entry["path"], entry["supported"], entry["findings"]) for entry in report.files] == [
        ("a.txt", True, 1), ("b.md", False, 0),
    ]


def test_invalid_findings_are_errors(fixtures):
    report = check_plugin("pdt_conformance_fixtures:Bad", [fixtures], isolation="process")
    assert not report.ok
    messages = [problem.message for problem in report.problems if problem.check == "findings"]
    assert any("is a str, not a Finding" in message for message in messages)
    assert any("category must match" in message for message in messages)
    # A missing version and description are only warnings.
    assert ("metadata", "") in _problems(report, "warning")
    with pytest.raises(AssertionError, match="not conformant"):
        assert_conformant("pdt_conformance_fixtures:Bad", [fixtures], isolation="process")


def test_non_determinism_redaction_and_claimed_names_are_warnings(fixtures):
    flaky = check_plugin("pdt_conformance_fixtures:Flaky", [fixtures / "a.txt"], isolation="process")
    assert flaky.ok and ("determinism", "a.txt") in _problems(flaky, "warning")
    leaky = check_plugin("pdt_conformance_fixtures:Leaky", [fixtures / "a.txt"], isolation="process")
    assert leaky.ok
    assert {("findings", "a.txt"), ("redaction", "a.txt")} <= _problems(leaky, "warning")


def test_failing_supports_and_reserved_names_are_errors(fixtures):
    raises = check_plugin("pdt_conformance_fixtures:Raises", [fixtures / "a.txt"], isolation="process")
    assert not raises.ok
    assert any("boom" in problem.message for problem in raises.problems if problem.check == "supports")
    impostor = check_plugin("pdt_conformance_fixtures:Impostor", [fixtures], isolation="process")
    assert [problem.check for problem in impostor.problems] == ["metadata"]
    assert "duplicate analyzer name" in impostor.problems[0].message


def test_unknown_entry_points_are_refused():
    with pytest.raises(ValueError, match="no installed pdt.analyzers entry point"):
        resolve_entry_point("not-installed-anywhere")


def test_cli_exit_status_follows_the_result(fixtures, monkeypatch, capsys):
    from project_discovery import cli

    monkeypatch.setattr(sys, "argv", ["pdt", "plugin-check", "pdt_conformance_fixtures:Good", str(fixtures),
                                      "--isolation", "process", "--json"])
    with pytest.raises(SystemExit) as passed:
        cli.main()
    assert passed.value.code == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    monkeypatch.setattr(sys, "argv", ["pdt", "plugin-check", "pdt_conformance_fixtures:Bad", str(fixtures),
                                      "--isolation", "process"])
    with pytest.raises(SystemExit) as failed:
        cli.main()
    assert failed.value.code == 1
    assert "NOT conformant" in capsys.readouterr().out


def test_plugin_check_hands_over_the_record_a_scan_builds(fixtures, tmp_path):
    # Regression: plugin-check built a stub record (file type "text", size bucket
    # "unknown", no permissions or modification time, never hidden), so a plugin that
    # decides on those fields was checked against values no scan produces.
    samples = tmp_path / "field-samples"
    samples.mkdir()
    (samples / "notes.txt").write_text("notes\n", encoding="utf-8")
    (samples / ".hidden.txt").write_text("hidden\n", encoding="utf-8")
    (samples / "tool.py").write_text("print(1)\n", encoding="utf-8")
    report = check_plugin("pdt_conformance_fixtures:Fields", [samples], isolation="process")
    assert {entry["path"]: entry["supported"] for entry in report.files} == {
        ".hidden.txt": True, "notes.txt": True, "tool.py": True,
    }


def test_findings_beyond_one_response_frame_are_cut_not_all_lost(fixtures):
    # Regression: 1,000 findings within every documented per-finding limit made a reply
    # over the 16 MiB frame limit, and the host replaced it with an error: all were lost.
    report = check_plugin("pdt_conformance_fixtures:Huge", [fixtures / "a.txt"], isolation="process")
    assert 0 < report.files[0]["findings"] < 1000
    assert any(problem.check == "findings" and "response limit" in problem.message for problem in report.problems)


SNOOP = '''
from pathlib import Path
from project_discovery.analyzers.base import Analyzer


class Snoop(Analyzer):
    name = "fixture-snoop"
    version = "1.0"
    description = "Supports a file only while it cannot read the file next to its own module."

    def supports(self, record):
        try:
            (Path(__file__).resolve().parent / "secret.txt").read_bytes()
        except OSError:
            return True
        return False

    def analyze(self, path, record):
        return []
'''


def test_a_plugin_on_pythonpath_cannot_read_its_neighbours_under_the_sandbox(tmp_path, monkeypatch):
    # Regression (Linux/macOS): every sys.path entry became a read rule, so a plugin
    # imported from PYTHONPATH or the working directory could read everything beside it.
    modules = tmp_path / "modules"
    modules.mkdir()
    (modules / "pdt_snoop_fixture.py").write_text(SNOOP, encoding="utf-8")
    (modules / "secret.txt").write_text("not for plugins\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(modules))
    monkeypatch.syspath_prepend(str(modules))
    sample = tmp_path / "sample.txt"
    sample.write_text("x\n", encoding="utf-8")
    try:
        report = check_plugin("pdt_snoop_fixture:Snoop", [sample])
    finally:
        sys.modules.pop("pdt_snoop_fixture", None)
    assert report.ok, format_report(report)
    assert report.files[0]["supported"] is True
