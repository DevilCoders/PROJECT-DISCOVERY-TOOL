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
