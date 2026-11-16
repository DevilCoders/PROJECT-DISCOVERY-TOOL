"""Per-analyzer time and memory budgets: the watchdog, the policy, the engine and the reports."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from project_discovery.engine import budgets
from project_discovery.engine.budgets import AnalyzerBudget, BudgetPolicy, parse_domain_budgets, run_with_budget
from project_discovery.engine.executor import FileOutcome, _run_analyzers
from project_discovery.intelligence.facts import collecting_facts, emit_fact
from project_discovery.models import FileRecord, Finding


def _spin_swallowing_exceptions():
    while True:
        try:
            sum(range(1000))
        except Exception:  # an analyzer's broad handler must not swallow the stop
            pass


def test_a_call_past_its_time_budget_is_stopped_even_if_it_catches_exceptions():
    started = time.monotonic()
    run = run_with_budget(AnalyzerBudget(0.2, None), _spin_swallowing_exceptions)
    assert run.result is None and run.stop.kind == "time" and run.stop.limit == 0.2
    assert 0.2 <= run.stop.used < 2 and time.monotonic() - started < 3


@pytest.mark.skipif(not budgets.memory_supported(), reason="the resident set cannot be read here")
def test_a_call_past_its_memory_budget_is_stopped():
    held = []

    def hog():
        while True:
            held.append(bytearray(4 * 1024 * 1024))
            time.sleep(0.001)

    run = run_with_budget(AnalyzerBudget(30, 64), hog)
    held.clear()
    assert run.stop.kind == "memory" and run.stop.limit == 64 and run.stop.used > 64


@pytest.mark.skipif(not budgets.cpu_supported(), reason="no per-thread CPU clock here (macOS)")
def test_the_cpu_budget_counts_the_threads_cpu_time_not_wall_time():
    run = run_with_budget(AnalyzerBudget(None, None, None, 0.3), _spin_swallowing_exceptions)
    assert run.result is None and (run.stop.kind, run.stop.limit) == ("cpu", 0.3) and 0.3 < run.stop.used < 2
    # Sleeping costs no CPU: a call that waits longer than its CPU budget completes.
    slept = run_with_budget(AnalyzerBudget(None, None, None, 0.1), lambda: time.sleep(0.4) or "done")
    assert (slept.result, slept.stop) == ("done", None)
    policy = BudgetPolicy(None, None, parse_domain_budgets(["archives:cpu=5"], {"archives"}), cpu_seconds=1)
    assert policy.for_analyzer(_Analyzer("a", ("archives",), None)).cpu_seconds == 5
    assert policy.describe()["cpu_enforced"] is True


def test_a_call_past_its_read_budget_is_stopped_by_the_readers(tmp_path: Path):
    from project_discovery.core.limits import accounting
    from project_discovery.core.source_utils import open_verified_binary

    data = tmp_path / "data.bin"
    data.write_bytes(b"x" * (3 * 1024 * 1024))

    def reader():
        with open_verified_binary(data) as stream:
            while stream.read(64 * 1024):
                pass
        return "read it all"

    with accounting(1024 * 1024) as account:  # the engine pairs the account with the budget
        run = run_with_budget(AnalyzerBudget(None, None, 1), reader)
    assert run.result is None and (run.stop.kind, run.stop.limit) == ("read", 1)
    assert 1 < run.stop.used < 1.2 and account.bytes_read < 2 * 1024 * 1024


def test_the_engine_reports_a_read_budget_stop(tmp_path: Path):
    from project_discovery.core.source_utils import open_verified_binary

    data = tmp_path / "data.bin"
    data.write_bytes(b"x" * (3 * 1024 * 1024))

    def greedy():
        with open_verified_binary(data) as stream:
            stream.read()
        return [Finding("security", "never kept", "detail", analyzer="greedy")]

    record = FileRecord("data.bin", data.stat().st_size, ".bin", "Binary")
    outcome = FileOutcome()
    budgets.set_policy(BudgetPolicy(None, None, read_mb=2))
    try:
        _run_analyzers([_Analyzer("greedy", ("security",), greedy)], {}, record, data, outcome)
    finally:
        budgets.set_policy(None)
    assert [item.title for item in outcome.findings] == ["Analyzer read budget exceeded: greedy: data.bin"]
    assert "2 MiB read budget" in outcome.findings[0].detail
    assert [(name, kind, limit) for name, kind, limit, _ in outcome.budget_stops] == [("greedy", "read", 2.0)]


def test_calls_within_budget_return_their_result_and_leave_no_stop_behind():
    for value in range(300):
        assert run_with_budget(AnalyzerBudget(5, 512), lambda value=value: value).result == value
    # A stop pending for a finished call would surface here as an exception.
    deadline = time.monotonic() + 0.3
    while time.monotonic() < deadline:
        sum(range(100))
    unlimited = run_with_budget(AnalyzerBudget(None, None), lambda: "done")
    assert (unlimited.result, unlimited.stop, unlimited.peak_mb) == ("done", None, None)


class _Analyzer:
    def __init__(self, name, domains, work):
        self.name, self.domains, self._work = name, domains, work

    def supports(self, record):
        return True

    def analyze(self, path, record):
        return self._work()


def test_the_engine_reports_a_stopped_analyzer_and_discards_its_findings_and_facts(tmp_path: Path):
    def slow():
        emit_fact("component", "partial")
        _spin_swallowing_exceptions()

    def quick():
        emit_fact("component", "kept")
        return [Finding("security", "kept finding", "detail", analyzer="quick")]

    record = FileRecord("app.py", 1, ".py", "Python")
    outcome = FileOutcome()
    budgets.set_policy(BudgetPolicy(0.2, None, {"firmware": {"timeout_seconds": None}}))
    try:
        with collecting_facts() as facts:
            _run_analyzers([_Analyzer("slow", ("security",), slow), _Analyzer("quick", ("security",), quick)],
                           {}, record, tmp_path / "app.py", outcome)
    finally:
        budgets.set_policy(None)
    titles = [item.title for item in outcome.findings]
    assert titles == ["Analyzer time budget exceeded: slow: app.py", "kept finding"]
    stop = outcome.findings[0]
    assert stop.confidence == "UNKNOWN" and "0.2-second time budget" in stop.detail
    assert [item[1] for item in facts.facts] == ["kept"]  # the stopped analyzer's fact was rolled back
    [(name, kind, limit, used)] = outcome.budget_stops
    assert (name, kind, limit) == ("slow", "time", 0.2) and used >= 0.2
    assert [name for name, *_ in outcome.budget_usage] == ["slow", "quick"]


def test_domain_overrides_take_the_most_permissive_limit():
    policy = BudgetPolicy(60, 1024, parse_domain_budgets(
        ["archives:timeout=10,memory=256", "supply_chain:timeout=30", "firmware:timeout=0,memory=0"],
        {"archives", "supply_chain", "firmware", "security"},
    ))
    assert policy.for_analyzer(_Analyzer("archive", ("archives", "supply_chain"), None)) == AnalyzerBudget(30, 256)
    assert policy.for_analyzer(_Analyzer("firmware", ("firmware",), None)) == AnalyzerBudget(None, None)
    assert policy.for_analyzer(_Analyzer("secrets", ("security",), None)) == AnalyzerBudget(60, 1024)
    assert policy.describe()["domain_overrides"]["archives"] == {"timeout_seconds": 10.0, "memory_mb": 256}
    for value, message in (
        ("archives", "expected DOMAIN:timeout=SECONDS,memory=MB"),
        ("archive:timeout=3", "unknown analyzer domain 'archive'; did you mean archives"),
        ("archives:speed=3", "settings are timeout=SECONDS, memory=MB, read=MB and cpu=SECONDS"),
        ("archives:cpu=-2", "cpu must be 0 (no limit) or a positive number"),
        ("archives:read=1.5", "read must be 0 (no limit) or a positive integer"),
        ("archives:memory=1.5", "memory must be 0 (no limit) or a positive integer"),
        ("archives:timeout=-1", "timeout must be 0 (no limit) or a positive number"),
        ("archives:timeout=nan", "timeout must be 0 (no limit) or a positive number"),
        ("archives:memory=inf", "memory must be 0 (no limit) or a positive integer"),
        ("archives:timeout=fast", "timeout must be a number"),
    ):
        with pytest.raises(ValueError, match=re.escape(message)):
            parse_domain_budgets([value], {"archives"})


def test_budgets_stop_slow_analyzers_in_a_scan_and_reach_every_report(tmp_path: Path, monkeypatch, capsys):
    from project_discovery.analyzers.environment.operating_systems import OperatingSystemAnalyzer
    from project_discovery.cli import run_scan

    monkeypatch.setattr(OperatingSystemAnalyzer, "analyze", lambda self, path, record: _spin_swallowing_exceptions())
    project = tmp_path / "project"
    project.mkdir()
    # 4 MiB of text: the secret scanner needs far longer than the 0.05-second budget for it.
    with (project / "notes.txt").open("w", encoding="ascii", newline="\n") as stream:
        for _ in range(64):
            stream.write("a" * 65535 + "\n")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 128, executor="thread", no_color=True,
                    analyzer_timeout=0.05, domain_budgets=["secrets:timeout=0"]) == 0
    assert "Analyzer budgets" in capsys.readouterr().err
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    measured = report["metrics"]["analysis_budgets"]
    assert measured["timeout_seconds"] == 0.05 and measured["domain_overrides"] == {"secrets": {"timeout_seconds": None}}
    stopped = {item["analyzer"]: item for item in measured["stopped"]}
    assert stopped["operating-system-intelligence"]["budget"] == "time"
    assert stopped["operating-system-intelligence"]["path"] == "notes.txt"
    # The secret scanner (domain "secrets") had no time limit, so it ran to the end.
    assert "secret-patterns" not in stopped and measured["analyzers"]["secret-patterns"]["seconds"] > 0.05
    assert measured["stops"]["time"] == len(measured["stopped"]) and measured["stops"]["memory"] == 0
    [finding] = [item for item in report["findings"]
                 if item["title"] == "Analyzer time budget exceeded: operating-system-intelligence: notes.txt"]
    assert finding["confidence"] == "UNKNOWN" and finding["category"] == "analysis_coverage"
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "## Analyzer Budgets" in markdown
    assert "- Budget: 0.05 s and 2,048 MiB per analyzer and file; 1 domain override(s);" in markdown
    assert "- Domain secrets: no time limit and 2,048 MiB" in markdown
    assert "- Stopped: notes.txt: operating-system-intelligence, time budget 0.05 s, at " in markdown
    assert 'id="analyzer-time"' in (output / "discovery-report.html").read_text(encoding="utf-8")
    # The scan's policy does not outlive it.
    assert budgets.current_policy().timeout_seconds == budgets.DEFAULT_TIMEOUT_SECONDS
    for timeout in (-1, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="--analyzer-timeout must be 0"):
            run_scan(project, tmp_path / "bad", {"json"}, 128, quiet=True, analyzer_timeout=timeout)
    with pytest.raises(ValueError, match="--analyzer-memory-mb must be 0"):
        run_scan(project, tmp_path / "bad", {"json"}, 128, quiet=True, analyzer_memory_mb=-5)
    with pytest.raises(ValueError, match="unknown analyzer domain 'secret'; did you mean secrets"):
        run_scan(project, tmp_path / "bad", {"json"}, 128, quiet=True, domain_budgets=["secret:memory=64"])


def test_inventory_only_scans_record_the_policy_without_a_budget_section(tmp_path: Path):
    from project_discovery.cli import run_scan

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown"}, 128, quiet=True, inventory_only=True) == 0
    measured = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["analysis_budgets"]
    assert measured["analyzers"] == {} and measured["stopped"] == []
    assert "## Analyzer Budgets" not in (output / "discovery-report.md").read_text(encoding="utf-8")
