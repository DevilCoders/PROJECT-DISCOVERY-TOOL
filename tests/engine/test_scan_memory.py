"""The scan's memory budget (--max-memory-mb): measuring the processes, back-pressure, reports."""
from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import warnings
from collections import deque
from pathlib import Path

import pytest

from project_discovery import cli
from project_discovery.engine import budgets
from project_discovery.engine.budgets import BudgetPolicy, ScanMemoryBudget, parse_domain_budgets

MiB = 1024 * 1024
needs_memory = pytest.mark.skipif(not budgets.memory_supported(), reason="the resident set cannot be read here")
needs_process_memory = pytest.mark.skipif(not budgets.process_memory_supported(),
                                          reason="other processes' resident sets cannot be read here")


def _holder(megabytes: int) -> subprocess.Popen:
    """A Python child process holding MEGABYTES of touched memory until its stdin closes."""
    code = (f"import sys\nblock = bytearray({megabytes} * 1024 * 1024)\n"
            "for index in range(0, len(block), 4096):\n    block[index] = 1\n"
            "print('ready', flush=True)\nsys.stdin.read()\n")
    # A virtual environment's python.exe on Windows only starts the base interpreter in a
    # child of its own (multiprocessing bypasses it the same way); the code needs no packages.
    executable = getattr(sys, "_base_executable", None) or sys.executable
    child = subprocess.Popen([executable, "-I", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == "ready"
    return child


def _release(child: subprocess.Popen) -> None:
    child.stdin.close()
    child.wait(timeout=60)
    child.stdout.close()


@needs_process_memory
def test_the_resident_sets_of_other_processes_are_read():
    own = budgets.resident_bytes()
    assert own and own / 2 <= budgets.process_resident_bytes(os.getpid()) <= own * 2
    child = _holder(64)
    pid = child.pid
    try:
        assert budgets.process_resident_bytes(pid) >= 64 * MiB
    finally:
        _release(child)
    del child  # Windows: closes the last handle to the exited process
    assert not budgets.process_resident_bytes(pid)


@needs_memory
@needs_process_memory
def test_the_scan_budget_counts_the_coordinator_and_its_worker_processes():
    children = [_holder(64), _holder(64)]
    try:
        scan = ScanMemoryBudget(100_000, lambda: [child.pid for child in children])
        total = scan.total_bytes(fresh=True)
        # Each child's 64 MiB is its own: shared pages or not, both count in full.
        assert total >= 2 * 60 * MiB + budgets.resident_bytes() // 2
        described = scan.describe()
        assert described["processes_measured"] == 3 and described["peak_mb"] == round(total / MiB, 1)
        assert described["samples"] == 1 and described["enforced"] is True
    finally:
        for child in children:
            _release(child)


@pytest.mark.skipif(budgets._PSS is None or not budgets.process_memory_supported(),
                    reason="Linux: the proportional set size splits shared pages")
def test_pages_forked_workers_share_with_the_coordinator_count_once():
    context = multiprocessing.get_context("fork")
    inherited = bytearray(128 * MiB)
    for index in range(0, len(inherited), 4096):
        inherited[index] = 1
    done = context.Event()
    children = [context.Process(target=done.wait) for _ in range(3)]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # fork() in a multi-threaded process
        for child in children:
            child.start()
    try:
        resident = budgets.resident_bytes() + sum(budgets.process_resident_bytes(child.pid) for child in children)
        scan = ScanMemoryBudget(100_000, lambda: [child.pid for child in children])
        total = scan.total_bytes(fresh=True)
        # Every child's resident set includes the 128 MiB it shares, copy-on-write, with this process.
        assert resident - total >= 3 * 100 * MiB
        assert scan.describe()["shared_pages"] == "proportional"
    finally:
        done.set()
        for child in children:
            child.join(timeout=60)
    del inherited


@needs_memory
def test_the_scan_budget_collects_queued_work_first_while_over_it():
    scan = ScanMemoryBudget(256)
    totals = iter([300, 300, 100])  # MiB: before queueing, then after each collected batch
    scan.total_bytes = lambda fresh=False: next(totals) * MiB
    pending, collected = deque(["a", "b", "c"]), []

    def collect():
        collected.append(pending.popleft())

    scan.make_room(lambda: len(pending), collect)
    assert collected == ["a", "b"] and (scan.waits, scan.over_budget_submissions) == (2, 0)
    # Still over it with nothing left in flight: the work is queued anyway, and counted.
    scan.total_bytes = lambda fresh=False: 300 * MiB
    scan.make_room(lambda: len(pending), collect)
    assert collected == ["a", "b", "c"] and (scan.waits, scan.over_budget_submissions) == (3, 1)
    scan.make_room(lambda: len(pending), collect)
    assert scan.over_budget_submissions == 2
    # Under it, nothing waits.
    scan.total_bytes = lambda fresh=False: 100 * MiB
    pending.extend(["d", "e"])
    scan.make_room(lambda: len(pending), collect)
    assert list(pending) == ["d", "e"] and scan.waits == 3
    # Without a budget nothing is sampled.
    unlimited = ScanMemoryBudget(None)
    unlimited.make_room(lambda: 1, lambda: pytest.fail("no budget, no wait"))
    assert unlimited.describe()["samples"] == 0 and unlimited.describe()["limit_mb"] is None


@needs_memory
def test_the_scan_memory_is_sampled_at_most_once_per_interval(monkeypatch):
    reads = []
    monkeypatch.setattr(budgets, "resident_bytes", lambda: reads.append(1) or 100 * MiB)
    scan = ScanMemoryBudget(256)
    for _ in range(50):
        scan.make_room(lambda: 0, lambda: None)
    assert 1 <= len(reads) <= 2 and scan.samples == len(reads)
    scan.total_bytes(fresh=True)
    assert len(reads) == scan.samples <= 3


class _Analyzer:
    def __init__(self, name, domains):
        self.name, self.domains = name, domains


def test_the_scan_budget_caps_every_calls_memory_budget():
    overrides = parse_domain_budgets(["firmware:memory=0", "archives:memory=4096", "secrets:memory=128"],
                                     {"firmware", "archives", "secrets", "security"})
    policy = BudgetPolicy(60, 2048, overrides, scan_memory_mb=512)
    memory = {domain: policy.for_analyzer(_Analyzer(domain, (domain,))).memory_mb
              for domain in ("security", "firmware", "archives", "secrets")}
    # "No limit" and larger budgets become the scan's; a smaller one stays.
    assert memory == {"security": 512, "firmware": 512, "archives": 512, "secrets": 128}
    described = policy.describe()
    assert (described["memory_mb"], described["scan_memory_mb"]) == (512, 512)
    assert described["domain_overrides"] == {"archives": {"memory_mb": 512}, "firmware": {"memory_mb": 512},
                                             "secrets": {"memory_mb": 128}}
    assert BudgetPolicy(60, 2048).describe()["scan_memory_mb"] is None


def _project(root: Path, files: int = 120) -> Path:
    for index in range(files):
        folder = root / f"pkg{index % 6}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"mod_{index}.py").write_text(
            f"import os\nfrom pkg{(index + 1) % 6} import mod_{index + 1}\n"
            f"SETTING_{index} = os.environ.get('PDT_SETTING')\n\ndef handler_{index}(value):\n"
            f"    return value + {index}\n",
            encoding="utf-8",
        )
    return root


def _results(output: Path) -> tuple:
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    findings = sorted((item["title"], tuple(item["evidence"])) for item in report["findings"])
    graph = report["metrics"]["python_dependency_graph"]
    return report, findings, (graph["summary"], graph["edges"])


@needs_memory
@pytest.mark.parametrize("executor", ["process", "thread"])
def test_a_scan_over_its_memory_budget_runs_one_batch_at_a_time_with_the_same_results(
    executor, tmp_path: Path, monkeypatch, capsys,
):
    project = _project(tmp_path / "project")
    assert cli.run_scan(project, tmp_path / "baseline", {"json"}, 128, quiet=True, executor=executor, jobs=2) == 0
    _, expected_findings, expected_graph = _results(tmp_path / "baseline")
    # The coordinator now reads as 10 GiB, so every batch waits for the one before it (and no
    # proportional-set calibration on Linux may correct that reading back to the real one).
    monkeypatch.setattr(budgets, "resident_bytes", lambda: 10 * 1024 * MiB)
    monkeypatch.setattr(budgets, "_PSS", None)
    output = tmp_path / "budgeted"
    capsys.readouterr()
    assert cli.run_scan(project, output, {"json", "markdown", "html"}, 128, no_color=True, executor=executor,
                        jobs=2, max_memory_mb=512) == 0
    assert "ran one at a time" in " ".join(capsys.readouterr().err.split())
    report, findings, graph = _results(output)
    assert (findings, graph) == (expected_findings, expected_graph)
    measured = report["metrics"]["analysis_budgets"]
    scan = measured["scan_memory"]
    assert (scan["limit_mb"], scan["enforced"], measured["memory_mb"], measured["scan_memory_mb"]) == (512, True, 512, 512)
    assert scan["peak_mb"] >= 10 * 1024 and scan["samples"] >= scan["waits"]
    # The analysis and the import parsing each queued their first batch with nothing in flight
    # and every later one after the batch before it: one wait fewer than submissions, each.
    assert scan["waits"] >= 2 and scan["over_budget_submissions"] - scan["waits"] == 2
    if executor == "process" and budgets.process_memory_supported():
        assert scan["processes_measured"] >= 2
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert f"scan memory budget 512 MiB, sampled peak {scan['peak_mb']:,.0f} MiB, {scan['waits']:,} wait(s)" in markdown
    assert f"{scan['over_budget_submissions']:,} batch(es) queued over it" in markdown
    assert "- Scan memory: " in markdown


def _main(monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


def test_max_memory_mb_reaches_the_scan_and_is_validated(tmp_path: Path, monkeypatch):
    project = _project(tmp_path / "project", files=3)
    output = tmp_path / "out"
    assert _main(monkeypatch, "scan", str(project), "--output", str(output), "--format", "json", "--quiet",
                 "--max-memory-mb", "768") == cli.EXIT_OK
    measured = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["analysis_budgets"]
    assert measured["scan_memory"]["limit_mb"] == measured["scan_memory_mb"] == 768
    unbudgeted = tmp_path / "unbudgeted"
    assert cli.run_scan(project, unbudgeted, {"json"}, 128, quiet=True) == 0
    measured = json.loads((unbudgeted / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["analysis_budgets"]
    assert measured["scan_memory"] == {**measured["scan_memory"], "limit_mb": None, "samples": 0, "peak_mb": None}
    for value in (-1, 100):
        with pytest.raises(ValueError, match="--max-memory-mb must be 0 \\(no limit\\) or at least 256 MiB"):
            cli.run_scan(project, tmp_path / "bad", {"json"}, 128, quiet=True, max_memory_mb=value)
