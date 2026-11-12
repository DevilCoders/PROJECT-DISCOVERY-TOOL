"""tools/benchmark.py: a failed scan is recorded as failed, never with an earlier run's figures."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

BENCHMARK = Path(__file__).resolve().parents[2] / "tools" / "benchmark.py"


def _module():
    spec = importlib.util.spec_from_file_location("pdt_benchmark_tool", BENCHMARK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_failed_scan_records_no_figures_and_exits_with_its_code(tmp_path, monkeypatch):
    # Regression: run() read the previous run's discovery-report.json after a scan that
    # failed before writing one, and recorded old file counts with the new wall time.
    benchmark = _module()
    output = tmp_path / "reports"
    output.mkdir()
    (output / "discovery-report.json").write_text(json.dumps({"metrics": {"file_count": 999}}), encoding="utf-8")
    monkeypatch.setattr(benchmark.subprocess, "run",
                        lambda command, check: subprocess.CompletedProcess(command, 2))
    results = tmp_path / "results.jsonl"
    monkeypatch.setattr(sys, "argv", ["benchmark.py", "run", str(tmp_path), "--output", str(output),
                                      "--results", str(results), "--no-such-option"])
    with pytest.raises(SystemExit) as exited:
        benchmark.main()
    assert exited.value.code == 2
    [line] = results.read_text(encoding="utf-8").splitlines()
    record = json.loads(line)
    assert record["failed"] is True and record["exit_code"] == 2
    assert "files" not in record and "files_per_second" not in record
    assert not (output / "discovery-report.json").exists()


def test_a_completed_scan_records_its_figures(tmp_path, monkeypatch):
    benchmark = _module()
    output = tmp_path / "reports"

    def fake_run(command, check):
        output.mkdir(exist_ok=True)
        report = {"metrics": {"file_count": 10, "total_bytes": 1000, "execution": {"executor": "thread"}}, "errors": []}
        (output / "discovery-report.json").write_text(json.dumps(report), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)
    result = benchmark.run(tmp_path, output, [], tmp_path / "results.jsonl", "label")
    assert result["failed"] is False and result["files"] == 10 and result["executor"] == "thread"
