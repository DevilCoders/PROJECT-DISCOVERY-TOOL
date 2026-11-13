"""Declared per-analyzer content limits, byte accounting and the limits a call reaches."""
from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

from project_discovery.analyzers import builtin_analyzers
from project_discovery.analyzers.dependencies.vulnerabilities import LocalVulnerabilityAnalyzer
from project_discovery.core import limits as content_limits
from project_discovery.core import source_utils
from project_discovery.core.limits import READS, AnalyzerLimits, accounting, limit_reached, over_limit
from project_discovery.core.source_utils import (
    PythonSourceTooLarge,
    SourceBudgetExceeded,
    open_verified_binary,
    parse_python,
    prefetched_content,
    read_bytes_bounded,
    read_python_source_bounded,
    read_text_bounded,
)
from project_discovery.engine.executor import FileOutcome, _run_analyzers
from project_discovery.models import FileRecord, Finding

MIB = 1024 * 1024


def test_every_builtin_analyzer_declares_its_content_limits():
    analyzers = [*builtin_analyzers(), LocalVulnerabilityAnalyzer]
    for analyzer in analyzers:
        declared = analyzer.limits
        assert isinstance(declared, AnalyzerLimits), f"{analyzer.name} declares no limits"
        assert declared.reads in READS and declared.outcome, analyzer.name
        assert declared.file_bytes is None or declared.file_bytes > 0, analyzer.name
        assert all(value > 0 for value in declared.caps.values()), analyzer.name
    by_name = {analyzer.name: analyzer.limits for analyzer in analyzers}
    # The declarations reference the constants the analyzers apply.
    from project_discovery.analyzers.security import secrets

    assert by_name["secret-patterns"].file_bytes == secrets._MAX_SCAN_BYTES == 64 * MIB
    assert by_name["secret-patterns"].caps["findings"] == secrets._MAX_FINDINGS
    assert by_name["archive-intelligence"].reads == "sampled"
    with pytest.raises(ValueError, match="reads must be one of"):
        AnalyzerLimits(1, "everything")
    with pytest.raises(ValueError, match="file_bytes must be positive"):
        AnalyzerLimits(0, "whole")


def test_verified_reads_are_accounted_and_overruns_recorded(tmp_path: Path):
    data = tmp_path / "data.bin"
    data.write_bytes(b"0123456789" * 1000)
    with accounting() as account:
        with open_verified_binary(data) as stream:
            assert stream.read(5) == b"01234"
            stream.seek(0)
            assert len(stream.read()) == 10_000
        with pytest.raises(SourceBudgetExceeded):
            read_bytes_bounded(data, 100)
        with pytest.raises(SourceBudgetExceeded):
            read_python_source_bounded(data, 200)
        assert over_limit(5_000, 4_096, "lines") and not over_limit(10, 10)
        limit_reached("wall_time", 8)
    # Buffered reads count what came from the file, read-ahead included.
    assert account.bytes_read >= 10_000 + 101 + 201
    assert account.limits == [("bytes", 100.0, 10_000.0), ("bytes", 200.0, 10_000.0),
                              ("lines", 4_096.0, 5_000.0), ("wall_time", 8.0, None)]
    # Prefetched content (files read once per worker) is accounted the same way.
    with prefetched_content(data, data.read_bytes(), None), accounting() as prefetched:
        assert read_text_bounded(data, 20_000) == "0123456789" * 1000
        with pytest.raises(SourceBudgetExceeded):
            read_bytes_bounded(data, 50)
    assert prefetched.bytes_read >= 10_000 and prefetched.limits == [("bytes", 50.0, 10_000.0)]
    # Outside an analyzer call nothing is recorded, and nested calls keep their own account.
    assert over_limit(2, 1) and content_limits.current_account() is None
    with accounting() as outer:
        with accounting() as inner:
            limit_reached("entries", 3, 4)
        assert content_limits.current_account() is outer
    assert (outer.limits, inner.limits) == ([], [("entries", 3.0, 4.0)])


@pytest.mark.parametrize(("module", "constant", "name", "language", "subject"), [
    ("code.type_systems", "_MAX_CONFIG_BYTES", "tsconfig.json", "JSON", "Type checker configuration"),
    ("domains.embedded", "_MAX_CONFIG_BYTES", "platformio.ini", "INI", "Embedded configuration"),
    ("domains.frontend", "_MAX_CONFIG_BYTES", "vite.config.ts", "TypeScript", "Frontend configuration"),
    ("domains.frontend", "_MAX_CONFIG_BYTES", "app.component.html", "HTML", "Frontend template"),
    ("domains.hdl", "MAX_HDL_BYTES", "top.v", "Verilog", "HDL source"),
    ("domains.shaders", "MAX_SHADER_BYTES", "light.glsl", "GLSL", "Shader source"),
    ("domains.firmware", "MAX_TABLE_BYTES", "partitions.csv", "CSV", "Firmware build file"),
    ("api.integration", "MAX_MANIFEST_BYTES", "package.json", "JSON", "Integration manifest"),
])
def test_a_file_past_an_analyzer_budget_is_reported_never_skipped_silently(
    tmp_path: Path, monkeypatch, module, constant, name, language, subject,
):
    imported = importlib.import_module(f"project_discovery.analyzers.{module}")
    monkeypatch.setattr(imported, constant, 64)
    [analyzer] = [item for item in builtin_analyzers() if type(item).__module__ == imported.__name__]
    path = tmp_path / name
    path.write_bytes(b"x" * 100)
    record = FileRecord(name, 100, Path(name).suffix, language)
    assert analyzer.supports(record)
    with accounting() as account:
        findings = analyzer.analyze(path, record)
    assert [(item.title, item.confidence) for item in findings] == [(f"{subject} resource limit: {name}", "UNKNOWN")]
    assert f"the {analyzer.name} analyzer's 64-byte content budget" in findings[0].detail
    assert account.limits == [("bytes", 64.0, 100.0)]


def test_the_python_syntax_tree_budget_is_recorded_for_every_analyzer_that_asks(monkeypatch):
    monkeypatch.setattr(source_utils, "MAX_PYTHON_SYNTAX_TREE_LINES", 10)
    source = "".join(f"value_{index} = {index}\n" for index in range(20)) + "# limits test\n"
    for _ in range(2):  # the second parse is served from the per-thread memo
        with accounting() as account, pytest.raises(PythonSourceTooLarge):
            parse_python(source)
        assert account.limits == [("lines", 10.0, 22.0)]


class _Analyzer:
    domains = ("security",)

    def __init__(self, name, work):
        self.name, self._work = name, work

    def supports(self, record):
        return True

    def analyze(self, path, record):
        return self._work(path, record)


def test_the_engine_reports_bytes_read_and_limits_reached(tmp_path: Path):
    data = tmp_path / "data.txt"
    data.write_text("x" * 300, encoding="ascii")

    def reader(path, record):
        with open_verified_binary(path) as stream:
            stream.read()
        return []

    def checker(path, record):
        if over_limit(record.size_bytes, 50):
            return [Finding("analysis_coverage", "over budget", "detail", confidence="UNKNOWN", analyzer="checker")]
        return []

    def overrunner(path, record):
        return [read_text_bounded(path, 10)]  # the budget error escapes the analyzer

    record = FileRecord("data.txt", 300, ".txt", "Text")
    outcome = FileOutcome()
    _run_analyzers([_Analyzer("reader", reader), _Analyzer("checker", checker), _Analyzer("overrunner", overrunner)],
                   {}, record, data, outcome)
    assert [(name, read) for name, _, _, read in outcome.budget_usage] == [
        ("reader", pytest.approx(300, abs=0)), ("checker", 0)]  # the overrunner raised: no usage row
    assert outcome.limit_hits == [("checker", "bytes", 50.0, 300.0), ("overrunner", "bytes", 10.0, 300.0)]
    assert [item.title for item in outcome.findings] == [
        "over budget", "Analyzer content limit reached: overrunner: data.txt"]
    assert outcome.findings[1].confidence == "UNKNOWN"
    assert any("SourceBudgetExceeded" in error for error in outcome.errors)


def test_a_scan_reports_declared_limits_bytes_read_and_limits_reached(tmp_path: Path, capsys):
    from project_discovery.cli import run_scan

    project = tmp_path / "project"
    project.mkdir()
    # Past the 2 MiB budget of type-systems, which skips it; the limit is recorded.
    (project / "tsconfig.json").write_bytes(b"{" + b" " * (3 * MIB) + b"}")
    (project / "app.py").write_bytes(b"print('ok')\n")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 128, executor="thread", no_color=True) == 0
    # The summary table wraps long values: compare without whitespace and cell borders.
    assert "contentlimit(s)reached(bytes" in re.sub(r"[\s│┃|]", "", capsys.readouterr().err)
    budgets = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))["metrics"]["analysis_budgets"]
    assert budgets["limits_reached"]["bytes"] >= 1
    assert {"analyzer": "type-systems", "path": "tsconfig.json", "limit": "bytes", "value": 2 * MIB,
            "used": 3 * MIB + 2} in budgets["limited"]
    assert budgets["analyzer_limits"]["type-systems"] == {"file_bytes": 2 * MIB, "reads": "whole", "caps": {}}
    assert set(budgets["analyzer_limits"]) >= {analyzer.name for analyzer in builtin_analyzers()}
    secrets = budgets["analyzers"]["secret-patterns"]
    assert secrets["bytes_read"] >= 3 * MIB and secrets["max_bytes_path"] == "tsconfig.json"
    assert budgets["analyzers"]["type-systems"]["limits_reached"] == 1
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Limit reached: tsconfig.json: type-systems, 2 MiB limit, at 3 MiB" in markdown
    assert "| type-systems | whole | 2 MiB | - |" in markdown
    assert "content limit(s) reached (bytes " in markdown
    assert 'id="analyzer-declared"' in (output / "discovery-report.html").read_text(encoding="utf-8")
