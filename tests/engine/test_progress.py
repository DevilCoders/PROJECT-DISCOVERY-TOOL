"""Phase-based scan progress: the model, the live display and what scans record."""
from __future__ import annotations

import io
import json
import zipfile
from collections import Counter
from pathlib import Path

from rich.console import Console

from project_discovery.cli import run_scan
from project_discovery.engine.progress import PHASES, ScanProgress
from project_discovery.reporting.terminal import PhaseDisplay


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class _Analyzer:
    def __init__(self, name, domains):
        self.name, self.domains = name, domains


def test_phases_record_their_state_counts_and_times():
    clock = _Clock()
    progress = ScanProgress(clock)
    assert [item["state"] for item in progress.describe()] == ["waiting"] * 6
    walk = Counter()
    progress.begin("inventory")
    progress.watch_walk(walk)
    walk.update(entry_count=7, total_bytes=900)
    # While the walk runs, the display reads its counters.
    assert (progress.snapshot()[0]["done"], progress.snapshot()[0]["bytes"]) == (7, 900)
    clock.now += 2
    progress.finish("inventory")
    progress.walked(9, 6, 1000)
    progress.set_analyzer_domains([_Analyzer("secrets", ("secrets", "security")), _Analyzer("plugin", ())])
    for key, total in (("hashing", None), ("analysis", 6), ("archives", 1)):
        progress.begin(key, total=total)
    progress.advance("hashing", size=400, work_seconds=0.5)
    progress.advance("hashing", 0, reused=1)
    progress.analyzer_calls([("secrets", 0.25, None, 10), ("plugin", 0.5, None, 0), ("secrets", 0.25, None, 3)])
    progress.advance("archives", work_seconds=0.1)
    progress.advance("analysis", 6)
    clock.now += 3
    for key in ("hashing", "analysis", "archives"):
        progress.finish(key)
    progress.begin("correlation", total=2)
    progress.step("correlation", "python_graph")
    clock.now += 1
    progress.step("correlation", "code_index")
    clock.now += 0.5
    progress.finish("correlation")
    progress.begin("reporting", total=2)
    progress.annotate("reporting", formats=["json", "html"])
    phases = {item["phase"]: item for item in progress.describe()}
    assert list(phases) == list(PHASES)
    assert phases["inventory"] | {} == {**phases["inventory"], "state": "done", "seconds": 2.0, "done": 9,
                                        "bytes": 1000, "files": 6}
    assert (phases["hashing"]["done"], phases["hashing"]["bytes"], phases["hashing"]["reused"],
            phases["hashing"]["work_seconds"], phases["hashing"]["seconds"]) == (1, 400, 1, 0.5, 3.0)
    assert phases["analysis"]["domains"] == {
        "secrets": {"calls": 2, "seconds": 0.5}, "security": {"calls": 2, "seconds": 0.5},
        "other": {"calls": 1, "seconds": 0.5},
    }
    assert (phases["archives"]["done"], phases["archives"]["total"]) == (1, 1)
    assert phases["correlation"]["steps"] == {"python_graph": 1.0, "code_index": 0.5}
    assert (phases["correlation"]["done"], phases["correlation"]["seconds"]) == (2, 1.5)
    # The reports are written in this phase: they can only record it as running.
    assert (phases["reporting"]["state"], phases["reporting"]["seconds"], phases["reporting"]["formats"]) == (
        "running", None, ["json", "html"])
    progress.skip("reporting", "no format")
    assert progress.describe()[-1]["note"] == "no format"


def _render(display: PhaseDisplay, *, terminal: bool) -> str:
    stream = io.StringIO()
    Console(file=stream, force_terminal=terminal, width=200, color_system=None).print(display.render())
    return stream.getvalue()


def test_the_display_draws_one_row_per_phase():
    clock = _Clock()
    progress = ScanProgress(clock)
    display = PhaseDisplay(Console(file=io.StringIO()), progress)
    progress.begin("inventory")
    progress.walked(1_234, 1_000, 5 * 1024 * 1024)
    progress.finish("inventory")
    progress.set_analyzer_domains([_Analyzer("secrets", ("secrets",))])
    progress.begin("analysis", total=1_000)
    progress.advance("analysis", 250)
    progress.analyzer_calls([("secrets", 0.1, None, 0)] * 250)
    clock.now += 10
    rendered = _render(display, terminal=True)
    for label in ("Inventory", "Hashing", "Analyzer domains", "Archive inspection", "Correlation", "Reporting"):
        assert rendered.count(label) == 1
    assert "done Inventory" in rendered and "1,234 entries / 1,000 files / 5 MiB" in rendered
    assert "250 of 1,000 files / analyzer calls: secrets 250 (about 30.0 s left)" in rendered
    assert "waiting" in rendered and "10.0 s" in rendered
    # Redirected, the rows carry no control sequences.
    assert "\x1b" not in _render(display, terminal=False)


def _project(root: Path) -> Path:
    for index in range(40):
        path = root / f"pkg{index % 4}" / f"module_{index}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"import os\nVALUE_{index} = os.environ.get('PDT_{index}')\n", encoding="utf-8")
    with zipfile.ZipFile(root / "bundle.zip", "w") as archive:
        archive.writestr("inner/app.py", "print('archived')\n")
    return root


def _phases(output: Path) -> dict[str, dict]:
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    return {item["phase"]: item for item in report["metrics"]["performance"]["phases"]}


def test_a_scan_records_and_shows_every_phase(tmp_path: Path, capsys):
    project = _project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 128, executor="thread", jobs=2, no_color=True) == 0
    shown = capsys.readouterr().err
    for label in ("done Inventory", "done Hashing", "done Analyzer domains", "done Archive inspection",
                  "done Correlation", "done Reporting"):
        assert label in shown
    assert "\x1b" not in shown and shown.index("done Reporting") < shown.index("[ SUCCESS ] Report:")
    phases = _phases(output)
    assert [phases[key]["state"] for key in PHASES] == ["done"] * 5 + ["running"]
    assert (phases["inventory"]["files"], phases["inventory"]["done"]) == (41, 41 + 4)
    assert (phases["hashing"]["done"], phases["hashing"]["reused"]) == (41, 0) and phases["hashing"]["bytes"] > 0
    assert (phases["analysis"]["done"], phases["analysis"]["total"]) == (41, 41)
    assert phases["analysis"]["domains"]["secrets"]["calls"] >= 41
    assert (phases["archives"]["done"], phases["archives"]["total"]) == (1, 1)
    assert list(phases["correlation"]["steps"]) == ["inventory_aggregates", "python_graph", "architecture", "code_index"]
    assert phases["reporting"]["formats"] == ["json", "markdown", "html"]
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "## Scan Phases" in markdown and "| Archive inspection | done |" in markdown
    assert "| secrets |" in markdown
    assert 'id="scan-phases"' in (output / "discovery-report.html").read_text(encoding="utf-8")
    # The fingerprint cache supplies every digest the second time.
    assert run_scan(project, output, {"json"}, 128, executor="thread", jobs=2, quiet=True) == 0
    assert "done Inventory" not in capsys.readouterr().err  # --quiet draws no display
    again = _phases(output)
    assert (again["hashing"]["done"], again["hashing"]["reused"], again["hashing"]["bytes"]) == (0, 41, 0)
    # A resumed scan reuses the stored inventory.
    assert run_scan(project, output, {"json"}, 128, executor="thread", jobs=2, quiet=True, resume=True) == 0
    resumed = _phases(output)
    assert resumed["inventory"]["state"] == "skipped" and resumed["inventory"]["files"] == 41
    assert resumed["inventory"]["note"] == "resumed from the stored inventory"


def test_an_inventory_only_scan_skips_the_file_pass(tmp_path: Path):
    project = _project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown"}, 128, quiet=True, inventory_only=True) == 0
    phases = _phases(output)
    for key in ("hashing", "analysis", "archives"):
        assert phases[key]["state"] == "skipped" and phases[key]["note"] == "--inventory-only reads no file contents"
    assert list(phases["correlation"]["steps"]) == ["inventory_aggregates", "architecture"]
    assert "| Hashing | skipped | - | 0.0 s | skipped: --inventory-only reads no file contents |" in (
        output / "discovery-report.md").read_text(encoding="utf-8")
