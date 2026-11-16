"""Large, sparse, changing and non-seekable files: a scan finishes, with bounded memory, and
names every file it could not read instead of reporting it as clean."""
from __future__ import annotations

import json
import os
import threading
import tracemalloc
from pathlib import Path

import pytest

from project_discovery import cli
from project_discovery.analyzers.environment.operating_systems import OperatingSystemAnalyzer
from project_discovery.core.source_utils import open_regular_descriptor, open_verified_binary
from project_discovery.inventory.scanner import _read_verified_sample, sha256_file

MIB = 1024 * 1024
POSIX = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs and device nodes are POSIX")


def _scan(project: Path, output: Path, **options) -> tuple[dict, int]:
    """Scan in this process (the thread executor) and return the report and the heap peak."""
    tracemalloc.start()
    try:
        assert cli.run_scan(project, output, {"json"}, 128, quiet=True, executor="thread", **options) == 0
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return json.loads((output / "discovery-report.json").read_text(encoding="utf-8")), peak


def _files(report: dict) -> dict[str, dict]:
    return {item["path"]: item for item in report["files"]}


def _within(seconds: float, function, fifos=()):
    """Run function in a thread; fail (instead of hanging the suite) if it blocks on a FIFO."""
    outcome: dict = {}

    def run():
        try:
            outcome["result"] = function()
        except BaseException as exc:  # handed back to the test thread below
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        for fifo in fifos:  # a writer releases a reader blocked in open()
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        worker.join(5)
        pytest.fail(f"still running after {seconds} s: blocked on a non-seekable file")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


def test_a_128_mib_text_file_is_analyzed_with_bounded_memory(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    # Lines longer than the 256 KiB per-line budgets keep the line-streaming analyzers cheap.
    line = b"a" * (300 * 1024 - 1) + b"\n"
    with (project / "big.txt").open("wb") as stream:
        stream.write(b"endpoint https://api.example.com/v1/users\n")
        for _ in range(128 * MIB // len(line) + 1):
            stream.write(line)
    size = (project / "big.txt").stat().st_size
    assert size > 128 * MIB
    # The regex scanners need 12-45 s for their 64 MiB byte budgets: a 5-second time budget
    # keeps the test short, after each has streamed several MiB (their steady state).
    report, peak = _scan(project, tmp_path / "out", analyzer_timeout=5)
    record = _files(report)["big.txt"]
    assert (record["size_bytes"], record["error"], record["analyzed"]) == (size, None, True)
    assert record["sha256"] and len(record["sha256"]) == 64  # hashed in full, in 1 MiB chunks
    # The analyzers read bounded chunks, lines and prefixes: the heap stays far below the file.
    assert peak < 64 * MIB, f"Python heap peak {peak / MIB:.0f} MiB for a {size / MIB:.0f} MiB file"
    # What a byte or time budget left unread is UNKNOWN coverage, never a clean result.
    partial = [item for item in report["findings"]
               if item["confidence"] == "UNKNOWN" and "big.txt" in item["evidence"]]
    assert partial, "no analyzer reported the part of the file past its budget"
    budgets = report["metrics"]["analysis_budgets"]
    assert budgets["analyzers"]["secret-patterns"]["calls"] == 1
    assert budgets["analyzers"]["secret-patterns"]["max_seconds_path"] == "big.txt"
    assert all(item["used"] < 30 for item in budgets["stopped"])  # each stop came close to its 5 s


def test_a_1_gib_sparse_file_is_inventoried_hashed_and_sampled_with_bounded_memory(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    with (project / "disk.img").open("wb") as stream:
        stream.truncate(1 << 30)  # sparse where the filesystem supports it; reads return zeros
    (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
    report, peak = _scan(project, tmp_path / "out")
    record = _files(report)["disk.img"]
    assert (record["size_bytes"], record["error"]) == (1 << 30, None)
    # Hashed in 1 MiB chunks; typed from a 4 KiB sample and its probes.
    assert record["sha256"] == "49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14"
    assert record["file_type"] == "binary/unknown" and record["type_source"] == "content"
    assert peak < 64 * MIB, f"Python heap peak {peak / MIB:.0f} MiB for a 1 GiB file"
    assert _files(report)["app.py"]["analyzed"]


def test_files_changed_after_inventory_are_refused_and_named(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    for name, content in (("grown.py", b"x = 1\n"), ("rewritten.py", b"y = 1\n"),
                          ("removed.py", b"z = 1\n"), ("stable.py", b"print('ok')\n")):
        (project / name).write_bytes(content)
    inventory = cli.discover_inventory

    def changing_inventory(*args, **kwargs):
        result = inventory(*args, **kwargs)
        with (project / "grown.py").open("ab") as stream:
            stream.write(b"x = 2\n")
        rewritten = project / "rewritten.py"
        before = rewritten.stat()
        rewritten.write_bytes(b"y = 2\n")  # the same size; a later modification time
        os.utime(rewritten, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
        (project / "removed.py").unlink()
        return result

    monkeypatch.setattr(cli, "discover_inventory", changing_inventory)
    report, _ = _scan(project, tmp_path / "out")
    files = _files(report)
    for name in ("grown.py", "rewritten.py"):
        # The identity check (size, times, inode) or the size/mtime check refuses it.
        assert "refusing analysis" in files[name]["error"]
        assert not files[name]["analyzed"] and files[name]["sha256"] is None
    assert files["removed.py"]["error"] and not files["removed.py"]["analyzed"]
    assert files["stable.py"]["error"] is None and files["stable.py"]["analyzed"]
    errors = "\n".join(report["errors"])
    assert all(f"{name}: " in errors for name in ("grown.py", "rewritten.py", "removed.py"))
    assert "stable.py" not in errors


def test_a_file_changed_while_it_is_analyzed_loses_its_findings(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "settings.py"
    target.write_bytes(b"import os\nDEBUG = True\n")
    (project / "stable.py").write_bytes(b"print('ok')\n")

    def rewrite_while_analyzing(self, path, record):
        if record.path == "settings.py":
            with target.open("ab") as stream:
                stream.write(b"EXTRA = 1\n")
        return []

    monkeypatch.setattr(OperatingSystemAnalyzer, "analyze", rewrite_while_analyzing)
    report, _ = _scan(project, tmp_path / "out")
    files = _files(report)
    assert "file identity changed during scan; refusing analysis" in files["settings.py"]["error"]
    assert not files["settings.py"]["analyzed"] and files["settings.py"]["sha256"] is None
    # Findings produced while the file changed are not trustworthy, so none is kept.
    assert not [item for item in report["findings"] if "settings.py" in item["evidence"]]
    assert files["stable.py"]["analyzed"]


@POSIX
def test_verified_reads_refuse_a_fifo_swapped_in_after_the_check_without_blocking(tmp_path: Path, monkeypatch):
    regular = tmp_path / "regular.txt"
    regular.write_bytes(b"data\n")
    fifo = tmp_path / "swapped"
    os.mkfifo(fifo)
    stale = os.lstat(regular)  # what a check made before the swap saw
    lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda self: stale if self == fifo else lstat(self))

    def opened_binary():
        with open_verified_binary(fifo):
            pass

    for read in (lambda: open_regular_descriptor(fifo), lambda: sha256_file(fifo, expected_info=stale),
                 lambda: _read_verified_sample(fifo, stale), opened_binary):
        with pytest.raises(OSError, match="entry changed to a non-regular file"):
            _within(10, read, [fifo])
    descriptor, opened = open_regular_descriptor(regular)
    try:
        assert os.get_blocking(descriptor) and os.read(descriptor, 16) == b"data\n"
    finally:
        os.close(descriptor)


@POSIX
def test_non_seekable_entries_and_files_replaced_by_them_never_block_a_scan(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    os.mkfifo(project / "pipe")
    (project / "to-pipe").symlink_to("pipe")
    (project / "zero").symlink_to("/dev/zero")
    (project / "later-a-pipe.txt").write_bytes(b"plain text\n")
    (project / "app.py").write_bytes(b"print('ok')\n")
    inventory = cli.discover_inventory

    def swapping_inventory(*args, **kwargs):
        result = inventory(*args, **kwargs)
        (project / "later-a-pipe.txt").unlink()
        os.mkfifo(project / "later-a-pipe.txt")
        return result

    monkeypatch.setattr(cli, "discover_inventory", swapping_inventory)
    report, _ = _within(120, lambda: _scan(project, tmp_path / "out"),
                        [project / "pipe", project / "later-a-pipe.txt"])
    files = _files(report)
    assert "refusing to analyze non-regular or symlink entry" in files["later-a-pipe.txt"]["error"]
    assert files["app.py"]["analyzed"] and "pipe" not in files and "zero" not in files
    assert {item["path"]: item["entry_type"] for item in report["special_entries"]}["pipe"] == "fifo"
    assert {item["path"] for item in report["symlinks"]} >= {"to-pipe", "zero"}
