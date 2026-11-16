"""What a scan keeps in memory per file and per report stays bounded as the corpus grows."""
from __future__ import annotations

import json
import sqlite3
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from project_discovery.analyzers import load_analyzers
from project_discovery.analyzers.security.secrets import _MAX_FINDINGS, SecretPatternAnalyzer
from project_discovery.cli import run_scan
from project_discovery.engine.executor import FileTask, analyze_tasks
from project_discovery.inventory.cache import ScanCache
from project_discovery.inventory.scanner import discover_inventory


def _tree(root: Path, scale: int) -> Path:
    for index in range(60 * scale):
        package = root / f"service{index % (3 * scale)}" / f"pkg{index % 7}"
        package.mkdir(parents=True, exist_ok=True)
        (package / f"module_{index}.py").write_text(
            f"import os\nimport requests\nfrom service0.pkg1 import module_{index + 1}\n"
            f"API = 'https://api{index}.example.com/v1'\nSECRET = os.environ.get('S{index}')\n"
            f"def handler_{index}(event):\n    return requests.get(API).json()\n", encoding="utf-8")
        if index % 10 == 0:
            (package / f"data_{index}.json").write_text(json.dumps({"id": index}), encoding="utf-8")
        if index % 25 == 0:
            with zipfile.ZipFile(package / f"bundle_{index}.zip", "w") as archive:
                archive.writestr("inner.txt", "x")
    for index in range(scale):
        node = root / f"web{index}" / "node_modules" / "left-pad"
        node.mkdir(parents=True, exist_ok=True)
        (node / "package.json").write_text('{"name": "left-pad", "version": "1.3.0"}', encoding="utf-8")
    return root


def _containers(value, path="metrics"):
    if isinstance(value, dict):
        yield path, len(value)
        for key, item in value.items():
            yield from _containers(item, f"{path}.{key}")
    elif isinstance(value, list):
        yield path, len(value)
        for item in value[:1]:
            yield from _containers(item, f"{path}[]")


# Store rows, streamed to the JSON report and capped in the HTML one.
_STORE_BACKED = {
    "metrics.architecture_layout.top_level_components",
    "metrics.python_dependency_graph.modules", "metrics.python_dependency_graph.edges",
    "metrics.python_dependency_graph.unresolved_imports", "metrics.python_dependency_graph.skipped_modules",
}


def test_report_metrics_do_not_grow_with_the_corpus(tmp_path: Path):
    sizes = {}
    for scale in (1, 4):
        output = tmp_path / f"out{scale}"
        assert run_scan(_tree(tmp_path / f"tree{scale}", scale), output, {"json"}, 128, quiet=True,
                        executor="thread", jobs=2) == 0
        report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
        assert len(report["files"]) >= 60 * scale
        sizes[scale] = dict(_containers(report["metrics"]))
    grown = {path: (sizes[1].get(path, 0), size) for path, size in sizes[4].items()
             if size > max(8, 2 * sizes[1].get(path, 0)) and path not in _STORE_BACKED}
    # Everything else is catalog-sized (types, languages, domains, analyzers) or capped.
    assert grown == {}
    assert sizes[4]["metrics.python_dependency_graph.modules"] >= 4 * sizes[1]["metrics.python_dependency_graph.modules"]


# Built by concatenation: no complete credential-shaped token appears in this source.
_TRIGGERS = (
    "API_KEY = '" + "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "'",
    "aws_access_key_id = " + "AKIA" + "Q3EXAMPLE7KEY9ZXCV",
    "DATABASE_URL = 'postgres://admin:" + "hunter2" + "@db.internal:5432/prod'",
    "url = 'https://api.example.com/v1/users?id=1'",
    "contact = 'jane.doe@example.com'  # phone +1-202-555-0143",
    "server = '10.0.12.7:8443'",
    "query = \"SELECT * FROM users WHERE id = \" + user_id",
    "os.system('rm -rf ' + path)",
    "@app.route('/admin/<id>', methods=['POST'])",
    "fetch('/api/orders/' + id)",
    "subprocess.call(cmd, shell=True)",
    "requests.get(url, verify=False)",
    "logging.info('ssn=123-45-6789 card=4111111111111111')",
)


def _per_file(tmp_path: Path, repeats: int) -> dict[str, tuple[int, int, int]]:
    root = tmp_path / f"files{repeats}"
    root.mkdir()
    for name in ("app.py", "notes.txt", "client.js", "config.yaml", "README.md"):
        (root / name).write_text("\n".join(f"{line}  # {index}" for index in range(repeats) for line in _TRIGGERS)
                                 + "\n", encoding="utf-8")
    records, *_ = discover_inventory(root, max_file_bytes=256 * 1024 * 1024)
    tasks = [FileTask(record, str(root / record.path), None, (root / record.path).lstat()) for record in records]
    measured: dict[str, list[int]] = {}
    for record, outcome in zip(records, analyze_tasks(load_analyzers().analyzers, {}, tasks), strict=True):
        for name, findings in Counter(item.analyzer for item in outcome.findings).items():
            evidence = [len(item.evidence) + len(item.code_evidence or ()) for item in outcome.findings
                        if item.analyzer == name]
            measured[f"{name} [{record.path}]"] = [findings, sum(evidence), max(evidence)]
    return {key: tuple(value) for key, value in measured.items()}


def test_every_analyzer_bounds_what_it_keeps_for_one_file(tmp_path: Path):
    small, large = _per_file(tmp_path, 40), _per_file(tmp_path, 240)  # about 500 and 3,100 trigger lines
    caps = {analyzer.name: (analyzer.limits.caps.get("findings") if analyzer.limits else None)
            for analyzer in load_analyzers().analyzers}
    unbounded = []
    for key, (findings, evidence, largest) in large.items():
        assert largest <= 500, key  # no single finding carries an unbounded evidence list
        name = key.split(" [", 1)[0]
        if caps.get(name) is not None and findings <= caps[name] + 1:
            continue  # within its declared per-file findings cap (the secret scanner's is tested below)
        before = small.get(key, (0, 0, 0))
        if findings > max(2 * before[0], before[0] + 20) or evidence > max(2 * before[1], before[1] + 200):
            unbounded.append((key, before, (findings, evidence)))
    assert unbounded == []


def test_the_secret_scanner_stops_listing_findings_at_its_cap(tmp_path: Path):
    path = tmp_path / "keys.txt"
    # Distinct key-shaped values, two per line: more matches than the per-file cap.
    path.write_text("\n".join(f"key_{index} = 'sk_live_{index:024d}' other = 'ghp_{index:036d}'"
                              for index in range(_MAX_FINDINGS // 2 + 500)), encoding="utf-8")
    [record], *_ = discover_inventory(tmp_path, max_file_bytes=64 * 1024 * 1024)
    [outcome] = analyze_tasks([SecretPatternAnalyzer()], {}, [FileTask(record, str(path), None, path.lstat())])
    assert _MAX_FINDINGS <= len(outcome.findings) <= _MAX_FINDINGS + 1
    assert ("secret-patterns", "findings") in {(name, kind) for name, kind, *_ in outcome.limit_hits}


def test_a_failing_fingerprint_cache_is_reported_once_and_every_file_is_still_hashed(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    for index in range(12):
        (project / f"f{index}.txt").write_text(f"file {index}\n", encoding="utf-8")

    def failing_put(self, *arguments):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(ScanCache, "put", failing_put)
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, quiet=True, executor="thread") == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert all(item["sha256"] for item in report["files"])
    assert [item for item in report["errors"] if "fingerprint cache write failed" in item] == [
        "fingerprint cache write failed (OperationalError: database or disk is full); later scans rehash these files"]


@pytest.mark.parametrize("count", [3, 45])
def test_skipped_lockfiles_are_counted_with_the_first_twenty_as_evidence(count, tmp_path: Path):
    from project_discovery.vulnerabilities.database import VulnerabilityDatabase

    project = tmp_path / "project"
    for index in range(count):
        folder = project / f"app{index:02d}"
        folder.mkdir(parents=True)
        (folder / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}' + " " * 2_000_000,
                                                 encoding="utf-8")
    database = tmp_path / "advisories.sqlite3"
    with VulnerabilityDatabase(database):
        pass
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True, skip_oversized=True, vulnerability_db=database) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    [finding] = [item for item in report["findings"] if item["title"].startswith("Lockfile(s) not checked")]
    assert finding["title"].endswith(f": {count:,}") and len(finding["evidence"]) == min(count, 20)
    assert report["metrics"]["vulnerability_intelligence"]["lockfiles_content_skipped"] == count
