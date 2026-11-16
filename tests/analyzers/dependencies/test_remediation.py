"""Fixed-version suggestions and remediation plans."""
from __future__ import annotations

import json
from pathlib import Path

from project_discovery.analyzers.dependencies.remediation import next_fixed, suggest_upgrade
from project_discovery.cli import run_scan
from project_discovery.vulnerabilities.database import VulnerabilityDatabase


def _advisory(identifier: str, *events: dict, ecosystem: str = "npm", name: str = "demo") -> dict:
    return {"id": identifier, "withdrawn": None, "ecosystem": ecosystem, "affected": {
        "package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": list(events)}]}}


def test_the_suggestion_is_the_lowest_release_no_known_advisory_affects():
    first = _advisory("A", {"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.0.3"})
    assert next_fixed("1.0.0", first["affected"], "npm") == "1.2.0"
    assert next_fixed("2.0.1", first["affected"], "npm") == "2.0.3"
    assert next_fixed("3.0.0", first["affected"], "npm") is None
    # 1.2.0 fixes A but B affects it: the suggestion moves on to B's fix, then C's.
    second = _advisory("B", {"introduced": "1.1.0"}, {"fixed": "1.4.0"})
    third = _advisory("C", {"introduced": "1.3.0"}, {"fixed": "1.5.2"})
    assert suggest_upgrade("1.0.0", [first, second, third], "npm") == ("1.5.2", [])
    # No recorded fix: named, not guessed.
    open_ended = _advisory("D", {"introduced": "0"})
    assert suggest_upgrade("1.0.0", [first, open_ended], "npm") == ("1.2.0", ["D"])
    assert suggest_upgrade("9.0.0", [first], "npm") == (None, [])
    # Each ecosystem's own order: Maven's 2.13.4.2 follows 2.13.4.
    maven = _advisory("M", {"introduced": "2.13.0"}, {"fixed": "2.13.4.2"}, ecosystem="Maven", name="g:a")
    assert suggest_upgrade("2.13.4", [maven], "Maven") == ("2.13.4.2", [])


def test_findings_name_the_upgrade_and_a_lockfile_gets_a_plan(tmp_path: Path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    records = [
        {"id": "GHSA-0001", "modified": "2024-01-01T00:00:00Z", "summary": "lodash flaw", "database_specific": {"severity": "HIGH"},
         "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
        # Not affecting 4.17.20, but 4.17.21: the suggestion must clear it too.
        {"id": "GHSA-0002", "modified": "2024-01-01T00:00:00Z", "summary": "lodash regression",
         "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.17.21"}, {"fixed": "4.17.23"}]}]}]},
        {"id": "GHSA-0003", "modified": "2024-01-01T00:00:00Z", "summary": "qs flaw", "database_specific": {"severity": "MODERATE"},
         "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.0.0"}, {"fixed": "6.7.3"}]}]}]},
        {"id": "GHSA-0004", "modified": "2024-01-01T00:00:00Z", "summary": "left-pad flaw",
         "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "versions": ["1.3.0"]}]},
    ]
    (feeds / "advisories.json").write_text(json.dumps(records), encoding="utf-8")
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as store:
        store.import_osv(feeds)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"express": "^4", "lodash": "^4", "left-pad": "^1"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0"}},
        "node_modules/qs": {"version": "6.7.0"}, "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/left-pad": {"version": "1.3.0"}}}), encoding="utf-8")
    run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, vulnerability_db=tmp_path / "db.sqlite3")
    report = json.loads((tmp_path / "out" / "discovery-report.json").read_text(encoding="utf-8"))
    lodash = next(item for item in report["findings"] if item["title"].startswith("GHSA-0001"))
    assert "suggested_upgrade: 4.17.23" in lodash["evidence"]
    assert lodash["recommendation"].startswith("Upgrade lodash from 4.17.20 to 4.17.23 or later")
    plan = next(item for item in report["findings"] if item["title"] == "Remediation plan: package-lock.json")
    assert (plan["severity"], plan["confidence"], plan["analyzer"]) == ("INFO", "INFERRED", "vulnerability-remediation")
    assert plan["evidence"][1:] == [
        "upgrade: lodash 4.17.20 -> 4.17.23 (fixes GHSA-0001; HIGH)",
        "upgrade through express@4.17.1: qs 6.7.0 -> 6.7.3 (fixes GHSA-0003; MEDIUM)",
        "no fix: left-pad 1.3.0: no recorded fix for GHSA-0004"]
    assert "upgrade the direct dependency that brings them in (express@4.17.1)" in plan["detail"]
