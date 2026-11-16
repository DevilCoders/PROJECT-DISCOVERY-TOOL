"""Triage files (pdt scan --triage): offline decisions with their rationale and expiry."""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import pytest

from project_discovery.cli import run_scan
from project_discovery.vulnerabilities.database import VulnerabilityDatabase
from project_discovery.vulnerabilities.triage import load_triage, parse_triage, triage_decision

TODAY = date(2026, 11, 16)
TRIAGE = """
[[decision]]
advisory = "CVE-2021-23337"            # an alias of the GHSA record
package = "lodash"
status = "accepted"
reason = "Templates are constants; no request data reaches _.template."
expires = 2027-01-31
reviewer = "appsec"

[[decision]]
advisory = "GHSA-0003"
package = "qs"
status = "accepted"
reason = "Fixed in the next release."
expires = "2026-10-01"                  # lapsed

[[decision]]
advisory = "GHSA-9999"
status = "false_positive"
reason = "Not our package."
"""


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_triage_files_are_validated(tmp_path: Path):
    for text, message in (
        ('[[decision]]\nadvisory = "X"\nstatus = "accepted"\nreason = "r"\n', "needs an expires date"),
        ('[[decision]]\nadvisory = "X"\nstatus = "accepted"\nexpires = 2027-01-01\n', "reason is required"),
        ('[[decision]]\nadvisory = "X"\nstatus = "ignored"\nreason = "r"\n', "status must be one of"),
        ('[[decision]]\nadvisory = "X"\nstatus = "mitigated"\nreason = "r"\nowner = "me"\n', "unknown key(s) owner"),
        ('[[decision]]\nadvisory = "X"\nstatus = "mitigated"\nreason = "r"\nexpires = "soon"\n', "must be a date"),
        ('title = "x"\n', "no [[decision]] entries"),
        ("not = [toml", "not a TOML file"),
    ):
        with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("(", r"\(").replace(")", r"\)")):
            load_triage([_write(tmp_path / "t.toml", text)], today=TODAY)


def test_the_most_specific_decision_applies():
    decisions = parse_triage({"decision": [
        {"advisory": "GHSA-1", "status": "mitigated", "reason": "a"},
        {"advisory": "ghsa-1", "package": "lodash", "status": "mitigated", "reason": "b"},
        {"advisory": "GHSA-1", "package": "lodash", "version": "4.17.20", "status": "mitigated", "reason": "c"},
        {"advisory": "GHSA-1", "package": "lodash", "lockfile": "./web/package-lock.json", "status": "mitigated",
         "reason": "d"},
        {"advisory": "GHSA-1", "ecosystem": "PyPI", "status": "mitigated", "reason": "e"}]}, "t.toml")
    def reason(version: str, lockfile: str, ecosystem: str = "npm", name: str = "lodash") -> str:
        decision = triage_decision(decisions, ["GHSA-1"], ecosystem, name, version, lockfile)
        return decision.reason if decision else ""
    assert reason("4.17.20", "web/package-lock.json") == "d"
    assert reason("4.17.20", "package-lock.json") == "c"
    assert reason("4.17.19", "package-lock.json") == "b"
    assert reason("1.0.0", "package-lock.json", name="other") == "a"
    assert reason("1.0.0", "poetry.lock", ecosystem="PyPI", name="other") == "e"


def test_a_scan_applies_decisions_and_reports_lapsed_and_unused_ones(tmp_path: Path, monkeypatch, capsys):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "advisories.json").write_text(json.dumps([
        {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "modified": "2024-01-01T00:00:00Z",
         "summary": "lodash command injection", "database_specific": {"severity": "HIGH"},
         "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
        {"id": "GHSA-0003", "modified": "2024-01-01T00:00:00Z", "summary": "qs flaw",
         "database_specific": {"severity": "MODERATE"},
         "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "6.7.3"}]}]}]},
    ]), encoding="utf-8")
    database = tmp_path / "db.sqlite3"
    with VulnerabilityDatabase(database) as store:
        store.import_osv(feeds)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"lodash": "^4", "qs": "^6"}},
        "node_modules/lodash": {"version": "4.17.20"}, "node_modules/qs": {"version": "6.7.0"}}}), encoding="utf-8")
    triage_file = _write(tmp_path / "triage.toml", TRIAGE)
    output = tmp_path / "out"
    run_scan(project, output, {"json"}, 1, quiet=True, vulnerability_db=database,
             triage=load_triage([triage_file], today=TODAY))
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    findings = {item["title"]: item for item in report["findings"]}
    accepted = findings["Accepted risk: GHSA-35jh-r3h4-6jhm: lodash command injection"]
    assert accepted["severity"] == "INFO" and "triage: accepted until 2027-01-31 (triage.toml#1)" in accepted["evidence"]
    assert "Templates are constants" in accepted["detail"] and "reviewed by appsec" in accepted["detail"]
    assert accepted["recommendation"].startswith("Review the decision before it expires on 2027-01-31")
    lapsed = findings["GHSA-0003: qs flaw"]
    assert lapsed["severity"] == "MEDIUM" and "triage: accepted expired 2026-10-01 (triage.toml#2)" in lapsed["evidence"]
    assert "expired on 2026-10-01" in lapsed["detail"]
    unused = findings["Triage decisions that matched no finding: 1"]
    assert unused["evidence"] == ["triage.toml#3: GHSA-9999"]
    # The accepted risk is out of the remediation plan: one vulnerable package left, so no plan.
    assert not any(title.startswith("Remediation plan") for title in findings)
    assert report["metrics"]["vulnerability_intelligence"]["triage"] == {
        "documents": ["triage.toml"], "decisions": 3, "expired": 1, "as_of": "2026-11-16", "unused": 1,
        "sha256": load_triage([triage_file], today=TODAY).sha256}

    from project_discovery import cli

    for argv, message in ((["--triage", str(triage_file)], "--triage needs --vuln-db or --vuln-online"),
                          (["--vuln-db", str(database), "--triage", str(_write(tmp_path / "bad.toml", "x = 1\n"))],
                           "no [[decision]] entries")):
        monkeypatch.setattr(sys, "argv", ["pdt", "scan", str(project), "--output", str(tmp_path / "o2"), *argv])
        with pytest.raises(SystemExit) as stopped:
            cli.main()
        assert stopped.value.code == 2 and message in capsys.readouterr().err
