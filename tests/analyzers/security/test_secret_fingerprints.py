"""Keyed fingerprints of secret values (--fingerprint-key) and the report of reused secrets; and
the rules a worker process must receive from the coordinator (fingerprint key, VEX, triage)."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from project_discovery.cli import run_scan
from project_discovery.core import fingerprints
from project_discovery.vulnerabilities.database import VulnerabilityDatabase
from project_discovery.vulnerabilities.triage import load_triage

KEY = b"0123456789abcdef-test-key"
SECRET = "Kq8vT2mZp9wXy7Lr"


def test_keys_load_and_fingerprints_are_keyed(tmp_path: Path):
    key_file = tmp_path / "key"
    key_file.write_bytes(KEY + b"\n")
    assert fingerprints.load_fingerprint_key(key_file) == (KEY, "file")
    assert fingerprints.load_fingerprint_key(None, {"PDT_FINGERPRINT_KEY": KEY.decode()}) == (KEY, "environment")
    assert fingerprints.load_fingerprint_key(None, {}) is None
    key_file.write_bytes(b"short")
    with pytest.raises(ValueError, match="at least 16 bytes"):
        fingerprints.load_fingerprint_key(key_file)
    try:
        fingerprints.configure_fingerprint_key(KEY)
        first = fingerprints.fingerprint(SECRET)
        assert first == fingerprints.fingerprint(SECRET) and first.startswith("hmac-sha256:") and len(first) == 28
        assert SECRET not in first and fingerprints.key_id() not in KEY.decode()
        fingerprints.configure_fingerprint_key(KEY + b"other")
        assert fingerprints.fingerprint(SECRET) != first  # another key, another fingerprint
        fingerprints.configure_fingerprint_key(None)
        assert fingerprints.fingerprint(SECRET) is None and fingerprints.key_id() is None
    finally:
        fingerprints.configure_fingerprint_key(None)


@pytest.mark.parametrize("executor", ["thread", "process"])
def test_reused_secrets_are_reported_by_fingerprint_and_never_by_value(tmp_path: Path, executor):
    project = tmp_path / "project"
    (project / "a").mkdir(parents=True)
    (project / "a" / "settings.env").write_text(f"DB_PASSWORD={SECRET}\n", encoding="utf-8")
    (project / "b.yaml").write_text(f"database:\n  password: {SECRET}\n", encoding="utf-8")
    (project / "c.ini").write_text("[x]\napi_token = Zz9Yy8Xx7Ww6Vv5U\n", encoding="utf-8")
    output = tmp_path / "out"
    run_scan(project, output, {"json", "markdown", "html"}, 1, quiet=True, executor=executor, jobs=2,
             fingerprint_key=(KEY, "file"))
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    secrets = [item for item in report["findings"] if item["title"].startswith("Potential hardcoded credential")]
    prints = {next(line for line in item["evidence"] if line.startswith("fingerprint:")) for item in secrets}
    assert len(secrets) == 3 and len(prints) == 2  # two findings share one value
    reused, = [item for item in report["findings"] if item["title"] == "Secret value repeated in 2 places"]
    assert {line.split(" (")[0] for line in reused["evidence"][1:]} == {"a/settings.env:1", "b.yaml:2"}
    assert report["metrics"]["secret_fingerprints"] == {
        "enabled": True, "key_id": fingerprints.key_id(KEY), "source": "file"}
    # Neither the value nor the key is anywhere in the output: reports, caches, stores.
    for path in output.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert SECRET.encode() not in data and KEY not in data, path
    run_scan(project, tmp_path / "plain", {"json"}, 1, quiet=True)
    plain = json.loads((tmp_path / "plain" / "discovery-report.json").read_text(encoding="utf-8"))
    assert plain["metrics"]["secret_fingerprints"] == {"enabled": False}
    assert not any(line.startswith("fingerprint:") for item in plain["findings"] for line in item["evidence"])


def test_worker_processes_apply_the_coordinators_triage_decisions(tmp_path: Path):
    # Regression: process workers rebuilt the advisory matcher from the database path alone,
    # so --vex and --triage were silently not applied to local findings in process mode.
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "osv.json").write_text(json.dumps({"id": "GHSA-aaaa-bbbb-cccc", "modified": "2024-01-01T00:00:00Z",
                                                "summary": "flaw", "affected": [{"package": {"ecosystem": "npm",
                                                "name": "lodash"}, "versions": ["4.17.20"]}]}), encoding="utf-8")
    database = tmp_path / "db.sqlite3"
    with VulnerabilityDatabase(database) as store:
        store.import_osv(feeds)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"}}}), encoding="utf-8")
    triage = tmp_path / "triage.toml"
    triage.write_text('[[decision]]\nadvisory = "GHSA-aaaa-bbbb-cccc"\nstatus = "mitigated"\nreason = "Patched in place."\n',
                      encoding="utf-8")
    run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, executor="process", jobs=2, vulnerability_db=database,
             triage=load_triage([triage], today=date(2026, 11, 16)))
    report = json.loads((tmp_path / "out" / "discovery-report.json").read_text(encoding="utf-8"))
    assert any(item["title"] == "Mitigated: GHSA-aaaa-bbbb-cccc: flaw" for item in report["findings"])
