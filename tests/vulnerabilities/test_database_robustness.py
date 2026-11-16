"""The advisory database under stress: damage and recovery, interrupted imports, duplicate IDs,
re-imports and withdrawals, version boundaries and prereleases, malformed records and a large
local feed."""
from __future__ import annotations

import json
import sys
import time
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.dependencies.lockfile_parsers import ResolvedPackage
from project_discovery.analyzers.dependencies.vulnerabilities import _affected_version, match_advisories
from project_discovery.vulnerabilities import database as database_module
from project_discovery.vulnerabilities.database import VulnerabilityDatabase


def _record(identifier: str, name: str = "demo", modified: str = "2024-01-01T00:00:00Z", **extra) -> dict:
    return {"id": identifier, "modified": modified, "summary": extra.pop("summary", identifier), **extra,
            "affected": extra.get("affected") or [{"package": {"ecosystem": "npm", "name": name}, "versions": ["1.0.0"]}]}


def _feed(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def test_damaged_databases_are_reported_and_a_new_file_recovers(tmp_path: Path, monkeypatch, capsys):
    feed = _feed(tmp_path / "feed.json", [_record(f"OSV-{i}", f"pkg{i}", summary="x" * 2000) for i in range(2000)])
    damaged = tmp_path / "damaged.sqlite3"
    with VulnerabilityDatabase(damaged) as store:
        store.import_osv(feed)
    data = bytearray(damaged.read_bytes())
    data[len(data) // 2:len(data) // 2 + 8192] = b"\xab" * 8192
    damaged.write_bytes(bytes(data))
    with VulnerabilityDatabase(damaged, read_only=True) as store:
        assert store.integrity()  # SQLite's own words for the damage
    from project_discovery import cli

    monkeypatch.setattr(sys, "argv", ["pdt", "vuln-db", "status", "--db", str(damaged)])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == cli.EXIT_USAGE and "The database is damaged" in capsys.readouterr().out
    # A file that is not a database at all, or is cut short, is named with the remedy.
    for name, content in (("garbage.sqlite3", b"not a database" * 100), ("cut.sqlite3", damaged.read_bytes()[:50])):
        (tmp_path / name).write_bytes(content)
        with pytest.raises(ValueError, match="not a .*PDT advisory database"):
            VulnerabilityDatabase(tmp_path / name, read_only=True)
    # Recovery: the snapshot imports into a new file, whole.
    with VulnerabilityDatabase(tmp_path / "new.sqlite3") as store:
        assert store.import_osv(feed)["imported_advisories"] == 2000 and store.integrity() == []


def test_an_interrupted_import_leaves_the_previous_snapshot(tmp_path: Path, monkeypatch):
    path = tmp_path / "db.sqlite3"
    with VulnerabilityDatabase(path) as store:
        store.import_osv(_feed(tmp_path / "v1.json", [_record("OSV-OLD")]))
        before = store.status()
    calls = {"count": 0}
    original = VulnerabilityDatabase._store_advisory

    def interrupted(self, data, relative):
        calls["count"] += 1
        if calls["count"] > 600:  # well past any batch: nothing of this import may stay
            raise KeyboardInterrupt
        return original(self, data, relative)

    monkeypatch.setattr(VulnerabilityDatabase, "_store_advisory", interrupted)
    with VulnerabilityDatabase(path) as store, pytest.raises(KeyboardInterrupt):
        store.import_osv(_feed(tmp_path / "v2.json", [_record(f"OSV-{i}", f"p{i}") for i in range(1000)]))
    with VulnerabilityDatabase(path, read_only=True) as store:
        after = store.status()
        assert after["advisory_count"] == before["advisory_count"] == 1
        assert after["last_imported_at"] == before["last_imported_at"] and store.integrity() == []


def test_duplicate_ids_reimports_and_withdrawals(tmp_path: Path):
    package = ResolvedPackage("npm", "demo", "1.0.0")
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as store:
        # In one import: the copy modified later wins, whatever the file order.
        result = store.import_osv(_feed(tmp_path / "a" / "feed.json", [
            _record("GHSA-dup", modified="2024-05-01T00:00:00Z", summary="newer"),
            _record("GHSA-dup", modified="2024-01-01T00:00:00Z", summary="older")]))
        assert (result["imported_advisories"], result["superseded_records"]) == (1, 1)
        assert [item["summary"] for item in store.query("npm", "demo")] == ["newer"]
        # Same time: the later copy wins, and a re-import changes nothing.
        store.import_osv(_feed(tmp_path / "b" / "feed.json", [_record("GHSA-dup", modified="2024-05-01T00:00:00Z",
                                                                         summary="same time, later file")]))
        first = store.status()
        store.import_osv(tmp_path / "b" / "feed.json")
        assert store.status()["affected_package_records"] == first["affected_package_records"] == 1
        assert [item["summary"] for item in store.query("npm", "demo")] == ["same time, later file"]
        assert len(match_advisories(package, store.query("npm", "demo"))) == 1
        # A newer copy that withdraws the advisory ends the match.
        store.import_osv(_feed(tmp_path / "c" / "feed.json", [_record(
            "GHSA-dup", modified="2024-06-01T00:00:00Z", withdrawn="2024-06-01T00:00:00Z")]))
        assert match_advisories(package, store.query("npm", "demo")) == []


@pytest.mark.parametrize(("ecosystem", "version", "events", "expected"), [
    ("npm", "1.0.0", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], True),       # introduced is inclusive
    ("npm", "2.0.0", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], False),      # fixed is exclusive
    ("npm", "1.5.0", [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}], True),  # last_affected is inclusive
    ("npm", "1.5.1", [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}], False),
    ("npm", "3.0.0", [{"introduced": "0"}, {"limit": "3.0.0"}], False),          # limit is exclusive
    ("npm", "0.0.1", [{"introduced": "0"}, {"fixed": "1.0.0"}], True),
    # Prereleases sort before their release.
    ("npm", "2.0.0-rc.1", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], True),
    ("npm", "1.0.0-beta", [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], False),
    ("PyPI", "2.0rc1", [{"introduced": "0"}, {"fixed": "2.0"}], True),
    ("PyPI", "2.0.post1", [{"introduced": "0"}, {"fixed": "2.0"}], False),
    ("Maven", "1.0-SNAPSHOT", [{"introduced": "0"}, {"fixed": "1.0"}], True),
    ("RubyGems", "2.0.0.beta.2", [{"introduced": "0"}, {"fixed": "2.0.0"}], True),
    # Two intervals: between them is not affected.
    ("npm", "1.5.0", [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}], False),
    ("npm", "2.0.5", [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}], True),
])
def test_boundary_versions_and_prereleases(ecosystem, version, events, expected):
    range_type = "SEMVER" if ecosystem == "npm" else "ECOSYSTEM"
    affected = {"package": {"ecosystem": ecosystem, "name": "x"}, "ranges": [{"type": range_type, "events": events}]}
    assert _affected_version(version, affected, ecosystem)[0] is expected


def test_malformed_records_are_skipped_or_unknown_and_never_raise(tmp_path: Path):
    records = [
        {"id": "OK-1", "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.0.0"]}]},
        {"id": "NO-AFFECTED"},
        {"affected": [{"package": {"ecosystem": "npm", "name": "demo"}}]},  # no ID
        {"id": "BAD-PACKAGE", "affected": [{"package": "npm/demo"}, {"package": {"ecosystem": "npm"}}]},
        {"id": "ODD-EVENTS", "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": None}, {"fixed": 7}, "junk"]},
            {"type": "SEMVER", "events": "not a list"}]}]},
        {"id": "HUGE", "summary": "s" * 50_000, "details": "d" * 500_000,
         "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["9.9.9"]}]},
        ["a", "list", "in", "a", "list"],
        {"id": "DEEP", "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "database_specific":
                                     json.loads("[" * 50 + "]" * 50)}]},
    ]
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as store:
        result = store.import_osv(_feed(tmp_path / "feed.json", records))
        assert result["imported_advisories"] >= 3 and result["skipped_records"] >= 3
        advisories = store.query("npm", "demo")
        by_id = {item["id"]: item for item in advisories}
        assert len(by_id["HUGE"]["summary"]) <= 4000 and len(by_id["HUGE"]["details"]) <= 100_000
        package = ResolvedPackage("npm", "demo", "1.0.0")
        verdicts = {advisory["id"]: confirmed for advisory, confirmed, _ in match_advisories(package, advisories)}
        assert verdicts.get("OK-1") is True
        assert "ODD-EVENTS" not in verdicts or verdicts["ODD-EVENTS"] is False  # unreadable bounds: never confirmed


def test_a_large_local_feed_imports_and_queries_quickly(tmp_path: Path):
    bundle = tmp_path / "all.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index in range(20_000):
            archive.writestr(f"npm/OSV-{index}.json", json.dumps(_record(
                f"OSV-{index}", f"pkg{index % 4000}", affected=[{"package": {"ecosystem": "npm", "name": f"pkg{index % 4000}"},
                                                                 "ranges": [{"type": "SEMVER", "events": [
                                                                     {"introduced": "0"}, {"fixed": f"{index % 7 + 1}.0.0"}]}]}])))
    started = time.monotonic()
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as store:
        result = store.import_osv(bundle)
        imported_in = time.monotonic() - started
        assert result["imported_advisories"] == 20_000 and result["affected_package_records"] == 20_000
        started = time.monotonic()
        for index in range(0, 4000, 40):
            assert len(store.query("npm", f"pkg{index}")) == 5
        queried_in = time.monotonic() - started
    assert imported_in < 120 and queried_in < 10, (imported_in, queried_in)
    assert database_module.MAX_DOCUMENT_BYTES >= 1024 * 1024 * 1024
