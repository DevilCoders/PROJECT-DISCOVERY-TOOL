"""Archive inspection records: states, coverage and limits per archive, and every member's metadata."""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tarfile
import warnings
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.content import archives
from project_discovery.analyzers.content.archives import ArchiveIntelligenceAnalyzer
from project_discovery.engine import budgets
from project_discovery.engine.budgets import BudgetPolicy
from project_discovery.engine.executor import FileOutcome, _run_analyzers
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord

_MEMBER_FIELDS = ("ordinal", "path", "type", "size", "compressed_size", "mode", "mtime", "flags", "link_target",
                  "uid", "gid", "owner", "group")


def _record(path: Path, file_type: str) -> FileRecord:
    return FileRecord(path.name, path.stat().st_size, "".join(path.suffixes).lower(), "Archive", file_type=file_type)


def _inspect(path: Path, file_type: str = "archive/zip"):
    """Analyze one archive; returns (its summary, its member records by path, the findings)."""
    with collecting_facts() as facts:
        findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, file_type))
    [(archive_format, state, states, detail)] = facts.archives
    summary = {"format": archive_format, "state": state, "states": states.split(","), **json.loads(detail)}
    members = {}
    for row in facts.archive_members:
        item = dict(zip(_MEMBER_FIELDS, row, strict=True))
        item["flags"] = item["flags"].split(",") if item["flags"] else []
        members.setdefault(item["path"], []).append(item)
    return summary, members, findings


def test_a_zip_records_every_members_type_sizes_mode_time_flags_and_link_target(tmp_path: Path):
    path = tmp_path / "app.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # zipfile warns about the duplicate name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(zipfile.ZipInfo("src/", date_time=(2023, 1, 2, 3, 4, 6)), b"")
            source = zipfile.ZipInfo("src/main.py", date_time=(2024, 5, 6, 7, 8, 10))
            source.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(source, "print('hello')\n")
            escape = zipfile.ZipInfo("../escape.sh")
            escape.external_attr = (stat.S_IFREG | stat.S_ISUID | 0o755) << 16
            archive.writestr(escape, "#!/bin/sh\n")
            link = zipfile.ZipInfo("current")
            link.create_system, link.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "src/main.py")
            archive.writestr("bomb.bin", b"\0" * (4 * 1024 * 1024), compress_type=zipfile.ZIP_DEFLATED)
            archive.writestr("notes.txt", "one")
            archive.writestr("notes.txt", "two")
    summary, members, _ = _inspect(path)
    assert (summary["format"], summary["state"]) == ("zip", "metadata-complete")
    assert summary["states"] == ["detected", "index-read", "metadata-complete", "sample-read", "sample-truncated"]
    assert (summary["members_declared"], summary["members_indexed"], summary["member_coverage_pct"]) == (7, 7, 100.0)
    assert summary["member_records"] == 7 and summary["compressed_bytes"] > 0
    # The 4 MiB member is sampled only up to the per-member budget.
    assert summary["limits"] == [{"limit": "member_sample_bytes", "value": archives._MAX_MEMBER_SCAN_BYTES, "members": 1}]
    assert 0 < summary["content_coverage_pct"] < 100
    [directory] = members["src/"]
    assert (directory["type"], directory["mtime"]) == ("directory", "2023-01-02T03:04:06")
    [source] = members["src/main.py"]
    assert (source["type"], source["size"], source["mode"], source["mtime"], source["flags"]) == (
        "file", 15, 0o644, "2024-05-06T07:08:10", [])
    [escape] = members["../escape.sh"]
    assert escape["mode"] == 0o4755 and escape["flags"] == ["unsafe-path", "setuid"]
    [link] = members["current"]
    assert (link["type"], link["link_target"]) == ("symlink", "src/main.py")
    [bomb] = members["bomb.bin"]
    assert bomb["flags"] == ["high-ratio"] and bomb["size"] == 4 * 1024 * 1024 and bomb["compressed_size"] < 10_000
    assert [item["flags"] for item in members["notes.txt"]] == [["duplicate"], ["duplicate"]]
    assert [item["ordinal"] for item in members["notes.txt"]] == [5, 6]


def test_an_encrypted_zip_member_is_flagged_and_not_sampled(tmp_path: Path):
    path = tmp_path / "secret.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("plain.txt", "visible")
        archive.writestr("locked.txt", "ciphertext-stand-in")
    # Set the "encrypted" bit in both headers, as an encrypting tool would.
    data = bytearray(path.read_bytes())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = data.rfind(signature)
        data[position + offset] |= 0x01
    path.write_bytes(bytes(data))
    summary, members, _ = _inspect(path)
    assert "encrypted" in summary["states"] and summary["encrypted_members"] == 1
    assert members["locked.txt"][0]["flags"] == ["encrypted"]
    assert summary["members_sampled"] == 1  # only the plain member


def test_a_tar_records_owners_utc_times_links_special_entries_and_duplicates(tmp_path: Path):
    path = tmp_path / "rootfs.tar"
    with tarfile.open(path, "w") as archive:
        def add(name, kind=tarfile.REGTYPE, data=b"", **fields):
            member = tarfile.TarInfo(name)
            member.type, member.size = kind, len(data)
            member.mtime, member.uid, member.gid, member.uname, member.gname = 1_700_000_000, 1000, 50, "dev", "staff"
            for key, value in fields.items():
                setattr(member, key, value)
            archive.addfile(member, io.BytesIO(data) if data else None)

        add("etc/", tarfile.DIRTYPE, mode=0o755)
        add("etc/passwd", data=b"root:x:0:0\n", mode=0o644)
        add("bin/su", data=b"\x7fELF", mode=0o4755)
        add("etc/shadow-link", tarfile.SYMTYPE, linkname="../../etc/shadow")
        add("etc/passwd.hard", tarfile.LNKTYPE, linkname="etc/passwd")
        add("dev/console", tarfile.CHRTYPE, mode=0o600)
        add("etc/passwd", data=b"override\n", mode=0o644)
    summary, members, _ = _inspect(path, "archive/tar")
    assert (summary["format"], summary["state"]) == ("tar", "metadata-complete")
    assert (summary["members_declared"], summary["members_indexed"], summary["compressed_bytes"]) == (7, 7, None)
    [su] = members["bin/su"]
    assert (su["mode"], su["flags"], su["uid"], su["gid"], su["owner"], su["group"]) == (
        0o4755, ["setuid"], 1000, 50, "dev", "staff")
    assert su["mtime"] == "2023-11-14T22:13:20Z"
    [link] = members["etc/shadow-link"]
    assert (link["type"], link["link_target"], link["flags"]) == ("symlink", "../../etc/shadow", ["unsafe-path"])
    assert members["etc/passwd.hard"][0]["type"] == "hardlink"
    assert members["dev/console"][0]["type"] == "special"
    assert [item["flags"] for item in members["etc/passwd"]] == [["duplicate"], ["duplicate"]]


@pytest.mark.parametrize(("mode", "name"), [("w:gz", "tar+gzip"), ("w:bz2", "tar+bzip2"), ("w:xz", "tar+xz")])
def test_compressed_tars_name_their_compression(mode, name, tmp_path: Path):
    path = tmp_path / f"bundle.tar.{mode[2:]}"
    with tarfile.open(path, mode) as archive:
        data = b"x" * 10
        member = tarfile.TarInfo("a.txt")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    summary, members, _ = _inspect(path, "archive/tar")
    assert (summary["format"], summary["state"], summary["compressed_bytes"]) == (name, "metadata-complete",
                                                                               path.stat().st_size)
    assert members["a.txt"][0]["size"] == 10 and summary["content_coverage_pct"] == 100.0


def test_unsupported_and_malformed_archives_say_so(tmp_path: Path):
    seven = tmp_path / "disk.7z"
    seven.write_bytes(b"7z\xbc\xaf\x27\x1c" + bytes(64))
    summary, members, _ = _inspect(seven, "archive/7z")
    assert (summary["format"], summary["state"], summary["states"]) == ("7z", "unsupported", ["detected", "unsupported"])
    assert members == {} and summary["content_coverage_pct"] is None
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"PK\x03\x04" + b"garbage" * 20)
    summary, _, _ = _inspect(broken)
    assert summary["state"] == "malformed" and "trailer" in summary["error"]
    truncated = tmp_path / "cut.tar"
    with tarfile.open(truncated, "w") as archive:
        member = tarfile.TarInfo("big.bin")
        member.size = 100_000
        archive.addfile(member, io.BytesIO(b"y" * 100_000))
    truncated.write_bytes(truncated.read_bytes()[:20_000])
    summary, members, _ = _inspect(truncated, "archive/tar")
    assert summary["state"] == "malformed" and "index-read" in summary["states"]


def test_every_limit_that_stops_an_archive_is_recorded(tmp_path: Path, monkeypatch):
    path = tmp_path / "many.tar"
    with tarfile.open(path, "w") as archive:
        for index in range(5):
            data = b"z" * 300
            member = tarfile.TarInfo(f"file{index}.txt")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_ENTRIES", 3)
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_SCAN_BYTES", 500)
    summary, members, _ = _inspect(path, "archive/tar")
    assert (summary["state"], summary["members_indexed"], summary["members_declared"]) == ("budget-stopped", 3, None)
    assert {"budget-stopped", "index-read", "sample-truncated"} <= set(summary["states"])
    assert "metadata-complete" not in summary["states"] and summary["member_coverage_pct"] is None
    assert {item["limit"]: item for item in summary["limits"]} == {
        "entries": {"limit": "entries", "value": 3},
        "archive_sample_bytes": {"limit": "archive_sample_bytes", "value": 500, "members": 2},
    }
    assert sorted(members) == ["file0.txt", "file1.txt", "file2.txt"]
    zipped = tmp_path / "wide.zip"
    with zipfile.ZipFile(zipped, "w") as archive:
        for index in range(5):
            archive.writestr(f"m{index}", "x")
    summary, members, _ = _inspect(zipped)
    # The declared entries exceed the budget: the index is not read at all.
    assert (summary["state"], summary["members_declared"], summary["members_indexed"]) == ("budget-stopped", 5, 0)
    assert summary["limits"] == [{"limit": "entries", "value": 3, "used": 5}] and members == {}
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_ENTRIES", 200_000)
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_WALL_SECONDS", 0.0)
    summary, _, _ = _inspect(zipped)
    assert summary["state"] == "budget-stopped" and [item["limit"] for item in summary["limits"]] == ["wall_seconds"]


def test_an_archive_the_engine_stops_is_recorded_as_budget_stopped(tmp_path: Path, monkeypatch):
    path = tmp_path / "slow.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("a.txt", "x")

    def spin(*_arguments, **_options):
        while True:
            sum(range(100))

    monkeypatch.setattr(archives, "_member_content_findings", spin)
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_WALL_SECONDS", 60.0)
    outcome = FileOutcome()
    budgets.set_policy(BudgetPolicy(0.2, None))
    try:
        with collecting_facts() as facts:
            _run_analyzers([ArchiveIntelligenceAnalyzer()], {}, _record(path, "archive/zip"), path, outcome)
    finally:
        budgets.set_policy(None)
    assert [kind for _, kind, *_ in outcome.budget_stops] == ["time"]
    [(archive_format, state, states, detail)] = facts.archives
    assert (archive_format, state, states) == ("zip", "budget-stopped", "detected,budget-stopped")
    [limit] = json.loads(detail)["limits"]
    assert limit["limit"] == "analyzer_time" and limit["value"] == 0.2
    assert facts.archive_members == []  # the stopped call's partial records were rolled back


def _project(root: Path) -> Path:
    (root / "lib").mkdir(parents=True)
    with zipfile.ZipFile(root / "lib" / "plugin.jar", "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
    with tarfile.open(root / "release.tar.gz", "w:gz") as archive:
        data = b"echo release\n"
        member = tarfile.TarInfo("bin/release.sh")
        member.size, member.mode = len(data), 0o755
        archive.addfile(member, io.BytesIO(data))
    (root / "image.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + bytes(32))
    return root


def test_a_scan_reports_archives_members_and_their_metrics(tmp_path: Path):
    from project_discovery.cli import run_scan

    project = _project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown", "html"}, 128, quiet=True, executor="thread") == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    by_path = {item["path"]: item for item in report["archives"]}
    assert {path: item["state"] for path, item in by_path.items()} == {
        "image.7z": "unsupported", "lib/plugin.jar": "metadata-complete", "release.tar.gz": "metadata-complete"}
    assert by_path["release.tar.gz"]["format"] == "tar+gzip"
    assert [(item["archive"], item["path"]) for item in report["archive_members"]] == [
        ("lib/plugin.jar", "META-INF/MANIFEST.MF"), ("lib/plugin.jar", "com/example/App.class"),
        ("release.tar.gz", "bin/release.sh")]
    metrics = report["metrics"]["archives"]
    assert (metrics["archives"], metrics["member_records"], metrics["member_records_dropped"]) == (3, 3, 0)
    assert metrics["by_state"] == {"metadata-complete": 2, "unsupported": 1}
    assert metrics["member_coverage_pct"] == 100.0 and metrics["content_coverage_pct"] == 100.0
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "## Archives" in markdown and "| image.7z | 7z | unsupported | 0 | - | - |" in markdown
    assert '"archives":[{' in (output / "discovery-report.html").read_text(encoding="utf-8")
    # --resume keeps one record per archive and member.
    assert run_scan(project, output, {"json"}, 128, quiet=True, executor="thread", resume=True) == 0
    again = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert (len(again["archives"]), len(again["archive_members"])) == (3, 3)


def test_the_scan_keeps_at_most_its_member_record_ceiling(tmp_path: Path, monkeypatch):
    from project_discovery.cli import run_scan
    from project_discovery.inventory import store

    table = store._CODE_TABLES["archive_members"]
    monkeypatch.setitem(store._CODE_TABLES, "archive_members", (*table[:3], 2))
    project = _project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, quiet=True, executor="thread") == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    metrics = report["metrics"]["archives"]
    assert (metrics["member_records"], metrics["member_records_dropped"], metrics["records_truncated"]) == (
        2, 1, ["archive_members"])
    assert len(report["archive_members"]) == 2
    # An archive table at its ceiling is not a code-index truncation.
    assert "archive_members" not in json.dumps(report["metrics"]["code_index"].get("truncated", {}))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX names may hold bytes that are not UTF-8")
def test_undecodable_member_names_are_stored_with_backslash_escapes(tmp_path: Path):
    path = tmp_path / "names.tar"
    with tarfile.open(path, "w", encoding="utf-8", errors="surrogateescape") as archive:
        member = tarfile.TarInfo(os.fsdecode(b"bad-\xff-name.txt"))
        archive.addfile(member, io.BytesIO(b""))
    with tarfile.open(path, "r", encoding="utf-8", errors="surrogateescape") as archive:
        assert any("\udcff" in name for name in archive.getnames())
    _, members, _ = _inspect(path, "archive/tar")
    # The reader decodes the byte as a lone surrogate; the record keeps it as an escape.
    assert list(members) == ["bad-\\udcff-name.txt"]
