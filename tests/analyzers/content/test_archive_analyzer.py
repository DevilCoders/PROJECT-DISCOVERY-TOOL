import io
import stat
import tarfile
import zipfile
from pathlib import Path

from project_discovery.analyzers.content.archives import ArchiveIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _record(path: Path, relative: str) -> FileRecord:
    return FileRecord(
        relative, path.stat().st_size, path.suffix.lower(), "Archive",
        file_type="archive/zip" if path.suffix == ".zip" else "archive/tar",
    )


def test_zip_metadata_path_traversal_symlink_and_encryption_indicators(tmp_path: Path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../escape.txt", "payload")
        archive.writestr("/absolute.txt", "payload")
        link = zipfile.ZipInfo("links/current")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
    before = path.read_bytes()
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "bundle.zip"))
    assert any("ZIP archive inventory" in item.title for item in findings)
    assert any("path traversal" in item.title for item in findings)
    assert any("symlink entries" in item.title for item in findings)
    assert path.read_bytes() == before


def test_tar_symlink_hardlink_and_parent_traversal_metadata(tmp_path: Path):
    path = tmp_path / "bundle.tar"
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("../escape.txt")
        member.size = 0
        archive.addfile(member, io.BytesIO())
        link = tarfile.TarInfo("links/current")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)
        hardlink = tarfile.TarInfo("links/hard")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "../outside"
        archive.addfile(hardlink)
    before = path.read_bytes()
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "bundle.tar"))
    assert any("TAR archive inventory" in item.title for item in findings)
    assert any("path traversal" in item.title for item in findings)
    assert any("symlink entries" in item.title for item in findings)
    assert path.read_bytes() == before


def test_archive_with_unsupported_metadata_format_is_identified(tmp_path: Path):
    path = tmp_path / "backup.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"metadata")
    findings = ArchiveIntelligenceAnalyzer().analyze(
        path,
        FileRecord("backup.7z", path.stat().st_size, ".7z", "Archive", file_type="archive/7z"),
    )
    assert findings[0].confidence == "CONFIRMED"
    assert "no extraction" in findings[0].detail



def test_zip_member_content_is_scanned_in_memory_with_redaction(tmp_path: Path):
    path = tmp_path / "secrets.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            ".env",
            "PASSWORD=super-secret-value\nEMAIL=person@example.test\n",
        )
    before = path.read_bytes()
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "secrets.zip"))
    assert any("Credential-Like Assignment inside archive member" in item.title for item in findings)
    assert any("Email-Shaped Value inside archive member" in item.title for item in findings)
    serialized = repr([item.to_dict() for item in findings])
    assert "super-secret-value" not in serialized
    assert "person@example.test" not in serialized
    assert "secrets.zip::.env" in serialized
    credential = next(item for item in findings if "Credential-Like Assignment" in item.title)
    email = next(item for item in findings if "Email-Shaped Value" in item.title)
    assert credential.code_evidence[0].line_number == 1
    assert "PASSWORD=" in credential.code_evidence[0].code
    assert "super-secret-value" not in credential.code_evidence[0].code
    assert credential.impact and credential.recommendation
    assert email.code_evidence[0].line_number == 2
    assert "person@example.test" not in email.code_evidence[0].code
    assert email.impact and email.recommendation
    assert path.read_bytes() == before
    assert not (tmp_path / ".env").exists()


def test_tar_member_content_is_scanned_without_extracting(tmp_path: Path):
    path = tmp_path / "credentials.tar"
    payload = b"API_KEY=AKIAABCDEFGHIJKLMNOP\n"
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("config/.env")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    before = path.read_bytes()
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "credentials.tar"))
    assert any("Provider Credential Token inside archive member" in item.title for item in findings)
    serialized = repr([item.to_dict() for item in findings])
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized
    assert "credentials.tar::config/.env" in serialized
    credential = next(item for item in findings if "Provider Credential Token" in item.title)
    assert credential.code_evidence[0].line_number == 1
    assert "AKIAABCDEFGHIJKLMNOP" not in credential.code_evidence[0].code
    assert credential.impact and credential.recommendation
    assert path.read_bytes() == before
    assert not (tmp_path / "config").exists()

def test_zip_central_directory_limit_is_checked_before_materializing_entries(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.content.archives as archive_module

    path = tmp_path / "many-entries.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one.txt", "1")
        archive.writestr("two.txt", "2")

    monkeypatch.setattr(archive_module, "_MAX_ARCHIVE_ENTRIES", 1)

    def forbidden_materialization(*args, **kwargs):
        raise AssertionError("ZipFile must not materialize an over-budget central directory")

    monkeypatch.setattr(archive_module.zipfile, "ZipFile", forbidden_materialization)
    findings = ArchiveIntelligenceAnalyzer()._zip(path, _record(path, "many-entries.zip"))
    assert findings[0].confidence == "UNKNOWN"
    assert "central-directory budget exceeded" in findings[0].title
    assert "declared entries: 2" in " ".join(findings[0].evidence)

def test_zip_index_is_not_materialized_when_preflight_bounds_are_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.content.archives as archive_module

    path = tmp_path / "unbounded-index.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one.txt", "small payload")

    monkeypatch.setattr(archive_module, "_zip_index_hint", lambda _path, *_identity: None)

    def forbidden_materialization(*args, **kwargs):
        raise AssertionError("ZipFile must not be opened after an unknown preflight")

    monkeypatch.setattr(archive_module.zipfile, "ZipFile", forbidden_materialization)
    findings = ArchiveIntelligenceAnalyzer()._zip(path, _record(path, "unbounded-index.zip"))
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "bounds unavailable" in findings[0].title

def test_zip_archive_wall_time_budget_returns_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.content.archives as archive_module

    path = tmp_path / "timed.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one.txt", "content")
    monkeypatch.setattr(archive_module, "_MAX_ARCHIVE_WALL_SECONDS", 0.0)
    findings = ArchiveIntelligenceAnalyzer()._zip(path, _record(path, "timed.zip"))
    assert any(item.confidence == "UNKNOWN" and "wall-time budget" in item.title for item in findings)


def test_tar_archive_wall_time_budget_returns_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.content.archives as archive_module

    path = tmp_path / "timed.tar"
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("one.txt")
        member.size = 7
        archive.addfile(member, io.BytesIO(b"content"))
    monkeypatch.setattr(archive_module, "_MAX_ARCHIVE_WALL_SECONDS", 0.0)
    findings = ArchiveIntelligenceAnalyzer()._tar(path, _record(path, "timed.tar"))
    assert any(item.confidence == "UNKNOWN" and "wall-time budget" in item.title for item in findings)


def test_archive_member_regex_matching_stops_at_wall_time_deadline():
    import project_discovery.analyzers.content.archives as archive_module

    findings, timed_out = archive_module._member_content_findings(
        "sample.zip",
        ".env",
        b"PASSWORD=secret-value\nEMAIL=person@example.test\n",
        deadline=0.0,
    )
    assert timed_out is True
    assert findings == []


def test_archive_member_matcher_reports_distinct_line_numbers_and_bounded_excerpts():
    import project_discovery.analyzers.content.archives as archive_module

    findings, timed_out = archive_module._member_content_findings(
        "sample.zip",
        ".env",
        (
            b"PASSWORD=secret-one\n"
            b"PASSWORD=secret-two\n"
            b"EMAIL=first@example.test\n"
            b"EMAIL=second@example.test\n"
        ),
    )
    assert timed_out is False
    credential = next(item for item in findings if item.category == "secrets")
    email = next(item for item in findings if item.category == "privacy")
    assert [line.line_number for line in credential.code_evidence] == [1, 2]
    assert [line.line_number for line in email.code_evidence] == [3, 4]
    assert all("secret-" not in line.code for line in credential.code_evidence)
    assert all("@example.test" not in line.code for line in email.code_evidence)


def _tar_bytes(members, mode="w"):
    import io as _io
    import tarfile as _tarfile

    buffer = _io.BytesIO()
    with _tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, payload, file_mode in members:
            info = _tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = file_mode
            archive.addfile(info, _io.BytesIO(payload))
    return buffer.getvalue()


def test_tar_members_after_a_large_member_are_still_inspected(tmp_path: Path):
    # Regression: traversal used to stop at the first member larger than the 1 MiB
    # sample, hiding later traversal and setuid entries while reporting CONFIRMED.
    path = tmp_path / "evil.tar"
    path.write_bytes(_tar_bytes([
        ("big.bin", b"\0" * (2 * 1024 * 1024), 0o644),
        ("../../etc/cron.d/evil", b"* * * * * root id\n", 0o644),
        ("bin/suid-shell", b"\x7fELF", 0o4755),
    ]))
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "evil.tar"))
    titles = [finding.title for finding in findings]
    assert any(title.startswith("Archive path traversal indicators") for title in titles)
    assert any(title.startswith("Risky archive permissions") for title in titles)
    inventory = next(finding for finding in findings if finding.title.startswith("TAR archive inventory"))
    assert "Indexed 3 member(s);" in inventory.detail


def test_compressed_tar_decompression_budget_is_enforced_inside_reads(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.content.archives as archive_module

    path = tmp_path / "bomb.tar.gz"
    path.write_bytes(_tar_bytes([
        ("zeros.bin", b"\0" * (8 * 1024 * 1024), 0o644),
        ("after.txt", b"late member", 0o644),
    ], mode="w:gz"))
    monkeypatch.setattr(archive_module, "_MAX_TAR_DECOMPRESSED_BYTES", 1024 * 1024)
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "bomb.tar.gz"))
    budget = [finding for finding in findings if "decompression budget" in finding.title]
    assert budget and budget[0].confidence == "UNKNOWN"
    assert "before a budget stopped traversal" in findings[0].detail


def test_case_and_unicode_colliding_member_names_are_reported(tmp_path: Path):
    path = tmp_path / "collide.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("README.txt", "a")
        archive.writestr("readme.TXT", "b")
        archive.writestr("caf\u00e9.txt", "c")
        archive.writestr("cafe\u0301.txt", "d")
    findings = ArchiveIntelligenceAnalyzer().analyze(path, _record(path, "collide.zip"))
    collision = next(finding for finding in findings if "colliding" in finding.title)
    assert len(collision.evidence) == 2
