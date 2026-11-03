import io
import stat
import tarfile
import zipfile
from pathlib import Path

from project_discovery.analyzers.archive_analyzer import ArchiveIntelligenceAnalyzer
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
