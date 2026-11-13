"""ZIP structure validation: local headers, data descriptors, truncation, overlap and entry counts."""
from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.content.archives import ArchiveIntelligenceAnalyzer
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord


class _Unseekable(io.RawIOBase):
    """A write-only stream zipfile cannot seek: it writes data descriptors, as streaming tools do."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, chunk) -> int:
        self.data.extend(chunk)
        return len(chunk)


def _streamed_zip(members: dict[str, bytes], *, zip64: bool = False) -> bytes:
    sink = _Unseekable()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            with archive.open(name, "w", force_zip64=zip64) as stream:
                stream.write(data)
    return bytes(sink.data)


def _inspect(tmp_path: Path, data: bytes, name: str = "app.zip"):
    path = tmp_path / name
    path.write_bytes(data)
    record = FileRecord(name, len(data), ".zip", "Archive", file_type="archive/zip")
    with collecting_facts() as facts:
        findings = ArchiveIntelligenceAnalyzer().analyze(path, record)
    [(_, _, state, states, detail)] = [item for item in facts.archives if item[0] == name]
    flags = {row[2]: row[8].split(",") if row[8] else [] for row in facts.archive_members if row[0] == name}
    return state, states.split(","), json.loads(detail), flags, {item.title for item in findings}


@pytest.mark.parametrize("zip64", [False, True])
def test_streamed_zips_with_data_descriptors_are_consistent(zip64, tmp_path: Path):
    data = _streamed_zip({"a.txt": b"alpha" * 100, "b/c.txt": b"bravo"}, zip64=zip64)
    assert data.count(b"PK\x07\x08") == 2  # zipfile wrote a descriptor after each member
    state, _, detail, flags, _ = _inspect(tmp_path, data)
    assert state == "metadata-complete" and "structure_issues" not in detail
    assert flags == {"a.txt": [], "b/c.txt": []}


def test_a_data_descriptor_that_disagrees_with_the_directory_is_flagged(tmp_path: Path):
    data = bytearray(_streamed_zip({"a.txt": b"alpha" * 100, "b.txt": b"bravo"}))
    first = data.find(b"PK\x07\x08")
    struct.pack_into("<L", data, first + 4, 0xDEADBEEF)  # the descriptor's CRC
    state, _, detail, flags, titles = _inspect(tmp_path, bytes(data))
    assert flags["a.txt"] == ["descriptor-mismatch"] and flags["b.txt"] == []
    assert detail["structure_issues"]["descriptor_mismatch"] == 1
    assert "ZIP local headers disagree with the central directory: app.zip" in titles


def _plain_zip(members: dict[str, bytes]) -> bytearray:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return bytearray(buffer.getvalue())


def _directory_entry(data: bytearray, name: bytes) -> int:
    """The offset of the central-directory entry for ``name``."""
    return next(position for position in range(len(data)) if data.startswith(b"PK\x01\x02", position)
                and data[position + 46:position + 46 + len(name)] == name)


def test_a_local_header_naming_another_file_is_flagged(tmp_path: Path):
    data = _plain_zip({"good.txt": b"one", "evil.txt": b"two"})
    local = data.find(b"PK\x03\x04")  # the first local header belongs to good.txt
    start = data.find(b"good.txt", local)
    data[start:start + 8] = b"gxod.txt"
    _, _, _, flags, titles = _inspect(tmp_path, bytes(data))
    assert flags["good.txt"] == ["header-mismatch"] and flags["evil.txt"] == []
    assert "ZIP local headers disagree with the central directory: app.zip" in titles


def test_overlapping_members_are_reported_as_a_zip_bomb_construction(tmp_path: Path):
    data = _plain_zip({"a.txt": b"x" * 64, "b.txt": b"y" * 64})
    entry = _directory_entry(data, b"b.txt")
    struct.pack_into("<L", data, entry + 42, 0)  # b.txt's local header offset: a.txt's
    state, _, detail, flags, titles = _inspect(tmp_path, bytes(data))
    assert "overlapping" in flags["a.txt"] and "overlapping" in flags["b.txt"]
    assert detail["structure_issues"]["overlapping"] == 2
    assert "Overlapping ZIP members: app.zip" in titles


def test_members_past_the_central_directory_mark_the_archive_malformed(tmp_path: Path):
    data = _plain_zip({"a.txt": b"x" * 64, "b.txt": b"y" * 64})
    entry = _directory_entry(data, b"b.txt")
    struct.pack_into("<L", data, entry + 20, 10_000_000)  # b.txt's compressed size
    state, states, detail, flags, titles = _inspect(tmp_path, bytes(data))
    assert "out-of-bounds" in flags["b.txt"] and state == "malformed" and "index-read" in states
    assert detail["error"] == "1 member(s) extend past the central directory or the end of the file"
    assert "Truncated or corrupt ZIP members: app.zip" in titles


def test_an_entry_count_that_disagrees_with_the_directory_is_reported(tmp_path: Path):
    data = _plain_zip({"a.txt": b"x", "b.txt": b"y"})
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<2H", data, end + 8, 3, 3)  # declares three entries; the directory holds two
    _, _, detail, _, titles = _inspect(tmp_path, bytes(data))
    assert (detail["declared_entries"], detail["members_declared"], detail["members_indexed"]) == (3, 3, 2)
    assert detail["member_coverage_pct"] == pytest.approx(66.7)
    assert "ZIP entry count disagrees with its central directory: app.zip" in titles
