from pathlib import Path

import pytest

from project_discovery.source_utils import (
    SourceBudgetExceeded,
    read_python_source_bounded,
)


def test_bounded_reader_honors_pep263_encoding_cookie(tmp_path: Path):
    path = tmp_path / "latin_source.py"
    path.write_bytes(
        b"# -*- coding: latin-1 -*-\n"
        + b"value = 'caf" + bytes([0xE9]) + b"'\n"
    )
    source = read_python_source_bounded(path, 128)
    assert "café" in source


def test_bounded_reader_raises_when_source_exceeds_budget(tmp_path: Path):
    path = tmp_path / "large_source.py"
    path.write_bytes(b"x" * 33)
    with pytest.raises(SourceBudgetExceeded, match="32-byte parser budget"):
        read_python_source_bounded(path, 32)


def test_bounded_reader_rejects_non_positive_budget(tmp_path: Path):
    path = tmp_path / "source.py"
    path.write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="positive"):
        read_python_source_bounded(path, 0)
