from pathlib import Path
from project_discovery.scanner import discover_files

def test_discovers_files_and_prunes_generated_dirs(tmp_path: Path):
    (tmp_path/"main.py").write_text("print('hello')",encoding="utf-8")
    (tmp_path/"node_modules").mkdir()
    (tmp_path/"node_modules"/"hidden.js").write_text("x",encoding="utf-8")
    records,stats = discover_files(tmp_path,max_file_bytes=1024)
    assert [r.path for r in records] == ["main.py"]
    assert stats["total_bytes"] > 0

def test_oversized_file_is_inventoried_but_marked(tmp_path: Path):
    (tmp_path/"large.bin").write_bytes(b"x"*20)
    records,_ = discover_files(tmp_path,max_file_bytes=10)
    assert len(records) == 1
    assert records[0].error is not None


def test_discover_inventory_returns_directory_and_file_metadata(tmp_path: Path):
    from project_discovery.scanner import discover_inventory

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=redacted", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")

    files, directories, symlinks, stats = discover_inventory(
        tmp_path, max_file_bytes=1024,
    )

    assert [item.path for item in files] == [".env", "src/main.py"]
    assert directories[0].path == "."
    assert any(item.path == "node_modules" and item.pruned for item in directories)
    assert any(item.path == "src" and item.development_marker == "src" for item in directories)
    assert files[0].is_hidden
    assert files[1].file_type == "source"
    assert stats["entry_count"] == 5
    assert stats["development_directory_count"] == 2
    assert symlinks == []


def test_discover_inventory_large_file_skip_is_explicit(tmp_path: Path):
    from project_discovery.scanner import discover_inventory

    (tmp_path / "large.bin").write_bytes(b"x" * 128)
    normal, *_ = discover_inventory(tmp_path, max_file_bytes=16)
    skipped, _, _, stats = discover_inventory(
        tmp_path, max_file_bytes=16, skip_oversized=True,
    )

    assert normal[0].content_skipped_reason is None
    assert skipped[0].content_skipped_reason.startswith("Explicit --skip")
    assert stats["oversized_content_skipped"] == 1


def test_discover_inventory_records_symlinks_without_following_them(tmp_path: Path):
    from project_discovery.scanner import discover_inventory
    import pytest

    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlink creation is not available on this runner")

    files, directories, symlinks, stats = discover_inventory(
        tmp_path, max_file_bytes=1024,
    )

    assert not any(item.path.startswith("linked/") for item in files)
    assert not any(item.path == "linked" and not item.pruned for item in directories)
    assert len(symlinks) == 1
    assert symlinks[0].target_scope == "external"
    assert stats["entry_count"] == 1
