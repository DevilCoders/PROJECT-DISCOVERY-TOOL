from pathlib import Path

from project_discovery.scanner import discover_files, discover_inventory


def test_discovers_generated_dependency_trees_by_default(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "hidden.js").write_text("x", encoding="utf-8")
    records, stats = discover_files(tmp_path)
    assert {item.path for item in records} == {"main.py", "node_modules/hidden.js"}
    assert stats["total_bytes"] > 0
    assert stats["development_directory_count"] >= 1


def test_explicit_exclusion_prunes_matching_subtree_and_records_reason(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("pass", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "large.js").write_text("x", encoding="utf-8")
    files, directories, _, _, stats = discover_inventory(
        tmp_path, ignores={"node_modules"},
    )
    node_modules = next(item for item in directories if item.path == "node_modules")
    assert node_modules.pruned is True
    assert node_modules.prune_reason == "explicit --exclude-dir name: node_modules"
    assert {item.path for item in files} == {"src/main.py"}
    assert stats["pruned_directory_count"] == 1


def test_explicit_relative_path_exclusion_does_not_hide_other_same_named_tree(tmp_path: Path):
    for folder in ("apps/a/node_modules", "apps/b/node_modules"):
        (tmp_path / folder).mkdir(parents=True)
        (tmp_path / folder / "package.js").write_text("x", encoding="utf-8")
    files, directories, _, _, _ = discover_inventory(
        tmp_path, ignores={"apps/a/node_modules"},
    )
    assert "apps/a/node_modules/package.js" not in {item.path for item in files}
    assert "apps/b/node_modules/package.js" in {item.path for item in files}
    assert next(item for item in directories if item.path == "apps/a/node_modules").pruned
    assert not next(item for item in directories if item.path == "apps/b/node_modules").pruned


def test_oversized_file_is_content_skipped_only_when_explicit(tmp_path: Path):
    (tmp_path / "large.bin").write_bytes(b"x" * 20)
    normal, _ = discover_files(tmp_path, max_file_bytes=10)
    skipped, _ = discover_files(
        tmp_path, max_file_bytes=10, skip_oversized=True,
    )
    assert normal[0].content_skipped_reason is None
    assert skipped[0].content_skipped_reason.startswith("Explicit --skip")


def test_discover_inventory_returns_directory_and_file_metadata(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=redacted", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")

    files, directories, symlinks, special, stats = discover_inventory(tmp_path)

    by_path = {item.path: item for item in files}
    assert set(by_path) == {".env", "src/main.py", "node_modules/ignored.js"}
    assert directories[0].path == "."
    marker = next(item for item in directories if item.path == "node_modules")
    assert marker.development_marker == "node_modules"
    assert marker.pruned is False
    assert by_path[".env"].is_hidden
    assert by_path["src/main.py"].file_type == "source"
    assert stats["entry_count"] == 5
    assert stats["development_directory_count"] == 1
    assert symlinks == []
    assert special == []


def test_discover_inventory_large_file_skip_is_explicit(tmp_path: Path):
    (tmp_path / "large.bin").write_bytes(b"x" * 128)
    normal, *_ = discover_inventory(tmp_path, max_file_bytes=16)
    skipped, _, _, _, stats = discover_inventory(
        tmp_path, max_file_bytes=16, skip_oversized=True,
    )
    assert normal[0].content_skipped_reason is None
    assert skipped[0].content_skipped_reason.startswith("Explicit --skip")
    assert stats["oversized_content_skipped"] == 1


def test_discover_inventory_records_symlinks_without_following_them(tmp_path: Path):
    target = tmp_path.parent / f"{tmp_path.name}-outside"
    target.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("Directory symlink creation is not available on this runner")

    files, directories, symlinks, special, stats = discover_inventory(tmp_path)

    assert not any(item.path.startswith("linked/") for item in files)
    assert not any(item.path == "linked" for item in directories)
    assert len(symlinks) == 1
    assert symlinks[0].target_scope == "external"
    assert stats["symlink_count"] == 1
    assert special == []


def test_magic_bytes_override_generic_binary_classification(tmp_path: Path):
    cases = {
        "archive.zip": (b"PK\x03\x04" + b"0" * 20, "archive/zip"),
        "manual.pdf": (b"%PDF-1.7" + b"0" * 20, "document/pdf"),
        "image.png": (b"\x89PNG\r\n\x1a\n" + b"0" * 20, "image/png"),
        "program.elf": (b"\x7fELF" + b"0" * 20, "executable/elf"),
        "index.db": (b"SQLite format 3\x00" + b"0" * 20, "database/sqlite"),
    }
    for name, (payload, expected) in cases.items():
        (tmp_path / name).write_bytes(payload)
    files, *_ = discover_inventory(tmp_path)
    observed = {item.path: item.file_type for item in files}
    for name, (_, expected) in cases.items():
        assert observed[name] == expected


def test_directory_markers_cover_common_and_unusual_caches(tmp_path: Path):
    names = ("node_modules", ".cache", ".yarn", ".pnpm-store", ".fuff", ".fuzz", ".gradle", ".m2")
    for name in names:
        (tmp_path / name).mkdir()
    _, directories, _, _, stats = discover_inventory(tmp_path)
    markers = {item.development_marker for item in directories if item.development_marker}
    assert set(names) <= markers
    assert stats["development_directory_count"] == len(names)


def test_special_files_are_recorded_when_platform_supports_fifo(tmp_path: Path):
    import os
    import pytest

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO entries are not supported on this platform")
    fifo = tmp_path / "events.pipe"
    try:
        os.mkfifo(fifo)
    except OSError:
        pytest.skip("FIFO creation is not permitted on this runner")
    _, _, _, special, stats = discover_inventory(tmp_path)
    assert len(special) == 1
    assert special[0].path == "events.pipe"
    assert special[0].entry_type == "fifo"
    assert stats["special_type:fifo"] == 1

def test_symlink_scope_is_lexical_and_does_not_resolve_chained_links(tmp_path: Path):
    import pytest

    outside = tmp_path.parent / f"{tmp_path.name}-outside-target"
    outside.mkdir()
    chained = tmp_path / "chained"
    alias = tmp_path / "alias"
    try:
        chained.symlink_to(outside, target_is_directory=True)
        alias.symlink_to("chained", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not available on this runner")

    _, _, symlinks, _, _ = discover_inventory(tmp_path)
    alias_record = next(item for item in symlinks if item.path == "alias")
    assert alias_record.target_scope == "internal"
    assert alias_record.target_state == "unverified"

def test_discover_inventory_rejects_symlink_root_without_following_it(tmp_path: Path):
    import pytest

    real_root = tmp_path / "real-project"
    real_root.mkdir()
    (real_root / "source.txt").write_text("content", encoding="utf-8")
    link_root = tmp_path / "project-link"
    try:
        link_root.symlink_to(real_root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not available on this runner")

    with pytest.raises(ValueError, match="scan root itself is a symlink"):
        discover_inventory(link_root)

def test_python_inventory_fallback_remains_available_without_rust(tmp_path: Path, monkeypatch):
    import project_discovery.scanner as scanner

    root = tmp_path / "fallback-project"
    root.mkdir()
    (root / "main.py").write_text("print('fallback')\\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "native_create_walker", lambda *args, **kwargs: None)

    records, directories, _, _, stats = scanner.discover_inventory(root)
    assert [record.path for record in records] == ["main.py"]
    assert len(directories) == 1
    assert stats["entry_count"] == 1

def test_scandir_fallback_streams_fanout_but_keeps_deterministic_inventory_order(
    tmp_path: Path, monkeypatch,
):
    import project_discovery.scanner as scanner

    monkeypatch.setattr(scanner, "native_create_walker", lambda *args, **kwargs: None)
    for name in ("zeta.py", "alpha.py", "mu.py", "Beta.py"):
        (tmp_path / name).write_text("pass\n", encoding="utf-8")
    for name in ("z-dir", "a-dir", "m-dir"):
        (tmp_path / name).mkdir()

    files, directories, _, _, _ = scanner.discover_inventory(tmp_path)
    assert [item.path for item in files] == sorted(
        (item.path for item in files), key=str.casefold,
    )
    assert [item.path for item in directories] == [
        item.path for item in sorted(
            directories, key=lambda item: (item.depth, item.path.casefold()),
        )
    ]
    assert {item.path for item in files} == {
        "zeta.py", "alpha.py", "mu.py", "Beta.py",
    }




def test_inventory_output_order_is_deterministic_without_sorted_scandir_buffers(tmp_path: Path):
    # Create entries in deliberately non-lexical order. The scanner may consume
    # the OS directory iterator directly, but its public result order is stable.
    for name in ("zeta.py", "Alpha.py", "middle.py"):
        (tmp_path / name).write_text("pass\\n", encoding="utf-8")
    for name in ("zeta_dir", "Alpha_dir", "middle_dir"):
        (tmp_path / name).mkdir()

    files, directories, _, _, _ = discover_inventory(tmp_path)

    assert [item.path for item in files] == ["Alpha.py", "middle.py", "zeta.py"]
    assert [item.path for item in directories] == [
        ".", "Alpha_dir", "middle_dir", "zeta_dir",
    ]

def test_inventory_order_has_exact_path_tiebreak_for_casefold_collisions(
    tmp_path: Path, monkeypatch,
):
    import pytest
    import project_discovery.scanner as scanner

    monkeypatch.setattr(scanner, "native_create_walker", lambda *args, **kwargs: None)
    for name in ("A.py", "a.py", "ss.py", "ß.py"):
        try:
            (tmp_path / name).write_text("pass\n", encoding="utf-8")
        except OSError:
            pytest.skip("Filesystem cannot represent the casefold-collision fixture")
    if (tmp_path / "A.py").samefile(tmp_path / "a.py"):
        pytest.skip("Filesystem is case-insensitive for the ASCII collision fixture")
    files, _, _, _, _ = scanner.discover_inventory(tmp_path)
    paths = [item.path for item in files]
    expected = sorted(paths, key=lambda value: (value.casefold(), value))
    assert paths == expected
    assert len(paths) == 4

def test_signature_reader_rejects_symlink_entries(tmp_path: Path):
    import pytest
    from project_discovery.scanner import _read_signature_sample

    target = tmp_path / "target.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 32)
    link = tmp_path / "linked.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(OSError, match="non-regular"):
        _read_signature_sample(link)


def test_signature_reader_rejects_file_identity_changes(tmp_path: Path):
    import pytest
    from project_discovery.scanner import _read_signature_sample

    path = tmp_path / "sample.bin"
    path.write_bytes(b"first version")
    observed = path.stat()
    path.write_bytes(b"second version with changed identity")
    with pytest.raises(OSError, match="identity changed"):
        _read_signature_sample(path, observed)


def test_signature_reader_uses_bounded_descriptor_read(tmp_path: Path):
    from project_discovery.scanner import _read_signature_sample

    path = tmp_path / "large.bin"
    path.write_bytes(b"\x7fELF" + b"x" * (1024 * 1024))
    observed = path.stat()
    sample = _read_signature_sample(path, observed)
    assert sample == b"\x7fELF" + b"x" * 508
    assert len(sample) == 512

def test_sha256_file_uses_verified_no_follow_descriptor(tmp_path: Path):
    import hashlib
    import pytest
    from project_discovery.scanner import sha256_file

    target = tmp_path / "payload.bin"
    payload = b"static evidence" * 1000
    target.write_bytes(payload)
    observed = target.stat()
    assert sha256_file(target, chunk_size=97, expected_info=observed) == hashlib.sha256(
        payload
    ).hexdigest()

    link = tmp_path / "payload-link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(OSError, match="non-regular"):
        sha256_file(link)


def test_sha256_file_rejects_changed_identity_before_read(tmp_path: Path):
    import pytest
    from project_discovery.scanner import sha256_file

    path = tmp_path / "mutable.bin"
    path.write_bytes(b"original")
    observed = path.stat()
    path.write_bytes(b"replacement content")
    with pytest.raises(OSError, match="identity changed"):
        sha256_file(path, expected_info=observed)


def test_sha256_file_rejects_invalid_chunk_size(tmp_path: Path):
    import pytest
    from project_discovery.scanner import sha256_file

    path = tmp_path / "payload.bin"
    path.write_bytes(b"payload")
    with pytest.raises(ValueError, match="chunk_size"):
        sha256_file(path, chunk_size=0)




def test_sha256_file_uses_verified_no_follow_descriptor(tmp_path: Path):
    import hashlib
    import pytest
    from project_discovery.scanner import sha256_file

    source = tmp_path / "source.bin"
    payload = b"bounded hashing fixture" * 4096
    source.write_bytes(payload)
    observed = source.stat()
    assert sha256_file(source, chunk_size=127, expected_info=observed) == hashlib.sha256(
        payload
    ).hexdigest()

    link = tmp_path / "source-link.bin"
    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(OSError, match="non-regular"):
        sha256_file(link)


def test_sha256_file_rejects_changed_file_identity(tmp_path: Path):
    import pytest
    from project_discovery.scanner import sha256_file

    source = tmp_path / "changing.bin"
    source.write_bytes(b"before")
    observed = source.stat()
    source.write_bytes(b"after with a different length")
    with pytest.raises(OSError, match="identity changed"):
        sha256_file(source, expected_info=observed)


def test_sha256_file_rejects_invalid_chunk_size(tmp_path: Path):
    import pytest
    from project_discovery.scanner import sha256_file

    source = tmp_path / "small.bin"
    source.write_bytes(b"x")
    with pytest.raises(ValueError, match="chunk_size"):
        sha256_file(source, chunk_size=0)

def test_discover_inventory_persists_records_and_final_directory_aggregates(tmp_path: Path):
    from project_discovery.inventory_store import InventoryStore
    from project_discovery.scanner import discover_inventory

    root = tmp_path / "store-backed-project"
    root.mkdir()
    nested = root / "src"
    nested.mkdir()
    (nested / "main.py").write_text("print('stored')\n", encoding="utf-8")
    link = root / "source-link"
    try:
        link.symlink_to(nested / "main.py")
    except (OSError, NotImplementedError):
        link = None

    database = tmp_path / "inventory.sqlite3"
    with InventoryStore(database, batch_size=1) as store:
        files, directories, symlinks, special, stats = discover_inventory(root, store=store)
        assert store.integrity_check() == "ok"
        assert store.get_metadata("inventory_status") == "complete"
        counts = store.get_metadata("record_counts")
        assert counts == {
            "file": len(files),
            "directory": len(directories),
            "symlink": len(symlinks),
            "special": len(special),
        }
        persisted_file = next(store.iter_records("file"))
        assert persisted_file["path"] == "src/main.py"
        persisted_src = next(
            item for item in store.iter_records("directory") if item["path"] == "src"
        )
        assert persisted_src["file_count"] == 1
        assert persisted_src["total_bytes"] == len("print('stored')\n".encode())
        if link is not None:
            assert any(item["path"] == "source-link" for item in store.iter_records("symlink"))
        assert stats["entry_count"] >= 2


def test_inventory_store_is_reset_for_each_new_scan(tmp_path: Path):
    from project_discovery.inventory_store import InventoryStore
    from project_discovery.scanner import discover_inventory

    root = tmp_path / "project"
    root.mkdir()
    (root / "first.py").write_text("pass\n", encoding="utf-8")
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        discover_inventory(root, store=store)
        assert store.count("file") == 1
        (root / "first.py").unlink()
        (root / "second.py").write_text("pass\n", encoding="utf-8")
        discover_inventory(root, store=store)
        assert [item["path"] for item in store.iter_records("file")] == ["second.py"]

def test_inventory_checkpoint_is_partial_when_directory_traversal_fails(tmp_path: Path, monkeypatch):
    import project_discovery.scanner as scanner
    from project_discovery.inventory_store import InventoryStore

    root = tmp_path / "partial-project"
    root.mkdir()
    blocked = root / "blocked"
    blocked.mkdir()
    monkeypatch.setattr(scanner, "native_create_walker", lambda *args, **kwargs: None)
    real_scandir = scanner.os.scandir

    def controlled_scandir(path):
        if Path(path) == blocked:
            raise PermissionError("fixture permission failure")
        return real_scandir(path)

    monkeypatch.setattr(scanner.os, "scandir", controlled_scandir)
    with InventoryStore(tmp_path / "partial.sqlite3") as store:
        _, directories, _, _, stats = scanner.discover_inventory(root, store=store)
        assert stats["walk_errors"] == 1
        assert next(item for item in directories if item.path == "blocked").error
        assert store.get_metadata("inventory_status") == "partial"
        assert store.get_metadata("traversal_finished") is True
        assert store.get_metadata("walk_errors") == 1

def test_signature_reader_accepts_rust_walker_identity_tuple(tmp_path: Path):
    from project_discovery.scanner import _read_signature_sample

    path = tmp_path / "rust-walker.bin"
    path.write_bytes(b"\x7fELF" + b"r" * 600)
    info = path.stat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    assert _read_signature_sample(path, identity) == b"\x7fELF" + b"r" * 508


def test_signature_reader_rejects_rust_walker_identity_mismatch(tmp_path: Path):
    import pytest
    from project_discovery.scanner import _read_signature_sample

    path = tmp_path / "changed-after-walk.bin"
    path.write_bytes(b"first")
    info = path.stat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    path.write_bytes(b"second version")
    with pytest.raises(OSError, match="identity changed"):
        _read_signature_sample(path, identity)

