from pathlib import Path

from project_discovery.cache import ScanCache


def test_cache_roundtrip(tmp_path: Path):
    path = tmp_path / "cache.sqlite3"
    with ScanCache(path) as cache:
        assert cache.get("/repo", "a.py") is None
        cache.put("/repo", "a.py", 10, 20, 30, 40, "abc")
    with ScanCache(path) as cache:
        assert cache.get("/repo", "a.py") == (10, 20, 30, 40, "abc")


def test_cache_migrates_legacy_schema(tmp_path: Path):
    import sqlite3

    path = tmp_path / "legacy.sqlite3"
    db = sqlite3.connect(path)
    db.execute(
        """CREATE TABLE fingerprints (
            project_root TEXT NOT NULL, relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
            sha256 TEXT NOT NULL, PRIMARY KEY(project_root, relative_path)
        )"""
    )
    db.execute(
        "INSERT INTO fingerprints VALUES (?, ?, ?, ?, ?)",
        ("/repo", "legacy.py", 5, 10, "digest"),
    )
    db.commit()
    db.close()

    with ScanCache(path) as cache:
        assert cache.get("/repo", "legacy.py") == (5, 10, 0, 0, "digest")
        cache.put("/repo", "new.py", 6, 11, 12, 13, "new")
    with ScanCache(path) as cache:
        assert cache.get("/repo", "new.py") == (6, 11, 12, 13, "new")


def test_cache_prunes_removed_paths_without_parameter_limit(tmp_path: Path):
    path = tmp_path / "cache.sqlite3"
    with ScanCache(path) as cache:
        for index in range(1200):
            cache.put("/repo", f"src/file_{index}.py", 1, 1, 1, index, str(index))
        removed = cache.prune_missing(
            "/repo", [f"src/file_{index}.py" for index in range(1000)]
        )
        assert removed == 200
        assert cache.get("/repo", "src/file_1199.py") is None
        assert cache.get("/repo", "src/file_999.py") is not None


def test_cache_pruning_is_scoped_to_project_root(tmp_path: Path):
    with ScanCache(tmp_path / "cache.sqlite3") as cache:
        cache.put("/repo-a", "a.py", 1, 1, 1, 1, "a")
        cache.put("/repo-b", "b.py", 1, 1, 1, 2, "b")
        cache.prune_missing("/repo-a", [])
        assert cache.get("/repo-a", "a.py") is None
        assert cache.get("/repo-b", "b.py") is not None
