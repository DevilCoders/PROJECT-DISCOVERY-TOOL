"""SQLite metadata-aware fingerprint cache for incremental hashing."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable


class ScanCache:
    """Persist file fingerprints without storing target file contents."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS fingerprints (
                project_root TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                ctime_ns INTEGER NOT NULL DEFAULT 0,
                inode INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(project_root, relative_path)
            )"""
        )
        columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(fingerprints)")
        }
        if "ctime_ns" not in columns:
            self.db.execute(
                "ALTER TABLE fingerprints ADD COLUMN ctime_ns INTEGER NOT NULL DEFAULT 0"
            )
        if "inode" not in columns:
            self.db.execute(
                "ALTER TABLE fingerprints ADD COLUMN inode INTEGER NOT NULL DEFAULT 0"
            )
        self.db.commit()

    def get(self, root: str, relative_path: str) -> tuple[int, int, int, int, str] | None:
        row = self.db.execute(
            """SELECT size_bytes, mtime_ns, ctime_ns, inode, sha256
               FROM fingerprints WHERE project_root=? AND relative_path=?""",
            (root, relative_path),
        ).fetchone()
        if row is None:
            return None
        return int(row[0]), int(row[1]), int(row[2]), int(row[3]), str(row[4])

    def put(
        self,
        root: str,
        relative_path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
        inode: int,
        digest: str,
    ) -> None:
        self.db.execute(
            """INSERT OR REPLACE INTO fingerprints
               (project_root, relative_path, size_bytes, mtime_ns, sha256, ctime_ns, inode)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (root, relative_path, size, mtime_ns, digest, ctime_ns, inode),
        )

    def prune_missing(self, root: str, current_paths: Iterable[str]) -> int:
        """Delete stale path entries without SQLite's bound-parameter limit."""
        self.db.execute(
            "CREATE TEMP TABLE IF NOT EXISTS current_scan_paths (relative_path TEXT PRIMARY KEY)"
        )
        self.db.execute("DELETE FROM current_scan_paths")
        self.db.executemany(
            "INSERT OR IGNORE INTO current_scan_paths(relative_path) VALUES (?)",
            ((path,) for path in current_paths),
        )
        cursor = self.db.execute(
            """DELETE FROM fingerprints
               WHERE project_root=?
               AND relative_path NOT IN (SELECT relative_path FROM current_scan_paths)""",
            (root,),
        )
        return cursor.rowcount

    def __enter__(self) -> "ScanCache":
        return self

    def __exit__(self, *_: object) -> None:
        self.db.commit()
        self.db.close()
