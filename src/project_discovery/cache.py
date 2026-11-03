"""SQLite fingerprint cache for incremental content hashing."""
import sqlite3
from pathlib import Path

class ScanCache:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS fingerprints (
            project_root TEXT NOT NULL, relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, sha256 TEXT NOT NULL,
            PRIMARY KEY(project_root, relative_path))""")
        self.db.commit()
    def get(self, root: str, rel: str) -> tuple[int,int,str] | None:
        row = self.db.execute("SELECT size_bytes,mtime_ns,sha256 FROM fingerprints WHERE project_root=? AND relative_path=?",
                              (root, rel)).fetchone()
        return (int(row[0]), int(row[1]), str(row[2])) if row else None
    def put(self, root: str, rel: str, size: int, mtime_ns: int, digest: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO fingerprints VALUES (?,?,?,?,?)",
                        (root, rel, size, mtime_ns, digest))
    def __enter__(self): return self
    def __exit__(self, *_):
        self.db.commit()
        self.db.close()
