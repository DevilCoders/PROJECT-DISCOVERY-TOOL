"""Bounded, SQLite-backed persistence for filesystem inventory records.

This store is the persistence boundary for the planned streaming scanner. It stores
metadata records only; target file contents are never copied into the inventory DB.
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

_RECORD_KINDS = frozenset({"file", "directory", "symlink", "special"})


class InventoryStore:
    """Persist inventory records in bounded batches and stream them back in path order.

    A store belongs to one scan. Callers should place it outside the scanned root.
    append() retains at most batch_size serialized rows in process memory;
    iter_records() uses SQLite fetchmany and does not materialize the result set.
    """

    def __init__(self, path: Path, *, batch_size: int = 512) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self.path = Path(path).expanduser().absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Do not let SQLite silently follow a pre-planted database symlink.
        if self.path.is_symlink():
            raise ValueError("inventory database path must not be a symlink")
        self.batch_size = batch_size
        self._pending: list[tuple[str, str, str]] = []
        self._closed = False
        self.db = sqlite3.connect(self.path, timeout=30.0)
        if os.name == "posix":
            # Inventory databases contain local project paths and metadata.
            # Keep the database private to the current account by default.
            os.chmod(self.path, 0o600)
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA temp_store=MEMORY")
        self.db.execute("PRAGMA cache_size=-8192")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_records (
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY(kind, path)
            ) WITHOUT ROWID"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID"""
        )
        self.db.commit()

    @staticmethod
    def _kind(kind: str) -> str:
        if kind not in _RECORD_KINDS:
            raise ValueError(f"unsupported inventory record kind: {kind}")
        return kind

    @staticmethod
    def _serialize(record: Mapping[str, Any] | Any) -> tuple[str, str]:
        if hasattr(record, "to_dict"):
            value = record.to_dict()
        elif isinstance(record, Mapping):
            value = dict(record)
        else:
            raise TypeError("inventory records must be mappings or expose to_dict()")
        path = value.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("inventory record requires a non-empty string path")
        return path, json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def append(self, kind: str, record: Mapping[str, Any] | Any) -> None:
        """Queue one record; flush automatically when the bounded batch is full."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        kind = self._kind(kind)
        path, payload = self._serialize(record)
        self._pending.append((kind, path, payload))
        if len(self._pending) >= self.batch_size:
            self.flush()

    def extend(self, kind: str, records: Iterable[Mapping[str, Any] | Any]) -> int:
        """Append an iterable without retaining it; return the number of accepted rows."""
        count = 0
        for record in records:
            self.append(kind, record)
            count += 1
        return count

    def flush(self) -> int:
        """Atomically persist the pending bounded batch and return its row count."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if not self._pending:
            return 0
        pending, self._pending = self._pending, []
        try:
            with self.db:
                self.db.executemany(
                    """INSERT INTO inventory_records(kind, path, payload)
                       VALUES (?, ?, ?)
                       ON CONFLICT(kind, path) DO UPDATE SET payload=excluded.payload""",
                    pending,
                )
        except Exception:
            self._pending = pending + self._pending
            raise
        return len(pending)

    def count(self, kind: str | None = None) -> int:
        self.flush()
        if kind is None:
            row = self.db.execute("SELECT COUNT(*) FROM inventory_records").fetchone()
        else:
            row = self.db.execute(
                "SELECT COUNT(*) FROM inventory_records WHERE kind=?", (self._kind(kind),)
            ).fetchone()
        return int(row[0])

    def counts(self) -> dict[str, int]:
        self.flush()
        rows = self.db.execute(
            "SELECT kind, COUNT(*) FROM inventory_records GROUP BY kind ORDER BY kind"
        )
        return {str(kind): int(count) for kind, count in rows}

    def iter_records(self, kind: str, *, fetch_size: int = 256) -> Iterator[dict[str, Any]]:
        """Yield decoded records in deterministic path order using bounded fetches."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")
        kind = self._kind(kind)
        self.flush()
        cursor = self.db.execute(
            "SELECT payload FROM inventory_records WHERE kind=? ORDER BY path COLLATE BINARY",
            (kind,),
        )
        try:
            while True:
                rows = cursor.fetchmany(fetch_size)
                if not rows:
                    break
                for (payload,) in rows:
                    yield json.loads(payload)
        finally:
            # Callers commonly stop after a page; release the SQLite read
            # cursor immediately instead of waiting for generator collection.
            cursor.close()

    def set_metadata(self, key: str, value: Any) -> None:
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if not key:
            raise ValueError("metadata key must be non-empty")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        with self.db:
            self.db.execute(
                """INSERT INTO inventory_metadata(key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (key, encoded),
            )

    def get_metadata(self, key: str, default: Any = None) -> Any:
        if self._closed:
            raise RuntimeError("inventory store is closed")
        row = self.db.execute(
            "SELECT value FROM inventory_metadata WHERE key=?", (key,)
        ).fetchone()
        return default if row is None else json.loads(row[0])

    def clear(self) -> None:
        if self._closed:
            raise RuntimeError("inventory store is closed")
        self._pending.clear()
        with self.db:
            self.db.execute("DELETE FROM inventory_records")
            self.db.execute("DELETE FROM inventory_metadata")

    def close(self) -> None:
        if self._closed:
            return
        self.flush()
        self.db.close()
        self._closed = True

    def __enter__(self) -> "InventoryStore":
        if self._closed:
            raise RuntimeError("inventory store is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
