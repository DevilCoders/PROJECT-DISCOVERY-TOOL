"""SQLite cache with a time-to-live for online advisory responses.

The cache holds public advisory data and the package coordinates that were looked up (the
same information as the lockfiles that produced them); it never stores credentials,
request headers or file contents. The database file is created with owner-only
permissions on POSIX. Only successful answers are cached, never failures.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from ..inventory.store import prepare_private_database

CACHE_SCHEMA_VERSION = "1"
DEFAULT_CACHE_TTL_SECONDS = 24 * 3600
_SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS responses (
    key TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_responses_expiry ON responses(expires_at);
"""


def endpoint_key(base_url: str, key: str) -> str:
    """A cache key scoped to the service that answers it.

    Without the endpoint, a run against another mirror within the TTL reused the first
    mirror's answers and named the new endpoint as their source.
    """
    return f"{base_url.rstrip('/')}\x1e{key}"


def default_cache_path() -> Path:
    return Path.home() / ".pdt" / "online-vulnerability-cache.sqlite3"


class ResponseCache:
    """Thread-safe key/value cache; ``ttl_seconds == 0`` disables caching entirely."""

    def __init__(self, path: Path | None, *, ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS) -> None:
        if ttl_seconds < 0:
            raise ValueError("cache TTL must not be negative")
        self.ttl_seconds = float(ttl_seconds)
        self.path = Path(path).expanduser() if path is not None else None
        self.enabled = self.path is not None and self.ttl_seconds > 0
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None
        if not self.enabled:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        prepare_private_database(self.path)
        self._connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        try:
            self._connection.executescript(_SCHEMA)
            self._connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES ('schema_version', ?)",
                (CACHE_SCHEMA_VERSION,),
            )
            self._connection.execute("DELETE FROM responses WHERE expires_at <= ?", (time.time(),))
            self._connection.commit()
        except sqlite3.Error:
            self._connection.close()
            raise

    def get(self, key: str) -> Any | None:
        if not self.enabled or self._connection is None:
            return None
        with self._lock:
            row = self._connection.execute(
                "SELECT body FROM responses WHERE key=? AND expires_at>?", (key, time.time()),
            ).fetchone()
            if row is None:
                self.misses += 1
                return None
            try:
                value = json.loads(row[0])
            except (json.JSONDecodeError, RecursionError):
                self.misses += 1
                return None
            self.hits += 1
            return value

    def put(self, key: str, value: Any) -> None:
        if not self.enabled or self._connection is None:
            return
        now = time.time()
        body = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._connection.execute(
                "INSERT OR REPLACE INTO responses(key, fetched_at, expires_at, body) VALUES (?, ?, ?, ?)",
                (key, now, now + self.ttl_seconds, body),
            )
            self._connection.commit()
            self.writes += 1

    def statistics(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "ttl_seconds": self.ttl_seconds,
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
        }

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "ResponseCache":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
