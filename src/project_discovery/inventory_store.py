"""Bounded, SQLite-backed persistence for filesystem inventory records.

The store supports incremental scanner persistence and lazy file-record iteration.
It stores metadata only; target file contents are never copied into the inventory DB.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # string annotations only; models imports this module lazily
    from .models import FileRecord, Finding

_RECORD_KINDS = frozenset({"file", "directory", "symlink", "special", "finding", "diagnostic"})
# Cross-file code facts (see code_facts). Rows are idempotent, so re-analysing a file
# after --resume cannot duplicate them. Each table stops growing at its ceiling.
_CODE_TABLES = {
    "code_symbols": (
        """CREATE TABLE IF NOT EXISTS code_symbols (
            path TEXT NOT NULL, qualified TEXT NOT NULL, line INTEGER NOT NULL,
            language TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL,
            end_line INTEGER NOT NULL, exported INTEGER NOT NULL,
            PRIMARY KEY(path, qualified, line)
        ) WITHOUT ROWID""",
        "INSERT OR IGNORE INTO code_symbols(language, kind, name, qualified, line, end_line, exported, path) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        "CREATE INDEX IF NOT EXISTS code_symbols_name ON code_symbols(name)",
        5_000_000,
    ),
    "code_calls": (
        """CREATE TABLE IF NOT EXISTS code_calls (
            path TEXT NOT NULL, line INTEGER NOT NULL, caller TEXT NOT NULL,
            callee TEXT NOT NULL, target TEXT NOT NULL,
            PRIMARY KEY(path, line, caller, callee, target)
        ) WITHOUT ROWID""",
        "INSERT OR IGNORE INTO code_calls(caller, callee, target, line, path) VALUES (?, ?, ?, ?, ?)",
        "CREATE INDEX IF NOT EXISTS code_calls_callee ON code_calls(callee)",
        10_000_000,
    ),
    "code_references": (
        """CREATE TABLE IF NOT EXISTS code_references (
            name TEXT NOT NULL, path TEXT NOT NULL, PRIMARY KEY(name, path)
        ) WITHOUT ROWID""",
        "INSERT OR IGNORE INTO code_references(name, path) VALUES (?, ?)",
        None,
        20_000_000,
    ),
    "code_facts": (
        """CREATE TABLE IF NOT EXISTS code_facts (
            kind TEXT NOT NULL, name TEXT NOT NULL, path TEXT NOT NULL, detail TEXT NOT NULL,
            PRIMARY KEY(kind, name, path, detail)
        ) WITHOUT ROWID""",
        "INSERT OR IGNORE INTO code_facts(kind, name, detail, path) VALUES (?, ?, ?, ?)",
        "CREATE INDEX IF NOT EXISTS code_facts_path ON code_facts(kind, path)",
        5_000_000,
    ),
}
_CODE_BATCH_ROWS = 8192
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CONFIDENCE_ORDER = {"CONFIRMED": 0, "INFERRED": 1, "UNKNOWN": 2}
# Prefix for keys of names that are not valid Unicode; U+FFFF is a noncharacter.
_UNDECODABLE_KEY_PREFIX = "￿"


def sqlite_text(value: str) -> str:
    """Return SQLite-bindable text for a file-system string, injectively.

    POSIX names that are not valid UTF-8 (surrogateescape) and unpaired surrogates in
    Windows names cannot be bound as SQLite TEXT. They are mapped into a separate,
    prefixed namespace using backslash escapes, so they cannot collide with real names.
    """
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        escaped = value.encode("utf-8", "surrogatepass").decode("utf-8", "backslashreplace")
        return _UNDECODABLE_KEY_PREFIX + escaped


def _payload_json(value: Any) -> str:
    """JSON for SQLite storage; falls back to ASCII escapes for unencodable strings."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if not text.isascii():
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            # \uXXXX escapes round-trip lone surrogates through json.loads exactly.
            text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return text


def prepare_private_database(path: Path) -> None:
    """Create a SQLite database file readable only by the current account (POSIX).

    The file is created atomically with mode 0600 before SQLite opens it; SQLite gives
    its -wal/-shm/-journal sidecars the main file's permissions. Pre-existing files are
    tightened, and symlinked database paths are refused.
    """
    if path.is_symlink():
        raise ValueError(f"database path must not be a symlink: {path}")
    if os.name != "posix":
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        os.close(os.open(path, flags, 0o600))
    except FileExistsError:
        if path.is_symlink():
            raise ValueError(f"database path must not be a symlink: {path}") from None
    for candidate in (path, *(path.with_name(path.name + suffix) for suffix in ("-wal", "-shm", "-journal"))):
        if candidate.exists() and not candidate.is_symlink():
            os.chmod(candidate, 0o600)


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
        # Inventory databases contain local project paths and metadata. Keep them private
        # and never let SQLite silently follow a pre-planted database symlink.
        if self.path.is_symlink():
            raise ValueError("inventory database path must not be a symlink")
        prepare_private_database(self.path)
        self.batch_size = batch_size
        self._pending: list[tuple[str, str, str, str]] = []
        self._directory_pending: dict[str, tuple[int, int, int, str | None]] = {}
        self._closed = False
        self.db = sqlite3.connect(self.path, timeout=30.0)
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA temp_store=MEMORY")
        self.db.execute("PRAGMA cache_size=-8192")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_records (
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                sort_key TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY(kind, path)
            ) WITHOUT ROWID"""
        )
        columns = {
            str(row[1]) for row in self.db.execute("PRAGMA table_info(inventory_records)")
        }
        if "sort_key" not in columns:
            # Migrate stores created before deterministic case-folded streaming order.
            self.db.execute(
                "ALTER TABLE inventory_records ADD COLUMN sort_key TEXT NOT NULL DEFAULT ''"
            )
            cursor = self.db.execute(
                "SELECT kind, path, payload FROM inventory_records"
            )
            try:
                while rows := cursor.fetchmany(self.batch_size):
                    updates = []
                    for kind, path, payload in rows:
                        sort_key = str(path).casefold()
                        if kind == "directory":
                            data = json.loads(payload)
                            depth = max(0, int(data.get("depth", 0)))
                            sort_key = f"{depth:012d}|{sort_key}"
                        updates.append((sort_key, str(kind), str(path)))
                    with self.db:
                        self.db.executemany(
                            "UPDATE inventory_records SET sort_key=? WHERE kind=? AND path=?",
                            updates,
                        )
            finally:
                cursor.close()
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_directory_state (
                path TEXT PRIMARY KEY,
                direct_child_count INTEGER NOT NULL DEFAULT 0,
                file_count INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                error TEXT
            ) WITHOUT ROWID"""
        )
        self.db.commit()
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_sequences (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK(value >= 0)
            ) WITHOUT ROWID"""
        )
        for create_table, _insert, create_index, _ceiling in _CODE_TABLES.values():
            self.db.execute(create_table)
            if create_index:
                self.db.execute(create_index)
        self.db.commit()
        self._code_pending: dict[str, list[tuple]] = {table: [] for table in _CODE_TABLES}
        self._code_truncated: set[str] = set()
        self._code_file_truncations: list[tuple[str, list[str]]] = []
        self._code_rows = {
            table: int(row[0]) for table, row in (
                (table, self.db.execute(
                    "SELECT value FROM inventory_sequences WHERE name=?", (table,),
                ).fetchone() or (0,))
                for table in _CODE_TABLES
            )
        }
        row = self.db.execute(
            "SELECT MAX(CAST(path AS INTEGER)) FROM inventory_records WHERE kind='diagnostic'"
        ).fetchone()
        initial_diagnostic_value = int(row[0] or 0) if row else 0
        with self.db:
            self.db.execute(
                """INSERT INTO inventory_sequences(name, value) VALUES ('diagnostic', ?)
                   ON CONFLICT(name) DO UPDATE SET
                       value=MAX(inventory_sequences.value, excluded.value)""",
                (initial_diagnostic_value,),
            )

    @staticmethod
    def _kind(kind: str) -> str:
        if kind not in _RECORD_KINDS:
            raise ValueError(f"unsupported inventory record kind: {kind}")
        return kind

    @staticmethod
    def _serialize(record: Mapping[str, Any] | Any) -> tuple[str, str, str]:
        if hasattr(record, "to_storage_dict"):
            value = record.to_storage_dict()
        elif hasattr(record, "to_dict"):
            value = record.to_dict()
        elif isinstance(record, Mapping):
            value = dict(record)
        else:
            raise TypeError("inventory records must be mappings or expose to_dict()")
        path = value.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("inventory record requires a non-empty string path")
        key = sqlite_text(path)
        return key, key.casefold(), _payload_json(value)

    def append(
        self, kind: str, record: Mapping[str, Any] | Any, *, sort_key: str | None = None,
    ) -> None:
        """Queue one record; flush automatically when the bounded batch is full."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        kind = self._kind(kind)
        path, default_sort_key, payload = self._serialize(record)
        sort_key = default_sort_key if sort_key is None else sort_key
        if kind == "directory":
            directory = json.loads(payload)
            depth = max(0, int(directory.get("depth", 0)))
            sort_key = f"{depth:012d}|{sort_key}"
        self._pending.append((kind, path, sort_key, payload))
        if len(self._pending) + len(self._directory_pending) >= self.batch_size:
            self.flush()

    def adjust_directory(
        self,
        path: str,
        *,
        direct_child_delta: int = 0,
        file_count_delta: int = 0,
        total_bytes_delta: int = 0,
        error: str | None = None,
    ) -> None:
        """Queue bounded directory aggregate updates for the next atomic flush."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if not isinstance(path, str) or not path:
            raise ValueError("directory path must be a non-empty string")
        if not any((direct_child_delta, file_count_delta, total_bytes_delta, error is not None)):
            return
        path = sqlite_text(path)
        current = self._directory_pending.get(path, (0, 0, 0, None))
        self._directory_pending[path] = (
            current[0] + direct_child_delta,
            current[1] + file_count_delta,
            current[2] + total_bytes_delta,
            error if error is not None else current[3],
        )
        if len(self._pending) + len(self._directory_pending) >= self.batch_size:
            self.flush()

    def extend(self, kind: str, records: Iterable[Mapping[str, Any] | Any]) -> int:
        """Append an iterable without retaining it; return the number of accepted rows."""
        count = 0
        for record in records:
            self.append(kind, record)
            count += 1
        return count

    def extend_code_facts(self, path: str, facts: Any) -> None:
        """Queue one file's code facts (a ``code_facts.FileFacts``) for the next flush.

        They are committed in the same transaction as pending findings, so a file record
        committed after a flush never lacks its facts. Rows beyond a table's ceiling are
        dropped and the table is recorded in the ``code_index_truncated`` metadata.
        """
        if self._closed:
            raise RuntimeError("inventory store is closed")
        key = sqlite_text(path)
        rows = {
            "code_symbols": [(*item, key) for item in facts.symbols],
            "code_calls": [(*item, key) for item in facts.calls],
            "code_references": [(name, key) for name in sorted(facts.references)],
            "code_facts": [(*item, key) for item in facts.facts],
        }
        for table, new_rows in rows.items():
            if not new_rows:
                continue
            ceiling = _CODE_TABLES[table][3]
            room = ceiling - self._code_rows[table] - len(self._code_pending[table])
            if room < len(new_rows):
                new_rows = new_rows[:max(0, room)]
                self._code_truncated.add(table)
            self._code_pending[table].extend(new_rows)
        if facts.truncated:
            self._code_file_truncations.append((key, sorted(facts.truncated)))
        if sum(map(len, self._code_pending.values())) >= _CODE_BATCH_ROWS:
            self.flush()

    def flush(self) -> int:
        """Atomically persist the pending bounded batch and return its row count."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        code_rows = sum(map(len, self._code_pending.values()))
        if not self._pending and not self._directory_pending and not code_rows and not self._code_file_truncations:
            return 0
        pending, self._pending = self._pending, []
        directory_pending, self._directory_pending = self._directory_pending, {}
        code_pending = self._code_pending
        self._code_pending = {table: [] for table in _CODE_TABLES}
        file_truncations, self._code_file_truncations = self._code_file_truncations, []
        try:
            with self.db:
                for table, rows in code_pending.items():
                    if rows:
                        self.db.executemany(_CODE_TABLES[table][1], rows)
                        self.db.execute(
                            """INSERT INTO inventory_sequences(name, value) VALUES (?, ?)
                               ON CONFLICT(name) DO UPDATE SET value=value+excluded.value""",
                            (table, len(rows)),
                        )
                if self._code_truncated or file_truncations:
                    previous = self.db.execute(
                        "SELECT value FROM inventory_metadata WHERE key='code_index_truncated'"
                    ).fetchone()
                    state = json.loads(previous[0]) if previous else {"tables": [], "files": 0}
                    state["tables"] = sorted(set(state["tables"]) | self._code_truncated)
                    state["files"] += len(file_truncations)
                    self.db.execute(
                        """INSERT INTO inventory_metadata(key, value) VALUES ('code_index_truncated', ?)
                           ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                        (json.dumps(state, sort_keys=True),),
                    )
                if pending:
                    self.db.executemany(
                        """INSERT INTO inventory_records(kind, path, sort_key, payload)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(kind, path) DO UPDATE SET
                               sort_key=excluded.sort_key,
                               payload=excluded.payload""",
                        pending,
                    )
                    initial_directory_state = []
                    for kind, path, _sort_key, payload in pending:
                        if kind == "directory":
                            data = json.loads(payload)
                            initial_directory_state.append((
                                path,
                                int(data.get("direct_child_count", 0)),
                                int(data.get("file_count", 0)),
                                int(data.get("total_bytes", 0)),
                                data.get("error"),
                            ))
                    if initial_directory_state:
                        self.db.executemany(
                            """INSERT OR IGNORE INTO inventory_directory_state(
                                   path, direct_child_count, file_count, total_bytes, error
                               ) VALUES (?, ?, ?, ?, ?)""",
                            initial_directory_state,
                        )
                if directory_pending:
                    self.db.executemany(
                        """INSERT INTO inventory_directory_state(
                               path, direct_child_count, file_count, total_bytes, error
                           ) VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT(path) DO UPDATE SET
                               direct_child_count=direct_child_count+excluded.direct_child_count,
                               file_count=file_count+excluded.file_count,
                               total_bytes=total_bytes+excluded.total_bytes,
                               error=COALESCE(excluded.error, inventory_directory_state.error)""",
                        [
                            (path, *deltas)
                            for path, deltas in directory_pending.items()
                        ],
                    )
        except BaseException:
            # Includes KeyboardInterrupt: the rolled-back rows stay pending, so close()
            # can still persist them and no caller sees them as committed.
            for table, rows in code_pending.items():
                self._code_pending[table] = rows + self._code_pending[table]
            self._code_file_truncations = file_truncations + self._code_file_truncations
            self._pending = pending + self._pending
            for path, deltas in directory_pending.items():
                current = self._directory_pending.get(path, (0, 0, 0, None))
                self._directory_pending[path] = (
                    current[0] + deltas[0],
                    current[1] + deltas[1],
                    current[2] + deltas[2],
                    deltas[3] if deltas[3] is not None else current[3],
                )
            raise
        for table, rows in code_pending.items():
            self._code_rows[table] += len(rows)
        return len(pending) + len(directory_pending) + code_rows

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
        """Yield decoded records in case-folded path order using bounded fetches."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")
        kind = self._kind(kind)
        self.flush()
        if kind == "directory":
            cursor = self.db.execute(
                """SELECT r.payload, d.direct_child_count, d.file_count,
                          d.total_bytes, d.error
                   FROM inventory_records AS r
                   LEFT JOIN inventory_directory_state AS d ON d.path=r.path
                   WHERE r.kind=?
                   ORDER BY r.sort_key COLLATE BINARY, r.path COLLATE BINARY""",
                (kind,),
            )
        else:
            cursor = self.db.execute(
                """SELECT payload FROM inventory_records WHERE kind=?
                   ORDER BY sort_key COLLATE BINARY, path COLLATE BINARY""",
                (kind,),
            )
        try:
            while True:
                rows = cursor.fetchmany(fetch_size)
                if not rows:
                    break
                for row in rows:
                    if kind == "directory":
                        payload, children, files, total_bytes, error = row
                        value = json.loads(payload)
                        if children is not None:
                            value["direct_child_count"] = int(children)
                            value["file_count"] = int(files)
                            value["total_bytes"] = int(total_bytes)
                            if error is not None:
                                value["error"] = str(error)
                        yield value
                    else:
                        yield json.loads(row[0])
        finally:
            # Callers commonly stop after a page; release the SQLite read
            # cursor immediately instead of waiting for generator collection.
            cursor.close()

    def append_finding(self, finding: Any) -> None:
        """Persist one finding under a deterministic content key.

        Identical analyzer findings are de-duplicated at the store boundary. The
        canonical key includes all public finding fields, including source evidence.
        """
        if not hasattr(finding, "to_dict"):
            raise TypeError("finding must expose to_dict()")
        value = finding.to_dict()
        canonical = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        )
        key = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()
        # Reports stream findings most-severe first; the content key keeps the order total.
        sort_key = "|".join((
            str(_SEVERITY_ORDER.get(value.get("severity"), len(_SEVERITY_ORDER))),
            str(_CONFIDENCE_ORDER.get(value.get("confidence"), len(_CONFIDENCE_ORDER))),
            sqlite_text(str(value.get("category", ""))).casefold(),
            sqlite_text(str(value.get("title", ""))).casefold(),
            key,
        ))
        self.append("finding", {"path": key, "finding": value}, sort_key=sort_key)

    def extend_findings(self, findings: Iterable[Any]) -> int:
        """Persist an iterable of findings without retaining it in memory."""
        count = 0
        for finding in findings:
            self.append_finding(finding)
            count += 1
        return count

    def iter_findings(self, *, fetch_size: int = 256) -> Iterator["Finding"]:
        """Yield persisted typed findings in deterministic content-key order."""
        from .models import Finding

        payloads = self.iter_records("finding", fetch_size=fetch_size)
        try:
            for payload in payloads:
                yield Finding.from_dict(payload["finding"])
        finally:
            payloads.close()

    def append_diagnostic(self, message: str) -> None:
        """Persist one scan diagnostic with stable insertion order and no deduplication."""
        if not isinstance(message, str):
            raise TypeError("diagnostic messages must be strings")
        if not message:
            raise ValueError("diagnostic messages must not be empty")
        # Reserve the sequence value transactionally so independent store
        # connections cannot reuse a diagnostic key. A crash can leave a gap,
        # but can never cause an earlier diagnostic to be overwritten.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT value FROM inventory_sequences WHERE name='diagnostic'"
            ).fetchone()
            sequence = int(row[0] if row else 0) + 1
            self.db.execute(
                """INSERT INTO inventory_sequences(name, value) VALUES ('diagnostic', ?)
                   ON CONFLICT(name) DO UPDATE SET value=excluded.value""",
                (sequence,),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        key = f"{sequence:020d}"
        self.append("diagnostic", {"path": key, "message": message})

    def extend_diagnostics(self, messages: Iterable[str]) -> int:
        """Persist diagnostic messages from an iterable without retaining it."""
        count = 0
        for message in messages:
            self.append_diagnostic(message)
            count += 1
        return count

    def iter_diagnostics(self, *, fetch_size: int = 256) -> Iterator[str]:
        """Yield diagnostics in original insertion order using bounded fetches."""
        payloads = self.iter_records("diagnostic", fetch_size=fetch_size)
        try:
            for payload in payloads:
                yield str(payload["message"])
        finally:
            payloads.close()

    def iter_file_records(self, *, fetch_size: int = 256) -> Iterator["FileRecord"]:
        """Yield typed file records while retaining their private scan-time identity."""
        from .models import FileRecord

        payloads = self.iter_records("file", fetch_size=fetch_size)
        try:
            for payload in payloads:
                yield FileRecord.from_storage_dict(payload)
        finally:
            payloads.close()

    def set_metadata(self, key: str, value: Any) -> None:
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if not key:
            raise ValueError("metadata key must be non-empty")
        encoded = _payload_json(value)
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
        self._directory_pending.clear()
        self._code_pending = {table: [] for table in _CODE_TABLES}
        self._code_truncated.clear()
        self._code_file_truncations.clear()
        self._code_rows = dict.fromkeys(_CODE_TABLES, 0)
        with self.db:
            self.db.execute("DELETE FROM inventory_records")
            self.db.execute("DELETE FROM inventory_metadata")
            self.db.execute("DELETE FROM inventory_directory_state")
            self.db.execute("DELETE FROM inventory_sequences")
            for table in _CODE_TABLES:
                self.db.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names

    def checkpoint(self, metadata: Mapping[str, Any]) -> None:
        """Flush inventory rows, then atomically persist a resumable scan checkpoint.

        The caller supplies stable progress fields (for example scan_id,
        phase, last_committed_path and completed). A checkpoint never claims
        completion unless the caller explicitly sets completed=True.
        """
        if self._closed:
            raise RuntimeError("inventory store is closed")
        if not metadata:
            raise ValueError("checkpoint metadata must not be empty")
        if any(not isinstance(key, str) or not key for key in metadata):
            raise ValueError("checkpoint metadata keys must be non-empty strings")
        encoded = [
            (key, _payload_json(value))
            for key, value in metadata.items()
        ]
        self.flush()
        with self.db:
            self.db.executemany(
                """INSERT INTO inventory_metadata(key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                encoded,
            )

    def integrity_check(self) -> str:
        """Return SQLite quick_check status; 'ok' indicates a structurally sound store."""
        if self._closed:
            raise RuntimeError("inventory store is closed")
        row = self.db.execute("PRAGMA quick_check").fetchone()
        return str(row[0]) if row else "no result"

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



class StoredFileRecords(Sequence["FileRecord"]):
    """Lazy file-record sequence backed by a private SQLite inventory database.

    Each iteration opens a short-lived store connection and uses fetchmany; no
    collection of FileRecord objects is retained between iterations.
    """

    def __init__(self, database_path: Path, *, fetch_size: int = 256) -> None:
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")
        self.database_path = Path(database_path).expanduser().absolute()
        self.fetch_size = fetch_size

    def __len__(self) -> int:
        with InventoryStore(self.database_path) as store:
            return store.count("file")

    def __iter__(self) -> Iterator["FileRecord"]:
        with InventoryStore(self.database_path) as store:
            yield from store.iter_file_records(fetch_size=self.fetch_size)

    def __getitem__(self, index):
        if isinstance(index, slice):
            if index.step is not None and index.step < 0:
                return list(self)[index]
            start, stop, step = index.indices(len(self))
            if stop <= start:
                return []
            iterator = iter(self)
            try:
                return list(islice(iterator, start, stop, step))
            finally:
                iterator.close()

        if not isinstance(index, int):
            raise TypeError("file record indices must be integers or slices")
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError("file record index out of range")
        iterator = iter(self)
        try:
            try:
                return next(islice(iterator, index, index + 1))
            except StopIteration as exc:
                raise IndexError("file record index out of range") from exc
        finally:
            iterator.close()

    def update_records(self, records: Iterable["FileRecord"]) -> int:
        """Persist mutated records in bounded batches without retaining the batch."""
        with InventoryStore(self.database_path) as store:
            return store.extend("file", records)

class StoredRecordSequence(Sequence[Any]):
    """Lazy typed sequence for one inventory kind stored in SQLite.

    Iteration is cursor-backed and fetch-bounded. Indexing supports the same
    sequence contract as StoredFileRecords without keeping a record list alive.
    """

    def __init__(
        self,
        database_path: Path,
        kind: str,
        record_type: type[Any],
        *,
        fetch_size: int = 256,
    ) -> None:
        if kind not in _RECORD_KINDS:
            raise ValueError(f"unsupported inventory record kind: {kind}")
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")
        self.database_path = Path(database_path).expanduser().absolute()
        self.kind = kind
        self.record_type = record_type
        self.fetch_size = fetch_size

    def __len__(self) -> int:
        with InventoryStore(self.database_path) as store:
            return store.count(self.kind)

    def __iter__(self) -> Iterator[Any]:
        with InventoryStore(self.database_path) as store:
            payloads = store.iter_records(self.kind, fetch_size=self.fetch_size)
            try:
                for payload in payloads:
                    yield self.record_type(**payload)
            finally:
                payloads.close()

    def __getitem__(self, index):
        if isinstance(index, slice):
            if index.step is not None and index.step < 0:
                return list(self)[index]
            start, stop, step = index.indices(len(self))
            if stop <= start:
                return []
            iterator = iter(self)
            try:
                return list(islice(iterator, start, stop, step))
            finally:
                iterator.close()
        if not isinstance(index, int):
            raise TypeError("inventory record indices must be integers or slices")
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError("inventory record index out of range")
        iterator = iter(self)
        try:
            try:
                return next(islice(iterator, index, index + 1))
            except StopIteration as exc:
                raise IndexError("inventory record index out of range") from exc
        finally:
            iterator.close()

class StoredFindingRecords(Sequence["Finding"]):
    """Lazy, deduplicated finding sequence backed by the scan's SQLite store."""

    def __init__(self, database_path: Path, *, fetch_size: int = 256) -> None:
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")
        self.database_path = Path(database_path).expanduser().absolute()
        self.fetch_size = fetch_size

    def __len__(self) -> int:
        with InventoryStore(self.database_path) as store:
            return store.count("finding")

    def __iter__(self) -> Iterator["Finding"]:
        with InventoryStore(self.database_path) as store:
            yield from store.iter_findings(fetch_size=self.fetch_size)

    def __getitem__(self, index):
        if isinstance(index, slice):
            if index.step is not None and index.step < 0:
                return list(self)[index]
            start, stop, step = index.indices(len(self))
            if stop <= start:
                return []
            iterator = iter(self)
            try:
                return list(islice(iterator, start, stop, step))
            finally:
                iterator.close()
        if not isinstance(index, int):
            raise TypeError("finding indices must be integers or slices")
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError("finding index out of range")
        iterator = iter(self)
        try:
            try:
                return next(islice(iterator, index, index + 1))
            except StopIteration as exc:
                raise IndexError("finding index out of range") from exc
        finally:
            iterator.close()




class StoredDiagnosticRecords(Sequence[str]):
    """Lazy sequence of diagnostic messages backed by the scan's SQLite store."""

    def __init__(self, database_path: Path, *, fetch_size: int = 256) -> None:
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")
        self.database_path = Path(database_path).expanduser().absolute()
        self.fetch_size = fetch_size

    def __len__(self) -> int:
        with InventoryStore(self.database_path) as store:
            return store.count("diagnostic")

    def __iter__(self) -> Iterator[str]:
        with InventoryStore(self.database_path) as store:
            yield from store.iter_diagnostics(fetch_size=self.fetch_size)

    def __getitem__(self, index):
        if isinstance(index, slice):
            if index.step is not None and index.step < 0:
                return list(self)[index]
            start, stop, step = index.indices(len(self))
            if stop <= start:
                return []
            iterator = iter(self)
            try:
                return list(islice(iterator, start, stop, step))
            finally:
                iterator.close()
        if not isinstance(index, int):
            raise TypeError("diagnostic indices must be integers or slices")
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError("diagnostic index out of range")
        iterator = iter(self)
        try:
            try:
                return next(islice(iterator, index, index + 1))
            except StopIteration as exc:
                raise IndexError("diagnostic index out of range") from exc
        finally:
            iterator.close()
