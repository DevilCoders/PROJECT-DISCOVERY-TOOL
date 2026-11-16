"""Untrusted SQLite databases (a Subversion working copy, an RPM database), read from memory.

The database's bytes are handed to SQLite with ``deserialize``, so SQLite never opens a file,
follows a link, takes a lock or writes anything (its temporary data stays in memory). Queries
run read-only with untrusted schema functions off, cell-size checks on, no attached databases,
a limit on the size of any value or row and a budget of virtual-machine steps; the tables a
reader names must be plain ``CREATE TABLE`` ones without virtual generated columns, so no
value is computed as it is read. Every failure is a ValueError naming what went wrong.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from .limits import limit_reached

MAX_SQLITE_STEPS = 50_000_000
# The longest string, blob or row SQLite builds while the queries run.
MAX_SQLITE_VALUE_BYTES = 16 * 1024 * 1024
_STEP_INTERVAL = 1000


def sql_words(sql: str, count: int) -> list[str]:
    """The first words of an SQL statement in upper case, its comments skipped: SQLite reads
    "CREATE/**/VIRTUAL TABLE" as a virtual table, so its text is not compared as written."""
    words: list[str] = []
    position, length = 0, len(sql)
    while position < length and len(words) < count:
        if sql.startswith("/*", position):
            end = sql.find("*/", position + 2)
            position = length if end < 0 else end + 2
        elif sql.startswith("--", position):
            end = sql.find("\n", position)
            position = length if end < 0 else end + 1
        elif sql[position].isspace():
            position += 1
        else:
            start = position
            while position < length and (sql[position].isalnum() or sql[position] == "_"):
                position += 1
            if position == start:  # punctuation is a word of its own
                position += 1
            words.append(sql[start:position].upper())
    return words


def plain_tables(db: sqlite3.Connection, required: tuple[str, ...], optional: tuple[str, ...] = (),
                 *, label: str = "database") -> set[str]:
    """The (upper-case) names of the database's tables, after checking that the ones named are
    plain: a table that computes values as it is read (a virtual table, a virtual generated
    column) is refused, and so is a database without the required tables."""
    schema = {str(name).upper(): str(sql or "") for name, sql in db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' LIMIT 10000")}
    if not set(required) <= set(schema):
        raise ValueError(f"not a {label} (no {' and '.join(required)} table{'s' if len(required) > 1 else ''})")
    for table in (*required, *optional):
        if table in schema and (sql_words(schema[table], 2) != ["CREATE", "TABLE"]
                                or any(row[6] in (1, 2) for row in db.execute(f'PRAGMA table_xinfo("{table}")'))):
            raise ValueError(f"not a {label} ({table} computes its values)")
    return set(schema)


@contextmanager
def untrusted_database(data: bytes, *, max_steps: int = MAX_SQLITE_STEPS,
                       label: str = "database") -> Iterator[sqlite3.Connection]:
    """A hardened, read-only connection over the bytes of an untrusted SQLite database."""
    if len(data) < 512 or not data.startswith(b"SQLite format 3\x00"):
        raise ValueError("not a SQLite database")
    db = sqlite3.connect(":memory:")
    try:
        deserialize = getattr(db, "deserialize", None)
        if deserialize is None:  # an SQLite library built without it
            raise ValueError("this Python's SQLite cannot read a database from memory")
        try:
            deserialize(data)
        except (sqlite3.DatabaseError, OverflowError, MemoryError) as exc:
            raise ValueError(f"not a SQLite database: {exc}") from exc
        steps = [0]

        def budget() -> int:
            steps[0] += _STEP_INTERVAL
            return 1 if steps[0] > max_steps else 0

        db.set_progress_handler(budget, _STEP_INTERVAL)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)
        db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        for pragma in ("query_only = ON", "trusted_schema = OFF", "cell_size_check = ON", "temp_store = MEMORY"):
            db.execute(f"PRAGMA {pragma}")
        try:
            yield db
        except sqlite3.OperationalError as exc:
            if steps[0] > max_steps:
                limit_reached("steps", max_steps, steps[0])
                raise ValueError(f"{label} queries exceeded the {max_steps:,}-step budget") from exc
            raise ValueError(f"unreadable {label}: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            raise ValueError(f"unreadable {label}: {exc}") from exc
    finally:
        db.close()
