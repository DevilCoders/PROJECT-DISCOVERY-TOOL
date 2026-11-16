"""Inventory aggregates: empty directories, fan-out, hard links, owners and file timestamps.

Computed after the inventory from the stored records with SQL aggregation (bounded memory,
and the same for fresh and resumed scans). Hard links are files that share a device and
inode (a file ID on Windows) with another inventoried file; they are found only where the
inventory recorded those identities, which a Windows ``--inventory-only`` scan does not.
"""
from __future__ import annotations

import sqlite3
from typing import Any

_FAN_OUT_BUCKETS = ((0, "0"), (9, "1-9"), (99, "10-99"), (999, "100-999"), (9999, "1000-9999"))
_TOP = 50  # owners, groups and owner SIDs listed by name; the rest are summed as "other"
_EPOCH_1980_NS = 315_532_800 * 10**9
# Modification times this far after the scan started are "in the future", not clock skew.
_FUTURE_TOLERANCE_NS = 24 * 3600 * 10**9


def _bucket(count: int) -> str:
    for limit, label in _FAN_OUT_BUCKETS:
        if count <= limit:
            return label
    return "10000+"


def _top(rows: list[tuple[Any, int]]) -> dict[str, int]:
    rows = sorted(((str(value), int(count)) for value, count in rows), key=lambda item: (-item[1], item[0]))
    top = dict(rows[:_TOP])
    if len(rows) > _TOP:
        top["other"] = sum(count for _, count in rows[_TOP:])
    return top


def _directory_structure(db) -> dict[str, Any]:
    rows = db.execute(
        """SELECT json_extract(r.payload, '$.path'),
                  COALESCE(d.direct_child_count, json_extract(r.payload, '$.direct_child_count'), 0),
                  COALESCE(json_extract(r.payload, '$.pruned'), 0),
                  COALESCE(d.error, json_extract(r.payload, '$.error'))
           FROM inventory_records AS r
           LEFT JOIN inventory_directory_state AS d ON d.path = r.path
           WHERE r.kind = 'directory'"""
    )
    buckets: dict[str, int] = {}
    walked = children = empty = 0
    largest: tuple[int, str] | None = None
    for path, count, pruned, error in rows:
        if pruned or error:  # their contents were not listed
            continue
        count = int(count)
        walked += 1
        children += count
        empty += count == 0
        buckets[_bucket(count)] = buckets.get(_bucket(count), 0) + 1
        if largest is None or (count, path) > largest:
            largest = (count, str(path))
    return {
        "empty_directory_count": empty,
        "fan_out": {
            "directories": walked,
            "max": largest[0] if largest else 0,
            "max_path": largest[1] if largest else None,
            "mean": round(children / walked, 2) if walked else 0.0,
            "buckets": {label: buckets[label] for _, label in (*_FAN_OUT_BUCKETS, (0, "10000+")) if label in buckets},
        },
    }


def _hard_links(db) -> dict[str, Any]:
    device = "json_extract(payload, '$.analysis_identity[0]')"
    inode = "json_extract(payload, '$.analysis_identity[1]')"
    known = f"kind = 'file' AND {inode} IS NOT NULL AND {device} IS NOT NULL"
    with_identity, distinct = db.execute(
        f"SELECT COUNT(*), COUNT(DISTINCT {device} || ':' || {inode}) FROM inventory_records WHERE {known}"
    ).fetchone()
    groups, files = db.execute(
        f"""SELECT COUNT(*), COALESCE(SUM(n), 0) FROM (
                SELECT COUNT(*) AS n FROM inventory_records WHERE {known}
                GROUP BY {device}, {inode} HAVING COUNT(*) > 1)"""
    ).fetchone()
    return {
        "supported": bool(with_identity),
        "files_with_identity": int(with_identity),
        "distinct_inodes": int(distinct),
        "hard_linked_files": int(files),
        "groups": int(groups),
    }


def _ownership(db) -> dict[str, dict[str, int]]:
    def counts(expression: str) -> dict[str, int]:
        return _top(db.execute(
            f"SELECT {expression} AS value, COUNT(*) FROM inventory_records WHERE value IS NOT NULL GROUP BY value"
        ).fetchall())

    return {
        "owners": counts("json_extract(payload, '$.uid')"),
        "groups": counts("json_extract(payload, '$.gid')"),
        "owner_sids": counts("json_extract(payload, '$.security.owner_sid')"),
    }


def _file_timestamps(db, scan_started_ns: int) -> dict[str, Any]:
    mtime = "json_extract(payload, '$.mtime_ns')"
    count, oldest, newest, future, early = db.execute(
        f"""SELECT COUNT(m), MIN(m), MAX(m), COALESCE(SUM(m > ?), 0), COALESCE(SUM(m < ?), 0)
            FROM (SELECT {mtime} AS m FROM inventory_records WHERE kind = 'file')""",
        (scan_started_ns + _FUTURE_TOLERANCE_NS, _EPOCH_1980_NS),
    ).fetchone()

    def path_of(value):
        row = db.execute(
            f"""SELECT json_extract(payload, '$.path') FROM inventory_records
                WHERE kind = 'file' AND {mtime} = ? ORDER BY path LIMIT 1""",
            (value,),
        ).fetchone()
        return None if row is None else row[0]

    years = db.execute(
        f"""SELECT strftime('%Y', m / 1000000000, 'unixepoch') AS year, COUNT(*)
            FROM (SELECT {mtime} AS m FROM inventory_records WHERE kind = 'file') WHERE m IS NOT NULL
            GROUP BY year ORDER BY year"""
    ).fetchall()
    return {
        "files": int(count),
        "oldest": None if oldest is None else {"mtime_ns": int(oldest), "path": path_of(oldest)},
        "newest": None if newest is None else {"mtime_ns": int(newest), "path": path_of(newest)},
        "by_year": {str(year): int(number) for year, number in years if year is not None},
        "future_count": int(future),
        "before_1980_count": int(early),
    }


def inventory_aggregates(store, *, scan_started_ns: int) -> dict[str, Any]:
    """Empty directories, fan-out, hard links, owners and groups, and file timestamps."""
    store.flush()
    db = store.db
    try:
        result = _directory_structure(db)
        result["hard_links"] = _hard_links(db)
        result.update(_ownership(db))
        result["file_timestamps"] = _file_timestamps(db, scan_started_ns)
    except sqlite3.OperationalError as exc:  # an SQLite build without JSON functions
        return {"error": f"inventory aggregates unavailable: {exc}"}
    return result
