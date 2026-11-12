"""Local-only OSV advisory database import and query helpers."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import zipfile
from urllib.parse import quote
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any, Iterator

from .cvss import base_score, qualitative_severity

SCHEMA_VERSION = 2
_MAX_ZIP_MEMBERS = 5_000_000
_MAX_ZIP_TOTAL_BYTES = 32 * 1024 * 1024 * 1024
_IMPORT_BATCH = 500

_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    aliases_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT NOT NULL,
    severity TEXT NOT NULL,
    published TEXT,
    modified TEXT,
    withdrawn TEXT,
    references_json TEXT NOT NULL,
    source_file TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS affected_packages (
    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    affected_index INTEGER NOT NULL,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    purl TEXT NOT NULL,
    affected_json TEXT NOT NULL,
    PRIMARY KEY(advisory_id, affected_index, ecosystem, package_name)
);
CREATE INDEX IF NOT EXISTS idx_affected_lookup
ON affected_packages(ecosystem, package_name);
"""


def normalize_ecosystem(ecosystem: str) -> str:
    return ecosystem.strip().casefold()


def normalize_package_name(ecosystem: str, name: str) -> str:
    value = name.strip()
    if ecosystem.strip().casefold() == "pypi":
        # PEP 503 normalization: runs of "-", "_" and "." are equivalent.
        return re.sub(r"[-_.]+", "-", value).casefold()
    return value.casefold()


def default_database_path() -> Path:
    """Return the per-user local advisory database path."""
    return Path.home() / ".pdt" / "vulnerability-advisories.sqlite3"


_GHSA_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def _severity(record: dict[str, Any]) -> str:
    """Derive one severity from database_specific labels or CVSS vectors/scores."""
    scores: list[float] = []
    for item in record.get("severity", []) if isinstance(record.get("severity"), list) else []:
        if isinstance(item, dict) and item.get("score") is not None:
            score = base_score(str(item.get("type") or ""), item["score"])
            if score is not None:
                scores.append(score)
    if scores:
        return qualitative_severity(max(scores))
    database_specific = record.get("database_specific")
    if isinstance(database_specific, dict):
        label = _GHSA_SEVERITY.get(str(database_specific.get("severity", "")).upper())
        if label:
            return label
    return "UNKNOWN"


def advisory_severity(record: dict[str, Any]) -> str:
    """Public name for the severity derivation shared by local and online advisories."""
    return _severity(record)


def osv_record_to_advisories(
    record: dict[str, Any], ecosystem: str, package_name: str, *, source: str,
) -> list[dict[str, Any]]:
    """Normalize one OSV record into the advisory rows ``VulnerabilityDatabase.query`` returns.

    One row is produced per ``affected`` entry naming this ecosystem/package, so local and
    online advisories feed the same version matching and finding construction.
    """
    if not isinstance(record, dict) or not record.get("id"):
        return []
    aliases = sorted({
        str(item) for item in record.get("aliases", []) if isinstance(item, str) and item
    }) if isinstance(record.get("aliases"), list) else []
    references = sorted({
        str(item.get("url")) for item in record.get("references", [])
        if isinstance(item, dict) and item.get("url")
    }) if isinstance(record.get("references"), list) else []
    wanted_ecosystem = normalize_ecosystem(ecosystem)
    wanted_name = normalize_package_name(ecosystem, package_name)
    rows = []
    for affected in record.get("affected", []) if isinstance(record.get("affected"), list) else []:
        if not isinstance(affected, dict) or not isinstance(affected.get("package"), dict):
            continue
        package = affected["package"]
        affected_ecosystem = str(package.get("ecosystem") or "").strip()
        affected_name = str(package.get("name") or "").strip()
        # OSV ecosystems may carry a suffix (for example "Debian:12"); match the base name.
        if (
            normalize_ecosystem(affected_ecosystem.split(":", 1)[0]) != wanted_ecosystem
            or normalize_package_name(ecosystem, affected_name) != wanted_name
        ):
            continue
        rows.append({
            "id": str(record["id"]),
            "aliases": aliases,
            "summary": str(record.get("summary") or record["id"])[:4000],
            "details": str(record.get("details") or "")[:100_000],
            "severity": _severity(record),
            "published": record.get("published"),
            "modified": record.get("modified"),
            "withdrawn": record.get("withdrawn"),
            "references": references,
            "affected": affected,
            "ecosystem": affected_ecosystem or ecosystem,
            "source_file": source,
        })
    return rows


def _advisory_files(source: Path) -> Iterator[tuple[Path, str]]:
    if source.is_file():
        if source.suffix.lower() == ".json":
            yield source, source.name
        return
    if not source.is_dir():
        raise FileNotFoundError(f"Advisory source does not exist: {source}")
    for current, dirs, names in os.walk(source, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if not (Path(current) / name).is_symlink()
        )
        for name in sorted(names):
            path = Path(current) / name
            if name.lower().endswith(".json") and not path.is_symlink():
                yield path, path.relative_to(source).as_posix()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# A local advisory snapshot older than this is reported as stale in every report format.
STALE_SNAPSHOT_DAYS = 30


def _items(value: Any) -> list:
    """A list field of an advisory, or [] (a string would iterate as characters)."""
    return value if isinstance(value, list) else []


def _malformed_affected(entry: Any) -> bool:
    """An affected entry the matchers cannot read: wrong types where OSV has lists/objects."""
    if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
        return True
    if "versions" in entry and not isinstance(entry["versions"], list):
        return True
    ranges = entry.get("ranges", [])
    if not isinstance(ranges, list):
        return True
    return any(not isinstance(item, dict) or not isinstance(item.get("events", []), list) for item in ranges)


def read_only_uri(path: PurePath) -> str:
    """A read-only SQLite URI for an absolute path, including Windows UNC shares.

    SQLite accepts only an empty or ``localhost`` URI authority, so a UNC path
    (``\\\\server\\share\\...``) is written ``file:////server/share/...``, not the
    ``file://server/share/...`` that ``as_uri()`` produces. Built from ``as_posix()``:
    ``PurePath.as_uri()`` is deprecated (Python 3.14).
    """
    if not path.is_absolute():
        raise ValueError(f"advisory database path must be absolute: {path}")
    posix = quote(path.as_posix(), safe="/:")
    if posix.startswith("//"):
        return f"file://{posix}?mode=ro"          # UNC: file: + // + //server/share/...
    return f"file://{'' if posix.startswith('/') else '/'}{posix}?mode=ro"


class VulnerabilityDatabase:
    """SQLite-backed local advisory store. This class never performs network I/O.

    read_only=True opens an existing database without creating or migrating anything,
    which is how scans consume it.
    """

    def __init__(self, path: Path, *, read_only: bool = False):
        self.path = path.expanduser()
        self.read_only = read_only
        if read_only:
            if not self.path.is_file():
                raise FileNotFoundError(f"Local vulnerability database is not a file: {self.path}")
            self.connection = sqlite3.connect(read_only_uri(self.path.absolute()), uri=True)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        if not read_only:
            self.connection.executescript(_SCHEMA)
            self._migrate()
            self.connection.commit()
        columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(affected_packages)")
        }
        self._has_keys = {"ecosystem_key", "name_key"} <= columns

    def _migrate(self) -> None:
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(affected_packages)")}
        if "ecosystem_key" not in columns:
            self.connection.execute("ALTER TABLE affected_packages ADD COLUMN ecosystem_key TEXT")
        if "name_key" not in columns:
            self.connection.execute("ALTER TABLE affected_packages ADD COLUMN name_key TEXT")
        stale = self.connection.execute(
            "SELECT rowid, ecosystem, package_name FROM affected_packages "
            "WHERE ecosystem_key IS NULL OR name_key IS NULL"
        ).fetchall()
        self.connection.executemany(
            "UPDATE affected_packages SET ecosystem_key=?, name_key=? WHERE rowid=?",
            [
                (normalize_ecosystem(ecosystem), normalize_package_name(ecosystem, name), rowid)
                for rowid, ecosystem, name in stale
            ],
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_affected_key "
            "ON affected_packages(ecosystem_key, name_key)"
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "VulnerabilityDatabase":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def _iter_source_records(
        self, source: Path, max_record_bytes: int,
    ) -> Iterator[tuple[str, bytes | None, str | None]]:
        """Yield (relative name, raw JSON bytes or None, error) from a file, tree or ZIP."""
        if source.is_file() and source.suffix.lower() == ".zip":
            total = 0
            with zipfile.ZipFile(source) as archive:
                members = [info for info in archive.infolist() if not info.is_dir()]
                if len(members) > _MAX_ZIP_MEMBERS:
                    raise ValueError(
                        f"advisory archive has {len(members):,} members; limit is {_MAX_ZIP_MEMBERS:,}"
                    )
                for info in members:
                    if not info.filename.lower().endswith(".json"):
                        continue
                    if info.file_size > max_record_bytes:
                        yield info.filename, None, (
                            f"record exceeds {max_record_bytes} byte import budget"
                        )
                        continue
                    total += info.file_size
                    if total > _MAX_ZIP_TOTAL_BYTES:
                        raise ValueError("advisory archive exceeds the total uncompressed import budget")
                    with archive.open(info) as stream:
                        data = stream.read(max_record_bytes + 1)
                    if len(data) > max_record_bytes:
                        yield info.filename, None, (
                            f"record exceeds {max_record_bytes} byte import budget"
                        )
                        continue
                    yield info.filename, data, None
            return
        for path, relative in _advisory_files(source):
            try:
                if path.stat().st_size > max_record_bytes:
                    yield relative, None, f"record exceeds {max_record_bytes} byte import budget"
                    continue
                yield relative, path.read_bytes(), None
            except OSError as exc:
                yield relative, None, f"{type(exc).__name__}: {exc}"

    def import_osv(self, source: Path, *, max_record_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
        """Import OSV JSON from a local file, directory tree or OSV ``all.zip`` archive.

        Each advisory is applied atomically (SAVEPOINT); commits are batched for speed.
        """
        if self.read_only:
            raise PermissionError("advisory database was opened read-only")
        source = source.expanduser().resolve(strict=True)
        if source.is_file() and source.suffix.lower() not in {".json", ".zip"}:
            # Anything else would import nothing yet look like a successful refresh.
            raise ValueError(f"Unsupported advisory source (expected a .json file, an OSV .zip or a directory): {source}")
        imported = 0
        skipped = 0
        errors: list[str] = []
        affected_count = 0
        pending = 0

        self.connection.execute("BEGIN")
        try:
            for relative, raw, error in self._iter_source_records(source, max_record_bytes):
                if error is not None:
                    skipped += 1
                    errors.append(f"{relative}: {error}")
                    continue
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                    skipped += 1
                    errors.append(f"{relative}: {type(exc).__name__}: {exc}")
                    continue
                if not isinstance(data, dict) or not data.get("id") or not isinstance(data.get("affected"), list):
                    skipped += 1
                    errors.append(f"{relative}: not a supported OSV vulnerability record")
                    continue
                malformed = [entry for entry in data["affected"] if _malformed_affected(entry)]
                if malformed:
                    # Matching would raise on these; the record's valid entries still count.
                    errors.append(f"{relative}: {len(malformed)} malformed affected entr"
                                  f"{'y' if len(malformed) == 1 else 'ies'} skipped")
                    data = {**data, "affected": [entry for entry in data["affected"] if not _malformed_affected(entry)]}
                try:
                    affected_count += self._store_advisory(data, relative)
                    imported += 1
                except sqlite3.Error as exc:
                    skipped += 1
                    errors.append(f"{relative}: {type(exc).__name__}: {exc}")
                pending += 1
                if pending >= _IMPORT_BATCH:
                    self.connection.execute("COMMIT")
                    self.connection.execute("BEGIN")
                    pending = 0
            if imported:
                # A no-op import must not refresh the snapshot's provenance and age.
                self._write_import_metadata(source, imported)
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
        status = self.status()
        return {
            "imported_advisories": imported,
            "affected_package_records": affected_count,
            "skipped_records": skipped,
            "errors": errors[:200],
            "database": str(self.path),
            "imported_at": status.get("last_imported_at"),
        }

    def _store_advisory(self, data: dict[str, Any], relative: str) -> int:
        advisory_id = str(data["id"])
        aliases = sorted({
            str(item) for item in _items(data.get("aliases")) if isinstance(item, str) and item
        })
        references = sorted({
            str(item.get("url")) for item in _items(data.get("references"))
            if isinstance(item, dict) and item.get("url")
        })
        rows = []
        for index, affected in enumerate(data["affected"]):
            if not isinstance(affected, dict) or not isinstance(affected.get("package"), dict):
                continue
            package = affected["package"]
            ecosystem = str(package.get("ecosystem") or "").strip()
            package_name = str(package.get("name") or "").strip()
            if not ecosystem or not package_name:
                continue
            rows.append((
                advisory_id, index, ecosystem, package_name,
                str(package.get("purl") or ""),
                json.dumps(affected, separators=(",", ":"), ensure_ascii=False),
                normalize_ecosystem(ecosystem),
                normalize_package_name(ecosystem, package_name),
            ))
        self.connection.execute("SAVEPOINT advisory")
        try:
            self.connection.execute(
                """INSERT OR REPLACE INTO advisories
                (id, aliases_json, summary, details, severity, published,
                 modified, withdrawn, references_json, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    advisory_id, json.dumps(aliases), str(data.get("summary") or advisory_id)[:4000],
                    str(data.get("details") or "")[:100_000], _severity(data),
                    data.get("published"), data.get("modified"), data.get("withdrawn"),
                    json.dumps(references), relative,
                ),
            )
            self.connection.execute("DELETE FROM affected_packages WHERE advisory_id=?", (advisory_id,))
            self.connection.executemany(
                """INSERT INTO affected_packages
                (advisory_id, affected_index, ecosystem, package_name, purl, affected_json,
                 ecosystem_key, name_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            self.connection.execute("RELEASE advisory")
        except sqlite3.Error:
            self.connection.execute("ROLLBACK TO advisory")
            self.connection.execute("RELEASE advisory")
            raise
        return len(rows)

    def _write_import_metadata(self, source: Path, imported: int) -> None:
        provenance = {
            "last_imported_at": datetime.now(timezone.utc).isoformat(),
            "last_source_name": source.name,
            "last_source_kind": "directory" if source.is_dir() else source.suffix.lower().lstrip("."),
            "last_imported_records": str(imported),
        }
        if source.is_file():
            provenance["last_source_sha256"] = _file_sha256(source)
        self.connection.executemany(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            list(provenance.items()),
        )

    def query(self, ecosystem: str, package_name: str) -> list[dict[str, Any]]:
        """Return local advisory matches for an ecosystem/package coordinate."""
        if self._has_keys:
            rows = self.connection.execute(
                """SELECT a.*, p.affected_json, p.ecosystem AS affected_ecosystem
                FROM affected_packages p
                JOIN advisories a ON a.id=p.advisory_id
                WHERE p.ecosystem_key=? AND p.name_key=?
                ORDER BY a.id""",
                (normalize_ecosystem(ecosystem), normalize_package_name(ecosystem, package_name)),
            ).fetchall()
        else:
            # Pre-migration database opened read-only: slower, but still name-normalized.
            rows = [
                row for row in self.connection.execute(
                    """SELECT a.*, p.affected_json, p.ecosystem AS affected_ecosystem,
                              p.package_name AS affected_name
                    FROM affected_packages p
                    JOIN advisories a ON a.id=p.advisory_id
                    WHERE lower(p.ecosystem)=lower(?)
                    ORDER BY a.id""",
                    (ecosystem,),
                )
                if normalize_package_name(ecosystem, row["affected_name"])
                == normalize_package_name(ecosystem, package_name)
            ]
        return [
            {
                "id": row["id"],
                "aliases": json.loads(row["aliases_json"]),
                "summary": row["summary"],
                "details": row["details"],
                "severity": row["severity"],
                "published": row["published"],
                "modified": row["modified"],
                "withdrawn": row["withdrawn"],
                "references": json.loads(row["references_json"]),
                "affected": json.loads(row["affected_json"]),
                "ecosystem": row["affected_ecosystem"],
                "source_file": row["source_file"],
            }
            for row in rows
        ]

    def status(self) -> dict[str, Any]:
        advisory_count = self.connection.execute(
            "SELECT COUNT(*) FROM advisories"
        ).fetchone()[0]
        affected_count = self.connection.execute(
            "SELECT COUNT(*) FROM affected_packages"
        ).fetchone()[0]
        ecosystem_rows = self.connection.execute(
            "SELECT ecosystem, COUNT(DISTINCT advisory_id) FROM affected_packages GROUP BY ecosystem ORDER BY ecosystem"
        ).fetchall()
        metadata = {
            row["key"]: row["value"]
            for row in self.connection.execute("SELECT key, value FROM metadata")
        }
        result = {
            "database": str(self.path),
            "advisory_count": advisory_count,
            "affected_package_records": affected_count,
            "ecosystems": {row[0]: row[1] for row in ecosystem_rows},
            "indexed_lookup": self._has_keys,
            **metadata,
        }
        imported_at = metadata.get("last_imported_at")
        if imported_at:
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(imported_at)
                result["snapshot_age_days"] = max(0, age.days)
                # Advisories published since the import are missing from a stale snapshot.
                result["stale_after_days"] = STALE_SNAPSHOT_DAYS
                result["stale"] = result["snapshot_age_days"] > STALE_SNAPSHOT_DAYS
            except ValueError:
                pass
        return result

    def covers(self, ecosystem: str) -> bool:
        """Whether the snapshot holds any advisory for this ecosystem."""
        row = self.connection.execute(
            "SELECT 1 FROM affected_packages WHERE ecosystem = ? LIMIT 1", (ecosystem,),
        ).fetchone()
        return row is not None
