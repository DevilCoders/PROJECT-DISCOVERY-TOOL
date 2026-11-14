"""Working-copy and repository metadata, decoded without the VCS's client.

Subversion's working-copy database (``.svn/wc.db``) is opened from memory: PDT reads its bytes
through the verified, bounded reader and hands them to SQLite with ``deserialize``, so SQLite never
opens a file, follows a link or writes anywhere (its temporary data stays in memory). The
database is untrusted input: queries run read-only with a work budget, a 16 MiB value limit,
cell-size checks and untrusted schema functions off; the tables read must be plain ``CREATE
TABLE`` ones without virtual generated columns, so no value is computed as it is read; and
results are bounded and typed before use. Mercurial's changelog index, dirstate, bookmarks and phase roots
and Jujutsu's checkout file are decoded from bytes.
"""
from __future__ import annotations

import sqlite3
import struct
from urllib.parse import urlsplit, urlunsplit

from ...core.limits import limit_reached

# SQLite virtual-machine steps a working-copy database's queries may take.
MAX_SQLITE_STEPS = 50_000_000
_STEP_INTERVAL = 1000
# The longest string, blob or row SQLite builds while the queries run.
MAX_SQLITE_VALUE_BYTES = 16 * 1024 * 1024
# The working-copy tables the queries read.
_SVN_TABLES = ("REPOSITORY", "NODES", "ACTUAL_NODE", "LOCK", "EXTERNALS", "WORK_QUEUE", "WC_LOCK", "PRISTINE")
_NULL_NODE = b"\0" * 20
_PHASES = {1: "draft", 2: "secret", 32: "archived", 96: "internal"}
_REVLOG_ENTRY = 64
_REVLOG_INLINE = 1 << 16
# A revlog v1 index entry: offset and flags, compressed and uncompressed lengths, delta base,
# link revision, parents, node, padding.
_REVLOG_ENTRY_FORMAT = struct.Struct(">Qiiiiii20s12x")


def _safe_root(url: str) -> str:
    """A repository root as evidence: no credentials, query or fragment; a file:// root on this
    machine is named by its last component only (its path is the user's); "" when it is not a URL."""
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() == "file":
            return "file://.../" + (parts.path.rstrip("/").rsplit("/", 1)[-1] or "")
        host = parts.hostname or ""
        netloc = host + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, netloc, parts.path, "", "")) if parts.scheme and host else ""
    except ValueError:  # an unbalanced IPv6 bracket, a port out of range
        return ""


def _text(value: object, limit: int) -> str:
    """A database value as text of at most ``limit`` characters."""
    if isinstance(value, bytes):
        value = value[:limit * 4].decode("utf-8", errors="replace")
    return "" if value is None else str(value)[:limit]


def _number(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _sql_words(sql: str, count: int) -> list[str]:
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


def branch_kind(path: str) -> str:
    """trunk, branch or tag, by the conventional layout of a repository path; or ""."""
    parts = path.strip("/").split("/")
    if "trunk" in parts:
        return "trunk"
    if "branches" in parts[:-1]:
        return "branch"
    if "tags" in parts[:-1]:
        return "tag"
    return ""


def svn_wc_db(data: bytes, max_steps: int = MAX_SQLITE_STEPS) -> dict:
    """What a Subversion working-copy database says, from its bytes."""
    # The file header; SQLite is not handed anything else.
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
        del data  # SQLite holds its own copy
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
            return _svn_queries(db)
        except sqlite3.OperationalError as exc:
            if steps[0] > max_steps:
                limit_reached("steps", max_steps, steps[0])
                raise ValueError(f"working-copy database queries exceeded the {max_steps:,}-step budget") from exc
            raise ValueError(f"unreadable working-copy database: {exc}") from exc
        except sqlite3.DatabaseError as exc:
            raise ValueError(f"unreadable working-copy database: {exc}") from exc
    finally:
        db.close()


def _svn_queries(db: sqlite3.Connection) -> dict:
    schema = {str(name).upper(): str(sql or "") for name, sql in db.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' LIMIT 10000")}
    tables = set(schema)
    if not {"REPOSITORY", "NODES"} <= tables:
        raise ValueError("not a Subversion working-copy database (no REPOSITORY and NODES tables)")
    for table in _SVN_TABLES:
        # Subversion's tables are plain: a table that computes values as it is read (a virtual
        # table, a virtual generated column) is not one of its.
        if table in tables and (_sql_words(schema[table], 2) != ["CREATE", "TABLE"]
                                or any(row[6] in (1, 2) for row in db.execute(f"PRAGMA table_xinfo({table})"))):
            raise ValueError(f"not a Subversion working-copy database ({table} computes its values)")

    def columns(table: str) -> set[str]:
        return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}

    def count(sql: str, *parameters) -> int:
        return int(db.execute(sql, parameters).fetchone()[0] or 0)

    result: dict = {"format": db.execute("PRAGMA user_version").fetchone()[0]}
    # Values are cut to a bound in the query, and checked for their type after it.
    repositories = db.execute("SELECT id, substr(root, 1, 2000), substr(uuid, 1, 100) FROM REPOSITORY ORDER BY id "
                              "LIMIT 10").fetchall()
    root = db.execute("SELECT repos_id, substr(repos_path, 1, 2000), revision FROM NODES WHERE local_relpath = '' AND "
                      "op_depth = 0 LIMIT 1").fetchone()
    by_id = {row[0]: row for row in repositories}
    if root:
        repository = by_id.get(root[0])
        path = _text(root[1], 2000)
        result.update({"repository": _safe_root(_text(repository[1], 2000)) if repository else "",
                       "uuid": _text(repository[2], 100) if repository else "", "path": path,
                       "revision": _number(root[2]), "branch_kind": branch_kind(path)})
    base = db.execute("SELECT kind, COUNT(*), MIN(revision), MAX(revision) FROM NODES WHERE op_depth = 0 AND "
                      "presence = 'normal' AND kind IN ('file', 'dir', 'symlink') GROUP BY kind").fetchall()
    result["kinds"] = {str(kind): number for kind, number, _, _ in base}
    revisions = [value for _, _, low, high in base for value in (_number(low), _number(high)) if value is not None]
    result["revisions"] = (min(revisions), max(revisions)) if revisions else None
    result["scheduled"] = dict(db.execute(
        "SELECT presence, COUNT(*) FROM NODES WHERE op_depth > 0 AND presence IN ('normal', 'base-deleted', "
        "'not-present', 'incomplete', 'excluded', 'server-excluded') GROUP BY presence"))
    result["excluded"] = count("SELECT COUNT(*) FROM NODES WHERE op_depth = 0 AND (presence IN ('excluded', "
                               "'server-excluded') OR (kind = 'dir' AND depth IS NOT NULL AND depth != 'infinity'))")
    path = result.get("path", "")
    node_columns = columns("NODES")
    file_external = " AND file_external IS NULL" if "file_external" in node_columns else ""
    result["switched"] = count("SELECT COUNT(*) FROM NODES WHERE op_depth = 0 AND local_relpath != '' AND repos_path IS "
                               "NOT NULL AND repos_path != (CASE WHEN ? = '' THEN local_relpath ELSE ? || '/' || "
                               "local_relpath END)" + file_external, path, path)
    if "ACTUAL_NODE" in tables:
        actual = columns("ACTUAL_NODE")
        markers = [name for name in ("conflict_data", "tree_conflict_data", "conflict_old", "conflict_new",
                                     "conflict_working", "prop_reject") if name in actual]
        result["conflicts"] = count("SELECT COUNT(*) FROM ACTUAL_NODE WHERE "
                                    + " OR ".join(f"{name} IS NOT NULL" for name in markers)) if markers else 0
        result["changelists"] = [_text(row[0], 100) for row in db.execute(
            "SELECT DISTINCT substr(changelist, 1, 100) FROM ACTUAL_NODE WHERE changelist IS NOT NULL ORDER BY 1 "
            "LIMIT 20")] if "changelist" in actual else []
    for table, key in (("LOCK", "locks"), ("EXTERNALS", "externals"), ("WORK_QUEUE", "work_queue"),
                       ("WC_LOCK", "wc_locks")):
        result[key] = count(f"SELECT COUNT(*) FROM {table}") if table in tables else 0
    if "PRISTINE" in tables:
        number, size = db.execute("SELECT COUNT(*), COALESCE(SUM(CASE WHEN typeof(size) = 'integer' AND size > 0 "
                                  "THEN size END), 0) FROM PRISTINE").fetchone()
        result["pristine"] = (int(number or 0), _number(size) or 0)
    return result


def revlog_header(head: bytes) -> tuple[int, bool]:
    """(version, inline) from the first four bytes of a revlog index."""
    if len(head) < 4:
        raise ValueError("changelog index too short")
    header = struct.unpack(">I", head[:4])[0]
    return header & 0xFFFF, bool(header & _REVLOG_INLINE)


def hg_changelog(index: bytes) -> dict:
    """Changeset count, tip and heads (changesets without children) of a whole revlog v1
    changelog index. An inline index carries each revision's compressed data after its entry."""
    version, inline = revlog_header(index)
    if version != 1:
        return {"version": version}
    if not inline and len(index) % _REVLOG_ENTRY:
        raise ValueError("changelog index size is not a whole number of entries")
    # A parent always precedes its child, so a revision's parents are marked before the end.
    has_child = bytearray(len(index) // _REVLOG_ENTRY)
    position, count, node = 0, 0, b""
    while position + _REVLOG_ENTRY <= len(index):
        _, compressed, _, _, _, first, second, node = _REVLOG_ENTRY_FORMAT.unpack_from(index, position)
        if compressed < 0 or not -1 <= first < count or not -1 <= second < count:
            raise ValueError(f"changelog index entry {count} is not valid")
        for parent in (first, second):
            if parent >= 0:
                has_child[parent] = 1
        count += 1
        position += _REVLOG_ENTRY + (compressed if inline else 0)
    if position != len(index):
        raise ValueError("changelog index does not end on an entry")
    return {"version": 1, "inline": inline, "changesets": count, "tip": node.hex(),
            "heads": count - sum(has_child[:count])}


def hg_changelog_ends(head: bytes, tail: bytes, size: int) -> dict:
    """Changeset count and tip of a separate revlog v1 changelog index too large to read whole,
    from its first four bytes and its last entry; its heads are not counted."""
    version, inline = revlog_header(head)
    if version != 1:
        return {"version": version}
    if inline or size % _REVLOG_ENTRY:
        raise ValueError("changelog index size is not a whole number of entries")
    count = size // _REVLOG_ENTRY
    node = tail[-_REVLOG_ENTRY:][32:52] if count and len(tail) >= _REVLOG_ENTRY else b""
    return {"version": 1, "inline": False, "changesets": count, "tip": node.hex()}


def hg_dirstate(head: bytes) -> tuple[str, str]:
    """The working directory's parents (hex; "" for none) from the start of a dirstate file:
    v1 starts with them, a dirstate-v2 docket with its marker and then them in 32-byte fields."""
    if head.startswith(b"dirstate-v2\n"):
        first, second = head[12:32], head[44:64]
    else:
        first, second = head[:20], head[20:40]
    if len(first) < 20:
        raise ValueError("dirstate too short")
    return ("" if first == _NULL_NODE else first.hex()), ("" if len(second) < 20 or second == _NULL_NODE else second.hex())


def hg_bookmarks(text: str) -> list[str]:
    """Bookmark names from a bookmarks file ("node name" lines)."""
    names = []
    for line in text.splitlines()[:1000]:
        node, _, name = line.strip().partition(" ")
        if len(node) == 40 and name:
            names.append(name)
    return names


def protobuf_fields(data: bytes) -> dict[int, bytes | int]:
    """The top-level fields of a protocol-buffer message (the first of each number): length-
    delimited ones as bytes, varints as integers; stops at the first other wire type."""
    fields: dict[int, bytes | int] = {}
    position = 0

    def varint() -> int:
        nonlocal position
        value, shift = 0, 0
        while position < len(data) and shift < 64:
            byte = data[position]
            position += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
        raise ValueError("truncated varint")

    while position < len(data) and len(fields) < 64:
        key = varint()
        number, wire = key >> 3, key & 7
        if wire == 0:
            fields.setdefault(number, varint())
        elif wire == 2:
            length = varint()
            if length > len(data) - position:
                raise ValueError("truncated field")
            fields.setdefault(number, data[position:position + length])
            position += length
        else:
            break
    return fields


def jj_checkout(data: bytes) -> dict:
    """The workspace a Jujutsu working copy's checkout file names, and the operation it is at
    (field 3 and field 2 of the checkout message)."""
    fields = protobuf_fields(data[:65536])
    workspace, operation = fields.get(3, b""), fields.get(2, b"")
    return {"workspace": workspace.decode("utf-8", errors="replace") if isinstance(workspace, bytes) else "",
            "operation": operation.hex() if isinstance(operation, bytes) else ""}


def hg_phases(text: str) -> dict[str, int]:
    """Phase roots by phase name from a phaseroots file ("phase node" lines)."""
    roots: dict[str, int] = {}
    for line in text.splitlines()[:100_000]:
        phase, _, node = line.strip().partition(" ")
        if phase.isascii() and phase.isdigit() and len(phase) <= 3 and len(node) == 40:
            name = _PHASES.get(int(phase), f"phase {phase}")
            roots[name] = roots.get(name, 0) + 1
    return roots
