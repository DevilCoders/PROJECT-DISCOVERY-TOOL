"""Decoded version-control metadata: Subversion working-copy databases, Mercurial changelogs and
dirstates, Jujutsu and Pijul layouts and Perforce settings. Built fixtures pin the decoding, the
real clients (where installed) cross-check it, and damaged or hostile input is refused."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import struct
import subprocess
from pathlib import Path

import pytest

from project_discovery.analyzers.delivery import vcs as vcs_module
from project_discovery.analyzers.delivery import vcs_metadata
from project_discovery.analyzers.delivery.vcs import VCSHostingAnalyzer
from project_discovery.cli import run_scan
from project_discovery.core.limits import accounting
from project_discovery.models import FileRecord

# The tables of a Subversion working-copy database (format 31: Subversion 1.8 to 1.15) that
# PDT reads, as Subversion creates them.
_SVN_SCHEMA = """
CREATE TABLE REPOSITORY (id INTEGER PRIMARY KEY AUTOINCREMENT, root TEXT UNIQUE NOT NULL, uuid TEXT NOT NULL);
CREATE TABLE WCROOT (id INTEGER PRIMARY KEY AUTOINCREMENT, local_abspath TEXT UNIQUE);
CREATE TABLE PRISTINE (checksum TEXT NOT NULL PRIMARY KEY, compression INTEGER, size INTEGER NOT NULL,
  refcount INTEGER NOT NULL, md5_checksum TEXT NOT NULL);
CREATE TABLE ACTUAL_NODE (wc_id INTEGER NOT NULL REFERENCES WCROOT (id), local_relpath TEXT NOT NULL,
  parent_relpath TEXT, properties BLOB, conflict_old TEXT, conflict_new TEXT, conflict_working TEXT,
  prop_reject TEXT, changelist TEXT, text_mod TEXT, tree_conflict_data TEXT, conflict_data BLOB,
  older_checksum TEXT, left_checksum TEXT, right_checksum TEXT, PRIMARY KEY (wc_id, local_relpath));
CREATE TABLE LOCK (repos_id INTEGER NOT NULL REFERENCES REPOSITORY (id), repos_relpath TEXT NOT NULL,
  lock_token TEXT NOT NULL, lock_owner TEXT, lock_comment TEXT, lock_date INTEGER,
  PRIMARY KEY (repos_id, repos_relpath));
CREATE TABLE WORK_QUEUE (id INTEGER PRIMARY KEY AUTOINCREMENT, work BLOB NOT NULL);
CREATE TABLE WC_LOCK (wc_id INTEGER NOT NULL REFERENCES WCROOT (id), local_dir_relpath TEXT NOT NULL,
  locked_levels INTEGER NOT NULL DEFAULT -1, PRIMARY KEY (wc_id, local_dir_relpath));
CREATE TABLE NODES (wc_id INTEGER NOT NULL REFERENCES WCROOT (id), local_relpath TEXT NOT NULL,
  op_depth INTEGER NOT NULL, parent_relpath TEXT, repos_id INTEGER REFERENCES REPOSITORY (id), repos_path TEXT,
  revision INTEGER, presence TEXT NOT NULL, moved_here INTEGER, moved_to TEXT, kind TEXT NOT NULL,
  properties BLOB, depth TEXT, checksum TEXT, symlink_target TEXT, changed_revision INTEGER,
  changed_date INTEGER, changed_author TEXT, translated_size INTEGER, last_mod_time INTEGER, dav_cache BLOB,
  file_external INTEGER, inherited_props BLOB, PRIMARY KEY (wc_id, local_relpath, op_depth));
CREATE TABLE EXTERNALS (wc_id INTEGER NOT NULL REFERENCES WCROOT (id), local_relpath TEXT NOT NULL,
  parent_relpath TEXT NOT NULL, repos_id INTEGER NOT NULL REFERENCES REPOSITORY (id), presence TEXT NOT NULL,
  kind TEXT NOT NULL, def_local_relpath TEXT NOT NULL, def_repos_relpath TEXT NOT NULL,
  def_operational_revision TEXT, def_revision TEXT, PRIMARY KEY (wc_id, local_relpath));
PRAGMA user_version = 31;
"""
# Credentials, a query and a fragment in the repository root, none of which may be reported.
_ROOT_PASSWORD = "hunter2" + "-wc"
_CREDENTIALED_ROOT = "https://alice:" + _ROOT_PASSWORD + "@svn.example.com/repo?access=" + "q-param" + "#frag"
# A branch checkout: a switched subtree, a depth-limited directory, an excluded one, a symlink,
# base nodes at two revisions, one scheduled addition and one scheduled deletion.
_BRANCH_NODES = (
    ("", 0, "branches/feature-x", 7, "normal", "dir", "infinity"),
    ("README.md", 0, "branches/feature-x/README.md", 7, "normal", "file", None),
    ("src", 0, "branches/feature-x/src", 5, "normal", "dir", "infinity"),
    ("src/app.py", 0, "branches/feature-x/src/app.py", 5, "normal", "file", None),
    ("vendor", 0, "trunk/vendor", 7, "normal", "dir", "infinity"),
    ("docs", 0, "branches/feature-x/docs", 7, "normal", "dir", "empty"),
    ("private", 0, "branches/feature-x/private", 7, "excluded", "dir", None),
    ("link", 0, "branches/feature-x/link", 7, "normal", "symlink", None),
    ("src/new.py", 2, None, None, "normal", "file", None),
    ("README.md", 1, None, None, "base-deleted", "file", None),
)


def _wc_db(path: Path, root: str = _CREDENTIALED_ROOT, nodes=_BRANCH_NODES, *, actual=(), locks=(), externals=0,
           work_queue=0, wc_locks=0, pristine=()) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    try:
        db.executescript(_SVN_SCHEMA)
        db.execute("INSERT INTO REPOSITORY (id, root, uuid) VALUES (1, ?, ?)",
                   (root, "5d1f7a8e-0000-4000-8000-000000000001"))
        db.execute("INSERT INTO WCROOT (id, local_abspath) VALUES (1, NULL)")
        for local, op_depth, repos_path, revision, presence, kind, depth in nodes:
            parent = None if local == "" else (local.rsplit("/", 1)[0] if "/" in local else "")
            db.execute("INSERT INTO NODES (wc_id, local_relpath, op_depth, parent_relpath, repos_id, repos_path, "
                       "revision, presence, kind, depth, changed_author) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'alice')",
                       (local, op_depth, parent, 1 if repos_path else None, repos_path, revision, presence, kind, depth))
        for local, changelist, conflict in actual:
            db.execute("INSERT INTO ACTUAL_NODE (wc_id, local_relpath, changelist, conflict_data) VALUES (1, ?, ?, ?)",
                       (local, changelist, conflict))
        for relpath, owner, comment in locks:
            db.execute("INSERT INTO LOCK VALUES (1, ?, 'opaquelocktoken:5f0e', ?, ?, 0)", (relpath, owner, comment))
        for number in range(externals):
            db.execute("INSERT INTO EXTERNALS VALUES (1, ?, '', 1, 'normal', 'dir', '', 'lib', NULL, NULL)",
                       (f"ext{number}",))
        for _ in range(work_queue):
            db.execute("INSERT INTO WORK_QUEUE (work) VALUES (x'28297a')")
        for number in range(wc_locks):
            db.execute("INSERT INTO WC_LOCK VALUES (1, ?, -1)", (f"dir{number}",))
        for number, size in enumerate(pristine):
            db.execute("INSERT INTO PRISTINE VALUES (?, 0, ?, 1, ?)", (f"$sha1${number:040d}", size, f"$md5 ${number}"))
        db.commit()
    finally:
        db.close()
    return path


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


def _analyze(root: Path, relative: str) -> list:
    path = root / relative
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Metadata")
    analyzer = VCSHostingAnalyzer()
    assert analyzer.supports(record), relative
    return analyzer.analyze(path, record)


def _text(findings: list) -> str:
    return json.dumps([item.to_dict() for item in findings])


# ---------------------------------------------------------------------------------------------
# Subversion


def test_subversion_working_copy_is_decoded_from_its_database(tmp_path: Path):
    _wc_db(tmp_path / "wc/.svn/wc.db",
           actual=(("src/app.py", "review", b"conflict"), ("src/new.py", "review", None), ("docs", "docs-pass", None)),
           locks=(("branches/feature-x/README.md", "alice", "Alice is editing"),), externals=1, work_queue=1,
           wc_locks=1, pristine=(1000, 2048))
    findings = _analyze(tmp_path, "wc/.svn/wc.db")
    repository, conflicts, cleanup = findings
    assert repository.title == "Subversion repository metadata: wc"
    assert repository.confidence == "CONFIRMED"
    assert repository.detail == (
        "Subversion working copy (format 31) of https://svn.example.com/repo at /branches/feature-x (a branch), "
        "revision 7: 2 files, 4 directories, 1 symlink; mixed revisions 5 to 7; 2 scheduled changes (1 added or "
        "copied, 1 deleted); 1 switched subtree; 2 excluded or depth-limited nodes (a sparse checkout); "
        "changelists docs-pass, review; 1 repository lock held; 1 external; 2 pristine copies (2.977 KiB).")
    assert repository.evidence == ["wc/.svn/wc.db", "repository UUID: 5d1f7a8e-0000-4000-8000-000000000001",
                                   "path: branches/feature-x", "revision: 7"]
    assert (conflicts.title, conflicts.severity) == ("Subversion conflicts: wc", "LOW")
    assert conflicts.detail == ("1 node of the working copy is in conflict (text, property or tree conflicts); "
                                "svn resolve marks a node resolved once its conflict is settled.")
    assert (cleanup.title, cleanup.severity) == ("Subversion working copy needs cleanup: wc", "LOW")
    assert cleanup.detail == ("An interrupted operation left 1 queued work item and 1 working-copy lock; svn cleanup "
                              "completes or releases them.")
    # Credentials, query and fragment of the root, lock owners and comments, authors and lock
    # tokens stay out of the findings.
    text = _text(findings)
    for private in (_ROOT_PASSWORD, "alice", "Alice", "q-param", "frag", "opaquelocktoken", "editing"):
        assert private not in text, private


def test_subversion_local_repository_roots_are_named_by_their_last_component(tmp_path: Path):
    for number, root in enumerate(("file:///home/alice/repositories/project", "file:///C:/Users/alice/svn/project")):
        _wc_db(tmp_path / f"wc{number}/.svn/wc.db", root, (("", 0, "trunk", 3, "normal", "dir", "infinity"),))
        findings = _analyze(tmp_path, f"wc{number}/.svn/wc.db")
        assert findings[0].detail == ("Subversion working copy (format 31) of file://.../project at /trunk, revision 3: "
                                      "0 files, 1 directory.")
        assert "alice" not in _text(findings)


def test_subversion_tag_checkout_and_clean_working_copy_add_no_other_findings(tmp_path: Path):
    _wc_db(tmp_path / "tag/.svn/wc.db", "svn://svn.example.com/repo",
           (("", 0, "tags/v1.0", 12, "normal", "dir", "infinity"), ("a.c", 0, "tags/v1.0/a.c", 12, "normal", "file", None)))
    findings = _analyze(tmp_path, "tag/.svn/wc.db")
    assert len(findings) == 1
    assert findings[0].detail == ("Subversion working copy (format 31) of svn://svn.example.com/repo at /tags/v1.0 "
                                  "(a tag), revision 12: 1 file, 1 directory.")


def test_damaged_and_hostile_working_copy_databases_are_refused(tmp_path: Path):
    good = _wc_db(tmp_path / "good.db").read_bytes()
    for data in (b"", b"SQLite format 3\x00" + b"\x00" * 100, b"SQLite format 3\x00" + bytes(range(256)) * 16,
                 good[: len(good) // 2]):
        with pytest.raises(ValueError):
            vcs_metadata.svn_wc_db(data)
    # A SQLite database that is not a working copy.
    other = tmp_path / "other.db"
    with sqlite3.connect(other) as db:
        db.execute("CREATE TABLE notes (body TEXT)")
        db.execute("INSERT INTO notes VALUES ('" + "x" * 600 + "')")
    db.close()
    with pytest.raises(ValueError, match="not a Subversion working-copy database"):
        vcs_metadata.svn_wc_db(other.read_bytes())
    # A table that computes its values when read: a 100 MB blob per row.
    generated = tmp_path / "generated.db"
    db = sqlite3.connect(generated)
    db.executescript("CREATE TABLE REPOSITORY (id INTEGER PRIMARY KEY, root TEXT, uuid TEXT);"
                     "CREATE TABLE NODES (wc_id INTEGER, local_relpath TEXT, op_depth INTEGER, repos_id INTEGER, "
                     "repos_path TEXT, revision INTEGER, presence TEXT, depth TEXT, "
                     "kind TEXT GENERATED ALWAYS AS (zeroblob(100000000)) VIRTUAL);"
                     "INSERT INTO NODES (wc_id, local_relpath, op_depth) VALUES (1, '', 0);"
                     "CREATE TABLE padding (body TEXT); INSERT INTO padding VALUES (printf('%.600c', 'x'));")
    db.close()
    with pytest.raises(ValueError, match="computes its values"):
        vcs_metadata.svn_wc_db(generated.read_bytes())


def test_odd_values_and_disguised_virtual_tables(tmp_path: Path):
    # Values of the wrong type or size are bounded or dropped; a root that is not a URL is left out.
    path = _wc_db(tmp_path / "odd.db", "https://[::1/repo", (("", 0, "trunk", "x" * 5000, "normal", "dir", "infinity"),
                                                            ("a", 0, "trunk/a", 3, "normal", "file", None)),
                  actual=(("a", "c" * 500, None),), pristine=(10,))
    with sqlite3.connect(path) as db:
        db.execute("UPDATE PRISTINE SET size = 'large'")
    db.close()
    info = vcs_metadata.svn_wc_db(path.read_bytes())
    assert (info["repository"], info["revision"], info["revisions"]) == ("", None, (3, 3))
    assert info["changelists"] == ["c" * 100] and info["pristine"] == (1, 0)
    assert vcs_metadata._safe_root("svn://host:99999/repo") == "" and vcs_metadata._safe_root("not a url") == ""
    assert vcs_metadata._sql_words("  create/**/VIRTUAL -- x\n TABLE t", 3) == ["CREATE", "VIRTUAL", "TABLE"]
    assert vcs_metadata._sql_words("CREATE TABLE \"NODES\"(", 4) == ["CREATE", "TABLE", '"', "NODES"]
    assert vcs_metadata.hg_phases("9" * 5000 + " " + "a" * 40 + "\n2 " + "b" * 40 + "\n") == {"secret": 1}


def test_virtual_tables_are_refused(tmp_path: Path):
    path = tmp_path / "virtual.db"
    db = sqlite3.connect(path)
    try:
        db.execute("CREATE TABLE REPOSITORY (id INTEGER PRIMARY KEY, root TEXT, uuid TEXT)")
        for module in ("fts5", "fts4", "rtree"):
            try:
                columns = "id, minx, maxx" if module == "rtree" else "local_relpath, kind"
                # SQLite reads the comment as a space: the table is virtual whatever its text.
                db.execute(f"CREATE/**/VIRTUAL TABLE NODES USING {module}({columns})")
                break
            except sqlite3.OperationalError:
                continue
        else:
            pytest.skip("this SQLite has no virtual table module")
        db.commit()
    finally:
        db.close()
    with pytest.raises(ValueError, match="computes its values"):
        vcs_metadata.svn_wc_db(path.read_bytes())


def test_working_copy_queries_stop_at_the_step_budget(tmp_path: Path):
    nodes = [("", 0, "trunk", 1, "normal", "dir", "infinity")] + [
        (f"f{number}", 0, f"trunk/f{number}", 1, "normal", "file", None) for number in range(3000)]
    data = _wc_db(tmp_path / "big.db", nodes=nodes).read_bytes()
    assert vcs_metadata.svn_wc_db(data)["kinds"] == {"dir": 1, "file": 3000}
    with accounting() as account, pytest.raises(ValueError, match="5,000-step budget"):
        vcs_metadata.svn_wc_db(data, max_steps=5000)
    assert account.limits and account.limits[0][:2] == ("steps", 5000.0)


def test_working_copy_database_size_budget_and_identity(tmp_path: Path, monkeypatch):
    _wc_db(tmp_path / "wc/.svn/wc.db")
    monkeypatch.setattr(vcs_module, "_MAX_WC_DB_BYTES", 1024)
    findings = _analyze(tmp_path, "wc/.svn/wc.db")
    assert findings[0].confidence == "CONFIRMED"
    assert "larger than the 1,024-byte budget" in findings[0].detail
    monkeypatch.undo()
    path = tmp_path / "wc/.svn/wc.db"
    observed = path.stat()
    record = FileRecord("wc/.svn/wc.db", observed.st_size, ".db", "Metadata", analysis_identity=(
        observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns))
    with path.open("ab") as stream:
        stream.write(b"\0" * 4096)
    findings = VCSHostingAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN" and "identity changed" in findings[0].detail.lower()


# ---------------------------------------------------------------------------------------------
# Mercurial


def _revlog_index(nodes: list[bytes], *, inline: bool, version: int = 1, parents=None) -> bytes:
    """A revlog changelog index; an inline one carries each revision's data after its entry.
    Revisions are linear unless ``parents`` gives each one's (p1, p2)."""
    index = bytearray()
    for revision, node in enumerate(nodes):
        data = b"u" + b"x" * (revision + 1) if inline else b""
        size = len(data) if inline else 10
        first, second = parents[revision] if parents else (revision - 1, -1)
        entry = bytearray(struct.pack(">Qiiiiii20s12x", 0, size, size, revision, revision, first, second, node))
        if revision == 0:  # the header overlays the first entry's offset
            entry[:4] = struct.pack(">I", version | (1 << 16 if inline else 0) | (1 << 17))
        index += entry + data
    return bytes(index)


_NODES = [bytes([value]) * 20 for value in (0x11, 0x22, 0x33)]
_DUMMY_CHANGELOG = b"\0\0\0\x02 dummy changelog to prevent using the old repo layout"


def test_mercurial_changelog_dirstate_bookmarks_phases_and_features(tmp_path: Path):
    _write(tmp_path, {
        "repo/.hg/requires": "exp-sparse\nshare-safe\n",
        "repo/.hg/store/requires": "dotencode\nfncache\ngeneraldelta\nlfs\nrevlogv1\nsparserevlog\nstore\n",
        "repo/.hg/00changelog.i": _DUMMY_CHANGELOG,
        # Two heads: revisions 1 and 2 are both children of revision 0.
        "repo/.hg/store/00changelog.i": _revlog_index(_NODES, inline=True, parents=[(-1, -1), (0, -1), (0, -1)]),
        "repo/.hg/dirstate": _NODES[2] + _NODES[1] + b"n\x00\x00\x01\xa4",
        "repo/.hg/branch": "stable\n",
        "repo/.hg/bookmarks": f"{_NODES[2].hex()} feature-x\n{_NODES[1].hex()} release\nnot a bookmark\n",
        "repo/.hg/bookmarks.current": "feature-x",
        "repo/.hg/store/phaseroots": f"1 {_NODES[1].hex()}\n2 {_NODES[2].hex()}\n",
        "repo/.hg/shelved/wip.patch": "", "repo/.hg/shelved/wip.shelve": "", "repo/.hg/shelved/wip.hg": "",
    })
    findings = _analyze(tmp_path, "repo/.hg/requires")
    assert len(findings) == 1
    assert findings[0].detail == (
        "Mercurial repository: 3 changesets, tip 333333333333, 2 heads (changesets without children); working "
        "directory at 333333333333 on branch stable, "
        "with an uncommitted merge of 222222222222; bookmarks feature-x, release (active: feature-x); phase roots: "
        "1 draft, 1 secret; 1 shelved change; uses LFS, a sparse checkout.")
    assert findings[0].evidence == [
        "repo/.hg/requires", "requirements: exp-sparse, share-safe",
        "store requirements: dotencode, fncache, generaldelta, lfs, revlogv1, sparserevlog, store"]


def test_mercurial_separate_index_dirstate_v2_empty_and_shared_repositories(tmp_path: Path):
    nodes = [bytes([value]) * 20 for value in range(1, 6)]
    _write(tmp_path, {
        "plain/.hg/requires": "dirstate-v2\nshare-safe\n", "plain/.hg/store/requires": "revlogv1\nstore\n",
        "plain/.hg/store/00changelog.i": _revlog_index(nodes, inline=False),
        "plain/.hg/dirstate": b"dirstate-v2\n" + nodes[4] + b"\0" * 12 + b"\0" * 32 + b"\0" * 40,
        # "hg init" leaves a dummy changelog beside the empty store.
        "empty/.hg/requires": "share-safe\n", "empty/.hg/store/requires": "revlogv1\nstore\n",
        "empty/.hg/00changelog.i": _DUMMY_CHANGELOG,
        "shared/.hg/requires": "share-safe\nshared\n", "shared/.hg/sharedpath": "/home/alice/source/.hg",
        "old/.hg/requires": "revlogv1\n", "old/.hg/00changelog.i": _revlog_index(nodes[:2], inline=True),
        "v2/.hg/requires": "store\n", "v2/.hg/store/00changelog.i": _revlog_index(nodes[:1], inline=False, version=2),
    })
    assert _analyze(tmp_path, "plain/.hg/requires")[0].detail == (
        "Mercurial repository: 5 changesets, tip 050505050505, 1 head (changesets without children); working directory "
        "at 050505050505 on branch default.")
    assert _analyze(tmp_path, "empty/.hg/requires")[0].detail == "Mercurial repository: 0 changesets."
    shared = _analyze(tmp_path, "shared/.hg/requires")
    assert shared[0].detail == "Mercurial repository: its store is shared with another repository, which is not followed."
    assert "alice" not in _text(shared)
    assert _analyze(tmp_path, "old/.hg/requires")[0].detail == (
        "Mercurial repository: 2 changesets, tip 020202020202, 1 head (changesets without children).")
    assert _analyze(tmp_path, "v2/.hg/requires")[0].detail == (
        "Mercurial repository: a revlog version 2 changelog, which is not decoded.")


def test_damaged_mercurial_files_are_skipped(tmp_path: Path, monkeypatch):
    index = _revlog_index(_NODES, inline=True)
    negative = bytearray(index)
    negative[8:12] = struct.pack(">i", -5)
    _write(tmp_path, {
        "cut/.hg/requires": "store\n", "cut/.hg/store/00changelog.i": index[:-3], "cut/.hg/dirstate": b"short",
        "negative/.hg/requires": "store\n", "negative/.hg/store/00changelog.i": bytes(negative),
        "ragged/.hg/requires": "store\n", "ragged/.hg/store/00changelog.i": _revlog_index(_NODES, inline=False)[:-1],
        # A parent after its child: not a changelog.
        "loop/.hg/requires": "store\n",
        "loop/.hg/store/00changelog.i": _revlog_index(_NODES, inline=False, parents=[(-1, -1), (2, -1), (1, -1)]),
        "big/.hg/requires": "store\n", "big/.hg/store/00changelog.i": index,
        "large/.hg/requires": "store\n",
        "large/.hg/store/00changelog.i": _revlog_index([bytes([value]) * 20 for value in range(1, 5)], inline=False),
    })
    for name in ("cut", "negative", "ragged", "loop"):
        assert _analyze(tmp_path, f"{name}/.hg/requires")[0].detail == "Mercurial repository metadata is present.", name
    monkeypatch.setattr(vcs_module, "_MAX_HG_INLINE_INDEX_BYTES", 100)
    assert _analyze(tmp_path, "big/.hg/requires")[0].detail == "Mercurial repository metadata is present."
    # A separate index over its budget gives its count and tip from its ends, without heads.
    monkeypatch.setattr(vcs_module, "_MAX_HG_INDEX_BYTES", 128)
    with accounting() as account:
        detail = _analyze(tmp_path, "large/.hg/requires")[0].detail
    assert detail == "Mercurial repository: 4 changesets, tip 040404040404."
    assert ("bytes", 128.0, 256.0) in account.limits


def test_linked_directories_inside_control_directories_are_not_followed(tmp_path: Path):
    elsewhere = tmp_path / "elsewhere"
    _write(elsewhere, {
        "store/requires": "revlogv1\nstore\n", "store/00changelog.i": _revlog_index(_NODES, inline=True),
        "store/phaseroots": f"1 {_NODES[0].hex()}\n",
        **{f"many/{number}.change": b"x" for number in range(3)},
        "working_copy/checkout": _checkout("borrowed"),
    })
    _write(tmp_path, {
        "hg/.hg/requires": "share-safe\n",
        "jj/.jj/repo/store/type": "git", "pj/.pijul/pristine/db": b"\0" * 64,
    })
    try:
        (tmp_path / "hg/.hg/store").symlink_to(elsewhere / "store", target_is_directory=True)
        (tmp_path / "jj/.jj/working_copy").symlink_to(elsewhere / "working_copy", target_is_directory=True)
        (tmp_path / "jj/.jj/repo/op_store").mkdir()
        (tmp_path / "jj/.jj/repo/op_store/operations").symlink_to(elsewhere / "many", target_is_directory=True)
        (tmp_path / "pj/.pijul/changes").symlink_to(elsewhere / "many", target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available")
    assert _analyze(tmp_path, "hg/.hg/requires")[0].detail == (
        "Mercurial repository: its store is a link to another location, which is not followed.")
    assert _analyze(tmp_path, "jj/.jj/repo/store/type")[0].detail == "Jujutsu repository: git backend."
    assert _analyze(tmp_path, "pj/.pijul/pristine/db")[0].detail == "Pijul repository: no recorded changes."


def test_mercurial_decoders():
    assert vcs_metadata.hg_dirstate(b"\0" * 40) == ("", "")
    assert vcs_metadata.hg_dirstate(b"dirstate-v2\n" + b"\x01" * 20 + b"\0" * 44) == ("01" * 20, "")
    with pytest.raises(ValueError):
        vcs_metadata.hg_dirstate(b"\x01" * 10)
    with pytest.raises(ValueError):
        vcs_metadata.hg_changelog(b"\0\0")
    with pytest.raises(ValueError):
        vcs_metadata.hg_changelog_ends(b"\0\x01\0\x01", b"", 64)  # inline indexes are read whole
    assert vcs_metadata.hg_changelog(b"\0\0\0\x02" + b"\0" * 60) == {"version": 2}
    assert vcs_metadata.hg_bookmarks("bad\n" + "a" * 40 + " ok\n" + "b" * 39 + " short\n") == ["ok"]
    assert vcs_metadata.hg_phases("x y\n1 " + "a" * 40 + "\n96 " + "b" * 40 + "\n7 " + "c" * 40 + "\n32 short\n") == {
        "draft": 1, "internal": 1, "phase 7": 1}


# ---------------------------------------------------------------------------------------------
# Jujutsu and Pijul


def _checkout(workspace: str, operation: bytes = b"\xaa\xbb\xcc\xdd") -> bytes:
    name = workspace.encode()
    return bytes([0x12, len(operation)]) + operation + bytes([0x1a, len(name)]) + name


def test_jujutsu_layouts(tmp_path: Path):
    _write(tmp_path, {
        "ws/.git/HEAD": "ref: refs/heads/main\n",
        "ws/.jj/repo/store/type": "git", "ws/.jj/repo/store/git_target": "../../../.git",
        **{f"ws/.jj/repo/op_store/operations/{number:0128x}": b"op" for number in range(3)},
        **{f"ws/.jj/repo/op_heads/heads/{number:0128x}": b"" for number in range(2)},
        "ws/.jj/working_copy/checkout": _checkout("default"),
        "second/.jj/repo": "../ws/.jj/repo", "second/.jj/working_copy/checkout": _checkout("second"),
        "inner/.jj/repo/store/type": "git", "inner/.jj/repo/store/git_target": "git",
        "elsewhere/.jj/repo/store/type": "git", "elsewhere/.jj/repo/store/git_target": "/home/alice/mirror.git",
        "windows/.git/HEAD": "ref: refs/heads/main\n",
        "windows/.jj/repo/store/type": "git", "windows/.jj/repo/store/git_target": "..\\..\\..\\.git",
    })
    assert _analyze(tmp_path, "ws/.jj/repo/store/type")[0].detail == (
        "Jujutsu repository: git backend; colocated with a Git repository; 3 recorded operations; 2 operation heads: "
        "concurrent operations that the next jj command merges; workspace default.")
    assert _analyze(tmp_path, "second/.jj/repo")[0].detail == (
        "A Jujutsu workspace (second) whose repository is shared with another workspace; the pointer is not followed.")
    assert _analyze(tmp_path, "inner/.jj/repo/store/type")[0].detail == "Jujutsu repository: git backend; Git store inside .jj."
    elsewhere = _analyze(tmp_path, "elsewhere/.jj/repo/store/type")
    assert elsewhere[0].detail == "Jujutsu repository: git backend; Git store elsewhere (not followed)."
    assert "alice" not in _text(elsewhere)
    assert "colocated" in _analyze(tmp_path, "windows/.jj/repo/store/type")[0].detail


def test_protobuf_and_checkout_decoders():
    assert vcs_metadata.jj_checkout(_checkout("second")) == {"workspace": "second", "operation": "aabbccdd"}
    assert vcs_metadata.protobuf_fields(bytes([0x08, 0x96, 0x01, 0x15, 1, 2, 3, 4])) == {1: 150}  # stops at fixed32
    for data in (bytes([0x08, 0x96]), bytes([0x12, 0x05, 1])):
        with pytest.raises(ValueError):
            vcs_metadata.protobuf_fields(data)


def test_pijul_changes_and_hooks(tmp_path: Path, monkeypatch):
    _write(tmp_path, {
        "pj/.pijul/pristine/db": b"\0" * 64,
        "pj/.pijul/changes/AB/CDEFGH.change": b"x", "pj/.pijul/changes/AB/IJKLMN.change": b"x",
        "pj/.pijul/changes/XY/OPQRST.change": b"x", "pj/.pijul/changes/XY/notes.txt": b"",
        "pj/.pijul/config.toml": 'default_remote = "https://nest.pijul.com/acme/project"\n\n[hooks] # local\n'
                                 'record = ["make check"]\n',
        "quiet/.pijul/pristine/db": b"\0" * 64,
        "quiet/.pijul/config.toml": "[hooks]\n# none yet\n\n[hooks.extra]\nx = 1\n",
    })
    assert _analyze(tmp_path, "pj/.pijul/pristine/db")[0].detail == (
        "Pijul repository: 3 changes recorded; hooks declared in .pijul/config.toml (they run commands).")
    assert _analyze(tmp_path, "quiet/.pijul/pristine/db")[0].detail == "Pijul repository: no recorded changes."
    monkeypatch.setattr(vcs_module, "_MAX_LISTED_ENTRIES", 2)
    with accounting() as account:
        detail = _analyze(tmp_path, "pj/.pijul/pristine/db")[0].detail
    assert detail.startswith("Pijul repository: 2+ changes recorded")
    assert ("entries", 2.0, None) in account.limits


# ---------------------------------------------------------------------------------------------
# Perforce


_P4_PASSWORD = "Hunter2" + "-p4"


def test_perforce_settings_are_reported_by_name(tmp_path: Path):
    _write(tmp_path, {
        ".p4config": "P4PORT=ssl:perforce.example.com:1666\nP4USER=alice\nP4CLIENT=alice_ws\nP4PASSWD="
                     + _P4_PASSWORD + "\n# P4TICKETS=/home/alice/.p4tickets\nnot a setting\nP4 BAD=1\n",
        "depot/main/p4config.txt": "P4CLIENT=build_ws\nP4PASSWD=\n",
        ".p4enviro": "P4EDITOR=vi\n",
    })
    findings = _analyze(tmp_path, ".p4config")
    assert [(item.category, item.title, item.severity) for item in findings] == [
        ("vcs", "Perforce client configuration: .p4config", "INFO"),
        ("secrets", "Perforce password in a settings file: .p4config", "HIGH")]
    assert findings[0].detail == "A Perforce settings file sets P4CLIENT, P4PASSWD, P4PORT, P4USER; their values are not copied."
    text = _text(findings)
    for private in (_P4_PASSWORD, "alice", "perforce.example.com", "1666", "P4TICKETS"):
        assert private not in text, private
    nested = _analyze(tmp_path, "depot/main/p4config.txt")
    assert [item.category for item in nested] == ["vcs"]  # an empty P4PASSWD sets no password
    assert "P4EDITOR" in _analyze(tmp_path, ".p4enviro")[0].detail


def test_perforce_tickets_are_never_read_and_ignore_files_mark_a_workspace(tmp_path: Path, monkeypatch):
    ticket = "perforce:1666=alice:" + "0123456789ABCDEF" * 2
    _write(tmp_path, {"home/.p4tickets": ticket, "p4tickets.txt": ticket, "ws/.p4ignore": "*.obj\n",
                      "home/.p4trust": "192.0.2.10:1666 " + "AB:" * 19 + "CD\n"})

    def refuse(*args, **kwargs):
        raise AssertionError("a Perforce ticket file was read")

    monkeypatch.setattr(vcs_module, "_read_text", refuse)
    monkeypatch.setattr(vcs_module, "read_text_bounded", refuse)
    for relative in ("home/.p4tickets", "p4tickets.txt"):
        findings = _analyze(tmp_path, relative)
        assert [(item.category, item.severity) for item in findings] == [("secrets", "HIGH")]
        assert findings[0].title == f"Perforce ticket file: {relative}"
        assert "alice" not in _text(findings) and "0123456789ABCDEF" not in _text(findings)
    assert _analyze(tmp_path, "ws/.p4ignore")[0].title == "Perforce ignore rules: ws/.p4ignore"
    trust = _analyze(tmp_path, "home/.p4trust")
    assert [item.title for item in trust] == ["Perforce trust file: home/.p4trust"]
    assert "192.0.2.10" not in _text(trust)


# ---------------------------------------------------------------------------------------------
# The real clients, where installed


def _tool(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        pytest.skip(", ".join(missing) + " not installed")


def _run(*command: str, cwd: Path | None = None, env: dict | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
                            stdin=subprocess.DEVNULL, check=False)
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    return result.stdout


def test_subversion_client_working_copy(tmp_path: Path):
    _tool("svn", "svnadmin")
    config = tmp_path / "svn-config"
    config.mkdir()
    env = {**os.environ, "LC_ALL": "C"}
    svn = ("svn", "--non-interactive", "--config-dir", str(config), "--username", "alice")
    repository = tmp_path / "private-parent" / "repo"
    repository.parent.mkdir()
    _run("svnadmin", "create", str(repository), env=env)
    url = repository.as_uri()
    _run(*svn, "mkdir", "--parents", "-m", "layout", f"{url}/trunk/src", f"{url}/branches", env=env)
    working = tmp_path / "wc"
    _run(*svn, "checkout", f"{url}/trunk", str(working), env=env)
    (working / "README.md").write_text("hello\n", encoding="utf-8")
    _run(*svn, "add", "README.md", cwd=working, env=env)
    _run(*svn, "commit", "-m", "readme", cwd=working, env=env)
    _run(*svn, "update", cwd=working, env=env)
    (working / "src" / "new.py").write_text("x = 1\n", encoding="utf-8")
    _run(*svn, "add", "src/new.py", cwd=working, env=env)
    _run(*svn, "changelist", "review", "src/new.py", cwd=working, env=env)
    _run(*svn, "lock", "-m", "editing the readme", "README.md", cwd=working, env=env)
    revision = _run(*svn, "info", "--show-item", "revision", cwd=working, env=env).strip()
    uuid = _run(*svn, "info", "--show-item", "repos-uuid", cwd=working, env=env).strip()
    findings = _analyze(tmp_path, "wc/.svn/wc.db")
    assert len(findings) == 1
    # The scheduled file is not a base node yet; the committed one has a pristine copy. The
    # format is the client's default (31 for Subversion 1.8 to 1.15).
    working_format, _, rest = findings[0].detail.partition(") of ")
    assert working_format.startswith("Subversion working copy (format ")
    assert rest == (f"file://.../repo at /trunk, revision {revision}: 1 file, 2 directories; 1 scheduled change "
                    "(1 added or copied); changelists review; 1 repository lock held; 1 pristine copy (6 B).")
    assert f"repository UUID: {uuid}" in findings[0].evidence
    text = _text(findings)
    for private in ("alice", "private-parent", "editing the readme"):
        assert private not in text, private


def test_mercurial_client_repository(tmp_path: Path):
    _tool("hg")
    rc = tmp_path / "hgrc"
    rc.write_text("", encoding="utf-8")
    env = {**os.environ, "HGRCPATH": str(rc), "HGPLAIN": "1", "HGUSER": "Alice <alice@example.invalid>",
           "HGMERGE": "internal:merge", "HGENCODING": "utf-8"}
    repo = tmp_path / "repo"
    _run("hg", "init", str(repo), env=env)
    assert "0 changesets" in _analyze(tmp_path, "repo/.hg/requires")[0].detail

    def hg(*arguments: str) -> str:
        return _run("hg", *arguments, cwd=repo, env=env)

    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    hg("add", "a.txt")
    hg("commit", "-m", "one")
    (repo / "a.txt").write_text("two\n", encoding="utf-8")
    hg("commit", "-m", "two")
    hg("update", "-r", "0")
    (repo / "b.txt").write_text("three\n", encoding="utf-8")
    hg("add", "b.txt")
    hg("commit", "-m", "three")
    hg("bookmark", "feature-x")
    hg("phase", "--secret", "--force", "-r", "1")
    hg("merge", "-r", "1")
    tip, first, second = (hg("log", "-r", revset, "-T", "{node}") for revset in ("tip", "p1()", "p2()"))
    count = len(hg("log", "--hidden", "-T", "{rev}\n").split())
    heads = len(hg("log", "--hidden", "-r", "heads(all())", "-T", "{rev}\n").split())
    findings = _analyze(tmp_path, "repo/.hg/requires")
    detail = findings[0].detail
    assert heads == 2
    assert f"{count} changesets, tip {tip[:12]}, {heads} heads (changesets without children)" in detail
    assert f"working directory at {first[:12]} on branch default, with an uncommitted merge of {second[:12]}" in detail
    assert "bookmarks feature-x (active: feature-x)" in detail and "phase roots: 1 draft, 1 secret" in detail
    assert "alice" not in _text(findings).lower()


def test_jujutsu_client_workspaces(tmp_path: Path):
    _tool("jj")
    config = tmp_path / "jj.toml"
    config.write_text("", encoding="utf-8")
    env = {**os.environ, "JJ_CONFIG": str(config), "JJ_USER": "Alice", "JJ_EMAIL": "alice@example.invalid"}
    _run("jj", "git", "init", "--colocate", "repo", cwd=tmp_path, env=env)
    repo = tmp_path / "repo"
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    _run("jj", "commit", "-m", "one", cwd=repo, env=env)
    _run("jj", "workspace", "add", "--name", "second", str(tmp_path / "second"), cwd=repo, env=env)
    _run("jj", "git", "init", "--no-colocate", "inner", cwd=tmp_path, env=env)
    # The operation log ends with the root operation, which is not stored.
    logged = _run("jj", "op", "log", "--ignore-working-copy", "--no-graph", "-T", 'id ++ "\\n"', cwd=repo, env=env)
    stored = len(logged.split()) - 1
    detail = _analyze(tmp_path, "repo/.jj/repo/store/type")[0].detail
    assert detail == (f"Jujutsu repository: git backend; colocated with a Git repository; {stored} recorded operations; "
                      "workspace default.")
    assert _analyze(tmp_path, "second/.jj/repo")[0].detail.startswith("A Jujutsu workspace (second) whose repository")
    assert "Git store inside .jj" in _analyze(tmp_path, "inner/.jj/repo/store/type")[0].detail


def test_pijul_client_repository(tmp_path: Path):
    _tool("pijul")
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}
    _run("pijul", "init", "pj", cwd=tmp_path, env=env)
    assert _analyze(tmp_path, "pj/.pijul/pristine/db")[0].detail == "Pijul repository: no recorded changes."
    with (tmp_path / "pj/.pijul/config.toml").open("a", encoding="utf-8") as stream:
        stream.write('record = ["make check"]\n')
    assert "hooks declared" in _analyze(tmp_path, "pj/.pijul/pristine/db")[0].detail


# ---------------------------------------------------------------------------------------------
# End to end


def test_scan_reports_decoded_metadata_without_private_values(tmp_path: Path):
    project = tmp_path / "project"
    _wc_db(project / "legacy/.svn/wc.db", locks=(("branches/feature-x/README.md", "alice", "Alice is editing"),))
    _write(project, {
        "legacy/README.md": "# legacy\n",
        "tools/.hg/requires": "share-safe\n", "tools/.hg/store/requires": "revlogv1\nstore\n",
        "tools/.hg/store/00changelog.i": _revlog_index(_NODES, inline=True),
        "tools/.hg/dirstate": _NODES[2] + b"\0" * 20,
        ".p4config": "P4PORT=ssl:perforce.example.com:1666\nP4PASSWD=" + _P4_PASSWORD + "\n",
        ".p4tickets": "perforce:1666=alice:" + "0123456789ABCDEF" * 2,
    })
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    raw = (output / "discovery-report.json").read_text(encoding="utf-8")
    report = json.loads(raw)
    findings = {item["title"]: item for item in report["findings"] if item["analyzer"] == "vcs-hosting-intelligence"}
    assert "at /branches/feature-x (a branch), revision 7" in findings["Subversion repository metadata: legacy"]["detail"]
    assert findings["Mercurial repository metadata: tools"]["detail"].startswith(
        "Mercurial repository: 3 changesets, tip 333333333333, 1 head (changesets without children); working directory "
        "at 333333333333")
    assert findings["Perforce password in a settings file: .p4config"]["severity"] == "HIGH"
    assert findings["Perforce ticket file: .p4tickets"]["severity"] == "HIGH"
    for private in (_ROOT_PASSWORD, _P4_PASSWORD, "0123456789ABCDEF", "Alice is editing", "q-param"):
        assert private not in raw, private
