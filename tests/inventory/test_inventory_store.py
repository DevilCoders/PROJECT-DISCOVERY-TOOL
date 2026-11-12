import os
import stat
from pathlib import Path

import pytest

from project_discovery.inventory.store import InventoryStore
from project_discovery.models import FileRecord


def test_inventory_store_persists_records_in_bounded_batches(tmp_path: Path):
    path = tmp_path / "inventory.sqlite3"
    with InventoryStore(path, batch_size=2) as store:
        store.append("file", FileRecord("b.py", 2, ".py", "Python"))
        assert len(store._pending) == 1
        store.append("file", FileRecord("a.py", 1, ".py", "Python"))
        assert store._pending == []
        assert store.count("file") == 2
        assert [item["path"] for item in store.iter_records("file", fetch_size=1)] == [
            "a.py", "b.py",
        ]


def test_inventory_store_round_trips_private_file_identity_without_public_serialization(
    tmp_path: Path,
):
    identity = (11, 22, 33, 44, 55)
    record = FileRecord(
        "src/main.py", 33, ".py", "Python",
        analysis_identity=identity,
    )
    assert "analysis_identity" not in record.to_dict()

    with InventoryStore(tmp_path / "identity.sqlite3") as store:
        store.append("file", record)
        payload = next(store.iter_records("file"))
        assert payload["analysis_identity"] == list(identity)
        restored = next(store.iter_file_records())
        assert restored.path == record.path
        assert restored.analysis_identity == identity
        assert "analysis_identity" not in restored.to_dict()


def test_inventory_store_orders_casefolded_paths_and_migrates_legacy_schema(
    tmp_path: Path,
):
    import json
    import sqlite3

    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE inventory_records (
            kind TEXT NOT NULL,
            path TEXT NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY(kind, path)
        ) WITHOUT ROWID"""
    )
    connection.executemany(
        "INSERT INTO inventory_records(kind, path, payload) VALUES (?, ?, ?)",
        [
            ("file", "ß.py", json.dumps({"path": "ß.py"})),
            ("file", "a.py", json.dumps({"path": "a.py"})),
            ("file", "ss.py", json.dumps({"path": "ss.py"})),
            ("file", "A.py", json.dumps({"path": "A.py"})),
            ("directory", "deep", json.dumps({"path": "deep", "depth": 2})),
            ("directory", "shallow", json.dumps({"path": "shallow", "depth": 1})),
            ("directory", ".", json.dumps({"path": ".", "depth": 0})),
        ],
    )
    connection.commit()
    connection.close()

    with InventoryStore(path) as store:
        assert [
            item["path"] for item in store.iter_records("file")
        ] == ["A.py", "a.py", "ss.py", "ß.py"]
        assert [
            item["path"] for item in store.iter_records("directory")
        ] == [".", "shallow", "deep"]
        store.append("file", {"path": "B.py"})
        assert [
            item["path"] for item in store.iter_records("file")
        ] == ["A.py", "a.py", "B.py", "ss.py", "ß.py"]


def test_inventory_store_updates_directory_aggregates_in_bounded_batches(
    tmp_path: Path,
):
    from project_discovery.models import DirectoryRecord

    path = tmp_path / "directories.sqlite3"
    with InventoryStore(path, batch_size=2) as store:
        store.append("directory", DirectoryRecord(".", 0))
        store.append("directory", DirectoryRecord("src", 1))
        store.adjust_directory(".", direct_child_delta=1)
        store.adjust_directory(
            "src",
            direct_child_delta=2,
            file_count_delta=3,
            total_bytes_delta=45,
            error="permission denied",
        )

        records = list(store.iter_records("directory", fetch_size=1))
        assert [record["path"] for record in records] == [".", "src"]
        assert records[0]["direct_child_count"] == 1
        assert records[0]["file_count"] == 0
        assert records[1]["direct_child_count"] == 2
        assert records[1]["file_count"] == 3
        assert records[1]["total_bytes"] == 45
        assert records[1]["error"] == "permission denied"
        assert store._directory_pending == {}


def test_inventory_store_upserts_records_by_kind_and_path(tmp_path: Path):
    with InventoryStore(tmp_path / "inventory.sqlite3", batch_size=8) as store:
        store.append("file", {"path": "src/app.py", "size_bytes": 10})
        store.append("file", {"path": "src/app.py", "size_bytes": 20})
        store.append("directory", {"path": "src", "depth": 1})
        assert store.count() == 2
        assert store.count("file") == 1
        assert list(store.iter_records("file")) == [
            {"path": "src/app.py", "size_bytes": 20},
        ]
        assert store.counts() == {"directory": 1, "file": 1}


def test_inventory_store_streams_extend_and_metadata(tmp_path: Path):
    with InventoryStore(tmp_path / "inventory.sqlite3", batch_size=3) as store:
        records = ({"path": f"file-{index:04}.txt", "size_bytes": index} for index in range(25))
        assert store.extend("file", records) == 25
        store.set_metadata("root", "/workspace/project")
        store.set_metadata("walk_complete", False)
        assert store.get_metadata("root") == "/workspace/project"
        assert store.get_metadata("walk_complete") is False
        assert store.get_metadata("missing", "default") == "default"
        streamed = store.iter_records("file", fetch_size=2)
        assert next(streamed)["path"] == "file-0000.txt"
        assert sum(1 for _ in streamed) == 24


def test_inventory_store_validates_kind_path_and_batch_size(tmp_path: Path):
    with pytest.raises(ValueError, match="batch_size"):
        InventoryStore(tmp_path / "invalid.sqlite3", batch_size=0)

    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        with pytest.raises(ValueError, match="unsupported"):
            store.append("unknown", {"path": "a"})
        with pytest.raises(ValueError, match="path"):
            store.append("file", {"size_bytes": 1})
        with pytest.raises(TypeError, match="mappings"):
            store.append("file", object())
        with pytest.raises(ValueError, match="fetch_size"):
            list(store.iter_records("file", fetch_size=0))


def test_inventory_store_reopens_and_clear_removes_scan_state(tmp_path: Path):
    path = tmp_path / "inventory.sqlite3"
    with InventoryStore(path) as store:
        store.append("symlink", {"path": "current", "target": "releases/v1"})
        store.set_metadata("scan_id", "scan-1")

    with InventoryStore(path) as store:
        assert store.count("symlink") == 1
        assert store.get_metadata("scan_id") == "scan-1"
        store.clear()
        assert store.count() == 0
        assert store.get_metadata("scan_id") is None


def test_inventory_store_rejects_use_after_close(tmp_path: Path):
    store = InventoryStore(tmp_path / "inventory.sqlite3")
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.append("file", {"path": "a"})



def test_inventory_store_rejects_symlink_database_path(tmp_path: Path):
    target = tmp_path / "real.sqlite3"
    link = tmp_path / "linked.sqlite3"
    with InventoryStore(target) as store:
        store.append("file", {"path": "safe.txt"})
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(ValueError, match="must not be a symlink"):
        InventoryStore(link)


def test_inventory_store_closes_early_stream_cursor(tmp_path: Path):
    with InventoryStore(tmp_path / "inventory.sqlite3", batch_size=1) as store:
        store.extend("file", ({"path": f"{index:04}.txt"} for index in range(5)))
        records = store.iter_records("file", fetch_size=1)
        assert next(records)["path"] == "0000.txt"
        records.close()
        assert [item["path"] for item in store.iter_records("file")] == [
            "0000.txt", "0001.txt", "0002.txt", "0003.txt", "0004.txt",
        ]


def test_inventory_store_metadata_rejects_use_after_close(tmp_path: Path):
    store = InventoryStore(tmp_path / "inventory.sqlite3")
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.get_metadata("root")



@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode semantics")
def test_inventory_store_database_is_private_by_default(tmp_path: Path):
    path = tmp_path / "private.sqlite3"
    with InventoryStore(path):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600



def test_inventory_store_checkpoint_flushes_rows_before_progress_metadata(tmp_path: Path):
    path = tmp_path / "checkpoint.sqlite3"
    with InventoryStore(path, batch_size=100) as store:
        store.append("file", {"path": "src/main.py", "size_bytes": 10})
        assert len(store._pending) == 1
        store.checkpoint({
            "scan_id": "scan-42",
            "phase": "inventory",
            "last_committed_path": "src/main.py",
            "completed": False,
        })
        assert store._pending == []
        assert store.count("file") == 1
        assert store.get_metadata("scan_id") == "scan-42"
        assert store.get_metadata("completed") is False

    with InventoryStore(path) as reopened:
        assert reopened.get_metadata("phase") == "inventory"
        assert reopened.get_metadata("last_committed_path") == "src/main.py"
        assert reopened.integrity_check() == "ok"


def test_inventory_store_checkpoint_validates_metadata(tmp_path: Path):
    with InventoryStore(tmp_path / "checkpoint.sqlite3") as store:
        with pytest.raises(ValueError, match="must not be empty"):
            store.checkpoint({})
        with pytest.raises(ValueError, match="non-empty strings"):
            store.checkpoint({"": "invalid"})
        with pytest.raises(ValueError, match="non-empty strings"):
            store.checkpoint({"phase": "inventory", 1: "invalid"})


def test_inventory_store_integrity_check_rejects_closed_store(tmp_path: Path):
    store = InventoryStore(tmp_path / "closed.sqlite3")
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.integrity_check()

def test_inventory_store_exposes_lazy_typed_symlink_and_special_sequences(tmp_path: Path):
    from project_discovery.inventory.store import StoredRecordSequence
    from project_discovery.models import SpecialEntryRecord, SymlinkRecord

    database = tmp_path / "typed-records.sqlite3"
    with InventoryStore(database, batch_size=1) as store:
        store.append("symlink", SymlinkRecord("alias", "target", "internal"))
        store.append(
            "special",
            SpecialEntryRecord("events.pipe", "fifo", permissions=0o600),
        )
        links = StoredRecordSequence(database, "symlink", SymlinkRecord, fetch_size=1)
        special = StoredRecordSequence(
            database, "special", SpecialEntryRecord, fetch_size=1,
        )
        assert len(links) == 1
        assert links[0].path == "alias"
        assert links[0].target == "target"
        assert links[:1] == [links[0]]
        assert len(special) == 1
        assert special[0].entry_type == "fifo"
        assert special[0].permissions == 0o600

def test_inventory_store_buffers_directory_aggregate_deltas_and_errors(tmp_path: Path):
    from project_discovery.models import DirectoryRecord

    database = tmp_path / "directory-state.sqlite3"
    with InventoryStore(database, batch_size=100) as store:
        store.append("directory", DirectoryRecord(".", 0))
        store.adjust_directory(".", direct_child_delta=3)
        store.adjust_directory(".", file_count_delta=2, total_bytes_delta=99)
        store.adjust_directory(".", direct_child_delta=4, error="permission denied")
        # The bounded update queue is flushed atomically with the initial record.
        assert store._directory_pending["."] == (7, 2, 99, "permission denied")
        store.flush()

        from project_discovery.inventory.store import StoredRecordSequence
        directories = StoredRecordSequence(database, "directory", DirectoryRecord)
        root = directories[0]
        assert root.path == "."
        assert root.direct_child_count == 7
        assert root.file_count == 2
        assert root.total_bytes == 99
        assert root.error == "permission denied"

        # Updates to an already-persisted directory are also applied and visible
        # through the joined directory-state projection.
        store.adjust_directory(".", direct_child_delta=1, file_count_delta=1, total_bytes_delta=5)
        store.flush()
        updated = directories[0]
        assert updated.direct_child_count == 8
        assert updated.file_count == 3
        assert updated.total_bytes == 104
        assert updated.error == "permission denied"

def test_inventory_store_persists_and_deduplicates_typed_findings(tmp_path: Path):
    from project_discovery.inventory.store import StoredFindingRecords
    from project_discovery.models import CodeEvidence, Finding

    database = tmp_path / "findings.sqlite3"
    finding = Finding(
        category="security",
        title="Hard-coded credential",
        detail="A credential-like literal is assigned in source.",
        evidence=["src/settings.py:12"],
        analyzer="secret-scanner",
        severity="HIGH",
        code_evidence=[CodeEvidence(12, "password = 'example-secret'")],
        impact="An attacker with repository access could recover the credential.",
        recommendation="Move the secret to a managed secret store and rotate it.",
    )
    duplicate = Finding.from_dict(finding.to_dict())
    other = Finding(
        category="configuration",
        title="Debug mode enabled",
        detail="The configuration sets a development-only mode.",
        analyzer="configuration",
        evidence=["config.yml:1"],
    )

    with InventoryStore(database, batch_size=2) as store:
        store.append_finding(finding)
        store.extend_findings([duplicate, other])
        assert store.count("finding") == 2
        restored = list(store.iter_findings(fetch_size=1))
        assert {item.title for item in restored} == {
            "Hard-coded credential", "Debug mode enabled",
        }
        credential = next(item for item in restored if item.title == "Hard-coded credential")
        assert credential.severity == "HIGH"
        assert credential.code_evidence[0].line_number == 12
        assert "example-secret" not in credential.code_evidence[0].code
        assert credential.impact == finding.impact
        assert credential.recommendation == finding.recommendation

        lazy = StoredFindingRecords(database, fetch_size=1)
        assert len(lazy) == 2
        assert {item.title for item in lazy} == {
            "Hard-coded credential", "Debug mode enabled",
        }
        first = lazy[0]
        assert first.title in {"Hard-coded credential", "Debug mode enabled"}
        reread = lazy[0]
        assert reread.to_dict() == first.to_dict()
        first_pass = [item.title for item in lazy]
        second_pass = [item.title for item in lazy]
        assert first_pass == second_pass
        assert set(first_pass) == {"Hard-coded credential", "Debug mode enabled"}
        with pytest.raises(IndexError):
            _ = lazy[2]




def test_inventory_store_streams_ordered_diagnostics_without_deduplication(tmp_path: Path):
    from project_discovery.inventory.store import StoredDiagnosticRecords

    database = tmp_path / "diagnostics.sqlite3"
    with InventoryStore(database, batch_size=2) as store:
        assert store.extend_diagnostics(["first diagnostic", "repeat", "repeat"]) == 3

    lazy = StoredDiagnosticRecords(database, fetch_size=1)
    assert len(lazy) == 3
    assert list(lazy) == ["first diagnostic", "repeat", "repeat"]
    assert lazy[1] == "repeat"
    assert lazy[3:] == []

    # The insertion sequence continues after reopening the store.
    with InventoryStore(database) as store:
        store.append_diagnostic("after reopen")
    assert list(lazy) == [
        "first diagnostic", "repeat", "repeat", "after reopen",
    ]

def test_inventory_store_allocates_unique_diagnostic_ids_across_connections(tmp_path: Path):
    from project_discovery.inventory.store import StoredDiagnosticRecords

    database = tmp_path / "concurrent-diagnostics.sqlite3"
    first = InventoryStore(database, batch_size=100)
    second = InventoryStore(database, batch_size=100)
    try:
        first.append_diagnostic("first connection")
        second.append_diagnostic("second connection")
        # Commit in reverse order to prove retrieval uses reserved sequence IDs,
        # not transaction commit order.
        second.close()
        first.close()
    finally:
        first.close()
        second.close()

    assert list(StoredDiagnosticRecords(database, fetch_size=1)) == [
        "first connection", "second connection",
    ]



def test_names_that_are_not_valid_unicode_round_trip_through_the_store(tmp_path: Path):
    # Regression: surrogate-escaped POSIX names and unpaired NTFS surrogates crashed
    # SQLite binding ("surrogates not allowed") and aborted the whole scan.
    from project_discovery.inventory.store import InventoryStore, sqlite_text
    from project_discovery.models import DirectoryRecord, FileRecord, Finding

    odd = "dir\udcff/bad\udcffname.py"
    with InventoryStore(tmp_path / "odd.sqlite3") as store:
        store.append("directory", DirectoryRecord("dir\udcff", 1))
        store.append("file", FileRecord(odd, 3, ".py", "Python"))
        store.adjust_directory("dir\udcff", file_count_delta=1, total_bytes_delta=3)
        store.append_finding(Finding("code", f"Python module: {odd}", "d", evidence=[odd]))
        store.append_diagnostic(f"{odd}: diagnostic")
        store.flush()
        assert [record.path for record in store.iter_file_records()] == [odd]
        directory = next(item for item in store.iter_records("directory") if item["path"] == "dir\udcff")
        assert directory["total_bytes"] == 3
        assert next(store.iter_findings()).evidence == [odd]
        assert list(store.iter_diagnostics()) == [f"{odd}: diagnostic"]
    assert sqlite_text("plain.py") == "plain.py"
    assert sqlite_text("a\udcff") != sqlite_text("a\xed\xb3\xbf")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_store_and_cache_databases_are_private_including_wal_files(tmp_path: Path):
    import stat as stat_module

    from project_discovery.inventory.cache import ScanCache
    from project_discovery.inventory.store import InventoryStore

    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        store.set_metadata("k", "v")
        for name in ("inventory.sqlite3", "inventory.sqlite3-wal", "inventory.sqlite3-shm"):
            mode = stat_module.S_IMODE((tmp_path / name).stat().st_mode)
            assert mode & 0o077 == 0, (name, oct(mode))
    with ScanCache(tmp_path / "fingerprints.sqlite3"):
        pass
    assert stat_module.S_IMODE((tmp_path / "fingerprints.sqlite3").stat().st_mode) & 0o077 == 0


def test_record_iteration_holds_no_read_snapshot_between_pages(tmp_path):
    # Regression: one cursor stayed open for the whole analysis loop, so SQLite could not
    # checkpoint past it and the WAL grew to about three times the store.
    import sqlite3

    path = tmp_path / "inventory.sqlite3"
    with InventoryStore(path, batch_size=500) as store:
        for index in range(1000):
            store.append("file", FileRecord(f"dir/F{index:04}.py", index, ".py", "Python"))
        store.flush()
        records = store.iter_records("file", fetch_size=256)
        first = [next(records) for _ in range(300)]      # well into the second page
        other = sqlite3.connect(path)
        other.execute("CREATE TABLE IF NOT EXISTS probe (value INTEGER)")
        other.execute("INSERT INTO probe VALUES (1)")
        other.commit()
        busy, _, _ = other.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        other.close()
        rest = list(records)
    assert busy == 0
    paths = [item["path"] for item in first + rest]
    assert len(paths) == 1000 and paths == sorted(paths, key=str.casefold)
