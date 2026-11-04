import os
import stat
from pathlib import Path

import pytest

from project_discovery.inventory_store import InventoryStore
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
        ],
    )
    connection.commit()
    connection.close()

    with InventoryStore(path) as store:
        assert [
            item["path"] for item in store.iter_records("file")
        ] == ["A.py", "a.py", "ss.py", "ß.py"]
        store.append("file", {"path": "B.py"})
        assert [
            item["path"] for item in store.iter_records("file")
        ] == ["A.py", "a.py", "B.py", "ss.py", "ß.py"]


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
    from project_discovery.inventory_store import StoredRecordSequence
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

