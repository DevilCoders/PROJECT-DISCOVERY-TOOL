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
