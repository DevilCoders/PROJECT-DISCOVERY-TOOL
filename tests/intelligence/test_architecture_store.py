"""The architecture layout backed by the scan store: the same layout, without the component cap."""
from __future__ import annotations

from pathlib import Path

from project_discovery.intelligence import architecture
from project_discovery.intelligence.architecture import analyze_project_architecture
from project_discovery.inventory.store import InventoryStore, StoredRows
from project_discovery.models import FileRecord


def _records(paths: list[str]) -> list[FileRecord]:
    return [FileRecord(path, 1, Path(path).suffix, "Text") for path in paths]


def test_the_store_backed_layout_equals_the_in_memory_layout(tmp_path: Path):
    records = _records([
        "api/routes/users.py", "api/routes/items.py", "web/components/App.tsx", "web/pages/index.tsx",
        "tests/test_api.py", "docs/index.md", "README.md", ".github/workflows/ci.yml", "zeta/x.py", "alpha/y.py",
    ])
    memory, memory_findings = analyze_project_architecture(records)
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        stored, stored_findings = analyze_project_architecture(records, store=store)
        assert isinstance(stored["top_level_components"], StoredRows)
        assert {**stored, "top_level_components": list(stored["top_level_components"])} == memory
        # A second scan replaces the rows instead of adding to the counters.
        again, _ = analyze_project_architecture(records, store=store)
        assert list(again["top_level_components"]) == memory["top_level_components"]
    assert [item.to_dict() for item in stored_findings] == [item.to_dict() for item in memory_findings]


def test_the_store_backed_layout_has_no_component_cap(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(architecture, "_COUNT_BATCH", 100)  # several store batches to merge
    count = architecture.MAX_ARCHITECTURE_COMPONENTS + 2_000
    records = _records([f"repo{index:05d}/main.py" for index in range(count)] + ["repo00007/second.py"])
    with InventoryStore(tmp_path / "inventory.sqlite3") as store:
        layout, findings = analyze_project_architecture(records, store=store)
        assert (layout["top_level_component_detail_count"], layout["layout_complete"]) == (count, True)
        rows = layout["top_level_components"]
        assert len(rows) == count
        assert (rows[0], rows[1]) == ({"name": "repo00007", "file_count": 2}, {"name": "repo00000", "file_count": 1})
    assert not any("resource limit" in item.title for item in findings)
    memory, memory_findings = analyze_project_architecture(records)
    assert memory["layout_complete"] is False
    assert any("resource limit" in item.title for item in memory_findings)
