import json
from pathlib import Path

import pytest

from project_discovery.projects.catalog import ProjectCatalog


def _write_report(path: Path, root: Path):
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "root": str(root),
        "finished_at": "2026-11-03T10:00:00+00:00",
        "files": [{"path": "app.py"}],
        "findings": [],
        "metrics": {"languages": {"Python": 1}},
    }), encoding="utf-8")


def test_catalog_add_update_list_and_remove(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    report = tmp_path / "report.json"
    _write_report(report, root)
    database = tmp_path / "catalog.sqlite3"

    with ProjectCatalog(database) as catalog:
        added = catalog.add_report(report)
        assert added["root"] == str(root.resolve())
        assert len(catalog.list_projects()) == 1
        _write_report(report, root)
        catalog.add_report(report)
        assert len(catalog.list_projects()) == 1
        assert catalog.remove_project(root) is True
        assert catalog.list_projects() == []


def test_catalog_requires_valid_report_schema(tmp_path: Path):
    report = tmp_path / "bad.json"
    report.write_text('{"schema_version":"99"}', encoding="utf-8")
    with ProjectCatalog(tmp_path / "catalog.sqlite3") as catalog:
        with pytest.raises(ValueError, match="Unsupported"):
            catalog.add_report(report)


def test_catalog_loads_registered_reports(tmp_path: Path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_report(first, first_root)
    _write_report(second, second_root)
    with ProjectCatalog(tmp_path / "catalog.sqlite3") as catalog:
        catalog.add_report(first)
        catalog.add_report(second)
        assert len(catalog.load_reports()) == 2
