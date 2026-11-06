"""Local SQLite registry for independent project scan reports."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .comparison import load_report


class ProjectCatalog:
    """Store report metadata and local report paths; never copies project source."""

    def __init__(self, database: Path) -> None:
        self.database = database.expanduser().resolve()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.database)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                root TEXT NOT NULL UNIQUE,
                project_name TEXT NOT NULL,
                report_path TEXT NOT NULL,
                scan_finished_at TEXT NOT NULL,
                file_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                languages_json TEXT NOT NULL
            )"""
        )
        self.db.commit()

    def add_report(self, report_path: Path) -> dict[str, Any]:
        report_path = report_path.expanduser().resolve(strict=True)
        report = load_report(report_path)
        root = str(Path(report["root"]).expanduser().resolve())
        project_id = hashlib.sha256(root.encode("utf-8")).hexdigest()
        metrics = report.get("metrics", {})
        languages = metrics.get("languages", {})
        values = (
            project_id,
            root,
            Path(root).name or root,
            str(report_path),
            str(report.get("finished_at", "")),
            len(report.get("files", [])),
            len(report.get("findings", [])),
            json.dumps(languages, sort_keys=True),
        )
        self.db.execute(
            """INSERT INTO projects
               (project_id, root, project_name, report_path, scan_finished_at,
                file_count, finding_count, languages_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(root) DO UPDATE SET
                project_id=excluded.project_id,
                project_name=excluded.project_name,
                report_path=excluded.report_path,
                scan_finished_at=excluded.scan_finished_at,
                file_count=excluded.file_count,
                finding_count=excluded.finding_count,
                languages_json=excluded.languages_json""",
            values,
        )
        self.db.commit()
        return {
            "root": root,
            "report_path": str(report_path),
            "file_count": values[5],
            "finding_count": values[6],
            "languages": languages,
        }

    def list_projects(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            """SELECT root, project_name, report_path, scan_finished_at,
                      file_count, finding_count, languages_json
               FROM projects ORDER BY root"""
        ).fetchall()
        return [
            {
                "root": row[0],
                "name": row[1],
                "report_path": row[2],
                "scan_finished_at": row[3],
                "file_count": row[4],
                "finding_count": row[5],
                "languages": json.loads(row[6]),
            }
            for row in rows
        ]

    def load_reports(self) -> list[dict[str, Any]]:
        reports = []
        for project in self.list_projects():
            report_path = Path(project["report_path"])
            if not report_path.is_file():
                raise FileNotFoundError(
                    f"Registered report for {project['root']} is missing: {report_path}"
                )
            reports.append(load_report(report_path))
        return reports

    def remove_project(self, root: Path) -> bool:
        canonical_root = str(root.expanduser().resolve())
        cursor = self.db.execute("DELETE FROM projects WHERE root=?", (canonical_root,))
        self.db.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "ProjectCatalog":
        return self

    def __exit__(self, *_: object) -> None:
        self.db.close()
