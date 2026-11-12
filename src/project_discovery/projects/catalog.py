"""Local SQLite registry for independent project scan reports."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .comparison import load_report

# ``user@host:path`` (scp-style Git remotes); a Windows drive ``C:\`` has no "@".
_SCP_REMOTE = re.compile(r"^[\w.-]+@[\w.-]+:")


def _is_remote(root: str) -> bool:
    return "://" in root or bool(_SCP_REMOTE.match(root))


def _local_path(root: str) -> bool:
    """Whether ``root`` is an absolute path on this host (``/srv/app`` is not, on Windows)."""
    return Path(root).expanduser().is_absolute()


def catalog_root(report: dict[str, Any]) -> str:
    """The catalog key of a report's project.

    Local roots are resolved. A remote scan's root is its credential-free URL, kept as is
    and followed by ``#ref`` when a ref or revision was scanned, so two refs of one
    repository are two projects. Roots that are not local paths on this host (a report
    from another operating system) are kept verbatim instead of being resolved under the
    current directory.
    """
    root = str(report.get("root", ""))
    scan = report.get("scan") if isinstance(report.get("scan"), dict) else {}
    remote = scan.get("remote") if isinstance(scan.get("remote"), dict) else None
    if remote is not None or _is_remote(root):
        ref = (remote or {}).get("ref") or (remote or {}).get("revision")
        return f"{root}#{ref}" if ref and "#" not in root else root
    if not _local_path(root):
        return root
    return str(Path(root).expanduser().resolve())


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
        root = catalog_root(report)
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

    def remove_project(self, root: Path | str) -> bool:
        """Remove a project by its local path, or a remote one by URL (every ref) or URL#ref."""
        text = str(root)
        if _is_remote(text) or not _local_path(text):
            cursor = self.db.execute(
                "DELETE FROM projects WHERE root=? OR (instr(?, '#') = 0 AND substr(root, 1, ?) = ?)",
                (text, text, len(text) + 1, text + "#"),
            )
        else:
            canonical_root = str(Path(text).expanduser().resolve())
            cursor = self.db.execute("DELETE FROM projects WHERE root=?", (canonical_root,))
        self.db.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "ProjectCatalog":
        return self

    def __exit__(self, *_: object) -> None:
        self.db.close()
