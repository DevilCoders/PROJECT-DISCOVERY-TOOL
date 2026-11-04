"""Static SQL schema, relationship and migration-risk inventory."""
from __future__ import annotations

import re
from pathlib import Path

from ..source_utils import read_text_bounded

from .base import Analyzer
from ..models import FileRecord, Finding


_IDENTIFIER = r'[\w."]+'
_OBJECT_PATTERNS = {
    "table": re.compile(
        rf"(?im)^\s*CREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({_IDENTIFIER})"
    ),
    "view": re.compile(
        rf"(?im)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+({_IDENTIFIER})"
    ),
    "index": re.compile(
        rf"(?im)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?({_IDENTIFIER})\s+ON\s+({_IDENTIFIER})"
    ),
    "procedure": re.compile(
        rf"(?im)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+({_IDENTIFIER})"
    ),
    "function": re.compile(
        rf"(?im)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+({_IDENTIFIER})"
    ),
    "trigger": re.compile(
        rf"(?im)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+({_IDENTIFIER})"
    ),
}
_RELATION = re.compile(rf"(?im)\bREFERENCES\s+({_IDENTIFIER})")
_DESTRUCTIVE = (
    ("drop_table", re.compile(r"(?im)^\s*DROP\s+TABLE\b")),
    ("drop_column", re.compile(r"(?im)^\s*ALTER\s+TABLE\b[^;]*?\bDROP\s+COLUMN\b")),
    ("truncate_table", re.compile(r"(?im)^\s*TRUNCATE\s+(?:TABLE\s+)?")),
    ("drop_database", re.compile(r"(?im)^\s*DROP\s+DATABASE\b")),
    ("drop_schema", re.compile(r"(?im)^\s*DROP\s+SCHEMA\b")),
)


def _clean_identifier(value: str) -> str:
    return value.strip().strip('"[]')


class SQLSchemaAnalyzer(Analyzer):
    """Inventory common SQL DDL objects and flag potentially destructive migrations."""

    name = "sql-schema"
    domains = ("databases_sql", "migrations",)

    def supports(self, record: FileRecord) -> bool:
        return record.extension == ".sql" and record.error is None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            content = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "database",
                f"SQL file read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        objects: dict[str, list[tuple[str, int]]] = {}
        for kind, pattern in _OBJECT_PATTERNS.items():
            matches = []
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                matches.append((_clean_identifier(match.group(1)), line))
            objects[kind] = matches

        relations = []
        for match in _RELATION.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            relations.append((_clean_identifier(match.group(1)), line))

        findings: list[Finding] = []
        object_count = sum(len(items) for items in objects.values())
        if object_count or relations:
            counts = ", ".join(
                f"{len(items)} {kind}{'s' if len(items) != 1 else ''}"
                for kind, items in objects.items() if items
            ) or "no top-level DDL objects"
            evidence = [
                f"{record.path}:{line} {kind} {name}"
                for kind, items in objects.items() for name, line in items[:100]
            ]
            evidence.extend(
                f"{record.path}:{line} references {name}" for name, line in relations[:100]
            )
            findings.append(Finding(
                "database",
                f"SQL schema inventory: {record.path}",
                f"Detected {counts}; {len(relations)} REFERENCES clauses. "
                "Static DDL inventory does not establish the live database schema.",
                confidence="CONFIRMED",
                evidence=evidence or [record.path],
                analyzer=self.name,
            ))

        for risk_name, pattern in _DESTRUCTIVE:
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(Finding(
                    "migration",
                    f"Potentially destructive SQL operation: {risk_name}",
                    "A destructive DDL/DML pattern was observed. Review transaction strategy, "
                    "data-loss impact, rollback plan and migration ordering.",
                    confidence="INFERRED",
                    evidence=[f"{record.path}:{line}"],
                    analyzer=self.name,
                    severity="HIGH",
                ))
        return findings
