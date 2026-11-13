"""Static SQL schema, relationship and migration-risk inventory."""
from __future__ import annotations

import bisect
import re
from pathlib import Path

from ...core.source_utils import LineIndex, describe_error, read_text_bounded
from ...models import FileRecord, Finding
from .migrations import down_regions, in_regions
from ..base import Analyzer

# Plain, "quoted", `backtick` (MySQL, mysqldump) and [bracket] (SQL Server) segments.
_SEGMENT = r'(?:"[^"\n]{1,128}+"|`[^`\n]{1,128}+`|\[[^\]\n]{1,128}+\]|\w++)'
_IDENTIFIER = rf"{_SEGMENT}(?:\.{_SEGMENT})*+"
_OBJECT_PATTERNS = {
    "table": re.compile(
        rf"(?im)^[ \t]*CREATE\s+(?:(?:GLOBAL|LOCAL)\s+)?(?:TEMP(?:ORARY)?\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({_IDENTIFIER})"
    ),
    "view": re.compile(
        rf"(?im)^[ \t]*CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?({_IDENTIFIER})"
    ),
    "index": re.compile(
        rf"(?im)^[ \t]*CREATE\s+(?:UNIQUE\s+)?(?:CLUSTERED\s+|NONCLUSTERED\s+)?INDEX\s+(?:CONCURRENTLY\s+)?"
        rf"(?:IF\s+NOT\s+EXISTS\s+)?({_IDENTIFIER})\s+ON\s+(?:ONLY\s+)?({_IDENTIFIER})"
    ),
    "procedure": re.compile(
        rf"(?im)^[ \t]*CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+({_IDENTIFIER})"
    ),
    "function": re.compile(
        rf"(?im)^[ \t]*CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+({_IDENTIFIER})"
    ),
    "trigger": re.compile(
        rf"(?im)^[ \t]*CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+({_IDENTIFIER})"
    ),
}
_RELATION = re.compile(rf"(?im)\bREFERENCES\s+({_IDENTIFIER})")
_DESTRUCTIVE = (
    ("drop_table", re.compile(rf"(?im)^[ \t]*DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?({_IDENTIFIER})")),
    ("drop_column", None),  # _drop_column_statements
    ("truncate_table", re.compile(r"(?im)^[ \t]*TRUNCATE\s+(?:TABLE\s+)?")),
    ("drop_database", re.compile(r"(?im)^[ \t]*DROP\s+DATABASE\b")),
    ("drop_schema", re.compile(r"(?im)^[ \t]*DROP\s+SCHEMA\b")),
)


_ALTER_TABLE = re.compile(r"(?im)^[ \t]*ALTER\s+TABLE\b")
_DROP_COLUMN = re.compile(r"(?i)\bDROP\s+COLUMN\b")
_SEMICOLON = re.compile(";")


def _drop_column_statements(content: str) -> list[int]:
    """Starts of ALTER TABLE statements that drop a column before their ``;``.

    The single regex ``ALTER TABLE [^;]*? DROP COLUMN`` scanned to the end of the file from
    every ALTER TABLE without a semicolon, which is quadratic; here every DROP COLUMN and
    semicolon is found once and each statement is checked by bisection.
    """
    drops = [match.start() for match in _DROP_COLUMN.finditer(content)]
    if not drops:
        return []
    semicolons = [match.start() for match in _SEMICOLON.finditer(content)]
    starts = []
    for head in _ALTER_TABLE.finditer(content):
        index = bisect.bisect_left(drops, head.end())
        if index == len(drops):
            break
        end = bisect.bisect_left(semicolons, head.end())
        if drops[index] < (semicolons[end] if end < len(semicolons) else len(content)):
            starts.append(head.start())
    return starts


def _clean_identifier(value: str) -> str:
    return re.sub(r'[`"\[\]]', "", value.strip())


class SQLSchemaAnalyzer(Analyzer):
    """Inventory common SQL DDL objects and flag potentially destructive migrations."""

    name = "sql-schema"
    domains = ("databases_sql", "migrations",)
    languages = ("SQL",)

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
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
                evidence=[record.path],
                analyzer=self.name,
            )]

        lines = LineIndex(content)
        objects: dict[str, list[tuple[str, int]]] = {}
        for kind, pattern in _OBJECT_PATTERNS.items():
            objects[kind] = [
                (_clean_identifier(match.group(1)), lines.line(match.start())) for match in pattern.finditer(content)
            ]

        relations = [
            (_clean_identifier(match.group(1)), lines.line(match.start())) for match in _RELATION.finditer(content)
        ]

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

        # A dump drops each table just before creating it again (DROP TABLE IF EXISTS
        # guards in mysqldump and pg_dump output), and rollback sections of migrations
        # reverse forward operations; neither destroys data the file keeps.
        created = {_clean_identifier(name).lower() for name, _ in objects["table"]}
        rollback = down_regions(content)
        for risk_name, pattern in _DESTRUCTIVE:
            if pattern is None:
                offsets = _drop_column_statements(content)
            else:
                offsets = [
                    match.start() for match in pattern.finditer(content)
                    if not (risk_name == "drop_table" and _clean_identifier(match.group(1)).lower() in created)
                ]
            for offset in offsets:
                if in_regions(offset, rollback):
                    continue
                line = lines.line(offset)
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
