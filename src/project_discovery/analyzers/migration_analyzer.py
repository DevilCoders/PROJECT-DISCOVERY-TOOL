"""Cross-framework static database migration inventory.

Migration scripts are parsed as text only. The analyzer never imports, executes,
connects to, or modifies a database or target project.
"""
from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from .base import Analyzer
from ..models import FileRecord, Finding
from ..language_catalog import source_extensions


_MIGRATION_EXTENSIONS = source_extensions() | {".xml", ".yaml", ".yml", ".json"}

_MIGRATION_DIRS = {
    "migration", "migrations", "migrate", "versions", "changelog",
    "changelogs", "changeset", "changesets", "flyway", "liquibase", "drizzle",
}
_FLYWAY_NAME = re.compile(r"^(?P<identifier>(?:V\d+|R|U\d+)__.+)\.sql$", re.I)
_REVISION = re.compile(r"(?m)^\s*revision\s*=\s*['\"]([^'\"]+)['\"]")
_PARENT_REVISION = re.compile(r"""(?m)^\s*down_revision\s*=\s*['"]([^'"]+)['"]""")
_CHANGESET_ID = re.compile(r"(?i)<changeSet\b[^>]*\bid\s*=\s*['\"]([^'\"]+)")
_OPERATION_PATTERNS = (
    ("create_table", re.compile(
        r"(?i)(?:\bCREATE\s+(?:TEMPORARY\s+)?TABLE\b|\b(?:op\.)?create_table\s*\(|\b(?:pgTable|mysqlTable|sqliteTable)\s*\(|"
        r"\bSchema::create\s*\(|\bcreateTable\s*\(|\bCreateTable\s*\(|"
        r"<\s*createTable\b|\bmigrations\.CreateModel\b)"
    ), False),
    ("drop_table", re.compile(
        r"(?i)(?:\bDROP\s+TABLE\b|\b(?:op\.)?drop_table\s*\(|"
        r"\bSchema::drop(?:IfExists)?\s*\(|\bdropTable\s*\(|"
        r"\bDropTable\s*\(|<\s*dropTable\b|\bmigrations\.DeleteModel\b)"
    ), True),
    ("add_column", re.compile(
        r"(?i)(?:\bADD\s+COLUMN\b|\b(?:op\.)?add_column\s*\(|"
        r"\baddColumn\s*\(|\bAddColumn\s*\(|<\s*addColumn\b|"
        r"\bmigrations\.AddField\b)"
    ), False),
    ("drop_column", re.compile(
        r"(?i)(?:\bDROP\s+COLUMN\b|\b(?:op\.)?drop_column\s*\(|"
        r"\b(?:remove_column|dropColumn|DropColumn)\s*\(|<\s*dropColumn\b|"
        r"\bmigrations\.RemoveField\b)"
    ), True),
    ("rename_column", re.compile(
        r"(?i)(?:\bRENAME\s+COLUMN\b|\brename_column\s*\(|"
        r"\brenameColumn\s*\(|\bRenameColumn\s*\(|<\s*renameColumn\b|"
        r"\bmigrations\.RenameField\b)"
    ), False),
    ("create_index", re.compile(
        r"(?i)(?:\bCREATE\s+(?:UNIQUE\s+)?INDEX\b|\bcreate_index\s*\(|"
        r"\bcreateIndex\s*\(|\bCreateIndex\s*\(|<\s*createIndex\b)"
    ), False),
    ("drop_index", re.compile(
        r"(?i)(?:\bDROP\s+INDEX\b|\bdrop_index\s*\(|"
        r"\bdropIndex\s*\(|\bDropIndex\s*\(|<\s*dropIndex\b)"
    ), True),
    ("truncate", re.compile(r"(?i)\bTRUNCATE\s+(?:TABLE\s+)?"), True),
    ("drop_database", re.compile(r"(?i)\bDROP\s+DATABASE\b"), True),
    ("drop_schema", re.compile(r"(?i)\bDROP\s+SCHEMA\b"), True),
)
_ROLLBACK_MARKER = re.compile(
    r"(?im)^\s*(?:def\s+(?:downgrade|down)|(?:async\s+)?down\s*\(|"
    r"exports\.down\s*=|function\s+downgrade\b|rollback\s*\()"
)


def _migration_context(path: str) -> tuple[str, ...]:
    normalized = path.replace("\\", "/")
    return tuple(part.lower() for part in PurePosixPath(normalized).parts[:-1])


def _framework(path: str, filename: str, content: str) -> str:
    parts = _migration_context(path)
    if _FLYWAY_NAME.match(filename):
        return "Flyway"
    if "-- +goose" in content.lower() or "github.com/pressly/goose" in content:
        return "Goose"
    if "-- atlas:" in content.lower() or "atlas.hcl" in parts:
        return "Atlas"
    if "-- migrate:up" in content.lower() or "-- migrate:down" in content.lower():
        return "Dbmate"
    if "drizzle-orm" in content or "drizzle-kit" in content:
        return "Drizzle ORM"
    if "diesel::" in content or "diesel" in parts:
        return "Diesel"
    if "sea_orm_migration" in content or "MigratorTrait" in content:
        return "SeaORM"
    if "sqlx::migrate" in content or "sqlx::migrate!" in content:
        return "SQLx"
    if "liquibase" in parts or "changelog" in parts or filename.startswith("changelog"):
        return "Liquibase"
    if "prisma" in parts:
        return "Prisma"
    if "alembic" in parts or _REVISION.search(content):
        return "Alembic"
    if ("db" in parts and "migrate" in parts) or "ActiveRecord::Migration" in content:
        return "Rails Active Record"
    if "django.db.migrations" in content or "migrations.Migration" in content:
        return "Django"
    if "MigrationBuilder" in content or "Microsoft.EntityFrameworkCore.Migrations" in content:
        return "Entity Framework Core"
    if "MigrationInterface" in content or "QueryRunner" in content:
        return "TypeORM"
    if "queryInterface" in content:
        return "Sequelize"
    if "knex.schema" in content or re.search(r"(?m)exports\.up\s*=", content):
        return "Knex"
    if "Schema::" in content or ("database" in parts and "migrations" in parts and filename.endswith(".php")):
        return "Laravel"
    if "Ecto.Migration" in content or ("priv" in parts and "repo" in parts):
        return "Ecto"
    return "Generic migration convention"


def _migration_identifier(filename: str, content: str) -> str:
    flyway = _FLYWAY_NAME.match(filename)
    if flyway:
        return flyway.group("identifier")
    revision = _REVISION.search(content)
    if revision:
        return revision.group(1)
    changeset = _CHANGESET_ID.search(content)
    if changeset:
        return changeset.group(1)
    stem = PurePosixPath(filename).stem
    numeric = re.match(r"^(\d{8,14}|\d+)_", stem)
    return numeric.group(1) if numeric else stem


class MigrationIntelligenceAnalyzer(Analyzer):
    """Identify migration frameworks, operations, rollback markers and destructive changes."""

    name = "migration-intelligence"
    domains = ("migrations",)
    languages = (
        "SQL", "Python", "Ruby", "JavaScript", "TypeScript", "C#", "PHP",
        "Elixir", "Java", "Kotlin", "XML", "YAML", "JSON",
    )

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.extension.lower() not in _MIGRATION_EXTENSIONS:
            return False
        path = record.path.replace("\\", "/")
        parts = _migration_context(path)
        filename = PurePosixPath(path).name
        return (
            bool(set(parts) & _MIGRATION_DIRS)
            or bool(_FLYWAY_NAME.match(filename))
            or filename.lower().startswith("changelog")
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "migration",
                f"Migration file read error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        filename = PurePosixPath(record.path.replace("\\", "/")).name
        framework = _framework(record.path, filename, content)
        identifier = _migration_identifier(filename, content)
        rollback_present = bool(_ROLLBACK_MARKER.search(content))
        parent_revision = _PARENT_REVISION.search(content)
        operations: list[tuple[str, int, bool]] = []
        for operation, pattern, destructive in _OPERATION_PATTERNS:
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                operations.append((operation, line, destructive))
        operations.sort(key=lambda item: (item[1], item[0]))

        evidence = [
            f"framework: {framework}",
            f"migration: {identifier}",
            *[
                f"operation: {operation} at {record.path}:{line}"
                for operation, line, _ in operations[:100]
            ],
        ]
        if parent_revision:
            evidence.append(f"parent revision: {parent_revision.group(1)}")
        if rollback_present:
            evidence.append("rollback/down migration marker present")
        findings = [Finding(
            "migration",
            f"Migration inventory: {record.path}",
            f"Framework: {framework}; identifier: {identifier}; "
            f"{len(operations)} schema/data operations; "
            f"rollback marker: {'present' if rollback_present else 'not detected'}. "
            "Static markers do not prove rollback safety or migration execution state.",
            confidence=(
                "INFERRED" if framework == "Generic migration convention" else "CONFIRMED"
            ),
            evidence=evidence,
            analyzer=self.name,
        )]

        # SQLSchemaAnalyzer already reports destructive SQL DDL, so this analyzer
        # adds framework-level destructive findings only for code/XML migrations.
        if record.extension.lower() != ".sql":
            for operation, line, destructive in operations:
                if destructive:
                    findings.append(Finding(
                        "migration",
                        f"Potentially destructive migration operation: {operation}",
                        "A destructive migration API or schema operation was observed. "
                        "Review data-loss impact, transaction behavior, backward compatibility "
                        "and the actual rollback implementation.",
                        confidence="INFERRED",
                        evidence=[f"{record.path}:{line}"],
                        analyzer=self.name,
                        severity="HIGH",
                    ))
        return findings
