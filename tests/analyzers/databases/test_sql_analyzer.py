from pathlib import Path

from project_discovery.analyzers.databases.sql import SQLSchemaAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, content: str):
    path = tmp_path / "V001__schema.sql"
    path.write_text(content, encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, ".sql", "SQL")
    analyzer = SQLSchemaAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_sql_schema_inventory_extracts_objects_and_relations(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "CREATE TABLE users (id INTEGER PRIMARY KEY);\n"
        "CREATE TABLE orders (user_id INTEGER REFERENCES users(id));\n"
        "CREATE INDEX idx_orders_user ON orders(user_id);\n"
        "CREATE VIEW active_users AS SELECT * FROM users;\n",
    )
    summary = findings[0]
    assert "2 tables" in summary.detail
    assert "1 index" in summary.detail
    assert "1 view" in summary.detail
    assert "1 REFERENCES clauses" in summary.detail
    assert any("references users" in evidence for evidence in summary.evidence)


def test_sql_migration_risks_are_inferred(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "DROP TABLE old_users;\n"
        "ALTER TABLE users DROP COLUMN legacy;\n"
        "TRUNCATE TABLE sessions;\n",
    )
    risks = [item for item in findings if item.category == "migration"]
    assert len(risks) == 3
    assert all(item.confidence == "INFERRED" for item in risks)
    assert all(item.evidence[0].startswith("V001__schema.sql:") for item in risks)


def test_sql_values_and_full_statements_are_not_copied_to_findings(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "CREATE TABLE credentials (token VARCHAR(255));\n"
        "INSERT INTO credentials VALUES ('sensitive-value');\n",
    )
    serialized = repr([item.to_dict() for item in findings])
    assert "sensitive-value" not in serialized


def test_mysql_sqlserver_and_postgres_ddl_are_inventoried(tmp_path: Path):
    # Regressions: backtick and bracket identifiers never matched (a mysqldump had no tables
    # but a HIGH finding per DROP TABLE IF EXISTS guard), and PostgreSQL variants were missed.
    findings = _scan(tmp_path, (
        "DROP TABLE IF EXISTS `customers`;\nCREATE TABLE `customers` (\n  `id` int NOT NULL\n);\n"
        "CREATE TABLE [dbo].[Orders] ([Id] INT, CONSTRAINT fk FOREIGN KEY (c) REFERENCES [dbo].[Customers](Id));\n"
        "CREATE UNLOGGED TABLE public.sessions (id int);\nCREATE MATERIALIZED VIEW public.daily AS SELECT 1;\n"
        "CREATE INDEX CONCURRENTLY idx_sessions ON public.sessions (id);\n"
    ))
    inventory = next(item for item in findings if item.title.startswith("SQL schema inventory"))
    evidence = " ".join(inventory.evidence)
    for name in ("table customers", "table dbo.Orders", "table public.sessions", "view public.daily",
                 "index idx_sessions", "references dbo.Customers"):
        assert name in evidence, name
    assert not any(item.title.startswith("Potentially destructive") for item in findings)


def test_rollback_sections_of_sql_migrations_are_not_destructive(tmp_path: Path):
    findings = _scan(tmp_path, (
        "-- +goose Up\nCREATE TABLE post (id int);\n-- +goose Down\nDROP TABLE post;\n"
    ))
    assert not any(item.title.startswith("Potentially destructive") for item in findings)
    destructive = _scan(tmp_path, "DROP TABLE legacy_orders;\n")
    assert any(item.title == "Potentially destructive SQL operation: drop_table" for item in destructive)
