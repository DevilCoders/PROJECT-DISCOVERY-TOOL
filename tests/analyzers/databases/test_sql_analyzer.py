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
