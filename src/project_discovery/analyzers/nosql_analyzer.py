"""Static NoSQL and non-relational datastore discovery."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


_SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".cs", ".go", ".rs", ".rb", ".php",
}
_TECHNOLOGIES = {
    "pymongo": ("MongoDB", "pymongo"),
    "motor": ("MongoDB", "motor"),
    "mongoose": ("MongoDB", "mongoose"),
    "mongodb": ("MongoDB", "mongodb"),
    "redis": ("Redis", "redis"),
    "ioredis": ("Redis", "ioredis"),
    "neo4j": ("Neo4j", "neo4j"),
    "elasticsearch": ("Elasticsearch", "elasticsearch"),
    "opensearch": ("OpenSearch", "opensearch"),
    "cassandra": ("Cassandra", "cassandra"),
    "boto3": ("DynamoDB", "boto3"),
    "firebase_admin": ("Firestore", "firebase_admin"),
    "couchdb": ("CouchDB", "couchdb"),
    "influxdb_client": ("InfluxDB", "influxdb_client"),
    "clickhouse_connect": ("ClickHouse", "clickhouse_connect"),
    "clickhouse_driver": ("ClickHouse", "clickhouse_driver"),
}
_IMPORT_PATTERNS = {
    "MongoDB": re.compile(
        r"(?:from\s+(?:pymongo|motor|mongodb)|import\s+(?:pymongo|motor|mongodb)|"
        r"(?:require|from)\s*\(?\s*['\"](?:mongoose|mongodb)['\"]|"
        r"org\.mongodb|go\.mongodb\.org/mongo-driver)", re.I
    ),
    "Redis": re.compile(
        r"(?:from\s+redis|import\s+redis|require\s*\(\s*['\"]ioredis['\"]|"
        r"redis\.clients|github\.com/redis)", re.I
    ),
    "Neo4j": re.compile(r"(?:from\s+neo4j|import\s+neo4j|org\.neo4j)", re.I),
    "Elasticsearch": re.compile(r"(?:from\s+elasticsearch|import\s+elasticsearch|org\.elasticsearch)", re.I),
    "OpenSearch": re.compile(r"(?:from\s+opensearch|import\s+opensearch|org\.opensearch)", re.I),
    "Cassandra": re.compile(r"(?:from\s+cassandra|import\s+cassandra|com\.datastax)", re.I),
    "DynamoDB": re.compile(r"(?:boto3.*dynamodb|DynamoDB|dynamodb)", re.I),
    "Firestore": re.compile(r"(?:firebase_admin\.firestore|google\.cloud\.firestore|Firestore)", re.I),
    "CouchDB": re.compile(r"(?:import\s+couchdb|require\s*\(\s*['\"]nano['\"])", re.I),
    "InfluxDB": re.compile(r"(?:influxdb_client|influxdb-client)", re.I),
    "ClickHouse": re.compile(r"(?:clickhouse_connect|clickhouse_driver|clickhouse-jdbc)", re.I),
}
_OPERATIONS = {
    "MongoDB": {"find", "find_one", "insert_one", "insert_many", "update_one", "update_many", "delete_one", "aggregate", "bulk_write"},
    "Redis": {"get", "set", "mget", "mset", "hget", "hset", "lpush", "rpush", "xadd", "publish", "subscribe"},
    "Neo4j": {"run", "execute_read", "execute_write", "execute_query"},
    "Elasticsearch": {"search", "index", "update", "delete_by_query", "bulk"},
    "OpenSearch": {"search", "index", "update", "delete_by_query", "bulk"},
    "Cassandra": {"execute", "prepare", "execute_async"},
    "DynamoDB": {"get_item", "put_item", "query", "scan", "update_item", "delete_item", "batch_write_item"},
    "Firestore": {"collection", "document", "add", "set", "stream"},
    "CouchDB": {"save", "get", "delete", "view"},
    "InfluxDB": {"write", "query"},
    "ClickHouse": {"query", "insert", "command"},
}


def _python_imports(source: str, relative: str) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError:
        return {}, {}
    imports: dict[str, set[int]] = {}
    operations: dict[str, set[int]] = {}
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                tech = _TECHNOLOGIES.get(root)
                if tech:
                    imports.setdefault(tech[0], set()).add(node.lineno)
                    aliases[alias.asname or root] = tech[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            tech = _TECHNOLOGIES.get(root)
            if tech:
                imports.setdefault(tech[0], set()).add(node.lineno)
                for alias in node.names:
                    aliases[alias.asname or alias.name] = tech[0]
        elif isinstance(node, ast.Call):
            func = node.func
            method = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else ""
            )
            if isinstance(func, ast.Attribute):
                base = func.value
                root = base.id if isinstance(base, ast.Name) else ""
                tech = aliases.get(root)
                if tech and method in _OPERATIONS[tech]:
                    operations.setdefault(tech, set()).add(node.lineno)
    return imports, operations


class NoSQLIntelligenceAnalyzer(Analyzer):
    """Identify non-relational database clients and statically visible operations."""

    name = "nosql-intelligence"
    domains = ("databases_nosql", "messaging")
    languages = ("Python", "JavaScript", "TypeScript", "Java", "Kotlin", "C#", "Go", "Rust", "Ruby", "PHP")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _SOURCE_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "database",
                f"NoSQL analysis unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        if record.extension in {".py", ".pyi"}:
            imports, operations = _python_imports(source, record.path)
        else:
            imports: dict[str, set[int]] = {}
            operations: dict[str, set[int]] = {}
            lines = source.splitlines()
            for technology, pattern in _IMPORT_PATTERNS.items():
                locations = {
                    number for number, line in enumerate(lines, 1)
                    if pattern.search(line)
                }
                if locations:
                    imports[technology] = locations
            for technology, methods in _OPERATIONS.items():
                pattern = re.compile(
                    r"\.\s*(?:" + "|".join(re.escape(method) for method in sorted(methods))
                    + r")\s*\("
                )
                locations = {
                    number for number, line in enumerate(lines, 1)
                    if pattern.search(line)
                }
                if locations and technology in imports:
                    operations[technology] = locations

        findings = []
        for technology in sorted(set(imports) | set(operations)):
            import_lines = sorted(imports.get(technology, set()))
            operation_lines = sorted(operations.get(technology, set()))
            evidence = [f"{record.path}:{line} (client import)" for line in import_lines]
            evidence.extend(
                f"{record.path}:{line} (operation call)" for line in operation_lines
            )
            findings.append(Finding(
                "database",
                f"{technology} datastore references: {record.path}",
                f"Detected {len(import_lines)} client import reference(s) and "
                f"{len(operation_lines)} recognized operation call site(s). This is a "
                "static source inventory, not proof of a live database connection or schema.",
                confidence="CONFIRMED" if import_lines else "INFERRED",
                evidence=evidence[:100] or [record.path],
                analyzer=self.name,
            ))
        return findings
