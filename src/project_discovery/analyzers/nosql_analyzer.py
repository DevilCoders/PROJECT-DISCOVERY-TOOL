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
    "chromadb": ("Chroma", "chromadb"),
    "qdrant_client": ("Qdrant", "qdrant_client"),
    "pinecone": ("Pinecone", "pinecone"),
    "weaviate": ("Weaviate", "weaviate"),
    "pymilvus": ("Milvus", "pymilvus"),
    "faiss": ("FAISS", "faiss"),
    "lancedb": ("LanceDB", "lancedb"),
    "vespa": ("Vespa", "vespa"),
    "arango": ("ArangoDB", "arango"),
    "surrealdb": ("SurrealDB", "surrealdb"),
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
    "Chroma": re.compile(r"""(?:from\\s+chromadb|import\\s+chromadb|(?:require|from)\\s*\\(?\\s*['"]chromadb['"])""", re.I),
    "Qdrant": re.compile(r"(?:from\\s+qdrant_client|import\\s+qdrant_client|@qdrant/js-client-rest|github.com/qdrant/go-client)", re.I),
    "Pinecone": re.compile(r"(?:from\\s+pinecone|import\\s+pinecone|@pinecone-database/pinecone)", re.I),
    "Weaviate": re.compile(r"(?:from\\s+weaviate|import\\s+weaviate|weaviate-client|io.weaviate)", re.I),
    "Milvus": re.compile(r"(?:from\\s+pymilvus|import\\s+pymilvus|io.milvus|milvus-sdk-go)", re.I),
    "FAISS": re.compile(r"(?:from\\s+faiss|import\\s+faiss|faiss/)", re.I),
    "LanceDB": re.compile(r"(?:from\\s+lancedb|import\\s+lancedb|@lancedb/lancedb)", re.I),
    "Vespa": re.compile(r"(?:from\\s+vespa|import\\s+vespa|com.yahoo.vespa)", re.I),
    "ArangoDB": re.compile(r"(?:from\\s+arango|import\\s+arango|arangojs|github.com/arangodb)", re.I),
    "SurrealDB": re.compile(r"(?:from\\s+surrealdb|import\\s+surrealdb|surrealdb)", re.I),
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
    "Chroma": {"get_or_create_collection", "create_collection", "add", "query", "upsert", "delete"},
    "Qdrant": {"create_collection", "upsert", "search", "query_points", "retrieve", "delete"},
    "Pinecone": {"Index", "upsert", "query", "delete", "describe_index_stats"},
    "Weaviate": {"collections", "query", "insert", "search", "delete"},
    "Milvus": {"create_collection", "insert", "search", "query", "delete"},
    "FAISS": {"IndexFlatL2", "IndexFlatIP", "add", "search", "write_index", "read_index"},
    "LanceDB": {"connect", "create_table", "open_table", "search", "add", "delete"},
    "Vespa": {"query", "feed", "delete"},
    "ArangoDB": {"collection", "db", "aql", "insert", "update", "delete"},
    "SurrealDB": {"query", "select", "create", "update", "delete", "upsert"},
}


def _python_imports(source: str, relative: str) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError:
        return {}, {}
    imports: dict[str, set[int]] = {}
    operations: dict[str, set[int]] = {}
    aliases: dict[str, str] = {}
    def root_name(node: ast.AST) -> str:
        while isinstance(node, ast.Attribute):
            node = node.value
        return node.id if isinstance(node, ast.Name) else ""

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
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Call):
                technology = aliases.get(root_name(value.func))
                if technology:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            aliases[target.id] = technology
        elif isinstance(node, ast.Call):
            func = node.func
            method = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else ""
            )
            if isinstance(func, ast.Attribute):
                root = root_name(func.value)
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
