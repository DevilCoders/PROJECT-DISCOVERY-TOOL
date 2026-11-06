from pathlib import Path

from project_discovery.analyzers.databases.nosql import NoSQLIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix.lower(), "Source")
    analyzer = NoSQLIntelligenceAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_python_mongodb_and_redis_imports_and_operations(tmp_path: Path):
    findings = _scan(
        tmp_path, "storage.py",
        "from pymongo import MongoClient\nimport redis\n"
        "client = MongoClient(uri)\ncollection.find_one({})\n"
        "cache = redis.Redis()\ncache.set('key', value)\n",
    )
    assert any("MongoDB datastore references" in item.title for item in findings)
    assert any("Redis datastore references" in item.title for item in findings)
    assert all(item.confidence == "CONFIRMED" for item in findings)


def test_javascript_mongoose_detection(tmp_path: Path):
    findings = _scan(
        tmp_path, "store.ts",
        "import mongoose from 'mongoose';\n"
        "collection.find({});\n",
    )
    assert any("MongoDB datastore references" in item.title for item in findings)


def test_java_neo4j_and_cassandra_import_detection(tmp_path: Path):
    findings = _scan(
        tmp_path, "GraphStore.java",
        "import org.neo4j.driver.Driver;\n"
        "import com.datastax.oss.driver.api.core.CqlSession;\n",
    )
    assert any("Neo4j datastore references" in item.title for item in findings)
    assert any("Cassandra datastore references" in item.title for item in findings)


def test_unrelated_source_has_no_nosql_findings(tmp_path: Path):
    assert _scan(tmp_path, "main.py", "def main():\n    return 1\n") == []


def test_non_source_files_are_not_supported():
    record = FileRecord("dataset.parquet", 10, ".parquet", "Data")
    assert NoSQLIntelligenceAnalyzer().supports(record) is False


def test_python_vector_database_imports_resolve_client_aliases_and_operations(tmp_path: Path):
    findings = _scan(
        tmp_path, "vector_store.py",
        "from qdrant_client import QdrantClient\n"
        "client = QdrantClient(url='http://localhost')\n"
        "client.search(collection_name='docs', query_vector=vector)\n"
        "from chromadb import PersistentClient\n"
        "chroma = PersistentClient()\n"
        "collection = chroma.get_or_create_collection('docs')\n"
        "collection.query(query_texts=['hello'])\n"
        "from pinecone import Pinecone\n"
        "pc = Pinecone()\n"
        "index = pc.Index('docs')\n"
        "index.upsert(vectors=items)\n",
    )
    by_name = {item.title.split(" datastore", 1)[0]: item for item in findings}
    assert "Qdrant" in by_name
    assert "Chroma" in by_name
    assert "Pinecone" in by_name
    assert any("operation call site(s)" in item.detail for item in findings)


def test_javascript_vector_database_clients_are_detected(tmp_path: Path):
    findings = _scan(
        tmp_path, "vector.ts",
        "import { QdrantClient } from '@qdrant/js-client-rest';\n"
        "client.search({ collection_name: 'docs' });\n"
        "import { ChromaClient } from 'chromadb';\n"
        "collection.query({ queryTexts: ['hello'] });\n",
    )
    assert any("Qdrant datastore references" in item.title for item in findings)
    assert any("Chroma datastore references" in item.title for item in findings)


def test_no_sql_analyzer_accepts_the_full_source_language_catalog():
    from project_discovery.catalog.languages import source_extensions, source_language_names

    analyzer = NoSQLIntelligenceAnalyzer()
    assert analyzer.languages == source_language_names()
    for extension in source_extensions():
        record = FileRecord("sample" + extension, 1, extension, "Source")
        assert analyzer.supports(record), extension
