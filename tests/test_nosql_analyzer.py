from pathlib import Path

from project_discovery.analyzers.nosql_analyzer import NoSQLIntelligenceAnalyzer
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
