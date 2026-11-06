from pathlib import Path

from project_discovery.analyzers.databases.prisma import PrismaSchemaAnalyzer
from project_discovery.models import FileRecord


def test_prisma_models_enums_provider_and_relations(tmp_path: Path):
    path = tmp_path / "schema.prisma"
    path.write_text(
        'datasource db {\n  provider = "postgresql"\n  url = env("DATABASE_URL")\n}\n'
        'model User {\n  id Int @id\n  posts Post[]\n}\n'
        'model Post {\n  id Int @id\n  author User @relation(fields: [authorId], references: [id])\n'
        '  authorId Int\n}\n'
        'enum Status {\n  ACTIVE\n  DISABLED\n}\n',
        encoding="utf-8",
    )
    record = FileRecord(path.name, path.stat().st_size, ".prisma", "Prisma")
    findings = PrismaSchemaAnalyzer().analyze(path, record)
    assert "2 models" in findings[0].detail
    assert "1 enums" in findings[0].detail
    assert "postgresql" in findings[0].detail
    assert "relation User.posts -> Post" in " ".join(findings[0].evidence)


def test_prisma_file_without_blocks_is_unknown(tmp_path: Path):
    path = tmp_path / "schema.prisma"
    path.write_text("// no model declarations\n", encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, ".prisma", "Prisma")
    findings = PrismaSchemaAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
