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


def test_prisma_reads_tab_indented_fields_and_only_datasource_providers(tmp_path: Path):
    path = tmp_path / "schema.prisma"
    path.write_text(
        'generator client {\n\tprovider = "prisma-client-js"\n}\n'
        'datasource db {\n\tprovider = "mysql"\n}\n'
        'model User {\n\tid Int @id\n\tposts Post[]\n}\nmodel Post {\n\tid Int @id\n\tauthor User\n}\n',
        encoding="utf-8",
    )
    record = FileRecord("schema.prisma", path.stat().st_size, ".prisma", "Prisma")
    finding = PrismaSchemaAnalyzer().analyze(path, record)[0]
    assert "4 model fields" in finding.detail and "2 model relations" in finding.detail
    assert "datasource providers: mysql" in finding.detail and "prisma-client-js" not in finding.detail
