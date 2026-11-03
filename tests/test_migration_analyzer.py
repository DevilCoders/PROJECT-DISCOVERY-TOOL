from pathlib import Path

from project_discovery.analyzers.migration_analyzer import MigrationIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, relative: str, content: str):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Migration")
    analyzer = MigrationIntelligenceAnalyzer()
    assert analyzer.supports(record), relative
    return analyzer.analyze(path, record)


def test_flyway_versioned_sql_migration_is_identified(tmp_path: Path):
    findings = _scan(
        tmp_path, "db/migration/V12__add_user_email.sql",
        "ALTER TABLE users ADD COLUMN email TEXT;\n",
    )
    inventory = findings[0]
    assert "Framework: Flyway" in inventory.detail
    assert "identifier: V12__add_user_email" in inventory.detail
    assert any("operation: add_column" in item for item in inventory.evidence)


def test_alembic_revision_and_destructive_operation_are_identified(tmp_path: Path):
    findings = _scan(
        tmp_path, "alembic/versions/abc_remove_legacy.py",
        'revision = "abc123"\ndown_revision = "abc122"\n'
        "def upgrade():\n    op.drop_column('users', 'legacy')\n"
        "def downgrade():\n    op.add_column('users', sa.Column('legacy', sa.String()))\n",
    )
    assert "Framework: Alembic" in findings[0].detail
    assert "identifier: abc123" in findings[0].detail
    assert "rollback marker: present" in findings[0].detail
    assert any("Potentially destructive" in item.title for item in findings)


def test_rails_and_laravel_migration_apis_are_recognized(tmp_path: Path):
    rails = _scan(
        tmp_path, "db/migrate/20261103120000_add_users.rb",
        "class AddUsers < ActiveRecord::Migration[7.1]\n"
        "  def change\n    create_table :users\n  end\nend\n",
    )
    laravel = _scan(
        tmp_path, "database/migrations/2026_create_users.php",
        '<?php\nSchema::create(\'users\', function (Blueprint $table) {});\n'
        "Schema::dropIfExists('users');\n",
    )
    assert "Rails Active Record" in rails[0].detail
    assert "Laravel" in laravel[0].detail
    assert any("Potentially destructive" in item.title for item in laravel)


def test_liquibase_and_entity_framework_migrations_are_recognized(tmp_path: Path):
    liquibase = _scan(
        tmp_path, "db/changelog/001-users.xml",
        '<databaseChangeLog><changeSet id="001" author="team">'
        '<createTable tableName="users"/><dropTable tableName="old_users"/>'
        '</changeSet></databaseChangeLog>',
    )
    ef = _scan(
        tmp_path, "Migrations/2026_RemoveLegacy.cs",
        'using Microsoft.EntityFrameworkCore.Migrations;\n'
        'public class RemoveLegacy : Migration { '
        'protected override void Up(MigrationBuilder migrationBuilder) { '
        'migrationBuilder.DropTable(name: "legacy"); } }',
    )
    assert "Liquibase" in liquibase[0].detail
    assert "identifier: 001" in liquibase[0].detail
    assert any("Potentially destructive" in item.title for item in liquibase)
    assert "Entity Framework Core" in ef[0].detail
    assert any("Potentially destructive" in item.title for item in ef)


def test_migration_analyzer_does_not_claim_execution_or_rollback_safety(tmp_path: Path):
    findings = _scan(
        tmp_path, "prisma/migrations/2026_init/migration.sql",
        "CREATE TABLE users (id INTEGER);\n",
    )
    assert "Prisma" in findings[0].detail
    assert "Static markers do not prove rollback safety" in findings[0].detail



def test_django_and_typeorm_migrations_are_recognized(tmp_path: Path):
    django = _scan(
        tmp_path, "accounts/migrations/0003_remove_legacy.py",
        "from django.db import migrations\n"
        "class Migration(migrations.Migration):\n"
        "    operations = [migrations.RemoveField(model_name='user', name='legacy')]\n",
    )
    typeorm = _scan(
        tmp_path, "src/migrations/1710000000-DropOld.ts",
        "export class DropOld implements MigrationInterface {\n"
        "  async up(queryRunner: QueryRunner) { await queryRunner.dropTable('old'); }\n"
        "  async down(queryRunner: QueryRunner) { await queryRunner.createTable(); }\n"
        "}\n",
    )
    assert "Django" in django[0].detail
    assert any("Potentially destructive" in item.title for item in django)
    assert "TypeORM" in typeorm[0].detail
    assert any("Potentially destructive" in item.title for item in typeorm)


def test_knex_sequelize_and_ecto_migration_conventions_are_recognized(tmp_path: Path):
    knex = _scan(
        tmp_path, "db/migrations/001_drop_old.js",
        "exports.up = async knex => knex.schema.dropTable('old');\n"
        "exports.down = async knex => knex.schema.createTable('old');\n",
    )
    sequelize = _scan(
        tmp_path, "migrations/002_drop_old.js",
        "module.exports = { async up(queryInterface) { await queryInterface.dropTable('old'); }, "
        "async down() {} };\n",
    )
    ecto = _scan(
        tmp_path, "priv/repo/migrations/20261103120000_drop_old.exs",
        "defmodule App.Repo.Migrations.DropOld do\n"
        "  use Ecto.Migration\n  def change do\n    drop table(:old)\n  end\nend\n",
    )
    assert "Knex" in knex[0].detail
    assert "Sequelize" in sequelize[0].detail
    assert "Ecto" in ecto[0].detail


def test_generic_migration_folder_is_not_overstated_as_confirmed(tmp_path: Path):
    findings = _scan(
        tmp_path, "migrations/notes.py",
        "# placeholder migration note\n",
    )
    assert findings[0].confidence == "INFERRED"


def test_goose_drizzle_and_diesel_migrations_are_discovered(tmp_path: Path):
    goose = _scan(
        tmp_path, "db/migrations/20261103_add_users.sql",
        "-- +goose Up\nCREATE TABLE users(id INTEGER);\n"
        "-- +goose Down\nDROP TABLE users;\n",
    )
    drizzle = _scan(
        tmp_path, "drizzle/0001_add_users.ts",
        'import { pgTable } from "drizzle-orm/pg-core";\n'
        'export const users = pgTable("users", {});\n',
    )
    diesel = _scan(
        tmp_path, "migrations/20261103_drop_legacy.rs",
        'diesel::sql_query("DROP TABLE legacy").execute(connection);\n',
    )
    assert "Goose" in goose[0].detail
    assert any("Potentially destructive" in item.title for item in goose)
    assert "Drizzle ORM" in drizzle[0].detail
    assert "create_table" in drizzle[0].detail
    assert "Diesel" in diesel[0].detail
    assert any("Potentially destructive" in item.title for item in diesel)
