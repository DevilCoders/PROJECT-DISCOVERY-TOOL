# ORM and Data Mapping

The first ORM-specific adapter inventories Prisma schema files. It extracts model and enum declarations, datasource providers (a generator's provider names a client, not a database), field counts with any indentation, and direct model-to-model field references. It does not connect to a database or prove that migrations have been applied.

SQLAlchemy, Django ORM, TypeORM, Sequelize, Entity Framework, Hibernate, Mongoose, MongoEngine, and other framework-specific model adapters remain part of the wider ORM coverage roadmap.
