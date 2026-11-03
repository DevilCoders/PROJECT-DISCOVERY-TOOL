# SQL and Migration Intelligence

The initial SQL analyzer statically inventories common CREATE TABLE/VIEW/INDEX/PROCEDURE/FUNCTION/TRIGGER declarations and REFERENCES clauses. It also flags potentially destructive DROP, TRUNCATE and ALTER TABLE DROP COLUMN patterns as INFERRED findings.

It does not connect to a database, execute SQL, resolve dialect-specific semantics, or claim that a source schema matches a live database. The initial patterns are lexical and require review; advanced parsing, ORM mappings, migration framework state, rollback analysis, NoSQL models and cross-dialect schema diffing remain future work.
