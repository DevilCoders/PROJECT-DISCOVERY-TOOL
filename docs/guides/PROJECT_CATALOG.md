# Local Project Catalog

The local catalog stores report metadata and report file paths in SQLite. It does not copy source files or merge project directories.

Register reports:

```bash
pdt catalog-add /reports/project-a/discovery-report.json
pdt catalog-add /reports/project-b/discovery-report.json
```

List or compare all registered projects:

```bash
pdt catalog-list
pdt catalog-compare --output /reports/all-projects-comparison
```

Remove a registered project:

```bash
pdt catalog-remove /absolute/path/to/project
```

The default catalog database is stored under the user's home directory in .pdt/catalog.sqlite3. Override it with --db. The catalog retains local paths; moving or deleting a report requires re-registering it. The report files remain the source of truth.
