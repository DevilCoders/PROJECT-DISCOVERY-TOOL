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
pdt catalog-remove https://github.com/org/repo          # every scanned ref of the repository
pdt catalog-remove 'https://github.com/org/repo#v1.2.0' # one ref
```

Local roots are stored as resolved absolute paths. A remote scan is registered by its credential-free URL followed by `#ref` when a ref or revision was scanned, so two refs of one repository are two projects; the key does not depend on the directory `catalog-add` runs in. Roots from a report made on another operating system are kept as written.

The default catalog database is stored under the user's home directory in .pdt/catalog.sqlite3. Override it with --db. The catalog retains local paths; moving or deleting a report requires re-registering it. The report files remain the source of truth.
