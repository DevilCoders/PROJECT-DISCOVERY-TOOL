# Fingerprint Cache

The SQLite cache stores file metadata and SHA-256 digests, never file contents. A cached digest is reused only when size, nanosecond modification time, `st_ctime_ns` and the file ID (inode) all match. This reduces false cache hits when timestamps are preserved or a path is replaced. File IDs are stored as text, so 128-bit ReFS and Dev Drive IDs and 64-bit inodes with the top bit set are kept exactly; a cache write that fails is reported once as a diagnostic and never fails the file.

**Windows has no change-time check.** There `st_ctime_ns` is the creation time, not a metadata-change time. A same-size rewrite whose modification time is restored afterwards (`cp -p`, `rsync -t --inplace`, a `utime` call) keeps every compared field, so the stale digest is reused. Reading the real change time would mean opening each file, which costs what the cache saves. On Windows, scan with a fresh output directory, or delete `.pdt-cache/fingerprints.sqlite3`, when digests must be exact (for example before `pdt compare` relies on duplicate content).

Legacy cache databases are migrated additively. After a complete filesystem traversal, entries for paths no longer present are pruned using a temporary SQLite table, avoiding the bound-variable limit for repositories with thousands of files. If traversal reports errors, pruning is skipped so an incomplete walk cannot delete valid cache entries.

The cache is an incremental optimization, not a cryptographic guarantee against an adversary able to preserve all filesystem metadata. Use a clean-cache scan when validating untrusted or adversarially modified trees.
