# Fingerprint Cache

The SQLite cache stores file metadata and SHA-256 digests, never file contents. A cached digest is reused only when size, nanosecond modification time, nanosecond change time and inode all match. This reduces false cache hits when timestamps are preserved or a path is replaced.

Legacy cache databases are migrated additively. After a complete filesystem traversal, entries for paths no longer present are pruned using a temporary SQLite table, avoiding the bound-variable limit for repositories with thousands of files. If traversal reports errors, pruning is skipped so an incomplete walk cannot delete valid cache entries.

The cache is an incremental optimization, not a cryptographic guarantee against an adversary able to preserve all filesystem metadata. Use a clean-cache scan when validating untrusted or adversarially modified trees.
