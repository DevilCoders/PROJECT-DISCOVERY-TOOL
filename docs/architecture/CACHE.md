# Fingerprint Cache

The SQLite cache stores file metadata and SHA-256 digests, never file contents. A cached digest is reused only when size, nanosecond modification time, the change time and the file ID (inode) all match. This reduces false cache hits when timestamps are preserved or a path is replaced. File IDs are stored as text, so 128-bit ReFS and Dev Drive IDs and 64-bit inodes with the top bit set are kept exactly; a cache write that fails is reported once as a diagnostic and never fails the file.

**Change time on Windows.** There `st_ctime_ns` is the creation time, so the cache compares the NTFS ChangeTime instead, read through a no-follow handle opened for attributes only (FileBasicInfo). That costs about 31 µs per cached file, against about 690 µs to read and hash even a 4 KiB file (measured 2026-11-13). A same-size rewrite whose modification time is restored afterwards (`cp -p`, `rsync -t --inplace`, a `utime` call) changes the ChangeTime, so it is rehashed. A file system that reports no ChangeTime falls back to the creation time.

**Damaged databases.** A cache that cannot be opened is moved aside (`fingerprints.sqlite3.corrupt-<time>`) when a scan starts. One that opens but fails a read during the scan ("database disk image is malformed") is bypassed for the rest of that scan, every file is hashed, a diagnostic says so, and it is moved aside when the scan ends, so the next scan rebuilds it.

Legacy cache databases are migrated additively. After a complete filesystem traversal, entries for paths no longer present are pruned using a temporary SQLite table, avoiding the bound-variable limit for repositories with thousands of files. If traversal reports errors, pruning is skipped so an incomplete walk cannot delete valid cache entries.

The cache is an incremental optimization, not a cryptographic guarantee against an adversary able to preserve all filesystem metadata. Use a clean-cache scan when validating untrusted or adversarially modified trees.
