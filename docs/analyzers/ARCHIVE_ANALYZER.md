# Archive intelligence

PDT inspects archive metadata and bounded member samples in memory. Archive members are never extracted to the target tree or report directory, and archive links are never followed.

## Supported inspection paths

| Format family | Current behavior |
|---|---|
| ZIP-based packages (ZIP, JAR, WAR, EAR, APK/AAB, IPA, WHL/EGG, NUPKG) | Central-directory preflight, bounded metadata inventory, link/permission/path checks, encrypted/duplicate/high-ratio indicators and bounded member content samples |
| TAR and compressed TAR variants | Streaming metadata walk, symlink/hardlink/special-entry checks, mode-bit checks and bounded member content samples |
| Standalone GZIP/BZIP2/XZ, Zstandard, 7z, RAR, CAB, ISO, DEB and RPM | Recognition/detection only unless the file is a TAR container readable by the standard-library TAR backend; no external extractor is invoked |

## Inspection records

Every archive the analyzer inspects gets a record in the JSON report's top-level `archives` list, and every member it indexes a record in `archive_members` (both stored in the scan's SQLite inventory and streamed).

An archive's `state` is how far its inspection got, and `states` lists everything that applies:

| State | Meaning |
|---|---|
| `detected` | Recognized as an archive (always present) |
| `unsupported` | No built-in metadata reader for the format (7z, RAR, CAB, ISO, standalone GZIP, ...) |
| `index-read` | The member index (ZIP central directory, TAR headers) was read, at least in part |
| `metadata-complete` | Every member's metadata was read |
| `sample-read` | Member content was sampled in memory |
| `sample-truncated` | Some members' content was not read in full (a sample budget, an unreadable member) |
| `encrypted` | At least one member is encrypted, so its content was not sampled |
| `malformed` | The archive could not be read; `error` says why |
| `budget-stopped` | A limit stopped the metadata traversal: the entry, index-byte, wall-time or TAR decompression budget, or the engine's per-call budgets (`analyzer_time`, `analyzer_memory`, ...) |

The primary `state` is the first of `malformed`, `unsupported`, `budget-stopped`, `metadata-complete`, `index-read`, `detected` that applies. Each record also holds `format` (`zip`, `tar`, `tar+gzip`, `tar+bzip2`, `tar+xz`, or the detected type), `archive_bytes`, `compressed_bytes`, `members_declared` (the ZIP central directory's count; for TAR, the count once every header was read), `members_indexed`, `member_coverage_pct`, `regular_members`, `member_bytes` (their uncompressed size), `members_sampled`, `members_fully_sampled`, `members_not_fully_sampled`, `member_bytes_sampled`, `content_coverage_pct` (the share of regular members' bytes sampled), `encrypted_members`, `member_records` and `limits`: every limit that prevented deeper inspection, with its `value` and, where known, what was `used` or how many `members` it affected.

A member record holds the `archive`, its `ordinal` in the archive, `path`, `type` (`file`, `directory`, `symlink`, `hardlink`, `special`), `size`, `compressed_size` (ZIP), `mode` (permission bits), `mtime`, `link_target`, `uid`, `gid`, `owner` and `group` (TAR) and `flags`: `unsafe-path` (absolute, drive-prefixed or parent-traversal path or link target), `setuid`, `setgid`, `world-writable`, `encrypted`, `high-ratio` (over 1000:1 or a zero compressed size) and `duplicate` (the name occurs more than once). ZIP times are the members' DOS timestamps, local time without a zone at two-second resolution; TAR times are UTC. Names that are not valid UTF-8 keep backslash escapes.

An archive keeps up to 200,000 member records (its entry limit) and a scan up to 1,000,000; past the scan's ceiling the archives keep their summaries, and `metrics.archives` reports the records dropped. `metrics.archives` also counts archives by state and format, sums the members and bytes with their coverage, and counts the archives each limit stopped. The Markdown report has an *Archives* section with the archives not fully inspected first, the HTML report an *Archives by inspection state* card, and the terminal summary an *Archives* row.

## Resource limits

These are the defaults; `pdt scan --archive-limit NAME=VALUE` overrides any of them for a scan (`entries`, `index_mb`, `member_sample_mb`, `sample_mb`, `wall_seconds`, `decompressed_mb`, `uncompressed_mb`, `ratio`; byte limits in MiB). The overrides travel with the budget policy to every worker process, and `metrics.analysis_budgets` reports them (`analyzer_limit_overrides`) with the values in force (`analyzer_limits`):

- ZIP central-directory preflight: 200,000 entries and 64 MiB of declared central-directory bytes. The ZIP64 record is read the way `zipfile` reads it (whenever its locator precedes the EOCD, from just before the locator), so a classic EOCD that understates the entry count cannot slip past. If a valid bounded index cannot be established from the EOCD/ZIP64 trailer, the analyzer returns UNKNOWN without materializing ZipFile.infolist().
- Member sample: 1 MiB maximum per regular member.
- Total member sample: 32 MiB maximum per archive.
- Compressed TAR (gzip, bzip2, xz): decompressed through a budgeted reader capped at 4 GiB of output. The reader also enforces the wall-time budget inside each read.
- Wall time: 8 seconds per archive for metadata traversal and member sampling.
- Declared uncompressed size: 16 GiB per archive. Members declaring more in total get an `INFERRED` HIGH "Archive declares more uncompressed data than its budget" finding (a possible archive bomb) and the archive record the `uncompressed_bytes` limit; traversal continues, since nothing is decompressed past the samples.
- Compression ratio: members compressed more than 1,000:1, or to zero bytes, are flagged `high-ratio`.
- Nested archives: one level (`nested_depth`) and 64 MiB of nested archives in memory per archive (`nested_mb`).
- Evidence: at most 100 source/member references per finding.

When a count, byte or time budget is reached, the analyzer records an explicit UNKNOWN finding. A partial archive result must not be interpreted as a complete clean scan. ## Nested archives

A ZIP or TAR member named like an archive these readers inspect (`.zip`, `.jar`, `.war`, `.ear`, `.apk`, `.aab`, `.ipa`, `.whl`, `.egg`, `.nupkg`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`) is flagged `nested-archive` and, within the budgets, read whole into memory and inspected the same way: it gets its own archive record, member records and findings, named `outer.war::WEB-INF/lib/inner.jar`, and shares the top-level archive's wall-time budget. Nesting stops at `nested_depth` levels (1 by default) and when the nested archives would exceed `nested_mb` (64 MiB per top-level archive in total); the archive that holds a member left uninspected records the `nested_depth` or `nested_bytes` limit, and the member is sampled like any other file. Nothing is written to disk.

## Evidence and checks

The current metadata/content checks include:

- Absolute paths, drive-prefixed names and parent-traversal member paths.
- ZIP symlink entries and TAR symlink/hardlink targets; links are reported but not followed.
- TAR device/FIFO/socket-like special entries.
- ZIP/TAR setuid, setgid and world-writable permission bits.
- Duplicate ZIP member names, encrypted ZIP entries and ZIP compression ratios above 1000:1.
- ZIP and TAR member names that collide after case folding and Unicode NFC normalization (they overwrite each other when extracted on case-insensitive or normalizing filesystems).
- TAR traversal continues past oversized members and exhausted sample budgets, so every header is examined.
- Bounded in-memory checks for credential-like assignments, private-key markers, cloud access-key identifiers and email-shaped values. Matched values are discarded; evidence contains archive/member paths and line numbers, not matched values.

The member content scan is a conservative indicator scan, not malware detection, complete DLP, semantic analysis or a guarantee that encrypted/unsupported/truncated members are clean.

## Production gates still open

- Nested archive traversal under a shared recursion/decompression budget.
- ZIP data-descriptor, self-extracting archive and malformed/truncated-header fixtures.
- Additional metadata readers for 7z, RAR, CAB, ISO, Zstandard and package formats, using optional offline readers only.
- Adversarial archive corpus and CPU/memory/time benchmark results on large real-world archives.
