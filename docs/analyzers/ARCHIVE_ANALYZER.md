# Archive intelligence

PDT inspects archive metadata and bounded member samples in memory. Archive members are never extracted to the target tree or report directory, and archive links are never followed.

## Supported inspection paths

| Format family | Current behavior |
|---|---|
| ZIP-based packages (ZIP, JAR, WAR, EAR, APK/AAB, IPA, WHL/EGG, NUPKG) | Central-directory preflight, bounded metadata inventory, link/permission/path checks, encrypted/duplicate/high-ratio indicators and bounded member content samples |
| TAR and compressed TAR variants | Streaming metadata walk, symlink/hardlink/special-entry checks, mode-bit checks and bounded member content samples |
| Standalone GZIP/BZIP2/XZ, Zstandard, 7z, RAR, CAB, ISO, DEB and RPM | Recognition/detection only unless the file is a TAR container readable by the standard-library TAR backend; no external extractor is invoked |

## Resource limits

The current implementation has hard safety limits:

- ZIP central-directory preflight: 200,000 entries and 64 MiB of declared central-directory bytes. If a valid bounded index cannot be established from the EOCD/ZIP64 trailer, the analyzer returns UNKNOWN without materializing ZipFile.infolist().
- Member sample: 1 MiB maximum per regular member.
- Total member sample: 32 MiB maximum per archive.
- Compressed TAR (gzip, bzip2, xz): decompressed through a budgeted reader capped at 4 GiB of output. The reader also enforces the wall-time budget inside each read.
- Wall time: 8 seconds per archive for metadata traversal and member sampling.
- Evidence: at most 100 source/member references per finding.

When a count, byte or time budget is reached, the analyzer records an explicit UNKNOWN finding. A partial archive result must not be interpreted as a complete clean scan. These limits are currently code constants, not yet exposed as CLI configuration. Nested archive recursion is not implemented, and ZIP archives have no total-uncompressed-size budget (only per-member and per-archive sample caps).

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

- CLI-configurable archive byte, entry, nesting, total-uncompressed-byte, compression-ratio, sample and wall-time policies.
- Nested archive traversal under a shared recursion/decompression budget.
- ZIP data-descriptor, self-extracting archive and malformed/truncated-header fixtures.
- Additional metadata readers for 7z, RAR, CAB, ISO, Zstandard and package formats, using optional offline readers only.
- Adversarial archive corpus and CPU/memory/time benchmark results on large real-world archives.
