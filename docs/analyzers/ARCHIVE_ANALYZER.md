# Archive intelligence

PDT inspects archive metadata and bounded member samples in memory. Archive members are never extracted to the target tree or report directory, and archive links are never followed.

## Supported inspection paths

| Format family | Current behavior |
|---|---|
| ZIP-based packages (ZIP, JAR, WAR, EAR, APK/AAB, IPA, WHL/EGG, NUPKG) | Central-directory preflight, bounded metadata inventory, link/permission/path checks, encrypted/duplicate/high-ratio indicators and bounded member content samples |
| TAR and compressed TAR (gzip, bzip2, xz, LZMA, Zstandard) | Streaming metadata walk, symlink/hardlink/special-entry checks, mode-bit checks and bounded member content samples |
| ar: DEB/UDEB packages, static libraries (`.a`, `.lib`) | Member headers (common, GNU long-name table and thin archives, BSD `#1/` names; the symbol table is not a member); a DEB's package fields from its control file; members sampled in place; a DEB's `control.tar.*` and `data.tar.*` inspected as nested archives in place |
| CAB (Microsoft Cabinet) | The file table: names, sizes and DOS times, and the folders' compression (MSZIP, LZX, Quantum, none); member data is not decompressed, so content is not sampled |
| RPM | The lead and header: package fields and the file list (paths, sizes, modes, times, owners, groups, symlink targets, hardlinks by shared inode); the payload is not decompressed |
| ISO 9660 images (any name: `.iso`, `.img`, ...) | The directory tree: the Rock Ridge tree (POSIX names, modes, owners, symlinks, relocated deep directories) when the image has one, else the Joliet tree (Unicode names), else the primary tree; multi-extent files; El Torito boot records and a UDF file system are detected and named. Files are stored as is, so they are sampled in place, and archives on the image (the packages of an install image) are inspected as nested archives in place. A UDF-only image is `unsupported` |
| Single compressed files: gzip, bzip2, xz, LZMA (`.lzma`), Zstandard | One member: the header's original name and time (gzip), the declared size (an xz index, Zstandard frame headers and block headers, an LZMA header, a gzip trailer when unambiguous) and a bounded decompressed sample. Content that is a TAR stream (a `.gz` without `.tar` in its name) is inspected as TAR; a member named like an archive (`app.zip.gz`) as a nested archive |
| 7z | The header, decompressed when 7-Zip packed it (LZMA, LZMA2, Deflate, BZip2 or Copy, under the index budget): names, sizes (substreams of solid folders included), times, Windows and Unix attributes, the folders' coders (`methods`) and which are encrypted (AES). Stored (Copy) members are sampled in place. An encrypted header (`-mhe`) lists nothing: the archive is `encrypted` |
| RAR 4 and RAR 5 | The block headers, each checked against its CRC: names (RAR 4's compressed Unicode names too), sizes, times, attributes or Unix modes, encryption, RAR 5 symlinks, hard links and owners, members spanning volumes. Stored members are sampled in place. Encrypted headers (`-hp`) list nothing: the archive is `encrypted` |
| Language packages: wheels, eggs and sdists, npm tarballs, gems, crates, NuGet packages, Maven JARs, conda packages, Go module zips, Composer packages, VS Code extensions | Read as the ZIP or TAR archives they are, and their manifest named: see *Language packages* below |
| cpio, xar, WIM, lz4, lzip and other recognized containers | Recognition only, recorded `unsupported`; no external extractor is invoked |

Every reader is built in (the standard library), except Zstandard before Python 3.14: Python 3.14 has `compression.zstd`, and earlier versions need the optional `zstandard` package (`python -m pip install -e ".[archives]"`, also part of `[all]`). Without either, a `.tar.zst` (or a DEB's `data.tar.zst`) is recorded `unsupported` with an `unsupported_reason` (a single `.zst` file keeps its frame metadata), and `pdt capabilities` shows which decompressor a host has. Both decompressors refuse frames whose window exceeds libzstd's default limit (128 MiB).

The reader follows the content's signature, then the name: a name decides unless the content is another archive format (a `.zip` that holds a RAR archive is not read as ZIP), and compressed content is a TAR stream under a TAR name (`.tgz`, `.tar.zst`, `.tlz`, `.ipk`) and otherwise a single compressed file, whose content may still turn out to be TAR. Content whose start is no archive at all (a `.jar` behind a launcher script, a self-extracting `.zip`) is read by its name.

## Inspection records

Every archive the analyzer inspects gets a record in the JSON report's top-level `archives` list, and every member it indexes a record in `archive_members` (both stored in the scan's SQLite inventory and streamed).

An archive's `state` is how far its inspection got, and `states` lists everything that applies:

| State | Meaning |
|---|---|
| `detected` | Recognized as an archive (always present) |
| `unsupported` | No built-in metadata reader for the format (UDF, cpio, xar, ...), or no decompressor for it in this installation (`unsupported_reason` says which) |
| `index-read` | The member index (ZIP central directory, TAR or ar headers, cabinet file table, RPM header, ISO 9660 directories, a compressed file's header) was read, at least in part |
| `metadata-complete` | Every member's metadata was read |
| `sample-read` | Member content was sampled in memory |
| `sample-truncated` | Some members' content was not read in full (a sample budget, an unreadable member) |
| `encrypted` | At least one member is encrypted, so its content was not sampled; as the primary state, the index itself is encrypted (7z `-mhe`, RAR `-hp`) and no member could be listed |
| `malformed` | The archive could not be read; `error` says why |
| `budget-stopped` | A limit stopped the metadata traversal: the entry, index-byte, wall-time or TAR decompression budget, or the engine's per-call budgets (`analyzer_time`, `analyzer_memory`, ...) |

The primary `state` is the first of `malformed`, `unsupported`, `encrypted` (an encrypted index), `budget-stopped`, `metadata-complete`, `index-read`, `detected` that applies. Each record also holds `format` (`zip`, `tar`, `tar+gzip`, `tar+bzip2`, `tar+xz`, `tar+lzma`, `tar+zstd`, `ar`, `deb`, `cab`, `rpm`, `iso`, `udf`, `7z`, `rar`, `gzip`, `bzip2`, `xz`, `lzma`, `zstd`, or the detected type), `archive_bytes`, `compressed_bytes` (for a cabinet or a compressed file the file, for an RPM its payload), `members_declared` (the count the ZIP central directory, the cabinet, the RPM header or the 7z header declares; for TAR and ar, the count once every header was read), `members_indexed`, `member_coverage_pct`, `regular_members`, `member_bytes` (their uncompressed size), `members_sampled`, `members_fully_sampled`, `members_not_fully_sampled`, `member_bytes_sampled`, `content_coverage_pct` (the share of regular members' bytes sampled; none when a member's size is unknown, and `members_unsized` counts those), `encrypted_members`, `member_records` and `limits`: every limit that prevented deeper inspection, with its `value` and, where known, what was `used` or how many `members` it affected. Readers add what their format says: `deb` (`format_version`, `package`, `source`, `version`, `architecture`, `maintainer`, `installed_size`, `depends`, `pre_depends`, `section`, `priority`, `homepage`, `description` (the synopsis), or a `control_error`), `ar` (`variant`: `common`, `gnu` or `bsd`; `thin`; `symbol_table`), `cab` (`version`, `folders`, `compression`, `set_id`, `cabinet_index`, `cabinet_bytes`, `spans_cabinets`), `rpm` (`name`, `version`, `release`, `epoch`, `summary`, `license`, `url`, `arch`, `source_rpm`, `payload_format`, `payload_compressor`, `source_package`, `payload_bytes`), `iso` (`volume_id`, `system_id`, `publisher`, `preparer`, `application`, `created`, `modified`, `block_size`, `volume_bytes`, `tree`: `rock-ridge`, `joliet` or `primary`; `extensions`: `rock-ridge`, `joliet`, `el-torito`, `udf`; `structure_issues`; `missing_bytes` for a truncated image), `stream` for a compressed file (gzip: `original_name`, `mtime`, `system`, `has_comment`, `trailer_size`; xz: `streams`, `blocks`; Zstandard: `frames`, `skippable_frames`, `checksummed_frames`, `window_bytes`, `dictionaries`; LZMA: `dictionary_bytes`; bzip2: `block_size_kb`; each with the declared `content_bytes`, and `unreadable` when no decompressor can read it), `7z` (`version`, `encoded_header`, `headers_encrypted`, `folders`, `methods`, `solid`, `packed_bytes`), `rar` (`version`, `headers_encrypted`, `volume`, `solid`, `locked`, `recovery_record`, and `comment` for RAR 4), `package` for a language package (see below), for cabinets, RPMs and 7z and RAR archives the archive's `compression_ratio`, and for an ISO image its `expansion_ratio` (its files' bytes over the image's).

A member record holds the `archive`, its `ordinal` in the archive, `path`, `type` (`file`, `directory`, `symlink`, `hardlink`, `special`), `size`, `compressed_size` (ZIP, RAR, a 7z folder of one member), `mode` (permission bits), `mtime`, `link_target` (TAR, ZIP, RPM, Rock Ridge and RAR 5 symlinks; an RPM hardlink names the file it shares an inode with, a RAR 5 hard link its target), `uid` and `gid` (TAR, ar, Rock Ridge, RAR 5), `owner` and `group` (TAR, RPM, RAR 5) and `flags`: `unsafe-path` (absolute, drive-prefixed or parent-traversal path or link target; an RPM installs its absolute paths from `/` and a DEB's tarballs install links as links, so there only a parent traversal or drive prefix in a path counts), `setuid`, `setgid`, `world-writable` (never for a symlink, whose own mode bits are unused), `encrypted` (ZIP, 7z, RAR), `high-ratio` (over 1000:1 or a zero compressed size; for 7z and RAR only outside solid archives, whose members are compressed together), `continued` and `continues` (a RAR member that spans volumes), `duplicate` (the name occurs more than once), `nested-archive`, `out-of-bounds` (ZIP and ISO members whose data runs past the end of the file) and, for ZIP members, `header-mismatch`, `descriptor-mismatch` and `overlapping` (see below). ZIP and cabinet times are the members' DOS timestamps, local time without a zone at two-second resolution; TAR, ar, RPM, ISO, 7z, RAR 5 and gzip times are UTC; RAR 4 times are DOS times like ZIP's. Names that are not valid UTF-8 keep backslash escapes.

An archive keeps up to 200,000 member records (its entry limit) and a scan up to 1,000,000; past the scan's ceiling the archives keep their summaries, and `metrics.archives` reports the records dropped. `metrics.archives` also counts archives by state and format, sums the members and bytes with their coverage, and counts the archives each limit stopped. The Markdown report has an *Archives* section with the archives not fully inspected first, the HTML report an *Archives by inspection state* card, and the terminal summary an *Archives* row.

## Resource limits

These are the defaults; `pdt scan --archive-limit NAME=VALUE` overrides any of them for a scan (`entries`, `index_mb`, `member_sample_mb`, `sample_mb`, `wall_seconds`, `decompressed_mb`, `uncompressed_mb`, `ratio`; byte limits in MiB). The overrides travel with the budget policy to every worker process, and `metrics.analysis_budgets` reports them (`analyzer_limit_overrides`) with the values in force (`analyzer_limits`):

- Index: 200,000 entries (`entries`) for every format, and 64 MiB (`index_mb`) of ZIP central directory, ar long-name table, cabinet file table, RPM header structure, ISO 9660 directories (with Rock Ridge continuation areas), 7z header (packed and unpacked) or xz indexes; an index over it is not read and the archive is `budget-stopped` with an UNKNOWN finding. A DEB's control tarball is read for its fields up to 4 MiB, decompressing to at most 16 MiB.
- ZIP central-directory preflight: 200,000 entries and 64 MiB of declared central-directory bytes. The ZIP64 record is read the way `zipfile` reads it (whenever its locator precedes the EOCD, from just before the locator), so a classic EOCD that understates the entry count cannot slip past. If a valid bounded index cannot be established from the EOCD/ZIP64 trailer, the analyzer returns UNKNOWN without materializing ZipFile.infolist().
- Member sample: 1 MiB maximum per regular member.
- Total member sample: 32 MiB maximum per archive.
- Compressed TAR (gzip, bzip2, xz, LZMA, Zstandard): decompressed through a budgeted reader capped at 4 GiB of output. A single compressed file is decompressed only for its sample (and, for a nested archive in it, up to `nested_mb`); Zstandard frames that need a dictionary or a window over 128 MiB are not decompressed. The reader also enforces the wall-time budget inside each read.
- Wall time: 8 seconds per archive for metadata traversal and member sampling.
- Declared uncompressed size: 16 GiB per archive. Members declaring more in total get an `INFERRED` HIGH "Archive declares more uncompressed data than its budget" finding (a possible archive bomb) and the archive record the `uncompressed_bytes` limit; traversal continues, since nothing is decompressed past the samples.
- Compression ratio: members compressed more than 1,000:1, or to zero bytes, are flagged `high-ratio`; a cabinet or RPM, whose members are compressed together, gets a HIGH "High compression-ratio archive" finding when its members declare more than 1,000 times its compressed bytes, and an ISO image whose files declare more than 1,000 times its bytes (files that share their data) a HIGH finding too.
- Nested archives: one level (`nested_depth`) and 64 MiB of nested archives in memory per archive (`nested_mb`).
- Evidence: at most 100 source/member references per finding.

When a count, byte or time budget is reached, the analyzer records an explicit UNKNOWN finding. A partial archive result must not be interpreted as a complete clean scan.

## Nested archives

A member named like an archive these readers inspect (`.zip`, `.jar`, `.war`, `.ear`, `.apk`, `.aab`, `.ipa`, `.whl`, `.egg`, `.nupkg`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, `.tar.lzma`, `.tlz`, `.deb`, `.udeb`, `.rpm`, `.cab`, `.iso`, `.7z`, `.rar`, and single compressed files: `.gz`, `.bz2`, `.xz`, `.lzma`, `.zst`) is flagged `nested-archive` and, within the budgets, read whole into memory and inspected the same way: it gets its own archive record, member records and findings, named `outer.war::WEB-INF/lib/inner.jar`, and shares the top-level archive's wall-time budget. Nesting stops at `nested_depth` levels (1 by default) and when the nested archives would exceed `nested_mb` (64 MiB per top-level archive in total); the archive that holds a member left uninspected records the `nested_depth` or `nested_bytes` limit, and the member is sampled like any other file. Nothing is written to disk.

ar archives and ISO images store their members uncompressed, and 7z and RAR archives may (Copy and store methods), so an archive inside one (a DEB's `control.tar.*` and `data.tar.*`, the packages on an install image) is read in place from the file, without buffering, and no `nested_mb` budget applies; the depth limit does. A DEB's tarballs are package payloads: `dpkg` installs their links as links, wherever they point, so their link targets are not checked for traversal (their member paths are).

## Language packages

A ZIP or TAR archive that is a language package names it from its own manifest member, read in memory up to 1 MiB (at most 16 per archive): its archive record gets a `package` object with the `ecosystem`, the `manifest` member, the `name` and `version`, `dependencies` (up to 100 names) and `dependency_count`, and what the manifest says beside (`summary`, `license`, `requires_python`, `build`, `main_class`, `extensions`), and the inventory finding's evidence starts with `package: NAME VERSION (ECOSYSTEM)`.

| Ecosystem | Package | Manifest |
|---|---|---|
| `pypi` | wheel, egg, sdist | `*.dist-info/METADATA`, `EGG-INFO/PKG-INFO`, `NAME-VERSION/PKG-INFO` |
| `npm` | npm tarball (`.tgz`) | `package/package.json` |
| `rubygems` | gem | `metadata.gz` (the gemspec, read line by line: no YAML is loaded) |
| `crates.io` | crate | `NAME-VERSION/Cargo.toml` (and `build.rs`: `build_script`) |
| `nuget` | NuGet package | `*.nuspec` |
| `maven` | JAR, WAR, EAR | `META-INF/maven/GROUP/ARTIFACT/pom.properties`, else `META-INF/MANIFEST.MF` |
| `conda` | `.conda`, conda `.tar.bz2` | `info/index.json` (in a `.conda`, inside its `info-*.tar.zst`) |
| `go` | module zip | `MODULE@VERSION/go.mod` |
| `packagist` | Composer package | `composer.json` |
| `vscode`, `visualstudio` | VS Code extension, VSIX | `extension/package.json`, `extension.vsixmanifest` |

Manifests are parsed, never evaluated: JSON, TOML (`tomllib`), RFC 822 headers and key-value text, and XML only without a document type, so no entity is defined or expanded. A ZIP's manifests are read before its members are sampled, so a package is named even when the wall-time budget ends the sampling.

A package that runs code when it is installed gets an INFERRED MEDIUM "Package runs code when installed" finding (supply chain), and the record's `install_code` lists it: npm `preinstall`, `install` and `postinstall` scripts (also `install_scripts`), a wheel's `.pth` files whose lines start with `import` (processed at every interpreter start once installed) and NuGet `tools/install.ps1` and `tools/init.ps1`. A crate's build script and a gem's native extensions are recorded (`build_script`, `extensions`), not reported: they run when the package is built.

## Evidence and checks

The current metadata/content checks include:

- Absolute paths, drive-prefixed names and parent-traversal member paths.
- ZIP and Rock Ridge symlink entries and TAR symlink/hardlink targets; links are reported but not followed.
- A gzip header's original name that escapes (`gunzip -N` restores it), and RAR symlink and hard-link targets that escape.
- Encrypted indexes (7z, RAR: a MEDIUM finding, since nothing inside can be inspected), encrypted 7z folders and RAR members, and 7z and RAR header CRCs that do not match (`malformed`).
- TAR and RPM device/FIFO/socket-like special entries, and RPM hardlinks (files that share an inode).
- ZIP/TAR setuid, setgid and world-writable permission bits.
- Duplicate ZIP member names, encrypted ZIP entries and ZIP compression ratios above 1000:1.
- ZIP structure: each member's local header is read and compared with the central directory (name, compression method, CRC and sizes), and so is its data descriptor (bit 3; with or without the optional signature, 4-byte or ZIP64 8-byte sizes). A disagreement (`header-mismatch`, `descriptor-mismatch`) means tools that read local headers see another archive than tools that read the directory: a MEDIUM finding. Members whose data overlaps another's (`overlapping`), the construction of non-recursive zip bombs, are a HIGH finding and are not opened. Members whose data runs past the central directory or the end of the file (`out-of-bounds`) mark the archive `malformed`, and an end-of-directory entry count that disagrees with the directory (a truncated or rewritten directory) is reported, with `declared_entries` in the archive record and the coverage computed against the larger count. The record's `structure_issues` counts each kind.
- ISO images: directory records that loop back to a directory already listed (listed once; a MEDIUM finding), both-endian fields whose halves disagree (systems that read the other half see other files: MEDIUM), files that share their data far past the image's size, files or directories past the end of a truncated image (`malformed`), and a UDF file system that was not read (a LOW finding: hybrid images may list only a few files in their ISO 9660 tree).
- ZIP and TAR member names that collide after case folding and Unicode NFC normalization (they overwrite each other when extracted on case-insensitive or normalizing filesystems).
- TAR traversal continues past oversized members and exhausted sample budgets, so every header is examined.
- Bounded in-memory checks for credential-like assignments, private-key markers, cloud access-key identifiers and email-shaped values. Matched values are discarded; evidence contains archive/member paths and line numbers, not matched values.

The member content scan is a conservative indicator scan, not malware detection, complete DLP, semantic analysis or a guarantee that encrypted/unsupported/truncated members are clean.

## Production gates still open

- Nested archive traversal under a shared recursion/decompression budget.
- Self-extracting archive fixtures (prepended data shifts every offset; `zipfile` adjusts them, untested here).
- A metadata reader for UDF file systems.
- Adversarial archive corpus and CPU/memory/time benchmark results on large real-world archives.
