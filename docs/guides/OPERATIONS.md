# Operations Guide

How to run PDT on real repositories, including multi-gigabyte and 100 GB+ trees, and how to
read its exit codes and performance data.

## Before a large scan

1. **Check the installation:** `pdt capabilities` lists the native backends (C/SIMD, OpenCL GPU,
   C++ signatures, Rust walker), optional parsers and every analyzer. Use `--json` to keep the
   output with your scan records.
2. **Place the output outside the target.** PDT refuses an output directory inside the scanned
   tree, and one output directory takes one scan at a time: a second scan into a directory whose
   scan is still running is refused with the running process named (`.pdt-cache/scan.lock`, an
   operating-system lock released when that process ends). Use a fast local disk with free space of roughly 1–2% of the scanned size for the
   inventory database and reports, plus up to about 5 GB for the code index of a very large
   source tree (see [Code index and `pdt query`](#code-index-and-pdt-query)).
3. **Antivirus on Windows.** Microsoft Defender scans each file the first time it is opened.
   On a freshly copied corpus the inventory phase was measured 18× slower on the first run
   than on the second (23 s vs 1.3 s for 2,000 files). Consider a Defender exclusion for the
   scan target and output directories on dedicated scan hosts.
4. **Optional Tree-sitter grammars must be provisioned explicitly.** PDT never downloads
   grammars. With `tree-sitter-language-pack` 1.23+, download the grammars you need in a
   separate, deliberate step, for example
   `python -c "import tree_sitter_language_pack as t; t.download(['python', 'rust'])"`.
   The pack keeps grammars in a per-user cache. To provision them once for a shared or
   offline host, set `TREE_SITTER_LANGUAGE_PACK_CACHE_DIR` to the same directory for the
   download and for scans. Grammar names are the pack's (C# is `csharp`).
   With the pack installed, a scan lists the languages it found whose grammar is not
   provisioned in one INFO `UNKNOWN` finding ("Tree-sitter grammars not provisioned");
   without the pack, `metrics.local_parser_capabilities` records each language's state.
   With grammars provisioned, the shared code model of 16 brace languages comes from the
   syntax tree instead of the structural lexer; set `PDT_CODE_MODEL=lexical` to keep the
   lexer (for example to compare results).

## Scan modes

| Goal | Command |
|---|---|
| Full analysis | `pdt scan /src --output /reports/src` |
| Fast metadata inventory (no content reads) | `pdt scan /src --output /reports/src --inventory-only` |
| Owners, attributes and ACLs of every entry | add `--security-metadata` (Windows and Linux) |
| Continue an interrupted scan | rerun the same command with `--resume` |
| Skip content of huge files | `--skip --max-file-mb 512` (skipped files stay inventoried; `--max-file-mb` requires `--skip`) |
| Prune directories explicitly | `--exclude-dir node_modules --exclude-dir build/cache` |
| CI gate | `pdt scan . --output ../pdt --fail-on HIGH --strict --quiet --no-color` |
| Remote repository, downloaded | `pdt scan https://github.com/org/repo --output /reports/repo` |
| Remote repository, not downloaded | `pdt scan https://github.com/org/repo --no-download --output /reports/repo` |
| Online advisory lookups | add `--vuln-online` (optionally `--vuln-enrich nvd,ghsa`) |

Online scans, their budgets and credentials are described in [ONLINE_MODE.md](ONLINE_MODE.md).

`--exclude-dir` takes a directory name, which prunes every directory of that name at any depth
(`node_modules`), or one directory by its path: relative to the scan root (`build/cache`,
`./web`, `web\src`) or absolute inside it. Matching ignores case, and `.`/`..` segments are
collapsed. A value outside the root, or the root itself, is a usage error (exit 2). A value that
matches no directory prints a warning and is recorded as a scan diagnostic.

### Parallelism

`--executor auto` (the default) uses worker processes for inventories of 1,000 files or more
and threads for smaller ones. Analyzers are CPU-bound Python, so threads share one interpreter
lock and processes give real parallelism. `--jobs N` sets the worker count (`0` = automatic,
at most 8); on hosts with many cores, try `--jobs` equal to the number of physical cores.
Worker processes never write to the scan databases: they return results, and the coordinator
persists them in deterministic order. If a worker dies (a native fault or an OOM kill), the
pool is restarted and the affected batch is re-run file by file, so only the culprit file is
reported as an error.

### Resuming

Ctrl-C (or SIGINT to the PDT process) stops the scan with exit code 130. Worker processes
are terminated immediately rather than finishing their batches, and everything already
persisted is kept.

`--resume` reuses the stored inventory and findings in `OUTPUT/.pdt-cache/inventory.sqlite3`
when that inventory finished traversal for the same root. Files already hashed and analyzed are
skipped; the rest are analyzed, then the import graph, architecture layout and reports are
rebuilt. Files whose analysis failed in the interrupted run (for example a sharing violation or a
terminated worker) keep their error and are not retried; run a fresh scan to retry them. Files added or removed after the original traversal are not picked up: run a fresh
scan for a current view. When no resumable inventory exists, PDT warns and starts a fresh scan.
The inventory-shaping options must match the original command: `--inventory-only`, `--skip` with
its `--max-file-mb`, the `--exclude-dir` values (however they are spelled) and `--security-metadata`. When one differs,
`--resume` stops with exit 2 and names it; rerun with the original options, or without `--resume`.
A file that was being analyzed when the process died is analyzed again, and its code-index rows
and truncation are stored and counted once.
An inventory or fingerprint database that SQLite cannot read (a damaged file) is moved aside as
`NAME.corrupt-<timestamp>` with a warning and a scan diagnostic, and the scan rebuilds it; a
locked database is never treated as damaged.

## Ownership, attributes and security metadata

Every inventory record carries `uid` and `gid` (the POSIX owner and group; null on Windows) and
`attributes`: the Windows `FILE_ATTRIBUTE_*` names, without the `FILE_ATTRIBUTE_` prefix and in
lower case (`readonly`, `hidden`, `system`, `archive`, `reparse_point`, `offline`,
`recall_on_data_access`, ...), or the macOS file flags (`uf_immutable`, `uf_hidden`, `sf_append`,
...). `directory` and `normal` are left out, because the record type says them. A bit without a
name is kept as its hexadecimal value. Linux records no attributes: inode flags (`chattr`) are not
read. Both values come from the same no-follow metadata read as the rest of the record, so they
cost nothing extra.

`--security-metadata` adds a `security` block per entry:

| Platform | `security` |
|---|---|
| Windows | `owner_sid`, `group_sid`, and `dacl`: `protected` (inheritance from the parent is disabled), `explicit_entries` (each with `type`, `sid`, `access_mask` and `flags`) and `inherited_entry_count`. `dacl` is null when the descriptor has no DACL, which grants everyone full access. |
| Linux | `posix_acl` and, for directories, `posix_default_acl`: the entries in getfacl's text form with numeric IDs (`user:1000:r--`), or null when the entry has no such ACL. Links carry no ACL on Linux. |
| macOS | not available: the option is refused. |

Windows opens one READ_CONTROL handle per entry, with the flags that open a link or junction
itself and never recall offline data; Linux reads one extended attribute per entry and two per
directory. Expect a slower inventory on very large trees. An access mask is the Windows
`ACCESS_MASK`; for example 2032127 (`0x1F01FF`) is full control and 1179817 (`0x1200A9`) read and
execute. SIDs and numeric IDs are recorded as they are; account names are not looked up. An entry
whose metadata cannot be read gets `{"error": "..."}`, and `--strict` exits 3.
`metrics.security_metadata` counts the entries read, those with ACL entries of their own and the
read errors.

## Special entries and reparse points

FIFOs, sockets, block and character devices and entries of unknown type are recorded in
`special_entries` with their type, mode, owner and group, attributes, size and modification time,
and devices with their major and minor numbers; none of them is opened. Links are recorded, never
followed. On Windows, `reparse_tag` names each reparse point by its `IO_REPARSE_TAG_*` constant in
lower case: a junction or volume mount point is a link with `mount_point`, a symbolic link has
`symlink`; other reparse points keep their record type (`cloud` for a OneDrive or other Cloud Files
placeholder, `dedup`, `wof`, `appexeclink`, ...), and an unnamed tag is its hexadecimal value.
AF_UNIX sockets (`af_unix`) and the FIFOs and device nodes WSL creates on NTFS (`lx_fifo`,
`lx_chr`, `lx_blk`) are special entries. `metrics.reparse_tags` counts the tags.

## Symbolic link targets

The walk records each link's target text and never follows it. When the walk is complete, every
target is resolved against the inventory itself, component by component, without opening,
stat-ing or following anything, so the outcome cannot race with changes on disk: it describes
the tree as inventoried. `target_state` is one of:

| State | Meaning |
|---|---|
| `resolved` | The chain reaches an inventoried entry: `resolved_path` (relative to the root, `.` for the root) and `resolved_type` (`file`, `directory` or a special type such as `fifo`). |
| `broken` | A component does not exist, or a file is used as a directory. `resolved_path` is the path the chain names. |
| `loop` | The chain returns to a link with the same remaining path, or uses more links than the platform follows (40 on POSIX, 63 on Windows). |
| `external` | The chain leaves the scanned tree; nothing outside it is examined. In a no-download scan an absolute target or a `..` above the repository is external. |
| `unknown` | The chain passes through a pruned (`--exclude-dir`) or unreadable directory, or through a link whose target could not be read. |
| `unreadable` | The link's own target could not be read. |

`target_detail` says why a link is broken, a loop, external or unknown. Resolution follows the
platform: POSIX resolves `..` physically, after the links before it have been replaced by their
targets; Windows resolves a relative target's `..` lexically against the link's directory, and
matches names without regard to case, as macOS does on case-insensitive volumes. An absolute
target is inside the tree only along the root's real path (`/var` is not `/private/var` on
macOS). `target_scope` stays the lexical classification of the target text.
`metrics.symlink_states` counts the states.

## Inventory aggregates

`metrics.inventory_aggregates` summarizes the stored inventory after every scan, local or online,
fresh or resumed:

| Field | Content |
|---|---|
| `empty_directory_count` | Directories with no entries; pruned and unreadable directories are not counted, because they were not listed. |
| `fan_out` | Over the listed directories: the largest entry count and its path, the mean, and a histogram (`0`, `1-9`, `10-99`, `100-999`, `1000-9999`, `10000+`). |
| `hard_links` | Files that share a device and inode (a volume and file ID on Windows) with another inventoried file: their number, the groups, the distinct inodes. `supported` is false when no identity was recorded, as in a Windows `--inventory-only` scan, which opens no file. |
| `owners`, `groups`, `owner_sids` | Entries per uid and gid (POSIX), and per owner SID with `--security-metadata` (Windows); the 50 most common by name, the rest as `other`. |
| `file_timestamps` | The oldest and newest file modification time with its path, files per year (UTC), and the number modified more than a day after the scan started or before 1980, which often marks clock problems, extracted archives or rewritten timestamps. |

## File types and signatures

`file_type` says what a file's content is, read from its first 4 KiB through the same verified
descriptor as every later read:

- a format label such as `library/elf`, `document/docx` or `ml-model/safetensors` when the leading
  bytes match a catalogued signature and its header checks out (`type_source: signature`;
  `signature` repeats the label and `type_detail` says what the header states, such as
  "PE32+ DLL, x86-64, .NET assembly");
- otherwise `text`, `binary/unknown` or `empty` (`type_source: content`). Text is UTF-8 without
  NUL bytes, UTF-16 or UTF-32, or a legacy 8-bit encoding with no NUL and almost no control
  bytes. Text formats keep `text` and are named in `signature`: scripts by their `#!` line
  (`script/shell`, `script/python`, ...), PEM blocks, PostScript, RTF, SVG, Intel HEX,
  S-records and Git LFS pointers. For `binary/unknown`, `type_detail` gives the sample's
  entropy; 7.5 bits per byte or more suggests compressed or encrypted data.

The type comes from the name only when the content was not read (`type_source: name`):
`--inventory-only` scans, files that could not be opened, and no-download files that were not
fetched.

`name_type` is what the name suggests, from a separate catalog of extensions and compound
suffixes (`.tar.gz`, versioned `.so.1.2`); `source` and `text` come from the language catalog.
`mime_type` is the content's, a registered or commonly used type (`application/octet-stream`
for formats without one, `inode/x-empty` for empty files). `type_mismatch` is set when the name
and the content disagree: a signature the name does not admit (an executable named `.png`),
text under a binary format's name (an HTML error page saved as `.zip`), binary content under a
text name, or no signature where the format always has one (a `.png` without the PNG header).
A Git LFS pointer stands for its file and is counted in `metrics.git_lfs_pointer_count`
instead. `metrics.type_sources`, `metrics.mime_types` and `metrics.type_mismatches` (pairs such
as `image/png → executable/elf`) summarize the scan, and the Markdown report lists the first 20
mismatched files.

Two kinds of file need one further read, from the same descriptor: ISO 9660 and UDF images
(the volume descriptor at 32 KiB, read when the first 4 KiB are zeros or a boot sector) and OLE
compound files whose directory lies past the sample (the Word, Excel, PowerPoint, Outlook and
Windows Installer subtypes). Nothing is decompressed: a `.tar.gz` is `archive/gzip` with
`name_type` `archive/tar+gzip`, and an Office Open XML package whose part names lie past the
sample is `document/ooxml`. Formats without a magic number (ONNX and other protocol buffers, raw
disk images, DMG) are `binary/unknown`.

The C++ classifier matches the same rule table, compiled from the generated
`native/cpp/pdt_signature_rules.h`, and Python validates each candidate; a build from another
catalog is not used. An inventory classified with another catalog version is not resumed.

## Code index and `pdt query`

During analysis, PDT stores code facts (symbols, call sites, referenced names, imports and
domain facts) in `OUTPUT/.pdt-cache/inventory.sqlite3`, in the same transaction as each
file's findings, so `--resume` keeps them consistent. After analysis, the `code_index` phase
builds the call graph, module graph and domain summaries from them
(`metrics.code_index` in the JSON report). `--inventory-only` scans skip it.

Storage is bounded so a 100 GB+ repository cannot exhaust the disk or the index phase:

| Bound | Limit |
|---|---|
| Per file | 5,000 symbols, 20,000 call sites, 10,000 referenced names, 5,000 domain facts |
| Per table | 5 million symbols, 10 million call sites, 20 million references, 5 million facts |
| Call graph | 500,000 resolved edges for cycle detection |
| Modelled file size | 4 MiB (larger files are reported as `UNKNOWN`) |

A bound that is reached produces an `UNKNOWN` "Code index truncated" finding. Results that
depend on the index (call graph, unreferenced functions, test links) are then incomplete,
while per-file findings are unaffected.

Measured on 4,684 real third-party files (2,061 modelled sources, 65 MB): the index held
293,632 rows in 41.6 MB, about 20 KiB per modelled source file, and the `code_index` phase
took 1.0 s of a 30 s scan. At the table ceilings the index stops growing at roughly 5 GB, so
reserve that much on top of the inventory for very large source trees.

Look up the index of a finished scan:

```bash
pdt query /reports/src --symbol Engine.run          # definitions
pdt query /reports/src --callers parse_config       # call sites of a function
pdt query /reports/src --callees Engine.run --limit 50
pdt query /reports/src --references TOKEN_TTL --json
```

## Third-party plugins

Installed analyzer plugins run in sandboxed host processes (`--plugin-isolation sandbox`, the
default). At start-up, PDT prints one line per plugin naming the sandbox mechanisms in use and a
warning for any restriction the platform cannot enforce. `pdt capabilities` shows the same
information without running a scan.

- A plugin that hangs is stopped after `--plugin-timeout` seconds (default 60) per request. That
  file gets an `UNKNOWN` coverage finding, and the next file uses a new host.
- After 3 consecutive host failures, PDT disables the plugin for the rest of the scan and says so
  in a coverage finding. `--strict` then exits with status 3.
- `--plugin-memory-mb` (default 4096, `0` = no limit) caps each host on Linux and Windows.
- Each file a plugin analyzes is copied to `OUTPUT/.pdt-cache/plugins/`, one file at a time per
  host. Files over 1 GiB are not handed to plugins. The directory is removed when the scan ends.
- On Linux, `sandbox` mode needs Landlock (Linux 5.13+, with `landlock` in the active LSM list).
  Without it, plugins are refused with a diagnostic. `--plugin-isolation process` runs them out of
  process without OS restrictions, and `off` runs them inside PDT. Use either only for plugins you
  trust.
- On Windows, plugin hosts run in an AppContainer without capabilities, so reads, network access
  and access to other processes are denied as on Linux and macOS. The first sandboxed scan copies
  the standard-library runtime (about 40 MB) to `%LOCALAPPDATA%\ProjectDiscoveryTool\plugin-runtime`,
  and each scan stages PDT and every plugin with its declared dependencies under
  `OUTPUT/.pdt-cache/plugins/`. Starting a host takes about 1.3 s, mostly the network check; hosts
  are reused for the rest of the scan.

Isolation adds about 0.3–1.1 ms per file that a plugin handles (2,000 files, 4 workers, on Linux
and Windows).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed (findings may exist) |
| 1 | `--fail-on`: a CONFIRMED or INFERRED finding at or above the given severity |
| 2 | Invalid usage or a fatal error (message on stderr) |
| 3 | `--strict`: the scan is incomplete: a file, analyzer, inventory or traversal error, or an `UNKNOWN` coverage finding above INFO |
| 130 | Interrupted (Ctrl-C) |

`UNKNOWN` findings describe coverage gaps such as budgets, parse failures and missing parsers.
They never trigger `--fail-on`; `--strict` gates on completeness and counts every `UNKNOWN`
finding above INFO. The FAILED line names the counts behind it. Entries whose metadata
could not be read during the walk are listed as diagnostics in every report.

## Performance data

Every JSON report contains `metrics.performance`:

- `phase_seconds`: inventory, analysis, cache_maintenance, online_vulnerabilities (with
  `--vuln-online`), python_graph, architecture, code_index and shutdown (the worker pool and
  plugin hosts). Report writing comes after the JSON report is assembled, so its time is not in
  the report: the terminal summary prints it as "reporting". Before 2026-11-12 the
  architecture pass was billed to code_index and "architecture" measured the shutdown.
- `files_per_second` and `bytes_per_second` up to report writing.
- `peak_rss_bytes`: the coordinator process's peak resident memory. Worker processes are
  separate; see `tools/benchmark.py` for the largest-process figure on POSIX.

The terminal summary also prints phase timings, including report writing.
`tools/benchmark.py run` appends these figures to a JSON-lines file for comparison across runs
(see [BENCHMARKS.md](BENCHMARKS.md)).

## Local vulnerability database

```bash
pdt vuln-db import /data/osv/all.zip --db ~/.pdt/advisories.sqlite3   # OSV bundle, offline
pdt vuln-db status --db ~/.pdt/advisories.sqlite3
pdt scan /src --output /reports/src --vuln-db ~/.pdt/advisories.sqlite3
```

The database is opened read-only during scans. Refresh it by importing a newer snapshot;
`status` reports the snapshot age. Databases created by 0.1.0 are migrated to indexed lookups
the first time they are opened for import or status.
