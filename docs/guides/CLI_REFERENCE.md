# CLI Reference

Every `pdt` command and option, with examples. `pdt --help` lists the commands and `pdt COMMAND --help` prints a command's options; `tests/test_documentation.py` fails when an option is missing from this page.

| Command | Purpose |
|---|---|
| [`pdt scan`](#pdt-scan) | Inventory and analyze a local directory or a remote repository, and write reports |
| [`pdt query`](#pdt-query) | Look up symbols, callers, callees and references in a scan's code index |
| [`pdt compare`](#pdt-compare) | Compare two or more scan reports |
| [`pdt capabilities`](#pdt-capabilities) | Show the native backends, optional integrations and analyzers on this host |
| [`pdt plugin-check`](#pdt-plugin-check) | Test a third-party analyzer plugin the way scans load it |
| [`pdt catalog-add`](#pdt-catalog-add), [`catalog-list`](#pdt-catalog-list), [`catalog-remove`](#pdt-catalog-remove), [`catalog-compare`](#pdt-catalog-compare) | Keep a local catalog of project reports |
| [`pdt vuln-db`](#pdt-vuln-db) | Import and inspect the local OSV advisory database |

`pdt --version` prints the version.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (a scan may still have findings) |
| `1` | `scan --fail-on`: a CONFIRMED or INFERRED finding at or above the severity; `plugin-check`: the plugin failed a check; `vuln-db import`: some records were skipped |
| `2` | Invalid usage or a fatal error, with the message on stderr |
| `3` | `scan --strict`: the scan is incomplete; a `--url` batch in which a repository could not be fetched; `query` on a scan without a code index |
| `130` | Interrupted (Ctrl-C) |

## `pdt scan`

```text
pdt scan PATH_OR_URL [options]
pdt scan --url FILE [options]
```

Inventories every file, directory, link and special entry, runs the analyzers on file contents, builds the code index and writes the reports. A local path is scanned in place, read-only. A repository URL is either checked out read-only into a temporary directory or, with `--no-download`, read through the provider's API in memory.

```bash
pdt scan ./service                                  # reports in ./service-pdt-report
pdt scan ./service --output ../reports/service      # reports where you choose
pdt scan https://github.com/owner/repository        # a remote repository
```

### Target and reports

| Option | Default | Description |
|---|---|---|
| `PATH_OR_URL` | — | A local project directory, or a repository URL (`https://`, `ssh://`, `git@host:path`, or a `hg+`, `svn+`, `bzr+`, `darcs+`, `jj+`, `pijul+`, `cvs+`, `p4+` or `fossil+` prefix). Not together with `--url`. |
| `--url FILE` | — | A UTF-8 file with one repository per line: `URL [ref=NAME] [vcs=BACKEND]`, then an optional `# comment`. Blank lines and lines starting with `#` are skipped and duplicates removed. Each repository gets its own report directory. |
| `--output DIR` | `NAME-pdt-report` beside a local project; `./NAME-pdt-report` for a URL; `./pdt-remote-reports` for a batch | The report directory. It must be outside the scanned project, and only one scan may use it at a time. |
| `--format FORMATS` | `json,markdown,html` | Comma-separated report formats. |

A scan writes `discovery-report.json`, `discovery-report.md` and `discovery-report.html` (for the formats asked for) and keeps its working state in `OUTPUT/.pdt-cache/`: the inventory and code index (`inventory.sqlite3`), the fingerprint cache and the scan lock. A batch adds `batch-summary.json` and `batch-summary.md` with the status, revision, exit code and error of every repository.

```bash
pdt scan ./service --format json                    # JSON only, for automation
pdt scan --url repositories.txt --output ./remote-reports
```

### Content, traversal and resume

| Option | Default | Description |
|---|---|---|
| `--inventory-only` | off | Inventory files, directories and links without opening any file: no hashing, signatures or content analyzers. File types then come from names alone. |
| `--development-trees MODE` | `deep` | What happens inside the development trees no option pruned (confirmed by their contents or named distinctively): `deep` inventories and analyzes them; `inventory` records every entry but reads no file content; `directory-only` records their directories, with files, links and special entries counted in the directory totals but not recorded. A common name nothing confirmed (`build`, `vendor`) never starts such a tree. |
| `--exclude-profile NAME` | none | Prune the development trees of a preset: `vcs`, `dependencies`, `build` (build output and generated code), `caches`, `ide`, `test-output`, `fuzzing`, `models` or `all`. Only trees confirmed by their contents or named distinctively (`node_modules`, `__pycache__`) are pruned, never a common name nothing confirmed (a `build/` that may be source). Each pruned directory stays in the inventory with a reason naming the preset and the marker. Repeatable, or comma-separated. |
| `--exclude-dir NAME` | none | Prune a directory, which stays in the inventory with its prune reason. A bare name (`node_modules`) prunes that name at any depth; a path relative to the scan root (`build/cache`, `./web`, `web\src`) or an absolute path inside it prunes one directory. Matching ignores case. A value outside the root, or the root itself, is a usage error; one that matches nothing prints a warning. Repeat the option for several directories. |
| `--skip` | off | Skip content analysis for files larger than `--max-file-mb`; they stay in the inventory with an explicit skip reason. Without `--skip`, no file is skipped by size. |
| `--max-file-mb MB` | `128` | The `--skip` threshold, at least 1. Requires `--skip`. |
| `--security-metadata` | off | Also record each entry's security metadata in its `security` field. Windows: the owner and group SIDs and the DACL (whether inheritance is disabled, every explicit entry with its type, SID, access mask and flags, and how many entries are inherited), read through one READ_CONTROL handle per entry. Linux: the POSIX access ACL and, for directories, the default ACL, in getfacl's text form with numeric IDs. Links are never followed and no file content is read. An entry whose metadata cannot be read gets `{"error": ...}` and counts for `--strict`. Not available on macOS or with `--no-download`. Owner and group IDs and platform attributes are recorded without this option. |
| `--resume` | off | Continue an interrupted scan of the same root into the same `--output`: the stored inventory and findings are reused and only files not yet analyzed are analyzed. The inventory options (`--inventory-only`, `--skip`/`--max-file-mb`, `--exclude-dir`, `--exclude-profile`, `--development-trees`, `--security-metadata`) must match the original command, or the scan stops with exit 2. Files that failed are not retried, and files added after the original walk are not picked up; run a fresh scan for both. Local roots only. |

```bash
pdt scan ./monorepo --inventory-only                          # a fast metadata census
pdt scan ./monorepo --exclude-dir node_modules --exclude-dir ./build/cache
pdt scan ./monorepo --exclude-profile dependencies,caches
pdt scan ./monorepo --development-trees directory-only
pdt scan ./data-lake --skip --max-file-mb 512                 # leave very large files unread
pdt scan ./share --inventory-only --security-metadata         # owners, attributes and ACLs of every entry
pdt scan ./monorepo --output ../reports/mono --resume         # after Ctrl-C or a crash
```

### Execution

| Option | Default | Description |
|---|---|---|
| `--jobs N` | `0` | Analysis workers: `0` picks a bounded number from the hardware (at most 8), or 1 to 64. |
| `--executor {auto,process,thread}` | `auto` | `process` runs analyzers in worker processes (real parallelism), `thread` in threads; `auto` uses processes for inventories of 1,000 files or more. |
| `--gpu` | off | Count the bytes of large in-memory buffers on an OpenCL GPU. Off by default, and the OpenCL runtime is then not loaded: on the hardware measured so far, copying a buffer to the device took longer than counting it on the CPU. `python tools/gpu_benchmark.py` measures this machine. |
| `--gpu-min-mb MB` | `8` | With `--gpu`, the smallest buffer counted on the GPU (at least 1). |

```bash
pdt scan ./service --jobs 16 --executor process
```

### CI gates and console

| Option | Default | Description |
|---|---|---|
| `--fail-on SEVERITY` | none | Exit 1 when a CONFIRMED or INFERRED finding is at or above `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` (case-insensitive). `UNKNOWN` findings never trigger it. |
| `--strict` | off | Exit 3 when the scan is incomplete: a file, analyzer, inventory or traversal error, or an `UNKNOWN` coverage finding above INFO (a budget, a parse failure, unread content). |
| `--quiet` | off | Print only errors. The reason for a non-zero exit is still printed. |
| `--no-color` | off | Plain output without colors (`NO_COLOR` is honored too). |

```bash
pdt scan . --output ../pdt --fail-on HIGH --strict --quiet --no-color
```

### Vulnerability intelligence

| Option | Default | Description |
|---|---|---|
| `--vuln-db FILE` | none | Match lockfile packages against a local OSV snapshot imported with `pdt vuln-db import`. No network access. The file must be outside the scanned project. |
| `--vuln-online` | off | Look lockfile packages up in OSV.dev. Only the ecosystem, package name and version are sent, never file contents or paths. Failures are `UNKNOWN` coverage findings. |
| `--vuln-enrich SOURCES` | none | With `--vuln-online`: add CVSS and CWE details from `nvd` (NVD CVE API 2.0) and/or `ghsa` (GitHub Advisory Database), comma-separated. Keys come from `NVD_API_KEY` and `GITHUB_TOKEN`. |
| `--vuln-cache FILE` | `~/.pdt/online-vulnerability-cache.sqlite3` | With `--vuln-online`: the response cache, outside the scanned project. |
| `--vuln-cache-ttl HOURS` | `24` | With `--vuln-online`: how long cached answers are reused, 0 to 87,600; `0` disables the cache. |
| `--network-timeout SECONDS` | `30` | Per-request timeout for online services and provider APIs, above 0 and at most 600. Needs `--vuln-online` or `--no-download`. |
| `--ca-bundle FILE` | system store | A PEM bundle for HTTPS to online services, for private or intercepting certificate authorities. Certificate verification is never disabled. Needs `--vuln-online` or `--no-download`. |

```bash
pdt vuln-db import ./osv-snapshot --db ~/.pdt/advisories.sqlite3
pdt scan ./service --vuln-db ~/.pdt/advisories.sqlite3
pdt scan ./service --vuln-online --vuln-enrich nvd,ghsa
```

### Remote repositories

These options apply to repository URLs and `--url` batches; with a local path they are usage errors.

| Option | Default | Description |
|---|---|---|
| `--vcs BACKEND` | `auto` | `git`, `hg`, `svn`, `bzr`/`bazaar`, `darcs`, `jj`, `pijul`, `cvs`, `p4`/`perforce` or `fossil`. `auto` uses the URL's VCS prefix and otherwise Git. The client must be installed (`pdt capabilities` lists them). |
| `--ref REF` | the default branch | A branch, tag or revision; Git also takes a full commit ID and Subversion a revision number. |
| `--remote-timeout SECONDS` | `600` | Timeout of each clone or checkout operation, 1 to 86,400. |
| `--remote-workdir DIR` | the system temporary directory | Where temporary checkouts are made; each is deleted when its scan ends. |
| `--remote-max-gb GIB` | `64` | Stop materializing a repository after this much file content (above 0, at most 1,048,576); the rest is an `UNKNOWN` coverage gap. |
| `--allow-insecure-transport` | off | Allow plain-text transports (`git://`, `http://`, `svn://`, `bzr://`, CVS pserver, Perforce `tcp`). Reports then flag the scan. |

A checkout is read-only and non-interactive: no hooks or filters run, submodules, externals and Git LFS objects are not fetched, and a missing credential fails at once instead of prompting. Credentials embedded in URLs are refused; use an SSH agent or your client's credential configuration.

```bash
pdt scan https://github.com/owner/repository --ref v2.1.0
pdt scan hg+https://hg.example.net/team/project
pdt scan svn+https://svn.example.net/repos/project/trunk --ref 9120
pdt scan --url repositories.txt --vcs auto --remote-timeout 900 --remote-workdir /scratch
```

A batch file:

```text
# Git hosting providers
https://github.com/owner/project-a
https://github.com/owner/project-a ref=v1.4.0     # a second target: the release tag
ssh://git@bitbucket.org/workspace/project-b.git
hg+https://hg.example.net/team/project-c
svn+https://svn.example.net/repos/project-d/trunk ref=9120
```

### Remote repositories without downloading

`--no-download` reads one commit through the provider's REST API and analyzes the files in memory; nothing is cloned or written to disk. It supports GitHub (and GitHub Enterprise Server), GitLab (and self-managed), Bitbucket (Cloud and Data Center/Server) and Gitea/Forgejo. `--resume`, `--remote-workdir`, `--remote-max-gb` and `--allow-insecure-transport` do not apply, and `--vcs` must be `auto` or `git`.

| Option | Default | Description |
|---|---|---|
| `--no-download` | off | Read through the provider API in memory instead of checking out. |
| `--api-provider PROVIDER` | detected from the host | `github`, `gitlab`, `bitbucket` (Cloud), `bitbucket-server` (Data Center/Server) or `gitea`, for hosts PDT cannot recognize. |
| `--api-url URL` | the provider's standard API | The API base for one URL (GitHub Enterprise `https://host/api/v3`, GitLab `https://host/api/v4`, Bitbucket Data Center `https://host/rest/api/1.0`, Gitea `https://host/api/v1`). For a batch, set `PDT_API_URL_<HOST>` per host. HTTPS only, except for loopback hosts. |
| `--api-max-files N` | `20,000` | Fetch at most N file contents (1 to 10,000,000). |
| `--api-max-mb MB` | `512` | Fetch at most this much content (1 to 1,048,576). |
| `--api-max-file-mb MB` | `16` | Skip larger files (1 to 102,400). |
| `--api-max-requests N` | `15,000` | API request budget per repository (1 to 10,000,000). |
| `--api-workers N` | `8` | Parallel content requests (1 to 32). |
| `--use-credential-helper` | off | Ask your Git credential helper for the host's token, non-interactively, when no token variable is set. |
| `--no-download-plugins` | off | Also run sandboxed third-party plugins. Each file a plugin analyzes is copied into the plugin host's private folder under `OUTPUT/.pdt-cache/plugins` for that call and deleted after it, and reports record the copies. Needs `--plugin-isolation sandbox` or `process`. |

Tokens are read only from variables bound to their host: `PDT_API_TOKEN_<HOST>` (the host upper-cased, other characters replaced by `_`) for any host, or the provider's standard variables for the public hosts (see [Environment variables](#environment-variables)). They are never logged or written to reports. Files that a budget, a failed request or the rate limit left unfetched stay in the inventory as `UNKNOWN` coverage gaps.

```bash
pdt scan https://github.com/owner/repository --no-download
pdt scan https://gitlab.example.com/group/project --no-download --api-url https://gitlab.example.com/api/v4
pdt scan https://bitbucket.example.com/scm/PROJ/repo.git --no-download --api-max-mb 256
pdt scan --url repositories.txt --no-download --vuln-online --output ./api-reports
```

### Analyzer budgets

| Option | Default | Description |
|---|---|---|
| `--analyzer-timeout SECONDS` | `120` | Time each analyzer may spend on one file. A call that runs longer is stopped, its findings and code facts for the file are discarded, and an `UNKNOWN` coverage finding names the analyzer, the file and the budget. `0` disables it. |
| `--analyzer-memory-mb MB` | `2048` | How far the process's resident memory may grow during one analyzer call on one file, sampled every 50 ms on Linux, Windows and macOS (elsewhere only the time budget applies). A call past it is stopped the same way. `0` disables it. |
| `--analyzer-cpu-seconds SECONDS` | `0` | CPU time each analyzer call may use on one file: the analyzing thread's own CPU time, so waiting for the GIL or I/O does not count (Linux and Windows; macOS has no per-thread CPU clock). A call past it is stopped the same way. `0`, the default, sets no limit. |
| `--analyzer-read-mb MB` | `0` | How many bytes each analyzer call may read from one file through the verified readers (an I/O budget). A call that reads more is stopped the same way. `0`, the default, sets no limit. |
| `--domain-budget DOMAIN:timeout=S,memory=MB,read=MB,cpu=S` | none | Override any of the budgets for the analyzers of one domain (`archives`, `secrets`, `firmware`, ...; `pdt capabilities --json` lists each analyzer's domains); `0` means no limit. An analyzer in several domains gets the most permissive override. Repeatable. |
| `--archive-limit NAME=VALUE` | none | Override an archive inspection limit for this scan (byte limits in MiB; repeatable, a later value wins): `entries` (200,000 members), `index_mb` (64, the ZIP central directory), `member_sample_mb` (1) and `sample_mb` (32, per archive; `0` reads no content), `wall_seconds` (8), `decompressed_mb` (4,096, compressed TAR output), `uncompressed_mb` (16,384: members declaring more in total get an archive-bomb finding) and `ratio` (1,000: members compressed more are flagged `high-ratio`). The archive records and `metrics.analysis_budgets` report the values in force. |
| `--max-memory-mb MB` | `0` | Memory budget for the whole scan: the resident memory of PDT and its analysis worker processes, with shared pages counted once on Linux. While the scan is over it, new work waits for queued work; over it with nothing in flight, the scan continues one batch at a time and says so. No analyzer call's own memory budget exceeds it. `0`, the default, sets none; otherwise at least 256. |

Isolated plugins keep `--plugin-timeout` and `--plugin-memory-mb` instead. `metrics.analysis_budgets` records the budgets, the overrides, every stop, the content limits each analyzer declares and every one a call reached, and, per analyzer, its calls, total and longest time, bytes read and largest sampled memory growth, and the scan memory budget (`scan_memory`: its sampled peak, waits and batches queued over it); the terminal summary and the Markdown and HTML reports show them.

```bash
pdt scan ./monorepo --analyzer-timeout 30 --analyzer-memory-mb 1024
pdt scan ./monorepo --max-memory-mb 4096 --jobs 4     # a host with little memory to spare
pdt scan ./firmware --domain-budget firmware:timeout=600,memory=4096 --domain-budget archives:timeout=0
```

### Plugins

| Option | Default | Description |
|---|---|---|
| `--plugin-isolation {sandbox,process,off}` | `sandbox` | `sandbox` runs each plugin in a separate process under a verified operating-system sandbox and refuses it where the sandbox cannot be applied; `process` in a separate process without restrictions; `off` inside PDT with its permissions (trusted plugins only). |
| `--plugin-timeout SECONDS` | `60` | Time a plugin may take per request before its host is stopped (above 0, at most 3,600). |
| `--plugin-memory-mb MB` | `4096` | Memory limit per plugin host on Linux and Windows (256 to 1,048,576); `0` disables it. |

```bash
pdt scan ./service --plugin-timeout 30 --plugin-memory-mb 2048
pdt scan ./service --plugin-isolation process        # hosts where the sandbox is unavailable
```

## `pdt query`

```text
pdt query SCAN_OUTPUT (--symbol NAME | --callers NAME | --callees NAME | --references NAME) [--limit N] [--json]
```

Looks up the code index of a completed scan. A name may be bare (`run`), qualified (`Engine.run`) or module-qualified as the call graph prints it (`pkg.engine.Engine.run`). Each call row says how its target was resolved: `resolved`, `same file`, `through a returned value`, `receiver not resolved` or `by name`. On a scan without a code index (an `--inventory-only` scan) the command warns and exits 3; on a truncated index it warns that results can be incomplete.

| Option | Default | Description |
|---|---|---|
| `SCAN_OUTPUT` | — | The `--output` directory of a completed scan. |
| `--symbol NAME` | — | Definitions named NAME. |
| `--callers NAME` | — | Call sites that call NAME. |
| `--callees NAME` | — | Calls made inside the function NAME. |
| `--references NAME` | — | Files that reference the identifier NAME. |
| `--limit N` | `200` | Maximum rows, 1 to 100,000. |
| `--json` | off | Machine-readable output. |

```bash
pdt query ../reports/service --symbol Engine.run
pdt query ../reports/service --callers parse_config --json
pdt query ../reports/service --references API_TOKEN --limit 50
```

## `pdt compare`

```text
pdt compare REPORT REPORT [REPORT ...] [--output DIR] [--format FORMATS]
```

Compares independent scan reports: shared languages, dependencies and resolved versions (with conflicts), Python module names, API evidence and identical files, and an integration map of how the projects call each other (packages, HTTP APIs, messaging and gRPC). Each project stays a separate identity; a similarity is evidence, not a recommendation to merge. Writes `project-comparison.json` and `project-comparison.md` and modifies none of the projects ([Multi-Project Intelligence](MULTI_PROJECT_INTELLIGENCE.md)).

| Option | Default | Description |
|---|---|---|
| `REPORT` | — | Two or more `discovery-report.json` files. |
| `--output DIR` | `./pdt-comparison` | Comparison directory, outside every compared local project. |
| `--format FORMATS` | `json,markdown` | `json` and/or `markdown`. |

```bash
pdt compare a-report/discovery-report.json b-report/discovery-report.json --output ./a-vs-b
```

## `pdt capabilities`

```text
pdt capabilities [--json]
```

Shows the Python version and platform, the native backends (C byte counter, OpenCL GPU with the reason it is unavailable, C++ signature classifier, Rust walker; a walker built from older sources, or a classifier built from another signature catalog, is reported as outdated and not used), the remote VCS clients found, the optional integrations (Tree-sitter grammars provisioned, PDF, DOCX, YAML), the loaded analyzers and plugins, and what the plugin sandbox verifies on this host.

| Option | Default | Description |
|---|---|---|
| `--json` | off | Machine-readable output, including each analyzer's version, domains and languages. |

```bash
pdt capabilities
pdt capabilities --json > capabilities.json
```

## `pdt plugin-check`

```text
pdt plugin-check PLUGIN [SAMPLE ...] [--isolation {sandbox,process}] [--timeout SECONDS] [--json]
```

Loads a plugin the way a scan does, in a host under the sandbox, through the same protocol and validation, then runs `supports()` and `analyze()` twice on each sample with the file record a scan would build. Exit 0 when every check passes and 1 when one fails. See the [Plugin SDK](PLUGIN_SDK.md).

| Option | Default | Description |
|---|---|---|
| `PLUGIN` | — | `module:attribute` of the analyzer class, or the name of an installed `pdt.analyzers` entry point. |
| `SAMPLE` | none | Sample files or directories to analyze. |
| `--isolation {sandbox,process}` | `sandbox` | Run under the operating-system sandbox, or in a separate process without restrictions. |
| `--timeout SECONDS` | `60` | Time allowed per plugin request, above 0 and at most 3,600. |
| `--json` | off | Machine-readable output. |

```bash
pdt plugin-check my_package.analyzer:MyAnalyzer tests/samples/
pdt plugin-check my-analyzer tests/samples/app.cfg --json
```

## `pdt catalog-add`

```text
pdt catalog-add REPORT [--db FILE]
```

Registers a scan report in the local project catalog, or updates it. The catalog stores report metadata and paths, never source. A local project is keyed by its resolved path; a remote one by its credential-free URL followed by `#ref` when a ref or revision was scanned. Only this command creates a catalog.

| Option | Default | Description |
|---|---|---|
| `REPORT` | — | A `discovery-report.json`. |
| `--db FILE` | `~/.pdt/catalog.sqlite3` | The catalog database. |

```bash
pdt catalog-add ../reports/service/discovery-report.json
```

## `pdt catalog-list`

```text
pdt catalog-list [--db FILE]
```

Lists the registered projects with their file and finding counts. A missing catalog is an error (exit 2).

| Option | Default | Description |
|---|---|---|
| `--db FILE` | `~/.pdt/catalog.sqlite3` | The catalog database, opened read-only. |

```bash
pdt catalog-list --db ./team-catalog.sqlite3
```

## `pdt catalog-remove`

```text
pdt catalog-remove ROOT [--db FILE]
```

Removes a project from the catalog. Exits 2 when no registered project matches, or when the catalog does not exist.

| Option | Default | Description |
|---|---|---|
| `ROOT` | — | A local project path, a remote URL (every scanned ref of it) or `URL#ref` (one ref). |
| `--db FILE` | `~/.pdt/catalog.sqlite3` | The catalog database. |

```bash
pdt catalog-remove /srv/projects/service
pdt catalog-remove 'https://github.com/org/repo#v1.2.0'
```

## `pdt catalog-compare`

```text
pdt catalog-compare [--db FILE] [--output DIR] [--format FORMATS]
```

Runs [`pdt compare`](#pdt-compare) over every registered report.

| Option | Default | Description |
|---|---|---|
| `--db FILE` | `~/.pdt/catalog.sqlite3` | The catalog database, opened read-only. |
| `--output DIR` | `./pdt-catalog-comparison` | Comparison directory, outside every compared local project. |
| `--format FORMATS` | `json,markdown` | `json` and/or `markdown`. |

```bash
pdt catalog-compare --output ../reports/all-projects
```

## `pdt vuln-db`

The local advisory database used by `pdt scan --vuln-db`. Neither action contacts the network.

### `pdt vuln-db import`

```text
pdt vuln-db import SOURCE [--db FILE]
```

Imports OSV JSON records from a local file or directory tree into the database, creating it when needed. Exit 0 when every record imported, 1 when some were skipped (each is reported), and 2 when none could be imported (the database's snapshot provenance is then unchanged).

| Option | Default | Description |
|---|---|---|
| `SOURCE` | — | A local OSV JSON file or directory tree. |
| `--db FILE` | `~/.pdt/vulnerability-advisories.sqlite3` | The advisory database. |

### `pdt vuln-db status`

```text
pdt vuln-db status [--db FILE]
```

Shows the advisory and affected-package counts, the last import and snapshot age (with a warning when the snapshot is stale), the snapshot source and the advisories per ecosystem. A missing database is an error (exit 2).

| Option | Default | Description |
|---|---|---|
| `--db FILE` | `~/.pdt/vulnerability-advisories.sqlite3` | The advisory database, opened read-only. |

```bash
pdt vuln-db import ./osv/npm-and-pypi --db ~/.pdt/advisories.sqlite3
pdt vuln-db status --db ~/.pdt/advisories.sqlite3
```

## Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `PDT_API_TOKEN_<HOST>` | `scan --no-download` | The API token for one host, for example `PDT_API_TOKEN_GITLAB_EXAMPLE_COM`. |
| `PDT_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN` | `scan --no-download`, `--vuln-enrich ghsa` | Token for github.com, and for the GitHub Advisory Database. |
| `PDT_GITLAB_TOKEN`, `GITLAB_TOKEN` | `scan --no-download` | Token for gitlab.com. |
| `PDT_BITBUCKET_TOKEN`, `BITBUCKET_TOKEN`, or `BITBUCKET_USERNAME` with `BITBUCKET_APP_PASSWORD` | `scan --no-download` | Credentials for bitbucket.org. |
| `CODEBERG_TOKEN` | `scan --no-download` | Token for codeberg.org. |
| `PDT_API_URL_<HOST>` | `scan --no-download` | The API base URL for one host, also in batches. |
| `NVD_API_KEY` | `--vuln-enrich nvd` | NVD API key (higher rate limits). |
| `PDT_OSV_API_URL`, `PDT_NVD_API_URL`, `PDT_GITHUB_API_URL` | `--vuln-online` | Alternative endpoints, for example an internal mirror. |
| `PDT_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` | online services | A CA bundle, as `--ca-bundle`. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | online services | Standard proxy settings. |
| `TREE_SITTER_LANGUAGE_PACK_CACHE_DIR` | Tree-sitter | Where provisioned grammars are kept ([Operations Guide](OPERATIONS.md)). |
| `PDT_CODE_MODEL=lexical` | `scan` | Use the structural lexer even where a Tree-sitter grammar is provisioned. |
| `PDT_PLUGIN_RUNTIME_DIR` | plugins on Windows | Where the sandboxed runtime copy for AppContainer hosts is kept. |
| `NO_COLOR` | all commands | Disable colors, as `--no-color`. |

Large-scan practice, performance data and resume details are in the [Operations Guide](OPERATIONS.md); remote scanning in depth in the [Online Mode guide](ONLINE_MODE.md).
