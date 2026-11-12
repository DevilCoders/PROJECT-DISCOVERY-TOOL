# Online Mode

PDT has two working modes:

- **Local mode** (the default) analyzes a directory on this machine. It is offline: PDT makes no network request of any kind.
- **Online mode** is used only when you ask for it explicitly. It analyzes remote repositories that PDT downloads into a private temporary directory, read-only.

Nothing switches PDT into online mode implicitly. A local `pdt scan PATH` never contacts a remote host, even when the project contains Git remotes, lockfiles or URLs.

| Command | What PDT does | Network use |
|---|---|---|
| `pdt scan PATH` | Analyzes a local directory | None |
| `pdt scan PATH --vuln-db FILE` | Adds offline advisory matching from an imported OSV snapshot | None |
| `pdt scan PATH --vuln-online` | Adds online advisory matching for the project's lockfile packages | Package coordinates are sent to OSV.dev (and, with `--vuln-enrich`, advisory IDs to NVD/GitHub) |
| `pdt scan URL` | Downloads one repository into a temporary directory, analyzes it, deletes the copy | The VCS client fetches the repository |
| `pdt scan --url FILE` | Same as above for every repository listed in `FILE`, one report directory each | The VCS client fetches each repository |
| `pdt scan URL --no-download` | Analyzes a GitHub, GitLab, Bitbucket Cloud or Gitea/Forgejo repository through its provider API in memory: nothing is cloned or written to disk | Tree listing and file contents from the provider API |
| `pdt scan --url FILE --no-download` | Same, for every repository in `FILE` | As above, per repository |

Online mode therefore has two acquisition paths: **download and analyze** (the default for URLs) and **analyze without downloading** (`--no-download`). The options combine: `pdt scan URL --vuln-online` (with or without `--no-download`) also looks the repository's dependencies up online, and `--vuln-db` and `--vuln-online` can be used together.

## Download and analyze

```bash
pdt scan https://github.com/owner/repository
pdt scan https://github.com/owner/repository --ref v2.1.0
pdt scan git@github.com:owner/private-repository.git
pdt scan hg+https://hg.example.net/team/project
pdt scan svn+ssh://svn.example.net/repos/project/trunk --ref 4182
pdt scan --url repositories.txt --output ./remote-reports
```

A browser URL is normalized to the repository: `https://github.com/owner/repo/tree/main/src` scans `https://github.com/owner/repo`. Use `--ref` (or `ref=` in a URL file) to scan something other than the remote default branch.

### URL files

`--url FILE` reads a UTF-8 text file with one repository per line:

```text
# Blank lines and lines starting with # are ignored; duplicate targets are removed.
https://github.com/owner/project-a
https://github.com/owner/project-a ref=v1.4.0          # a second target: the release tag
https://gitlab.com/group/subgroup/project-b
ssh://git@bitbucket.org/workspace/project-c.git
https://code.example.net/team/project-d vcs=hg         # force a backend for an ambiguous URL
svn+https://svn.example.net/repos/project-e/trunk ref=9120
p4+ssl://perforce.example.net:1666/depot/project-f ref=release-2026.1
fossil+https://fossil.example.net/project-g
```

After the URL a line may carry `ref=NAME` and `vcs=BACKEND` options and a trailing `# comment`. A line's options override the command-line `--ref` and `--vcs` defaults for that line. An unknown option or an invalid URL stops the run before anything is downloaded, with the file name and line number in the error. A file may list up to 10,000 unique repositories and be up to 4 MiB.

### Backends

The VCS prefix of a URL selects the backend; without a prefix, `svn://`, `bzr://` and `pserver://` URLs select their own backend and everything else is treated as Git. `--vcs` (or `vcs=`) forces a backend. The backend's command-line client must be installed; `pdt capabilities --json` reports which clients are present.

| Backend | URL forms | Client | What is analyzed | Ref (`--ref`) |
|---|---|---|---|---|
| Git (GitHub, GitLab, Bitbucket, Azure Repos, CodeCommit, SourceHut, Gitea/Forgejo and other hosts) | `https://`, `ssh://`, `user@host:path`, `git://` | `git` | The tree of one commit, streamed from the object database (no checkout) | Branch, tag or full 40/64-hex commit ID |
| Mercurial | `hg+https://`, `hg+ssh://`, `hg+http://` | `hg` | `hg archive` of one revision | Branch, tag, bookmark or changeset ID |
| Subversion | `svn+https://`, `svn+ssh://`, `svn://`, `svn+http://` | `svn` | `svn export` of one revision, externals excluded | Revision number |
| Bazaar / Breezy | `bzr+https://`, `bzr+ssh://`, `bzr://` | `brz` or `bzr` | `brz export` of one revision | Revision spec |
| Darcs | `darcs+https://`, `darcs+ssh://`, `darcs+http://` | `darcs` | Working tree of a lazy clone | Tag |
| Jujutsu (Git-backed) | `jj+https://`, `jj+ssh://`, `jj+git://`, `user@host:path` | `jj` | Working tree of `jj git clone` | Not supported |
| Pijul | `pijul+https://`, `pijul+ssh://`, `pijul+http://` | `pijul` | Working tree of one channel | Channel |
| CVS | `cvs+pserver://host[:port]/root/module`, `cvs+ssh://` | `cvs` | Checkout of one module | Tag or branch |
| Perforce | `p4+ssl://host:port/depot/path`, `p4+tcp://` | `p4` | `p4 print` of the live head revisions | Label or changelist |
| Fossil | `fossil+https://`, `fossil+ssh://`, `fossil+http://` | `fossil` | One checkout opened without autosync | Check-in, tag or branch |

**Verification status.** The Git path is tested end to end on Windows and Linux against a real Git server on the loopback interface (clone, tree streaming, tags, commit IDs, URL batches, reports). The other backends are tested with recorded client invocations; they have not been run against live servers in this project's test environments, because those clients are not installed there.

### Security model

Online mode treats the remote repository as hostile input and the network as untrusted.

- **Read-only acquisition.** PDT never pushes, commits or changes a remote. Git repositories are cloned with `--no-checkout --depth 1 --single-branch --no-tags --no-recurse-submodules`, an empty hook directory and an empty template, and the tree is read straight from the object database: smudge filters, checkout hooks, submodule commands and Git LFS never run. Other backends use export/print operations, or remove their control metadata (`_darcs`, `.jj`, `.pijul`, `CVS`, Fossil's `_FOSSIL_`/`.fslckout`) from the working copy before analysis; Mercurial archives are written without `.hg_archival.txt`.
- **No credentials in URLs.** URLs with passwords, `https://user@` user names or credential-bearing query parameters (`token`, `access_token`, `private_token`, `password`, `secret`, `auth`) are rejected. Authenticate with an SSH agent, a Git credential helper or your VCS client's own configuration. Reports contain only the credential-free URL.
- **No prompts.** Clients run non-interactively: `GIT_TERMINAL_PROMPT=0`, `GCM_INTERACTIVE=never`, `SSH_ASKPASS_REQUIRE=never`, `--non-interactive`/`--noninteractive` where the client has it, and SSH in `BatchMode` for Git and Subversion unless you configured your own SSH command (`GIT_SSH_COMMAND`, `GIT_SSH`, `core.sshCommand`, `SVN_SSH`). On Linux and macOS each client runs in a new session without a controlling terminal, so a host-key or passphrase prompt fails immediately instead of hanging. Load SSH keys into an agent before a batch.
- **Isolated client configuration where possible.** Mercurial runs with an empty `HGRCPATH` (no user extensions, hooks or `[auth]`; it always uses SSH in `BatchMode`), and Breezy with a private home directory and without user or site plugins. Git uses your global and system configuration, so credential helpers keep working, but never a repository's own configuration.
- **Pinned Git transport.** Git may use only the target URL's own transport (`GIT_ALLOW_PROTOCOL` and `protocol.allow=never`), so redirects to another protocol and `ext::`/`file::` helpers are refused. Repository-locating variables such as `GIT_DIR` and `GIT_WORK_TREE` are removed from the client environment, and Git never discovers a repository above the temporary directory.
- **Plain-text transports need consent.** `git://`, `http://`, `svn://`, `bzr://`, CVS pserver and Perforce `tcp` carry the source without TLS, so it can be read or altered in transit. PDT refuses them unless you pass `--allow-insecure-transport`; reports then record `transport_insecure: true`.
- **No option injection.** Host names, user names, SCP paths, CVS modules and Perforce depot paths may not start with `-`, URLs may not contain whitespace or control characters, and refs are restricted to letters, digits, `.`, `_`, `/`, `+` and `-` (no `..`, no `@{...}`).
- **Safe tree materialization.** Every path in a Git tree is validated before anything is written: no absolute paths, `..`, empty or `.` components, backslashes or `.git` at the top. On Windows, names the filesystem cannot represent faithfully are refused too: reserved device names in any directory and with any extension (`CON`, `NUL`, `AUX`, `aux.c`, `COM1`…), trailing dots or spaces, and `< > : " | ? *`. Files are created exclusively and without following links; a symlink is created only when its target stays inside the repository lexically, and never on an ancestor of another path. Refused paths are never requested from Git and are reported as coverage gaps.
- **Sanitized errors.** Client error output is size-bounded, stripped of terminal control sequences and redacted (URL user information and recognized token formats) before it reaches the console, a report or a batch summary.
- **Cleanup on every exit path.** Each repository is materialized in its own private `pdt-remote-*` directory, removed when its scan ends, fails or is interrupted with Ctrl-C (read-only Git pack files included). If removal fails, PDT prints the leftover path and records it in the batch summary instead of failing silently. Only a forcibly killed PDT process can leave such a directory behind.

### Resource limits

| Limit | Default | Option | When it is reached |
|---|---|---|---|
| Time per client operation (clone, export, tree streaming…) | 600 s | `--remote-timeout SECONDS` (1–86,400) | The client and every process it started are stopped (process group on Linux/macOS, `taskkill /T` on Windows); the target fails |
| Materialized file content per repository | 64 GiB | `--remote-max-gb GIB` | Remaining files are not written; a coverage gap makes the scan incomplete |
| Materialized files per repository | 2,000,000 | — | As above |
| Free space on the temporary filesystem | 256 MiB floor | `--remote-workdir DIR` to use another filesystem | The client is stopped; the target fails |
| Client output kept for messages | 16 MiB of output, last 64 KiB of errors, 1,500 characters shown | — | The client is stopped (output) or the message is truncated |
| Perforce depot listing | 64 MiB, 50,000 files | — | Listing fails, or remaining files become a coverage gap |

On Linux, `/tmp` is often a RAM-backed `tmpfs`; use `--remote-workdir` on a disk-backed filesystem for large repositories.

### Reports

Each repository gets its own report directory (`OUTPUT/<repository>-<id>/` in a batch, `OUTPUT` or `./<repository>-<id>-pdt-report` for a single URL) with the usual JSON, Markdown and HTML reports. The report root is the credential-free repository URL.

Every report, local or online, starts from the same scan summary. In the JSON report (schema 1.7) it is the top-level `scan` block:

```json
"scan": {
  "mode": "online",
  "source": "remote",
  "network_access": ["git-client", "osv.dev", "nvd"],
  "remote": {
    "acquisition": "download", "url": "https://github.com/owner/repository",
    "provider": "GitHub", "vcs": "git", "repository": "repository", "ref": "v2.1.0",
    "revision": "0123456789abcdef0123456789abcdef01234567", "branch": null,
    "transport": "https", "transport_insecure": false,
    "acquired_at": "2026-11-06T10:00:00+00:00", "acquisition_seconds": 3.25,
    "history_complete": false, "coverage_gap_count": 0
  },
  "vulnerability_sources": ["osv.dev"],
  "online_vulnerability_coverage": "complete"
}
```

`mode` is `online` when PDT used the network for the scan (fetching the repository or querying an advisory service) and `local` otherwise; `network_access` lists each use (`<vcs>-client`, `provider-api`, `osv.dev`, `nvd`, `ghsa`). The URL is reduced to its credential-free form again when the summary is written. The Markdown report shows the same facts in its header (`Scan mode`, `Source`) and in *Scan Source* and *Vulnerability Intelligence* sections; the HTML report shows a LOCAL SCAN / ONLINE SCAN badge and a NO TLS badge in its header, a *Scan source* view with the remote metadata, coverage gaps and notes, and the online advisory provenance with a warning whenever a lookup was incomplete. All three formats are self-contained and load nothing from the network.

The full remote metadata is in `metrics.source`:

| Field | Meaning |
|---|---|
| `mode` | `local` or `remote` |
| `remote.acquisition` | `download` (temporary materialization) |
| `remote.url`, `provider`, `vcs`, `repository`, `identity` | Credential-free URL, detected provider, backend, repository name and stable target ID |
| `remote.ref`, `revision`, `branch` | Requested ref (or `null`), the exact revision analyzed and its branch where the backend reports one |
| `remote.transport`, `transport_insecure` | URL scheme, and whether it lacks TLS |
| `remote.acquired_at`, `acquisition_seconds` | When the download started and how long materialization took |
| `remote.coverage` | Content PDT did not analyze: kind, count, detail and whether it makes the scan incomplete |
| `remote.coverage_gaps` | The incomplete items alone |
| `remote.warnings` | Every coverage detail plus notes such as "history was not imported" or "fetched without TLS" |
| Backend counters | For Git: `tracked_file_count`, `materialized_bytes`, symlink, submodule, LFS-pointer, omitted-path, missing-blob and budget counts |

Coverage is never hidden. Every `coverage` item also appears among the findings as an `UNKNOWN`-confidence `analysis_coverage` finding from the `remote-source` analyzer: `LOW` severity when content is missing from the analyzed tree (refused paths, symlinks that could not be created, missing blobs, budget truncation), `INFO` for referenced content that is deliberately not fetched (Git submodules, Git LFS objects, Subversion externals). Missing content is also recorded as a scan diagnostic, so `--strict` reports the scan as incomplete. Informational notes, including the plain-text-transport note, do not affect `--strict`.

A batch also writes `batch-summary.json` and `batch-summary.md` into the output directory, even when it is interrupted. They list every requested repository with its credential-free URL, provider, backend, ref, analyzed revision, status (`completed`, `findings`, `incomplete`, `failed`, `interrupted` or `not_started`), exit code, report directory, timing and sanitized error.

### Exit codes

The exit codes are the same as for local scans: `0` complete, `1` a finding at or above `--fail-on`, `2` usage or fatal error, `3` incomplete under `--strict`, `130` interrupted.

- A single URL that cannot be fetched is a fatal error (`2`), like a missing local path.
- A batch continues after a repository fails. Its exit code is the worst outcome across repositories: `1` if any repository has a finding at or above `--fail-on` (as in a local scan, `--fail-on` takes precedence); otherwise `3` if any repository could not be fetched or, under `--strict`, was scanned incompletely; otherwise `0`.
- `--fail-on` ignores `UNKNOWN` findings, so coverage gaps never trigger it.

### Platform notes

- **Windows.** Creating symbolic links needs Developer Mode or the symlink privilege. Without it, Git symlinks are counted as coverage gaps (`symlinks_not_materialized`) rather than replaced by regular files. Reserved device names and other unrepresentable names are refused as described above, so a repository such as the Linux kernel (which contains `aux.c`) is reported as incomplete on Windows but complete on Linux.
- **Linux and macOS.** Clients run without a controlling terminal and are stopped as a process group. Executable bits from Git trees are preserved.
- **Both.** `--resume` is not available for remote targets, because every run materializes a fresh copy. The fingerprint cache is not used for temporary checkouts.

## Analyze without downloading (`--no-download`)

```bash
pdt scan https://github.com/owner/repository --no-download
pdt scan https://gitlab.com/group/subgroup/project --no-download --ref v3.2.0
pdt scan https://bitbucket.org/workspace/repository --no-download --inventory-only
pdt scan https://codeberg.org/owner/repository --no-download --vuln-online
pdt scan https://ghe.example.com/team/service --no-download --api-url https://ghe.example.com/api/v3
pdt scan --url repositories.txt --no-download --output ./api-reports
```

`--no-download` reads one commit of the repository through the provider's REST API and streams it straight into PDT's analyzers. The repository is never cloned, archived or written to disk: the tree listing becomes PDT's inventory, and each file's content is requested, held in memory while the built-in analyzers read it (through the same verified-read layer as local scans) and then discarded. PDT writes only its usual outputs into the report directory (reports and the SQLite inventory with findings and code facts). A test runs these scans with every file write outside the report directory, every temporary-directory creation and every subprocess start turned into a failure.

### Providers and requests

| Provider | Default API | Requests |
|---|---|---|
| GitHub and GitHub Enterprise Server | `https://api.github.com`; `https://<host>/api/v3` | `GET /repos/{owner}/{repo}`, `/commits/{ref}`, `/git/trees/{tree}?recursive=1` (a truncated tree is walked directory by directory), `/git/blobs/{sha}` (raw) |
| GitLab (gitlab.com and self-managed) | `https://gitlab.com/api/v4`; `https://<host>/api/v4` | `GET /projects/{path}`, `/repository/commits/{ref}`, `/repository/tree?recursive=true` (keyset pages via `Link`), `/repository/blobs/{sha}/raw` |
| Bitbucket Cloud | `https://api.bitbucket.org/2.0` | `GET /repositories/{workspace}/{repo}`, `/commit/{ref}`, `/src/{commit}/?max_depth=…` (paginated by `next`), `/src/{commit}/{path}` |
| Gitea, Forgejo (Codeberg) | `https://<host>/api/v1` | `GET /repos/{owner}/{repo}`, `/commits?sha={ref}&limit=1`, `/git/trees/{sha}?recursive=true` (paginated), `/raw/{path}?ref={sha}` |

The provider is detected from the URL host (github.com, gitlab.com, bitbucket.org, codeberg.org, and host names containing `github`, `gitlab`, `gitea`, `forgejo` or `gogs`); `--api-provider github|gitlab|bitbucket|gitea` sets it for other hosts. `--api-url` sets the API base for a single URL; `PDT_API_URL_<HOST>` (for example `PDT_API_URL_GHE_EXAMPLE_COM`) sets it per host, also for batches. API URLs must use HTTPS (plain HTTP only for loopback hosts). Bitbucket Data Center/Server has a different API and is not supported here; use the download mode. `--ref` selects a branch, tag or commit as in the download mode. SSH and scp-style repository URLs map to the provider's HTTPS API.

### Credentials

Public repositories need no credentials (but anonymous API limits are low: GitHub allows 60 requests per hour). A token is looked up for the repository's host only, in this order:

1. `PDT_API_TOKEN_<HOST>`, for any provider (for example `PDT_API_TOKEN_GITLAB_EXAMPLE_COM`);
2. the provider's standard variables, used only for its public host: `PDT_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN` (github.com); `PDT_GITLAB_TOKEN`, `GITLAB_TOKEN` (gitlab.com); `PDT_BITBUCKET_TOKEN`, `BITBUCKET_TOKEN`, or `BITBUCKET_USERNAME` with `BITBUCKET_APP_PASSWORD` (bitbucket.org); `CODEBERG_TOKEN` (codeberg.org);
3. with `--use-credential-helper`, your Git credential helper (`git credential fill` for `https://<host>`), run non-interactively, outside any repository, and never asked to store or erase anything.

Tokens are sent as `Authorization` headers (`Bearer`, Gitea's `token`, or Basic for app passwords and helper user names) only to the configured API host, never forwarded on redirects, and never logged, cached or written to reports; reports record only `credential_source` (for example `env:GITHUB_TOKEN`). A repository that the API reports as missing produces "not found or is not accessible" with a hint to provide a token, and the target fails.

### Budgets, rate limits and coverage

| Budget | Default | Option |
|---|---|---|
| File contents fetched | 20,000 | `--api-max-files N` |
| Total content | 512 MiB | `--api-max-mb MB` |
| Content per file | 16 MiB | `--api-max-file-mb MB` |
| API requests (listing, contents, symlink targets) | 15,000 | `--api-max-requests N` |
| Parallel content requests | 8 | `--api-workers N` (1–32) |
| Per-request timeout | 30 s | `--network-timeout SECONDS` |

At most twice `--api-workers` file contents are in memory at once. A file that a budget, the rate limit or a failed request kept from being fetched stays in the inventory with a `content_skipped_reason` beginning `no-download:` and the cause. Each cause becomes a `content_not_fetched` coverage gap: an `UNKNOWN` finding and a scan diagnostic, so `--strict` reports the scan as incomplete. When the provider answers that its rate limit is exhausted (HTTP 403/429 with `X-RateLimit-Remaining: 0`, a reset more than 120 seconds away, or `Retry-After`), PDT stops requesting contents for that repository and records when the limit resets. Shorter waits are retried. A truncated tree listing, unsafe or malformed tree paths (absolute, `..`, empty components) and Git submodules are reported as coverage too.

Everything that works on a local tree works here: all built-in analyzers, the Python import graph, the code index, architecture views, `--inventory-only` (one tree listing, no contents), `--exclude-dir`, `--skip`/`--max-file-mb`, `--fail-on`, `--strict` and `--vuln-online` (lockfiles are kept in memory for the lookup, up to 256 MiB in total). Two exceptions: third-party plugins are not run, because their sandbox receives a file copy on disk (reported as a `plugins_not_run` coverage gap when plugins are installed), and `--resume` is not available.

Reports record `acquisition: "api"`, `written_to_disk: false`, the API provider and URL, revision, branch and default branch, `private`, `credential_source`, the budgets, `files_fetched`, `bytes_fetched`, `content_requests`, `api_requests` and per-host request statistics under `metrics.source.remote`, and `scan.network_access: ["provider-api"]`.

**Verification status.** The four provider clients are tested end to end against a loopback emulation of their APIs (authentication, private repositories, pagination styles, truncated GitHub trees, unsafe paths, every budget, rate-limit and request-budget exhaustion, batches with per-host API URLs, the Git credential helper, `--vuln-online` from memory, and the no-disk-write guard). An opt-in test (`PDT_LIVE_NETWORK_TESTS=1`) reads small public repositories through the real GitHub, GitLab, Bitbucket Cloud and Codeberg (Forgejo) APIs without credentials; it passed for all four on 2026-11-06. Authenticated access to private repositories, GitHub Enterprise Server and self-managed GitLab/Gitea instances are covered by the emulation only.

## Online vulnerability intelligence

`--vuln-online` looks up every package resolved in the project's lockfiles in [OSV.dev](https://osv.dev), the aggregated open-source vulnerability database (GitHub advisories, PyPA, RustSec, Go, npm and others). It works for local paths and for remote targets, and next to the offline `--vuln-db` matcher:

```bash
pdt scan /path/to/project --vuln-online
pdt scan https://github.com/owner/repository --vuln-online
pdt scan --url repositories.txt --vuln-online --vuln-enrich nvd,ghsa
pdt scan /path/to/project --vuln-db ~/.pdt/vulnerability-advisories.sqlite3 --vuln-online
```

Without `--vuln-online` PDT never contacts an advisory service: local scans stay offline (a test opens a scan with every socket call disabled to prove it).

### What is sent

| Service | Requests | Data sent |
|---|---|---|
| OSV.dev | `POST /v1/querybatch` (up to 1,000 packages per request, `next_page_token` pages followed up to 10 times), `GET /v1/vulns/{id}` for each matched advisory | Ecosystem, package name and resolved version, for example `npm` / `lodash` / `4.17.20` (Go versions without the `v` prefix) |
| NVD CVE API 2.0 (`--vuln-enrich nvd`) | `GET /rest/json/cves/2.0?cveId=…` | CVE IDs of matched advisories |
| GitHub Advisory Database (`--vuln-enrich ghsa`) | `GET /advisories/{ghsa_id}` | GHSA IDs of matched advisories |

File contents, file paths, lockfile names and project or repository names are never sent; the project's own packages (root, workspace and path members) are not looked up, and only plain registry versions are. Package names are: if your lockfiles name private packages, those names reach OSV.dev. The `User-Agent` is `PDT/<version> (project-discovery-tool; +https://github.com/DevilCoders/PROJECT-DISCOVERY-TOOL)`.

Supported lockfiles are those of the offline matcher: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock`, `composer.lock`, `Gemfile.lock`, `go.sum`, `mix.lock`, `Package.resolved`, `packages.lock.json` and `pubspec.lock`. Each is read once in the scan coordinator (bounded to 128 MiB and 250,000 packages, pinned to the inventoried file identity); worker processes never use the network.

### Results

OSV.dev evaluates the version against the advisory's affected ranges server side, so every match is a `CONFIRMED` finding in the `vulnerabilities` category from the `online-vulnerability-intelligence` analyzer. Findings have the same shape as offline matches: advisory ID and summary, aliases (CVE, GHSA…), severity from the record's CVSS vector or `database_specific` label, fixed-version boundary, conditional impact and remediation, and evidence naming the lockfile, package, ecosystem, resolved version and `source: OSV.dev (<host>), queried <time>`. Withdrawn advisories are skipped. When both `--vuln-db` and `--vuln-online` are used, each source reports its own matches.

Enrichment adds `cvss_<version>: <score> <vector> (<source> <id>)` and `cwe: …` evidence lines. When the OSV record has no severity, the highest enriched CVSS score sets it. At most 200 identifiers are enriched per scan, interleaved per advisory so both sources contribute.

### Failures are coverage gaps, never clean results

| Situation | Finding (confidence `UNKNOWN`) | `--strict` |
|---|---|---|
| OSV.dev unreachable, TLS failure, timeout, HTTP error, rate limit beyond the retry bound | `Online vulnerability lookup failed for N package(s)` with the cause and examples (`LOW`) | Incomplete |
| A lockfile cannot be read or parsed, or exceeds its budget | `Lockfile(s) not checked online: N` (`LOW`) | Incomplete |
| A matched advisory's details cannot be fetched | The match stays `CONFIRMED` (ID only, `MEDIUM`), plus `Online advisory details unavailable` (`LOW`) | Incomplete |
| More than 500,000 unique packages | `Online vulnerability lookup limit reached` (`LOW`) | Incomplete |
| Lockfile content skipped with `--skip` | `Lockfile(s) not checked online because of --skip: N` (`LOW`) | Not affected |
| Enrichment failed or hit its limit | `CVE/advisory enrichment incomplete` (`INFO`) | Not affected |

Transient failures (timeouts, connection resets, HTTP 408/425/429/5xx) are retried three times with jittered exponential backoff, honoring `Retry-After` up to 120 seconds; a longer `Retry-After`, HTTP 4xx and TLS verification failures are not retried. `--fail-on` ignores `UNKNOWN` findings.

### Options and environment

| Option / variable | Default | Purpose |
|---|---|---|
| `--vuln-online` | off | Enable the OSV.dev lookup |
| `--vuln-enrich nvd,ghsa` | none | Add NVD and/or GitHub Advisory details (CVSS, CWE, aliases) |
| `--vuln-cache FILE` | `~/.pdt/online-vulnerability-cache.sqlite3` | Response cache; must be outside the analyzed project |
| `--vuln-cache-ttl HOURS` | 24 | How long answers are reused; `0` disables the cache |
| `--network-timeout SECONDS` | 30 | Per-request timeout |
| `--ca-bundle FILE` | system trust store | PEM bundle for private or TLS-intercepting CAs; also read from `PDT_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and OpenSSL's `SSL_CERT_FILE` |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | none | Standard proxy settings |
| `NVD_API_KEY` | none | NVD API key: 50 instead of 5 requests per rolling 30 seconds |
| `PDT_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN` | none | GitHub token: 5,000 instead of 60 advisory requests per hour |
| `PDT_OSV_API_URL`, `PDT_NVD_API_URL`, `PDT_GITHUB_API_URL` | public endpoints | Mirrors or GitHub Enterprise Server; must be `https://` (plain `http://` only for loopback hosts) |

Certificate verification is never disabled, and TLS 1.2 is the minimum. Requests follow redirects only to the same scheme and host. An API key or token is sent only to its own service's host, as a header that is not forwarded on redirects, never logged, never cached and never written to reports (reports record only `nvd_api_key_used` / `github_token_used`). Rate limits are enforced client side with rolling windows: OSV.dev 20 requests per second, NVD 5 (50 with a key) per 30 seconds, GitHub 60 (5,000 with a token) per hour. Responses are capped at 32 MiB (8 MiB per advisory record), including after gzip decoding.

The cache stores public advisory data and the looked-up coordinates (owner-only file permissions on POSIX); failures are never cached. A batch shares one cache, so a dependency used by many repositories is queried once.

### Provenance in reports

`metrics.vulnerability_intelligence.sources` lists the advisory sources used (`local-database`, `osv.dev`). `metrics.vulnerability_intelligence.online` records the provider and endpoint, enrichment sources and endpoints, whether a key or token was used, `query_started_at`/`query_finished_at`/`query_seconds`, lockfile, unique-package, queried, failed and vulnerable-package counts, advisories, findings, withdrawn records skipped, packages per ecosystem, cache statistics (`hits`, `misses`, `writes`, `ttl_seconds`), request statistics (`requests_by_host`, failures, retries, bytes, `osv_querybatch`, `osv_vulns`), enrichment status, failure reasons, and `coverage`: `complete`, `partial`, `unavailable`, `not_applicable` (no lockfiles) or `skipped` (`--inventory-only`).

**Verification status.** The lookup is tested end to end against a loopback service that implements the OSV.dev, NVD and GitHub advisory endpoints (matching, privacy of the request bodies, caching, retries, rate limits, timeouts, pagination, batching, enrichment, secret isolation, proxies). An opt-in test (`PDT_LIVE_NETWORK_TESTS=1`) queries the real services; it passed against OSV.dev, NVD and the GitHub Advisory Database on 2026-11-06.

## Limitations

- Only one revision is analyzed; repository history is not imported, and Git clones are shallow (depth 1).
- Git submodules, Git LFS objects and Subversion externals are inventoried but not fetched.
- Jujutsu support covers Git-backed repositories, and `ref` selection is not supported for it.
- Backends other than Git have not been verified against live servers (see *Verification status*).
- `--no-download` supports Git hosting APIs only (GitHub, GitLab, Bitbucket Cloud, Gitea/Forgejo); Bitbucket Data Center/Server and the native VCS backends need the download mode. It does not run third-party plugins, and `--resume` is not available.
- Anonymous provider API limits are low (GitHub: 60 requests per hour); use a token for anything beyond small public repositories.
