# Online Mode

PDT has two working modes:

- **Local mode** (the default) analyzes a directory on this machine. It is offline: PDT makes no network request of any kind.
- **Online mode** is used only when you ask for it explicitly. It analyzes remote repositories that PDT downloads into a private temporary directory, read-only.

Nothing switches PDT into online mode implicitly. A local `pdt scan PATH` never contacts a remote host, even when the project contains Git remotes, lockfiles or URLs.

| Command | What PDT does | Network use |
|---|---|---|
| `pdt scan PATH` | Analyzes a local directory | None |
| `pdt scan URL` | Downloads one repository into a temporary directory, analyzes it, deletes the copy | The VCS client fetches the repository |
| `pdt scan --url FILE` | Same as above for every repository listed in `FILE`, one report directory each | The VCS client fetches each repository |

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

Each repository gets its own report directory (`OUTPUT/<repository>-<id>/` in a batch, `OUTPUT` or `./<repository>-<id>-pdt-report` for a single URL) with the usual JSON, Markdown and HTML reports. The report root is the credential-free repository URL, and `metrics.source` describes the source:

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

### Limitations

- Only one revision is analyzed; repository history is not imported, and Git clones are shallow (depth 1).
- Git submodules, Git LFS objects and Subversion externals are inventoried but not fetched.
- Jujutsu support covers Git-backed repositories, and `ref` selection is not supported for it.
- Backends other than Git have not been verified against live servers (see *Verification status*).
