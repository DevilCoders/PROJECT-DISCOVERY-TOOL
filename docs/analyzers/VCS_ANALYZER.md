# Version control, hosting and delivery providers

The `vcs-hosting-intelligence` analyzer reads the metadata that version-control systems keep in a working copy, and the files that name hosting, CI and deployment providers. It runs no VCS client and contacts no server: control files are read through the same verified, bounded reads as every other file (no symbolic link is followed, a directory inside a control directory that is a link or junction is not entered, and the file being analyzed is not read if it changed since the inventory listed it), binary formats are decoded from bytes, and pointers to other locations (a `.git` file's `gitdir`, a Jujutsu workspace's repository, a shared Mercurial store) are reported, never followed.

Control directories are analyzed by default. The inventory marks `.git`, `.hg`, `.svn`, `.bzr`, `_darcs`, `CVS`, `.jj` and `.pijul` as version-control trees: `--exclude-profile vcs` prunes them, and `--development-trees inventory` lists them without reading them (see [CLI_REFERENCE.md](../guides/CLI_REFERENCE.md)).

## What it reports

| System | Files read | Reported |
|---|---|---|
| Git | `.git/config`, `config.worktree`, `HEAD`, `packed-refs`, `shallow`, `worktrees/*/gitdir`, `refs/remotes/*/HEAD`; `.git` pointer files; `.gitmodules` and `.gitattributes` at any depth; `HEAD` next to `objects/` and `config` | remotes with their hosting provider and a credential-free locator, branch sections, the checkout reference or detached HEAD, shallow boundaries, packed references, linked worktrees, remote default branches, submodules, Git LFS rules, bare repositories at any depth |
| Subversion | `.svn/wc.db` (1.7 and later); `.svn/entries` or `format` before 1.7 | the working copy decoded from its database ([below](#subversion-working-copies)); the format number before 1.7 |
| Mercurial | `.hg/requires` and the files beside it; `.hg/hgrc` | the repository decoded from its changelog index, dirstate and state files ([below](#mercurial-repositories)); path aliases with their providers |
| Jujutsu | `.jj/repo/store/type` and the files around it; `.jj/repo` pointer files; `.jj/repo/store/git/config`; `.jj/repo/config.toml` | the repository and workspace ([below](#jujutsu-repositories)); Git backend remotes; configured remotes |
| Pijul | `.pijul/pristine/db` (never opened) and the files beside it; `.pijul/config`, `config.toml` | recorded changes and hooks ([below](#pijul-repositories)); remote providers |
| Perforce | `.p4config`, `p4config.txt`, `.p4enviro`, `p4enviro.txt`, `.p4tickets`, `p4tickets.txt`, `.p4trust`, `p4trust.txt`, `.p4ignore`, `p4ignore.txt`, at any depth | settings by name, passwords and ticket files as secrets ([below](#perforce-workspaces)) |
| Bazaar/Breezy | `.bzr/branch-format`, `.bzr/branch/branch.conf` | the branch format; parent and push locations' providers |
| Darcs | `_darcs/format`, `_darcs/prefs/repos` | the repository format; remote providers |
| CVS | `CVS/Root` | the server host, once per working copy |
| Fossil | `_FOSSIL_`, `.fslckout`, `.fos` (never opened) | a checkout marker |

Each control directory gives one repository finding, from a file every repository of that system has, so `hg init`, `darcs init` and ordinary Jujutsu repositories are reported without their optional configuration files. Subversion before 1.7 and CVS keep a control directory in every directory of a working copy; the working copy is reported once, at its top directory.

### Hosting providers, CI and deployment

Remote hosts are fingerprinted as GitHub, GitLab, Bitbucket, Azure Repos, AWS CodeCommit, Google Cloud Source Repositories and SourceHut, and by name as GitHub Enterprise, GitLab self-managed, Bitbucket Data Center/Server, Azure DevOps Server, Gitea, Forgejo (Codeberg included) and Gerrit; other hosts are "Self-hosted or unclassified". Locators keep the scheme, host, port and path: user information, query and fragment are removed, and scp-style addresses (`git@host:path`) become `ssh://host/path`.

CI definitions (GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, Jenkins, CircleCI, Buildkite, TeamCity, Travis CI, Drone, Woodpecker, AppVeyor, AWS CodeBuild and CodeDeploy) and deployment markers (AWS CDK and SAM, Serverless Framework, Google Cloud Build and App Engine, Firebase, Cloudflare Workers, Fly.io, Render, Vercel, Netlify) are reported by file; pipelines are not run and credential values are not extracted.

## Subversion working copies

A Subversion 1.7+ working copy keeps its state in one SQLite database, `.svn/wc.db`. PDT reads the file's bytes (up to 256 MiB) and hands them to SQLite in memory with `deserialize`, so SQLite never opens the file, follows a link, takes a lock or writes anything. The repository finding gives:

- the working-copy format, the repository root (credential-free; a `file://` root on the scanned machine is named by its last component only, `file://.../project`, because the rest of its path is the user's) and the repository UUID;
- the checked-out repository path and revision, with branch or tag by the conventional `trunk`/`branches`/`tags` layout;
- the files, directories and symlinks of the checkout, and mixed revisions when its nodes are at more than one;
- scheduled changes (added or copied, deleted), switched subtrees, excluded and depth-limited (sparse) nodes, changelists, repository locks held, externals, and the pristine store's copies and size.

Two LOW findings follow when they apply: *Subversion conflicts* (text, property and tree conflicts recorded in the working copy) and *Subversion working copy needs cleanup* (queued work items or working-copy locks left by an interrupted operation, which `svn cleanup` completes or releases).

Never reported: lock owners, lock comments and tokens, commit authors, the working copy's own local paths, and the root URL's user, password, query and fragment.

The database is untrusted input. Queries run read-only (`query_only`), with untrusted schema functions off (`trusted_schema`), cell-size checks on, temporary data kept in memory, no attached databases, a 16 MiB limit on any value or row SQLite builds and a budget of 50 million virtual-machine steps, recorded as a `steps` limit when it stops the queries. The tables PDT reads must be plain `CREATE TABLE` tables without virtual generated columns, so no value is computed as it is read: a virtual table or a computed column is refused whatever comments its definition hides it behind, and so are damaged and truncated databases. Values are cut to bounds (2,000 characters for roots and paths, 100 for UUIDs and changelist names) and checked for their type. A refused or over-budget database still gives the repository finding, saying why it was not decoded.

Before 1.7, the `entries` file's format number is reported.

## Mercurial repositories

The repository finding is decoded from the files beside `.hg/requires`:

- the changeset count, the tip and the heads (changesets without children, obsolete ones included), from the changelog index (`store/00changelog.i`; `00changelog.i` without the `store` requirement). The index is read whole: up to 64 MiB (about a million changesets) when it is separate from the revision data, up to 8 MiB when it holds the data inline as small repositories do. Each entry is checked (lengths are not negative, parents precede their children), so a damaged index gives no counts. A larger separate index gives its count and tip from its first and last entries, without heads. A repository without changesets has no changelog in its store; the dummy changelog `hg init` leaves beside the store is not read as one. A revlog version 2 changelog is named, not decoded;
- the working directory's parent and branch, and an uncommitted merge's second parent, from the dirstate (version 1, or the version 2 docket);
- bookmarks and the active one, phase roots by phase (draft, secret, archived, internal), and shelved changes;
- features its requirements enable: largefiles, LFS, narrow clones, sparse checkouts and tree manifests. Requirements are read from `.hg/requires` and, in share-safe repositories, `.hg/store/requires`, and both lists are evidence.

A repository whose store is shared with another (`shared` or `relshared`, or a `sharedpath` file), or whose `store` directory is a link, is reported as such: the store is not followed. Commit messages, authors and file contents are never read.

## Jujutsu repositories

From `.jj/repo/store/type` and the files around it: the backend; whether the Git store is colocated with a `.git` directory beside `.jj`, inside `.jj`, or elsewhere (not followed); the recorded operations in the operation store (`jj op log` also lists the root operation, which is not stored); more than one operation head (concurrent operations the next `jj` command merges); and the workspace named in `.jj/working_copy/checkout`, a protocol-buffer message decoded from bytes. A secondary workspace's `.jj/repo` is a pointer file: it is reported with its workspace name, and its target is not followed. Operation metadata (user names, host names) is never read.

## Pijul repositories

From `.pijul/pristine/db`, which is never opened: the number of recorded changes (`.pijul/changes/*/*.change`; on a clone of a repository on the Nest the count matched `pijul log`, 79 changes), and whether `.pijul/config.toml` declares hooks, which run commands. Identities (`.pijul/identities`) are never read.

## Perforce workspaces

A Perforce workspace keeps its view and file state on the server; a working tree has only the files that configure its client.

| File | Reported |
|---|---|
| P4CONFIG (`.p4config`, `p4config.txt`) and P4ENVIRO (`.p4enviro`, `p4enviro.txt`) files | the `P4*` settings the file makes, by name only; values (servers, users, client names) are not copied. A `P4PASSWD` with a value is also a HIGH `secrets` finding |
| Ticket files (`.p4tickets`, `p4tickets.txt`) | a HIGH `secrets` finding: tickets authenticate as their user until they expire. The file is not read |
| Trust files (`.p4trust`, `p4trust.txt`) | a marker; the file is not read |
| Ignore files (`.p4ignore`, `p4ignore.txt`) | a marker: the tree is, or was, a Perforce workspace |

## Limits

| Limit | Value |
|---|---|
| Control and configuration files | 2 MiB each |
| Subversion working-copy database | 256 MiB, decoded in memory |
| SQLite work per database | 50,000,000 virtual-machine steps |
| SQLite value or row | 16 MiB |
| Mercurial changelog index read whole | 64 MiB separate, 8 MiB inline |
| Jujutsu checkout file | 64 KiB |
| Entries counted in one control directory (operations, changes, shelves) | 100,000; a count that stops there is shown as `100,000+` and recorded |

The generated [budget table](../architecture/ANALYZER_RESOURCE_BUDGETS.md) lists the same values.

## Verification

`tests/analyzers/delivery/test_vcs_metadata.py` pins the decoding with fixtures built in the formats' own layouts (a working-copy database with Subversion's format 31 schema, revlog indexes, dirstates, Jujutsu checkouts), refuses damaged and hostile input (truncated and malformed databases, a virtual table, a generated column that would build a 100 MB value per row, truncated and ragged changelog indexes, negative lengths, a parent after its child, truncated protocol buffers, linked directories inside control directories), checks the size, step and listing budgets, and runs a whole scan to check that no private value reaches the report. Where the clients are installed it cross-checks the decoding against them. On Linux, Subversion 1.15.0, Mercurial 7.2.4 and Jujutsu 0.45.1 create working copies and repositories with commits, merges, bookmarks, phases, changelists, locks and workspaces, and the revisions, counts, heads, parents and names PDT decodes are compared with what the clients report; Pijul 1.0.0-beta.26 creates an empty repository (recording a change needs an identity key in an SSH agent), and its change count was compared with `pijul log` on a Nest clone. `tests/analyzers/delivery/test_vcs_analyzer.py` covers Git, the markers and the hosting, CI and deployment providers.

Not decoded: Fossil checkout databases, Pijul's pristine database and channels, Bazaar's repository store, Darcs patches, CVS `Entries` files, Git's object store and index, and Mercurial revlog version 2 changelogs.
