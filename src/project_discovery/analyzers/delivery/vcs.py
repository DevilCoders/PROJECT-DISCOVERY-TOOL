"""Read-only VCS, source-hosting, CI and cloud-delivery discovery."""
from __future__ import annotations

import configparser
import io
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ...catalog.hosting import classify_host
from ...core.limits import AnalyzerLimits, limit_reached, over_limit
from ...core.source_utils import (SourceBudgetExceeded, describe_error, open_verified_binary, read_bytes_bounded,
                                  read_text_bounded)
from ...models import FileRecord, Finding
from ..base import Analyzer
from .vcs_metadata import (MAX_SQLITE_STEPS, MAX_SQLITE_VALUE_BYTES, hg_bookmarks, hg_changelog, hg_changelog_ends,
                           hg_dirstate, hg_phases, jj_checkout, revlog_header, svn_wc_db)

_VCS_ROOTS = {
    ".git": "Git", ".hg": "Mercurial", ".svn": "Subversion",
    ".bzr": "Bazaar", "_darcs": "Darcs", ".jj": "Jujutsu",
    ".pijul": "Pijul", "CVS": "CVS",
}
# Marker files at a working-copy root. Fossil's checkout database is _FOSSIL_ on Windows,
# .fslckout elsewhere and .fos in old releases; it is never opened.
_MARKER_FILES = {
    ".git": "Git", ".hg": "Mercurial", ".svn": "Subversion",
    "_FOSSIL_": "Fossil", ".fslckout": "Fossil", ".fos": "Fossil",
}
# Git files read anywhere inside a .git directory (also below modules/ and worktrees/).
_GIT_FILES = frozenset({"config", "config.worktree", "HEAD", "packed-refs", "shallow"})
# Files read inside the other control directories, by their path inside the directory.
# A "marker" is a file every repository of that VCS has: it gives the one repository
# finding of its control directory, whether or not optional files such as hgrc exist.
# The "remotes" files name remote locations.
_CONTROL_FILES = {
    ".hg": {"requires": "marker", "hgrc": "remotes"},
    ".svn": {"wc.db": "marker", "entries": "marker", "format": "marker"},
    ".bzr": {"branch-format": "marker", "branch/branch.conf": "remotes"},
    "_darcs": {"format": "marker", "prefs/repos": "remotes"},
    # .jj/repo is a directory in a repository's first workspace and a pointer file in
    # the others. A non-colocated repository keeps its Git remotes in store/git/config.
    ".jj": {"repo/store/type": "marker", "repo": "marker",
            "repo/store/git/config": "remotes", "repo/config.toml": "remotes"},
    ".pijul": {"pristine/db": "marker", "config": "remotes", "config.toml": "remotes"},
    "CVS": {"Root": "marker"},
}
# How a remote's provider is known, when it is not a public service's own host.
_PROVIDER_NOTES = {
    "provider-map": " The provider comes from the provider map.",
    "host-name": " The provider is guessed from a word in the host name; a provider map (--provider-map) names "
                 "it for certain.",
}
_CI_FILES = {
    ".gitlab-ci.yml": "GitLab CI",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines",
    "azure-pipelines.yml": "Azure Pipelines",
    "jenkinsfile": "Jenkins",
    ".travis.yml": "Travis CI",
    ".drone.yml": "Drone CI",
    ".woodpecker.yml": "Woodpecker CI",
    "appveyor.yml": "AppVeyor",
    "buildspec.yml": "AWS CodeBuild",
    "appspec.yml": "AWS CodeDeploy",
}
_CI_PATHS = {
    ".github/workflows": "GitHub Actions",
    ".circleci": "CircleCI",
    ".buildkite": "Buildkite",
    ".teamcity": "TeamCity",
    ".azure/pipelines": "Azure Pipelines",
}
_CLOUD_MARKERS = {
    "cdk.json": "AWS CDK",
    "samconfig.toml": "AWS SAM",
    "serverless.yml": "Serverless Framework",
    "serverless.yaml": "Serverless Framework",
    "cloudbuild.yaml": "Google Cloud Build",
    "cloudbuild.yml": "Google Cloud Build",
    "firebase.json": "Firebase",
    "app.yaml": "Google App Engine",
    "wrangler.toml": "Cloudflare Workers",
    "fly.toml": "Fly.io",
    "render.yaml": "Render",
    "vercel.json": "Vercel",
    "netlify.toml": "Netlify",
}


def _vcs_root(relative: str) -> tuple[str, str, str] | None:
    """(control directory, VCS name, path inside the directory) of the first control
    directory on ``relative``; None when the path is not inside one."""
    parts = relative.split("/")
    for index, part in enumerate(parts[:-1]):
        if part in _VCS_ROOTS:
            return part, _VCS_ROOTS[part], "/".join(parts[index + 1:])
    return None


def _is_worktree_pointer(inner: str) -> bool:
    """``worktrees/<name>/gitdir`` inside a .git directory: a linked worktree."""
    parts = inner.split("/")
    return len(parts) == 3 and parts[0] == "worktrees" and parts[2] == "gitdir"


def _remote_host(raw: str) -> tuple[str | None, str | None]:
    """Return credential-free host and scrubbed locator."""
    value = raw.strip()
    if not value:
        return None, None
    if "://" not in value and re.match(r"^[^/@\s]+@[^:/\s]+:.+", value):
        host = value.split("@", 1)[1].split(":", 1)[0].lower()
        path = value.split(":", 1)[1]
        path = path.split("?", 1)[0].split("#", 1)[0]
        return host, f"ssh://{host}/{path.lstrip('/')}"
    if value.startswith("codecommit::"):
        match = re.match(r"codecommit::([a-z0-9-]+)://(.+)", value, re.I)
        if match:
            return "codecommit.amazonaws.com", f"codecommit://{match.group(1)}/{match.group(2)}"
    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return None, None
        host = parsed.hostname.lower()
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        locator = urlunsplit((parsed.scheme or "https", netloc, parsed.path.rstrip("/"), "", ""))
        return host, locator
    except ValueError:
        return None, None


def _hosting_provider(host: str | None) -> str:
    """A remote host's provider label: the provider map's, a public service's or a guess from the
    host name (catalog.hosting), else "Self-hosted or unclassified"."""
    if not host:
        return "unknown"
    provider = classify_host(host)
    return provider.label if provider is not None else "Self-hosted or unclassified"


def _read_text(
    path: Path,
    expected_identity: tuple[int | None, int | None, int | None, int | None, int | None] | None = None,
) -> tuple[str | None, str | None]:
    try:
        return read_text_bounded(
            path, _MAX_VCS_FILE_BYTES, encoding="utf-8", errors="replace",
            expected_identity=expected_identity,
        ), None
    except OSError as exc:
        return None, describe_error(exc)


_MAX_VCS_FILE_BYTES = 2 * 1024 * 1024
# Subversion's working-copy database is decoded from memory up to this size.
_MAX_WC_DB_BYTES = 256 * 1024 * 1024
# A Mercurial changelog index is read whole up to these sizes: one stored inline (with its revision
# data, which Mercurial keeps under 128 KiB) and a separate one (64 bytes per changeset); a larger
# separate index gives its count and tip from its ends.
_MAX_HG_INLINE_INDEX_BYTES = 8 * 1024 * 1024
_MAX_HG_INDEX_BYTES = 64 * 1024 * 1024
# Entries counted in a control directory (Jujutsu operations, Pijul changes).
_MAX_LISTED_ENTRIES = 100_000
# A Jujutsu working copy's checkout file (a short protocol-buffer message).
_MAX_JJ_CHECKOUT_BYTES = 64 * 1024
# Perforce: settings files (P4CONFIG, P4ENVIRO), ticket, trust and ignore files, by name.
_P4_SETTINGS = frozenset({".p4config", "p4config.txt", ".p4enviro", "p4enviro.txt"})
_P4_TICKETS = frozenset({".p4tickets", "p4tickets.txt"})
_P4_TRUST = frozenset({".p4trust", "p4trust.txt"})
_P4_IGNORE = frozenset({".p4ignore", "p4ignore.txt"})
_P4_FILES = _P4_SETTINGS | _P4_TICKETS | _P4_TRUST | _P4_IGNORE
# Mercurial requirements that change what a repository or its working directory holds.
_HG_FEATURES = (
    ("largefiles", "largefiles"), ("lfs", "LFS"), ("narrowhg-experimental", "a narrow clone"),
    ("exp-sparse", "a sparse checkout"), ("treemanifest", "tree manifests"),
)


def _is_link(path: Path) -> bool:
    """A symbolic link or, on Windows, a junction: a directory inside a control directory that
    points elsewhere is not followed."""
    try:
        return path.is_symlink() or bool(getattr(os.path, "isjunction", None) and os.path.isjunction(path))
    except OSError:
        return True


def _control_text(path: Path) -> str:
    """A small control file's text, or "" when it is missing, unreadable or too large."""
    try:
        return read_text_bounded(path, _MAX_VCS_FILE_BYTES, encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _count_entries(directory: Path, suffix: str = "", depth: int = 1) -> int:
    """Files in a directory (and its subdirectories, to ``depth``) whose name ends with
    ``suffix``, up to the listing budget (recorded when reached); links are not followed."""
    if _is_link(directory) or _is_link(directory.parent):
        return 0
    count = 0
    pending = [(directory, depth)]
    while pending and count < _MAX_LISTED_ENTRIES:
        current, level = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if level > 1 and entry.is_dir(follow_symlinks=False):
                        pending.append((Path(entry.path), level - 1))
                    elif entry.name.endswith(suffix) and entry.is_file(follow_symlinks=False):
                        count += 1
                        if count >= _MAX_LISTED_ENTRIES:
                            limit_reached("entries", _MAX_LISTED_ENTRIES)
                            break
        except OSError:
            continue
    return count


def _plural(number: int, singular: str, plural: str = "") -> str:
    return f"{number:,} {singular if number == 1 else (plural or singular + 's')}"


def _listed(number: int, singular: str, plural: str = "") -> str:
    """A count from a bounded listing: "100,000+ ..." when the listing stopped at its budget."""
    text = _plural(number, singular, plural)
    return text.replace(f"{number:,}", f"{number:,}+", 1) if number >= _MAX_LISTED_ENTRIES else text


def _size(value: int) -> str:
    for unit, scale in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if value >= scale:
            return f"{value / scale:.4g} {unit}"
    return f"{value} B"


def _svn_summary(info: dict) -> tuple[str, list[str]]:
    """A Subversion working copy's repository finding detail and evidence, from its database."""
    detail = f"Subversion working copy (format {info.get('format')})"
    if info.get("repository"):
        detail += f" of {info['repository']}"
    if "path" in info:
        kind = info.get("branch_kind")
        detail += f" at /{info['path']}" + (f" (a {kind})" if kind in ("branch", "tag") else "") \
            + f", revision {info.get('revision')}"
    kinds = info.get("kinds", {})
    counts = [_plural(kinds.get("file", 0), "file"), _plural(kinds.get("dir", 0), "directory", "directories")]
    if kinds.get("symlink"):
        counts.append(_plural(kinds["symlink"], "symlink"))
    notes = [", ".join(counts)]
    revisions = info.get("revisions")
    if revisions and revisions[0] != revisions[1]:
        notes.append(f"mixed revisions {revisions[0]} to {revisions[1]}")
    scheduled = info.get("scheduled", {})
    total = sum(scheduled.values())
    if total:
        # Working rows: "normal" ones add, copy or replace a node, "base-deleted" ones delete it.
        parts = [f"{count:,} {label}" for count, label in ((scheduled.get("normal", 0), "added or copied"),
                                                           (scheduled.get("base-deleted", 0), "deleted")) if count]
        notes.append(_plural(total, "scheduled change") + (f" ({', '.join(parts)})" if parts else ""))
    if info.get("switched"):
        notes.append(_plural(info["switched"], "switched subtree"))
    if info.get("excluded"):
        notes.append(_plural(info["excluded"], "excluded or depth-limited node") + " (a sparse checkout)")
    if info.get("changelists"):
        notes.append("changelists " + ", ".join(str(name)[:100] for name in info["changelists"][:10]))
    if info.get("locks"):
        notes.append(_plural(info["locks"], "repository lock") + " held")
    if info.get("externals"):
        notes.append(_plural(info["externals"], "external"))
    if info.get("pristine") and info["pristine"][0]:
        notes.append(_plural(info["pristine"][0], "pristine copy", "pristine copies") + f" ({_size(info['pristine'][1])})")
    evidence = [f"{label}: {info[key]}" for key, label in (("uuid", "repository UUID"), ("path", "path"),
                                                         ("revision", "revision")) if info.get(key) not in (None, "")]
    return detail + ": " + "; ".join(notes) + ".", evidence


def _hg_changelog(control: Path, requirements: set[str]) -> dict | None:
    """The changeset count, tip and heads of a Mercurial repository's changelog index, read whole
    within its budget (a larger separate index gives its count and tip from its ends). A
    repository without changesets has no changelog in its store ("hg init" leaves a dummy one
    beside the store)."""
    index = control / "store" / "00changelog.i" if "store" in requirements else control / "00changelog.i"
    try:
        with open_verified_binary(index) as stream:
            head = stream.read(4)
            version, inline = revlog_header(head)
            if version != 1:
                return {"version": version}
            size = stream.seek(0, io.SEEK_END)
            budget = _MAX_HG_INLINE_INDEX_BYTES if inline else _MAX_HG_INDEX_BYTES
            if not over_limit(size, budget):
                stream.seek(0)
                return hg_changelog(stream.read(size))
            if inline:
                return None
            stream.seek(size - 64)
            return hg_changelog_ends(head, stream.read(64), size)
    except FileNotFoundError:
        return {"version": 1, "changesets": 0, "tip": ""}
    except (OSError, ValueError):
        return None


def _hg_parents(control: Path) -> tuple[str, str] | None:
    try:
        with open_verified_binary(control / "dirstate") as stream:
            return hg_dirstate(stream.read(64))
    except (OSError, ValueError):
        return None


def _hg_detail(control: Path, requires: list[str], evidence: list[str]) -> str:
    """A Mercurial repository's state, from the control files next to its requires file."""
    notes = []
    linked_store = _is_link(control / "store")
    store = [] if linked_store else _control_text(control / "store" / "requires").split()
    if store:
        evidence.append("store requirements: " + ", ".join(store)[:300])
    # A share-safe repository lists its store requirements in the store.
    requirements = {*requires, *store}
    if linked_store:
        notes.append("its store is a link to another location, which is not followed")
    elif {"shared", "relshared"} & requirements or (control / "sharedpath").is_file():
        # The store, with the changelog and phases, belongs to the shared repository.
        notes.append("its store is shared with another repository, which is not followed")
    else:
        changelog = _hg_changelog(control, requirements)
        if changelog and changelog.get("changesets") is not None:
            notes.append(_plural(changelog["changesets"], "changeset")
                         + (f", tip {changelog['tip'][:12]}" if changelog.get("tip") else "")
                         + (f", {_plural(changelog['heads'], 'head')} (changesets without children)"
                            if changelog.get("heads") else ""))
        elif changelog:
            notes.append(f"a revlog version {changelog.get('version')} changelog, which is not decoded")
    branch = (_control_text(control / "branch").strip().splitlines() or ["default"])[0][:200]
    parents = _hg_parents(control)
    if parents:
        first, second = parents
        notes.append((f"working directory at {first[:12]}" if first else "working directory at the null revision")
                     + f" on branch {branch}" + (f", with an uncommitted merge of {second[:12]}" if second else ""))
    bookmarks = hg_bookmarks(_control_text(control / "bookmarks"))
    active = _control_text(control / "bookmarks.current").strip()[:200]
    if bookmarks:
        notes.append("bookmarks " + ", ".join(bookmarks[:10]) + (f" (active: {active})" if active else ""))
    phases = hg_phases(("" if linked_store else _control_text(control / "store" / "phaseroots"))
                       or _control_text(control / "phaseroots"))
    if phases:
        notes.append("phase roots: " + ", ".join(f"{count:,} {name}" for name, count in sorted(phases.items())))
    shelved = _count_entries(control / "shelved", ".patch")
    if shelved:
        notes.append(_listed(shelved, "shelved change"))
    features = [label for requirement, label in _HG_FEATURES if requirement in requirements]
    if features:
        notes.append("uses " + ", ".join(features))
    return ("Mercurial repository: " + "; ".join(notes) + ".") if notes else "Mercurial repository metadata is present."


def _jj_workspace(control: Path) -> str:
    """The workspace a Jujutsu working copy's checkout file names, or ""."""
    if _is_link(control / "working_copy"):
        return ""
    try:
        checkout = read_bytes_bounded(control / "working_copy" / "checkout", _MAX_JJ_CHECKOUT_BYTES)
        return jj_checkout(checkout)["workspace"][:200]
    except (OSError, ValueError):
        return ""


def _jj_detail(marker: Path, backend: list[str]) -> str:
    """A Jujutsu repository's state, from the files around its store type marker."""
    repository, control = marker.parents[1], marker.parents[2]
    notes = [f"{backend[0] if backend else 'unknown'} backend"]
    target = _control_text(repository / "store" / "git_target").strip().replace("\\", "/")
    if target:
        if target.rstrip("/") == "../../../.git" and (control.parent / ".git").exists():
            notes.append("colocated with a Git repository")
        elif target == "git":
            notes.append("Git store inside .jj")
        else:
            notes.append("Git store elsewhere (not followed)")
    operations = _count_entries(repository / "op_store" / "operations")
    if operations:
        notes.append(_listed(operations, "recorded operation"))
    heads = _count_entries(repository / "op_heads" / "heads")
    if heads > 1:
        notes.append(_listed(heads, "operation head") + ": concurrent operations that the next jj command merges")
    workspace = _jj_workspace(control)
    if workspace:
        notes.append(f"workspace {workspace}")
    return "Jujutsu repository: " + "; ".join(notes) + "."


def _pijul_hooks(config: str) -> bool:
    """Whether a Pijul config.toml declares hooks: an entry in its [hooks] table."""
    in_hooks = False
    for line in config.splitlines()[:10_000]:
        stripped = line.strip()
        if stripped.startswith("["):
            in_hooks = stripped.split("#", 1)[0].strip() == "[hooks]"
        elif in_hooks and stripped and not stripped.startswith("#"):
            return True
    return False


def _pijul_detail(control: Path) -> str:
    changes = _count_entries(control / "changes", ".change", depth=2)
    notes = [_listed(changes, "change") + " recorded" if changes else "no recorded changes"]
    if _pijul_hooks(_control_text(control / "config.toml")):
        notes.append("hooks declared in .pijul/config.toml (they run commands)")
    return "Pijul repository: " + "; ".join(notes) + "."


class VCSHostingAnalyzer(Analyzer):
    """Discover local VCS metadata and hosting/CI providers without invoking clients."""

    name = "vcs-hosting-intelligence"
    limits = AnalyzerLimits(
        _MAX_VCS_FILE_BYTES,
        "whole",
        {"wc_db_bytes": _MAX_WC_DB_BYTES, "sqlite_steps": MAX_SQLITE_STEPS, "sqlite_value_bytes": MAX_SQLITE_VALUE_BYTES,
         "hg_index_bytes": _MAX_HG_INDEX_BYTES, "hg_inline_index_bytes": _MAX_HG_INLINE_INDEX_BYTES,
         "jj_checkout_bytes": _MAX_JJ_CHECKOUT_BYTES,
         "listed_entries": _MAX_LISTED_ENTRIES},
        outcome="An unreadable or over-budget file contributes no signals; the limit reached is recorded",
    )
    domains = ("vcs", "hosting_providers", "ci_cd", "cloud_services")
    languages = tuple(dict.fromkeys([*_VCS_ROOTS.values(), *_MARKER_FILES.values()])) + (
        "Perforce", "Git LFS", "Git Submodules",
    )

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        relative = record.path.replace("\\", "/")
        relative_lower = relative.casefold()
        file_name = relative.rsplit("/", 1)[-1]
        name = file_name.lower()
        control = _vcs_root(relative)
        if control is not None:
            # Only files that a handler reads: names without one cost a read and gave nothing.
            root_name, _, inner = control
            if root_name == ".git":
                return file_name in _GIT_FILES or _is_worktree_pointer(inner)
            return inner in _CONTROL_FILES[root_name]
        if file_name in _MARKER_FILES or file_name == "HEAD":
            return True  # HEAD: a bare repository is recognized from its siblings
        if name in _CI_FILES or name in {".gitmodules", ".gitattributes"} or name in _P4_FILES:
            return True
        if any(relative_lower.startswith(prefix + "/") for prefix in _CI_PATHS):
            return True
        if name in _CLOUD_MARKERS:
            return True
        return False

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        relative = record.path.replace("\\", "/")
        file_name = relative.rsplit("/", 1)[-1]
        name = file_name.lower()
        control = _vcs_root(relative)
        if control is not None:
            return self._vcs_metadata(path, record, *control)
        if file_name == "HEAD":
            return self._bare_repository(path, relative)
        if file_name in _MARKER_FILES:
            if file_name == ".git":
                content, error = _read_text(path, record.analysis_identity)
                if error:
                    return [self._unknown(record, error)]
                if content and content.strip().startswith("gitdir:"):
                    return [Finding(
                        "vcs", f"Git metadata pointer: {record.path}",
                        "The .git file points to a separate Git metadata directory, as used by "
                        "linked worktrees and submodules. The pointer target is not followed.",
                        confidence="CONFIRMED", evidence=[record.path, "gitdir pointer present"],
                        analyzer=self.name,
                    )]
            return [Finding(
                "vcs", f"{_MARKER_FILES[file_name]} metadata marker: {record.path}",
                "A version-control metadata marker file is present; it is not opened.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if file_name == ".gitmodules":  # at any depth: vendored and nested repositories have their own
            return self._gitmodules(path, record)
        if file_name == ".gitattributes":
            return self._gitattributes(path, record)
        if name in _P4_SETTINGS:
            return self._perforce_settings(path, record)
        if name in _P4_TICKETS:
            return [Finding(
                "secrets", f"Perforce ticket file: {record.path}",
                "A Perforce ticket file is in the scanned tree; it is not read. Tickets authenticate as their user to "
                "their server until they expire.",
                confidence="CONFIRMED", severity="HIGH", evidence=[record.path], analyzer=self.name,
                recommendation="Remove the file from the tree and from version control, and run p4 logout for the "
                               "tickets it held.",
            )]
        if name in _P4_TRUST:
            return [Finding(
                "vcs", f"Perforce trust file: {record.path}",
                "A Perforce trust file (P4TRUST) is present: it records the fingerprints of the SSL servers its user "
                "accepted. It is not read.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if name in _P4_IGNORE:
            return [Finding(
                "vcs", f"Perforce ignore rules: {record.path}",
                "A Perforce ignore file (P4IGNORE) is present: the tree is, or was, a Perforce workspace.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        provider = next((value for key, value in _CI_FILES.items() if name == key), None)
        if provider is None:
            provider = next(
                (value for prefix, value in _CI_PATHS.items()
                 if relative.startswith(prefix + "/")), None
            )
        if provider:
            return [Finding(
                "ci_cd", f"CI/CD provider: {provider}",
                "A provider-specific pipeline definition is present. Pipeline jobs are not "
                "executed and credential values are not extracted.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if name in _CLOUD_MARKERS:
            label = _CLOUD_MARKERS[name]
            return [Finding(
                "cloud_services", f"Cloud/deployment platform marker: {label}",
                "A provider-specific deployment/application configuration file is present. "
                "No cloud API or deployment endpoint is contacted.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        return []

    def _perforce_settings(self, path: Path, record: FileRecord) -> list[Finding]:
        """A P4CONFIG or P4ENVIRO file: the settings it makes, by name only."""
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        settings: dict[str, bool] = {}  # name: whether a line gives it a value
        for line in (content or "").splitlines()[:10_000]:
            key, separator, value = line.partition("=")
            key = key.strip().upper()
            if separator and key.startswith("P4") and len(key) <= 40 and key.isascii() and key.replace("_", "").isalnum():
                settings[key] = settings.get(key, False) or bool(value.strip())
        names = sorted(settings)[:50]
        findings = [Finding(
            "vcs", f"Perforce client configuration: {record.path}",
            "A Perforce settings file sets " + (", ".join(names) if names else "no P4 variables")
            + "; their values are not copied.",
            confidence="CONFIRMED", evidence=[record.path, *(f"sets {name}" for name in names[:20])], analyzer=self.name,
        )]
        if settings.get("P4PASSWD"):
            findings.append(Finding(
                "secrets", f"Perforce password in a settings file: {record.path}",
                "P4PASSWD is set in a file in the scanned tree: whoever can read the file can use the account. The "
                "value is not copied.",
                confidence="CONFIRMED", severity="HIGH", evidence=[record.path], analyzer=self.name,
                recommendation="Remove P4PASSWD from the file, change the password, and authenticate with tickets "
                               "(p4 login) instead.",
            ))
        return findings

    def _svn_working_copy(self, path: Path, record: FileRecord, title: str, working: str) -> list[Finding]:
        """The repository finding of a Subversion 1.7+ working copy, from its database, read from
        memory (SQLite never opens the file)."""
        if over_limit(record.size_bytes, _MAX_WC_DB_BYTES):
            return [Finding("vcs", title, f"Subversion working copy; its database is larger than the "
                            f"{_MAX_WC_DB_BYTES:,}-byte budget and was not decoded.", confidence="CONFIRMED",
                            evidence=[record.path], analyzer=self.name)]
        try:
            info = svn_wc_db(read_bytes_bounded(path, _MAX_WC_DB_BYTES, expected_identity=record.analysis_identity))
        except (OSError, SourceBudgetExceeded) as exc:
            return [self._unknown(record, describe_error(exc))]
        except ValueError as exc:
            return [Finding("vcs", title, f"Subversion working copy; its database could not be decoded ({exc}).",
                            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name)]
        detail, evidence = _svn_summary(info)
        findings = [Finding("vcs", title, detail, confidence="CONFIRMED", evidence=[record.path, *evidence],
                            analyzer=self.name)]
        conflicts = info.get("conflicts", 0)
        if conflicts:
            findings.append(Finding(
                "vcs", f"Subversion conflicts: {working}",
                f"{_plural(conflicts, 'node')} of the working copy {'is' if conflicts == 1 else 'are'} in conflict "
                "(text, property or tree conflicts); svn resolve marks a node resolved once its conflict is settled.",
                confidence="CONFIRMED", severity="LOW", evidence=[record.path], analyzer=self.name,
            ))
        if info.get("work_queue") or info.get("wc_locks"):
            findings.append(Finding(
                "vcs", f"Subversion working copy needs cleanup: {working}",
                f"An interrupted operation left {_plural(info.get('work_queue', 0), 'queued work item')} and "
                f"{_plural(info.get('wc_locks', 0), 'working-copy lock')}; svn cleanup completes or releases them.",
                confidence="CONFIRMED", severity="LOW", evidence=[record.path], analyzer=self.name,
            ))
        return findings

    def _unknown(self, record: FileRecord, detail: str) -> Finding:
        return Finding(
            "vcs", f"VCS metadata read error: {record.path}", detail,
            confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
        )

    def _bare_repository(self, path: Path, relative: str) -> list[Finding]:
        """A HEAD file outside any control directory, next to objects/ and config."""
        directory = path.parent
        if not ((directory / "objects").is_dir() and (directory / "config").is_file()):
            return []
        location = relative.rsplit("/", 1)[0] if "/" in relative else ""
        prefix = location + "/" if location else ""
        return [Finding(
            "vcs", "Git bare repository metadata" + (f": {location}" if location else ""),
            "A Git HEAD file, objects directory and config file are present"
            + (f" in {location}" if location else " at the scan root")
            + ". This is consistent with a bare Git repository.",
            confidence="CONFIRMED",
            evidence=[prefix + "HEAD", prefix + "objects/", prefix + "config"],
            analyzer=self.name,
        )]

    def _git_config(self, record: FileRecord, text: str, label: str) -> list[Finding]:
        parser = configparser.ConfigParser(
            interpolation=None, strict=False, allow_no_value=True, inline_comment_prefixes=("#", ";"),
        )
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            return [self._unknown(record, f"Invalid Git config: {exc}")]
        remotes = []
        for section in parser.sections():
            if section.lower().startswith('remote "'):
                remote_name = section[8:-1] if section.endswith('"') else section
                raw = parser.get(section, "url", fallback="")
                host, locator = _remote_host(raw)
                remotes.append((remote_name, classify_host(host), host, locator))
        findings = [
            Finding(
                "hosting_providers",
                f"Git remote provider: {_hosting_provider(host)}",
                f"Remote {remote_name!r} points to host {host or 'unresolved'}; "
                f"sanitized locator: {locator or 'not resolved'}. Authentication material "
                "and URL query/fragment values are removed." + _PROVIDER_NOTES.get(provider.source if provider else "", ""),
                # A provider guessed from the host name is inferred; the host itself is confirmed.
                confidence="UNKNOWN" if not host else "INFERRED" if provider and provider.source == "host-name"
                else "CONFIRMED",
                evidence=[record.path, f"remote section: {remote_name}"] + (
                    [f"provider map entry {provider.entry}: {provider.kind}"]
                    if provider and provider.source == "provider-map" else []),
                analyzer=self.name,
            )
            for remote_name, provider, host, locator in remotes
        ]
        branches = sum(
            section.lower().startswith('branch "') for section in parser.sections()
        )
        findings.append(Finding(
            "vcs", f"{label}: {record.path}",
            f"Detected {len(remotes)} remote(s) and {branches} local branch configuration "
            "section(s). A config file alone does not prove a complete clone.",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        ))
        return findings

    def _control_marker(
        self, path: Path, record: FileRecord, root_name: str, vcs_name: str, inner: str,
    ) -> list[Finding]:
        """The one repository finding of a control directory, from its marker file."""
        relative = record.path.replace("\\", "/")
        control_directory = relative[: len(relative) - len(inner) - 1]
        working = control_directory.rsplit("/", 1)[0] if "/" in control_directory else "."
        if root_name == ".svn" and inner != "wc.db":
            # One marker per working copy: wc.db (Subversion 1.7+), else entries, else format.
            if (path.parent / "wc.db").exists() or (inner == "format" and (path.parent / "entries").exists()):
                return []
        if root_name in {".svn", "CVS"} and inner != "wc.db" and relative.count("/") >= 2:
            # CVS and Subversion before 1.7 keep a control directory in every directory of a
            # working copy: report the copy once, at its top directory.
            parent_control = path.parents[2] / root_name
            if (parent_control / inner).exists():
                return []
        detail = f"{vcs_name} repository metadata is present."
        evidence = [record.path]
        title = f"{vcs_name} repository metadata: {working}"
        if root_name == ".svn" and inner == "wc.db":
            return self._svn_working_copy(path, record, title, working)
        if root_name == ".jj" and inner == "repo":
            workspace = _jj_workspace(path.parent)
            detail = ("A Jujutsu workspace" + (f" ({workspace})" if workspace else "")
                      + " whose repository is shared with another workspace; the pointer is not followed.")
        elif root_name in {".hg", "_darcs", ".bzr", ".jj", "CVS"} or inner == "entries":
            # Small text files with the repository format or server; Pijul's pristine database
            # is never opened.
            content, error = _read_text(path, record.analysis_identity)
            if error:
                return [self._unknown(record, error)]
            lines = [line.strip() for line in (content or "").splitlines() if line.strip()]
            if root_name == "CVS":
                match = re.search(r"@([^:/]+)", content or "")
                detail = "CVS working copy; server host: " + (match.group(1).lower() if match else "not identified")
            elif lines:
                label = {".hg": "requirements", "_darcs": "format", ".bzr": "format",
                         ".jj": "backend", ".svn": "format"}[root_name]
                # Subversion's entries file lists the working copy after its format number.
                shown = lines[:1] if root_name == ".svn" else lines[:20]
                evidence.append(f"{label}: " + ", ".join(shown)[:300])
            if root_name == ".hg":
                detail = _hg_detail(path.parent, lines, evidence)
            elif root_name == ".jj" and inner == "repo/store/type":
                detail = _jj_detail(path, lines)
        elif root_name == ".pijul":
            detail = _pijul_detail(path.parents[1])
        return [Finding(
            "vcs", title, detail, confidence="CONFIRMED", evidence=evidence, analyzer=self.name,
        )]

    def _vcs_metadata(
        self, path: Path, record: FileRecord, root_name: str, vcs_name: str, inner: str,
    ) -> list[Finding]:
        name = Path(record.path).name.lower()
        if root_name == ".git":
            if _is_worktree_pointer(inner):
                return [Finding(
                    "vcs", f"Git linked worktree: {inner.split('/')[1]}",
                    "The repository has a linked worktree; its location is not followed.",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
        elif _CONTROL_FILES[root_name].get(inner) == "marker":
            return self._control_marker(path, record, root_name, vcs_name, inner)
        elif inner not in _CONTROL_FILES[root_name]:
            return []
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        text = content or ""
        if root_name == ".git" and name in {"config", "config.worktree"}:
            return self._git_config(record, text, "Git repository configuration")
        if root_name == ".jj" and inner == "repo/store/git/config":
            return self._git_config(record, text, "Jujutsu Git backend configuration")
        if root_name == ".git" and name == "head" and inner.startswith("refs/"):
            # refs/remotes/origin/HEAD names the remote's default branch, not the checkout.
            stripped = text.strip()
            return [Finding(
                "vcs", f"Git remote default branch: {inner.rsplit('/', 1)[0]}",
                f"{inner} references {stripped.partition(':')[2].strip() or stripped[:64]}.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )] if stripped else []
        if root_name == ".git" and name == "head":
            stripped = text.strip()
            if stripped.startswith("ref:"):
                return [Finding(
                    "vcs", "Git checkout HEAD reference",
                    f"HEAD references {stripped.partition(':')[2].strip()}.",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
            if re.fullmatch(r"[0-9a-fA-F]{40,64}", stripped):
                return [Finding(
                    "vcs", "Git detached HEAD",
                    f"HEAD contains a direct object identifier ({len(stripped)} hexadecimal characters).",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
        if root_name == ".git" and name == "shallow":
            count = sum(
                bool(re.fullmatch(r"[0-9a-fA-F]{40,64}", line.strip()))
                for line in text.splitlines()
            )
            return [Finding(
                "vcs", "Git shallow clone metadata",
                f"The shallow boundary file contains {count} commit boundary record(s).",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".git" and name == "packed-refs":
            refs = [
                line for line in text.splitlines()
                if line and not line.startswith(("#", "^"))
            ]
            return [Finding(
                "vcs", "Git packed reference inventory",
                f"Detected {len(refs)} packed reference record(s).",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".hg" and name == "hgrc":
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                parser.read_string(text)
            except configparser.Error as exc:
                return [self._unknown(record, f"Invalid Mercurial config: {exc}")]
            refs = []
            for section in parser.sections():
                if section.lower() in {"paths", "path"}:
                    for key, raw in parser.items(section):
                        host, _ = _remote_host(raw)
                        refs.append((key, host, _hosting_provider(host)))
            return [Finding(
                "vcs", "Mercurial repository configuration",
                f"Detected {len(refs)} path alias(es). Hosting providers: "
                + (", ".join(sorted({item[2] for item in refs})) or "not identified"),
                confidence="CONFIRMED",
                evidence=[record.path] + [
                    f"path: {key} -> {provider} ({host or 'unknown host'})"
                    for key, host, provider in refs
                ],
                analyzer=self.name,
            )]
        if root_name == ".bzr" and inner == "branch/branch.conf":
            providers = []
            for line in text.splitlines():
                match = re.match(r"\s*(?:parent_location|push_location)\s*=\s*(\S+)", line)
                if match:
                    host, _ = _remote_host(match.group(1))
                    providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Bazaar branch metadata",
                "Hosting providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == "_darcs" and inner == "prefs/repos":
            providers = []
            for remote in text.splitlines():
                host, _ = _remote_host(remote)
                if host:
                    providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Darcs repository remote metadata",
                "Remote providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".pijul" and inner in {"config", "config.toml"}:
            providers = []
            for line in text.splitlines():
                if re.search(r"(?i)(?:remote|url|path)\s*=", line):
                    host, _ = _remote_host(line.split("=", 1)[1].strip().strip("\"'"))
                    if host:
                        providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Pijul repository configuration",
                "Remote providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if root_name == ".jj" and inner == "repo/config.toml":
            providers = []
            for line in text.splitlines():
                if re.search(r"(?i)(?:remote|url)\s*=", line):
                    host, _ = _remote_host(line.split("=", 1)[1].strip().strip('"\''))
                    if host:
                        providers.append(_hosting_provider(host))
            return [Finding(
                "vcs", "Jujutsu repository configuration",
                "Remote providers: " + (", ".join(sorted(set(providers))) or "not identified"),
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        return []

    def _gitmodules(self, path: Path, record: FileRecord) -> list[Finding]:
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        parser = configparser.ConfigParser(
            interpolation=None, strict=False, allow_no_value=True, inline_comment_prefixes=("#", ";"),
        )
        try:
            parser.read_string(content or "")
        except configparser.Error as exc:
            return [self._unknown(record, f"Invalid .gitmodules: {exc}")]
        entries = []
        for section in parser.sections():
            if section.lower().startswith('submodule "'):
                module = section[10:-1] if section.endswith('"') else section
                host, _ = _remote_host(parser.get(section, "url", fallback=""))
                entries.append((module, host, _hosting_provider(host)))
        return [Finding(
            "vcs", f"Git submodule declarations: {record.path}",
            f"Detected {len(entries)} submodule declaration(s).",
            confidence="CONFIRMED",
            evidence=[record.path] + [
                f"submodule: {name}; host: {host or 'not identified'}; provider: {provider}"
                for name, host, provider in entries[:100]
            ],
            analyzer=self.name,
        )]

    def _gitattributes(self, path: Path, record: FileRecord) -> list[Finding]:
        content, error = _read_text(path, record.analysis_identity)
        if error:
            return [self._unknown(record, error)]
        lines = [
            number for number, line in enumerate((content or "").splitlines(), 1)
            if "filter=lfs" in line
        ]
        if not lines:
            return []
        return [Finding(
            "vcs", f"Git LFS tracking rules: {record.path}",
            f"Detected {len(lines)} Git LFS filter rule(s).",
            confidence="CONFIRMED",
            evidence=[f"{record.path}:{line}" for line in lines[:100]],
            analyzer=self.name,
        )]
