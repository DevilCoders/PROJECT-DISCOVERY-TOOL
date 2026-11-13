"""Remote repository URL parsing and safe, read-only source materialization.

Git checkouts are created without a working-tree checkout. PDT reads the Git tree
and blob objects directly, so project smudge filters, checkout hooks and submodule
commands are never run. Other VCS adapters use read-only clone/export/print operations
and remove repository control metadata from the temporary analysis tree. No adapter
pushes changes or modifies the remote repository.

Every VCS client runs non-interactively without a controlling terminal (POSIX) and in
its own process group, so a timeout, a disk-space guard or Ctrl-C stops the client and
everything it started. Client error output is size-bounded, stripped of terminal control
sequences and redacted before it reaches a message or report. Temporary checkouts are
removed on every exit path; a removal failure is reported, never silently ignored.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Iterator
from urllib.parse import unquote, urlsplit, urlunsplit

from ..core.secret_patterns import ANY_TOKEN

MAX_URL_FILE_BYTES = 4 * 1024 * 1024
MAX_REMOTE_TARGETS = 10_000
MAX_URL_LINE_CHARS = 8_192
MAX_GIT_PATH_BYTES = 1 * 1024 * 1024
MAX_SYMLINK_TARGET_BYTES = 4_096
DEFAULT_REMOTE_TIMEOUT = 600
MAX_P4_LISTING_BYTES = 64 * 1024 * 1024
MAX_P4_FILES = 50_000
# Materialization budgets: a small compressed pack can expand into an enormous tree.
DEFAULT_REMOTE_MAX_BYTES = 64 * 1024 ** 3
DEFAULT_REMOTE_MAX_FILES = 2_000_000
# Remote operations stop before the temporary filesystem is filled completely.
MIN_FREE_DISK_BYTES = 256 * 1024 ** 2
# Bounded capture of VCS client output (metadata commands and error text).
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_COMMAND_ERROR_BYTES = 16 * 1024 * 1024
MAX_ERROR_DETAIL_CHARS = 1_500
_POLL_SECONDS = 0.2
_WINDOWS = os.name == "nt"
REMOTE_VCS = (
    "auto", "git", "hg", "svn", "bzr", "bazaar", "darcs",
    "jj", "pijul", "cvs", "p4", "perforce", "fossil",
)
_VCS_ALIASES = {"bazaar": "bzr", "perforce": "p4"}
_REMOTE_CLIENTS = {
    "git": ("git",),
    "hg": ("hg",),
    "svn": ("svn",),
    "bzr": ("brz", "bzr"),
    "darcs": ("darcs",),
    "jj": ("jj",),
    "pijul": ("pijul",),
    "cvs": ("cvs",),
    "p4": ("p4",),
    "fossil": ("fossil",),
}
_VCS_PREFIXES = (
    ("fossil+", "fossil"),
    ("perforce+", "p4"),
    ("p4+", "p4"),
    ("cvs+", "cvs"),
    ("pijul+", "pijul"),
    ("darcs+", "darcs"),
    ("jj+", "jj"),
    ("bzr+", "bzr"),
    ("brz+", "bzr"),
    ("svn+", "svn"),
    ("hg+", "hg"),
    ("git+", "git"),
)
# Backends whose clients accept a revision selector, and how it is applied.
_REF_SUPPORT = {"git", "hg", "svn", "bzr", "fossil", "p4", "cvs", "darcs", "pijul"}
# Plain-text transports: content can be read or altered in transit.
INSECURE_SCHEMES = frozenset({"git", "http", "svn", "bzr", "tcp", "pserver"})
# Repository-locating Git variables would redirect PDT's Git commands elsewhere.
_GIT_LOCATION_VARIABLES = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
    "GIT_PREFIX", "GIT_QUARANTINE_PATH",
)
_URL_LINE_OPTIONS = ("ref", "vcs")

_SCP_URL = re.compile(r"^(?P<user>[^@/\s:]+)@(?P<host>[^:/\s]+):(?P<path>.+)$")
_SCHEME_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_SENSITIVE_QUERY = re.compile(
    r"(?:token|access[_-]?token|private[_-]?token|password|passwd|secret|auth)",
    re.IGNORECASE,
)
_PROVIDER_HOSTS = (
    (re.compile(r"(^|\.)github\.com$", re.I), "GitHub"),
    (re.compile(r"(^|\.)gitlab\.com$", re.I), "GitLab"),
    (re.compile(r"(^|\.)bitbucket\.org$", re.I), "Bitbucket"),
    (re.compile(r"(^|\.)dev\.azure\.com$|(^|\.)visualstudio\.com$|^ssh\.dev\.azure\.com$", re.I), "Azure Repos"),
    (re.compile(r"(^|\.)git-codecommit\.[a-z0-9-]+\.amazonaws\.com$", re.I), "AWS CodeCommit"),
    (re.compile(r"(^|\.)git\.sr\.ht$|(^|\.)sr\.ht$", re.I), "SourceHut"),
    (re.compile(r"(^|\.)source\.developers\.google\.com$", re.I), "Google Cloud Source Repositories"),
)
# Device names Windows reserves in every directory, with or without an extension.
_WINDOWS_RESERVED = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]|CONIN\$|CONOUT\$)"
    r"(?:[ .].*+)?\Z",
    re.IGNORECASE,
)
_WINDOWS_INVALID = re.compile(r'[<>:"|?*\x00-\x1f]')
_REF_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/+-]{0,254}\Z")
_COMMIT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_FOSSIL_HASH = re.compile(r"(?m)^checkout:\s*+([0-9a-f]{40,64})(?:\s|$)", re.IGNORECASE)
_P4_ESCAPE = re.compile(r"%(?:40|23|25|2[Aa])")
_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\[[0-?]*+[ -/]*+[@-~]|\][^\x07\x1b]*+(?:\x07|\x1b\\)?|[@-Z\\-_])"
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,31}+://)[^/\s@]{1,512}+@")
# ``user:secret@host`` without a scheme, as git prints it ("unable to look up user:pw@host").
_BARE_USERINFO = re.compile(r"(?<![\w/])[^\s/@:'\"]{1,256}+:[^\s/@'\"]{1,512}+@(?=[A-Za-z0-9\[])")


class RemoteScanError(ValueError):
    """A remote target could not be validated, fetched or safely materialized."""


def remote_vcs_capabilities() -> dict[str, dict[str, str | bool | list[str] | None]]:
    """Report installed remote VCS clients without making network requests."""
    capabilities: dict[str, dict[str, str | bool | list[str] | None]] = {}
    for backend, executable_names in _REMOTE_CLIENTS.items():
        resolved = None
        for name in executable_names:
            resolved = shutil.which(name)
            if resolved:
                break
        wrapper = bool(resolved) and _WINDOWS and resolved.lower().endswith((".cmd", ".bat"))
        capabilities[backend] = {
            # A .cmd/.bat wrapper (Scoop installs some clients that way) cannot be started
            # without cmd.exe, which would re-parse repository URLs: it is not available.
            "available": resolved is not None and not wrapper,
            "executable": resolved,
            "alternatives": list(executable_names),
            **({"note": "only a .cmd/.bat wrapper was found; install the client's .exe"} if wrapper else {}),
        }
    return capabilities


@dataclass(frozen=True, slots=True)
class RemoteTarget:
    input_url: str
    clone_url: str
    provider: str
    vcs: str
    repository_name: str
    output_name: str
    identity: str
    insecure_transport: bool = False
    ref: str | None = None
    transport: str = ""


@dataclass(frozen=True, slots=True)
class RemoteCheckout:
    path: Path
    metadata: dict


@dataclass(frozen=True, slots=True)
class RemoteLimits:
    """Resource budgets for one remote materialization."""

    max_bytes: int = DEFAULT_REMOTE_MAX_BYTES
    max_files: int = DEFAULT_REMOTE_MAX_FILES
    min_free_bytes: int = MIN_FREE_DISK_BYTES

    def __post_init__(self) -> None:
        if self.max_bytes < 1 or self.max_files < 1 or self.min_free_bytes < 0:
            raise ValueError("remote materialization limits must be positive")


@dataclass(slots=True)
class _Coverage:
    """Accumulates acquisition notes and the content a backend could not materialize."""

    items: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, kind: str, count: int, detail: str, *, incomplete: bool) -> None:
        if count:
            self.items.append({
                "kind": kind, "count": count, "detail": detail, "incomplete": incomplete,
            })

    def metadata(self) -> dict:
        return {
            "coverage": list(self.items),
            "warnings": [item["detail"] for item in self.items] + list(self.notes),
        }


_DEFAULT_PORTS = {"https": 443, "http": 80, "ssh": 22, "git": 9418}
# Hosts whose repository paths ignore case and accept an optional ``.git`` suffix.
_CASE_INSENSITIVE_PROVIDERS = frozenset({
    "GitHub", "GitHub Enterprise", "GitLab", "GitLab self-managed", "Bitbucket", "Gitea", "Forgejo",
    "Azure Repos",
})


def _identity_path(path: str, folded: bool) -> str:
    path = path.rstrip("/")
    if folded:
        path = path.casefold()
        if path.endswith(".git"):
            path = path[:-4]
    return path


def is_remote_target(value: str) -> bool:
    candidate = value.strip()
    return bool(_SCHEME_URL.match(candidate) or _SCP_URL.match(candidate))


def _provider(host: str) -> str:
    normalized = host.lower().split("%", 1)[0]
    for pattern, name in _PROVIDER_HOSTS:
        if pattern.search(normalized):
            return name
    if "github" in normalized:
        return "GitHub Enterprise"
    if "gitlab" in normalized:
        return "GitLab self-managed"
    if "bitbucket" in normalized:
        return "Bitbucket Data Center"
    if "azure" in normalized:
        return "Azure DevOps Server"
    if "gitea" in normalized:
        return "Gitea"
    if "forgejo" in normalized or normalized == "codeberg.org":
        return "Forgejo"
    if "gogs" in normalized:
        return "Gogs"
    if "gerrit" in normalized:
        return "Gerrit"
    if "gitolite" in normalized:
        return "Gitolite"
    return "Git-compatible host"


def _server_repository_parts(parts: list[str]) -> list[str] | None:
    """A Bitbucket Data Center/Server clone path (``[context..., "scm", key, repo]``), or None."""
    lowered = [part.lower() for part in parts]
    if "scm" in lowered:
        index = lowered.index("scm")
        return parts[:index + 3] if len(parts) >= index + 3 else None
    for marker, prefix in (("projects", ""), ("users", "~")):
        if marker in lowered:
            index = lowered.index(marker)
            if len(parts) >= index + 4 and lowered[index + 2] == "repos":
                return [*parts[:index], "scm", prefix + parts[index + 1], parts[index + 3] + ".git"]
    return None


def _canonical_git_path(host: str, path: str, provider: str) -> str:
    path = "/" + path.lstrip("/")
    parts = [part for part in path.split("/") if part]
    lower_parts = [part.lower() for part in parts]

    if provider in {"GitHub", "GitHub Enterprise"} and len(parts) >= 2:
        parts = parts[:2]
    elif provider in {"GitLab", "GitLab self-managed"}:
        if "-" in parts:
            parts = parts[:parts.index("-")]
        else:
            markers = {"tree", "blob", "raw", "edit", "blame", "commits", "commit",
                       "issues", "merge_requests", "milestones", "pipelines", "jobs",
                       "releases", "tags", "branches", "wikis", "settings"}
            for index, item in enumerate(lower_parts):
                if item in markers:
                    parts = parts[:index]
                    break
    elif provider == "Bitbucket Data Center" and _server_repository_parts(parts) is not None:
        # /scm/PROJ/repo.git, also below a context path (/bitbucket/scm/...); a browse page
        # (/projects/PROJ/repos/repo/browse) or a personal one (/users/name/repos/repo) is
        # turned into its clone path. Cutting these to two segments left /scm/PROJ.
        parts = _server_repository_parts(parts)
    elif provider in {"Bitbucket", "Bitbucket Data Center"} and len(parts) >= 2:
        markers = {"src", "commits", "branches", "pull-requests", "issues",
                   "downloads", "pipelines", "deployments", "admin", "wiki"}
        for index, item in enumerate(lower_parts):
            if item in markers:
                parts = parts[:index]
                break
        parts = parts[:2]
    elif provider == "Azure Repos":
        if "_git" in lower_parts:
            index = lower_parts.index("_git")
            parts = parts[:index + 2]
    elif provider == "SourceHut":
        if len(parts) >= 2 and parts[0].startswith("~"):
            for marker in ("tree", "browse", "log", "commit", "patch", "refs"):
                if marker in lower_parts[2:]:
                    parts = parts[:2 + lower_parts[2:].index(marker)]
                    break
    elif provider in {"Gitea", "Forgejo", "Gogs", "Gerrit", "Gitolite"}:
        markers = {"src", "tree", "blob", "raw", "commit", "commits", "issues",
                   "pull", "pulls", "merge_requests", "compare", "releases"}
        for index, item in enumerate(lower_parts[2:], 2):
            if item in markers:
                parts = parts[:index]
                break
    elif provider == "Google Cloud Source Repositories":
        if len(parts) >= 4 and parts[0].lower() == "p" and parts[2].lower() == "r":
            parts = parts[:4]

    return "/" + "/".join(parts)


def validate_ref(ref: str | None, vcs: str) -> str | None:
    """Validate a branch, tag, revision or commit selector for a remote backend."""
    if ref is None:
        return None
    value = ref.strip()
    if not value:
        raise RemoteScanError("The requested ref is empty.")
    if vcs not in _REF_SUPPORT:
        raise RemoteScanError(
            f"Selecting a ref is not supported for {vcs} remotes; scan the default branch "
            "or point the URL at the branch you need."
        )
    if (
        not _REF_NAME.match(value) or ".." in value or "//" in value
        or value.endswith(("/", ".", ".lock"))
    ):
        raise RemoteScanError(
            f"Invalid ref {value!r}: use a branch, tag or revision name made of letters, "
            "digits, '.', '_', '/', '+' and '-', or a full commit ID."
        )
    if vcs == "svn" and not value.isdigit() and value != "HEAD":
        raise RemoteScanError("Subversion refs must be a revision number or HEAD.")
    return value


def parse_remote_target(raw_url: str, *, vcs: str = "auto", ref: str | None = None) -> RemoteTarget:
    if vcs not in REMOTE_VCS:
        raise ValueError(f"--vcs must be one of: {', '.join(REMOTE_VCS)}")
    selected_vcs = _VCS_ALIASES.get(vcs, vcs)
    raw = raw_url.strip()
    if not raw or len(raw) > MAX_URL_LINE_CHARS:
        raise RemoteScanError("Repository URL is empty or exceeds the supported line length.")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise RemoteScanError("Repository URLs cannot contain control characters.")
    if any(char.isspace() for char in raw):
        raise RemoteScanError("Repository URLs cannot contain whitespace.")

    clone_url = raw
    prefixed_backend = None
    for prefix, backend in _VCS_PREFIXES:
        if raw.lower().startswith(prefix):
            prefixed_backend = backend
            clone_url = raw[len(prefix):]
            break
    if selected_vcs == "auto":
        scheme_backend = {
            "svn://": "svn",
            "bzr://": "bzr",
            "pserver://": "cvs",
        }
        selected_vcs = prefixed_backend or next(
            (backend for prefix, backend in scheme_backend.items() if raw.lower().startswith(prefix)),
            "git",
        )

    host = ""
    scp = _SCP_URL.match(clone_url)
    if scp:
        host = scp.group("host").lower()
        user = scp.group("user")
        if user.startswith("-") or host.startswith("-") or scp.group("path").startswith("-"):
            raise RemoteScanError("SCP-style repository URLs cannot start a component with '-'.")
        path = "/" + scp.group("path").lstrip("/")
        clone_url = f"{user}@{host}:{scp.group('path')}"
        scheme = "ssh"
    else:
        if not _SCHEME_URL.match(clone_url):
            raise RemoteScanError(
                "Use an HTTPS/SSH repository URL, a Git SSH scp-style URL, or a VCS-prefixed "
                "URL such as hg+https://, svn+https://, bzr+https://, darcs+https://, "
                "jj+https://, pijul+https://, cvs+pserver://, p4+ssl:// or fossil+https://."
            )
        parsed = urlsplit(clone_url)
        scheme = parsed.scheme.lower()
        allowed_schemes = {
            "git": {"https", "http", "ssh", "git"},
            "jj": {"https", "http", "ssh", "git"},
            "hg": {"https", "ssh", "http"},
            "svn": {"https", "ssh", "svn", "http"},
            "bzr": {"https", "ssh", "bzr"},
            "darcs": {"https", "ssh", "http"},
            "pijul": {"https", "ssh", "http"},
            "cvs": {"pserver", "ssh"},
            "p4": {"ssl", "tcp"},
            "fossil": {"https", "http", "ssh"},
        }
        allowed = allowed_schemes[selected_vcs]
        if scheme not in allowed:
            raise RemoteScanError(
                f"Unsupported {selected_vcs} URL scheme {scheme!r}; allowed: "
                + ", ".join(sorted(allowed))
            )
        if parsed.password is not None or (
            parsed.username is not None and scheme not in {"ssh", "pserver"}
        ):
            raise RemoteScanError(
                "Passwords must not be embedded in repository URLs. Use an SSH agent "
                "or your configured VCS credential manager."
            )
        if parsed.query and _SENSITIVE_QUERY.search(parsed.query):
            raise RemoteScanError("Credential-bearing URL query parameters are not accepted.")
        host = (parsed.hostname or "").lower()
        if not host:
            raise RemoteScanError("Repository URL must include a hostname.")
        # A leading "-" would be parsed as a command-line option by ssh and some clients.
        if host.startswith("-") or (parsed.username or "").startswith("-"):
            raise RemoteScanError("Repository host and user names cannot start with '-'.")
        try:
            port = parsed.port
        except ValueError as exc:
            raise RemoteScanError("Repository URL contains an invalid port.") from exc
        if selected_vcs == "p4" and port is None:
            raise RemoteScanError("Perforce URLs must include the server port, for example :1666.")
        host_part = f"[{host}]" if ":" in host else host
        username = parsed.username if scheme in {"ssh", "pserver"} else None
        netloc = f"{username}@{host_part}" if username else host_part
        if port is not None:
            netloc += f":{port}"
        path = parsed.path or "/"
        if selected_vcs == "git":
            provider = _provider(host)
            path = _canonical_git_path(host, path, provider)
        elif selected_vcs == "fossil":
            provider = "Fossil server"
        else:
            provider = _provider(host)
        if selected_vcs in {"cvs", "p4"}:
            parts = [part for part in path.split("/") if part]
            if len(parts) < 2:
                example = (
                    "cvs+pserver://host/cvsroot/project" if selected_vcs == "cvs"
                    else "p4+ssl://server:1666/depot/project"
                )
                raise RemoteScanError(
                    f"{'CVS' if selected_vcs == 'cvs' else 'Perforce'} URL must include "
                    f"both the repository root and project path, for example {example}."
                )
            if any(part.startswith("-") for part in parts):
                raise RemoteScanError("Repository path components cannot start with '-'.")
        # Subversion and Bazaar name their SSH tunnels svn+ssh:// and bzr+ssh://.
        output_scheme = f"{selected_vcs}+ssh" if selected_vcs in {"svn", "bzr"} and scheme == "ssh" else scheme
        clone_url = urlunsplit((output_scheme, netloc, path, "", ""))

    if scp:
        provider = _provider(host)
    if scp and selected_vcs not in {"git", "jj"}:
        raise RemoteScanError("SCP-style URLs are supported only for Git and Jujutsu remotes.")

    if selected_vcs == "git" and scheme not in {"https", "http", "ssh", "git"}:
        # http:// and git:// are plain text: check_transport_policy refuses them unless
        # --allow-insecure-transport is given.
        raise RemoteScanError("Git repository transport must use HTTPS, SSH, git:// or http://.")
    if selected_vcs == "svn" and scheme == "git":
        raise RemoteScanError("Subversion does not support the git:// transport.")
    if selected_vcs == "hg" and scheme == "git":
        raise RemoteScanError("Mercurial does not support the git:// transport.")
    selected_ref = validate_ref(ref, selected_vcs)

    path_for_name = path.rstrip("/").split("/")[-1] or host
    repository_name = path_for_name[:-4] if path_for_name.lower().endswith(".git") else path_for_name
    repository_name = repository_name or host
    # Equivalent spellings share an identity (and so are scanned once): no default port or
    # user name, and on the large hosts no ``.git`` suffix and no case in the path.
    folded = provider in _CASE_INSENSITIVE_PROVIDERS
    if scp:
        safe_identity = f"ssh://{host.lower()}/{_identity_path(path.lstrip('/'), folded)}"
    else:
        normalized = urlsplit(clone_url)
        identity_host = (normalized.hostname or "").lower()
        if normalized.port is not None and normalized.port != _DEFAULT_PORTS.get(scheme.lower()):
            identity_host += f":{normalized.port}"
        safe_identity = urlunsplit((
            scheme.lower(), identity_host, _identity_path(normalized.path, folded), "", "",
        ))
    identity_source = f"{selected_vcs}|{safe_identity}"
    if selected_ref is not None:
        identity_source += f"|{selected_ref}"
    digest = hashlib.sha256(identity_source.encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", repository_name).strip("-.")[:48] or "repository"
    return RemoteTarget(
        input_url=raw,
        clone_url=clone_url,
        provider=provider,
        vcs=selected_vcs,
        repository_name=repository_name,
        output_name=f"{slug}-{digest}",
        identity=digest,
        insecure_transport=scheme in INSECURE_SCHEMES,
        ref=selected_ref,
        transport=scheme,
    )


def _parse_url_line(value: str) -> tuple[str, dict[str, str]]:
    """Split ``URL [ref=NAME] [vcs=BACKEND] [# comment]`` into the URL and its options."""
    tokens = value.split()
    options: dict[str, str] = {}
    for token in tokens[1:]:
        if token.startswith("#"):
            break
        key, separator, item = token.partition("=")
        key = key.lower()
        if not separator or not item or key not in _URL_LINE_OPTIONS:
            raise RemoteScanError(
                f"Unsupported URL option {token!r}; use ref=NAME or vcs=BACKEND after the URL."
            )
        if key in options:
            raise RemoteScanError(f"URL option {key!r} is given twice.")
        options[key] = item
    return tokens[0], options


def load_remote_targets(path: Path, *, vcs: str = "auto", ref: str | None = None) -> list[RemoteTarget]:
    """Read one repository per line: ``URL [ref=NAME] [vcs=BACKEND] [# comment]``.

    A line's ``vcs=``/``ref=`` options override the command-line defaults for that line.
    """
    source = path.expanduser()
    if source.stat().st_size > MAX_URL_FILE_BYTES:
        raise RemoteScanError(
            f"URL list exceeds the {MAX_URL_FILE_BYTES // (1024 * 1024)} MiB size limit."
        )
    try:
        text = source.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RemoteScanError("URL list must be UTF-8 text.") from exc
    targets: list[RemoteTarget] = []
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if len(value) > MAX_URL_LINE_CHARS:
            raise RemoteScanError(
                f"{source}:{line_number}: URL exceeds {MAX_URL_LINE_CHARS} characters."
            )
        try:
            url, options = _parse_url_line(value)
            line_vcs = options.get("vcs", vcs)
            if line_vcs not in REMOTE_VCS:
                raise RemoteScanError(f"vcs={line_vcs!r} is not one of: {', '.join(REMOTE_VCS)}")
            target = parse_remote_target(url, vcs=line_vcs, ref=options.get("ref", ref))
        except RemoteScanError as exc:
            raise RemoteScanError(f"{source}:{line_number}: {exc}") from exc
        key = target.identity
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)
        if len(targets) > MAX_REMOTE_TARGETS:
            raise RemoteScanError(
                f"URL list contains more than {MAX_REMOTE_TARGETS:,} unique repositories."
            )
    if not targets:
        raise RemoteScanError(f"No repository URLs found in {source}.")
    return targets


def check_transport_policy(target: RemoteTarget, *, allow_insecure: bool) -> None:
    """Refuse plain-text transports unless the operator explicitly allowed them."""
    if target.insecure_transport and not allow_insecure:
        raise RemoteScanError(
            f"{target.clone_url} uses the plain-text {target.transport}:// transport, so the "
            "fetched source could be read or altered in transit. Use an HTTPS/SSH/TLS URL, or "
            "pass --allow-insecure-transport to accept the risk (reports record it)."
        )


# ---------------------------------------------------------------------------
# Hardened client execution
# ---------------------------------------------------------------------------

def sanitize_client_output(raw: bytes | str, *, max_chars: int = MAX_ERROR_DETAIL_CHARS) -> str:
    """Make client output safe to print and store: no control sequences or credentials."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = _ANSI_ESCAPE.sub("", text)
    text = _CONTROL_CHARACTERS.sub("", text)
    text = _URL_USERINFO.sub(r"\1<redacted>@", text)
    text = _BARE_USERINFO.sub("<redacted>@", text)
    text = ANY_TOKEN.sub("[REDACTED_TOKEN]", text)
    text = text.strip()
    if len(text) > max_chars:
        text = text[:max_chars] + " … [truncated]"
    return text


def _isolation_kwargs() -> dict:
    """Run clients without a controlling terminal and in their own process group."""
    if _WINDOWS:
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _kill_process_tree(process) -> None:
    """Stop a client and every process it started (best effort, never raises)."""
    try:
        running = process.poll() is None
    except Exception:
        running = True
    pid = getattr(process, "pid", None)
    if running and isinstance(pid, int):
        if _WINDOWS:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=30, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                # start_new_session made the client a group leader (pgid == pid).
                if os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGKILL)
            except (OSError, AttributeError):
                pass
    try:
        process.kill()
    except (OSError, AttributeError, ValueError):
        pass


def _file_size(stream) -> int:
    try:
        return os.fstat(stream.fileno()).st_size
    except (OSError, AttributeError, ValueError):
        return 0


def _read_tail(stream, limit: int = 64 * 1024) -> bytes:
    try:
        size = _file_size(stream)
        stream.seek(max(0, size - limit))
        return stream.read(limit)
    except (OSError, AttributeError, ValueError):
        return b""


def _free_bytes(path: Path) -> int | None:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def _vcs_environment(**overrides: str) -> dict[str, str]:
    """A non-interactive client environment: no prompts, no askpass dialogs."""
    environment = os.environ.copy()
    for name in _GIT_LOCATION_VARIABLES:
        environment.pop(name, None)
    environment.update({
        "GIT_TERMINAL_PROMPT": "0",
        # Git Credential Manager: use stored credentials, never open a sign-in dialog.
        "GCM_INTERACTIVE": "never",
        # OpenSSH 8.4+: never ask for passphrases or host keys through an askpass helper.
        "SSH_ASKPASS_REQUIRE": "never",
    })
    environment.update(overrides)
    return environment


def _run(
    command: list[str],
    *,
    timeout: int,
    env: dict[str, str],
    label: str,
    check: bool = True,
    cwd: Path | None = None,
    max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    disk_guard: tuple[Path, int] | None = None,
) -> subprocess.CompletedProcess:
    """Run one VCS client command with bounded time, output and disk usage.

    stdout/stderr go to anonymous temporary files (no pipe deadlocks, bounded memory). The
    client is killed together with its children when the deadline passes, when it writes
    more than the output budget, when free space under ``disk_guard`` falls below the
    floor, or when PDT is interrupted.
    """
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=env, cwd=cwd, **_isolation_kwargs(),
            )
        except FileNotFoundError as exc:
            raise RemoteScanError(
                f"{label} requires the '{command[0]}' client to be installed and available on PATH."
            ) from exc
        deadline = time.monotonic() + timeout
        failure = None
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = f"{label} exceeded the {timeout}-second remote operation timeout."
                    break
                try:
                    process.wait(timeout=min(_POLL_SECONDS, remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
                if _file_size(out) > max_output_bytes:
                    failure = f"{label} produced more than {max_output_bytes:,} bytes of output."
                    break
                if _file_size(err) > MAX_COMMAND_ERROR_BYTES:
                    failure = f"{label} produced more than {MAX_COMMAND_ERROR_BYTES:,} bytes of error output."
                    break
                if disk_guard is not None:
                    free = _free_bytes(disk_guard[0])
                    if free is not None and free < disk_guard[1]:
                        failure = (
                            f"{label} stopped: free disk space under {disk_guard[0]} fell below "
                            f"{disk_guard[1] // (1024 * 1024):,} MiB. Use --remote-workdir to "
                            "materialize remote repositories on a larger filesystem."
                        )
                        break
        except BaseException:
            _kill_process_tree(process)
            try:
                process.wait(timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
            raise
        if failure is not None:
            _kill_process_tree(process)
            try:
                process.wait(timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
            raise RemoteScanError(failure)
        returncode = process.returncode
        out.seek(0)
        stdout = out.read(max_output_bytes + 1)
        stderr = _read_tail(err)
    if len(stdout) > max_output_bytes:
        raise RemoteScanError(f"{label} produced more than {max_output_bytes:,} bytes of output.")
    if check and returncode:
        detail = sanitize_client_output(stderr)
        raise RemoteScanError(
            f"{label} failed with exit code {returncode}"
            + (f": {detail}" if detail else ".")
        )
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


# ---------------------------------------------------------------------------
# Safe materialization of repository trees
# ---------------------------------------------------------------------------

def _unsafe_component(name: str, *, windows: bool | None = None) -> str | None:
    """Return why one path component cannot be materialized safely, or None."""
    windows = _WINDOWS if windows is None else windows
    if name in {"", ".", ".."}:
        return "path traversal or empty component"
    if "\x00" in name or "\\" in name or "/" in name:
        return "invalid path character"
    if windows:
        if _WINDOWS_INVALID.search(name) or name[-1] in " .":
            return "name is not representable on Windows"
        if _WINDOWS_RESERVED.match(name):
            return "reserved Windows device name"
    return None


def _safe_destination(root: Path, raw_path: bytes, *, windows: bool | None = None) -> Path:
    try:
        name = os.fsdecode(raw_path)
    except UnicodeError as exc:
        raise RemoteScanError("Repository path is not valid in this platform's file-name encoding.") from exc
    if not name or "\x00" in name or "\\" in name:
        raise RemoteScanError("Repository tree contains an unsafe path.")
    posix = PurePosixPath(name)
    windows_path = PureWindowsPath(name)
    if posix.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise RemoteScanError("Repository tree contains an absolute path.")
    # Split the raw text: PurePosixPath would silently collapse "a//b" and "a/./b".
    parts = name.split("/")
    for part in parts:
        reason = _unsafe_component(part, windows=windows)
        if reason is not None:
            if part in {"", ".", ".."}:
                raise RemoteScanError("Repository tree contains a path traversal component.")
            raise RemoteScanError(f"Repository tree path cannot be materialized: {reason}.")
    if parts[0].lower() == ".git":
        raise RemoteScanError("Repository tree attempts to overwrite Git metadata.")
    return root.joinpath(*parts)


def _ensure_safe_parent(root: Path, parent: Path, created: set[str] | None = None) -> None:
    """Create the directories from ``root`` down to ``parent``, refusing collisions.

    ``created`` holds the exact spelling of every directory made so far in this tree. On a
    filesystem that folds case (Windows, default macOS) or Unicode normalization (macOS),
    ``src`` resolves to an existing ``Src``; without this check the two directories were
    merged, and reports cited paths such as ``Src/b.py`` that the repository does not have.
    """
    relative = parent.relative_to(root)
    current = root
    for component in relative.parts:
        current = current / component
        try:
            current.lstat()
        except FileNotFoundError:
            current.mkdir()
            if created is not None:
                created.add(str(current))
            continue
        if current.is_symlink() or not current.is_dir():
            raise RemoteScanError("Repository tree has a non-directory ancestor collision.")
        if created is not None and str(current) not in created:
            raise RemoteScanError(
                "Repository tree has directories whose names differ only in case or Unicode "
                "normalization, which this filesystem cannot keep apart."
            )


def _read_blob(
    output,
    process: subprocess.Popen,
    object_id: bytes,
    *,
    symlink: bool = False,
) -> tuple[bytes, int] | None:
    """Request one blob from ``git cat-file --batch``; None when Git reports it missing."""
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(object_id + b"\n")
    process.stdin.flush()
    header = process.stdout.readline(512)
    fields = header.rstrip(b"\n").split()
    if len(fields) == 2 and fields[0] == object_id and fields[1] == b"missing":
        return None
    if len(fields) != 3 or fields[1] != b"blob" or fields[0] != object_id:
        raise RemoteScanError("Git returned an invalid or missing blob object.")
    try:
        remaining = int(fields[2])
    except ValueError as exc:
        raise RemoteScanError("Git returned an invalid blob size.") from exc
    if remaining < 0:
        raise RemoteScanError("Git returned a negative blob size.")
    capture = bytearray()
    prefix = bytearray()
    while remaining:
        chunk = process.stdout.read(min(1024 * 1024, remaining))
        if not chunk:
            raise RemoteScanError("Git blob stream ended before the declared object size.")
        remaining -= len(chunk)
        if len(prefix) < 128:
            prefix.extend(chunk[:128 - len(prefix)])
        if symlink and len(capture) <= MAX_SYMLINK_TARGET_BYTES:
            capture.extend(chunk[:MAX_SYMLINK_TARGET_BYTES + 1 - len(capture)])
        if output is not None:
            output.write(chunk)
    if process.stdout.read(1) != b"\n":
        raise RemoteScanError("Git blob stream framing is invalid.")
    return bytes(capture) if symlink else bytes(prefix), int(fields[2])


def _iter_nul_records(stream) -> Iterator[bytes]:
    buffer = bytearray()
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        buffer.extend(chunk)
        while True:
            delimiter = buffer.find(0)
            if delimiter < 0:
                break
            yield bytes(buffer[:delimiter])
            del buffer[:delimiter + 1]
        if len(buffer) > MAX_GIT_PATH_BYTES:
            raise RemoteScanError("Git tree contains an overlong path record.")
    if buffer:
        raise RemoteScanError("Git tree stream ended with an incomplete record.")


def _safe_symlink_target(raw_path: bytes, captured: bytes) -> str | None:
    """Return a lexically internal relative symlink target, or None when it is unsafe."""
    if not captured or len(captured) > MAX_SYMLINK_TARGET_BYTES:
        return None
    try:
        target = os.fsdecode(captured)
        link_path = os.fsdecode(raw_path)
    except UnicodeError:
        return None
    if (
        "\x00" in target or "\\" in target or PurePosixPath(target).is_absolute()
        or PureWindowsPath(target).is_absolute() or PureWindowsPath(target).drive
    ):
        return None
    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
    if normalized == ".." or normalized.startswith("../"):
        return None
    return target


def _extract_git_tree(
    checkout: Path,
    git_env: dict[str, str],
    *,
    timeout: int,
    tree_ish: str = "HEAD",
    limits: RemoteLimits | None = None,
) -> dict:
    """Stream ``tree_ish`` out of the isolated object database into ``checkout``.

    Paths are validated before anything is written; files are created exclusively without
    following links; blobs whose path is unsafe or that exceed the materialization budget
    are never requested. A watchdog kills both Git processes when the deadline passes.
    """
    limits = limits or RemoteLimits()
    tree_command = ["git", "-C", str(checkout), "ls-tree", "-r", "-z", "-l", "--full-tree", tree_ish]
    blob_command = ["git", "-C", str(checkout), "cat-file", "--batch"]
    with tempfile.TemporaryFile() as tree_errors, tempfile.TemporaryFile() as blob_errors:
        try:
            tree = subprocess.Popen(
                tree_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=tree_errors, env=git_env, **_isolation_kwargs(),
            )
        except FileNotFoundError as exc:
            raise RemoteScanError("Git client is required for online Git repository scans.") from exc
        try:
            blobs = subprocess.Popen(
                blob_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=blob_errors, env=git_env, **_isolation_kwargs(),
            )
        except BaseException as exc:
            _kill_process_tree(tree)
            if isinstance(exc, FileNotFoundError):
                raise RemoteScanError("Git client is required for online Git repository scans.") from exc
            raise

        expired = threading.Event()

        def expire() -> None:
            expired.set()
            for process in (tree, blobs):
                _kill_process_tree(process)

        watchdog = threading.Timer(timeout, expire)
        watchdog.daemon = True
        watchdog.start()
        started = time.monotonic()

        file_count = 0
        symlink_count = 0
        omitted_symlink_count = 0
        submodule_count = 0
        submodule_paths: list[str] = []
        lfs_pointer_count = 0
        omitted_path_count = 0
        missing_blob_count = 0
        budget_omitted_count = 0
        budget_omitted_bytes = 0
        materialized_bytes = 0
        next_space_check = 64 * 1024 * 1024
        created_directories: set[str] = set()

        assert tree.stdout is not None and blobs.stdin is not None
        assert blobs.stdout is not None
        try:
            for entry in _iter_nul_records(tree.stdout):
                header, separator, raw_path = entry.partition(b"\t")
                fields = header.split()
                # "ls-tree -l" adds an object-size column ("-" for commits and trees).
                if not separator or len(fields) not in {3, 4}:
                    raise RemoteScanError("Git returned a malformed tree entry.")
                mode, object_type, object_id = fields[:3]
                size = None
                if len(fields) == 4 and fields[3] != b"-":
                    try:
                        size = int(fields[3])
                    except ValueError as exc:
                        raise RemoteScanError("Git returned a malformed tree entry size.") from exc
                if mode == b"160000" and object_type == b"commit":
                    submodule_count += 1
                    if len(submodule_paths) < 100:
                        submodule_paths.append(raw_path.decode("utf-8", errors="replace"))
                    try:
                        destination = _safe_destination(checkout, raw_path)
                        # The submodule's own (empty) directory, created like an ancestor.
                        _ensure_safe_parent(checkout, destination, created_directories)
                    except (OSError, RemoteScanError):
                        omitted_path_count += 1
                    continue
                if object_type != b"blob" or mode not in {b"100644", b"100755", b"120000"}:
                    omitted_path_count += 1
                    continue

                symlink = mode == b"120000"
                if not symlink and (
                    file_count >= limits.max_files
                    or (size is not None and materialized_bytes + size > limits.max_bytes)
                ):
                    budget_omitted_count += 1
                    budget_omitted_bytes += size or 0
                    continue
                destination = None
                output = None
                try:
                    destination = _safe_destination(checkout, raw_path)
                    _ensure_safe_parent(checkout, destination.parent, created_directories)
                    if not symlink:
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                        flags |= getattr(os, "O_NOFOLLOW", 0)
                        descriptor = os.open(destination, flags, 0o755 if mode == b"100755" else 0o644)
                        output = os.fdopen(descriptor, "wb")
                except (OSError, RemoteScanError):
                    destination = None
                    output = None
                if destination is None:
                    # Unsafe or colliding path: count it and never request its content.
                    if symlink:
                        omitted_symlink_count += 1
                    else:
                        omitted_path_count += 1
                    continue

                try:
                    blob = _read_blob(output, blobs, object_id, symlink=symlink)
                finally:
                    if output is not None:
                        output.close()
                if blob is None:
                    missing_blob_count += 1
                    if output is not None:
                        destination.unlink(missing_ok=True)
                    continue
                captured, blob_size = blob
                if symlink:
                    link_target = _safe_symlink_target(raw_path, captured)
                    if link_target is None:
                        omitted_symlink_count += 1
                        continue
                    try:
                        os.symlink(link_target, destination)
                        symlink_count += 1
                    except (OSError, NotImplementedError):
                        omitted_symlink_count += 1
                    continue
                file_count += 1
                materialized_bytes += blob_size
                if captured.startswith(b"version https://git-lfs.github.com/spec/v1"):
                    lfs_pointer_count += 1
                if materialized_bytes >= next_space_check:
                    next_space_check = materialized_bytes + 64 * 1024 * 1024
                    free = _free_bytes(checkout)
                    if free is not None and free < limits.min_free_bytes:
                        raise RemoteScanError(
                            "Git tree materialization stopped: free disk space fell below "
                            f"{limits.min_free_bytes // (1024 * 1024):,} MiB. Use "
                            "--remote-workdir to materialize on a larger filesystem."
                        )
            if expired.is_set():
                # The watchdog closed the stream: the listing ended early, not naturally.
                raise RemoteScanError(
                    f"Git tree materialization exceeded the {timeout}-second remote operation timeout."
                )
            remaining = max(1.0, timeout - (time.monotonic() - started))
            tree_code = tree.wait(timeout=remaining)
            if tree_code:
                raise RemoteScanError(
                    "git ls-tree failed: " + sanitize_client_output(_read_tail(tree_errors))
                )
            blobs.stdin.close()
            blob_code = blobs.wait(timeout=remaining)
            if blob_code:
                raise RemoteScanError(
                    "git cat-file failed: " + sanitize_client_output(_read_tail(blob_errors))
                )
        except BaseException as exc:
            for process in (tree, blobs):
                _kill_process_tree(process)
                try:
                    process.wait(timeout=10)
                except (OSError, subprocess.SubprocessError):
                    pass
            if expired.is_set() and not isinstance(exc, KeyboardInterrupt):
                raise RemoteScanError(
                    f"Git tree materialization exceeded the {timeout}-second remote operation timeout."
                ) from exc
            if isinstance(exc, subprocess.TimeoutExpired):
                raise RemoteScanError(
                    f"Git tree materialization exceeded the {timeout}-second remote operation timeout."
                ) from exc
            raise
        finally:
            watchdog.cancel()

    return {
        "tracked_file_count": file_count,
        "materialized_bytes": materialized_bytes,
        "materialized_symlink_count": symlink_count,
        "omitted_symlink_count": omitted_symlink_count,
        "submodule_count": submodule_count,
        "submodule_paths_sample": submodule_paths,
        "git_lfs_pointer_count": lfs_pointer_count,
        "omitted_tree_path_count": omitted_path_count,
        "missing_blob_count": missing_blob_count,
        "budget_omitted_file_count": budget_omitted_count,
        "budget_omitted_bytes": budget_omitted_bytes,
    }


def _git_protocol(target: RemoteTarget) -> str:
    if "://" not in target.clone_url:
        return "ssh"
    return urlsplit(target.clone_url).scheme.lower()


def _git_checkout(
    target: RemoteTarget,
    checkout: Path,
    git_dir: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    template = temporary / "empty-template"
    hooks = temporary / "empty-hooks"
    template.mkdir()
    hooks.mkdir()
    protocol = _git_protocol(target)
    environment = _vcs_environment(
        GIT_LFS_SKIP_SMUDGE="1",
        GIT_NO_LAZY_FETCH="1",
        # Only the target's own transport may be used (no redirects to other protocols,
        # no ext:: or file:: helpers), whatever the user's environment allows.
        GIT_ALLOW_PROTOCOL=protocol,
        # Never discover a repository above the temporary directory.
        GIT_CEILING_DIRECTORIES=str(temporary.parent),
    )
    config = [
        "-c", f"core.hooksPath={hooks}",
        "-c", "protocol.allow=never",
        "-c", f"protocol.{protocol}.allow=always",
        "-c", "core.fsmonitor=false",
    ]
    if (
        protocol == "ssh"
        and not environment.get("GIT_SSH_COMMAND") and not environment.get("GIT_SSH")
    ):
        configured = _run(
            ["git", "config", "--get", "core.sshCommand"],
            timeout=min(timeout, 60), env=environment, label="Git SSH configuration lookup",
            check=False, cwd=temporary,
        ).stdout.strip()
        if not configured:
            # Fail instead of waiting on a host-key or passphrase prompt.
            config += ["-c", "core.sshCommand=ssh -o BatchMode=yes"]
    disk_guard = (temporary, limits.min_free_bytes)
    ref = target.ref
    if ref is not None and _COMMIT_ID.match(ref):
        _run(
            ["git", "init", "--quiet", "--template", str(template),
             "--separate-git-dir", str(git_dir), str(checkout)],
            timeout=timeout, env=environment, label="Git repository initialization",
        )
        _run(
            ["git", "-C", str(checkout), *config, "fetch", "--quiet", "--depth", "1",
             "--no-tags", "--no-recurse-submodules", "--", target.clone_url, ref],
            timeout=timeout, env=environment, label="Git commit fetch", disk_guard=disk_guard,
        )
        tree_ish = "FETCH_HEAD"
    else:
        clone_command = [
            "git", *config,
            "clone", "--quiet", "--no-checkout", "--depth", "1", "--single-branch", "--no-tags",
            "--no-recurse-submodules", "--template", str(template),
            "--separate-git-dir", str(git_dir),
        ]
        if ref is not None:
            clone_command += ["--branch", ref]
        clone_command += ["--", target.clone_url, str(checkout)]
        _run(clone_command, timeout=timeout, env=environment, label="Git clone", disk_guard=disk_guard)
        tree_ish = "HEAD"
    revision = _run(
        ["git", "-C", str(checkout), "rev-parse", "--verify", "--quiet", f"{tree_ish}^{{commit}}"],
        timeout=timeout, env=environment, label="Git revision lookup", check=False,
    ).stdout.decode("ascii", errors="replace").strip()
    if not revision:
        raise RemoteScanError(
            "The remote Git repository has no commits on the selected branch "
            "(empty repository or unborn default branch)."
        )
    if ref is not None and _COMMIT_ID.match(ref) and revision.lower() != ref.lower():
        raise RemoteScanError("Git fetched a different commit than the requested commit ID.")
    branch = None
    if tree_ish == "HEAD":
        branch = _run(
            ["git", "-C", str(checkout), "symbolic-ref", "--short", "-q", "HEAD"],
            timeout=timeout, env=environment, label="Git branch lookup", check=False,
        ).stdout.decode("utf-8", errors="replace").strip() or None
    counts = _extract_git_tree(
        checkout, environment, timeout=timeout, tree_ish=tree_ish, limits=limits,
    )

    # Git created this pointer because metadata lives outside the project root.
    # Remove it before PDT scans the source tree: otherwise reports would expose
    # the ephemeral checkout path and misclassify a remote scan as a local clone.
    git_pointer = checkout / ".git"
    try:
        pointer_info = git_pointer.lstat()
    except FileNotFoundError as exc:
        raise RemoteScanError("Git clone did not create its separate-metadata pointer.") from exc
    if not stat.S_ISREG(pointer_info.st_mode):
        raise RemoteScanError("Git separate-metadata pointer is not a regular file.")
    pointer_text = git_pointer.read_text(encoding="utf-8", errors="strict").strip()
    if not pointer_text.startswith("gitdir: "):
        raise RemoteScanError("Git separate-metadata pointer has an invalid format.")
    pointed_git_dir = Path(pointer_text[8:].strip())
    if not pointed_git_dir.is_absolute():
        pointed_git_dir = checkout / pointed_git_dir
    if pointed_git_dir.resolve() != git_dir.resolve():
        raise RemoteScanError("Git separate-metadata pointer does not match the isolated metadata path.")
    git_pointer.unlink()

    def count(name: str) -> int:
        value = counts.get(name, 0)
        return value if isinstance(value, int) else 0

    coverage = _Coverage()
    coverage.add(
        "git_submodules_not_fetched", count("submodule_count"),
        f"{count('submodule_count')} Git submodule(s) were inventoried but not fetched.",
        incomplete=False,
    )
    coverage.add(
        "git_lfs_objects_not_fetched", count("git_lfs_pointer_count"),
        f"{count('git_lfs_pointer_count')} Git LFS pointer file(s) were found; LFS objects "
        "were not downloaded.",
        incomplete=False,
    )
    coverage.add(
        "symlinks_not_materialized", count("omitted_symlink_count"),
        f"{count('omitted_symlink_count')} Git symlink(s) could not be safely materialized.",
        incomplete=True,
    )
    coverage.add(
        "paths_not_materialized", count("omitted_tree_path_count"),
        f"{count('omitted_tree_path_count')} tracked path(s) could not be materialized safely.",
        incomplete=True,
    )
    coverage.add(
        "blobs_missing", count("missing_blob_count"),
        f"{count('missing_blob_count')} Git blob(s) were missing from the fetched objects.",
        incomplete=True,
    )
    coverage.add(
        "materialization_budget", count("budget_omitted_file_count"),
        f"{count('budget_omitted_file_count'):,} file(s) "
        f"({count('budget_omitted_bytes'):,} bytes) were not materialized because the remote "
        f"budget of {limits.max_bytes:,} bytes / {limits.max_files:,} files was reached.",
        incomplete=True,
    )
    return {
        "mode": "remote",
        "vcs": "git",
        "provider": target.provider,
        "url": target.clone_url,
        "repository": target.repository_name,
        "revision": revision,
        "branch": branch,
        "depth": 1,
        "history_complete": False,
        "submodules_fetched": False,
        "git_lfs_objects_fetched": False,
        "transport_insecure": target.insecure_transport,
        **coverage.metadata(),
        **counts,
    }


def _remove_entry(path: Path) -> None:
    """Delete one file, link or directory tree without following links."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and not _is_link_like(info):
        error = _remove_tree(path)
        if error:
            raise RemoteScanError(error)
    else:
        path.unlink()


def _is_link_like(info: os.stat_result) -> bool:
    """Symlinks plus Windows junctions/mount points (name-surrogate reparse points)."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_tag = getattr(info, "st_reparse_tag", 0)
    return bool(attributes & 0x400 and reparse_tag & 0x20000000)


def _strip_metadata(root: Path, names: tuple[str, ...], *, recursive: bool = False) -> int:
    """Remove VCS control entries from a client-created working copy, in place.

    Removing (rather than copying the tree without them) keeps symlinks intact on systems
    that cannot create them and avoids doubling disk use. Directory links are never
    descended into.
    """
    removed = 0
    if not root.is_dir() or _is_link_like(root.lstat()):
        raise RemoteScanError("VCS client did not create the expected working directory.")
    if not recursive:
        for name in names:
            candidate = root / name
            if candidate.exists() or candidate.is_symlink():
                _remove_entry(candidate)
                removed += 1
        return removed
    pending = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            children = list(entries)
        for entry in children:
            info = entry.stat(follow_symlinks=False)
            if entry.name in names:
                _remove_entry(Path(entry.path))
                removed += 1
            elif stat.S_ISDIR(info.st_mode) and not _is_link_like(info):
                pending.append(Path(entry.path))
    return removed


def _replace_directory(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise RemoteScanError("Temporary checkout destination already exists.")
    os.replace(source, destination)


def _delete_file(path: Path) -> None:
    """Unlink one file, clearing a read-only bit (Windows refuses to unlink those)."""
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        path.unlink(missing_ok=True)


def _apply_budget(checkout: Path, limits: RemoteLimits) -> tuple[int, int]:
    """Keep regular files in path order up to the byte and file budgets; delete the rest.

    For clients that export a whole tree at once, this applies the budgets that Git
    extraction applies file by file: first fit in path order, links not counted, and
    directory links never descended into. Returns (files removed, bytes removed).
    """
    kept_files = kept_bytes = removed_files = removed_bytes = 0
    pending = [checkout]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
        directories = []
        for entry in children:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and not _is_link_like(info):
                directories.append(Path(entry.path))
            elif stat.S_ISREG(info.st_mode) and not _is_link_like(info):
                if kept_files >= limits.max_files or kept_bytes + info.st_size > limits.max_bytes:
                    _delete_file(Path(entry.path))
                    removed_files += 1
                    removed_bytes += info.st_size
                else:
                    kept_files += 1
                    kept_bytes += info.st_size
        # A stack pops the last item first: push in reverse to walk in sorted order.
        pending.extend(reversed(directories))
    return removed_files, removed_bytes


def _add_coverage(metadata: dict, kind: str, count: int, detail: str, *, incomplete: bool) -> None:
    """Append one coverage item (and its warning) to a backend's metadata."""
    if count:
        metadata["coverage"] = [
            *(metadata.get("coverage") or []),
            {"kind": kind, "count": count, "detail": detail, "incomplete": incomplete},
        ]
        metadata["warnings"] = [*(metadata.get("warnings") or []), detail]


def _hg_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    empty_hgrc = temporary / "empty-hgrc"
    empty_hgrc.write_text("", encoding="utf-8")
    # HGRCPATH points at an empty file: no user extensions or hooks are loaded.
    environment = _vcs_environment(HGPLAIN="1", HGRCPATH=str(empty_hgrc))
    options = ["--noninteractive", "--config", "ui.ssh=ssh -o BatchMode=yes"]
    repository = temporary / "hg-repository"
    _run(
        ["hg", *options, "clone", "--noupdate", target.clone_url, str(repository)],
        timeout=timeout, env=environment, label="Mercurial clone",
        disk_guard=(temporary, limits.min_free_bytes),
    )

    def lookup(revset: str) -> str:
        return _run(
            ["hg", *options, "--cwd", str(repository), "log", "-l", "1", "-r", revset,
             "-T", "{node}"],
            timeout=timeout, env=environment, label="Mercurial revision lookup",
            check=target.ref is not None,
        ).stdout.decode("ascii", errors="replace").strip()

    if target.ref is not None:
        revision = lookup(target.ref)
    else:
        # The revision `hg clone` would update to: the "@" bookmark, else the newest
        # head of the default branch, else tip.
        revision = ""
        for revset in ("present(bookmark('@'))", "max(head() and present(branch('default')))", "tip"):
            revision = lookup(revset)
            if revision:
                break
    if not revision:
        raise RemoteScanError("Mercurial repository has no revision to analyze.")
    branch = _run(
        ["hg", *options, "--cwd", str(repository), "log", "-r", revision, "-T", "{branch}"],
        timeout=timeout, env=environment, label="Mercurial branch lookup",
    ).stdout.decode("utf-8", errors="replace").strip()
    # Archive committed files without updating an untrusted working copy; no
    # .hg_archival.txt metadata file is added to the analysis tree.
    _run(
        ["hg", *options, "--config", "ui.archivemeta=false", "--cwd", str(repository),
         "archive", "--no-decode", "--rev", revision, "--type", "files", str(checkout)],
        timeout=timeout, env=environment, label="Mercurial source export",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    return {
        "mode": "remote", "vcs": "hg", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": revision, "branch": branch or None, "history_complete": True,
        "coverage": [], "warnings": [],
    }


def _svn_checkout(
    target: RemoteTarget,
    checkout: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    overrides = {}
    if target.clone_url.startswith("svn+ssh://") and not os.environ.get("SVN_SSH"):
        overrides["SVN_SSH"] = "ssh -o BatchMode=yes"
    environment = _vcs_environment(**overrides)
    if target.ref is not None and target.ref != "HEAD":
        revision = target.ref
    else:
        revision = _run(
            ["svn", "info", "--non-interactive", "--show-item", "revision", target.clone_url],
            timeout=timeout, env=environment, label="Subversion revision lookup",
        ).stdout.decode("utf-8", errors="replace").strip()
    if not revision.isdigit():
        raise RemoteScanError("Subversion did not report a numeric repository revision.")
    # Export exactly the looked-up revision (peg and operative), not a later HEAD.
    _run(
        ["svn", "export", "--non-interactive", "--ignore-externals", "--quiet",
         "-r", revision, f"{target.clone_url}@{revision}", str(checkout)],
        timeout=timeout, env=environment, label="Subversion source export",
        disk_guard=(checkout.parent, limits.min_free_bytes),
    )
    coverage = _Coverage(notes=["The source was exported without .svn metadata."])
    coverage.add(
        "svn_externals_not_fetched", 1,
        "Subversion externals were not fetched (--ignore-externals).",
        incomplete=False,
    )
    return {
        "mode": "remote", "vcs": "svn", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": revision, "branch": None, "history_complete": False,
        "externals_fetched": False,
        **coverage.metadata(),
    }


def _bzr_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    executable = shutil.which("brz") or shutil.which("bzr")
    if executable is None:
        raise RemoteScanError("Bazaar/Breezy remote scans require the 'brz' or 'bzr' client on PATH.")
    home = temporary / "brz-home"
    environment = _vcs_environment(
        BRZ_HOME=str(home), BZR_HOME=str(home),
        # Disable user and site plugins; core transports remain available.
        BRZ_PLUGIN_PATH="-site:-user", BZR_PLUGIN_PATH="-site:-user",
    )
    command = [executable, "export", "--quiet", "--format=dir", str(checkout), target.clone_url]
    if target.ref is not None:
        command += ["-r", target.ref]
    _run(
        command, timeout=timeout, env=environment, label="Bazaar/Breezy source export",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    return {
        "mode": "remote", "vcs": "bzr", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": target.ref, "branch": None, "history_complete": False,
        "coverage": [],
        "warnings": ["Bazaar/Breezy export contains the committed source tree; history metadata is not retained."],
    }


def _darcs_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    environment = _vcs_environment(DARCS_DONT_COLOR="1")
    repository = temporary / "darcs-repository"
    command = ["darcs", "clone", "--lazy", "--no-set-default"]
    if target.ref is not None:
        command.append(f"--tag={target.ref}")
    command += [target.clone_url, str(repository)]
    _run(
        command, timeout=timeout, env=environment, label="Darcs clone",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    _strip_metadata(repository, ("_darcs",))
    _replace_directory(repository, checkout)
    return {
        "mode": "remote", "vcs": "darcs", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": None, "branch": None, "history_complete": False,
        "coverage": [],
        "warnings": ["Darcs source was materialized from a lazy clone; repository metadata was excluded."],
    }


def _jj_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    repository = temporary / "jj-repository"
    environment = _vcs_environment(GIT_CEILING_DIRECTORIES=str(temporary.parent))
    _run(
        ["jj", "git", "clone", "--no-colocate", target.clone_url, str(repository)],
        timeout=timeout, env=environment, label="Jujutsu Git-backed clone",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    # "@" is the new, empty working-copy commit; its parent is the fetched commit.
    revision = _run(
        ["jj", "--repository", str(repository), "log", "-r", "@-", "--no-graph", "-T", "commit_id"],
        timeout=timeout, env=environment, label="Jujutsu revision lookup",
    ).stdout.decode("utf-8", errors="replace").strip()
    _strip_metadata(repository, (".jj", ".git"))
    _replace_directory(repository, checkout)
    return {
        "mode": "remote", "vcs": "jj", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": revision or None, "branch": None, "history_complete": False,
        "coverage": [],
        "warnings": ["Jujutsu remote mode currently supports Git-backed Jujutsu repositories."],
    }


def _pijul_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    repository = temporary / "pijul-repository"
    environment = _vcs_environment()
    command = ["pijul", "clone"]
    if target.ref is not None:
        command += ["--channel", target.ref]
    command += [target.clone_url, str(repository)]
    _run(
        command, timeout=timeout, env=environment, label="Pijul clone",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    _strip_metadata(repository, (".pijul",))
    _replace_directory(repository, checkout)
    channel = target.ref or "main"
    return {
        "mode": "remote", "vcs": "pijul", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": None, "branch": channel, "history_complete": False,
        "coverage": [],
        "warnings": [f"Pijul source was materialized from the {channel} channel; repository metadata was excluded."],
    }


def _cvs_root(target: RemoteTarget) -> tuple[str, str]:
    """Return (CVSROOT, module) for a cvs+pserver:// or cvs+ssh:// URL."""
    parsed = urlsplit(target.clone_url)
    components = [part for part in parsed.path.split("/") if part]
    if len(components) < 2:
        raise RemoteScanError("CVS URL must include a repository root and module.")
    module = components[-1]
    repository_root = "/" + "/".join(components[:-1])
    username = parsed.username
    user_prefix = f"{username}@" if username else ""
    if parsed.scheme == "pserver":
        # CVSROOT syntax: [:method:][[user]@]host[:[port]]/path
        port = f":{parsed.port}" if parsed.port is not None else ":"
        return f":pserver:{user_prefix}{parsed.hostname}{port}{repository_root}", module
    return f":ext:{user_prefix}{parsed.hostname}:{repository_root}", module


def _cvs_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    cvsroot, module = _cvs_root(target)
    overrides = {}
    if not cvsroot.startswith(":pserver:") and not os.environ.get("CVS_RSH"):
        overrides["CVS_RSH"] = "ssh"  # CVS would otherwise default to rsh for :ext:
    environment = _vcs_environment(**overrides)
    repository_name = "cvs-repository"
    command = ["cvs", "-d", cvsroot, "checkout", "-P", "-d", repository_name]
    if target.ref is not None:
        command += ["-r", target.ref]
    command.append(module)
    # CVS resolves "-d DIR" relative to its working directory.
    _run(
        command, timeout=timeout, env=environment, label="CVS checkout", cwd=temporary,
        disk_guard=(temporary, limits.min_free_bytes),
    )
    repository = temporary / repository_name
    _strip_metadata(repository, ("CVS",), recursive=True)
    _replace_directory(repository, checkout)
    return {
        "mode": "remote", "vcs": "cvs", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": target.ref, "branch": None, "history_complete": False,
        "coverage": [],
        "warnings": ["CVS working-copy metadata was excluded; revision history was not imported."],
    }


def _fossil_checkout(
    target: RemoteTarget,
    checkout: Path,
    temporary: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    """Clone a Fossil repository and open one snapshot without auto-syncing."""
    limits = limits or RemoteLimits()
    repository = temporary / "fossil-repository.fossil"
    environment = _vcs_environment()
    _run(
        ["fossil", "clone", "--once", target.clone_url, str(repository)],
        timeout=timeout,
        env=environment,
        label="Fossil clone",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    if not repository.is_file() or repository.is_symlink():
        raise RemoteScanError("Fossil did not create the expected local repository database.")

    open_command = ["fossil", "open", str(repository)]
    if target.ref is not None:
        open_command.append(target.ref)
    open_command += ["--nosync", "--workdir", str(checkout)]
    _run(
        open_command,
        timeout=timeout,
        env=environment,
        label="Fossil source checkout",
        disk_guard=(temporary, limits.min_free_bytes),
    )
    if not checkout.is_dir() or checkout.is_symlink():
        raise RemoteScanError("Fossil did not create the expected source working directory.")

    info = _run(
        ["fossil", "info"],
        timeout=timeout,
        env=environment,
        label="Fossil revision lookup",
        cwd=checkout,
    ).stdout.decode("utf-8", errors="replace")
    branch = _run(
        ["fossil", "branch", "current"],
        timeout=timeout,
        env=environment,
        label="Fossil branch lookup",
        cwd=checkout,
    ).stdout.decode("utf-8", errors="replace").strip()
    revision_match = _FOSSIL_HASH.search(info)
    revision = revision_match.group(1) if revision_match else None

    # Fossil's per-checkout database is not project source. It is named _FOSSIL_ on
    # Windows and .fslckout elsewhere (.fos in old releases); remove exactly these files.
    for name in ("_FOSSIL_", ".fslckout", ".fos"):
        control_file = checkout / name
        if control_file.is_symlink() or control_file.is_file():
            control_file.unlink()
        elif control_file.exists():
            raise RemoteScanError("Fossil checkout metadata path is not a regular file.")

    return {
        "mode": "remote",
        "vcs": "fossil",
        "provider": target.provider,
        "url": target.clone_url,
        "repository": target.repository_name,
        "revision": revision,
        "branch": branch or None,
        "history_complete": False,
        "coverage": [],
        "warnings": [
            "Only the current Fossil checkout was analyzed; repository history was not imported into the analysis tree."
        ],
    }


def _p4_local_name(relative: str) -> str:
    """Undo Perforce's depot-path escaping of @ # % * for local file names."""
    return _P4_ESCAPE.sub(lambda match: unquote(match.group(0)), relative)


def _p4_checkout(
    target: RemoteTarget,
    checkout: Path,
    *,
    timeout: int,
    limits: RemoteLimits | None = None,
) -> dict:
    limits = limits or RemoteLimits()
    parsed = urlsplit(target.clone_url)
    depot_parts = [part for part in parsed.path.split("/") if part]
    if len(depot_parts) < 2 or parsed.port is None:
        raise RemoteScanError("Perforce URL must identify //depot/project and a server port.")
    depot_root = "//" + "/".join(depot_parts)
    depot_prefix = depot_root.rstrip("/") + "/"
    depot_pattern = depot_root.rstrip("/") + "/..."
    if target.ref is not None:
        depot_pattern += "@" + target.ref
    port = f"{parsed.scheme}:{parsed.hostname}:{parsed.port}"
    environment = _vcs_environment(P4PORT=port, P4CONFIG="")
    listing = _run(
        # -e: list only files whose head revision is not deleted.
        ["p4", "-ztag", "files", "-e", depot_pattern],
        timeout=timeout, env=environment, label="Perforce depot listing",
        max_output_bytes=MAX_P4_LISTING_BYTES,
    ).stdout
    if len(listing) > MAX_P4_LISTING_BYTES:
        raise RemoteScanError(
            f"Perforce depot listing exceeds the {MAX_P4_LISTING_BYTES // (1024 * 1024)} MiB safety limit."
        )

    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in listing.decode("utf-8", errors="replace").splitlines():
        if not line.startswith("... "):
            continue
        fields = line[4:].split(" ", 1)
        if len(fields) != 2:
            continue
        key, value = fields
        if key == "depotFile":
            if current:
                entries.append(current)
            current = {"depotFile": value}
        elif current:
            current[key] = value
    if current:
        entries.append(current)
    entries = [item for item in entries if "delete" not in item.get("action", "")]

    file_limit = min(MAX_P4_FILES, limits.max_files)
    if len(entries) > file_limit:
        omitted = len(entries) - file_limit
        entries = entries[:file_limit]
    else:
        omitted = 0

    checkout.mkdir(parents=True, exist_ok=False)
    materialized = 0
    materialized_bytes = 0
    unsafe = 0
    created_directories: set[str] = set()
    for index, entry in enumerate(entries):
        depot_file = entry.get("depotFile", "")
        revision = entry.get("rev", "")
        if not depot_file.startswith(depot_prefix) or not revision.isdigit():
            unsafe += 1
            continue
        relative = _p4_local_name(depot_file[len(depot_prefix):])
        try:
            destination = _safe_destination(checkout, os.fsencode(relative))
            _ensure_safe_parent(checkout, destination.parent, created_directories)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o644,
            )
            os.close(descriptor)
        except (OSError, RemoteScanError):
            unsafe += 1
            continue
        try:
            _run(
                ["p4", "print", "-q", "-o", str(destination), f"{depot_file}#{revision}"],
                timeout=timeout, env=environment, label="Perforce file materialization",
                disk_guard=(checkout, limits.min_free_bytes),
            )
        except Exception:
            _delete_file(destination)
            raise
        size = destination.lstat().st_size
        if materialized_bytes + size > limits.max_bytes:
            # The depot listing carries no sizes, so the byte budget is checked after each
            # print: the file that crosses it is removed and the rest are not fetched.
            _delete_file(destination)
            omitted += len(entries) - index
            break
        materialized_bytes += size
        materialized += 1

    changes = [
        int(item["change"]) for item in entries
        if item.get("change", "").isdigit()
    ]
    coverage = _Coverage()
    coverage.add(
        "materialization_budget", omitted,
        f"{omitted:,} depot file(s) were not fetched because the remote budget of "
        f"{limits.max_bytes:,} bytes / {file_limit:,} files was reached.",
        incomplete=True,
    )
    coverage.add(
        "paths_not_materialized", unsafe,
        f"{unsafe:,} depot file(s) could not be materialized safely.",
        incomplete=True,
    )
    return {
        "mode": "remote", "vcs": "p4", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": str(max(changes)) if changes else None,
        "branch": depot_root, "history_complete": False,
        "tracked_file_count": materialized,
        "omitted_file_count": omitted,
        **coverage.metadata(),
    }


def _rmtree(path: Path) -> None:
    """shutil.rmtree that clears read-only bits (Git pack files on Windows) and retries."""

    def retry(function, failed_path, _error) -> None:
        try:
            os.chmod(failed_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            parent = os.path.dirname(failed_path)
            if parent:
                os.chmod(parent, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
        except OSError:
            pass
        function(failed_path)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry)
    else:  # pragma: no cover - Python 3.11
        shutil.rmtree(path, onerror=lambda function, failed, info: retry(function, failed, info[1]))


def _remove_tree(path: Path) -> str | None:
    """Remove a temporary tree; return an error message instead of raising."""
    last_error = None
    for attempt in range(4):
        try:
            _rmtree(path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            last_error = exc
        if not os.path.lexists(path):
            return None
        time.sleep(0.25 * (attempt + 1))  # Windows releases file handles asynchronously
    return (
        f"Temporary remote checkout could not be removed: {path}"
        + (f" ({type(last_error).__name__}: {last_error})" if last_error else "")
    )


def _materialize(target: RemoteTarget, temporary: Path, *, timeout: int, limits: RemoteLimits) -> tuple[Path, dict]:
    checkout = temporary / "source"
    if target.vcs == "git":
        metadata = _git_checkout(
            target, checkout, temporary / "git-metadata", temporary, timeout=timeout, limits=limits,
        )
    elif target.vcs == "hg":
        metadata = _hg_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    elif target.vcs == "svn":
        metadata = _svn_checkout(target, checkout, timeout=timeout, limits=limits)
    elif target.vcs == "bzr":
        metadata = _bzr_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    elif target.vcs == "darcs":
        metadata = _darcs_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    elif target.vcs == "jj":
        metadata = _jj_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    elif target.vcs == "pijul":
        metadata = _pijul_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    elif target.vcs == "cvs":
        metadata = _cvs_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    elif target.vcs == "p4":
        metadata = _p4_checkout(target, checkout, timeout=timeout, limits=limits)
    elif target.vcs == "fossil":
        metadata = _fossil_checkout(target, checkout, temporary, timeout=timeout, limits=limits)
    else:
        raise RemoteScanError(f"Unsupported remote VCS backend: {target.vcs}")
    if target.vcs not in {"git", "p4"}:
        # These clients export the whole tree; the free-space guard bounds the export, and
        # the byte and file budgets are applied here, before analysis. Git and Perforce
        # apply them while fetching, file by file.
        removed_files, removed_bytes = _apply_budget(checkout, limits)
        _add_coverage(
            metadata, "materialization_budget", removed_files,
            f"{removed_files:,} file(s) ({removed_bytes:,} bytes) were removed before analysis "
            f"because the remote budget of {limits.max_bytes:,} bytes / {limits.max_files:,} "
            "files was reached.",
            incomplete=True,
        )
    return checkout, metadata


def _finalize_metadata(
    target: RemoteTarget, metadata: dict, *, acquired_at: str, seconds: float,
) -> dict:
    """Add the target-level facts every report records for a remote source."""
    result = dict(metadata)
    coverage = list(result.get("coverage") or [])
    notes = list(result.get("warnings") or [])
    if target.insecure_transport:
        notes.append("The repository was fetched over a transport without TLS.")
    result.update({
        "mode": "remote",
        "acquisition": "download",
        "vcs": target.vcs,
        "provider": target.provider,
        "url": target.clone_url,
        "repository": target.repository_name,
        "identity": target.identity,
        "ref": target.ref,
        "transport": target.transport,
        "transport_insecure": target.insecure_transport,
        "acquired_at": acquired_at,
        "acquisition_seconds": round(seconds, 3),
        "coverage": coverage,
        "coverage_gaps": [item["detail"] for item in coverage if item.get("incomplete")],
        "warnings": notes,
    })
    return result


@contextmanager
def remote_checkout(
    target: RemoteTarget,
    *,
    timeout: int = DEFAULT_REMOTE_TIMEOUT,
    workdir: Path | None = None,
    limits: RemoteLimits | None = None,
    allow_insecure_transport: bool = False,
    on_cleanup_error: Callable[[str], None] | None = None,
) -> Iterator[RemoteCheckout]:
    """Materialize ``target`` in a private temporary directory for the ``with`` body.

    Only materialization errors are reported as RemoteScanError; exceptions raised by the
    body (the scan itself) propagate unchanged. The temporary tree is removed on every
    exit path, including KeyboardInterrupt; a failed removal is passed to
    ``on_cleanup_error`` (default: a RuntimeWarning) rather than masking the outcome.
    """
    if timeout < 1 or timeout > 86_400:
        raise ValueError("--remote-timeout must be between 1 and 86400 seconds.")
    limits = limits or RemoteLimits()
    check_transport_policy(target, allow_insecure=allow_insecure_transport)
    parent = None
    if workdir is not None:
        parent = Path(workdir).expanduser().resolve()
        parent.mkdir(parents=True, exist_ok=True)
        if not parent.is_dir():
            raise RemoteScanError(f"--remote-workdir is not a directory: {parent}")
    free = _free_bytes(parent or Path(tempfile.gettempdir()))
    if free is not None and free < limits.min_free_bytes:
        raise RemoteScanError(
            f"Only {free // (1024 * 1024):,} MiB are free for the temporary checkout; PDT keeps "
            f"at least {limits.min_free_bytes // (1024 * 1024):,} MiB free. Use --remote-workdir "
            "to choose a larger filesystem."
        )
    temporary = Path(tempfile.mkdtemp(prefix="pdt-remote-", dir=parent))
    acquired_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    try:
        try:
            checkout, metadata = _materialize(target, temporary, timeout=timeout, limits=limits)
        except RemoteScanError:
            raise
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise RemoteScanError(
                f"Remote checkout failed for {target.provider} repository "
                f"{target.repository_name!r}: {type(exc).__name__}: "
                + sanitize_client_output(str(exc))
            ) from exc
        metadata = _finalize_metadata(
            target, metadata, acquired_at=acquired_at, seconds=time.monotonic() - started,
        )
        yield RemoteCheckout(checkout, metadata)
    finally:
        try:
            error = _remove_tree(temporary)
        except KeyboardInterrupt:
            # A second Ctrl-C during cleanup: try once more, then let it propagate.
            error = _remove_tree(temporary)
            if error:
                (on_cleanup_error or _warn_cleanup)(error)
            raise
        if error:
            (on_cleanup_error or _warn_cleanup)(error)


def _warn_cleanup(message: str) -> None:
    warnings.warn(message, RuntimeWarning, stacklevel=3)
