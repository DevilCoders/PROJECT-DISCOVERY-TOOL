"""Remote repository URL parsing and safe, read-only source materialization.

Git checkouts are created without a working-tree checkout. PDT reads the Git tree
and blob objects directly, so project smudge filters, checkout hooks and submodule
commands are never run. Other VCS adapters use read-only clone/export/print operations
and omit repository control metadata from the temporary analysis tree where possible.
No adapter pushes changes or modifies the remote repository.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shutil
import subprocess
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit


MAX_URL_FILE_BYTES = 4 * 1024 * 1024
MAX_REMOTE_TARGETS = 10_000
MAX_URL_LINE_CHARS = 8_192
MAX_GIT_PATH_BYTES = 1 * 1024 * 1024
MAX_SYMLINK_TARGET_BYTES = 4_096
DEFAULT_REMOTE_TIMEOUT = 600
MAX_P4_LISTING_BYTES = 64 * 1024 * 1024
MAX_P4_FILES = 50_000
REMOTE_VCS = (
    "auto", "git", "hg", "svn", "bzr", "bazaar", "darcs",
    "jj", "pijul", "cvs", "p4", "perforce",
)
_VCS_ALIASES = {"bazaar": "bzr", "perforce": "p4"}
_VCS_PREFIXES = (
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


class RemoteScanError(ValueError):
    """A remote target could not be validated, fetched or safely materialized."""


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


@dataclass(frozen=True, slots=True)
class RemoteCheckout:
    path: Path
    metadata: dict


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


def parse_remote_target(raw_url: str, *, vcs: str = "auto") -> RemoteTarget:
    if vcs not in REMOTE_VCS:
        raise ValueError(f"--vcs must be one of: {', '.join(REMOTE_VCS)}")
    selected_vcs = _VCS_ALIASES.get(vcs, vcs)
    raw = raw_url.strip()
    if not raw or len(raw) > MAX_URL_LINE_CHARS:
        raise RemoteScanError("Repository URL is empty or exceeds the supported line length.")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise RemoteScanError("Repository URLs cannot contain control characters.")

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
        path = "/" + scp.group("path").lstrip("/")
        clone_url = f"{scp.group('user')}@{host}:{scp.group('path')}"
        scheme = "ssh"
    else:
        if not _SCHEME_URL.match(clone_url):
            raise RemoteScanError(
                "Use an HTTPS/SSH repository URL, a Git SSH scp-style URL, or a VCS-prefixed "
                "URL such as hg+https://, svn+https://, bzr+https://, darcs+https://, "
                "jj+https://, pijul+https://, cvs+pserver:// or p4+ssl://."
            )
        parsed = urlsplit(clone_url)
        scheme = parsed.scheme.lower()
        allowed_schemes = {
            "git": {"https", "ssh", "git"},
            "jj": {"https", "ssh", "git"},
            "hg": {"https", "ssh", "http"},
            "svn": {"https", "ssh", "svn", "http"},
            "bzr": {"https", "ssh", "bzr"},
            "darcs": {"https", "ssh", "http"},
            "pijul": {"https", "ssh", "http"},
            "cvs": {"pserver", "ssh"},
            "p4": {"ssl", "tcp"},
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
        else:
            provider = _provider(host)
        if selected_vcs == "cvs":
            parts = [part for part in path.split("/") if part]
            if len(parts) < 2:
                raise RemoteScanError(
                    "CVS URL must include both the repository root and module, "
                    "for example cvs+pserver://host/cvsroot/project."
                )
        if selected_vcs == "p4":
            parts = [part for part in path.split("/") if part]
            if len(parts) < 2:
                raise RemoteScanError(
                    "Perforce URL must include a depot and project path, "
                    "for example p4+ssl://server:1666/depot/project."
                )
        clone_url = urlunsplit((scheme, netloc, path, "", ""))

    if scp:
        provider = _provider(host)
    if scp and selected_vcs not in {"git", "jj"}:
        raise RemoteScanError("SCP-style URLs are supported only for Git and Jujutsu remotes.")

    if selected_vcs == "git" and scheme not in {"https", "ssh", "git"}:
        raise RemoteScanError("Git repository transport must use HTTPS, SSH or git://.")
    if selected_vcs == "svn" and scheme == "git":
        raise RemoteScanError("Subversion does not support the git:// transport.")
    if selected_vcs == "hg" and scheme == "git":
        raise RemoteScanError("Mercurial does not support the git:// transport.")

    path_for_name = path.rstrip("/").split("/")[-1] or host
    repository_name = path_for_name[:-4] if path_for_name.lower().endswith(".git") else path_for_name
    repository_name = repository_name or host
    if scp:
        safe_identity = f"ssh://{host}/{path.lstrip('/')}"
    else:
        normalized = urlsplit(clone_url)
        safe_identity = urlunsplit((
            scheme.lower(), (normalized.netloc or "").lower(), normalized.path, "", "",
        ))
    digest = hashlib.sha256(
        f"{selected_vcs}|{safe_identity}".encode("utf-8")
    ).hexdigest()[:10]
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", repository_name).strip("-.")[:48] or "repository"
    insecure = scheme in {"git", "http", "svn", "bzr", "tcp", "pserver"}
    return RemoteTarget(
        input_url=raw,
        clone_url=clone_url,
        provider=provider,
        vcs=selected_vcs,
        repository_name=repository_name,
        output_name=f"{slug}-{digest}",
        identity=digest,
        insecure_transport=insecure,
    )

def load_remote_targets(path: Path, *, vcs: str = "auto") -> list[RemoteTarget]:
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
            target = parse_remote_target(value, vcs=vcs)
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


def _run(
    command: list[str],
    *,
    timeout: int,
    env: dict[str, str],
    label: str,
    check: bool = True,
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, env=env, check=False,
        )
    except FileNotFoundError as exc:
        executable = command[0]
        raise RemoteScanError(
            f"{label} requires the '{executable}' client to be installed and available on PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RemoteScanError(f"{label} exceeded the {timeout}-second remote operation timeout.") from exc
    if check and result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        detail = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1<redacted>@", detail)
        detail = detail[:1_500]
        raise RemoteScanError(
            f"{label} failed with exit code {result.returncode}"
            + (f": {detail}" if detail else ".")
        )
    return result


def _safe_destination(root: Path, raw_path: bytes) -> Path:
    name = os.fsdecode(raw_path)
    if not name or "\x00" in name or "\\" in name:
        raise RemoteScanError("Repository tree contains an unsafe path.")
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise RemoteScanError("Repository tree contains an absolute path.")
    if any(part in {"", ".", ".."} for part in posix.parts):
        raise RemoteScanError("Repository tree contains a path traversal component.")
    if posix.parts and posix.parts[0].lower() == ".git":
        raise RemoteScanError("Repository tree attempts to overwrite Git metadata.")
    return root.joinpath(*posix.parts)


def _ensure_safe_parent(root: Path, parent: Path) -> None:
    relative = parent.relative_to(root)
    current = root
    for component in relative.parts:
        current = current / component
        try:
            current.lstat()
        except FileNotFoundError:
            current.mkdir()
            continue
        if current.is_symlink() or not current.is_dir():
            raise RemoteScanError("Repository tree has a non-directory ancestor collision.")


def _read_blob(
    output,
    process: subprocess.Popen,
    object_id: bytes,
    *,
    symlink: bool = False,
) -> tuple[bytes, int]:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(object_id + b"\n")
    process.stdin.flush()
    header = process.stdout.readline(512)
    fields = header.rstrip(b"\n").split()
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


def _extract_git_tree(
    checkout: Path,
    git_env: dict[str, str],
    *,
    timeout: int,
) -> dict:
    tree_command = ["git", "-C", str(checkout), "ls-tree", "-r", "-z", "--full-tree", "HEAD"]
    blob_command = ["git", "-C", str(checkout), "cat-file", "--batch"]
    try:
        tree = subprocess.Popen(
            tree_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=git_env,
        )
        blobs = subprocess.Popen(
            blob_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=git_env,
        )
    except FileNotFoundError as exc:
        raise RemoteScanError("Git client is required for online Git repository scans.") from exc

    file_count = 0
    symlink_count = 0
    omitted_symlink_count = 0
    submodule_count = 0
    submodule_paths: list[str] = []
    lfs_pointer_count = 0
    omitted_path_count = 0

    assert tree.stdout is not None and blobs.stdin is not None
    assert blobs.stdout is not None
    try:
        for entry in _iter_nul_records(tree.stdout):
            header, separator, raw_path = entry.partition(b"\t")
            fields = header.split()
            if not separator or len(fields) != 3:
                raise RemoteScanError("Git returned a malformed tree entry.")
            mode, object_type, object_id = fields
            if mode == b"160000" and object_type == b"commit":
                submodule_count += 1
                if len(submodule_paths) < 100:
                    submodule_paths.append(os.fsdecode(raw_path))
                try:
                    destination = _safe_destination(checkout, raw_path)
                    _ensure_safe_parent(checkout, destination.parent)
                    destination.mkdir(exist_ok=True)
                except (OSError, RemoteScanError):
                    omitted_path_count += 1
                continue
            if object_type != b"blob" or mode not in {b"100644", b"100755", b"120000"}:
                omitted_path_count += 1
                continue

            symlink = mode == b"120000"
            destination = None
            output = None
            try:
                destination = _safe_destination(checkout, raw_path)
                _ensure_safe_parent(checkout, destination.parent)
                if symlink:
                    pass
                else:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    flags |= getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(destination, flags, 0o755 if mode == b"100755" else 0o644)
                    output = os.fdopen(descriptor, "wb")
            except (OSError, RemoteScanError):
                omitted_path_count += 1

            try:
                captured, size = _read_blob(
                    output, blobs, object_id, symlink=symlink,
                )
            finally:
                if output is not None:
                    output.close()
            if symlink:
                target = os.fsdecode(captured)
                normalized_target = posixpath.normpath(posixpath.join(
                    posixpath.dirname(os.fsdecode(raw_path)), target,
                ))
                if (
                    destination is None
                    or not captured or len(captured) > MAX_SYMLINK_TARGET_BYTES
                    or "\\" in target or PurePosixPath(target).is_absolute()
                    or PureWindowsPath(target).is_absolute() or PureWindowsPath(target).drive
                    or normalized_target == ".." or normalized_target.startswith("../")
                ):
                    omitted_symlink_count += 1
                    continue
                try:
                    os.symlink(target, destination)
                    symlink_count += 1
                except (OSError, NotImplementedError):
                    omitted_symlink_count += 1
                continue
            if output is not None:
                file_count += 1
            if captured.startswith(b"version https://git-lfs.github.com/spec/v1"):
                lfs_pointer_count += 1
        tree_code = tree.wait(timeout=timeout)
        tree_error = tree.stderr.read() if tree.stderr is not None else b""
        if tree_code:
            raise RemoteScanError(
                "git ls-tree failed: " + tree_error.decode("utf-8", errors="replace")[:1_000]
            )
        blobs.stdin.close()
        blob_code = blobs.wait(timeout=timeout)
        blob_error = blobs.stderr.read() if blobs.stderr is not None else b""
        if blob_code:
            raise RemoteScanError(
                "git cat-file failed: " + blob_error.decode("utf-8", errors="replace")[:1_000]
            )
    except BaseException:
        for process in (tree, blobs):
            if process.poll() is None:
                process.kill()
                process.wait()
        raise

    return {
        "tracked_file_count": file_count,
        "materialized_symlink_count": symlink_count,
        "omitted_symlink_count": omitted_symlink_count,
        "submodule_count": submodule_count,
        "submodule_paths_sample": submodule_paths,
        "git_lfs_pointer_count": lfs_pointer_count,
        "omitted_tree_path_count": omitted_path_count,
    }


def _git_checkout(
    target: RemoteTarget,
    checkout: Path,
    git_dir: Path,
    temporary: Path,
    *,
    timeout: int,
) -> dict:
    template = temporary / "empty-template"
    hooks = temporary / "empty-hooks"
    template.mkdir()
    hooks.mkdir()
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_LFS_SKIP_SMUDGE"] = "1"
    clone_command = [
        "git", "-c", f"core.hooksPath={hooks}",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.ssh.allow=always",
        "-c", "protocol.git.allow=always",
        "clone", "--no-checkout", "--depth", "1", "--single-branch", "--no-tags",
        "--no-recurse-submodules", "--template", str(template),
        "--separate-git-dir", str(git_dir), "--", target.clone_url, str(checkout),
    ]
    _run(clone_command, timeout=timeout, env=environment, label="Git clone")
    revision = _run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        timeout=timeout, env=environment, label="Git revision lookup",
    ).stdout.decode("ascii", errors="replace").strip()
    branch = _run(
        ["git", "-C", str(checkout), "symbolic-ref", "--short", "-q", "HEAD"],
        timeout=timeout, env=environment, label="Git branch lookup", check=False,
    ).stdout.decode("utf-8", errors="replace").strip() or None
    counts = _extract_git_tree(checkout, environment, timeout=timeout)

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

    warnings = []
    if counts["submodule_count"]:
        warnings.append(
            f"{counts['submodule_count']} Git submodule(s) were inventoried but not fetched."
        )
    if counts["git_lfs_pointer_count"]:
        warnings.append(
            f"{counts['git_lfs_pointer_count']} Git LFS pointer file(s) were found; LFS objects "
            "were not downloaded."
        )
    if counts["omitted_symlink_count"]:
        warnings.append(
            f"{counts['omitted_symlink_count']} Git symlink(s) could not be safely materialized."
        )
    if counts["omitted_tree_path_count"]:
        warnings.append(
            f"{counts['omitted_tree_path_count']} tracked path(s) could not be materialized safely."
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
        "warnings": warnings,
        **counts,
    }


def _copy_tree_without_metadata(
    source: Path,
    destination: Path,
    *,
    metadata_names: tuple[str, ...],
) -> None:
    """Copy a VCS working tree without copying its control directory."""
    if not source.is_dir():
        raise RemoteScanError("VCS client did not create the expected working directory.")
    shutil.copytree(
        source,
        destination,
        symlinks=True,
        ignore=shutil.ignore_patterns(*metadata_names),
    )


def _hg_checkout(target: RemoteTarget, checkout: Path, temporary: Path, *, timeout: int) -> dict:
    environment = os.environ.copy()
    environment["HGPLAIN"] = "1"
    empty_hgrc = temporary / "empty-hgrc"
    empty_hgrc.write_text("", encoding="utf-8")
    environment["HGRCPATH"] = str(empty_hgrc)
    repository = temporary / "hg-repository"
    _run(
        ["hg", "--noninteractive", "clone", "--noupdate", target.clone_url, str(repository)],
        timeout=timeout, env=environment, label="Mercurial clone",
    )
    revision = _run(
        ["hg", "--cwd", str(repository), "log", "-r", "tip", "-T", "{node}"],
        timeout=timeout, env=environment, label="Mercurial revision lookup",
    ).stdout.decode("ascii", errors="replace").strip()
    branch = _run(
        ["hg", "--cwd", str(repository), "log", "-r", "tip", "-T", "{branch}"],
        timeout=timeout, env=environment, label="Mercurial branch lookup",
    ).stdout.decode("utf-8", errors="replace").strip()
    # Archive committed files without updating an untrusted working copy.
    _run(
        ["hg", "--cwd", str(repository), "archive", "--no-decode", "--rev", "tip", "--type", "files", str(checkout)],
        timeout=timeout, env=environment, label="Mercurial source export",
    )
    return {
        "mode": "remote", "vcs": "hg", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": revision, "branch": branch, "history_complete": True,
        "warnings": [],
    }


def _svn_checkout(target: RemoteTarget, checkout: Path, *, timeout: int) -> dict:
    environment = os.environ.copy()
    revision = _run(
        ["svn", "info", "--show-item", "revision", target.clone_url],
        timeout=timeout, env=environment, label="Subversion revision lookup",
    ).stdout.decode("utf-8", errors="replace").strip()
    _run(
        ["svn", "export", "--non-interactive", "--ignore-externals",
         target.clone_url, str(checkout)],
        timeout=timeout, env=environment, label="Subversion source export",
    )
    return {
        "mode": "remote", "vcs": "svn", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": revision, "branch": None, "history_complete": False,
        "externals_fetched": False,
        "warnings": ["Subversion externals were not fetched; the source was exported without .svn metadata."],
    }


def _bzr_checkout(target: RemoteTarget, checkout: Path, temporary: Path, *, timeout: int) -> dict:
    executable = shutil.which("brz") or shutil.which("bzr")
    if executable is None:
        raise RemoteScanError("Bazaar/Breezy remote scans require the 'brz' or 'bzr' client on PATH.")
    environment = os.environ.copy()
    environment["BRZ_HOME"] = str(temporary / "brz-home")
    environment["BRZ_PLUGIN_PATH"] = ""
    _run(
        [executable, "export", "--quiet", "--format=dir", str(checkout), target.clone_url],
        timeout=timeout, env=environment, label="Bazaar/Breezy source export",
    )
    return {
        "mode": "remote", "vcs": "bzr", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": None, "branch": None, "history_complete": False,
        "warnings": ["Bazaar/Breezy export contains the committed source tree; history metadata is not retained."],
    }


def _darcs_checkout(target: RemoteTarget, checkout: Path, temporary: Path, *, timeout: int) -> dict:
    environment = os.environ.copy()
    environment["DARCS_DONT_COLOR"] = "1"
    repository = temporary / "darcs-repository"
    _run(
        ["darcs", "clone", "--lazy", "--no-set-default", target.clone_url, str(repository)],
        timeout=timeout, env=environment, label="Darcs clone",
    )
    _copy_tree_without_metadata(
        repository, checkout, metadata_names=("_darcs",),
    )
    return {
        "mode": "remote", "vcs": "darcs", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": None, "branch": None, "history_complete": False,
        "warnings": ["Darcs source was materialized from a lazy clone; repository metadata was excluded."],
    }


def _jj_checkout(target: RemoteTarget, checkout: Path, temporary: Path, *, timeout: int) -> dict:
    repository = temporary / "jj-repository"
    environment = os.environ.copy()
    _run(
        ["jj", "git", "clone", "--no-colocate", target.clone_url, str(repository)],
        timeout=timeout, env=environment, label="Jujutsu Git-backed clone",
    )
    revision = _run(
        ["jj", "--repository", str(repository), "log", "-r", "@", "--no-graph", "-T", "commit_id"],
        timeout=timeout, env=environment, label="Jujutsu revision lookup",
    ).stdout.decode("utf-8", errors="replace").strip()
    _copy_tree_without_metadata(
        repository, checkout, metadata_names=(".jj", ".git"),
    )
    return {
        "mode": "remote", "vcs": "jj", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": revision or None, "branch": None, "history_complete": False,
        "warnings": ["Jujutsu remote mode currently supports Git-backed Jujutsu repositories."],
    }


def _pijul_checkout(target: RemoteTarget, checkout: Path, temporary: Path, *, timeout: int) -> dict:
    repository = temporary / "pijul-repository"
    environment = os.environ.copy()
    _run(
        ["pijul", "clone", target.clone_url, str(repository)],
        timeout=timeout, env=environment, label="Pijul clone",
    )
    _copy_tree_without_metadata(
        repository, checkout, metadata_names=(".pijul",),
    )
    return {
        "mode": "remote", "vcs": "pijul", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": None, "branch": "main", "history_complete": False,
        "warnings": ["Pijul source was materialized from the main channel; repository metadata was excluded."],
    }


def _cvs_checkout(target: RemoteTarget, checkout: Path, temporary: Path, *, timeout: int) -> dict:
    parsed = urlsplit(target.clone_url)
    components = [part for part in parsed.path.split("/") if part]
    if len(components) < 2:
        raise RemoteScanError("CVS URL must include a repository root and module.")
    module = components[-1]
    repository_root = "/" + "/".join(components[:-1])
    username = parsed.username
    user_prefix = f"{username}@" if username else ""
    port_suffix = f":{parsed.port}" if parsed.port is not None else ""
    if parsed.scheme == "pserver":
        cvsroot = f":pserver:{user_prefix}{parsed.hostname}{port_suffix}:{repository_root}"
    else:
        cvsroot = f":ext:{user_prefix}{parsed.hostname}:{repository_root}"
    repository = temporary / "cvs-repository"
    _run(
        ["cvs", "-d", cvsroot, "checkout", "-P", "-d", str(repository), module],
        timeout=timeout, env=os.environ.copy(), label="CVS checkout",
    )
    _copy_tree_without_metadata(
        repository, checkout, metadata_names=("CVS",),
    )
    return {
        "mode": "remote", "vcs": "cvs", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": None, "branch": None, "history_complete": False,
        "warnings": ["CVS working-copy metadata was excluded; revision history was not imported."],
    }


def _p4_checkout(target: RemoteTarget, checkout: Path, *, timeout: int) -> dict:
    parsed = urlsplit(target.clone_url)
    depot_parts = [part for part in parsed.path.split("/") if part]
    if len(depot_parts) < 2 or parsed.port is None:
        raise RemoteScanError("Perforce URL must identify //depot/project and a server port.")
    depot_root = "//" + "/".join(depot_parts)
    depot_prefix = depot_root.rstrip("/") + "/"
    depot_pattern = depot_root.rstrip("/") + "/..."
    port = f"{parsed.scheme}:{parsed.hostname}:{parsed.port}"
    environment = os.environ.copy()
    environment["P4PORT"] = port
    environment["P4CONFIG"] = ""
    listing = _run(
        ["p4", "-ztag", "files", depot_pattern],
        timeout=timeout, env=environment, label="Perforce depot listing",
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

    if len(entries) > MAX_P4_FILES:
        omitted = len(entries) - MAX_P4_FILES
        entries = entries[:MAX_P4_FILES]
    else:
        omitted = 0

    checkout.mkdir(parents=True, exist_ok=False)
    materialized = 0
    for entry in entries:
        depot_file = entry.get("depotFile", "")
        revision = entry.get("rev", "")
        if not depot_file.startswith(depot_prefix) or not revision.isdigit():
            continue
        relative = depot_file[len(depot_prefix):]
        try:
            destination = _safe_destination(checkout, os.fsencode(relative))
            _ensure_safe_parent(checkout, destination.parent)
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o644,
            )
            os.close(descriptor)
        except (OSError, RemoteScanError):
            continue
        try:
            _run(
                ["p4", "print", "-q", "-o", str(destination), f"{depot_file}#{revision}"],
                timeout=timeout, env=environment, label="Perforce file materialization",
            )
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        materialized += 1

    changes = [
        int(item["change"]) for item in entries
        if item.get("change", "").isdigit()
    ]
    warnings = []
    if omitted:
        warnings.append(f"{omitted:,} depot file(s) were not fetched because the Perforce file-count limit was reached.")
    return {
        "mode": "remote", "vcs": "p4", "provider": target.provider,
        "url": target.clone_url, "repository": target.repository_name,
        "revision": str(max(changes)) if changes else None,
        "branch": depot_root, "history_complete": False,
        "tracked_file_count": materialized,
        "omitted_file_count": omitted,
        "warnings": warnings,
    }


@contextmanager
def remote_checkout(
    target: RemoteTarget,
    *,
    timeout: int = DEFAULT_REMOTE_TIMEOUT,
) -> Iterator[RemoteCheckout]:
    if timeout < 1 or timeout > 86_400:
        raise ValueError("--remote-timeout must be between 1 and 86400 seconds.")
    with tempfile.TemporaryDirectory(prefix="pdt-remote-") as temporary_name:
        temporary = Path(temporary_name)
        checkout = temporary / "source"
        git_dir = temporary / "git-metadata"
        try:
            if target.vcs == "git":
                metadata = _git_checkout(
                    target, checkout, git_dir, temporary, timeout=timeout,
                )
            elif target.vcs == "hg":
                metadata = _hg_checkout(target, checkout, temporary, timeout=timeout)
            elif target.vcs == "svn":
                metadata = _svn_checkout(target, checkout, timeout=timeout)
            elif target.vcs == "bzr":
                metadata = _bzr_checkout(target, checkout, temporary, timeout=timeout)
            elif target.vcs == "darcs":
                metadata = _darcs_checkout(target, checkout, temporary, timeout=timeout)
            elif target.vcs == "jj":
                metadata = _jj_checkout(target, checkout, temporary, timeout=timeout)
            elif target.vcs == "pijul":
                metadata = _pijul_checkout(target, checkout, temporary, timeout=timeout)
            elif target.vcs == "cvs":
                metadata = _cvs_checkout(target, checkout, temporary, timeout=timeout)
            elif target.vcs == "p4":
                metadata = _p4_checkout(target, checkout, timeout=timeout)
            else:
                raise RemoteScanError(f"Unsupported remote VCS backend: {target.vcs}")
            if target.insecure_transport:
                metadata["warnings"] = list(metadata.get("warnings", [])) + [
                    "The repository was fetched over a transport without TLS."
                ]
            yield RemoteCheckout(checkout, metadata)
        except RemoteScanError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise RemoteScanError(
                f"Remote checkout failed for {target.provider} repository "
                f"{target.repository_name!r}: {type(exc).__name__}: {exc}"
            ) from exc
