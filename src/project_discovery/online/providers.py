"""Read-only provider API clients for the no-download online mode.

GitHub (REST v3, also GitHub Enterprise Server), GitLab (REST v4, gitlab.com and
self-managed), Bitbucket Cloud (REST 2.0) and Gitea/Forgejo (REST v1, including
Codeberg). Each client resolves a ref to a commit, lists that commit's tree, and returns
file contents as bytes held in memory. Nothing is written to disk.

Every request counts against a per-repository request budget; rate-limit exhaustion and
budget exhaustion raise :class:`~project_discovery.online.http.NetworkError` with kind
``rate_limit`` or ``budget`` so the caller can report the remaining content as UNKNOWN.
"""
from __future__ import annotations

import os
import posixpath
import re
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Any

from .credentials import ApiCredential
from .http import HttpClient, NetworkError, RateLimiter, validate_service_url
from .repositories import RemoteScanError

API_PROVIDERS = ("auto", "github", "gitlab", "bitbucket", "gitea")
PUBLIC_API_URLS = {
    ("github", "github.com"): "https://api.github.com",
    ("gitlab", "gitlab.com"): "https://gitlab.com/api/v4",
    ("bitbucket", "bitbucket.org"): "https://api.bitbucket.org/2.0",
}
_PROVIDER_BY_NAME = {
    "GitHub": "github", "GitHub Enterprise": "github",
    "GitLab": "gitlab", "GitLab self-managed": "gitlab",
    "Bitbucket": "bitbucket",
    "Gitea": "gitea", "Forgejo": "gitea", "Gogs": "gitea",
}
_HOST_VARIABLE = re.compile(r"[^A-Z0-9]")
MAX_TREE_ENTRIES = 2_000_000
MAX_TREE_PAGES = 10_000


class ProviderError(RemoteScanError):
    """The repository cannot be read through the provider API (not found, no access...)."""


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    kind: str  # "file", "symlink", "submodule" or "directory"
    size: int | None = None
    object_id: str | None = None
    executable: bool = False


@dataclass(slots=True)
class ResolvedRevision:
    revision: str
    branch: str | None
    default_branch: str | None
    private: bool | None
    tree_id: str | None = None


class RequestBudget:
    """Thread-safe cap on API requests for one repository."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("the API request budget must be at least 1")
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    def take(self) -> None:
        with self._lock:
            if self.used >= self.limit:
                raise NetworkError(
                    f"the request budget of {self.limit:,} API requests is exhausted", kind="budget",
                )
            self.used += 1


def api_provider_for(target_provider: str, explicit: str = "auto") -> str:
    if explicit != "auto":
        if explicit not in API_PROVIDERS:
            raise ValueError(f"--api-provider must be one of: {', '.join(API_PROVIDERS)}")
        return explicit
    provider = _PROVIDER_BY_NAME.get(target_provider)
    if provider is None:
        raise ProviderError(
            f"No-download mode supports GitHub, GitLab, Bitbucket Cloud and Gitea/Forgejo; "
            f"{target_provider} repositories need --api-provider, or the download mode."
        )
    return provider


def default_api_url(provider: str, host: str) -> str:
    """Public API endpoints, or the provider's standard path on a self-hosted host."""
    host = host.lower()
    override = os.environ.get("PDT_API_URL_" + _HOST_VARIABLE.sub("_", host.upper()))
    if override:
        return override
    public = PUBLIC_API_URLS.get((provider, host))
    if public:
        return public
    if provider == "bitbucket":
        raise ProviderError(
            "Bitbucket Data Center/Server uses a different API; only Bitbucket Cloud "
            "(bitbucket.org) is supported in no-download mode."
        )
    suffix = {"github": "/api/v3", "gitlab": "/api/v4", "gitea": "/api/v1"}[provider]
    return f"https://{host}{suffix}"


def split_repository(clone_url: str) -> tuple[str, str]:
    """Return (host, repository path) for an HTTPS, SSH or scp-style Git URL."""
    if "://" in clone_url:
        parsed = urllib.parse.urlsplit(clone_url)
        host, path = (parsed.hostname or "").lower(), parsed.path
    else:
        user_host, _, path = clone_url.partition(":")
        host = user_host.rpartition("@")[2].lower()
    path = path.strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    parts = [part for part in path.split("/") if part]
    if not host or len(parts) < 2 or any(part in {".", ".."} for part in parts):
        raise ProviderError(f"Cannot derive an owner/repository path from {clone_url!r}.")
    return host, "/".join(parts)


def _quote_path(path: str) -> str:
    return "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))


def safe_tree_path(path: Any) -> str | None:
    """Repository-relative POSIX path, or None if it could escape or is malformed."""
    if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
        return None
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return None
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return path


def _link_next(headers) -> str | None:
    header = headers.get("Link") if headers else None
    if not header:
        return None
    for part in header.split(","):
        section = part.strip()
        if 'rel="next"' in section and section.startswith("<"):
            return section[1:section.index(">")]
    return None


class ProviderClient:
    name = ""

    def __init__(
        self, http: HttpClient, *, api_url: str, repository: str, host: str,
        credential: ApiCredential | None, budget: RequestBudget, requests_per_second: int = 10,
    ) -> None:
        self.http = http
        self.api_url = validate_service_url(api_url, label="provider API URL")
        self.repository = repository
        self.host = host
        self.credential = credential
        self.budget = budget
        self.limiter = RateLimiter(requests_per_second, 1.0)
        api = urllib.parse.urlsplit(self.api_url)
        self._api_origin = (api.scheme, api.hostname, api.port)

    def _url(self, path_or_url: str) -> str:
        if "://" in path_or_url:
            parsed = urllib.parse.urlsplit(path_or_url)
            if (parsed.scheme, parsed.hostname, parsed.port) != self._api_origin:
                raise NetworkError("the provider returned a pagination link to another host", kind="protocol")
            return path_or_url
        return self.api_url + path_or_url

    def _request(self, path_or_url: str, *, accept: str = "application/json", max_bytes: int = 64 * 1024 * 1024,
                 not_found_ok: bool = False, extra_headers: dict[str, str] | None = None):
        self.budget.take()
        return self.http.request(
            "GET", self._url(path_or_url),
            headers={"Accept": accept, **(extra_headers or {})},
            secret_headers=self.credential.headers() if self.credential else None,
            limiter=self.limiter, max_bytes=max_bytes, not_found_ok=not_found_ok,
        )

    def _json(self, path_or_url: str, *, not_found_ok: bool = False, accept: str = "application/json"):
        import json

        status, data, headers = self._request(path_or_url, not_found_ok=not_found_ok, accept=accept)
        if status == 404:
            return None, headers
        try:
            return json.loads(data.decode("utf-8")), headers
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise NetworkError(f"{self.host} API returned invalid JSON", kind="protocol") from exc

    def _not_found(self) -> ProviderError:
        hint = "" if self.credential else " If it is private, provide a token (see docs/guides/ONLINE_MODE.md)."
        return ProviderError(f"{self.name} repository {self.repository!r} was not found or is not accessible.{hint}")

    # Interface -------------------------------------------------------------
    def resolve(self, ref: str | None) -> ResolvedRevision:  # pragma: no cover - abstract
        raise NotImplementedError

    def tree(self, revision: ResolvedRevision) -> tuple[list[TreeEntry], bool]:  # pragma: no cover
        raise NotImplementedError

    def read(self, entry: TreeEntry, revision: ResolvedRevision, max_bytes: int) -> bytes:  # pragma: no cover
        raise NotImplementedError


def _kind_for_mode(mode: str | None, object_type: str | None) -> tuple[str, bool] | None:
    if object_type == "tree" or mode in {"040000", "40000"}:
        return "directory", False
    if object_type == "commit" or mode == "160000":
        return "submodule", False
    if mode == "120000":
        return "symlink", False
    if object_type in {None, "blob"}:
        return "file", mode == "100755"
    return None


class GitHubClient(ProviderClient):
    name = "GitHub"
    _ACCEPT = "application/vnd.github+json"

    def _repo(self) -> str:
        owner, _, name = self.repository.partition("/")
        return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"

    def _get(self, path, *, not_found_ok=False):
        return self._json(path, not_found_ok=not_found_ok, accept=self._ACCEPT)

    def resolve(self, ref):
        info, _ = self._get(self._repo(), not_found_ok=True)
        if not isinstance(info, dict):
            raise self._not_found()
        default_branch = info.get("default_branch")
        target = ref or default_branch
        if not target:
            raise ProviderError("The GitHub repository is empty (no default branch).")
        commit, _ = self._get(f"{self._repo()}/commits/{urllib.parse.quote(target, safe='')}", not_found_ok=True)
        if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str):
            raise ProviderError(f"GitHub ref {target!r} was not found in {self.repository}.")
        tree = ((commit.get("commit") or {}).get("tree") or {}).get("sha")
        return ResolvedRevision(
            commit["sha"], target if ref is None or ref == default_branch else None,
            default_branch, info.get("private"), tree if isinstance(tree, str) else commit["sha"],
        )

    def _entries(self, payload, prefix: str = "") -> list[TreeEntry]:
        entries = []
        for item in payload.get("tree", []) if isinstance(payload, dict) else []:
            if not isinstance(item, dict):
                continue
            path = safe_tree_path((prefix + "/" if prefix else "") + str(item.get("path", "")))
            kind = _kind_for_mode(item.get("mode"), item.get("type"))
            if path is None or kind is None:
                entries.append(TreeEntry(str(item.get("path", "?")), "invalid"))
                continue
            size = item.get("size") if isinstance(item.get("size"), int) else None
            entries.append(TreeEntry(path, kind[0], size, item.get("sha"), kind[1]))
        return entries

    def tree(self, revision):
        payload, _ = self._get(f"{self._repo()}/git/trees/{revision.tree_id}?recursive=1")
        if not isinstance(payload, dict):
            raise NetworkError("GitHub returned a malformed tree", kind="protocol")
        if not payload.get("truncated"):
            return self._entries(payload), False
        # Very large trees: walk directory by directory (one request per directory).
        entries: list[TreeEntry] = []
        pending = [("", revision.tree_id)]
        while pending:
            prefix, sha = pending.pop()
            listing, _ = self._get(f"{self._repo()}/git/trees/{sha}")
            for entry in self._entries(listing, prefix):
                entries.append(entry)
                if entry.kind == "directory" and entry.object_id:
                    pending.append((entry.path, entry.object_id))
            if len(entries) > MAX_TREE_ENTRIES:
                return entries, True
        return entries, False

    def read(self, entry, revision, max_bytes):
        _, data, _ = self._request(
            f"{self._repo()}/git/blobs/{urllib.parse.quote(str(entry.object_id), safe='')}",
            accept="application/vnd.github.raw", max_bytes=max_bytes,
        )
        return data


class GitLabClient(ProviderClient):
    name = "GitLab"

    def _project(self) -> str:
        return "/projects/" + urllib.parse.quote(self.repository, safe="")

    def resolve(self, ref):
        info, _ = self._json(self._project(), not_found_ok=True)
        if not isinstance(info, dict):
            raise self._not_found()
        default_branch = info.get("default_branch")
        target = ref or default_branch
        if not target:
            raise ProviderError("The GitLab repository is empty (no default branch).")
        commit, _ = self._json(
            f"{self._project()}/repository/commits/{urllib.parse.quote(target, safe='')}", not_found_ok=True,
        )
        if not isinstance(commit, dict) or not isinstance(commit.get("id"), str):
            raise ProviderError(f"GitLab ref {target!r} was not found in {self.repository}.")
        return ResolvedRevision(
            commit["id"], target if ref is None or ref == default_branch else None,
            default_branch, info.get("visibility") == "private" if info.get("visibility") else None,
        )

    def tree(self, revision):
        entries: list[TreeEntry] = []
        url = (f"{self._project()}/repository/tree?ref={urllib.parse.quote(revision.revision, safe='')}"
               "&recursive=true&per_page=100&pagination=keyset")
        pages = 0
        while url:
            payload, headers = self._json(url)
            if not isinstance(payload, list):
                raise NetworkError("GitLab returned a malformed tree page", kind="protocol")
            for item in payload:
                if not isinstance(item, dict):
                    continue
                path = safe_tree_path(item.get("path"))
                kind = _kind_for_mode(item.get("mode"), item.get("type"))
                if path is None or kind is None:
                    entries.append(TreeEntry(str(item.get("path", "?")), "invalid"))
                    continue
                entries.append(TreeEntry(path, kind[0], None, item.get("id"), kind[1]))
            pages += 1
            if len(entries) > MAX_TREE_ENTRIES or pages >= MAX_TREE_PAGES:
                return entries, True
            url = _link_next(headers)
        return entries, False

    def read(self, entry, revision, max_bytes):
        _, data, _ = self._request(
            f"{self._project()}/repository/blobs/{urllib.parse.quote(str(entry.object_id), safe='')}/raw",
            accept="*/*", max_bytes=max_bytes,
        )
        return data


class BitbucketClient(ProviderClient):
    name = "Bitbucket"

    def _repo(self) -> str:
        workspace, _, name = self.repository.partition("/")
        return f"/repositories/{urllib.parse.quote(workspace, safe='')}/{urllib.parse.quote(name, safe='')}"

    def resolve(self, ref):
        info, _ = self._json(self._repo(), not_found_ok=True)
        if not isinstance(info, dict):
            raise self._not_found()
        default_branch = (info.get("mainbranch") or {}).get("name") if isinstance(info.get("mainbranch"), dict) else None
        target = ref or default_branch
        if not target:
            raise ProviderError("The Bitbucket repository is empty (no main branch).")
        commit, _ = self._json(f"{self._repo()}/commit/{urllib.parse.quote(target, safe='')}", not_found_ok=True)
        if not isinstance(commit, dict) or not isinstance(commit.get("hash"), str):
            raise ProviderError(f"Bitbucket ref {target!r} was not found in {self.repository}.")
        return ResolvedRevision(
            commit["hash"], target if ref is None or ref == default_branch else None,
            default_branch, info.get("is_private"),
        )

    def tree(self, revision):
        entries: list[TreeEntry] = []
        url = f"{self._repo()}/src/{revision.revision}/?max_depth=1000&pagelen=100"
        pages = 0
        while url:
            payload, _ = self._json(url)
            if not isinstance(payload, dict) or not isinstance(payload.get("values"), list):
                raise NetworkError("Bitbucket returned a malformed source listing", kind="protocol")
            for item in payload["values"]:
                if not isinstance(item, dict):
                    continue
                path = safe_tree_path(item.get("path"))
                attributes = set(item.get("attributes") or []) if isinstance(item.get("attributes"), list) else set()
                if item.get("type") == "commit_directory":
                    kind = ("directory", False)
                elif "subrepository" in attributes:
                    kind = ("submodule", False)
                elif "link" in attributes:
                    kind = ("symlink", False)
                elif item.get("type") == "commit_file":
                    kind = ("file", "executable" in attributes)
                else:
                    kind = None
                if path is None or kind is None:
                    entries.append(TreeEntry(str(item.get("path", "?")), "invalid"))
                    continue
                size = item.get("size") if isinstance(item.get("size"), int) else None
                entries.append(TreeEntry(path, kind[0], size, path, kind[1]))
            pages += 1
            if len(entries) > MAX_TREE_ENTRIES or pages >= MAX_TREE_PAGES:
                return entries, True
            url = payload.get("next") if isinstance(payload.get("next"), str) else None
        return entries, False

    def read(self, entry, revision, max_bytes):
        _, data, _ = self._request(
            f"{self._repo()}/src/{revision.revision}/{_quote_path(entry.path)}",
            accept="*/*", max_bytes=max_bytes,
        )
        return data


class GiteaClient(ProviderClient):
    name = "Gitea"

    def _repo(self) -> str:
        owner, _, name = self.repository.partition("/")
        return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"

    def resolve(self, ref):
        info, _ = self._json(self._repo(), not_found_ok=True)
        if not isinstance(info, dict):
            raise self._not_found()
        default_branch = info.get("default_branch")
        target = ref or default_branch
        if not target:
            raise ProviderError("The Gitea repository is empty (no default branch).")
        commits, _ = self._json(
            f"{self._repo()}/commits?sha={urllib.parse.quote(target, safe='')}&limit=1"
            "&stat=false&verification=false&files=false",
            not_found_ok=True,
        )
        if not isinstance(commits, list) or not commits or not isinstance(commits[0], dict) \
                or not isinstance(commits[0].get("sha"), str):
            raise ProviderError(f"Gitea ref {target!r} was not found in {self.repository}.")
        return ResolvedRevision(
            commits[0]["sha"], target if ref is None or ref == default_branch else None,
            default_branch, info.get("private"),
        )

    def tree(self, revision):
        entries: list[TreeEntry] = []
        page = 1
        while True:
            payload, _ = self._json(
                f"{self._repo()}/git/trees/{revision.revision}?recursive=true&per_page=1000&page={page}",
            )
            if not isinstance(payload, dict):
                raise NetworkError("Gitea returned a malformed tree", kind="protocol")
            items = payload.get("tree") if isinstance(payload.get("tree"), list) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                path = safe_tree_path(item.get("path"))
                kind = _kind_for_mode(item.get("mode"), item.get("type"))
                if path is None or kind is None:
                    entries.append(TreeEntry(str(item.get("path", "?")), "invalid"))
                    continue
                size = item.get("size") if isinstance(item.get("size"), int) else None
                entries.append(TreeEntry(path, kind[0], size, item.get("sha"), kind[1]))
            total = payload.get("total_count")
            if not items or not payload.get("truncated") and (not isinstance(total, int) or len(entries) >= total):
                return entries, False
            if len(entries) > MAX_TREE_ENTRIES or page >= MAX_TREE_PAGES:
                return entries, True
            page += 1

    def read(self, entry, revision, max_bytes):
        _, data, _ = self._request(
            f"{self._repo()}/raw/{_quote_path(entry.path)}?ref={urllib.parse.quote(revision.revision, safe='')}",
            accept="*/*", max_bytes=max_bytes,
        )
        return data


CLIENTS = {"github": GitHubClient, "gitlab": GitLabClient, "bitbucket": BitbucketClient, "gitea": GiteaClient}


def symlink_scope(link_path: str, target: str) -> str:
    """Lexical scope of a symlink target relative to the repository root."""
    if not target or target.startswith("/") or re.match(r"^[A-Za-z]:", target) or "\\" in target:
        return "external"
    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
    return "external" if normalized == ".." or normalized.startswith("../") else "internal"
