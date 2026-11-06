"""Loopback emulation of the GitHub, GitLab, Bitbucket Cloud and Gitea/Forgejo REST APIs.

One fixture repository is served under four path prefixes (/github, /gitlab/api/v4,
/bitbucket/2.0, /gitea/api/v1) so no-download scans exercise each provider client's real
requests, pagination, authentication and error handling without external network access.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COMMIT = "c0ffee" + "0" * 34
TREE = "7ee" + "1" * 37
MARKER = b"PDT-NO-DOWNLOAD-MARKER-5f1d2c"


def blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def fixture_files() -> dict[str, tuple[bytes, str]]:
    lock = json.dumps({
        "name": "fixture", "lockfileVersion": 3,
        "packages": {"": {"name": "fixture"}, "node_modules/lodash": {"version": "4.17.20"}},
    }).encode("utf-8")
    return {
        "README.md": (b"# Fixture\n", "100644"),
        "src/app.py": (b"import os\nfrom pkg import util\n\n\ndef run(command):\n    os.system(command)\n", "100644"),
        "pkg/__init__.py": (b"", "100644"),
        "pkg/util.py": (b"VALUE = 1\n\n\ndef helper():\n    return VALUE\n", "100644"),
        "tools/run.sh": (b"#!/bin/sh\necho run\n", "100755"),
        "package-lock.json": (lock, "100644"),
        "notes/MARKER.txt": (MARKER + b"\n", "100644"),
        "assets/big.bin": (b"\0" * (1536 * 1024), "100644"),
        "docs/readme-link": (b"../README.md", "120000"),
    }


@dataclass
class ProviderService:
    files: dict[str, tuple[bytes, str]] = field(default_factory=fixture_files)
    submodules: tuple[str, ...] = ("vendor/lib",)
    extra_unsafe_paths: tuple[str, ...] = ()
    # Expected Authorization header per provider (None: anonymous access allowed).
    auth: dict[str, str] = field(default_factory=dict)
    private: bool = False
    github_truncated: bool = False
    rate_limit_after_blobs: int | None = None
    page_size: int = 3
    requests: list[dict] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    base_url: str = ""

    def blobs_by_sha(self) -> dict[str, bytes]:
        return {blob_sha(content): content for content, _ in self.files.values()}

    def tree_items(self) -> list[dict]:
        directories = set()
        for path in [*self.files, *self.submodules]:
            parts = path.split("/")[:-1]
            for index in range(1, len(parts) + 1):
                directories.add("/".join(parts[:index]))
        items = [{"path": path, "mode": "040000", "type": "tree", "sha": hashlib.sha1(path.encode()).hexdigest(), "size": None}
                 for path in sorted(directories)]
        for path, (content, mode) in sorted(self.files.items()):
            items.append({"path": path, "mode": mode, "type": "blob", "sha": blob_sha(content), "size": len(content)})
        for path in self.submodules:
            items.append({"path": path, "mode": "160000", "type": "commit", "sha": "5" * 40, "size": None})
        for path in self.extra_unsafe_paths:
            items.append({"path": path, "mode": "100644", "type": "blob", "sha": "6" * 40, "size": 1})
        return sorted(items, key=lambda item: item["path"])

    def content_requests(self) -> list[dict]:
        markers = ("/git/blobs/", "/repository/blobs/", "/raw/", "/src/" + COMMIT + "/")
        result = []
        for item in self.requests:
            path = urllib.parse.urlsplit(item["path"]).path
            if any(marker in path for marker in markers) and not path.rstrip("/").endswith(COMMIT):
                result.append(item)
        return result


class _Handler(BaseHTTPRequestHandler):
    service: ProviderService

    def log_message(self, *_args) -> None:
        return

    def _send(self, status: int, body, *, raw: bool = False, headers: dict | None = None) -> None:
        payload = body if raw else json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream" if raw else "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self, provider: str) -> bool:
        expected = self.service.auth.get(provider)
        if expected is None:
            return not self.service.private
        return self.headers.get("Authorization") == expected

    def _content(self, content: bytes) -> None:
        service = self.service
        with service.lock:
            fetched = len(service.content_requests())
        if service.rate_limit_after_blobs is not None and fetched > service.rate_limit_after_blobs:
            self._send(403, {"message": "API rate limit exceeded"}, headers={
                "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 3600),
            })
            return
        self._send(200, content, raw=True)

    def do_GET(self) -> None:  # noqa: C901 - one dispatcher per emulated API
        service = self.service
        with service.lock:
            service.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}})
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path)
        query = urllib.parse.parse_qs(parsed.query)
        for prefix, handler in (("/github", self._github), ("/gitlab/api/v4", self._gitlab),
                                ("/bitbucket/2.0", self._bitbucket), ("/gitea/api/v1", self._gitea)):
            if path.startswith(prefix + "/"):
                provider = prefix.strip("/").split("/")[0]
                if not self._authorized(provider):
                    self._send(404, {"message": "Not Found"})
                    return
                handler(path[len(prefix):], parsed, query)
                return
        self._send(404, {"message": "unknown route"})

    # GitHub ---------------------------------------------------------------
    def _github(self, path, parsed, query):
        service = self.service
        repo = "/repos/acme/fixture"
        if path == repo:
            self._send(200, {"default_branch": "main", "private": service.private})
        elif path in {f"{repo}/commits/main", f"{repo}/commits/{COMMIT}", f"{repo}/commits/v1.0"}:
            self._send(200, {"sha": COMMIT, "commit": {"tree": {"sha": TREE}}})
        elif path.startswith(f"{repo}/git/trees/"):
            sha = path.rsplit("/", 1)[1]
            items = service.tree_items()
            if query.get("recursive") == ["1"]:
                self._send(200, {"sha": TREE, "tree": items, "truncated": service.github_truncated})
                return
            prefix = "" if sha == TREE else next(
                (item["path"] for item in items if item["type"] == "tree" and item["sha"] == sha), None)
            if prefix is None:
                self._send(404, {"message": "Not Found"})
                return
            children = [dict(item, path=item["path"][len(prefix) + 1:] if prefix else item["path"])
                        for item in items
                        if (item["path"].rsplit("/", 1)[0] if "/" in item["path"] else "") == prefix]
            self._send(200, {"sha": sha, "tree": children, "truncated": False})
        elif path.startswith(f"{repo}/git/blobs/"):
            content = service.blobs_by_sha().get(path.rsplit("/", 1)[1])
            self._content(content) if content is not None else self._send(404, {"message": "Not Found"})
        else:
            self._send(404, {"message": "Not Found"})

    # GitLab ---------------------------------------------------------------
    def _gitlab(self, path, parsed, query):
        service = self.service
        project = "/projects/group/sub/fixture"
        if path == project:
            self._send(200, {"default_branch": "main", "visibility": "private" if service.private else "public"})
        elif path in {f"{project}/repository/commits/main", f"{project}/repository/commits/{COMMIT}"}:
            self._send(200, {"id": COMMIT})
        elif path == f"{project}/repository/tree":
            items = [{"id": item["sha"], "name": item["path"].rsplit("/", 1)[-1], "type": item["type"],
                      "path": item["path"], "mode": item["mode"]} for item in service.tree_items()]
            page = int(query.get("page", ["1"])[0])
            size = service.page_size
            chunk = items[(page - 1) * size: page * size]
            headers = {}
            if page * size < len(items):
                next_query = dict(urllib.parse.parse_qsl(parsed.query))
                next_query["page"] = str(page + 1)
                headers["Link"] = f'<{service.base_url}/gitlab/api/v4{project.replace("/group/sub/fixture", "/group%2Fsub%2Ffixture")}/repository/tree?{urllib.parse.urlencode(next_query)}>; rel="next"'
            self._send(200, chunk, headers=headers)
        elif path.startswith(f"{project}/repository/blobs/") and path.endswith("/raw"):
            content = service.blobs_by_sha().get(path.split("/")[-2])
            self._content(content) if content is not None else self._send(404, {"message": "404 Not Found"})
        else:
            self._send(404, {"message": "404 Not Found"})

    # Bitbucket ------------------------------------------------------------
    def _bitbucket(self, path, parsed, query):
        service = self.service
        repo = "/repositories/ws/fixture"
        if path == repo:
            self._send(200, {"mainbranch": {"name": "main"}, "is_private": service.private})
        elif path in {f"{repo}/commit/main", f"{repo}/commit/{COMMIT}"}:
            self._send(200, {"hash": COMMIT})
        elif path == f"{repo}/src/{COMMIT}/" and "max_depth" in query:
            values = []
            for item in service.tree_items():
                attributes = []
                if item["mode"] == "100755":
                    attributes.append("executable")
                if item["mode"] == "120000":
                    attributes.append("link")
                if item["mode"] == "160000":
                    attributes.append("subrepository")
                values.append({
                    "type": "commit_directory" if item["type"] == "tree" else "commit_file",
                    "path": item["path"], "size": item["size"], "attributes": attributes,
                })
            page = int(query.get("page", ["1"])[0])
            size = service.page_size
            body = {"values": values[(page - 1) * size: page * size], "page": page}
            if page * size < len(values):
                body["next"] = f"{service.base_url}/bitbucket/2.0{repo}/src/{COMMIT}/?max_depth=1000&pagelen=100&page={page + 1}"
            self._send(200, body)
        elif path.startswith(f"{repo}/src/{COMMIT}/"):
            file_path = path[len(f"{repo}/src/{COMMIT}/"):]
            entry = service.files.get(file_path)
            self._content(entry[0]) if entry else self._send(404, {"type": "error"})
        else:
            self._send(404, {"type": "error"})

    # Gitea ----------------------------------------------------------------
    def _gitea(self, path, parsed, query):
        service = self.service
        repo = "/repos/acme/fixture"
        if path == repo:
            self._send(200, {"default_branch": "main", "private": service.private})
        elif path == f"{repo}/commits":
            if query.get("sha", [""])[0] not in {"main", COMMIT}:
                self._send(404, {"message": "not found"})
                return
            self._send(200, [{"sha": COMMIT}])
        elif path == f"{repo}/git/trees/{COMMIT}":
            items = service.tree_items()
            page = int(query.get("page", ["1"])[0])
            size = service.page_size
            chunk = items[(page - 1) * size: page * size]
            self._send(200, {"sha": COMMIT, "tree": chunk, "truncated": page * size < len(items),
                             "page": page, "total_count": len(items)})
        elif path.startswith(f"{repo}/raw/"):
            entry = service.files.get(path[len(f"{repo}/raw/"):])
            self._content(entry[0]) if entry else self._send(404, {"message": "not found"})
        else:
            self._send(404, {"message": "not found"})


class RunningProviders:
    def __init__(self, service: ProviderService) -> None:
        handler = type("Handler", (_Handler,), {"service": service})
        self.service = service
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        service.base_url = self.url
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "RunningProviders":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
