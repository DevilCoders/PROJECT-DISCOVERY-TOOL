"""A loopback HTTP server emulating OSV.dev, NVD CVE API 2.0 and GitHub advisories.

Tests point PDT at it with PDT_OSV_API_URL / PDT_NVD_API_URL / PDT_GITHUB_API_URL (plain
http:// is accepted only for loopback hosts), so the real HTTP client, retries, caching
and parsing run without any external network access. Every request is recorded.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class AdvisoryService:
    # (ecosystem, name, version) -> list of vulnerability IDs (or pages: list of lists)
    affected: dict[tuple[str, str, str], Any] = field(default_factory=dict)
    records: dict[str, dict] = field(default_factory=dict)
    nvd: dict[str, dict] = field(default_factory=dict)
    ghsa: dict[str, dict] = field(default_factory=dict)
    requests: list[dict] = field(default_factory=list)
    # Failure injection.
    querybatch_status: int | None = None
    record_status: int | None = None
    rate_limit_first_querybatch: bool = False
    delay_seconds: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def paths(self, prefix: str) -> list[dict]:
        return [item for item in self.requests if item["path"].startswith(prefix)]


class _Handler(BaseHTTPRequestHandler):
    service: AdvisoryService

    def log_message(self, *_args) -> None:
        return

    def _send(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _record(self, body: bytes | None) -> None:
        with self.service.lock:
            self.service.requests.append({
                "method": self.command,
                "path": self.path,
                "headers": {key.lower(): value for key, value in self.headers.items()},
                "body": json.loads(body) if body else None,
            })

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._record(body)
        service = self.service
        if service.delay_seconds:
            time.sleep(service.delay_seconds)
        if self.path != "/v1/querybatch":
            self._send(404, {"error": "not found"})
            return
        with service.lock:
            first = len(service.paths("/v1/querybatch")) == 1
        if service.rate_limit_first_querybatch and first:
            self._send(429, {"error": "slow down"}, {"Retry-After": "0"})
            return
        if service.querybatch_status is not None:
            self._send(service.querybatch_status, {"error": "unavailable"})
            return
        results = []
        for query in json.loads(body)["queries"]:
            key = (query["package"]["ecosystem"], query["package"]["name"], query["version"])
            entry = service.affected.get(key, [])
            if entry and isinstance(entry[0], list):  # paginated
                page = int(query.get("page_token") or 0)
                ids = entry[page]
                result = {"vulns": [{"id": item, "modified": "2026-01-01T00:00:00Z"} for item in ids]}
                if page + 1 < len(entry):
                    result["next_page_token"] = str(page + 1)
            else:
                result = {"vulns": [{"id": item, "modified": "2026-01-01T00:00:00Z"} for item in entry]} if entry else {}
            results.append(result)
        self._send(200, {"results": results})

    def do_GET(self) -> None:
        self._record(None)
        service = self.service
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.startswith("/v1/vulns/"):
            if service.record_status is not None:
                self._send(service.record_status, {"error": "unavailable"})
                return
            identifier = urllib.parse.unquote(parsed.path[len("/v1/vulns/"):])
            record = service.records.get(identifier)
            self._send(200, record) if record else self._send(404, {"code": 5, "message": "Bug not found."})
            return
        if parsed.path == "/rest/json/cves/2.0":
            cve_id = urllib.parse.parse_qs(parsed.query).get("cveId", [""])[0]
            cve = service.nvd.get(cve_id)
            self._send(200, {"totalResults": 1 if cve else 0, "vulnerabilities": [{"cve": cve}] if cve else []})
            return
        if parsed.path.startswith("/advisories/"):
            advisory = service.ghsa.get(parsed.path[len("/advisories/"):])
            self._send(200, advisory) if advisory else self._send(404, {"message": "Not Found"})
            return
        self._send(404, {"error": "not found"})


class RunningService:
    def __init__(self, service: AdvisoryService) -> None:
        handler = type("Handler", (_Handler,), {"service": service})
        self.service = service
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "RunningService":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def ghsa_record(identifier: str, ecosystem: str, name: str, *, fixed: str, cve: str | None = None,
                severity_vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                withdrawn: str | None = None) -> dict:
    record = {
        "id": identifier,
        "summary": f"Prototype pollution in {name}",
        "details": f"{name} before {fixed} allows prototype pollution.",
        "aliases": [cve] if cve else [],
        "modified": "2026-01-02T00:00:00Z",
        "published": "2021-01-01T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
        "references": [{"type": "ADVISORY", "url": f"https://github.com/advisories/{identifier}"}],
    }
    if severity_vector:
        record["severity"] = [{"type": "CVSS_V3", "score": severity_vector}]
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record
