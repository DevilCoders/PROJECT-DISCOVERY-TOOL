"""OSV.dev client: batched package queries (`/v1/querybatch`) and records (`/v1/vulns/{id}`).

Only package coordinates are sent: ecosystem, package name and resolved version. File
paths, file contents and project names never leave the machine.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable

from ..analyzers.dependencies.lockfile_parsers import normalize_version
from .cache import ResponseCache
from .http import HttpClient, NetworkError, RateLimiter, validate_service_url

OSV_API_URL = "https://api.osv.dev"
# OSV.dev accepts at most 1,000 queries per querybatch request.
OSV_BATCH_SIZE = 1000
MAX_PAGES_PER_PACKAGE = 10
MAX_RECORD_BYTES = 8 * 1024 * 1024
_VULNERABILITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True, slots=True, order=True)
class PackageQuery:
    """One package coordinate as sent to OSV.dev."""

    ecosystem: str
    name: str
    version: str

    @property
    def osv_version(self) -> str:
        # Go lockfiles keep the module "v" prefix; OSV.dev expects the bare version.
        if self.ecosystem == "Go":
            return normalize_version(self.version, strip_prefix=True)
        return self.version

    @property
    def cache_key(self) -> str:
        return "osv:query:" + "\x1f".join((self.ecosystem, self.name, self.osv_version))

    def payload(self, page_token: str | None = None) -> dict[str, Any]:
        query: dict[str, Any] = {
            "package": {"ecosystem": self.ecosystem, "name": self.name},
            "version": self.osv_version,
        }
        if page_token:
            query["page_token"] = page_token
        return query

    @property
    def label(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


def valid_vulnerability_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_VULNERABILITY_ID.match(value))


class OsvClient:
    def __init__(
        self,
        http: HttpClient,
        cache: ResponseCache,
        *,
        base_url: str = OSV_API_URL,
        requests_per_second: int = 20,
    ) -> None:
        self.http = http
        self.cache = cache
        self.base_url = validate_service_url(base_url, label="OSV API URL")
        self.limiter = RateLimiter(requests_per_second, 1.0)
        self.batch_requests = 0
        self.record_requests = 0

    def query(
        self, packages: Iterable[PackageQuery],
    ) -> tuple[dict[PackageQuery, list[str]], dict[PackageQuery, NetworkError]]:
        """Return (vulnerability IDs per package, failure per package)."""
        results: dict[PackageQuery, list[str]] = {}
        failures: dict[PackageQuery, NetworkError] = {}
        pending: list[PackageQuery] = []
        for package in packages:
            cached = self.cache.get(package.cache_key)
            if isinstance(cached, list) and all(valid_vulnerability_id(item) for item in cached):
                results[package] = cached
            else:
                pending.append(package)
        for start in range(0, len(pending), OSV_BATCH_SIZE):
            batch = pending[start:start + OSV_BATCH_SIZE]
            try:
                answered = self._query_batch(batch)
            except NetworkError as exc:
                for package in batch:
                    failures[package] = exc
                continue
            for package, (ids, error) in answered.items():
                if error is not None:
                    failures[package] = error
                    continue
                results[package] = ids
                self.cache.put(package.cache_key, ids)
        return results, failures

    def _post_batch(self, queries: list[dict[str, Any]]) -> list[Any]:
        self.batch_requests += 1
        _, payload = self.http.post_json(
            f"{self.base_url}/v1/querybatch", {"queries": queries}, limiter=self.limiter,
        )
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(queries):
            raise NetworkError("OSV.dev returned a malformed querybatch response", kind="protocol")
        return results

    @staticmethod
    def _parse_result(result: Any) -> tuple[list[str], str | None]:
        if not isinstance(result, dict):
            raise NetworkError("OSV.dev returned a malformed query result", kind="protocol")
        vulns = result.get("vulns") or []
        if not isinstance(vulns, list):
            raise NetworkError("OSV.dev returned a malformed vulnerability list", kind="protocol")
        ids = []
        for item in vulns:
            identifier = item.get("id") if isinstance(item, dict) else None
            if not valid_vulnerability_id(identifier):
                raise NetworkError("OSV.dev returned an invalid vulnerability ID", kind="protocol")
            ids.append(identifier)
        token = result.get("next_page_token")
        return ids, token if isinstance(token, str) and token else None

    def _query_batch(
        self, batch: list[PackageQuery],
    ) -> dict[PackageQuery, tuple[list[str], NetworkError | None]]:
        results = self._post_batch([package.payload() for package in batch])
        answered: dict[PackageQuery, tuple[list[str], NetworkError | None]] = {}
        for package, result in zip(batch, results, strict=True):
            error = None
            try:
                ids, token = self._parse_result(result)
                pages = 1
                while token is not None:
                    if pages >= MAX_PAGES_PER_PACKAGE:
                        error = NetworkError(
                            f"OSV.dev returned more than {MAX_PAGES_PER_PACKAGE} result pages",
                            kind="truncated",
                        )
                        break
                    more = self._post_batch([package.payload(token)])
                    page_ids, token = self._parse_result(more[0])
                    ids.extend(page_ids)
                    pages += 1
            except NetworkError as exc:
                ids, error = [], exc
            answered[package] = (sorted(set(ids)), error)
        return answered

    def vulnerability(self, vulnerability_id: str) -> dict[str, Any] | None:
        """Fetch one full OSV record (cached); None when OSV.dev no longer has it."""
        if not valid_vulnerability_id(vulnerability_id):
            raise NetworkError("invalid vulnerability ID", kind="protocol")
        key = f"osv:vuln:{vulnerability_id}"
        cached = self.cache.get(key)
        if isinstance(cached, dict):
            return None if cached.get("_pdt_missing") else cached
        self.record_requests += 1
        status, record = self.http.get_json(
            f"{self.base_url}/v1/vulns/{urllib.parse.quote(vulnerability_id, safe='')}",
            limiter=self.limiter, not_found_ok=True, max_bytes=MAX_RECORD_BYTES,
        )
        if status == 404:
            self.cache.put(key, {"_pdt_missing": True})
            return None
        if not isinstance(record, dict) or not valid_vulnerability_id(record.get("id")):
            raise NetworkError("OSV.dev returned a malformed vulnerability record", kind="protocol")
        self.cache.put(key, record)
        return record
