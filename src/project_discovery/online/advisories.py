"""Optional CVE/advisory enrichment from NVD CVE API 2.0 and the GitHub Advisory Database.

Only advisory identifiers (CVE-..., GHSA-...) are sent. An NVD API key (``NVD_API_KEY``)
or GitHub token (``PDT_GITHUB_TOKEN``, ``GITHUB_TOKEN``, ``GH_TOKEN``) raises the services'
rate limits; it is sent only to that service's host and is never logged or stored.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

from .cache import ResponseCache
from .http import HttpClient, NetworkError, RateLimiter, validate_service_url

NVD_API_URL = "https://services.nvd.nist.gov"
GITHUB_API_URL = "https://api.github.com"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}\Z")
_GHSA_ID = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z")
_CWE_ID = re.compile(r"^CWE-\d{1,6}\Z")
_MAX_DESCRIPTION = 2_000
_MAX_REFERENCES = 20


def is_cve_id(value: str) -> bool:
    return bool(_CVE_ID.match(value))


def is_ghsa_id(value: str) -> bool:
    return bool(_GHSA_ID.match(value))


def _text(value: Any, limit: int = 500) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


class NvdClient:
    """NVD CVE API 2.0: 5 requests per rolling 30 s without a key, 50 with one."""

    def __init__(
        self, http: HttpClient, cache: ResponseCache, *,
        base_url: str = NVD_API_URL, api_key: str | None = None,
    ) -> None:
        self.http = http
        self.cache = cache
        self.base_url = validate_service_url(base_url, label="NVD API URL")
        self._api_key = api_key or None
        self.limiter = RateLimiter(50 if self._api_key else 5, 30.0)
        self.requests = 0

    @property
    def authenticated(self) -> bool:
        return self._api_key is not None

    def cve(self, cve_id: str) -> dict[str, Any] | None:
        if not is_cve_id(cve_id):
            raise NetworkError("invalid CVE identifier", kind="protocol")
        key = f"nvd:cve:{cve_id}"
        cached = self.cache.get(key)
        if isinstance(cached, dict):
            return None if cached.get("_pdt_missing") else cached
        self.requests += 1
        status, payload = self.http.get_json(
            f"{self.base_url}/rest/json/cves/2.0?{urllib.parse.urlencode({'cveId': cve_id})}",
            secret_headers={"apiKey": self._api_key} if self._api_key else None,
            limiter=self.limiter, not_found_ok=True,
        )
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if status == 404 or not vulnerabilities:
            self.cache.put(key, {"_pdt_missing": True})
            return None
        if not isinstance(vulnerabilities, list) or not isinstance(vulnerabilities[0], dict):
            raise NetworkError("NVD returned a malformed CVE response", kind="protocol")
        record = normalize_nvd_cve(vulnerabilities[0].get("cve"))
        if record is None or record["id"] != cve_id:
            raise NetworkError("NVD returned a malformed CVE record", kind="protocol")
        self.cache.put(key, record)
        return record


def normalize_nvd_cve(cve: Any) -> dict[str, Any] | None:
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        return None
    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    description = next(
        (item.get("value") for item in descriptions
         if isinstance(item, dict) and item.get("lang") == "en" and item.get("value")),
        None,
    )
    cvss = []
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key, version in (
        ("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"),
    ):
        for metric in metrics.get(key, []) if isinstance(metrics.get(key), list) else []:
            data = metric.get("cvssData") if isinstance(metric, dict) else None
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            cvss.append({
                "version": version,
                "vector": _text(data.get("vectorString"), 200),
                "score": float(score) if isinstance(score, (int, float)) else None,
                "severity": _text(data.get("baseSeverity") or metric.get("baseSeverity"), 20),
                "source": _text(metric.get("source"), 200),
                "type": _text(metric.get("type"), 20),
            })
    cwes = sorted({
        str(detail.get("value"))
        for weakness in cve.get("weaknesses", []) if isinstance(weakness, dict)
        for detail in weakness.get("description", []) if isinstance(detail, dict)
        and _CWE_ID.match(str(detail.get("value", "")))
    })
    references = [
        str(item.get("url")) for item in cve.get("references", [])[:_MAX_REFERENCES]
        if isinstance(item, dict) and isinstance(item.get("url"), str)
    ] if isinstance(cve.get("references"), list) else []
    return {
        "id": cve["id"],
        "source": "NVD",
        "published": _text(cve.get("published"), 40),
        "last_modified": _text(cve.get("lastModified"), 40),
        "status": _text(cve.get("vulnStatus"), 60),
        "description": _text(description, _MAX_DESCRIPTION),
        "cvss": cvss,
        "cwes": cwes,
        "references": references,
    }


class GhsaClient:
    """GitHub global security advisories (REST): 60 requests/hour anonymous, 5,000 with a token."""

    def __init__(
        self, http: HttpClient, cache: ResponseCache, *,
        base_url: str = GITHUB_API_URL, token: str | None = None,
    ) -> None:
        self.http = http
        self.cache = cache
        self.base_url = validate_service_url(base_url, label="GitHub API URL")
        self._token = token or None
        self.limiter = RateLimiter(5000 if self._token else 60, 3600.0)
        self.requests = 0

    @property
    def authenticated(self) -> bool:
        return self._token is not None

    def advisory(self, ghsa_id: str) -> dict[str, Any] | None:
        if not is_ghsa_id(ghsa_id):
            raise NetworkError("invalid GHSA identifier", kind="protocol")
        key = f"ghsa:advisory:{ghsa_id}"
        cached = self.cache.get(key)
        if isinstance(cached, dict):
            return None if cached.get("_pdt_missing") else cached
        self.requests += 1
        status, payload = self.http.get_json(
            f"{self.base_url}/advisories/{ghsa_id}",
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
            secret_headers={"Authorization": f"Bearer {self._token}"} if self._token else None,
            limiter=self.limiter, not_found_ok=True,
        )
        if status == 404 or payload is None:
            self.cache.put(key, {"_pdt_missing": True})
            return None
        record = normalize_github_advisory(payload)
        if record is None or record["id"] != ghsa_id:
            raise NetworkError("GitHub returned a malformed advisory", kind="protocol")
        self.cache.put(key, record)
        return record


def normalize_github_advisory(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("ghsa_id"), str):
        return None
    cvss = []
    severities = payload.get("cvss_severities") if isinstance(payload.get("cvss_severities"), dict) else {}
    for key, version in (("cvss_v4", "4.0"), ("cvss_v3", "3.x")):
        item = severities.get(key)
        if isinstance(item, dict) and item.get("vector_string"):
            score = item.get("score")
            cvss.append({
                "version": version, "vector": _text(item.get("vector_string"), 200),
                "score": float(score) if isinstance(score, (int, float)) else None,
            })
    legacy = payload.get("cvss")
    if not cvss and isinstance(legacy, dict) and legacy.get("vector_string"):
        score = legacy.get("score")
        cvss.append({
            "version": "3.x", "vector": _text(legacy.get("vector_string"), 200),
            "score": float(score) if isinstance(score, (int, float)) else None,
        })
    cwes = sorted({
        str(item.get("cwe_id")) for item in payload.get("cwes", [])
        if isinstance(item, dict) and _CWE_ID.match(str(item.get("cwe_id", "")))
    }) if isinstance(payload.get("cwes"), list) else []
    identifiers = sorted({
        str(item.get("value")) for item in payload.get("identifiers", [])
        if isinstance(item, dict) and isinstance(item.get("value"), str)
    }) if isinstance(payload.get("identifiers"), list) else []
    severity = str(payload.get("severity") or "").upper()
    return {
        "id": payload["ghsa_id"],
        "source": "GitHub Advisory Database",
        "cve_id": _text(payload.get("cve_id"), 40),
        "severity": {"MODERATE": "MEDIUM"}.get(severity, severity) or None,
        "cvss": cvss,
        "cwes": cwes,
        "identifiers": identifiers,
        "summary": _text(payload.get("summary"), _MAX_DESCRIPTION),
        "published": _text(payload.get("published_at"), 40),
        "updated": _text(payload.get("updated_at"), 40),
        "withdrawn": _text(payload.get("withdrawn_at"), 40),
        "url": _text(payload.get("html_url"), 300),
    }
