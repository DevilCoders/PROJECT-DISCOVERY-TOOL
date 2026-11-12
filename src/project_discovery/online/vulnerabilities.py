"""Opt-in online vulnerability intelligence for resolved lockfile packages.

The lookup runs in the scan coordinator after file analysis, so worker processes never
touch the network. It reads each supported lockfile once (bounded), sends the unique
package coordinates to OSV.dev in batches, fetches the matching OSV records and,
optionally, CVE/GHSA details from NVD and the GitHub Advisory Database. Findings use the
same construction as the offline ``--vuln-db`` matcher.

Every failure is explicit: a package whose lookup failed, a lockfile that could not be
read, an advisory whose details could not be fetched and a truncated enrichment are each
reported as UNKNOWN coverage findings plus scan diagnostics, never as "no vulnerabilities".
"""
from __future__ import annotations

import os
import re
import time
import urllib.parse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from ..analyzers.dependencies.lockfile_parsers import (
    MAX_LOCKFILE_PACKAGE_ENTRIES,
    LockfileEntryBudgetExceeded,
    ResolvedPackage,
    parse_lockfile,
)
from ..analyzers.dependencies.vulnerabilities import advisory_findings
from ..core.source_utils import SourceBudgetExceeded, redact_source_excerpt
from ..models import Finding
from ..vulnerabilities.database import osv_record_to_advisories
from .advisories import GITHUB_API_URL, NVD_API_URL, GhsaClient, NvdClient, is_cve_id, is_ghsa_id
from .cache import DEFAULT_CACHE_TTL_SECONDS, ResponseCache, default_cache_path
from .http import DEFAULT_TIMEOUT, HttpClient, NetworkError
from .osv import OSV_API_URL, OsvClient, PackageQuery

# A registry release: no URL, path, scope or whitespace (Go "+incompatible" is fine).
_PLAIN_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+~_-]{0,127}+\Z")

ONLINE_ANALYZER_NAME = "online-vulnerability-intelligence"
ENRICHMENT_SOURCES = ("nvd", "ghsa")
DEFAULT_MAX_ENRICHMENT = 200
# Unique package coordinates sent per scan; the remainder is reported as UNKNOWN.
MAX_ONLINE_PACKAGES = 500_000
_SAMPLE = 10
_MAX_EVIDENCE_LOCKFILES = 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _github_token() -> str | None:
    for variable in ("PDT_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return None


@dataclass(frozen=True)
class OnlineVulnerabilityOptions:
    """Settings for one opt-in lookup; tokens are excluded from repr() and reports."""

    cache_path: Path | None = field(default_factory=default_cache_path)
    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS
    ca_bundle: Path | None = None
    timeout: float = DEFAULT_TIMEOUT
    enrich: frozenset[str] = frozenset()
    osv_url: str = OSV_API_URL
    nvd_url: str = NVD_API_URL
    github_url: str = GITHUB_API_URL
    nvd_api_key: str | None = field(default=None, repr=False)
    github_token: str | None = field(default=None, repr=False)
    max_enrichment: int = DEFAULT_MAX_ENRICHMENT
    workers: int = 8
    retries: int = 3

    def __post_init__(self) -> None:
        unknown = set(self.enrich) - set(ENRICHMENT_SOURCES)
        if unknown:
            raise ValueError(f"--vuln-enrich accepts: {', '.join(ENRICHMENT_SOURCES)}")
        if not 1 <= self.workers <= 32:
            raise ValueError("online lookup workers must be between 1 and 32")
        if self.max_enrichment < 0:
            raise ValueError("enrichment limit must not be negative")
        if not 0 <= self.retries <= 10:
            raise ValueError("network retries must be between 0 and 10")

    @classmethod
    def from_environment(
        cls, *, cache_path: Path | None = None, cache_ttl_hours: float | None = None,
        ca_bundle: Path | None = None, timeout: float | None = None,
        enrich: Iterable[str] = (),
    ) -> "OnlineVulnerabilityOptions":
        """Build options from CLI values plus the documented environment variables."""
        return cls(
            cache_path=cache_path if cache_path is not None else default_cache_path(),
            cache_ttl_seconds=(
                DEFAULT_CACHE_TTL_SECONDS if cache_ttl_hours is None else cache_ttl_hours * 3600
            ),
            ca_bundle=ca_bundle,
            timeout=DEFAULT_TIMEOUT if timeout is None else timeout,
            enrich=frozenset(item.strip().lower() for item in enrich if item.strip()),
            osv_url=os.environ.get("PDT_OSV_API_URL") or OSV_API_URL,
            nvd_url=os.environ.get("PDT_NVD_API_URL") or NVD_API_URL,
            github_url=os.environ.get("PDT_GITHUB_API_URL") or GITHUB_API_URL,
            nvd_api_key=os.environ.get("NVD_API_KEY", "").strip() or None,
            github_token=_github_token(),
        )

    def describe(self) -> dict[str, Any]:
        """Report-safe provenance: endpoints and whether credentials were used, never values."""
        return {
            "provider": "OSV.dev",
            "endpoint": self.osv_url,
            "enrichment": sorted(self.enrich),
            "enrichment_endpoints": {
                **({"nvd": self.nvd_url} if "nvd" in self.enrich else {}),
                **({"ghsa": self.github_url} if "ghsa" in self.enrich else {}),
            },
            "nvd_api_key_used": "nvd" in self.enrich and self.nvd_api_key is not None,
            "github_token_used": "ghsa" in self.enrich and self.github_token is not None,
            "custom_ca_bundle": self.ca_bundle is not None,
            "request_timeout_seconds": self.timeout,
            "data_sent": "package ecosystem, name and version; advisory IDs for enrichment",
        }


@dataclass(frozen=True, slots=True)
class LockfileSource:
    """A lockfile path (as reported) and a callable returning its bounded text."""

    path: str
    read: Callable[[], str]


@dataclass(slots=True)
class OnlineLookupResult:
    findings: list[Finding]
    diagnostics: list[str]
    status: dict[str, Any]


def _coverage_finding(title: str, detail: str, evidence: list[str], *, severity: str = "LOW") -> Finding:
    return Finding(
        "vulnerabilities",
        title,
        detail + " This is not evidence that the affected dependencies are free of known vulnerabilities.",
        confidence="UNKNOWN",
        evidence=evidence,
        analyzer=ONLINE_ANALYZER_NAME,
        severity=severity,
        recommendation=(
            "Re-run the scan with network access to the advisory service (check proxy, TLS and "
            "rate-limit settings), or use an offline advisory snapshot with --vuln-db."
        ),
    )


def _enrichment_lines(advisory: dict[str, Any], details: dict[str, dict[str, Any]]) -> list[str]:
    lines = []
    for identifier in [advisory["id"], *advisory.get("aliases", [])]:
        record = details.get(identifier)
        if not record:
            continue
        for metric in record.get("cvss", [])[:3]:
            if metric.get("vector") or metric.get("score") is not None:
                lines.append(
                    f"cvss_{metric.get('version')}: {metric.get('score')} {metric.get('vector') or ''} "
                    f"({record.get('source')} {identifier})".replace("  ", " ")
                )
        if record.get("cwes"):
            lines.append(f"cwe: {', '.join(record['cwes'][:6])} ({record.get('source')} {identifier})")
    return lines


def _enrichment_severity(advisory: dict[str, Any], details: dict[str, dict[str, Any]]) -> str | None:
    from ..vulnerabilities.cvss import qualitative_severity

    best = None
    for identifier in [advisory["id"], *advisory.get("aliases", [])]:
        record = details.get(identifier) or {}
        for metric in record.get("cvss", []):
            score = metric.get("score")
            if isinstance(score, (int, float)) and (best is None or score > best):
                best = float(score)
        label = record.get("severity")
        if best is None and label in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return label
    return qualitative_severity(best) if best is not None else None


def _placeholder_advisory(identifier: str, query: PackageQuery, summary: str) -> dict[str, Any]:
    return {
        "id": identifier, "aliases": [], "summary": summary, "details": "",
        "severity": "UNKNOWN", "published": None, "modified": None, "withdrawn": None,
        "references": [], "affected": {}, "ecosystem": query.ecosystem, "source_file": "OSV.dev",
    }


class OnlineVulnerabilityLookup:
    """Run one online lookup for a set of lockfiles and build findings and provenance."""

    def __init__(self, options: OnlineVulnerabilityOptions) -> None:
        self.options = options

    def run(self, lockfiles: Iterable[LockfileSource]) -> OnlineLookupResult:
        options = self.options
        started_at = _now()
        started = time.monotonic()
        findings: list[Finding] = []
        diagnostics: list[str] = []
        paths_by_package: dict[PackageQuery, list[str]] = defaultdict(list)
        parse_failures: list[tuple[str, str]] = []
        lockfile_count = 0
        for source in lockfiles:
            lockfile_count += 1
            try:
                packages = parse_lockfile(
                    PurePosixPath(source.path).name, source.read(),
                    max_entries=MAX_LOCKFILE_PACKAGE_ENTRIES,
                )
            except (SourceBudgetExceeded, LockfileEntryBudgetExceeded, OSError, ValueError,
                    RecursionError, MemoryError) as exc:
                parse_failures.append((source.path, redact_source_excerpt(f"{type(exc).__name__}: {exc}")))
                continue
            for package in packages:
                # Defense in depth: only plain registry versions leave the machine or reach
                # the response cache; source specifiers can hold credentials and paths.
                if not _PLAIN_VERSION.match(package.version):
                    continue
                paths = paths_by_package[PackageQuery(package.ecosystem, package.name, package.version)]
                if source.path not in paths:
                    paths.append(source.path)

        queries = sorted(paths_by_package)
        over_limit = queries[MAX_ONLINE_PACKAGES:]
        queries = queries[:MAX_ONLINE_PACKAGES]
        status: dict[str, Any] = {
            "enabled": True,
            **options.describe(),
            "query_started_at": started_at,
            "lockfiles": lockfile_count,
            "lockfiles_unreadable": len(parse_failures),
            "unique_packages": len(paths_by_package),
            "packages_queried": 0,
            "packages_failed": 0,
            "packages_not_queried": len(over_limit),
            "vulnerable_packages": 0,
            "advisories": 0,
            "advisory_details_unavailable": 0,
            "withdrawn_skipped": 0,
            "findings": 0,
            "ecosystems": dict(sorted(Counter(query.ecosystem for query in paths_by_package).items())),
        }

        results: dict[PackageQuery, list[str]] = {}
        failures: dict[PackageQuery, NetworkError] = {}
        records: dict[str, dict[str, Any]] = {}
        record_failures: dict[str, NetworkError] = {}
        enrichment: dict[str, dict[str, Any]] = {}
        enrichment_failures: dict[str, NetworkError] = {}
        enrichment_skipped = 0
        http = HttpClient(ca_bundle=options.ca_bundle, timeout=options.timeout, retries=options.retries)
        with ResponseCache(options.cache_path, ttl_seconds=options.cache_ttl_seconds) as cache:
            osv = OsvClient(http, cache, base_url=options.osv_url)
            if queries:
                results, failures = osv.query(queries)
            identifiers = sorted({identifier for ids in results.values() for identifier in ids})
            if identifiers:
                with ThreadPoolExecutor(max_workers=options.workers, thread_name_prefix="pdt-osv") as pool:
                    futures = {identifier: pool.submit(osv.vulnerability, identifier) for identifier in identifiers}
                    for identifier, future in futures.items():
                        try:
                            record = future.result()
                        except NetworkError as exc:
                            record_failures[identifier] = exc
                            continue
                        if record is not None:
                            records[identifier] = record
            if options.enrich and records:
                enrichment, enrichment_failures, enrichment_skipped, enrichment_status = self._enrich(
                    http, cache, records,
                )
                status["enrichment_status"] = enrichment_status
            status["cache"] = cache.statistics()
            status["requests"] = {
                **http.statistics(),
                "osv_querybatch": osv.batch_requests,
                "osv_vulns": osv.record_requests,
            }

        for query in queries:
            ids = results.get(query)
            if not ids:
                continue
            package = ResolvedPackage(query.ecosystem, query.name, query.version)
            advisories = []
            for identifier in ids:
                record = records.get(identifier)
                if record is None:
                    summary = (
                        f"{identifier} (advisory details unavailable)" if identifier in record_failures
                        else f"{identifier} (record no longer published by OSV.dev)"
                    )
                    advisories.append(_placeholder_advisory(identifier, query, summary))
                    continue
                if record.get("withdrawn"):
                    status["withdrawn_skipped"] += 1
                    continue
                rows = osv_record_to_advisories(record, query.ecosystem, query.name, source="OSV.dev")
                advisory = rows[0] if rows else {
                    **_placeholder_advisory(identifier, query, str(record.get("summary") or identifier)),
                    "aliases": sorted(str(item) for item in record.get("aliases", []) if isinstance(item, str))
                    if isinstance(record.get("aliases"), list) else [],
                    "details": str(record.get("details") or "")[:100_000],
                    "modified": record.get("modified"),
                }
                advisories.append(advisory)
            if not advisories:
                continue
            for advisory in advisories:
                extra = _enrichment_lines(advisory, enrichment)
                if extra:
                    advisory["evidence_extra"] = extra
                if advisory["severity"] == "UNKNOWN":
                    enriched = _enrichment_severity(advisory, enrichment)
                    if enriched:
                        advisory["severity"] = enriched
            matches = [(advisory, True, "OSV.dev reported this version as affected") for advisory in advisories]
            status["vulnerable_packages"] += 1
            status["advisories"] += len(advisories)
            for lockfile in sorted(paths_by_package[query])[:_MAX_EVIDENCE_LOCKFILES]:
                for finding in advisory_findings(
                    lockfile, package, matches,
                    analyzer=ONLINE_ANALYZER_NAME, source_label="OSV.dev advisory",
                ):
                    finding.evidence.append(
                        f"source: OSV.dev ({urllib.parse.urlsplit(options.osv_url).hostname}), "
                        f"queried {started_at}"
                    )
                    findings.append(finding)
        status["findings"] = len(findings)
        status["packages_queried"] = len(results)
        status["packages_failed"] = len(failures)
        status["advisory_details_unavailable"] = len(record_failures)

        # Coverage gaps: grouped by cause, each with samples, never silent.
        by_reason: dict[str, list[PackageQuery]] = defaultdict(list)
        for query, error in failures.items():
            by_reason[f"{error.kind}: {error}"].append(query)
        for reason, failed in sorted(by_reason.items()):
            sample = ", ".join(item.label for item in sorted(failed)[:_SAMPLE])
            message = (
                f"Online vulnerability lookup incomplete: {len(failed):,} of {len(queries):,} "
                f"package(s) could not be checked against OSV.dev ({reason})"
            )
            diagnostics.append(message)
            findings.append(_coverage_finding(
                f"Online vulnerability lookup failed for {len(failed):,} package(s)",
                message + f". Examples: {sample}.",
                sorted({path for item in failed for path in paths_by_package[item]})[:_MAX_EVIDENCE_LOCKFILES],
            ))
        if over_limit:
            message = (
                f"Online vulnerability lookup skipped {len(over_limit):,} package(s) beyond the "
                f"{MAX_ONLINE_PACKAGES:,}-package limit per scan"
            )
            diagnostics.append(message)
            findings.append(_coverage_finding(
                "Online vulnerability lookup limit reached", message + ".",
                sorted({path for item in over_limit[:1000] for path in paths_by_package[item]})[:_MAX_EVIDENCE_LOCKFILES],
            ))
        if parse_failures:
            message = (
                f"Online vulnerability lookup could not read {len(parse_failures):,} lockfile(s); "
                "their packages were not checked"
            )
            diagnostics.append(message)
            findings.append(_coverage_finding(
                f"Lockfile(s) not checked online: {len(parse_failures):,}",
                message + ": " + "; ".join(f"{path}: {error}" for path, error in parse_failures[:_SAMPLE]) + ".",
                [path for path, _ in parse_failures[:_MAX_EVIDENCE_LOCKFILES]],
            ))
        if record_failures:
            reason = next(iter(record_failures.values()))
            message = (
                f"Details for {len(record_failures):,} matched OSV.dev advisory(ies) could not be "
                f"fetched ({reason.kind}: {reason}); the matches are reported with their IDs only"
            )
            diagnostics.append(message)
            findings.append(_coverage_finding(
                "Online advisory details unavailable", message + ".",
                [f"advisory: {identifier}" for identifier in sorted(record_failures)[:_MAX_EVIDENCE_LOCKFILES]],
            ))
        if enrichment_failures or enrichment_skipped:
            parts = []
            if enrichment_failures:
                reason = next(iter(enrichment_failures.values()))
                parts.append(f"{len(enrichment_failures):,} lookup(s) failed ({reason.kind}: {reason})")
            if enrichment_skipped:
                parts.append(
                    f"{enrichment_skipped:,} identifier(s) beyond the limit of "
                    f"{self.options.max_enrichment:,} were not looked up"
                )
            findings.append(Finding(
                "vulnerabilities",
                "CVE/advisory enrichment incomplete",
                "Optional NVD/GitHub Advisory enrichment is incomplete: " + "; ".join(parts) + ". "
                "Advisory matches themselves are unaffected; CVSS/CWE details may be missing.",
                confidence="UNKNOWN",
                evidence=[f"advisory: {identifier}" for identifier in sorted(enrichment_failures)[:_MAX_EVIDENCE_LOCKFILES]],
                analyzer=ONLINE_ANALYZER_NAME,
                severity="INFO",
            ))
        failed_scope = len(failures) + len(over_limit) + len(parse_failures)
        if not lockfile_count:
            coverage = "not_applicable"
        elif failed_scope == 0 and not record_failures:
            coverage = "complete"
        elif queries and len(failures) == len(queries) and not results:
            coverage = "unavailable"
        else:
            coverage = "partial"
        status.update({
            "coverage": coverage,
            "query_finished_at": _now(),
            "query_seconds": round(time.monotonic() - started, 3),
            "failures": [
                {"reason": reason, "packages": len(failed)} for reason, failed in sorted(by_reason.items())
            ],
        })
        return OnlineLookupResult(findings, diagnostics, status)

    def _enrich(self, http: HttpClient, cache: ResponseCache, records: dict[str, dict[str, Any]]):
        options = self.options
        wanted_cves: set[str] = set()
        wanted_ghsa: set[str] = set()
        # Advisory by advisory, so a small --max-enrichment budget covers both sources for
        # the first advisories instead of exhausting one source first.
        ordered: list[tuple[str, str]] = []
        for record in sorted(records.values(), key=lambda item: str(item.get("id"))):
            aliases = record.get("aliases") if isinstance(record.get("aliases"), list) else []
            for identifier in [record.get("id"), *aliases]:
                if not isinstance(identifier, str):
                    continue
                if "nvd" in options.enrich and is_cve_id(identifier) and identifier not in wanted_cves:
                    wanted_cves.add(identifier)
                    ordered.append(("nvd", identifier))
                if "ghsa" in options.enrich and is_ghsa_id(identifier) and identifier not in wanted_ghsa:
                    wanted_ghsa.add(identifier)
                    ordered.append(("ghsa", identifier))
        selected = ordered[:options.max_enrichment]
        skipped = len(ordered) - len(selected)
        nvd = NvdClient(http, cache, base_url=options.nvd_url, api_key=options.nvd_api_key) if wanted_cves else None
        ghsa = GhsaClient(http, cache, base_url=options.github_url, token=options.github_token) if wanted_ghsa else None
        details: dict[str, dict[str, Any]] = {}
        failures: dict[str, NetworkError] = {}

        def fetch(item):
            source, identifier = item
            client = nvd if source == "nvd" else ghsa
            return client.cve(identifier) if source == "nvd" else client.advisory(identifier)

        with ThreadPoolExecutor(max_workers=min(4, options.workers), thread_name_prefix="pdt-enrich") as pool:
            futures = {item: pool.submit(fetch, item) for item in selected}
            for (_source, identifier), future in futures.items():
                try:
                    record = future.result()
                except NetworkError as exc:
                    failures[identifier] = exc
                    continue
                if record is not None:
                    details[identifier] = record
        enrichment_status = {
            "nvd": {
                "requested": len([item for item in selected if item[0] == "nvd"]),
                "retrieved": len([key for key in details if is_cve_id(key)]),
                "network_requests": nvd.requests if nvd else 0,
                "authenticated": bool(nvd and nvd.authenticated),
            } if "nvd" in options.enrich else None,
            "ghsa": {
                "requested": len([item for item in selected if item[0] == "ghsa"]),
                "retrieved": len([key for key in details if is_ghsa_id(key)]),
                "network_requests": ghsa.requests if ghsa else 0,
                "authenticated": bool(ghsa and ghsa.authenticated),
            } if "ghsa" in options.enrich else None,
            "skipped_beyond_limit": skipped,
            "failed": len(failures),
        }
        return details, failures, skipped, {key: value for key, value in enrichment_status.items() if value is not None}
