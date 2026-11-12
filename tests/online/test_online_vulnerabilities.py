"""Opt-in online vulnerability intelligence (OSV.dev, NVD, GitHub advisories).

Every test talks to the loopback advisory service in advisory_server.py through PDT's real
HTTP client; no external network is used. One test proves that local scans open no
network connection at all.
"""
from __future__ import annotations

import gzip
import io
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from advisory_server import AdvisoryService, RunningService, ghsa_record

from project_discovery import cli
from project_discovery.online import http as online_http
from project_discovery.online.cache import ResponseCache
from project_discovery.online.http import (
    HttpClient,
    NetworkError,
    RateLimiter,
    validate_service_url,
)
from project_discovery.online.osv import OSV_BATCH_SIZE, OsvClient, PackageQuery
from project_discovery.online.vulnerabilities import (
    LockfileSource,
    OnlineVulnerabilityLookup,
    OnlineVulnerabilityOptions,
)

LODASH_GHSA = "GHSA-35jh-r3h4-6jhm"
LODASH_CVE = "CVE-2021-23337"
NVD_KEY = "nvd-key-secret-0123456789"
GITHUB_TOKEN = "ghp_" + "S3cr3tT0k3nValue0123456789abcdefABCD"


@pytest.fixture(autouse=True)
def _no_proxies(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    for name in ("NVD_API_KEY", "PDT_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
                 "PDT_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)


def _service() -> AdvisoryService:
    service = AdvisoryService()
    service.affected[("npm", "lodash", "4.17.20")] = [LODASH_GHSA]
    service.records[LODASH_GHSA] = ghsa_record(
        LODASH_GHSA, "npm", "lodash", fixed="4.17.21", cve=LODASH_CVE,
    )
    return service


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "web").mkdir(parents=True)
    (project / "web" / "package-lock.json").write_text(json.dumps({
        "name": "web", "lockfileVersion": 3,
        "packages": {
            "": {"name": "web", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/left-pad": {"version": "1.3.0"},
        },
    }), encoding="utf-8")
    (project / "app.js").write_text("const _ = require('lodash');\n", encoding="utf-8")
    return project


def _options(running: RunningService, tmp_path: Path, **overrides) -> OnlineVulnerabilityOptions:
    values = {
        "cache_path": tmp_path / "cache" / "online.sqlite3",
        "osv_url": running.url, "nvd_url": running.url, "github_url": running.url,
        "timeout": 5.0, "retries": 1,
    }
    values.update(overrides)
    return OnlineVulnerabilityOptions(**values)


def _scan(project: Path, output: Path, options, **kwargs) -> tuple[int, dict]:
    code = cli.run_scan(
        project, output, {"json", "markdown", "html"}, 128, quiet=True,
        online_vulnerabilities=options, **kwargs,
    )
    return code, json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))


def _online_findings(report: dict) -> list[dict]:
    return [item for item in report["findings"] if item["analyzer"] == "online-vulnerability-intelligence"]


def test_online_lookup_reports_confirmed_osv_matches_end_to_end(tmp_path: Path):
    with RunningService(_service()) as running:
        code, report = _scan(_project(tmp_path), tmp_path / "out", _options(running, tmp_path))
        requests = list(running.service.requests)
    assert code == cli.EXIT_OK
    findings = _online_findings(report)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == f"{LODASH_GHSA}: Prototype pollution in lodash"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["severity"] == "CRITICAL"
    assert finding["evidence"][0] == "web/package-lock.json"
    assert "resolved_version: 4.17.20" in finding["evidence"]
    assert any(line.startswith("source: OSV.dev (127.0.0.1)") for line in finding["evidence"])
    assert "4.17.21" in finding["recommendation"]
    assert "OSV.dev advisory" in finding["detail"]

    online = report["metrics"]["vulnerability_intelligence"]["online"]
    assert report["metrics"]["vulnerability_intelligence"]["sources"] == ["osv.dev"]
    assert online["coverage"] == "complete"
    assert online["lockfiles"] == 1
    assert online["packages_queried"] == 2 and online["vulnerable_packages"] == 1
    assert online["requests"]["osv_querybatch"] == 1 and online["requests"]["osv_vulns"] == 1
    assert online["cache"]["writes"] == 3
    assert online["endpoint"] == running.url
    assert online["query_started_at"] <= online["query_finished_at"]
    assert [item["path"] for item in requests] == ["/v1/querybatch", f"/v1/vulns/{LODASH_GHSA}"]
    markdown = (tmp_path / "out" / "discovery-report.md").read_text(encoding="utf-8")
    assert LODASH_GHSA in markdown


def test_only_package_coordinates_are_sent(tmp_path: Path):
    project = _project(tmp_path)
    with RunningService(_service()) as running:
        _scan(project, tmp_path / "out", _options(running, tmp_path))
        requests = list(running.service.requests)
    batch = requests[0]
    assert batch["body"] == {"queries": [
        {"package": {"ecosystem": "npm", "name": "left-pad"}, "version": "1.3.0"},
        {"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.20"},
    ]}
    sent = json.dumps(requests)
    for private in (str(project), "package-lock.json", "app.js", "require("):
        assert private not in sent
    assert batch["headers"]["user-agent"].startswith("PDT/")
    assert "authorization" not in batch["headers"] and "apikey" not in batch["headers"]


def test_cached_answers_are_reused_without_network(tmp_path: Path):
    project = _project(tmp_path)
    with RunningService(_service()) as running:
        _scan(project, tmp_path / "first", _options(running, tmp_path))
        before = len(running.service.requests)
        code, report = _scan(project, tmp_path / "second", _options(running, tmp_path))
        after = len(running.service.requests)
    assert after == before
    online = report["metrics"]["vulnerability_intelligence"]["online"]
    assert online["cache"]["hits"] == 3 and online["requests"]["requests"] == 0
    assert online["coverage"] == "complete"
    assert len(_online_findings(report)) == 1


def test_zero_ttl_disables_the_cache(tmp_path: Path):
    with RunningService(_service()) as running:
        options = _options(running, tmp_path, cache_ttl_seconds=0)
        _scan(_project(tmp_path), tmp_path / "out", options)
    assert not (tmp_path / "cache" / "online.sqlite3").exists()


def test_service_failure_is_unknown_coverage_never_a_clean_result(tmp_path: Path):
    service = _service()
    service.querybatch_status = 500
    with RunningService(service) as running:
        code, report = _scan(
            _project(tmp_path), tmp_path / "out", _options(running, tmp_path),
            strict=True, fail_on="LOW",
        )
        attempts = len(running.service.paths("/v1/querybatch"))
    assert attempts == 2  # one retry
    assert code == cli.EXIT_INCOMPLETE  # UNKNOWN never trips --fail-on; --strict reports the gap
    online = report["metrics"]["vulnerability_intelligence"]["online"]
    assert online["coverage"] == "unavailable"
    assert online["packages_failed"] == 2
    findings = _online_findings(report)
    assert [item["confidence"] for item in findings] == ["UNKNOWN"]
    assert findings[0]["title"] == "Online vulnerability lookup failed for 2 package(s)"
    assert "HTTP 500" in findings[0]["detail"]
    assert "not evidence" in findings[0]["detail"]
    assert any("could not be checked against OSV.dev" in error for error in report["errors"])


def test_rate_limit_is_retried_after_the_advertised_delay(tmp_path: Path):
    service = _service()
    service.rate_limit_first_querybatch = True
    with RunningService(service) as running:
        code, report = _scan(_project(tmp_path), tmp_path / "out", _options(running, tmp_path))
    online = report["metrics"]["vulnerability_intelligence"]["online"]
    assert online["coverage"] == "complete"
    assert online["requests"]["retries"] == 1
    assert len(_online_findings(report)) == 1


def test_timeouts_are_reported_as_unknown(tmp_path: Path):
    service = _service()
    service.delay_seconds = 2.0
    with RunningService(service) as running:
        options = _options(running, tmp_path, timeout=0.3, retries=0)
        code, report = _scan(_project(tmp_path), tmp_path / "out", options)
    online = report["metrics"]["vulnerability_intelligence"]["online"]
    assert online["coverage"] == "unavailable"
    assert "timeout" in online["failures"][0]["reason"]


def test_matches_without_details_stay_confirmed_and_flag_the_gap(tmp_path: Path):
    service = _service()
    service.record_status = 503
    with RunningService(service) as running:
        code, report = _scan(_project(tmp_path), tmp_path / "out", _options(running, tmp_path))
    findings = {item["title"]: item for item in _online_findings(report)}
    match = findings[f"{LODASH_GHSA}: {LODASH_GHSA} (advisory details unavailable)"]
    assert match["confidence"] == "CONFIRMED"
    assert match["severity"] == "MEDIUM"
    assert findings["Online advisory details unavailable"]["confidence"] == "UNKNOWN"
    assert report["metrics"]["vulnerability_intelligence"]["online"]["coverage"] == "partial"


def test_withdrawn_records_are_not_reported(tmp_path: Path):
    service = _service()
    service.records[LODASH_GHSA]["withdrawn"] = "2026-01-03T00:00:00Z"
    with RunningService(service) as running:
        code, report = _scan(_project(tmp_path), tmp_path / "out", _options(running, tmp_path))
    assert _online_findings(report) == []
    assert report["metrics"]["vulnerability_intelligence"]["online"]["withdrawn_skipped"] == 1


def test_enrichment_adds_cvss_and_cwe_and_keeps_secrets_on_their_own_host(tmp_path: Path):
    service = _service()
    service.records[LODASH_GHSA] = ghsa_record(
        LODASH_GHSA, "npm", "lodash", fixed="4.17.21", cve=LODASH_CVE, severity_vector=None,
    )
    service.nvd[LODASH_CVE] = {
        "id": LODASH_CVE, "published": "2021-02-15T13:15:12.560", "lastModified": "2024-11-21T05:51:00",
        "vulnStatus": "Modified",
        "descriptions": [{"lang": "en", "value": "Lodash versions prior to 4.17.21 are vulnerable."}],
        "metrics": {"cvssMetricV31": [{
            "source": "nvd@nist.gov", "type": "Primary",
            "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                         "baseScore": 7.2, "baseSeverity": "HIGH"},
        }]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-94"}]}],
        "references": [{"url": "https://github.com/lodash/lodash/blob/master/lodash.js"}],
    }
    service.ghsa[LODASH_GHSA] = {
        "ghsa_id": LODASH_GHSA, "cve_id": LODASH_CVE, "severity": "high", "summary": "Command Injection in lodash",
        "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "score": 7.2}},
        "cwes": [{"cwe_id": "CWE-77", "name": "Command Injection"}],
        "identifiers": [{"type": "GHSA", "value": LODASH_GHSA}, {"type": "CVE", "value": LODASH_CVE}],
        "html_url": f"https://github.com/advisories/{LODASH_GHSA}",
    }
    with RunningService(service) as running:
        options = _options(
            running, tmp_path, enrich=frozenset({"nvd", "ghsa"}),
            nvd_api_key=NVD_KEY, github_token=GITHUB_TOKEN,
        )
        code, report = _scan(_project(tmp_path), tmp_path / "out", options)
        requests = list(running.service.requests)
    finding = _online_findings(report)[0]
    assert finding["severity"] == "HIGH"  # from enrichment: the OSV record had no severity
    assert any(line.startswith("cvss_3.1: 7.2 CVSS:3.1/AV:N/AC:L/PR:H") for line in finding["evidence"])
    assert "cwe: CWE-94 (NVD CVE-2021-23337)" in finding["evidence"]
    assert "cwe: CWE-77 (GitHub Advisory Database GHSA-35jh-r3h4-6jhm)" in finding["evidence"]
    for item in requests:
        if item["path"].startswith("/rest/json/cves/2.0"):
            assert item["headers"]["apikey"] == NVD_KEY and "authorization" not in item["headers"]
        elif item["path"].startswith("/advisories/"):
            assert item["headers"]["authorization"] == f"Bearer {GITHUB_TOKEN}" and "apikey" not in item["headers"]
        else:
            assert "apikey" not in item["headers"] and "authorization" not in item["headers"]
    online = report["metrics"]["vulnerability_intelligence"]["online"]
    assert online["nvd_api_key_used"] is True and online["github_token_used"] is True
    assert online["enrichment_status"]["nvd"]["retrieved"] == 1
    assert online["enrichment_status"]["ghsa"]["retrieved"] == 1
    everything = "\n".join(path.read_text(encoding="utf-8") for path in (tmp_path / "out").glob("discovery-report.*"))
    assert NVD_KEY not in everything and GITHUB_TOKEN not in everything
    assert NVD_KEY not in repr(options) and GITHUB_TOKEN not in repr(options)
    cache_bytes = (tmp_path / "cache" / "online.sqlite3").read_bytes()
    assert NVD_KEY.encode() not in cache_bytes and GITHUB_TOKEN.encode() not in cache_bytes


def test_enrichment_limit_is_reported(tmp_path: Path):
    service = _service()
    with RunningService(service) as running:
        options = _options(running, tmp_path, enrich=frozenset({"nvd"}), max_enrichment=0)
        code, report = _scan(_project(tmp_path), tmp_path / "out", options)
    titles = {item["title"]: item for item in _online_findings(report)}
    assert titles["CVE/advisory enrichment incomplete"]["severity"] == "INFO"
    assert report["metrics"]["vulnerability_intelligence"]["online"]["enrichment_status"]["skipped_beyond_limit"] == 1


def test_osv_pagination_and_batching(tmp_path: Path):
    service = AdvisoryService()
    service.affected[("PyPI", "jinja2", "2.10")] = [["PYSEC-2019-1"], ["PYSEC-2020-2", "GHSA-462w-v97r-4m45"]]
    packages = [PackageQuery("PyPI", f"package-{index}", "1.0") for index in range(OSV_BATCH_SIZE + 250)]
    packages.append(PackageQuery("PyPI", "jinja2", "2.10"))
    with RunningService(service) as running, ResponseCache(None) as cache:
        client = OsvClient(HttpClient(timeout=5, retries=0), cache, base_url=running.url)
        results, failures = client.query(packages)
        batches = running.service.paths("/v1/querybatch")
    assert failures == {}
    assert results[PackageQuery("PyPI", "jinja2", "2.10")] == ["GHSA-462w-v97r-4m45", "PYSEC-2019-1", "PYSEC-2020-2"]
    assert [len(item["body"]["queries"]) for item in batches] == [OSV_BATCH_SIZE, 251, 1]
    assert batches[-1]["body"]["queries"][0]["page_token"] == "1"


def test_go_module_versions_are_sent_without_the_v_prefix(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "go.sum").write_text(
        "golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\n"
        "golang.org/x/text v0.3.7/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=\n",
        encoding="utf-8",
    )
    service = AdvisoryService()
    service.affected[("Go", "golang.org/x/text", "0.3.7")] = ["GO-2022-1059"]
    service.records["GO-2022-1059"] = ghsa_record("GO-2022-1059", "Go", "golang.org/x/text", fixed="0.3.8")
    with RunningService(service) as running:
        code, report = _scan(project, tmp_path / "out", _options(running, tmp_path))
        body = running.service.paths("/v1/querybatch")[0]["body"]
    assert body["queries"] == [{"package": {"ecosystem": "Go", "name": "golang.org/x/text"}, "version": "0.3.7"}]
    finding = _online_findings(report)[0]
    assert finding["title"].startswith("GO-2022-1059")
    assert "resolved_version: v0.3.7" in finding["evidence"]


def test_unreadable_lockfiles_are_reported(tmp_path: Path):
    def broken():
        raise OSError("permission denied")

    with RunningService(_service()) as running:
        result = OnlineVulnerabilityLookup(_options(running, tmp_path)).run([
            LockfileSource("a/package-lock.json", broken),
            LockfileSource("b/package-lock.json", lambda: "{not json"),
        ])
    assert result.status["lockfiles_unreadable"] == 2
    assert result.status["coverage"] == "partial"
    gap = next(item for item in result.findings if item.title.startswith("Lockfile(s) not checked online"))
    assert gap.confidence == "UNKNOWN" and gap.evidence == ["a/package-lock.json", "b/package-lock.json"]
    assert result.diagnostics


def test_lookup_without_lockfiles_is_not_applicable(tmp_path: Path):
    with RunningService(_service()) as running:
        result = OnlineVulnerabilityLookup(_options(running, tmp_path)).run([])
        assert running.service.requests == []
    assert result.status["coverage"] == "not_applicable" and result.findings == []


# ---------------------------------------------------------------------------
# Local mode stays offline
# ---------------------------------------------------------------------------

def test_local_scans_open_no_network_connections(tmp_path: Path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError(f"local scan attempted a network connection: {args!r}")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    project = _project(tmp_path)
    code = cli.run_scan(project, tmp_path / "out", {"json", "markdown", "html"}, 128, quiet=True)
    assert code == cli.EXIT_OK
    report = json.loads((tmp_path / "out" / "discovery-report.json").read_text(encoding="utf-8"))
    assert "online" not in report["metrics"]["vulnerability_intelligence"]
    assert report["metrics"]["vulnerability_intelligence"]["sources"] == []


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def _run_cli(monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


@pytest.mark.parametrize(
    "option", [["--vuln-enrich", "nvd"], ["--vuln-cache", "c.sqlite3"], ["--vuln-cache-ttl", "1"],
               ["--network-timeout", "5"], ["--ca-bundle", "ca.pem"]],
)
def test_online_options_require_vuln_online(tmp_path: Path, monkeypatch, option):
    assert _run_cli(monkeypatch, "scan", str(tmp_path), *option) == 2


def test_online_endpoint_must_be_https_or_loopback(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("PDT_OSV_API_URL", "http://osv.example.net")
    assert _run_cli(monkeypatch, "scan", str(_project(tmp_path)), "--vuln-online",
                    "--output", str(tmp_path / "out"), "--quiet") == 2
    assert "https" in capsys.readouterr().err


def test_cli_vuln_online_end_to_end_with_cache_option(tmp_path: Path, monkeypatch):
    with RunningService(_service()) as running:
        monkeypatch.setenv("PDT_OSV_API_URL", running.url)
        code = _run_cli(
            monkeypatch, "scan", str(_project(tmp_path)), "--vuln-online",
            "--vuln-cache", str(tmp_path / "c.sqlite3"), "--vuln-cache-ttl", "2",
            "--network-timeout", "5", "--output", str(tmp_path / "out"), "--quiet",
        )
    assert code == 0
    report = json.loads((tmp_path / "out" / "discovery-report.json").read_text(encoding="utf-8"))
    assert report["metrics"]["vulnerability_intelligence"]["online"]["cache"]["ttl_seconds"] == 7200
    assert (tmp_path / "c.sqlite3").is_file()


def test_cache_inside_the_project_is_refused(tmp_path: Path, monkeypatch):
    project = _project(tmp_path)
    with RunningService(_service()) as running:
        monkeypatch.setenv("PDT_OSV_API_URL", running.url)
        code = _run_cli(monkeypatch, "scan", str(project), "--vuln-online",
                        "--vuln-cache", str(project / "cache.sqlite3"), "--output",
                        str(tmp_path / "out"), "--quiet")
    assert code == 2
    assert not (project / "cache.sqlite3").exists()


def test_invalid_enrichment_source_is_rejected(tmp_path: Path, monkeypatch):
    assert _run_cli(monkeypatch, "scan", str(tmp_path), "--vuln-online", "--vuln-enrich", "nvd,exploitdb") == 2


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("url", "ok"),
    [("https://api.osv.dev", True), ("http://127.0.0.1:8080", True), ("http://[::1]:9", True),
     ("http://localhost:1", True), ("http://api.osv.dev", False), ("ftp://api.osv.dev", False),
     ("https://user:pw@api.osv.dev", False), ("https://api.osv.dev/?token=x", False)],
)
def test_service_url_policy(url: str, ok: bool):
    if ok:
        assert validate_service_url(url, label="test")
    else:
        with pytest.raises(ValueError):
            validate_service_url(url, label="test")


class _RawHandler(BaseHTTPRequestHandler):
    routes: dict = {}
    seen: list = []

    def log_message(self, *_args):
        return

    def do_GET(self):
        self.seen.append((self.path, dict(self.headers)))
        status, headers, body = self.routes.get(self.path, (404, {}, b"{}"))
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def raw_server():
    handler = type("Raw", (_RawHandler,), {"routes": {}, "seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield handler, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_cross_host_redirects_are_refused_and_secrets_not_forwarded(raw_server):
    handler, url = raw_server
    handler.routes["/start"] = (302, {"Location": "http://localhost:1/steal"}, b"")
    handler.routes["/same"] = (302, {"Location": "/final"}, b"")
    handler.routes["/final"] = (200, {}, b'{"ok": true}')
    client = HttpClient(timeout=5, retries=0)
    with pytest.raises(NetworkError, match="redirected to another host"):
        client.get_json(url + "/start", secret_headers={"Authorization": "Bearer t"})
    status, payload = client.get_json(url + "/same", secret_headers={"Authorization": "Bearer t"})
    assert payload == {"ok": True}
    final = [headers for path, headers in handler.seen if path == "/final"][0]
    assert final.get("Authorization") == "Bearer t"


def test_response_size_and_gzip_bombs_are_bounded(raw_server):
    handler, url = raw_server
    handler.routes["/big"] = (200, {}, b"x" * 5000)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as stream:
        stream.write(b"0" * 200_000)
    handler.routes["/bomb"] = (200, {"Content-Encoding": "gzip"}, buffer.getvalue())
    handler.routes["/small-gzip"] = (200, {"Content-Encoding": "gzip"}, gzip.compress(b'{"a": 1}'))
    client = HttpClient(timeout=5, retries=0)
    with pytest.raises(NetworkError, match="exceeds"):
        client.request("GET", url + "/big", max_bytes=1000)
    with pytest.raises(NetworkError, match="decompressed response exceeds"):
        client.request("GET", url + "/bomb", max_bytes=10_000)
    assert client.get_json(url + "/small-gzip")[1] == {"a": 1}


def test_http_errors_are_not_retried_and_404_can_be_allowed(raw_server):
    handler, url = raw_server
    handler.routes["/forbidden"] = (403, {}, b"{}")
    client = HttpClient(timeout=5, retries=3)
    with pytest.raises(NetworkError, match="HTTP 403"):
        client.get_json(url + "/forbidden")
    assert [path for path, _ in handler.seen].count("/forbidden") == 1
    assert client.get_json(url + "/missing", not_found_ok=True) == (404, None)


def test_retry_after_beyond_the_bound_is_not_waited_for(raw_server):
    handler, url = raw_server
    handler.routes["/limited"] = (429, {"Retry-After": "3600"}, b"{}")
    started = time.monotonic()
    with pytest.raises(NetworkError) as error:
        HttpClient(timeout=5, retries=3).get_json(url + "/limited")
    assert error.value.kind == "rate_limit" and time.monotonic() - started < 5


def test_proxy_environment_is_honored(monkeypatch):
    seen = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            seen.append(self.path)
            body = b'{"proxied": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{server.server_address[1]}")
        status, payload = HttpClient(timeout=5, retries=0).get_json("http://127.0.0.1:9/v1/vulns/X")
    finally:
        server.shutdown()
        server.server_close()
    assert payload == {"proxied": True}
    assert seen == ["http://127.0.0.1:9/v1/vulns/X"]


def test_ca_bundle_resolution(tmp_path: Path, monkeypatch):
    bundle = tmp_path / "corporate-ca.pem"
    bundle.write_text("not a real certificate\n", encoding="utf-8")
    assert online_http.resolve_ca_bundle(bundle) == bundle
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    assert online_http.resolve_ca_bundle(None) == bundle
    monkeypatch.setenv("PDT_CA_BUNDLE", str(tmp_path / "missing.pem"))
    with pytest.raises(FileNotFoundError, match="PDT_CA_BUNDLE"):
        online_http.resolve_ca_bundle(None)
    with pytest.raises(FileNotFoundError):
        online_http.resolve_ca_bundle(tmp_path / "absent.pem")


def test_rate_limiter_enforces_a_rolling_window():
    limiter = RateLimiter(3, 0.5)
    started = time.monotonic()
    for _ in range(6):
        limiter.acquire()
    assert time.monotonic() - started >= 0.45


def test_cache_expires_entries(tmp_path: Path):
    with ResponseCache(tmp_path / "c.sqlite3", ttl_seconds=0.2) as cache:
        cache.put("osv:query:x", ["A"])
        assert cache.get("osv:query:x") == ["A"]
        time.sleep(0.3)
        assert cache.get("osv:query:x") is None
        assert cache.statistics()["hits"] == 1 and cache.statistics()["misses"] == 1


# ---------------------------------------------------------------------------
# Opt-in live checks against the real services (never run in CI)
# ---------------------------------------------------------------------------

_LIVE = pytest.mark.skipif(
    __import__("os").environ.get("PDT_LIVE_NETWORK_TESTS") != "1",
    reason="set PDT_LIVE_NETWORK_TESTS=1 to query the real OSV.dev, NVD and GitHub APIs",
)


@_LIVE
def test_live_osv_nvd_and_github_lookups(tmp_path: Path, monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"):
        value = __import__("os").environ.get("PDT_LIVE_" + name)
        if value:
            monkeypatch.setenv(name, value)
    options = OnlineVulnerabilityOptions(
        cache_path=None, enrich=frozenset({"nvd", "ghsa"}), max_enrichment=2, timeout=30,
    )
    result = OnlineVulnerabilityLookup(options).run([
        LockfileSource("package-lock.json", lambda: json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {"name": "live"}, "node_modules/lodash": {"version": "4.17.20"}},
        })),
    ])
    assert result.status["coverage"] == "complete", result.status
    titles = [finding.title for finding in result.findings if finding.confidence == "CONFIRMED"]
    assert any(title.startswith(LODASH_GHSA) for title in titles), titles
    assert result.status["requests"]["osv_querybatch"] == 1


def test_online_fix_boundary_comes_from_the_matching_release_line(tmp_path: Path):
    # Regression: only the record's first affected entry was used, so semver 6.3.0 was told
    # to upgrade to 7.5.2 (another release line) instead of 6.3.1.
    service = AdvisoryService()
    service.affected[("npm", "semver", "6.3.0")] = ["GHSA-c2qf-rxjj-qqgw"]
    record = ghsa_record("GHSA-c2qf-rxjj-qqgw", "npm", "semver", fixed="7.5.2")
    record["affected"] = [
        {"package": {"ecosystem": "npm", "name": "semver"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}
        for introduced, fixed in (("7.0.0", "7.5.2"), ("6.0.0", "6.3.1"), ("0", "5.7.2"))
    ]
    service.records["GHSA-c2qf-rxjj-qqgw"] = record
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/semver": {"version": "6.3.0"},
    }}), encoding="utf-8")
    with RunningService(service) as running:
        _, report = _scan(project, tmp_path / "out", _options(running, tmp_path))
    [finding] = _online_findings(report)
    text = json.dumps(finding)
    assert "6.3.1" in text and "7.5.2" not in finding["recommendation"]


def test_every_lockfile_sharing_a_vulnerable_package_gets_its_finding(tmp_path: Path):
    # Regression: findings were built for the first 20 lockfiles only, silently.
    project = tmp_path / "project"
    for index in range(25):
        folder = project / f"service-{index:02}"
        folder.mkdir(parents=True)
        (folder / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": f"service-{index}"}, "node_modules/lodash": {"version": "4.17.20"},
        }}), encoding="utf-8")
    with RunningService(_service()) as running:
        _, report = _scan(project, tmp_path / "out", _options(running, tmp_path))
    lockfiles = {item["evidence"][0] for item in _online_findings(report)}
    assert len(lockfiles) == 25


def test_a_corrupt_cache_fails_before_the_scan_starts(tmp_path: Path):
    # Regression: the cache was first opened after the whole analysis, so a damaged file
    # aborted the scan at the end and no report was written.
    cache = tmp_path / "cache" / "online.sqlite3"
    cache.parent.mkdir()
    cache.write_bytes(b"this is not a database" * 100)
    with RunningService(_service()) as running:
        with pytest.raises(ValueError, match="unusable"):
            _scan(_project(tmp_path), tmp_path / "out", _options(running, tmp_path))
