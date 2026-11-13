"""JSON, Markdown and HTML reports for local and online scans (schema 1.7 and later).

The HTML client is executed with Node.js against a minimal DOM so the rendered text of the
scan-source and vulnerability-provenance views is checked, not just the template.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from project_discovery.models import REPORT_SCHEMA_VERSION, FileRecord, Finding, ScanResult
from project_discovery.reporting.writers import public_url, scan_summary, write_reports


def _remote_metadata(**overrides) -> dict:
    metadata = {
        "mode": "remote", "acquisition": "download", "vcs": "git", "provider": "GitHub",
        "url": "https://github.com/acme/widgets", "repository": "widgets", "identity": "abc123",
        "ref": "v2.1.0", "revision": "0123456789abcdef0123456789abcdef01234567", "branch": None,
        "transport": "https", "transport_insecure": False,
        "acquired_at": "2026-11-06T10:00:00+00:00", "acquisition_seconds": 3.25,
        "history_complete": False,
        "coverage": [
            {"kind": "git_submodules_not_fetched", "count": 1, "incomplete": False,
             "detail": "1 Git submodule(s) were inventoried but not fetched."},
            {"kind": "paths_not_materialized", "count": 2, "incomplete": True,
             "detail": "2 tracked path(s) could not be materialized safely."},
        ],
        "coverage_gaps": ["2 tracked path(s) could not be materialized safely."],
        "warnings": [
            "1 Git submodule(s) were inventoried but not fetched.",
            "2 tracked path(s) could not be materialized safely.",
        ],
    }
    metadata.update(overrides)
    return metadata


def _online_status(**overrides) -> dict:
    status = {
        "enabled": True, "provider": "OSV.dev", "endpoint": "https://api.osv.dev",
        "enrichment": ["nvd"], "data_sent": "package ecosystem, name and version; advisory IDs for enrichment",
        "query_started_at": "2026-11-06T10:00:05+00:00", "query_finished_at": "2026-11-06T10:00:06+00:00",
        "query_seconds": 1.2, "coverage": "complete", "lockfiles": 1, "lockfiles_unreadable": 0,
        "unique_packages": 3, "packages_queried": 3, "packages_failed": 0, "vulnerable_packages": 1,
        "advisories": 1, "findings": 1,
        "cache": {"enabled": True, "ttl_seconds": 86400.0, "hits": 2, "misses": 2, "writes": 2},
        "requests": {"requests": 3, "requests_by_host": {"api.osv.dev": 2, "services.nvd.nist.gov": 1},
                     "failed_requests": 0, "retries": 0, "bytes_received": 1000},
        "failures": [],
    }
    status.update(overrides)
    return status


def _result(*, remote: dict | None = None, online: dict | None = None, local_db: bool = False) -> ScanResult:
    vulnerability = {"enabled": local_db, "advisory_count": 50 if local_db else 0,
                     "sources": (["local-database"] if local_db else []) + (["osv.dev"] if online else [])}
    if local_db:
        vulnerability["last_imported_at"] = "2026-11-01T00:00:00+00:00"
    if online is not None:
        vulnerability["online"] = online
    findings = [Finding(
        "vulnerabilities", "GHSA-35jh-r3h4-6jhm: Command Injection in lodash",
        "npm package lodash@4.17.20 matched OSV.dev advisory GHSA-35jh-r3h4-6jhm.",
        confidence="CONFIRMED", severity="HIGH", analyzer="online-vulnerability-intelligence",
        evidence=["package-lock.json", "package: lodash", "source: OSV.dev (api.osv.dev), queried 2026-11-06"],
    )] if online else []
    return ScanResult(
        root=remote["url"] if remote else "/srv/projects/app",
        started_at="2026-11-06T10:00:00+00:00", finished_at="2026-11-06T10:01:00+00:00",
        files=[FileRecord("package-lock.json", 200, ".json", "JSON", file_type="text")],
        findings=findings,
        metrics={
            "source": {"mode": "remote" if remote else "local", "remote": remote},
            "vulnerability_intelligence": vulnerability,
            "file_types": {"text": 1}, "size_buckets": {}, "development_directories": {},
        },
    )


# ---------------------------------------------------------------------------
# Shared scan summary
# ---------------------------------------------------------------------------

def test_scan_summary_for_each_mode():
    local = scan_summary(_result().metrics)
    assert local == {
        "mode": "local", "source": "local", "network_access": [], "remote": None,
        "vulnerability_sources": [], "online_vulnerability_coverage": None,
    }
    offline_db = scan_summary(_result(local_db=True).metrics)
    assert offline_db["mode"] == "local" and offline_db["vulnerability_sources"] == ["local-database"]
    online_local = scan_summary(_result(online=_online_status()).metrics)
    assert online_local["mode"] == "online" and online_local["source"] == "local"
    assert online_local["network_access"] == ["osv.dev", "nvd"]
    remote = scan_summary(_result(remote=_remote_metadata(), online=_online_status()).metrics)
    assert remote["mode"] == "online" and remote["source"] == "remote"
    assert remote["network_access"] == ["git-client", "osv.dev", "nvd"]
    assert remote["remote"]["revision"].startswith("0123")
    assert remote["remote"]["coverage_gap_count"] == 1
    api = scan_summary(_result(remote=_remote_metadata(acquisition="api")).metrics)
    assert api["network_access"] == ["provider-api"]
    skipped = scan_summary(_result(online=_online_status(coverage="skipped")).metrics)
    assert skipped["mode"] == "local"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://user:secret@github.com/acme/x.git?token=abc#frag", "https://github.com/acme/x.git"),
        ("ssh://git@github.com:2222/acme/x.git", "ssh://git@github.com:2222/acme/x.git"),
        ("http://[::1]:8080/path?q=1", "http://[::1]:8080/path"),
        ("git@github.com:acme/x.git", "git@github.com:acme/x.git"),
        (None, ""),
    ],
)
def test_public_url_drops_credentials_queries_and_fragments(raw, expected):
    assert public_url(raw) == expected


def test_summary_never_repeats_url_credentials():
    result = _result(remote=_remote_metadata(url="https://user:hunter2@git.example.net/r.git?private_token=x"))
    assert scan_summary(result.metrics)["remote"]["url"] == "https://git.example.net/r.git"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def test_json_reports_carry_the_scan_summary(tmp_path: Path):
    for name, result in {
        "local": _result(),
        "remote": _result(remote=_remote_metadata(), online=_online_status()),
    }.items():
        payload = json.loads(write_reports(result, tmp_path / name, {"json"})[0].read_text(encoding="utf-8"))
        assert payload["schema_version"] == REPORT_SCHEMA_VERSION == "1.8"
        assert payload["scan"] == scan_summary(result.metrics)
    assert payload["scan"]["remote"]["url"] == "https://github.com/acme/widgets"
    assert payload["metrics"]["vulnerability_intelligence"]["online"]["cache"]["hits"] == 2


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _markdown(result: ScanResult, tmp_path: Path) -> str:
    return write_reports(result, tmp_path, {"markdown"})[0].read_text(encoding="utf-8")


def test_markdown_local_scan_states_that_no_network_was_used(tmp_path: Path):
    content = _markdown(_result(), tmp_path)
    assert "- Scan mode: local (no network access)" in content
    assert "- Source: local directory" in content
    assert "## Scan Source" in content
    assert "Not used: no advisory service was contacted" in content
    assert "none configured (use --vuln-db or --vuln-online). This is not a vulnerability-free result." in content


def test_markdown_online_scan_shows_source_and_vulnerability_provenance(tmp_path: Path):
    content = _markdown(_result(remote=_remote_metadata(), online=_online_status(), local_db=True), tmp_path)
    assert "- Scan mode: online (network used: git-client, OSV.dev, NVD)" in content
    assert "remote repository https://github.com/acme/widgets (downloaded to a temporary directory" in content
    assert "- Requested ref: v2.1.0" in content
    assert "- Revision analyzed: 0123456789abcdef0123456789abcdef01234567" in content
    assert "- Transport: https (encrypted)" in content
    assert "- Acquired: 2026-11-06T10:00:00+00:00 (3.25 s)" in content
    assert "2 tracked path(s) could not be materialized safely. (missing from the analyzed tree)" in content
    assert "1 Git submodule(s) were inventoried but not fetched. (not fetched)" in content
    assert "- Sources: local advisory database, OSV.dev (online)" in content
    assert "- Provider: OSV.dev (https://api.osv.dev)" in content
    assert "- Query time: 2026-11-06T10:00:05+00:00 to 2026-11-06T10:00:06+00:00 (1.2 s)" in content
    assert "- Coverage: complete" in content
    assert "- Cache: 2 hit(s), 2 miss(es), TTL 24 h" in content
    assert "- Requests: 3 (api.osv.dev 2, services.nvd.nist.gov 1); retries 0; failed 0" in content
    assert "(online-vulnerability-intelligence)" in content
    assert "**Incomplete:**" not in content


def test_markdown_flags_incomplete_lookups_and_plain_text_transports(tmp_path: Path):
    result = _result(
        remote=_remote_metadata(transport="git", transport_insecure=True,
                                url="git://git.example.net/project.git"),
        online=_online_status(coverage="partial", packages_failed=2,
                              failures=[{"reason": "timeout: timed out", "packages": 2}]),
    )
    content = _markdown(result, tmp_path)
    assert "- Transport: git — **not encrypted** (accepted with --allow-insecure-transport)" in content
    assert "- **Incomplete:** 2 package(s) could not be checked" in content
    assert "This is not a vulnerability-free result" in content
    assert "- Failure: timeout: timed out (2 package(s))" in content


def test_markdown_api_mode_source_label(tmp_path: Path):
    content = _markdown(_result(remote=_remote_metadata(acquisition="api")), tmp_path)
    assert "read through the provider API, not downloaded" in content
    assert "- Source: remote repository (provider API)" in content


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def test_html_template_shows_the_scan_mode_without_javascript(tmp_path: Path):
    local = write_reports(_result(), tmp_path / "local", {"html"})[0].read_text(encoding="utf-8")
    online = write_reports(
        _result(remote=_remote_metadata(), online=_online_status()), tmp_path / "online", {"html"},
    )[0].read_text(encoding="utf-8")
    assert 'class="badge mode-local">LOCAL SCAN<' in local
    assert "LOCAL SCAN // OFFLINE REPORT // STATIC EVIDENCE" in local
    assert 'class="badge mode-online">ONLINE SCAN<' in online
    for element in ('id="source-details"', 'id="source-coverage"', 'id="vuln-provenance"',
                    'id="vuln-online-state"', 'id="vuln-coverage-warning"', 'href="#source"'):
        assert element in online
    assert '"scan":{"mode":"online"' in online


_DOM_SHIM = r"""
"use strict";
class ClassList {
  constructor() { this.items = new Set(); }
  add(...names) { names.forEach((name) => this.items.add(name)); }
  remove(...names) { names.forEach((name) => this.items.delete(name)); }
  toggle(name, force) {
    const on = force === undefined ? !this.items.has(name) : Boolean(force);
    if (on) this.items.add(name); else this.items.delete(name);
    return on;
  }
  contains(name) { return this.items.has(name); }
}
class Element {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase(); this.children = []; this.text = "";
    this.className = ""; this.classList = new ClassList(); this.style = {}; this.value = "";
    this.disabled = false; this.open = false; this.listeners = {};
  }
  get textContent() { return this.text + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) { this.text = String(value); this.children = []; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; this.text = ""; }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  querySelectorAll() { return []; }
}
const elements = new Map();
globalThis.document = {
  getElementById(id) { if (!elements.has(id)) elements.set(id, new Element("div")); return elements.get(id); },
  createElement(tag) { return new Element(tag); },
};
"""

_DOM_DUMP = r"""
const dump = {};
for (const [id, element] of elements) {
  dump[id] = {
    text: element.textContent, hidden: element.classList.contains("hidden"),
    className: element.className,
    rows: element.children.map((child) => child.children.map((cell) => cell.textContent)),
  };
}
process.stdout.write(JSON.stringify(dump));
"""


def _render_html_client(result: ScanResult, tmp_path: Path) -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    content = write_reports(result, tmp_path, {"html"})[0].read_text(encoding="utf-8")
    script = re.search(r'<script nonce="[^"]+">\n(.*)\n</script>', content, re.S).group(1)
    program = tmp_path / "render.js"
    program.write_bytes((_DOM_SHIM + script + _DOM_DUMP).encode("utf-8"))
    completed = subprocess.run([node, str(program)], capture_output=True, timeout=120)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout.decode("utf-8"))


def _rows(dump: dict, element: str) -> dict:
    return {row[0]: row[1] for row in dump[element]["rows"] if len(row) == 2}


def test_html_client_renders_a_local_scan(tmp_path: Path):
    dump = _render_html_client(_result(), tmp_path)
    assert dump["source-line"]["text"] == "Local directory"
    assert dump["source-summary"]["text"] == "Local directory // no network access"
    assert _rows(dump, "source-details") == {"Mode": "local", "Source": "local directory", "Network access": "none"}
    assert dump["vuln-online-state"]["text"] == "ONLINE LOOKUP OFF"
    assert dump["vuln-provenance"]["rows"] == []
    assert dump["vuln-coverage-warning"]["hidden"] is True
    assert dump["source-coverage"]["hidden"] is True


def test_html_client_renders_remote_source_and_online_provenance(tmp_path: Path):
    dump = _render_html_client(
        _result(remote=_remote_metadata(transport="git", transport_insecure=True), online=_online_status()),
        tmp_path,
    )
    assert dump["source-line"]["text"] == "GitHub / git @ 0123456789abcdef0123456789abcdef01234567"
    assert dump["transport-badge"]["hidden"] is False
    details = _rows(dump, "source-details")
    assert details["Mode"] == "online"
    assert details["Network access"] == "git-client, OSV.dev, NVD"
    assert details["URL"] == "https://github.com/acme/widgets"
    assert details["Requested ref"] == "v2.1.0"
    assert details["Transport"] == "git (NOT ENCRYPTED)"
    assert details["Acquired"] == "2026-11-06T10:00:00+00:00 (3.25 s)"
    assert dump["source-coverage"]["hidden"] is False
    assert "(missing from the analyzed tree)" in dump["source-coverage"]["text"]
    provenance = _rows(dump, "vuln-provenance")
    assert provenance["Online source"] == "OSV.dev (https://api.osv.dev)"
    assert provenance["Coverage"] == "complete"
    assert provenance["Cache"] == "2 hit(s) • 2 miss(es) • TTL 24 h"
    assert provenance["Query time"].startswith("2026-11-06T10:00:05+00:00 → ")
    assert dump["vuln-online-state"]["text"] == "ONLINE: COMPLETE"
    assert dump["vuln-coverage-warning"]["hidden"] is True
    assert "OSV.DEV" in dump["vulnerability-findings"]["text"]


def test_html_client_warns_when_the_online_lookup_is_incomplete(tmp_path: Path):
    dump = _render_html_client(
        _result(online=_online_status(coverage="unavailable", packages_failed=3, packages_queried=0)), tmp_path,
    )
    assert dump["vuln-coverage-warning"]["hidden"] is False
    assert "not a vulnerability-free result" in dump["vuln-coverage-warning"]["text"]
    assert dump["vuln-online-state"]["className"] == "badge unavailable"
    assert dump["source-summary"]["text"] == "Local directory // online advisory lookup"


def test_html_views_count_every_finding_when_the_slice_is_truncated(tmp_path: Path, monkeypatch):
    # Regression: the vulnerability and VCS views counted only the embedded, severity-
    # ordered slice, so in large reports they claimed "0" and "No ... evidence".
    import project_discovery.reporting.writers as reporting

    result = _result()
    result.findings = [Finding("security", f"High {index}", "d", severity="HIGH") for index in range(3)] + [
        Finding("vulnerabilities", "GHSA-xxxx: lodash", "d", confidence="CONFIRMED", severity="LOW"),
        Finding("vcs", "GitHub: remote origin", "d", severity="INFO"),
        Finding("hosting_providers", "GitLab: remote mirror", "d", severity="INFO"),
    ]
    monkeypatch.setitem(reporting.HTML_MAX_EMBEDDED, "findings", 1)
    dump = _render_html_client(result, tmp_path)
    assert "1 vulnerability finding(s)" in dump["vuln-summary"]["text"]
    assert dump["vcs-summary"]["text"].startswith("2 evidence item(s)")
    assert "GitHub" in dump["vcs-summary"]["text"] and "GitLab" in dump["vcs-summary"]["text"]


def test_reports_summarize_entry_attributes_and_security_metadata(tmp_path: Path):
    result = _result()
    result.metrics["entry_attributes"] = {"archive": 5, "readonly": 2}
    result.metrics["security_metadata"] = {"enabled": True, "entries": 7, "explicit_acl_entries": 1, "errors": 2}
    result.files[0].attributes = ["readonly", "archive"]
    markdown = write_reports(result, tmp_path, {"markdown"})[0].read_text(encoding="utf-8")
    assert "- Entry attributes: archive 5, readonly 2" in markdown
    assert "- Security metadata: 7 entries read, 1 with ACL entries of their own, 2 unreadable" in markdown
    dump = _render_html_client(result, tmp_path)
    assert [row[0] for row in dump["entry-attributes"]["rows"]] == ["archive", "readonly"]
    assert dump["inventory-summary"]["text"].endswith(
        " • security metadata: 7 entries, 1 with ACL entries of their own, 2 unreadable"
    )
    assert dump["file-rows"]["rows"][0][4] == "readonly / archive"
    # A scan without the option shows neither, and says so in Markdown.
    plain = _result()
    markdown = write_reports(plain, tmp_path / "plain", {"markdown"})[0].read_text(encoding="utf-8")
    assert "- Entry attributes: none recorded" in markdown
    assert "- Security metadata: not recorded (pdt scan --security-metadata records owners and ACLs)" in markdown
    dump = _render_html_client(plain, tmp_path / "plain")
    assert dump["entry-attributes"]["text"] == "No entries"
    assert "security metadata" not in dump["inventory-summary"]["text"]
