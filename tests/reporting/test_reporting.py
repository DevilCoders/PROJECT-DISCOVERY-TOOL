import json
from pathlib import Path

from project_discovery.models import (
    CodeEvidence,
    DirectoryRecord,
    FileRecord,
    Finding,
    ScanResult,
    SpecialEntryRecord,
    SymlinkRecord,
)
from project_discovery.reporting.writers import write_reports


def _result() -> ScanResult:
    return ScanResult(
        root="/private/project",
        started_at="2026-11-03T10:00:00+00:00",
        finished_at="2026-11-03T10:01:00+00:00",
        files=[
            FileRecord(
                "src/app.py", 128, ".py", "Python",
                file_type="text", size_bucket="4-64KiB",
            ),
            FileRecord(
                ".env", 64, "", "Other", file_type="text", is_hidden=True,
            ),
        ],
        findings=[
            Finding(
                "security", "<script>alert('x')</script>",
                "Potential secret <value> redacted.", confidence="INFERRED",
                evidence=["config.py:12"], analyzer="secret-patterns", severity="HIGH",
                code_evidence=[CodeEvidence(12, "query = build_query(user_input) + [REDACTED]")],
                impact="If untrusted input reaches this query, an attacker may read or alter database records.",
                recommendation="Use parameterized SQL and validate input.",
            ),
            Finding(
                "network", "IPv4 address indicators: config.yaml",
                "Detected one IP indicator.", confidence="CONFIRMED",
                evidence=["config.yaml:4 (192.0.2.1)"], analyzer="network-indicators",
            ),
            Finding(
                "vulnerabilities", "GHSA-unit-test-1234: Vulnerable dependency",
                "requests@2.31.0 matched a local OSV advisory. Secret-free evidence.",
                confidence="CONFIRMED", evidence=["poetry.lock", "package: requests", "resolved_version: 2.31.0"],
                analyzer="local-vulnerability-intelligence", severity="HIGH",
            ),
            Finding(
                "hosting_providers", "Git remote provider: GitHub",
                "Remote origin points to github.com; sanitized locator only.",
                confidence="CONFIRMED", evidence=[".git/config", "remote section: origin"],
                analyzer="vcs-hosting-intelligence",
            ),
        ],
        metrics={
            "file_count": 2, "total_bytes": 192, "directory_count": 1,
            "symlink_count": 1, "hidden_entry_count": 1,
            "file_types": {"text": 2}, "size_buckets": {"4-64KiB": 2},
            "development_directories": {"node_dependencies": 1},
            "host_os": {"system": "Linux", "machine": "x86_64"},
            "native_backend": {
                "backend": "x86_64-sse2-popcnt-asm", "hardware_threads": 8,
                "gpu_status": "online", "gpu_name": "Test GPU",
                "gpu_dispatches": 3, "gpu_fallbacks": 1,
                "gpu_unavailable_reason": "", "gpu_fallback_reasons": {"memory_limit": 1, "dispatch": 0},
            },
            "execution": {
                "mode": "bounded-thread-pool", "worker_count": 4,
                "max_pending_tasks": 8,
                "ordering": "deterministic-submission-order",
            },
            "vulnerability_intelligence": {
                "enabled": True, "advisory_count": 1200,
                "last_imported_at": "2026-11-03T12:00:00+00:00",
            },
        },
        errors=["sample diagnostic"],
        analyzer_names=["secret-patterns", "network-indicators"],
        directories=[
            DirectoryRecord(".", 0, direct_child_count=2, file_count=2, total_bytes=192),
            DirectoryRecord("src", 1, direct_child_count=1, file_count=1, total_bytes=128),
        ],
        symlinks=[SymlinkRecord("current", "releases/v1", "internal")],
        special_entries=[SpecialEntryRecord("events.pipe", "fifo", permissions=0o600)],
    )


def test_html_report_has_interactive_paged_inventory_and_findings(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    for expected in (
        'id="search"', 'id="category"', 'id="confidence"', 'id="severity"',
        'id="open-all"', 'id="close-all"', 'id="load-more"',
        'id="file-search"', 'id="symlink-rows"', 'id="directory-rows"',
        'id="special-rows"', 'id="stat-special"',
        'id="symlink-more"', 'id="symlink-page-info"', 'id="special-more"',
        'id="special-page-info"', 'id="vulnerability-findings"', 'id="vcs-findings"',
        'id="vuln-db-state"', "FINDING_PAGE=100", "FILE_PAGE=100",
        "SYMLINK_PAGE=100", "SPECIAL_PAGE=100", "REPORT =", "textContent",
    ):
        assert expected in content
    assert "&lt;script&gt;" not in content or "alert" in content
    assert "</script><script>alert" not in content
    assert "config.py:12" in content
    assert "192.0.2.1" in content
    assert "current" in content
    assert "events.pipe" in content
    assert "GHSA-unit-test-1234" in content
    assert "Git remote provider: GitHub" in content
    assert "node_dependencies" in content
    assert "VULNERABLE SOURCE LINES // REDACTED" in content
    assert "vulnerable-line" in content
    assert "POTENTIAL ATTACKER IMPACT" in content
    assert "RECOMMENDED REMEDIATION" in content
    assert "build_query(user_input)" in content


def test_html_json_embedding_escapes_script_terminators(tmp_path: Path):
    result = _result()
    result.findings.append(Finding(
        "documentation", "Unsafe", "</script><script>alert(1)</script>",
    ))
    path = write_reports(result, tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    assert "</script><script>alert(1)</script>" not in content
    assert "\u003c/script\u003e" in content


def test_markdown_includes_inventory_symlink_and_directory_sections(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"markdown"})[0]
    content = path.read_text(encoding="utf-8")
    assert "## File Type Distribution" in content
    assert "## Largest Directories" in content
    assert "## Symbolic Links" in content
    assert "## Special Filesystem Entries" in content
    assert "## Vulnerability Intelligence" in content
    assert "### Local Advisory Database" in content
    assert "### Online Advisory Lookup" in content
    assert "GHSA-unit-test-1234" in content
    assert "Git remote provider: GitHub" in content
    assert "current" in content
    assert "node_dependencies" in content
    assert "Potential attacker impact" in content
    assert "Recommended remediation" in content
    assert "🔴 Line 12" in content
    assert "Analysis workers: 4" in content
    assert "Analysis queue limit: 8 pending batches" in content
    assert "GPU status: online" in content
    assert "GPU device: Test GPU" in content
    assert "GPU byte-count dispatches: 3" in content
    assert "GPU CPU fallbacks: 1 (memory_limit 1)" in content
    assert content.startswith("# Project Discovery Report\n")
    assert content.endswith("\n")
    assert "\\n" not in content


def test_markdown_writer_streams_without_compatibility_string_builder(tmp_path: Path, monkeypatch):
    import project_discovery.reporting.writers as reporting

    def forbidden(_result):
        raise AssertionError("write_reports must stream Markdown instead of building one string")

    monkeypatch.setattr(reporting, "_markdown_report", forbidden)
    path = write_reports(_result(), tmp_path, {"markdown"})[0]
    content = path.read_text(encoding="utf-8")
    assert "## Findings" in content
    assert content.endswith("\n")


def test_json_report_includes_additive_inventory_schema(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"json"})[0]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.17"
    assert payload["directories"][1]["path"] == "src"
    assert payload["symlinks"][0]["target_scope"] == "internal"
    assert payload["special_entries"][0]["entry_type"] == "fifo"
    security_finding = payload["findings"][0]
    assert security_finding["code_evidence"][0]["line_number"] == 12
    assert "[REDACTED]" in security_finding["code_evidence"][0]["code"]
    assert "untrusted input" in security_finding["impact"]
    assert "parameterized SQL" in security_finding["recommendation"]

def test_html_report_exposes_symlink_scope_verification_and_permissions(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    assert "<th>Verification</th>" in content
    assert "<th>Permissions</th>" in content
    assert "linkOutcome(item)" in content
    assert "const REPORT =" in content

def test_html_report_uses_bounded_page_rendering_without_full_match_copies(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    assert "const files=REPORT.files;" in content
    assert "fileScanIndex" in content
    assert "findingScanIndex" in content
    assert "vulnFindingCount" in content and "vulnFindings.length<200" in content
    assert "vcsFindingCount" in content and "vcsFindings.length<100" in content
    assert "REPORT.files.slice().sort" not in content
    assert "findings.filter" not in content

def test_json_and_html_report_writers_do_not_materialize_scanresult_dict(
    tmp_path: Path, monkeypatch,
):
    from project_discovery.models import ScanResult

    result = _result()

    def forbidden_materialization(self):
        raise AssertionError("report writers must stream records instead of calling ScanResult.to_dict")

    monkeypatch.setattr(ScanResult, "to_dict", forbidden_materialization)
    paths = write_reports(result, tmp_path, {"json", "html"})
    assert {path.suffix for path in paths} == {".json", ".html"}
    payload = json.loads((tmp_path / "discovery-report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.17"
    assert "const REPORT =" in (tmp_path / "discovery-report.html").read_text(encoding="utf-8")


def test_html_report_escapes_untrusted_source_code_inside_script_payload(tmp_path: Path):
    result = _result()
    result.findings = [
        Finding(
            "security",
            "Untrusted source excerpt",
            "Test finding",
            severity="HIGH",
            code_evidence=[
                CodeEvidence(
                    77,
                    'message = "</script><script>window.pwned = true</script>"; '
                    'email = "dev@example.com"',
                )
            ],
            impact="Conditional impact for the test fixture.",
            recommendation="Render source through a text node.",
        )
    ]
    path = write_reports(result, tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    assert "</script><script>window.pwned" not in content
    assert "\\u003c/script\\u003e" in content
    assert "textContent=String(sourceLine.code" in content



def test_markdown_largest_directory_summary_keeps_only_top_100(tmp_path: Path):
    result = _result()
    result.directories.extend(
        DirectoryRecord(
            path=f"synthetic-{index:03}",
            depth=1,
            file_count=index,
            total_bytes=index,
        )
        for index in range(150)
    )
    path = write_reports(result, tmp_path, {"markdown"})[0]
    content = path.read_text(encoding="utf-8")
    section = content.split("## Largest Directories\n", 1)[1].split(
        "## Symbolic Links\n", 1
    )[0]
    rows = [line for line in section.splitlines() if line.startswith("- ")]
    # The fixture's 128-byte "src" directory legitimately ranks inside the top 100.
    assert len(rows) == 100
    assert any(line.startswith("- src ") for line in rows)
    assert any("synthetic-149" in line for line in rows)
    assert not any("synthetic-000 " in line for line in rows)



def test_report_writers_stream_lazy_diagnostics(tmp_path: Path):
    from project_discovery.inventory.store import InventoryStore, StoredDiagnosticRecords

    database = tmp_path / "diagnostics.sqlite3"
    with InventoryStore(database, batch_size=2) as store:
        store.extend_diagnostics([
            "first diagnostic",
            "same diagnostic",
            "same diagnostic",
        ])

    result = _result()
    result.errors = StoredDiagnosticRecords(database, fetch_size=1)
    paths = write_reports(result, tmp_path, {"json", "html", "markdown"})
    assert {path.suffix for path in paths} == {".json", ".html", ".md"}

    payload = json.loads(
        (tmp_path / "discovery-report.json").read_text(encoding="utf-8")
    )
    assert payload["errors"] == [
        "first diagnostic", "same diagnostic", "same diagnostic",
    ]
    html = (tmp_path / "discovery-report.html").read_text(encoding="utf-8")
    assert "first diagnostic" in html
    markdown = (tmp_path / "discovery-report.md").read_text(encoding="utf-8")
    assert markdown.count("same diagnostic") == 2

def test_report_writers_stream_lazy_diagnostics_without_dropping_repeats(tmp_path: Path):
    from project_discovery.inventory.store import InventoryStore, StoredDiagnosticRecords

    database = tmp_path / "report-diagnostics.sqlite3"
    with InventoryStore(database, batch_size=2) as store:
        store.extend_diagnostics([
            "first analyzer warning",
            "repeated file read error",
            "repeated file read error",
            "</script><script>not executable</script>",
        ])

    result = _result()
    result.errors = StoredDiagnosticRecords(database, fetch_size=1)
    paths = write_reports(result, tmp_path / "reports", {"json", "markdown", "html"})
    assert {path.suffix for path in paths} == {".json", ".md", ".html"}

    payload = json.loads((tmp_path / "reports" / "discovery-report.json").read_text(
        encoding="utf-8"
    ))
    assert payload["errors"] == [
        "first analyzer warning",
        "repeated file read error",
        "repeated file read error",
        "</script><script>not executable</script>",
    ]

    markdown = (tmp_path / "reports" / "discovery-report.md").read_text(encoding="utf-8")
    assert markdown.count("repeated file read error") == 2
    assert "first analyzer warning" in markdown

    html = (tmp_path / "reports" / "discovery-report.html").read_text(encoding="utf-8")
    assert "</script><script>not executable</script>" not in html
    assert "\\u003c/script\\u003e" in html



def test_html_report_is_not_corrupted_by_template_placeholders_in_paths(tmp_path: Path):
    # Regression: placeholders were substituted with str.replace over user text, so a
    # project path containing "__DATA__" split the template at the wrong place.
    result = _result()
    result.root = "/work/__DATA__/__REPORT_JS__/__ROOT__/<script>alert(1)</script>"
    content = write_reports(result, tmp_path, {"html"})[0].read_text(encoding="utf-8")
    assert content.count("const REPORT = {") == 1
    assert "/work/__DATA__/__REPORT_JS__/__ROOT__/&lt;script&gt;" in content
    assert "<script>alert(1)" not in content


def test_html_report_declares_a_nonce_csp_that_blocks_network_access(tmp_path: Path):
    import re

    content = write_reports(_result(), tmp_path, {"html"})[0].read_text(encoding="utf-8")
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', content).group(1)
    nonce = re.search(r"script-src 'nonce-([^']+)'", policy).group(1)
    assert "default-src 'none'" in policy and "base-uri 'none'" in policy
    assert content.count(f'<script nonce="{nonce}">') == 1
    assert content.count("<script") == 1
    second = write_reports(_result(), tmp_path / "again", {"html"})[0].read_text(encoding="utf-8")
    assert nonce not in second


def test_html_report_embeds_bounded_slices_with_true_totals(tmp_path: Path, monkeypatch):
    import json
    import re

    import project_discovery.reporting.writers as reporting

    monkeypatch.setitem(reporting.HTML_MAX_EMBEDDED, "findings", 1)
    content = write_reports(_result(), tmp_path, {"html"})[0].read_text(encoding="utf-8")
    payload = json.loads(re.search(r"const REPORT = (\{.*?\});\n", content, re.S).group(1))
    assert payload["totals"]["findings"] == 4
    assert len(payload["findings"]) == 1
    assert "truncation-notice" in content


def test_markdown_neutralizes_html_links_and_code_span_breakouts(tmp_path: Path):
    result = _result()
    result.findings = [Finding(
        "security", "<img src=x onerror=alert(1)> [x](javascript:alert(1))",
        "multi\nline detail", evidence=["src/__init__.py:1"], severity="HIGH",
        code_evidence=[CodeEvidence(1, "value = `x` + ``y``")],
    )]
    content = write_reports(result, tmp_path, {"markdown"})[0].read_text(encoding="utf-8")
    assert "<img" not in content and "&lt;img src=x onerror=alert(1)&gt;" in content
    assert r"\[x\](javascript:alert(1))" in content
    assert "multi line detail" in content
    assert r"src/\_\_init\_\_.py:1" in content
    # The fence outgrows the longest backtick run; content ending in "`" is space-padded.
    assert "``` value = `x` + ``y`` ```" in content


def test_findings_stream_most_severe_first(tmp_path: Path):
    from project_discovery.inventory.store import InventoryStore

    with InventoryStore(tmp_path / "order.sqlite3") as store:
        # "code" findings keep INFO; security categories raise INFO to MEDIUM by design.
        for severity in ("INFO", "CRITICAL", "LOW", "HIGH"):
            store.append_finding(Finding("code", f"{severity} item", "d", severity=severity))
        store.flush()
        order = [finding.severity for finding in store.iter_findings()]
    assert order == ["CRITICAL", "HIGH", "LOW", "INFO"]


def test_public_url_drops_credentials_even_when_the_url_does_not_parse():
    # Regression: when urlsplit or the port lookup failed, the fallback kept user:password.
    from project_discovery.reporting.writers import public_url

    for value in ("https://user:secret@example.com:99999/repo?token=x", "https://user:secret@[::1/repo#frag"):
        cleaned = public_url(value)
        assert "secret" not in cleaned and "token" not in cleaned and "frag" not in cleaned, cleaned


def test_scan_result_to_dict_writes_the_schema_it_stamps():
    from project_discovery.models import ScanResult

    data = ScanResult("/r", "start", "end", metrics={"source": {"mode": "local"}}).to_dict()
    assert data["scan"]["source"] == "local"


def test_an_online_lookup_that_sent_nothing_is_not_network_use():
    from project_discovery.reporting.writers import scan_summary

    idle = {"vulnerability_intelligence": {"online": {"coverage": "not_applicable", "requests": {"requests": 0}}}}
    assert scan_summary(idle)["mode"] == "local"
    used = {"vulnerability_intelligence": {"online": {"coverage": "complete", "requests": {"requests": 3}}}}
    assert scan_summary(used)["network_access"] == ["osv.dev"]


def test_html_inventory_summary_shows_the_pruned_count():
    # Regression: terminal, Markdown and JSON reported explicitly pruned directories, the
    # HTML summary did not.
    from importlib import resources

    script = resources.files("project_discovery.reporting.web").joinpath("report.js").read_text(encoding="utf-8")
    assert "metrics.pruned_directory_count" in script
    assert "explicitly pruned directories" in script
