import json
from pathlib import Path

from project_discovery.models import (
    DirectoryRecord, FileRecord, Finding, ScanResult, SpecialEntryRecord, SymlinkRecord,
)
from project_discovery.reporting import write_reports


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
            "native_backend": {"backend": "x86_64-sse2-popcnt-asm", "hardware_threads": 8},
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
        'id="vulnerability-findings"', 'id="vcs-findings"', 'id="vuln-db-state"',
        "FINDING_PAGE=100", "FILE_PAGE=100", "REPORT =", "textContent",
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
    assert "## Local Vulnerability Intelligence" in content
    assert "GHSA-unit-test-1234" in content
    assert "Git remote provider: GitHub" in content
    assert "current" in content
    assert "node_dependencies" in content


def test_json_report_includes_additive_inventory_schema(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"json"})[0]
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.2"
    assert payload["directories"][1]["path"] == "src"
    assert payload["symlinks"][0]["target_scope"] == "internal"
    assert payload["special_entries"][0]["entry_type"] == "fifo"

def test_html_report_exposes_symlink_scope_verification_and_permissions(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    assert "<th>Verification</th>" in content
    assert "<th>Permissions</th>" in content
    assert 'item.target_state||"unverified"' in content
    assert "const REPORT =" in content

def test_html_report_uses_bounded_page_rendering_without_full_match_copies(tmp_path: Path):
    path = write_reports(_result(), tmp_path, {"html"})[0]
    content = path.read_text(encoding="utf-8")
    assert "const files=REPORT.files;" in content
    assert "fileScanIndex" in content
    assert "findingScanIndex" in content
    assert "REPORT.files.slice().sort" not in content
    assert "findings.filter" not in content

def test_json_and_html_report_writers_do_not_materialize_scanresult_dict(tmp_path: Path):
    result = _result()

    def forbidden_materialization():
        raise AssertionError("report writers must stream records instead of calling ScanResult.to_dict")

    result.to_dict = forbidden_materialization  # type: ignore[method-assign]
    paths = write_reports(result, tmp_path, {"json", "html"})
    assert {path.suffix for path in paths} == {".json", ".html"}
    payload = json.loads((tmp_path / "discovery-report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.2"
    assert "const REPORT =" in (tmp_path / "discovery-report.html").read_text(encoding="utf-8")
