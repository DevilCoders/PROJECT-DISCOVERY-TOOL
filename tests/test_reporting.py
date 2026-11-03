from pathlib import Path

from project_discovery.models import Finding, ScanResult
from project_discovery.reporting import write_reports


def test_html_report_has_search_filters_and_escaped_content(tmp_path: Path):
    result = ScanResult(
        root="/private/project",
        started_at="2026-11-03T10:00:00+00:00",
        finished_at="2026-11-03T10:01:00+00:00",
        findings=[
            Finding(
                "security",
                "<script>alert('x')</script>",
                "Potential secret <value> redacted.",
                confidence="INFERRED",
                evidence=["config.py:12"],
                analyzer="secret-patterns",
            )
        ],
        metrics={"file_count": 4},
        analyzer_names=["secret-patterns"],
    )
    paths = write_reports(result, tmp_path, {"html"})
    html_text = paths[0].read_text(encoding="utf-8")
    assert 'id="search"' in html_text
    assert 'id="category"' in html_text
    assert 'id="confidence"' in html_text
    assert "applyFilters" in html_text
    assert "&lt;script&gt;" in html_text
    assert "<script>alert" not in html_text
    assert "config.py:12" in html_text


def test_all_report_formats_are_written(tmp_path: Path):
    result = ScanResult(
        root="/project",
        started_at="start",
        finished_at="finish",
        findings=[Finding("code", "Example", "Detail", evidence=["a.py:1"])],
    )
    paths = write_reports(result, tmp_path, {"json", "markdown", "html"})
    assert {path.suffix for path in paths} == {".json", ".md", ".html"}
