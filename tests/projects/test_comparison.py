from project_discovery.projects.comparison import compare_reports


def _report(root, languages, dependencies, modules, files):
    return {
        "schema_version": "1.0",
        "root": root,
        "files": files,
        "findings": [
            {"title": "Declared dependency: " + item, "category": "dependency", "evidence": []}
            for item in dependencies
        ],
        "metrics": {
            "languages": {language: 1 for language in languages},
            "python_dependency_graph": {
                "modules": [{"name": module} for module in modules]
            },
        },
    }


def test_comparison_preserves_project_independence_and_finds_overlap():
    left = _report(
        "/projects/alpha", ["Python", "Rust"], ["rich", "httpx"], ["alpha.core"],
        [{"path": "src/shared.py", "sha256": "samehash"}],
    )
    right = _report(
        "/projects/beta", ["Python", "TypeScript"], ["rich", "requests"], ["alpha.core"],
        [{"path": "lib/shared.py", "sha256": "samehash"}],
    )
    comparison = compare_reports(left, right)
    assert [item["root"] for item in comparison["projects"]] == [
        "/projects/alpha", "/projects/beta"
    ]
    assert comparison["language_overlap"]["shared"] == ["Python"]
    assert comparison["dependency_overlap"]["shared_declared_dependencies"] == ["rich"]
    assert comparison["python_module_overlap"]["shared_module_names"] == ["alpha.core"]
    assert comparison["duplicate_file_content"][0]["confidence"] == "CONFIRMED"
    assert "Not generated" in comparison["interpretation"]["integration_recommendation"]


def test_comparison_handles_no_overlap():
    left = _report("/a", ["Go"], [], [], [])
    right = _report("/b", ["Rust"], [], [], [])
    comparison = compare_reports(left, right)
    assert comparison["language_overlap"]["shared"] == []
    assert comparison["duplicate_file_content"] == []


def test_compare_many_reports_finds_overlap_across_all_projects():
    from project_discovery.projects.comparison import compare_many_reports

    reports = [
        _report(
            f"/projects/{name}", ["Python", "Rust"], ["shared-lib", f"only-{name}"],
            ["common.module"], [{"path": "common.py", "sha256": "shared-bytes"}],
        )
        for name in ("one", "two", "three")
    ]
    result = compare_many_reports(reports)
    assert len(result["projects"]) == 3
    assert result["all_projects_shared"]["languages"] == ["Python", "Rust"]
    assert result["all_projects_shared"]["declared_dependencies"] == ["shared-lib"]
    assert len(result["pairwise_comparisons"]) == 3
    assert len(result["duplicate_file_content"]) == 1
    assert len(result["duplicate_file_content"][0]["projects"]) == 3


def test_multi_project_markdown_writer(tmp_path):
    from project_discovery.projects.comparison import compare_many_reports, write_comparison

    reports = [
        _report(f"/{name}", ["Python"], ["common"], [], [])
        for name in ("a", "b", "c")
    ]
    comparison = compare_many_reports(reports)
    paths = write_comparison(comparison, tmp_path, {"markdown"})
    markdown = paths[0].read_text(encoding="utf-8")
    assert "Shared across all projects" in markdown
    assert "/a" in markdown and "/b" in markdown and "/c" in markdown


def test_comparison_markdown_neutralizes_scanned_strings(tmp_path):
    # Regression (PDT-107 class): project-comparison.md wrote dependency names, module
    # names, roots and paths from scanned projects verbatim, so a package.json entry could
    # inject live HTML, links or new Markdown blocks.
    from project_discovery.projects.comparison import compare_many_reports, write_comparison

    payload = "<img src=x onerror=alert(1)>[x](javascript:alert(1))\n# Forged heading `x`"
    files = [{"path": "evil\n# Owned <b>.py", "sha256": "same"}]
    reports = [
        _report(f"/{name}<script>", ["Python"], [payload], [payload], list(files))
        for name in ("a", "b")
    ]
    for compared in (compare_reports(*reports), compare_many_reports(reports)):
        markdown = write_comparison(compared, tmp_path, {"markdown"})[0].read_text(encoding="utf-8")
        assert "<img" not in markdown and "<script>" not in markdown and "<b>" not in markdown
        import re

        assert not re.search(r"(?<!\\)\]\(javascript:", markdown)
        assert r"\[x\](javascript:alert(1))" in markdown
        assert "\n# Forged" not in markdown and "\n# Owned" not in markdown
        assert "&lt;img src=x onerror=alert(1)&gt;" in markdown


def test_comparison_reports_resolved_dependency_version_conflicts():
    left = _report("/left", ["Python"], [], [], [])
    right = _report("/right", ["Python"], [], [], [])
    left["findings"].append({
        "category": "dependency",
        "title": "Resolved dependency inventory: poetry.lock",
        "evidence": ["httpx==0.27.0"],
    })
    right["findings"].append({
        "category": "dependency",
        "title": "Resolved dependency inventory: poetry.lock",
        "evidence": ["httpx==0.28.0"],
    })
    result = compare_reports(left, right)
    assert result["resolved_dependency_overlap"] == [{
        "name": "httpx",
        "left_versions": ["0.27.0"],
        "right_versions": ["0.28.0"],
        "version_conflict": True,
    }]


def test_reports_with_null_sections_compare_as_empty(tmp_path):
    # Regression: a 1.x report whose metrics.python_dependency_graph (or another section) is
    # null crashed `pdt compare` with AttributeError, and main() exited 1, the --fail-on code.
    import json

    from project_discovery.projects.comparison import compare_many_reports, load_report

    paths = []
    for name, metrics in (("left", {"python_dependency_graph": None, "languages": None,
                                    "code_index": {"integration": {"packages": [None, {"name": 3}]}}}),
                          ("right", None)):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps({
            "schema_version": "1.4", "root": f"/{name}", "files": None,
            "findings": [None, {"title": None, "evidence": "not-a-list"}], "metrics": metrics,
        }), encoding="utf-8")
        paths.append(path)
    comparison = compare_many_reports([load_report(path) for path in paths])
    assert [project["file_count"] for project in comparison["projects"]] == [0, 0]


def test_an_unexpected_error_exits_2_not_the_fail_on_code(tmp_path, monkeypatch, capsys):
    import sys

    import pytest

    from project_discovery import cli

    def broken(*_args, **_kwargs):
        raise AttributeError("'NoneType' object has no attribute 'get'")

    monkeypatch.setattr(cli, "compare_many_reports", broken)
    report = tmp_path / "report.json"
    report.write_text('{"schema_version": "1.0", "root": "/r", "files": [], "findings": [], "metrics": {}}',
                      encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["pdt", "compare", str(report), str(report), "--output", str(tmp_path / "out")])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == cli.EXIT_USAGE
    assert "Unexpected AttributeError" in capsys.readouterr().err
