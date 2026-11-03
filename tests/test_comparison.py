from project_discovery.comparison import compare_reports


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
    from project_discovery.comparison import compare_many_reports

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
    from project_discovery.comparison import compare_many_reports, write_comparison

    reports = [
        _report(f"/{name}", ["Python"], ["common"], [], [])
        for name in ("a", "b", "c")
    ]
    comparison = compare_many_reports(reports)
    paths = write_comparison(comparison, tmp_path, {"markdown"})
    markdown = paths[0].read_text(encoding="utf-8")
    assert "Shared across all projects" in markdown
    assert "/a" in markdown and "/b" in markdown and "/c" in markdown
