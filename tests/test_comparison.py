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
