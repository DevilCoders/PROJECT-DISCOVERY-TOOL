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
        "ecosystem": "",  # these findings name no ecosystem (detail text absent)
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


def _lockfile_report(root, versions, *, ref=None):
    report = _report(root, ["JavaScript"], [], [], [])
    report["metrics"]["code_index"] = {"dependencies": {"lockfiles": {"package-lock.json": {
        "ecosystem": "npm", "packages": {name: [version] for name, version in versions.items()},
    }}}, "integration": {}}
    if ref:
        report["scan"] = {"remote": {"ref": ref, "revision": "abc"}}
    return report


def test_resolved_versions_come_from_every_package_not_the_first_200():
    # Regression: versions were read from finding evidence, which lists the first 200
    # packages of each lockfile, so a conflict at entry 230 was never reported.
    from project_discovery.projects.comparison import compare_many_reports

    shared = {f"pkg{index:03d}": "1.0.0" for index in range(300)}
    left = _lockfile_report("/left", shared)
    right = _lockfile_report("/right", {**shared, "pkg230": "2.0.0"})
    result = compare_many_reports([left, right])
    conflicts = [item["name"] for item in result["all_projects_shared"]["resolved_dependencies"] if item["version_conflict"]]
    assert conflicts == ["pkg230"]
    assert result["pairwise_comparisons"][0]["dependency_version_conflict_count"] == 1


def test_older_reports_with_capped_evidence_are_marked_partial():
    from project_discovery.projects.comparison import compare_many_reports

    old = _report("/old", [], [], [], [])
    old["findings"].append({"title": "Resolved dependency inventory: package-lock.json", "category": "dependency",
                            "detail": "Extracted 230 entries. Evidence lists the first 200; 30 more are omitted.",
                            "evidence": ["a==1"]})
    result = compare_many_reports([old, _lockfile_report("/new", {"a": "1"})])
    [gaps] = [item["gaps"] for item in result["coverage"] if item["project"] == "/old"]
    assert any("first 200 packages of 1 lockfile(s): package-lock.json" in gap for gap in gaps)


def test_missing_evidence_is_reported_as_unknown_not_as_no_links(tmp_path):
    # Regression: an inventory-only report (no hashes, dependencies or integration points)
    # produced "No package, HTTP, messaging or gRPC links were found", like a clean result.
    from project_discovery.projects.comparison import compare_many_reports, write_comparison

    inventory_only = _report("/fast", [], [], [], [{"path": "a.py", "sha256": None}])
    inventory_only["metrics"]["execution"] = {"analysis_mode": "inventory-only"}
    inventory_only["metrics"]["code_index"] = {"skipped": "inventory-only scan"}
    full = _lockfile_report("/full", {"a": "1"})
    result = compare_many_reports([inventory_only, full])
    assert [item["complete"] for item in result["coverage"]] == [False, True]
    assert any(warning.startswith("/fast: inventory-only scan") for warning in result["warnings"])
    [written] = write_comparison(result, tmp_path / "out", {"markdown"})
    markdown = written.read_text(encoding="utf-8")
    assert "## Coverage" in markdown
    assert "not evidence that the projects are unrelated" in markdown


def test_reports_with_one_root_keep_their_own_entries():
    # Regression: two refs (or a before/after pair) of one project share a root, and the
    # second report replaced the first in every result keyed by root.
    from project_discovery.projects.comparison import compare_many_reports

    before = _lockfile_report("https://github.com/acme/app", {"lodash": "4.17.20"}, ref="v1")
    after = _lockfile_report("https://github.com/acme/app", {"lodash": "4.17.21"}, ref="v2")
    result = compare_many_reports([before, after])
    assert [project["label"] for project in result["projects"]] == [
        "https://github.com/acme/app#v1", "https://github.com/acme/app#v2",
    ]
    [lodash] = result["all_projects_shared"]["resolved_dependencies"]
    assert lodash["versions_by_project"] == {
        "https://github.com/acme/app#v1": ["4.17.20"], "https://github.com/acme/app#v2": ["4.17.21"],
    }
    local = compare_many_reports([_lockfile_report("/app", {"a": "1"}), _lockfile_report("/app", {"a": "2"})])
    assert [project["label"] for project in local["projects"]] == ["/app [report 1]", "/app [report 2]"]
    assert any("2 input reports have the project label /app" in warning for warning in local["warnings"])
    [entry] = local["all_projects_shared"]["resolved_dependencies"]
    assert entry["versions_by_project"] == {"/app [report 1]": ["1"], "/app [report 2]": ["2"]}


def test_a_scan_records_every_resolved_package_for_comparison(tmp_path):
    import json

    from project_discovery.cli import run_scan

    project = tmp_path / "app"
    project.mkdir()
    packages = {"": {"name": "app"}, **{f"node_modules/pkg{index}": {"version": "1.0.0"} for index in range(250)}}
    (project / "package-lock.json").write_text(
        json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}), encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    lockfiles = report["metrics"]["code_index"]["dependencies"]["lockfiles"]
    assert len(lockfiles["package-lock.json"]["packages"]) == 250


def _ecosystem_report(root, lockfiles, files=()):
    report = _report(root, ["Python"], [], [], list(files))
    report["metrics"]["code_index"] = {"dependencies": {"lockfiles": {
        path: {"ecosystem": ecosystem, "packages": packages} for path, (ecosystem, packages) in lockfiles.items()
    }}, "integration": {}}
    return report


def test_version_conflicts_respect_the_ecosystem_and_one_rule():
    # Regressions: PyPI redis and npm redis "conflicted", and identical lockfiles resolving two
    # lodash versions each were a conflict across all projects but not pairwise.
    from project_discovery.projects.comparison import compare_many_reports

    left = _ecosystem_report("/a", {"poetry.lock": ("PyPI", {"redis": ["5.0.1"]}),
                                     "package-lock.json": ("npm", {"lodash": ["4.17.20", "4.17.21"]})})
    right = _ecosystem_report("/b", {"package-lock.json": ("npm", {"redis": ["4.6.13"], "lodash": ["4.17.20", "4.17.21"]})})
    result = compare_many_reports([left, right])
    shared = {(item["ecosystem"], item["name"]): item for item in result["all_projects_shared"]["resolved_dependencies"]}
    assert set(shared) == {("npm", "lodash")}
    assert shared[("npm", "lodash")]["version_conflict"] is False
    assert result["pairwise_comparisons"][0]["dependency_version_conflict_count"] == 0


def test_empty_files_and_other_are_not_shared():
    from project_discovery.projects.comparison import compare_many_reports

    empty = {"path": "pkg/__init__.py", "sha256": "e3b0c442", "size_bytes": 0}
    left = _report("/a", ["Python", "Other"], [], [], [empty])
    right = _report("/b", ["Python", "Other"], [], [], [empty])
    result = compare_many_reports([left, right])
    assert result["duplicate_file_content"] == [] and result["duplicate_file_total"] == 0
    assert result["all_projects_shared"]["languages"] == ["Python"]


def test_comparison_output_inside_a_compared_project_is_refused(tmp_path, monkeypatch):
    import json
    import sys

    import pytest

    from project_discovery import cli

    project = tmp_path / "project"
    project.mkdir()
    reports = []
    for name in ("a", "b"):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps({"schema_version": "1.7", "root": str(project), "files": [],
                                    "findings": [], "metrics": {}}), encoding="utf-8")
        reports.append(str(path))
    monkeypatch.setattr(sys, "argv", ["pdt", "compare", *reports, "--output", str(project / "cmp")])
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert exited.value.code == cli.EXIT_USAGE
