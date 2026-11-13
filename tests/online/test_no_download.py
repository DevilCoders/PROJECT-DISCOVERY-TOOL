"""No-download online mode: provider APIs streamed into the analyzers, nothing written to disk.

Scans run through `pdt scan URL --no-download` against provider_server.py, a loopback
emulation of the GitHub, GitLab, Bitbucket Cloud and Gitea REST APIs.
"""
from __future__ import annotations

import builtins
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from provider_server import COMMIT, MARKER, ProviderService, RunningProviders, blob_sha, fixture_files

from project_discovery import cli
from project_discovery.online import credentials

TOKEN = "pdt-test-token-0123456789abcdef"
PROVIDERS = {
    # provider: (repository URL, API prefix, token variable, expected Authorization header)
    "github": ("https://github.com/acme/fixture", "/github", "PDT_API_TOKEN_GITHUB_COM", f"Bearer {TOKEN}"),
    "gitlab": ("https://gitlab.com/group/sub/fixture", "/gitlab/api/v4", "PDT_API_TOKEN_GITLAB_COM", f"Bearer {TOKEN}"),
    "bitbucket": ("https://bitbucket.org/ws/fixture", "/bitbucket/2.0", "PDT_API_TOKEN_BITBUCKET_ORG", f"Bearer {TOKEN}"),
    "gitea": ("https://codeberg.org/acme/fixture", "/gitea/api/v1", "PDT_API_TOKEN_CODEBERG_ORG", f"token {TOKEN}"),
}


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
                 "GITHUB_TOKEN", "GH_TOKEN", "PDT_GITHUB_TOKEN", "GITLAB_TOKEN", "PDT_GITLAB_TOKEN",
                 "BITBUCKET_TOKEN", "PDT_BITBUCKET_TOKEN", "BITBUCKET_USERNAME", "BITBUCKET_APP_PASSWORD",
                 "CODEBERG_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    for provider in PROVIDERS.values():
        monkeypatch.delenv(provider[2], raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


def _main(monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


def _report(output: Path) -> dict:
    return json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))


def _guard_disk_writes(monkeypatch, allowed: list[Path]):
    """Fail on any file opened for writing outside the allowed directories."""
    roots = [os.path.normcase(str(path.resolve())) for path in allowed]
    real_open, real_os_open = builtins.open, os.open

    def check(target) -> None:
        resolved = os.path.normcase(os.path.abspath(os.fsdecode(target)))
        if not any(resolved == root or resolved.startswith(root + os.sep) for root in roots):
            raise AssertionError(f"no-download scan wrote outside the report directory: {resolved}")

    def guarded_open(file, mode="r", *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)) and any(flag in mode for flag in "wax+"):
            check(file)
        return real_open(file, mode, *args, **kwargs)

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            check(path)
        return real_os_open(path, flags, *args, **kwargs)

    def no_temporary_directory(*args, **kwargs):
        raise AssertionError("no-download scan created a temporary directory")

    def no_subprocess(*args, **kwargs):
        raise AssertionError(f"no-download scan started a process: {args!r}")

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    monkeypatch.setattr(tempfile, "mkdtemp", no_temporary_directory)
    monkeypatch.setattr(subprocess, "Popen", no_subprocess)


@pytest.mark.parametrize("provider", sorted(PROVIDERS))
def test_no_download_scan_end_to_end_for_each_provider(provider, tmp_path: Path, monkeypatch):
    url, prefix, variable, header = PROVIDERS[provider]
    service = ProviderService(auth={provider: header}, private=True)
    output = tmp_path / "report"
    monkeypatch.setenv(variable, TOKEN)
    with RunningProviders(service) as running:
        _guard_disk_writes(monkeypatch, [output])
        code = _main(
            monkeypatch, "scan", url, "--no-download", "--api-url", running.url + prefix,
            "--output", str(output), "--quiet", "--format", "json,markdown,html",
        )
        monkeypatch.undo()
    assert code == cli.EXIT_OK
    report = _report(output)
    assert report["root"] == url
    assert report["scan"]["mode"] == "online" and report["scan"]["source"] == "remote"
    assert report["scan"]["network_access"] == ["provider-api"]
    remote = report["metrics"]["source"]["remote"]
    assert remote["acquisition"] == "api" and remote["written_to_disk"] is False
    assert remote["revision"] == COMMIT and remote["branch"] == "main"
    assert remote["credential_source"] == f"env:{variable}"
    assert remote["files_fetched"] >= 8
    # Fetched content is hashed and analyzed in memory: the same phases as a local scan.
    phases = {item["phase"]: item for item in report["metrics"]["performance"]["phases"]}
    assert [phases[key]["state"] for key in ("inventory", "hashing", "analysis", "archives", "correlation")] == [
        "done"] * 5
    assert phases["hashing"]["done"] == remote["files_fetched"] and phases["hashing"]["bytes"] > 0
    assert phases["analysis"]["done"] == phases["analysis"]["total"] == len(report["files"])

    files = {item["path"]: item for item in report["files"]}
    assert files["assets/big.bin"]["size_bytes"] == 1536 * 1024
    assert files["src/app.py"]["sha256"]
    assert files["tools/run.sh"]["permissions"] == 0o755
    # File types come from the fetched content, as in a local scan.
    script = files["tools/run.sh"]
    assert (script["file_type"], script["type_source"], script["mime_type"]) == ("text", "content", "text/x-shellscript")
    assert (files["pkg/__init__.py"]["file_type"], files["pkg/__init__.py"]["name_type"]) == ("empty", "source")
    assert report["metrics"]["type_sources"].get("content", 0) >= 7
    links = {item["path"]: item for item in report["symlinks"]}
    assert links["docs/readme-link"]["target"] == "../README.md"
    assert links["docs/readme-link"]["target_scope"] == "internal"
    # The analyzers ran on in-memory content.
    assert any("src/app.py" in " ".join(item["evidence"]) and item["category"] == "security"
               for item in report["findings"])
    assert report["metrics"]["code_index"]["symbols"]["symbol_count"] >= 2
    gaps = {item["title"] for item in report["findings"] if item["analyzer"] == "remote-source"}
    assert "Remote source coverage gap: git submodules not fetched" in gaps
    # Nothing about the repository's content or the token reaches the reports.
    everything = "\n".join(path.read_text(encoding="utf-8") for path in output.glob("discovery-report.*"))
    assert TOKEN not in everything and MARKER.decode() not in everything
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "read through the provider API, not downloaded" in markdown
    for request in service.requests:
        assert request["headers"].get("authorization") == header


def test_private_repository_without_a_token_is_a_clear_fatal_error(tmp_path: Path, monkeypatch, capsys):
    with RunningProviders(ProviderService(private=True)) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet")
    assert code == cli.EXIT_USAGE
    # --quiet still prints errors (Rich may wrap the line).
    assert "not found or is not accessible" in " ".join(capsys.readouterr().err.split())


@pytest.mark.parametrize("mode", ["inventory", "directory-only"])
def test_development_trees_apply_to_the_tree_listing(mode, tmp_path: Path, monkeypatch):
    files = fixture_files()
    files["node_modules/.package-lock.json"] = (b"{}\n", "100644")
    files["node_modules/left-pad/index.js"] = (b"module.exports = 1;\n", "100644")
    output = tmp_path / "out"
    with RunningProviders(ProviderService(files=files)) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url", running.url + "/github",
                     "--output", str(output), "--quiet", "--format", "json", "--development-trees", mode)
        fetched = {item["path"] for item in running.service.requests}
    assert code == cli.EXIT_OK
    report = _report(output)
    tree = next(item for item in report["directories"] if item["path"] == "node_modules")
    assert (tree["marker_confidence"], tree["marker_evidence"]) == ("confirmed", ".package-lock.json")
    # Nothing inside the tree is fetched (GitHub content requests name the blob SHA).
    tree_blobs = {blob_sha(files[path][0]) for path in files if path.startswith("node_modules/")}
    assert not any(sha in path for path in fetched for sha in tree_blobs)
    assert any(blob_sha(files["src/app.py"][0]) in path for path in fetched)  # files outside it are
    tree_files = [item for item in report["files"] if item["path"].startswith("node_modules/")]
    trees = report["metrics"]["development_trees"]
    if mode == "inventory":
        assert {item["content_skipped_reason"] for item in tree_files} == {
            "--development-trees inventory: inside the dependencies tree node_modules (node_modules, confirmed)",
        }
        assert trees["files_not_read"] == 2 and tree["contents_recorded"] is True
    else:
        assert tree_files == [] and tree["contents_recorded"] is False
        assert (tree["file_count"], trees["files_not_recorded"]) == (2, 2)


def test_public_repository_needs_no_token_and_tokens_stay_host_bound(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "gitlab-com-only")  # must not be sent to a GitHub API
    with RunningProviders(ProviderService()) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet", "--format", "json")
        headers = [item["headers"] for item in running.service.requests]
    assert code == cli.EXIT_OK
    assert all("authorization" not in item for item in headers)
    assert _report(tmp_path / "out")["metrics"]["source"]["remote"]["credential_source"] is None


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        (["--api-max-files", "3"], "file budget of 3 files reached"),
        (["--api-max-file-mb", "1"], "per-file budget of 1,048,576 bytes"),
        (["--api-max-mb", "1"], "byte budget of 1,048,576 bytes reached"),
    ],
)
def test_budgets_leave_unfetched_files_in_the_inventory_as_coverage_gaps(options, reason, tmp_path: Path, monkeypatch):
    with RunningProviders(ProviderService()) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet", "--strict",
                     "--format", "json", *options)
    assert code == cli.EXIT_INCOMPLETE
    report = _report(tmp_path / "out")
    skipped = [item for item in report["files"] if (item["content_skipped_reason"] or "").startswith("no-download:")]
    assert skipped and all(reason in item["content_skipped_reason"] for item in skipped)
    assert any(reason in error for error in report["errors"])
    assert any(item["title"] == "Remote source coverage gap: content not fetched" for item in report["findings"])


def test_no_download_scans_keep_to_the_scan_memory_budget(tmp_path: Path, monkeypatch):
    from project_discovery.engine import budgets

    if not budgets.memory_supported():
        pytest.skip("the resident set cannot be read here")
    with RunningProviders(ProviderService()) as running:
        arguments = ("scan", PROVIDERS["github"][0], "--no-download", "--api-url", running.url + "/github",
                     "--quiet", "--format", "json")
        assert _main(monkeypatch, *arguments, "--output", str(tmp_path / "baseline")) == cli.EXIT_OK
        # The scan now reads as 10 GiB: each file is fetched and analyzed after the one before it.
        monkeypatch.setattr(budgets, "resident_bytes", lambda: 10 * 1024 ** 3)
        monkeypatch.setattr(budgets, "_PSS", None)
        assert _main(monkeypatch, *arguments, "--output", str(tmp_path / "out"), "--max-memory-mb", "512") == cli.EXIT_OK
    report, expected = _report(tmp_path / "out"), _report(tmp_path / "baseline")
    scan = report["metrics"]["analysis_budgets"]["scan_memory"]
    assert scan["limit_mb"] == 512 and scan["waits"] >= 5 and scan["over_budget_submissions"] == scan["waits"] + 1
    assert scan["processes_measured"] == 1  # no-download scans analyze in this process's threads
    assert [(item["path"], item["sha256"]) for item in report["files"]] == [
        (item["path"], item["sha256"]) for item in expected["files"]]
    assert sorted(item["title"] for item in report["findings"]) == sorted(item["title"] for item in expected["findings"])


@pytest.mark.parametrize(
    ("options", "reason", "gap"),
    [
        (["--api-max-mb", "1"], "byte budget of 1,048,576 bytes reached", True),
        (["--api-max-file-mb", "1"], "per-file budget of 1,048,576 bytes", True),
        (["--skip", "--max-file-mb", "1"], "Explicit --skip: exceeds 1048576 bytes", False),
    ],
)
def test_gitlab_sizes_the_listing_lacks_are_unknown_not_zero(options, reason, gap, tmp_path: Path, monkeypatch):
    # Regression: GitLab's tree listing has no sizes, and each became 0 bytes. --skip let
    # assets/big.bin (1.5 MiB) through, --api-max-mb 1 fetched 1.5 MiB, and files that
    # were never fetched were reported as 0 bytes in the smallest size bucket.
    with RunningProviders(ProviderService()) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["gitlab"][0], "--no-download", "--api-url",
                     running.url + "/gitlab/api/v4", "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json", *options)
    assert code == cli.EXIT_OK
    report = _report(tmp_path / "out")
    big = next(item for item in report["files"] if item["path"] == "assets/big.bin")
    assert reason in big["content_skipped_reason"]
    assert big["content_skipped_reason"].startswith("no-download:") is gap
    assert big["size_bucket"] == "unknown"
    metrics = report["metrics"]
    source = metrics["source"]["remote"]
    assert source["bytes_fetched"] <= 1024 * 1024
    # The Content-Length header refused big.bin before its body was transferred.
    assert source["bytes_discarded"] == 0
    # Fetched files have their real sizes; only big.bin's stays unknown, out of the totals.
    files = {path: content for path, (content, mode) in fixture_files().items() if mode != "120000"}
    assert metrics["size_unknown_count"] == 1
    assert metrics["size_buckets"]["unknown"] == 1
    assert metrics["total_bytes"] == sum(len(content) for path, content in files.items() if path != "assets/big.bin")
    assert any(item["title"] == "Remote source coverage gap: sizes unknown" for item in report["findings"])


def test_gitlab_inventory_only_reports_sizes_as_unknown(tmp_path: Path, monkeypatch):
    with RunningProviders(ProviderService()) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["gitlab"][0], "--no-download", "--api-url",
                     running.url + "/gitlab/api/v4", "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json", "--inventory-only")
    assert code == cli.EXIT_OK
    metrics = _report(tmp_path / "out")["metrics"]
    files = [path for path, (_, mode) in fixture_files().items() if mode != "120000"]
    assert metrics["size_buckets"] == {"unknown": len(files)}
    assert metrics["size_unknown_count"] == len(files)
    assert metrics["total_bytes"] == 0


def test_parallel_reads_never_overshoot_the_byte_budget(tmp_path: Path, monkeypatch):
    # Regression: each worker checked the bytes fetched so far, so eight parallel reads of
    # 300,000-byte files all passed a 1 MiB budget together. Reservations count reads in flight.
    service = ProviderService(files={f"data/f{index}.txt": (b"x" * 300_000, "100644") for index in range(8)},
                              submodules=())
    with RunningProviders(service) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json", "--api-max-mb", "1", "--api-workers", "8")
    assert code == cli.EXIT_OK
    source = _report(tmp_path / "out")["metrics"]["source"]["remote"]
    assert source["files_fetched"] == 3
    assert source["bytes_fetched"] == 900_000


def test_rate_limit_exhaustion_stops_fetching_and_is_reported(tmp_path: Path, monkeypatch):
    service = ProviderService(rate_limit_after_blobs=2)
    with RunningProviders(service) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["gitea"][0], "--no-download", "--api-url",
                     running.url + "/gitea/api/v1", "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json", "--api-workers", "1")
        content_requests = len(service.content_requests())
    assert code == cli.EXIT_OK  # without --strict the scan completes with UNKNOWN coverage
    report = _report(tmp_path / "out")
    reasons = {item["content_skipped_reason"] for item in report["files"] if item["content_skipped_reason"]}
    assert any("rate limit exhausted; resets in about" in item for item in reasons)
    # After the first rate-limited answer PDT stops asking.
    assert content_requests <= 4
    assert any("rate limit" in error for error in report["errors"])


@pytest.mark.parametrize("retry_after", ["1", None])
def test_a_short_secondary_rate_limit_is_waited_out_and_retried(retry_after, tmp_path: Path, monkeypatch):
    # Regression: HTTP 403 with Retry-After (or GitHub's "secondary rate limit" message) and
    # requests left on the primary limit was a plain HTTP error: never retried, and every
    # later file was requested again from an API that refused it.
    from project_discovery.online import http as http_module

    monkeypatch.setattr(http_module, "SECONDARY_RATE_LIMIT_WAIT_SECONDS", 0.05)
    service = ProviderService(secondary_refusals=1, secondary_retry_after=retry_after)
    with RunningProviders(service) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet",
                     "--strict", "--format", "json", "--api-workers", "1")
    assert code == cli.EXIT_OK
    report = _report(tmp_path / "out")
    assert not [item for item in report["files"] if (item["content_skipped_reason"] or "").startswith("no-download:")]
    assert report["metrics"]["source"]["remote"]["requests"]["retries"] >= 1


def test_a_long_secondary_rate_limit_stops_content_requests(tmp_path: Path, monkeypatch):
    service = ProviderService(secondary_refusals=1_000, secondary_retry_after="3600")
    with RunningProviders(service) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json", "--api-workers", "1")
        content_requests = len(service.content_requests())
    assert code == cli.EXIT_OK
    report = _report(tmp_path / "out")
    reasons = {item["content_skipped_reason"] for item in report["files"] if item["content_skipped_reason"]}
    assert reasons == {"no-download: provider API rate limit exhausted; resets in about 3,600 s"}
    # The first refused request (the symlink target, read while listing) stopped all others.
    assert content_requests == 1
    # The link's target could not be fetched, so it cannot be resolved either.
    assert {item["target_state"] for item in report["symlinks"]} == {"unreadable"}


def test_request_budget_exhaustion_is_reported(tmp_path: Path, monkeypatch):
    with RunningProviders(ProviderService()) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json", "--api-max-requests", "6", "--api-workers", "1")
        total = len(running.service.requests)
    assert code == cli.EXIT_OK
    assert total <= 6
    report = _report(tmp_path / "out")
    assert any("request budget of 6 API requests is exhausted" in (item["content_skipped_reason"] or "")
               for item in report["files"])


def test_truncated_github_trees_are_walked_directory_by_directory(tmp_path: Path, monkeypatch):
    with RunningProviders(ProviderService(github_truncated=True)) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet", "--format", "json")
        tree_requests = [item for item in running.service.requests if "/git/trees/" in item["path"]]
    assert code == cli.EXIT_OK
    assert len(tree_requests) > 1
    paths = {item["path"] for item in _report(tmp_path / "out")["files"]}
    assert {"src/app.py", "pkg/util.py", "assets/big.bin"} <= paths


def test_unsafe_api_paths_are_not_inventoried(tmp_path: Path, monkeypatch):
    service = ProviderService(extra_unsafe_paths=("../escape.py", "/etc/passwd", "a//b.py"))
    with RunningProviders(service) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["gitea"][0], "--no-download", "--api-url",
                     running.url + "/gitea/api/v1", "--output", str(tmp_path / "out"), "--quiet",
                     "--strict", "--format", "json")
    assert code == cli.EXIT_INCOMPLETE
    report = _report(tmp_path / "out")
    paths = {item["path"] for item in report["files"]}
    assert not any("escape" in path or "passwd" in path or "//" in path for path in paths)
    assert any("3 tree path(s) were malformed or unsafe" in error for error in report["errors"])


def test_inventory_only_lists_the_tree_without_fetching_contents(tmp_path: Path, monkeypatch):
    service = ProviderService(submodules=())
    with RunningProviders(service) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["bitbucket"][0], "--no-download", "--api-url",
                     running.url + "/bitbucket/2.0", "--output", str(tmp_path / "out"), "--quiet",
                     "--inventory-only", "--format", "json")
        fetched = [item["path"] for item in service.content_requests()]
    assert code == cli.EXIT_OK
    assert all("readme-link" in path for path in fetched)  # only the symlink target
    assert len(_report(tmp_path / "out")["files"]) == 8


def test_online_vulnerability_lookup_reads_lockfiles_from_memory(tmp_path: Path, monkeypatch):
    from advisory_server import AdvisoryService, RunningService, ghsa_record

    advisories = AdvisoryService()
    advisories.affected[("npm", "lodash", "4.17.20")] = ["GHSA-35jh-r3h4-6jhm"]
    advisories.records["GHSA-35jh-r3h4-6jhm"] = ghsa_record(
        "GHSA-35jh-r3h4-6jhm", "npm", "lodash", fixed="4.17.21",
    )
    with RunningProviders(ProviderService()) as running, RunningService(advisories) as osv:
        monkeypatch.setenv("PDT_OSV_API_URL", osv.url)
        code = _main(monkeypatch, "scan", PROVIDERS["gitlab"][0], "--no-download", "--api-url",
                     running.url + "/gitlab/api/v4", "--vuln-online", "--vuln-cache",
                     str(tmp_path / "cache.sqlite3"), "--output", str(tmp_path / "out"), "--quiet",
                     "--format", "json")
    assert code == cli.EXIT_OK
    report = _report(tmp_path / "out")
    assert report["scan"]["network_access"] == ["provider-api", "osv.dev"]
    matches = [item for item in report["findings"] if item["analyzer"] == "online-vulnerability-intelligence"]
    assert matches and matches[0]["evidence"][0] == "package-lock.json"
    assert report["metrics"]["vulnerability_intelligence"]["online"]["coverage"] == "complete"


def test_url_batch_mixes_providers_through_per_host_api_urls(tmp_path: Path, monkeypatch):
    url_file = tmp_path / "repos.txt"
    url_file.write_text(
        f"{PROVIDERS['github'][0]}\n{PROVIDERS['gitea'][0]}\nhttps://github.com/acme/missing\n",
        encoding="utf-8",
    )
    with RunningProviders(ProviderService()) as running:
        monkeypatch.setenv("PDT_API_URL_GITHUB_COM", running.url + "/github")
        monkeypatch.setenv("PDT_API_URL_CODEBERG_ORG", running.url + "/gitea/api/v1")
        code = _main(monkeypatch, "scan", "--url", str(url_file), "--no-download",
                     "--output", str(tmp_path / "batch"), "--quiet", "--format", "json")
    assert code == cli.EXIT_INCOMPLETE
    summary = json.loads((tmp_path / "batch" / "batch-summary.json").read_text(encoding="utf-8"))
    assert [item["status"] for item in summary["targets"]] == ["completed", "completed", "failed"]
    assert summary["targets"][0]["revision"] == COMMIT
    assert "not found" in summary["targets"][2]["error"]


def test_a_malformed_provider_answer_fails_only_its_own_target(tmp_path: Path, monkeypatch):
    # Regression: a GitHub repository answer with "default_branch": 123 raised TypeError,
    # which escaped the batch loop: later repositories were skipped, no batch summary was
    # written, and the process exited 1, the --fail-on code.
    url_file = tmp_path / "repos.txt"
    url_file.write_text(f"{PROVIDERS['github'][0]}\n{PROVIDERS['gitea'][0]}\n", encoding="utf-8")
    with RunningProviders(ProviderService(default_branches={"github": 123})) as running:
        monkeypatch.setenv("PDT_API_URL_GITHUB_COM", running.url + "/github")
        monkeypatch.setenv("PDT_API_URL_CODEBERG_ORG", running.url + "/gitea/api/v1")
        code = _main(monkeypatch, "scan", "--url", str(url_file), "--no-download",
                     "--output", str(tmp_path / "batch"), "--quiet", "--format", "json")
    assert code == cli.EXIT_INCOMPLETE
    summary = json.loads((tmp_path / "batch" / "batch-summary.json").read_text(encoding="utf-8"))
    assert [item["status"] for item in summary["targets"]] == ["failed", "completed"]
    assert "malformed default branch" in summary["targets"][0]["error"]


def test_git_credential_helper_supplies_a_host_bound_token(tmp_path: Path, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git client not installed")
    empty = tmp_path / "empty.gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "credential.helper")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "!f() { echo username=pdt; echo password=helper-secret; }; f")
    assert credentials.git_credential_fill("github.com") == ("pdt", "helper-secret")
    with RunningProviders(ProviderService(auth={"github": "Bearer helper-secret"}, private=True)) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--use-credential-helper",
                     "--api-url", running.url + "/github", "--output", str(tmp_path / "out"),
                     "--quiet", "--format", "json")
    assert code == cli.EXIT_OK
    report_text = (tmp_path / "out" / "discovery-report.json").read_text(encoding="utf-8")
    assert "helper-secret" not in report_text
    assert _report(tmp_path / "out")["metrics"]["source"]["remote"]["credential_source"] == "git-credential-helper"


def test_credential_resolution_order(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "public")
    assert credentials.resolve_credential("github", "github.com").source == "env:GITHUB_TOKEN"
    monkeypatch.setenv("PDT_API_TOKEN_GITHUB_COM", "specific")
    assert credentials.resolve_credential("github", "github.com").value == "Bearer specific"
    # Standard variables never apply to another host.
    assert credentials.resolve_credential("github", "ghe.example.com") is None
    monkeypatch.setenv("BITBUCKET_USERNAME", "me")
    monkeypatch.setenv("BITBUCKET_APP_PASSWORD", "app")
    basic = credentials.resolve_credential("bitbucket", "bitbucket.org")
    assert basic.value.startswith("Basic ") and "app" not in repr(basic)


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", ".", "--no-download"],
        ["scan", "--url", "repos.txt", "--no-download", "--api-url", "https://api.github.com"],
        ["scan", "https://github.com/a/b", "--no-download", "--remote-workdir", "w"],
        ["scan", "https://github.com/a/b", "--no-download", "--remote-max-gb", "1"],
        ["scan", "https://github.com/a/b", "--no-download", "--vcs", "hg"],
        ["scan", "https://github.com/a/b", "--api-max-files", "5"],
        ["scan", "https://github.com/a/b", "--use-credential-helper"],
        ["scan", "https://github.com/a/b", "--no-download", "--api-url", "http://api.example.com"],
        ["scan", "https://github.com/a/b", "--no-download", "--api-workers", "0"],
    ],
)
def test_no_download_option_validation(tmp_path: Path, monkeypatch, argv):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "repos.txt").write_text("https://github.com/a/b\n", encoding="utf-8")
    assert _main(monkeypatch, *argv) == cli.EXIT_USAGE


def test_unsupported_hosts_and_backends_are_explained(tmp_path: Path, monkeypatch, capsys):
    code = _main(monkeypatch, "scan", "https://git.example.net/team/project", "--no-download",
                 "--output", str(tmp_path / "out"), "--quiet")
    assert code == cli.EXIT_USAGE
    assert "--api-provider" in " ".join(capsys.readouterr().err.split())
    code = _main(monkeypatch, "scan", "hg+https://hg.example.net/team/project", "--no-download",
                 "--output", str(tmp_path / "out"), "--quiet")
    assert code == cli.EXIT_USAGE


@pytest.mark.skipif(
    os.environ.get("PDT_LIVE_NETWORK_TESTS") != "1",
    reason="set PDT_LIVE_NETWORK_TESTS=1 to read public repositories through the real provider APIs",
)
@pytest.mark.parametrize("url", [
    "https://github.com/octocat/Hello-World",
    "https://gitlab.com/gitlab-org/project-templates/express",
    "https://bitbucket.org/tutorials/markdowndemo",
    "https://codeberg.org/Codeberg/pages-server",
])
def test_live_no_download_scan(url: str, tmp_path: Path, monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    code = _main(monkeypatch, "scan", url, "--no-download", "--output", str(tmp_path / "live"),
                 "--quiet", "--format", "json", "--api-max-requests", "60", "--api-max-files", "40")
    assert code == cli.EXIT_OK
    report = _report(tmp_path / "live")
    remote = report["metrics"]["source"]["remote"]
    assert remote["acquisition"] == "api" and len(remote["revision"]) == 40
    assert report["files"] and remote["files_fetched"] >= 1
    assert remote["api_requests"] <= 60


def test_failed_requests_group_by_cause_with_sample_paths(tmp_path: Path, monkeypatch):
    # Regression: each failed file had its own reason (the request path was part of it),
    # so one systematic failure became one UNKNOWN finding per file.
    from project_discovery.online import memory_scan
    from project_discovery.online.http import NetworkError

    original = memory_scan.NoDownloadSource._fetch

    def failing(self, record):
        if record.path.endswith(".py"):
            reason, reservation = self._reserve(record)
            self._settle(reservation, 0)
            cause = "HTTP 404"
            return None, f"content request failed ({cause} from {self._api_host})"
        return original(self, record)

    monkeypatch.setattr(memory_scan.NoDownloadSource, "_fetch", failing)
    with RunningProviders(ProviderService()) as running:
        _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
              running.url + "/github", "--output", str(tmp_path / "out"), "--quiet", "--format", "json")
    report = _report(tmp_path / "out")
    gaps = [item for item in report["metrics"]["source"]["remote"]["coverage"] if "HTTP 404" in item["detail"]]
    assert len(gaps) == 1 and gaps[0]["count"] >= 3 and gaps[0]["samples"]
    assert NetworkError  # imported for the shape of the real failure


def test_a_rate_limit_while_listing_keeps_the_listed_entries(tmp_path: Path, monkeypatch):
    # Regression: a budget or rate limit during a tree walk failed the whole repository.
    from project_discovery.online import providers
    from project_discovery.online.http import NetworkError

    def partial_tree(self, revision):
        self._listed.append(providers.TreeEntry("README.md", "file", 10, "1" * 40, False))
        raise NetworkError("rate limited", kind="rate_limit", retry_after=3600)

    monkeypatch.setattr(providers.GitHubClient, "tree", partial_tree)
    with RunningProviders(ProviderService()) as running:
        code = _main(monkeypatch, "scan", PROVIDERS["github"][0], "--no-download", "--api-url",
                     running.url + "/github", "--output", str(tmp_path / "out"), "--quiet", "--format", "json")
    assert code == cli.EXIT_OK
    report = _report(tmp_path / "out")
    assert [item["path"] for item in report["files"]] == ["README.md"]
    kinds = {item["kind"]: item for item in report["metrics"]["source"]["remote"]["coverage"]}
    assert "stopped early" in kinds["tree_truncated"]["detail"]


MARKER_PLUGIN = """
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import Finding


class MarkerAnalyzer(Analyzer):
    name = "fixture-marker"

    def supports(self, record):
        return record.path.endswith(".txt")

    def analyze(self, path, record):
        with open(path, "rb") as stream:
            content = stream.read()
        return [Finding("plugin_fixture", "Marker seen", "found" if b"NO-DOWNLOAD-MARKER" in content else "absent")]
"""


def test_plugins_run_in_no_download_mode_only_when_asked(tmp_path: Path, monkeypatch):
    # Regression: third-party plugins never ran in no-download mode, because their sandbox
    # needs a file copy on disk. --no-download-plugins stages one copy per call in the plugin
    # host's private folder under the output and deletes it after the call.
    from importlib.metadata import EntryPoint

    import project_discovery.analyzers as registry

    directory = tmp_path / "plugins"
    directory.mkdir()
    (directory / "pdt_fixture_marker.py").write_text(MARKER_PLUGIN, encoding="utf-8")
    monkeypatch.syspath_prepend(str(directory))
    point = EntryPoint(name="marker", value="pdt_fixture_marker:MarkerAnalyzer", group="pdt.analyzers")
    monkeypatch.setattr(registry, "entry_points", lambda **_kwargs: [point])
    url, prefix, _variable, _header = PROVIDERS["github"]
    with RunningProviders(ProviderService()) as running:
        plain = tmp_path / "plain"
        assert _main(monkeypatch, "scan", url, "--no-download", "--api-url", running.url + prefix,
                     "--output", str(plain), "--quiet", "--plugin-isolation", "process") == cli.EXIT_OK
        staged = tmp_path / "staged"
        assert _main(monkeypatch, "scan", url, "--no-download", "--api-url", running.url + prefix,
                     "--output", str(staged), "--quiet", "--plugin-isolation", "process",
                     "--no-download-plugins") == cli.EXIT_OK
    without = _report(plain)
    assert not [item for item in without["findings"] if item["category"] == "plugin_fixture"]
    gap = next(item for item in without["findings"] if item["title"].endswith("plugins not run"))
    assert "--no-download-plugins" in gap["detail"]
    assert without["metrics"]["source"]["remote"]["written_to_disk"] is False

    report = _report(staged)
    seen = [(item["title"], item["detail"]) for item in report["findings"] if item["category"] == "plugin_fixture"]
    assert seen == [("Marker seen", "found")]  # notes/MARKER.txt, read from the staged copy
    remote = report["metrics"]["source"]["remote"]
    assert remote["written_to_disk"] is True
    assert remote["disk_writes"] == "transient plugin staging under OUTPUT/.pdt-cache/plugins"
    assert not any(item["title"].endswith("plugins not run") for item in report["findings"])
    staging = staged / ".pdt-cache" / "plugins"
    assert not staging.exists() or not [path for path in staging.rglob("*") if path.is_file()]


def test_no_download_plugins_needs_no_download_and_a_plugin_host(tmp_path: Path, monkeypatch, capsys):
    assert _main(monkeypatch, "scan", str(tmp_path), "--no-download-plugins", "--output", str(tmp_path / "o")) == 2
    assert "--no-download-plugins requires --no-download" in capsys.readouterr().err
    assert _main(monkeypatch, "scan", "https://github.com/acme/fixture", "--no-download", "--no-download-plugins",
                 "--plugin-isolation", "off", "--output", str(tmp_path / "o")) == 2
    assert "--no-download-plugins needs --plugin-isolation sandbox or process" in capsys.readouterr().err


# Bitbucket Data Center/Server (REST API 1.0) ------------------------------------------
@pytest.mark.parametrize("url", [
    "https://bitbucket.example.com/scm/PROJ/fixture.git",
    "https://bitbucket.example.com/projects/PROJ/repos/fixture/browse",
])
def test_no_download_reads_bitbucket_data_center(url, tmp_path: Path, monkeypatch):
    # Regression: Bitbucket Data Center/Server was refused in no-download mode ("uses a
    # different API"). Its REST API 1.0 lists files without sizes or modes.
    service = ProviderService(auth={"bitbucket-server": f"Bearer {TOKEN}"}, private=True)
    output = tmp_path / "report"
    monkeypatch.setenv("PDT_API_TOKEN_BITBUCKET_EXAMPLE_COM", TOKEN)
    with RunningProviders(service) as running:
        _guard_disk_writes(monkeypatch, [output])
        code = _main(
            monkeypatch, "scan", url, "--no-download",
            "--api-url", running.url + "/bitbucket-server/rest/api/1.0", "--output", str(output), "--quiet",
        )
        monkeypatch.undo()
    assert code == cli.EXIT_OK
    report = _report(output)
    remote = report["metrics"]["source"]["remote"]
    assert remote["api_provider"] == "Bitbucket Data Center" and remote["written_to_disk"] is False
    assert remote["revision"] == COMMIT and remote["branch"] == "main" and remote["private"] is True
    assert remote["credential_source"] == "env:PDT_API_TOKEN_BITBUCKET_EXAMPLE_COM"
    files = {item["path"]: item for item in report["files"]}
    assert set(files) == set(fixture_files())  # paged listing complete; no submodule entries
    assert files["assets/big.bin"]["size_bytes"] == 1536 * 1024  # learned from the content
    assert any("src/app.py" in " ".join(item["evidence"]) and item["category"] == "security"
               for item in report["findings"])
    raw = [item for item in service.requests if "/raw/" in item["path"]]
    assert raw and all(item["headers"].get("authorization") == f"Bearer {TOKEN}" for item in raw)


def test_bitbucket_repository_paths_and_provider_selection():
    from project_discovery.online.providers import (
        ProviderError, api_provider_for, provider_for_host, server_repository,
    )

    assert server_repository("scm/PROJ/repo") == ("PROJ", "repo")
    assert server_repository("projects/PROJ/repos/repo/browse") == ("PROJ", "repo")
    assert server_repository("scm/~alice/notes") == ("~alice", "notes")
    assert server_repository("users/alice/repos/notes") == ("~alice", "notes")
    with pytest.raises(ProviderError):
        server_repository("a/b/c")
    assert api_provider_for("Bitbucket Data Center") == "bitbucket-server"
    assert api_provider_for("Bitbucket") == "bitbucket"
    assert provider_for_host("bitbucket", "git.example.com") == "bitbucket-server"
    assert provider_for_host("bitbucket", "bitbucket.org") == "bitbucket"
    assert provider_for_host("bitbucket", "git.example.com", "bitbucket") == "bitbucket"
