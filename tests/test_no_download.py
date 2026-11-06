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

from provider_server import COMMIT, MARKER, ProviderService, RunningProviders
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

    files = {item["path"]: item for item in report["files"]}
    assert files["assets/big.bin"]["size_bytes"] == 1536 * 1024
    assert files["src/app.py"]["sha256"]
    assert files["tools/run.sh"]["permissions"] == 0o755
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
