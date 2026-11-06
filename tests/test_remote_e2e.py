"""End-to-end remote scans against a real Git server on the loopback interface.

A `git daemon` bound to 127.0.0.1 serves fixture repositories built with Git plumbing
(executable bit, symlink, submodule gitlink, LFS pointer). `pdt scan` then clones them
exactly as it would a hosted repository: no network beyond localhost is used. The tests
skip when the Git client is unavailable.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from project_discovery import cli, remote

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git client not installed")

_GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "PDT", "GIT_AUTHOR_EMAIL": "pdt@example.invalid",
    "GIT_COMMITTER_NAME": "PDT", "GIT_COMMITTER_EMAIL": "pdt@example.invalid",
}


def _git(*args: str, cwd: Path | None = None, stdin: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false",
         "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, input=stdin, capture_output=True, check=True, env=_GIT_ENV,
    )
    return result.stdout.decode("utf-8").strip()


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _build_repositories(base: Path) -> dict:
    work = base / "work"
    _git("init", "-q", str(work))
    _write(work / "README.md", b"# Fixture\n")
    _write(work / "src" / "app.py", b"import os\n\ndef run(command):\n    os.system(command)\n")
    _write(work / "tools" / "run.sh", b"#!/bin/sh\necho run\n")
    _write(
        work / "assets" / "model.bin",
        b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 12\n",
    )
    _git("add", ".", cwd=work)
    _git("update-index", "--chmod=+x", "tools/run.sh", cwd=work)
    link_blob = _git("hash-object", "-w", "--stdin", cwd=work, stdin=b"../README.md")
    _git("update-index", "--add", "--cacheinfo", f"120000,{link_blob},docs/readme-link", cwd=work)
    _git("update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},vendor/lib", cwd=work)
    _git("commit", "-q", "-m", "v1", cwd=work)
    _git("tag", "v1.0", cwd=work)
    first = _git("rev-parse", "HEAD", cwd=work)
    _write(work / "src" / "added_in_v2.py", b"VALUE = 2\n")
    _git("add", "src/added_in_v2.py", cwd=work)
    _git("commit", "-q", "-m", "v2", cwd=work)
    second = _git("rev-parse", "HEAD", cwd=work)

    small = base / "small"
    _git("init", "-q", str(small))
    _write(small / "README.md", b"small fixture\n")
    _git("add", ".", cwd=small)
    _git("commit", "-q", "-m", "only", cwd=small)

    served = base / "served"
    served.mkdir()
    _git("clone", "-q", "--bare", str(work), str(served / "repo.git"))
    _git("clone", "-q", "--bare", str(small), str(served / "small.git"))
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=served / "repo.git")
    return {"served": served, "v1": first, "v2": second}


@pytest.fixture(scope="module")
def git_server(tmp_path_factory):
    base = tmp_path_factory.mktemp("git-server")
    repositories = _build_repositories(base)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    daemon = subprocess.Popen(
        ["git", "daemon", "--reuseaddr", "--export-all",
         f"--base-path={repositories['served']}", "--listen=127.0.0.1", f"--port={port}",
         str(repositories["served"])],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **remote._isolation_kwargs(),
    )
    try:
        deadline = time.monotonic() + 20
        while True:
            probe_result = subprocess.run(
                ["git", "ls-remote", f"git://127.0.0.1:{port}/small.git"],
                capture_output=True, timeout=20, env=_GIT_ENV,
            )
            if probe_result.returncode == 0:
                break
            if time.monotonic() > deadline or daemon.poll() is not None:
                pytest.skip("git daemon could not serve on the loopback interface")
            time.sleep(0.2)
        yield {**repositories, "url": f"git://127.0.0.1:{port}"}
    finally:
        remote._kill_process_tree(daemon)
        daemon.wait(timeout=30)


def _main(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


def _report_text(output: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(output.glob("discovery-report.*"))
    )


def test_real_git_remote_scan_end_to_end(git_server, tmp_path: Path, monkeypatch):
    output = tmp_path / "report"
    workdir = tmp_path / "work"
    url = f"{git_server['url']}/repo.git"
    code = _main(
        monkeypatch, "scan", url, "--allow-insecure-transport", "--output", str(output),
        "--remote-workdir", str(workdir), "--quiet",
    )
    assert code == cli.EXIT_OK

    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert report["root"] == url
    source = report["metrics"]["source"]
    assert source["mode"] == "remote"
    remote_meta = source["remote"]
    assert remote_meta["revision"] == git_server["v2"]
    assert remote_meta["branch"] == "main"
    assert remote_meta["transport"] == "git" and remote_meta["transport_insecure"] is True
    assert remote_meta["acquisition"] == "download"
    assert remote_meta["submodule_count"] == 1 and remote_meta["git_lfs_pointer_count"] == 1

    files = {item["path"]: item for item in report["files"]}
    assert {"README.md", "src/app.py", "src/added_in_v2.py", "tools/run.sh", "assets/model.bin"} <= set(files)
    if os.name != "nt":
        assert files["tools/run.sh"]["permissions"] & stat.S_IXUSR
    links = {item["path"]: item for item in report["symlinks"]}
    if remote_meta["materialized_symlink_count"]:
        assert links["docs/readme-link"]["target"] == "../README.md"
    else:
        assert "symlinks_not_materialized" in {item["kind"] for item in remote_meta["coverage"]}

    gaps = [item for item in report["findings"] if item["analyzer"] == "remote-source"]
    titles = {item["title"] for item in gaps}
    assert "Remote source coverage gap: git submodules not fetched" in titles
    assert "Remote source coverage gap: git lfs objects not fetched" in titles
    assert all(item["confidence"] == "UNKNOWN" for item in gaps)

    # Nothing about the ephemeral checkout leaks into reports, and nothing is left behind.
    text = _report_text(output)
    assert "pdt-remote-" not in text
    assert str(workdir.resolve()) not in text
    assert list(workdir.iterdir()) == []
    assert not any(path.name == ".git" for path in output.rglob(".git"))


def test_real_git_remote_scan_of_a_tag_and_of_a_commit(git_server, tmp_path: Path, monkeypatch):
    url = f"{git_server['url']}/repo.git"
    for ref, name in (("v1.0", "tag"), (git_server["v1"], "commit")):
        output = tmp_path / name
        code = _main(
            monkeypatch, "scan", url, "--ref", ref, "--allow-insecure-transport",
            "--output", str(output), "--quiet", "--format", "json",
        )
        assert code == cli.EXIT_OK
        report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
        assert report["metrics"]["source"]["remote"]["revision"] == git_server["v1"]
        assert report["metrics"]["source"]["remote"]["ref"] == ref
        paths = {item["path"] for item in report["files"]}
        assert "src/app.py" in paths and "src/added_in_v2.py" not in paths


def test_plain_text_remote_requires_explicit_opt_in(git_server, tmp_path: Path, monkeypatch, capsys):
    output = tmp_path / "refused"
    code = _main(monkeypatch, "scan", f"{git_server['url']}/small.git", "--output", str(output))
    assert code == cli.EXIT_USAGE
    assert "--allow-insecure-transport" in capsys.readouterr().err
    assert not (output / "discovery-report.json").exists()


def test_strict_counts_missing_content_but_not_transport_notes(git_server, tmp_path: Path, monkeypatch):
    small = f"{git_server['url']}/small.git"
    clean = _main(
        monkeypatch, "scan", small, "--allow-insecure-transport", "--strict",
        "--output", str(tmp_path / "clean"), "--quiet", "--format", "json",
    )
    assert clean == cli.EXIT_OK
    truncated_output = tmp_path / "truncated"
    truncated = _main(
        monkeypatch, "scan", f"{git_server['url']}/repo.git", "--allow-insecure-transport",
        "--strict", "--remote-max-gb", "0.00000001", "--output", str(truncated_output),
        "--quiet", "--format", "json",
    )
    assert truncated == cli.EXIT_INCOMPLETE
    report = json.loads((truncated_output / "discovery-report.json").read_text(encoding="utf-8"))
    assert any("remote budget" in error for error in report["errors"])
    assert report["metrics"]["source"]["remote"]["budget_omitted_file_count"] > 0


def test_url_batch_isolates_an_unreachable_repository(git_server, tmp_path: Path, monkeypatch):
    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        f"{git_server['url']}/small.git\n"
        f"{git_server['url']}/missing.git   # does not exist\n"
        f"{git_server['url']}/repo.git ref=v1.0\n",
        encoding="utf-8",
    )
    output = tmp_path / "batch"
    code = _main(
        monkeypatch, "scan", "--url", str(url_file), "--allow-insecure-transport",
        "--output", str(output), "--quiet", "--format", "json",
    )
    assert code == cli.EXIT_INCOMPLETE
    summary = json.loads((output / "batch-summary.json").read_text(encoding="utf-8"))
    assert summary["kind"] == "pdt-remote-batch"
    assert [item["status"] for item in summary["targets"]] == ["completed", "failed", "completed"]
    assert summary["targets"][1]["error"]
    assert summary["targets"][2]["revision"] == git_server["v1"]
    assert summary["exit_code"] == cli.EXIT_INCOMPLETE
    for item in summary["targets"]:
        if item["status"] == "completed":
            assert (Path(item["report_directory"]) / "discovery-report.json").is_file()
    assert "| failed |" in (output / "batch-summary.md").read_text(encoding="utf-8")
