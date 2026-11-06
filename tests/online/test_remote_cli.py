from contextlib import contextmanager
from pathlib import Path

import pytest


def test_cli_scans_one_remote_url(tmp_path: Path, monkeypatch):
    import sys

    from project_discovery import cli
    from project_discovery.online.repositories import RemoteCheckout

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    calls = []

    @contextmanager
    def fake_checkout(target, *, timeout, **_kwargs):
        calls.append(("checkout", target, timeout))
        yield RemoteCheckout(
            checkout,
            {"mode": "remote", "vcs": "git", "provider": target.provider, "warnings": []},
        )

    def fake_run_scan(root, output, formats, max_file_mb, **kwargs):
        calls.append(("scan", root, output, formats, max_file_mb, kwargs))
        return 0

    monkeypatch.setattr(cli, "remote_checkout", fake_checkout)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(
        sys, "argv",
        ["pdt", "scan", "https://github.com/acme/widgets/tree/main", "--quiet"],
    )

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == 0
    assert calls[0][1].provider == "GitHub"
    scan_call = calls[1]
    assert scan_call[1] == checkout
    assert scan_call[2].name.endswith("-pdt-report")
    assert scan_call[5]["display_root"] == "https://github.com/acme/widgets"
    assert scan_call[5]["source_metadata"]["provider"] == "GitHub"


def test_cli_scans_mixed_provider_url_file_into_separate_report_folders(
    tmp_path: Path, monkeypatch,
):
    import sys

    from project_discovery import cli
    from project_discovery.online.repositories import RemoteCheckout

    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        "https://github.com/acme/one\n"
        "https://gitlab.com/group/two\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"
    calls = []

    @contextmanager
    def fake_checkout(target, *, timeout, **_kwargs):
        path = tmp_path / f"checkout-{len(calls)}"
        path.mkdir(exist_ok=True)
        calls.append(("checkout", target.provider))
        yield RemoteCheckout(
            path,
            {"mode": "remote", "vcs": "git", "provider": target.provider, "warnings": []},
        )

    def fake_run_scan(root, report_output, formats, max_file_mb, **kwargs):
        calls.append(("scan", root, report_output, kwargs))
        return 0

    monkeypatch.setattr(cli, "remote_checkout", fake_checkout)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(
        sys, "argv",
        ["pdt", "scan", "--url", str(url_file), "--output", str(output), "--quiet"],
    )

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == 0
    scans = [item for item in calls if item[0] == "scan"]
    assert len(scans) == 2
    assert scans[0][3]["source_metadata"]["provider"] == "GitHub"
    assert scans[1][3]["source_metadata"]["provider"] == "GitLab"
    assert scans[0][2].parent == output
    assert scans[1][2].parent == output
    assert scans[0][2] != scans[1][2]


def test_cli_continues_url_batch_after_one_remote_checkout_failure(
    tmp_path: Path, monkeypatch,
):
    import sys

    from project_discovery import cli
    from project_discovery.online.repositories import RemoteCheckout, RemoteScanError

    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        "https://github.com/acme/fails\n"
        "https://gitlab.com/group/succeeds\n",
        encoding="utf-8",
    )
    scan_calls = []

    @contextmanager
    def fake_checkout(target, *, timeout, **_kwargs):
        if target.provider == "GitHub":
            raise RemoteScanError("simulated authentication failure")
        checkout = tmp_path / "success-checkout"
        checkout.mkdir(exist_ok=True)
        yield RemoteCheckout(
            checkout,
            {"mode": "remote", "vcs": "git", "provider": target.provider, "warnings": []},
        )

    def fake_run_scan(*args, **kwargs):
        scan_calls.append(args)
        return 0

    monkeypatch.setattr(cli, "remote_checkout", fake_checkout)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    # Without --output a batch writes into ./pdt-remote-reports.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["pdt", "scan", "--url", str(url_file), "--quiet"],
    )

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == cli.EXIT_INCOMPLETE
    assert len(scan_calls) == 1
    assert (tmp_path / "pdt-remote-reports" / "batch-summary.json").is_file()



def test_cli_scans_mixed_vcs_url_batch_and_keeps_backend_metadata(
    tmp_path: Path, monkeypatch,
):
    import sys

    from project_discovery import cli
    from project_discovery.online.repositories import RemoteCheckout

    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        "https://github.com/acme/git-project\n"
        "hg+https://hg.example.net/team/hg-project\n"
        "svn+https://svn.example.net/repos/svn-project/trunk\n"
        "bzr+https://code.example.net/team/bzr-project\n"
        "p4+ssl://perforce.example.net:1666/depot/p4-project\n"
        "fossil+https://fossil.example.net/fossil-project\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"
    calls = []

    @contextmanager
    def fake_checkout(target, *, timeout, **_kwargs):
        checkout = tmp_path / f"checkout-{target.vcs}"
        checkout.mkdir(exist_ok=True)
        calls.append(("checkout", target.vcs))
        yield RemoteCheckout(
            checkout,
            {
                "mode": "remote", "vcs": target.vcs,
                "provider": target.provider, "warnings": [],
            },
        )

    def fake_run_scan(root, report_output, formats, max_file_mb, **kwargs):
        calls.append(("scan", kwargs["source_metadata"]["vcs"], report_output))
        return 0

    monkeypatch.setattr(cli, "remote_checkout", fake_checkout)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(
        sys, "argv",
        ["pdt", "scan", "--url", str(url_file), "--output", str(output), "--quiet"],
    )

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == 0
    scan_calls = [item for item in calls if item[0] == "scan"]
    assert [item[1] for item in scan_calls] == ["git", "hg", "svn", "bzr", "p4", "fossil"]
    assert len({item[2] for item in scan_calls}) == 6
    assert all(item[2].parent == output for item in scan_calls)


# ---------------------------------------------------------------------------
# Online-mode audit regressions
# ---------------------------------------------------------------------------

def _run_cli(monkeypatch, *argv):
    import sys

    from project_discovery import cli

    monkeypatch.setattr(sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


def _fake_remote(monkeypatch, tmp_path, *, fail=None, scan_code=0, calls=None):
    from project_discovery import cli
    from project_discovery.online.repositories import RemoteCheckout, RemoteScanError

    calls = [] if calls is None else calls

    @contextmanager
    def fake_checkout(target, **kwargs):
        calls.append(("checkout", target, kwargs))
        if fail is not None and fail(target):
            raise RemoteScanError(fail(target))
        path = tmp_path / f"checkout-{target.identity}"
        path.mkdir(exist_ok=True)
        yield RemoteCheckout(path, {
            "mode": "remote", "vcs": target.vcs, "provider": target.provider,
            "url": target.clone_url, "revision": "r1", "warnings": [], "coverage": [],
        })

    def fake_run_scan(root, output, formats, max_file_mb, **kwargs):
        calls.append(("scan", root, output, kwargs))
        return scan_code(root) if callable(scan_code) else scan_code

    monkeypatch.setattr(cli, "remote_checkout", fake_checkout)
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    return calls


def _identity(name: str) -> str:
    from project_discovery.online.repositories import parse_remote_target

    return parse_remote_target(f"https://github.com/acme/{name}").identity


def test_remote_error_text_with_markup_does_not_crash_the_batch(tmp_path: Path, monkeypatch, capsys):
    url_file = tmp_path / "repos.txt"
    url_file.write_text("https://github.com/acme/one\nhttps://github.com/acme/two\n", encoding="utf-8")

    def fail(target):
        if target.repository_name == "one":
            return "fatal: repository '[/red][bold]x' not found"
        return None

    calls = _fake_remote(monkeypatch, tmp_path, fail=fail)
    code = _run_cli(monkeypatch, "scan", "--url", str(url_file), "--output", str(tmp_path / "out"))
    assert code == 3
    assert [item[0] for item in calls].count("scan") == 1
    assert "[/red][bold]x" in capsys.readouterr().err


def test_quiet_suppresses_remote_progress_output(tmp_path: Path, monkeypatch, capsys):
    _fake_remote(monkeypatch, tmp_path)
    code = _run_cli(monkeypatch, "scan", "https://github.com/acme/widgets", "--quiet",
                    "--output", str(tmp_path / "out"))
    assert code == 0
    assert capsys.readouterr().err == ""


def test_single_unreachable_remote_is_a_fatal_error(tmp_path: Path, monkeypatch):
    _fake_remote(monkeypatch, tmp_path, fail=lambda target: "authentication failed")
    code = _run_cli(monkeypatch, "scan", "https://github.com/acme/private", "--quiet",
                    "--output", str(tmp_path / "out"))
    assert code == 2


def test_batch_exit_code_prefers_fail_on_and_writes_a_summary(tmp_path: Path, monkeypatch):
    import json

    url_file = tmp_path / "repos.txt"
    url_file.write_text(
        "https://github.com/acme/clean\nhttps://github.com/acme/vulnerable\n"
        "https://github.com/acme/unreachable\nhttps://github.com/acme/partial\n",
        encoding="utf-8",
    )
    codes = {_identity("clean"): 0, _identity("vulnerable"): 1, _identity("partial"): 3}

    def scan_code(root):
        return codes[root.name.removeprefix("checkout-")]

    _fake_remote(
        monkeypatch, tmp_path,
        fail=lambda target: "not found" if target.repository_name == "unreachable" else None,
        scan_code=scan_code,
    )
    output = tmp_path / "out"
    code = _run_cli(monkeypatch, "scan", "--url", str(url_file), "--output", str(output), "--quiet",
                    "--fail-on", "HIGH")
    assert code == 1
    summary = json.loads((output / "batch-summary.json").read_text(encoding="utf-8"))
    assert [item["status"] for item in summary["targets"]] == [
        "completed", "findings", "failed", "incomplete",
    ]
    assert summary["totals"] == {"completed": 1, "failed": 1, "findings": 1, "incomplete": 1}
    assert summary["targets"][2]["error"] == "not found"
    assert summary["exit_code"] == 1
    markdown = (output / "batch-summary.md").read_text(encoding="utf-8")
    assert "| 3 | failed | GitHub | https://github.com/acme/unreachable |" in markdown


def test_interrupted_batch_records_remaining_targets(tmp_path: Path, monkeypatch):
    import json

    url_file = tmp_path / "repos.txt"
    url_file.write_text(
        "https://github.com/acme/one\nhttps://github.com/acme/two\nhttps://github.com/acme/three\n",
        encoding="utf-8",
    )

    def interrupt_second(root):
        if root.name == f"checkout-{_identity('two')}":
            raise KeyboardInterrupt
        return 0

    _fake_remote(monkeypatch, tmp_path, scan_code=interrupt_second)
    output = tmp_path / "out"
    code = _run_cli(monkeypatch, "scan", "--url", str(url_file), "--output", str(output), "--quiet")
    assert code == 130
    summary = json.loads((output / "batch-summary.json").read_text(encoding="utf-8"))
    assert [item["status"] for item in summary["targets"]] == ["completed", "interrupted", "not_started"]
    assert summary["exit_code"] == 130


def test_plain_text_remote_is_refused_before_checkout(tmp_path: Path, monkeypatch):
    calls = _fake_remote(monkeypatch, tmp_path)
    code = _run_cli(monkeypatch, "scan", "git://git.example.net/project.git", "--quiet",
                    "--output", str(tmp_path / "out"))
    assert code == 2
    assert not any(item[0] == "checkout" for item in calls)
    code = _run_cli(monkeypatch, "scan", "git://git.example.net/project.git", "--quiet",
                    "--allow-insecure-transport", "--output", str(tmp_path / "out"))
    assert code == 0
    assert calls[0][2]["allow_insecure_transport"] is True


def test_remote_options_reach_the_checkout(tmp_path: Path, monkeypatch):
    calls = _fake_remote(monkeypatch, tmp_path)
    code = _run_cli(
        monkeypatch, "scan", "https://github.com/acme/widgets", "--ref", "v2.1.0",
        "--remote-workdir", str(tmp_path / "work"), "--remote-max-gb", "2",
        "--remote-timeout", "45", "--quiet", "--output", str(tmp_path / "out"),
    )
    assert code == 0
    _, target, kwargs = calls[0]
    assert target.ref == "v2.1.0"
    assert kwargs["timeout"] == 45
    assert kwargs["workdir"] == tmp_path / "work"
    assert kwargs["limits"].max_bytes == 2 * 1024 ** 3


@pytest.mark.parametrize(
    "option",
    [["--ref", "main"], ["--remote-timeout", "30"], ["--remote-workdir", "w"],
     ["--remote-max-gb", "1"], ["--allow-insecure-transport"], ["--vcs", "git"]],
)
def test_remote_only_options_are_rejected_for_local_paths(tmp_path: Path, monkeypatch, option):
    assert _run_cli(monkeypatch, "scan", str(tmp_path), *option) == 2


def test_run_scan_turns_remote_coverage_into_unknown_findings(tmp_path: Path):
    import json

    from project_discovery import cli

    root = tmp_path / "checkout"
    root.mkdir()
    (root / "README.md").write_text("# remote\n", encoding="utf-8")
    metadata = {
        "mode": "remote", "acquisition": "download", "vcs": "git", "provider": "GitHub",
        "url": "https://github.com/acme/widgets", "revision": "abc",
        "warnings": ["2 Git submodule(s) were inventoried but not fetched.",
                     "The repository was fetched over a transport without TLS."],
        "coverage": [
            {"kind": "git_submodules_not_fetched", "count": 2, "incomplete": False,
             "detail": "2 Git submodule(s) were inventoried but not fetched."},
            {"kind": "paths_not_materialized", "count": 1, "incomplete": True,
             "detail": "1 tracked path(s) could not be materialized safely."},
        ],
        "coverage_gaps": ["1 tracked path(s) could not be materialized safely."],
    }
    output = tmp_path / "report"
    code = cli.run_scan(
        root, output, {"json"}, 128, quiet=True, strict=True,
        source_metadata=metadata, display_root=metadata["url"],
    )
    assert code == cli.EXIT_INCOMPLETE
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert report["root"] == "https://github.com/acme/widgets"
    assert report["errors"] == ["1 tracked path(s) could not be materialized safely."]
    gaps = {item["title"]: item for item in report["findings"] if item["analyzer"] == "remote-source"}
    assert gaps["Remote source coverage gap: paths not materialized"]["severity"] == "LOW"
    assert gaps["Remote source coverage gap: git submodules not fetched"]["severity"] == "INFO"
    assert all(item["confidence"] == "UNKNOWN" for item in gaps.values())
    assert not (output / ".pdt-cache" / "fingerprints.sqlite3").exists()

    metadata["coverage"], metadata["coverage_gaps"] = metadata["coverage"][:1], []
    assert cli.run_scan(
        root, tmp_path / "report-2", {"json"}, 128, quiet=True, strict=True,
        source_metadata=metadata, display_root=metadata["url"],
    ) == cli.EXIT_OK
