from contextlib import contextmanager
from pathlib import Path

import pytest


def test_cli_scans_one_remote_url(tmp_path: Path, monkeypatch):
    import sys

    from project_discovery import cli
    from project_discovery.remote import RemoteCheckout

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    calls = []

    @contextmanager
    def fake_checkout(target, *, timeout):
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
    from project_discovery.remote import RemoteCheckout

    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        "https://github.com/acme/one\n"
        "https://gitlab.com/group/two\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"
    calls = []

    @contextmanager
    def fake_checkout(target, *, timeout):
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
    from project_discovery.remote import RemoteCheckout, RemoteScanError

    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        "https://github.com/acme/fails\n"
        "https://gitlab.com/group/succeeds\n",
        encoding="utf-8",
    )
    scan_calls = []

    @contextmanager
    def fake_checkout(target, *, timeout):
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
    monkeypatch.setattr(
        sys, "argv", ["pdt", "scan", "--url", str(url_file), "--quiet"],
    )

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == cli.EXIT_INCOMPLETE
    assert len(scan_calls) == 1
