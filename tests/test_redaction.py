"""URL credentials, query strings and fragments never reach any output of a scan.

A project is seeded with URLs whose user name, password, query value and fragment are unique
canary strings, in every kind of file PDT reads URLs from: VCS remotes and submodules, lockfiles
and registry configuration, source code, environment and configuration files, CI workflows,
container and deployment manifests, API contracts, Terraform and documentation. A full scan
writes every report format, and the test searches each output for the canaries: the JSON,
Markdown and HTML reports, what the terminal printed, every table of the scan's SQLite stores
(inventory, findings, code facts, fingerprint cache) and `pdt compare` reports. Remote targets
that embed credentials are refused without echoing them, in a single scan and in a batch.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

from project_discovery import cli

# Built by concatenation: no secret scanner mistakes them for real credentials.
USER = "canary" + "user" + "8812"
PASSWORD = "canary" + "Pw" + "4471"
QUERY = "canary" + "Query" + "5590"
FRAGMENT = "canary" + "Frag" + "3317"
CANARIES = (USER, PASSWORD, QUERY, FRAGMENT)


def _url(scheme: str, host: str, path: str = "/") -> str:
    return f"{scheme}://{USER}:{PASSWORD}@{host}{path}?token={QUERY}&page=2#{FRAGMENT}"


def _project(root: Path) -> Path:
    project = root / "project"
    files = {
        ".git/config": f'[remote "origin"]\n\turl = {_url("https", "git.example.com", "/acme/app.git")}\n',
        ".gitmodules": f'[submodule "lib"]\n\tpath = lib\n\turl = {_url("https", "git.example.com", "/acme/lib.git")}\n',
        ".hg/hgrc": f"[paths]\ndefault = {_url('https', 'hg.example.com', '/acme/app')}\n",
        ".hg/requires": "revlogv1\nstore\n",
        ".bzr/branch/branch.conf": f"parent_location = {_url('https', 'bzr.example.com', '/acme/app')}\n",
        ".bzr/branch-format": "Bazaar-NG meta directory, format 1\n",
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/left-pad": {"version": "1.3.0",
                                      "resolved": _url("https", "npm.example.com", "/left-pad/-/l-1.3.0.tgz")},
        }}),
        "yarn.lock": ("lodash@^4.17.21:\n  version \"4.17.21\"\n"
                      f"  resolved \"{_url('https', 'npm.example.com', '/lodash/-/lodash-4.17.21.tgz')}\"\n"),
        "Pipfile.lock": json.dumps({"_meta": {"sources": [{"name": "corp", "url": _url("https", "pypi.example.com",
                                                                                      "/simple")}]},
                                    "default": {"requests": {"version": "==2.31.0"}}}),
        ".npmrc": f"registry={_url('https', 'npm.example.com')}\n",
        "requirements.txt": (f"--index-url {_url('https', 'pypi.example.com', '/simple')}\n"
                             f"inhouse @ git+{_url('https', 'git.example.com', '/acme/inhouse.git')}\n"),
        "pyproject.toml": ("[project]\nname = \"app\"\nversion = \"1.0\"\n\n[[tool.poetry.source]]\nname = \"corp\"\n"
                           f"url = \"{_url('https', 'pypi.example.com', '/simple')}\"\n"),
        "src/app.py": (f"import requests\n\nAPI = \"{_url('https', 'api.example.com', '/v1')}\"\n\n\n"
                       "def fetch():\n    return requests.get(API, timeout=5)\n"),
        "src/client.ts": f"export const base = '{_url('https', 'api.example.com', '/v2')}';\nfetch(base);\n",
        ".env": f"DATABASE_URL={_url('postgres', 'db.example.com:5432', '/app')}\n",
        "config/settings.yaml": f"database:\n  url: {_url('postgresql', 'db.example.com', '/app')}\n",
        "docker-compose.yml": ("services:\n  app:\n    image: registry.example.com/app:1.0\n    environment:\n"
                               f"      UPSTREAM: {_url('https', 'upstream.example.com')}\n"),
        ".github/workflows/ci.yml": ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                                     f"      - run: curl -fsS {_url('https', 'artifacts.example.com', '/x')}\n"),
        ".gitlab-ci.yml": f"deploy:\n  stage: deploy\n  script:\n    - curl {_url('https', 'deploy.example.com')}\n",
        "k8s/deployment.yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n"
                                "    spec:\n      containers:\n        - name: app\n          image: nginx:1.25\n"
                                "          env:\n            - name: UPSTREAM\n"
                                f"              value: {_url('https', 'upstream.example.com')}\n"),
        "Dockerfile": (f"FROM python:3.12\nARG MIRROR={_url('https', 'mirror.example.com', '/simple')}\n"
                       "RUN pip install --index-url $MIRROR requests\n"),
        "openapi.yaml": ("openapi: 3.0.3\ninfo:\n  title: App\n  version: '1'\nservers:\n"
                         f"  - url: {_url('https', 'api.example.com', '/v1')}\npaths:\n  /pets:\n    get:\n"
                         "      responses:\n        '200':\n          description: ok\n"),
        "infra/main.tf": (f'module "network" {{\n  source = "git::{_url("https", "git.example.com", "/acme/mod.git")}"\n}}\n'
                          'provider "aws" {\n  region = "eu-west-1"\n}\n'),
        "README.md": f"# App\n\nMirror: <{_url('https', 'docs.example.com', '/guide')}>\n",
    }
    for name, content in files.items():
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return project


def _main(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["pdt", *argv])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


def _leaks(text: str, where: str) -> list[str]:
    found = []
    for canary in CANARIES:
        at = text.find(canary)
        if at >= 0:
            found.append(f"{where}: {canary!r} in ...{text[max(0, at - 120):at + 60]!r}...")
    return found


def _database_leaks(path: Path) -> list[str]:
    found = []
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        for table in tables:
            for row in db.execute(f'SELECT * FROM "{table}"'):  # noqa: S608 - names from sqlite_master
                for value in row:
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace")
                    if isinstance(value, str):
                        found.extend(_leaks(value, f"{path.name}:{table}"))
    return found


def test_no_output_of_a_scan_contains_url_credentials_queries_or_fragments(tmp_path: Path, monkeypatch, capsys):
    project = _project(tmp_path)
    output = tmp_path / "out"
    assert _main(monkeypatch, "scan", str(project), "--output", str(output), "--format", "json,markdown,html",
                 "--no-color") in {cli.EXIT_OK, cli.EXIT_INCOMPLETE}
    captured = capsys.readouterr()
    leaks = _leaks(captured.out + captured.err, "terminal")
    for name in ("discovery-report.json", "discovery-report.md", "discovery-report.html"):
        leaks += _leaks((output / name).read_text(encoding="utf-8"), name)
    for database in sorted((output / ".pdt-cache").glob("*.sqlite3")):
        leaks += _database_leaks(database)
    # Comparison reports are built from reports; they must stay as clean.
    second = tmp_path / "second"
    assert _main(monkeypatch, "scan", str(project), "--output", str(second), "--format", "json", "--quiet") in {
        cli.EXIT_OK, cli.EXIT_INCOMPLETE}
    comparison = tmp_path / "comparison"
    assert _main(monkeypatch, "compare", str(output / "discovery-report.json"), str(second / "discovery-report.json"),
                 "--output", str(comparison), "--format", "json,markdown") == 0
    for path in sorted(comparison.iterdir()):
        leaks += _leaks(path.read_text(encoding="utf-8"), f"compare/{path.name}")
    assert not leaks, "\n".join(leaks)
    # The scan did see the URLs: their hosts are reported.
    report = (output / "discovery-report.json").read_text(encoding="utf-8")
    for host in ("git.example.com", "npm.example.com", "api.example.com"):
        assert host in report, host


def test_source_excerpts_keep_where_a_url_points_but_none_of_its_secrets():
    from project_discovery.core.source_utils import redact_source_excerpt

    line = f'API = "{_url("https", "api.example.com:8443", "/v1/items")}"; other = https://plain.example.com/a'
    assert redact_source_excerpt(line) == ('API = "https://[REDACTED]@api.example.com:8443/v1/items?[REDACTED]#[REDACTED]"; '
                                           "other = https://plain.example.com/a")
    # A user name alone can be a token (https://<token>@github.com/...).
    assert redact_source_excerpt(f"git clone https://{PASSWORD}@github.com/acme/app.git") == (
        "git clone https://[REDACTED]@github.com/acme/app.git")
    assert redact_source_excerpt(f"curl 'http://[::1]:8080/x#{FRAGMENT}'") == "curl 'http://[::1]:8080/x#[REDACTED]'"
    # An scp-style address is not a URL; the e-mail rule takes its user@host for an address
    # (more is redacted than needed, nothing leaks).
    assert redact_source_excerpt("git@github.com:acme/app.git") == "[REDACTED_EMAIL]:acme/app.git"


def test_plugin_findings_are_redacted_like_built_in_ones():
    from project_discovery.plugins.isolation import rebuild_plugin_findings

    url = _url("https", "api.example.com", "/v1")
    findings = rebuild_plugin_findings([{
        "category": "security", "title": f"Endpoint {url}", "detail": f"The plugin saw {url}.",
        "confidence": "INFERRED", "evidence": [f"config.yml: {url}"],
    }], "canary-plugin", "config.yml")
    text = json.dumps([item.to_dict() for item in findings])
    assert "api.example.com" in text and not _leaks(text, "plugin findings")


@pytest.mark.parametrize("url", [
    _url("https", "github.com", "/acme/app"),
    f"https://{USER}:{PASSWORD}@github.com/acme/app",
    f"https://github.com/acme/app?access_token={QUERY}",
    f"hg+https://{USER}:{PASSWORD}@hg.example.com/acme/app",
])
def test_remote_targets_with_credentials_are_refused_without_echoing_them(url: str, tmp_path: Path, monkeypatch,
                                                                          capsys):
    assert _main(monkeypatch, "scan", url, "--output", str(tmp_path / "out"), "--quiet") == cli.EXIT_USAGE
    captured = capsys.readouterr()
    assert not _leaks(captured.out + captured.err, "terminal"), captured.err
    urls = tmp_path / "repositories.txt"
    urls.write_text(f"https://github.com/acme/ok\n{url} ref=main\n", encoding="utf-8")
    assert _main(monkeypatch, "scan", "--url", str(urls), "--output", str(tmp_path / "batch"), "--quiet") == (
        cli.EXIT_USAGE)
    captured = capsys.readouterr()
    assert not _leaks(captured.out + captured.err, "terminal (batch)"), captured.err
    for path in (tmp_path / "batch").glob("batch-summary.*"):
        assert not _leaks(path.read_text(encoding="utf-8"), path.name)
