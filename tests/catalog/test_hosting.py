"""Source-hosting provider fingerprints: the public services, host-name guesses, and the
operator's provider map (pdt scan --provider-map) with its validation, its use in local scans,
analyzer worker processes and --resume."""
from __future__ import annotations

import json
import pickle
import re
import sys
from pathlib import Path

import pytest

from project_discovery import cli
from project_discovery.catalog import hosting
from project_discovery.catalog.hosting import (
    classify_host,
    configure_provider_map,
    configured_provider_map,
    load_provider_map,
    parse_provider_map,
)

MAP = """
[[provider]]
host = "code.acme.example"
kind = "github-enterprise"
api_url = "https://code.acme.example/api/v3/"

[[provider]]
host = "*.forge.acme.example"
kind = "gitea"

[[provider]]
host = "deep.forge.acme.example"
kind = "forgejo"

[[provider]]
host = "*.acme.example"
kind = "gitlab-self-managed"

[[provider]]
host = "github-mirror.acme.example"
kind = "unclassified"

[[provider]]
host = "192.0.2.10"
kind = "gerrit"

[[provider]]
host = "[2001:DB8::1]"
kind = "gitolite"

[[provider]]
host = "Gït.Example."
kind = "bitbucket-data-center"
"""


def _map(text: str = MAP, name: str = "providers.toml"):
    return parse_provider_map(text.encode("utf-8"), name)


def test_public_services_and_host_name_guesses():
    built_in = {
        "github.com": "GitHub", "API.GitHub.com.": "GitHub", "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket",
        "dev.azure.com": "Azure Repos", "ssh.dev.azure.com": "Azure Repos", "acme.visualstudio.com": "Azure Repos",
        "git-codecommit.eu-west-1.amazonaws.com": "AWS CodeCommit",
        "source.developers.google.com": "Google Cloud Source Repositories", "git.sr.ht": "SourceHut",
        "hg.sr.ht": "SourceHut", "codeberg.org": "Forgejo", "nest.pijul.com": "Pijul Nest", "hub.darcs.net": "Darcs Hub",
    }
    for host, label in built_in.items():
        assert classify_host(host) == hosting.HostProvider(label, "built-in"), host
    guessed = {
        "github.acme.example": "GitHub Enterprise", "gitlab.internal": "GitLab self-managed",
        "bitbucket.corp.example": "Bitbucket Data Center", "azure-devops.corp": "Azure DevOps Server",
        "gitea.lan": "Gitea", "forgejo.lan": "Forgejo", "gogs.lan": "Gogs", "review.gerrit.example": "Gerrit",
        "gitolite.corp": "Gitolite", "vpce-1.git-codecommit.us-east-1.vpce.amazonaws.com": "AWS CodeCommit",
        # Only a guess: the name says GitHub, the host is not github.com.
        "github.com.evil.example": "GitHub Enterprise",
    }
    for host, label in guessed.items():
        assert classify_host(host) == hosting.HostProvider(label, "host-name"), host
    for host in ("git.example.com", "", None, "[::1]", "192.0.2.7"):
        assert classify_host(host) is None, host


def test_the_provider_map_comes_first_and_the_most_specific_entry_wins():
    provider_map = _map()
    assert classify_host("code.acme.example", provider_map) == hosting.HostProvider(
        "GitHub Enterprise", "provider-map", "github-enterprise", "https://code.acme.example/api/v3", 1)
    assert classify_host("x.forge.acme.example", provider_map).label == "Gitea"  # *.forge beats *.acme
    assert classify_host("deep.forge.acme.example", provider_map).label == "Forgejo"  # a host beats a wildcard
    assert classify_host("forge.acme.example", provider_map).label == "GitLab self-managed"  # not its own wildcard
    # An unclassified host is no provider, whatever its name suggests or a wildcard says.
    assert classify_host("github-mirror.acme.example", provider_map) is None
    assert classify_host("192.0.2.10", provider_map).label == "Gerrit"
    # IP addresses compare in their compressed form, as a URL may spell them otherwise.
    assert classify_host("2001:db8:0::1", provider_map).label == "Gitolite"
    assert classify_host("[2001:DB8::1]", provider_map).label == "Gitolite"
    assert classify_host("gït.example", provider_map).label == "Bitbucket Data Center"
    # Hosts the map does not name keep the public services and the guesses.
    assert classify_host("gitlab.com", provider_map).source == "built-in"
    assert classify_host("gitea.lan", provider_map).source == "host-name"
    # The configured map is what classify_host uses by default.
    configure_provider_map(provider_map)
    assert classify_host("code.acme.example").source == "provider-map"
    assert configured_provider_map() is provider_map


def test_the_provider_map_pickles_and_describes_itself():
    provider_map = _map()
    assert pickle.loads(pickle.dumps(provider_map)) == provider_map
    assert pickle.loads(pickle.dumps(provider_map)).match("x.forge.acme.example").kind == "gitea"
    description = provider_map.describe()
    assert (description["file"], description["entries"]) == ("providers.toml", 8)
    assert len(description["sha256"]) == 64 and description["kinds"]["gitea"] == 1
    assert not hosting.ProviderMap() and hosting.ProviderMap().match("code.acme.example") is None


@pytest.mark.parametrize(("text", "message"), [
    ("[[provider]\n", "not a TOML file"),
    ("[providers]\n", "unknown top-level key 'providers'"),
    ('provider = "x"\n', "list of [[provider]] tables"),
    ('[[provider]]\nhost = "a.example"\nkind = "gitea"\nname = "x"\n', "entry 1: unknown key 'name'"),
    ('[[provider]]\nhost = "a.example"\nkind = "github"\n', "kind must be one of"),
    ('[[provider]]\nkind = "gitea"\n', "host must be a host name"),
    ('[[provider]]\nhost = "https://git.example.com"\nkind = "gitea"\n', "is not a host name"),
    ('[[provider]]\nhost = "git.example.com:8443"\nkind = "gitea"\n', "no scheme, port, path or user"),
    ('[[provider]]\nhost = "*.com"\nkind = "gitea"\n', "at least two labels"),
    ('[[provider]]\nhost = "-bad.example"\nkind = "gitea"\n', "is not a host name"),
    ('[[provider]]\nhost = "github.com"\nkind = "github-enterprise"\n', "is GitHub, a public service"),
    ('[[provider]]\nhost = "*.gitlab.com"\nkind = "gitlab-self-managed"\n', "is GitLab, a public service"),
    ('[[provider]]\nhost = "a.example"\nkind = "gitea"\n[[provider]]\nhost = "A.example."\nkind = "gogs"\n',
     "entry 2: a.example is already named by entry 1"),
    ('[[provider]]\nhost = "a.example"\nkind = "gitea"\napi_url = "http://a.example/api/v1"\n', "must use https://"),
    ('[[provider]]\nhost = "a.example"\nkind = "gitea"\napi_url = "https://me:pw@a.example/api"\n', "credentials"),
    ('[[provider]]\nhost = "a.example"\nkind = "gitea"\napi_url = "https://a.example/api?x=1"\n', "query string"),
    ('[[provider]]\nhost = "a.example"\nkind = "gitea"\napi_url = "ftp://a.example/"\n', "https:// URL"),
    ('[[provider]]\nhost = "a.example"\nkind = "gerrit"\napi_url = "https://a.example/api"\n', "has no API for kind"),
])
def test_provider_map_files_are_validated(text: str, message: str):
    with pytest.raises(ValueError, match=re.escape(message)):
        _map(text)


def test_provider_map_limits_and_loopback_apis(tmp_path: Path, monkeypatch):
    with pytest.raises(ValueError, match="larger than"):
        _map("#" * (hosting.MAX_MAP_BYTES + 1))
    monkeypatch.setattr(hosting, "MAX_MAP_ENTRIES", 2)
    with pytest.raises(ValueError, match="more than 2"):
        _map("".join(f'[[provider]]\nhost = "h{number}.example"\nkind = "gitea"\n' for number in range(3)))
    monkeypatch.undo()
    loopback = _map('[[provider]]\nhost = "a.example"\nkind = "gitea"\napi_url = "http://127.0.0.1:8080/api/v1"\n')
    assert loopback.entries[0].api_url == "http://127.0.0.1:8080/api/v1"
    assert not _map("") and _map("").describe()["entries"] == 0
    with pytest.raises(FileNotFoundError):
        load_provider_map(tmp_path / "missing.toml")
    path = tmp_path / "providers.toml"
    path.write_text(MAP, encoding="utf-8")
    assert load_provider_map(path).describe()["file"] == "providers.toml"


# ---------------------------------------------------------------------------------------------
# pdt scan --provider-map


def _project(root: Path) -> Path:
    project = root / "project"
    (project / ".git").mkdir(parents=True)
    (project / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://code.acme.example/team/app.git\n'
        '[remote "mirror"]\n\turl = git@github-mirror.acme.example:team/app.git\n', encoding="utf-8")
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return project


def _scan(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["pdt", "scan", *argv, "--quiet", "--format", "json,markdown,html"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    return result.value.code


@pytest.mark.parametrize("executor", ["thread", "process"])
def test_scans_classify_remotes_with_the_map_in_every_worker(executor: str, tmp_path: Path, monkeypatch):
    project = _project(tmp_path)
    providers = tmp_path / "providers.toml"
    providers.write_text(MAP, encoding="utf-8")
    output = tmp_path / f"out-{executor}"
    assert _scan(monkeypatch, str(project), "--provider-map", str(providers), "--output", str(output),
                 "--executor", executor, "--jobs", "2") == cli.EXIT_OK
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    remotes = {item["title"]: item for item in report["findings"] if item["category"] == "hosting_providers"}
    configured = remotes["Git remote provider: GitHub Enterprise"]
    assert configured["confidence"] == "CONFIRMED"
    assert "provider map entry 1: github-enterprise" in configured["evidence"]
    # The map marks the mirror unclassified, although its name says GitHub.
    assert remotes["Git remote provider: Self-hosted or unclassified"]["confidence"] == "CONFIRMED"
    summary = report["scan"]["provider_map"]
    assert (summary["file"], summary["entries"]) == ("providers.toml", 8)
    assert report["metrics"]["provider_map"] == summary
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Provider map: providers.toml: 8 entries (SHA-256 " in markdown
    assert report["metrics"]["execution"]["executor"] == executor


def test_without_a_map_the_host_names_are_guesses(tmp_path: Path, monkeypatch):
    project = _project(tmp_path)
    output = tmp_path / "out"
    assert _scan(monkeypatch, str(project), "--output", str(output)) == cli.EXIT_OK
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    remotes = {item["title"]: item for item in report["findings"] if item["category"] == "hosting_providers"}
    guessed = remotes["Git remote provider: GitHub Enterprise"]
    assert guessed["confidence"] == "INFERRED" and "guessed from a word in the host name" in guessed["detail"]
    assert "Git remote provider: Self-hosted or unclassified" in remotes
    assert report["scan"]["provider_map"] is None and report["metrics"]["provider_map"] is None


def test_an_invalid_map_is_a_usage_error_and_resume_needs_the_same_map(tmp_path: Path, monkeypatch, capsys):
    project = _project(tmp_path)
    bad = tmp_path / "bad.toml"
    bad.write_text('[[provider]]\nhost = "github.com"\nkind = "gitea"\n', encoding="utf-8")
    assert _scan(monkeypatch, str(project), "--provider-map", str(bad), "--output", str(tmp_path / "x")) == cli.EXIT_USAGE
    assert "a public service" in capsys.readouterr().err
    assert _scan(monkeypatch, str(project), "--provider-map", str(tmp_path / "none.toml"),
                 "--output", str(tmp_path / "x")) == cli.EXIT_USAGE
    providers = tmp_path / "providers.toml"
    providers.write_text(MAP, encoding="utf-8")
    output = tmp_path / "out"
    assert _scan(monkeypatch, str(project), "--provider-map", str(providers), "--output", str(output)) == cli.EXIT_OK
    assert _scan(monkeypatch, str(project), "--provider-map", str(providers), "--output", str(output),
                 "--resume") == cli.EXIT_OK
    capsys.readouterr()
    assert _scan(monkeypatch, str(project), "--output", str(output), "--resume") == cli.EXIT_USAGE
    error = " ".join(capsys.readouterr().err.split())
    assert "--provider-map: stored a map with SHA-256" in error and "now none" in error
