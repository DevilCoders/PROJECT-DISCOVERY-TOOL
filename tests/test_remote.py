from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from project_discovery import remote
from project_discovery.remote import RemoteScanError


@pytest.mark.parametrize(
    ("url", "provider", "clone_url", "vcs"),
    [
        (
            "https://github.com/acme/widgets/tree/main/src",
            "GitHub",
            "https://github.com/acme/widgets",
            "git",
        ),
        (
            "https://gitlab.com/group/subgroup/project/-/tree/main",
            "GitLab",
            "https://gitlab.com/group/subgroup/project",
            "git",
        ),
        (
            "https://bitbucket.org/workspace/project/src/main/",
            "Bitbucket",
            "https://bitbucket.org/workspace/project",
            "git",
        ),
        (
            "https://dev.azure.com/acme/platform/_git/agent?path=/src",
            "Azure Repos",
            "https://dev.azure.com/acme/platform/_git/agent",
            "git",
        ),
        (
            "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/platform",
            "AWS CodeCommit",
            "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/platform",
            "git",
        ),
        (
            "https://git.sr.ht/~acme/platform/tree/main",
            "SourceHut",
            "https://git.sr.ht/~acme/platform",
            "git",
        ),
        (
            "https://codeberg.org/acme/platform/src/branch/main",
            "Forgejo",
            "https://codeberg.org/acme/platform",
            "git",
        ),
        (
            "hg+https://hg.example.net/team/project",
            "Git-compatible host",
            "https://hg.example.net/team/project",
            "hg",
        ),
        (
            "svn+https://svn.example.net/repos/project/trunk",
            "Git-compatible host",
            "https://svn.example.net/repos/project/trunk",
            "svn",
        ),
    ],
)
def test_remote_target_detects_provider_and_normalizes_browser_urls(
    url: str, provider: str, clone_url: str, vcs: str,
):
    target = remote.parse_remote_target(url)
    assert target.provider == provider
    assert target.clone_url == clone_url
    assert target.vcs == vcs
    assert target.repository_name == clone_url.rstrip("/").split("/")[-1].removesuffix(".git")
    assert target.output_name


def test_remote_target_preserves_ssh_user_and_case_sensitive_repository_path():
    ssh = remote.parse_remote_target("ssh://git@github.com/Acme/Project.git")
    scp = remote.parse_remote_target("git@github.com:Acme/Project.git")
    lower = remote.parse_remote_target("git@github.com:acme/project.git")

    assert ssh.clone_url == "ssh://git@github.com/Acme/Project.git"
    assert scp.clone_url == "git@github.com:Acme/Project.git"
    assert ssh.identity != lower.identity
    assert ssh.repository_name == "Project"


@pytest.mark.parametrize(
    "url",
    [
        "https://token:secret@github.com/acme/project.git",
        "https://github.com/acme/project.git?access_token=secret",
        "https://github.com/acme/project.git?private_token=secret",
        "http://github.com/acme/project.git",
        "file:///tmp/project.git",
        "ftp://example.com/project.git",
    ],
)
def test_remote_target_rejects_credential_bearing_or_unsafe_urls(url: str):
    with pytest.raises(RemoteScanError):
        remote.parse_remote_target(url)


def test_remote_target_can_force_hg_or_svn_for_ambiguous_https_urls():
    hg = remote.parse_remote_target("https://hg.example.net/team/project", vcs="hg")
    svn = remote.parse_remote_target("https://svn.example.net/repos/project/trunk", vcs="svn")
    assert hg.vcs == "hg"
    assert svn.vcs == "svn"


def test_url_file_supports_mixed_providers_comments_and_deduplication(tmp_path: Path):
    url_file = tmp_path / "repositories.txt"
    url_file.write_text(
        "\ufeff# public and private repositories\n"
        "https://github.com/acme/widgets\n"
        "https://github.com/acme/widgets/tree/main\n"
        "https://gitlab.com/group/project\n"
        "ssh://git@bitbucket.org/workspace/service.git\n"
        "git@github.com:Acme/Project.git\n"
        "git@github.com:acme/project.git\n",
        encoding="utf-8",
    )

    targets = remote.load_remote_targets(url_file)

    assert [item.provider for item in targets] == [
        "GitHub", "GitLab", "Bitbucket", "GitHub", "GitHub",
    ]
    assert len({item.identity for item in targets}) == len(targets)
    assert targets[0].clone_url == "https://github.com/acme/widgets"
    assert targets[-2].identity != targets[-1].identity


def test_url_file_rejects_invalid_lines_with_line_number(tmp_path: Path):
    url_file = tmp_path / "bad.txt"
    url_file.write_text(
        "# first line\nhttps://github.com/acme/project\nnot-a-url\n",
        encoding="utf-8",
    )
    with pytest.raises(RemoteScanError, match=r"bad\.txt:3"):
        remote.load_remote_targets(url_file)


@pytest.mark.parametrize(
    "relative",
    [
        "../outside",
        "/absolute/path",
        r"..\outside",
        ".git/config",
        "folder/../../outside",
    ],
)
def test_git_tree_path_validation_rejects_unsafe_paths(tmp_path: Path, relative: str):
    with pytest.raises(RemoteScanError):
        remote._safe_destination(tmp_path, relative.encode())


def test_git_tree_path_validation_and_parent_creation_are_safe(tmp_path: Path):
    destination = remote._safe_destination(tmp_path, b"src/module/main.py")
    remote._ensure_safe_parent(tmp_path, destination.parent)
    assert destination.parent.is_dir()

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RemoteScanError, match="non-directory ancestor"):
        remote._ensure_safe_parent(tmp_path, tmp_path / "linked" / "child")


def test_git_checkout_uses_no_checkout_and_separate_git_metadata(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("https://github.com/acme/platform")
    checkout = tmp_path / "source"
    git_dir = tmp_path / "git"
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if "rev-parse" in command:
            return SimpleNamespace(stdout=b"abc123\n")
        if "symbolic-ref" in command:
            return SimpleNamespace(stdout=b"main\n")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    monkeypatch.setattr(
        remote,
        "_extract_git_tree",
        lambda *args, **kwargs: {
            "tracked_file_count": 2,
            "materialized_symlink_count": 0,
            "omitted_symlink_count": 0,
            "submodule_count": 1,
            "submodule_paths_sample": ["vendor/lib"],
            "git_lfs_pointer_count": 1,
            "omitted_tree_path_count": 0,
        },
    )

    metadata = remote._git_checkout(
        target, checkout, git_dir, tmp_path, timeout=30,
    )

    clone = commands[0]
    assert clone[0] == "git"
    assert "clone" in clone
    assert "--no-checkout" in clone
    assert "--no-recurse-submodules" in clone
    assert "--separate-git-dir" in clone
    assert metadata["revision"] == "abc123"
    assert metadata["branch"] == "main"
    assert metadata["submodules_fetched"] is False
    assert metadata["git_lfs_objects_fetched"] is False
    assert len(metadata["warnings"]) == 2


def test_remote_checkout_cleans_temporary_source_after_context_exit(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("https://github.com/acme/platform")
    captured = {}

    def fake_checkout(_target, checkout, _git_dir, _temporary, *, timeout):
        checkout.mkdir()
        (checkout / "main.py").write_text("print('ok')\n", encoding="utf-8")
        captured["path"] = checkout
        return {"mode": "remote", "vcs": "git", "warnings": []}

    monkeypatch.setattr(remote, "_git_checkout", fake_checkout)
    with remote.remote_checkout(target, timeout=15) as result:
        assert result.path.is_dir()
        assert (result.path / "main.py").is_file()
    assert not captured["path"].exists()
