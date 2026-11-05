from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit
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
        (
            "fossil+https://fossil.example.net/project",
            "Fossil server",
            "https://fossil.example.net/project",
            "fossil",
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


@pytest.mark.parametrize(
    "url",
    [
        "cvs+pserver://anonymous:secret@cvs.example.net/cvsroot/project",
        "p4+ssl://token:secret@perforce.example.net:1666/depot/project",
        "darcs+https://user:secret@code.example.net/team/project",
        "jj+https://github.com/acme/project?auth_token=secret",
        "pijul+https://nest.pijul.com/acme/project?private_token=secret",
    ],
)
def test_remote_target_rejects_embedded_credentials_for_native_vcs(url: str):
    with pytest.raises(RemoteScanError):
        remote.parse_remote_target(url)


def test_url_file_does_not_deduplicate_distinct_vcs_for_same_remote_url(tmp_path: Path):
    url_file = tmp_path / "same-url-different-vcs.txt"
    url_file.write_text(
        "https://code.example.net/team/project\n"
        "hg+https://code.example.net/team/project\n",
        encoding="utf-8",
    )

    targets = remote.load_remote_targets(url_file)

    assert [item.vcs for item in targets] == ["git", "hg"]
    assert targets[0].identity != targets[1].identity


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
        if "clone" in command:
            checkout_path = Path(command[-1])
            checkout_path.mkdir()
            git_dir_path = Path(command[command.index("--separate-git-dir") + 1])
            (checkout_path / ".git").write_text(
                f"gitdir: {git_dir_path}\n", encoding="utf-8",
            )
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
    assert not (checkout / ".git").exists()


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



def test_git_tree_stream_materializes_files_symlinks_and_submodules_safely(
    tmp_path: Path, monkeypatch,
):
    import io

    file_oid = b"a" * 40
    symlink_oid = b"b" * 40
    invalid_oid = b"c" * 40
    submodule_oid = b"d" * 40
    tree_bytes = b"".join(
        [
            b"100644 blob " + file_oid + b"\tsrc/main.py\0",
            b"120000 blob " + symlink_oid + b"\tsrc/entry.py\0",
            b"160000 commit " + submodule_oid + b"\tvendor/lib\0",
            b"100644 blob " + invalid_oid + b"\t../../outside.py\0",
        ]
    )
    blob_bytes = b"".join(
        [
            file_oid + b" blob 11\nprint('ok')\n",
            symlink_oid + b" blob 7\nmain.py\n",
            invalid_oid + b" blob 9\nmalicious\n",
        ]
    )

    class FakeProcess:
        def __init__(self, *, stdout: bytes):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(stdout)
            self.stderr = io.BytesIO()
            self.returncode = None

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    created = []

    def fake_popen(command, **kwargs):
        if "ls-tree" in command:
            process = FakeProcess(stdout=tree_bytes)
        elif "cat-file" in command:
            process = FakeProcess(stdout=blob_bytes)
        else:
            raise AssertionError(f"unexpected Git subprocess: {command!r}")
        created.append(process)
        return process

    monkeypatch.setattr(remote.subprocess, "Popen", fake_popen)
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    result = remote._extract_git_tree(checkout, {}, timeout=10)

    assert (checkout / "src" / "main.py").read_text(encoding="utf-8") == "print('ok')"
    assert (checkout / "src" / "entry.py").is_symlink()
    assert (checkout / "src" / "entry.py").readlink() == Path("main.py")
    assert (checkout / "vendor" / "lib").is_dir()
    assert not (tmp_path / "outside.py").exists()
    assert result["tracked_file_count"] == 1
    assert result["materialized_symlink_count"] == 1
    assert result["submodule_count"] == 1
    assert result["omitted_tree_path_count"] == 1
    assert len(created) == 2



@pytest.mark.parametrize(
    ("url", "expected_vcs", "expected_scheme"),
    [
        ("bzr+https://code.example.net/team/project", "bzr", "https"),
        ("darcs+https://code.example.net/team/project", "darcs", "https"),
        ("jj+https://github.com/acme/project", "jj", "https"),
        ("pijul+https://nest.pijul.com/acme/project", "pijul", "https"),
        (
            "cvs+pserver://anonymous@cvs.example.net:2401/cvsroot/project",
            "cvs", "pserver",
        ),
        ("cvs+ssh://cvs@cvs.example.net/cvsroot/project", "cvs", "ssh"),
        ("p4+ssl://perforce.example.net:1666/depot/project", "p4", "ssl"),
        ("perforce+tcp://perforce.example.net:1666/depot/project", "p4", "tcp"),
    ],
)
def test_remote_target_recognizes_native_vcs_transports(
    url: str, expected_vcs: str, expected_scheme: str,
):
    target = remote.parse_remote_target(url)
    assert target.vcs == expected_vcs
    assert urlsplit(target.clone_url).scheme == expected_scheme
    assert target.repository_name == "project"
    assert target.output_name


def test_remote_target_auto_detects_native_bzr_and_cvs_schemes():
    bazaar = remote.parse_remote_target("bzr://bzr.example.net/team/project")
    cvs = remote.parse_remote_target("pserver://anonymous@cvs.example.net/cvsroot/project")

    assert bazaar.vcs == "bzr"
    assert cvs.vcs == "cvs"
    assert cvs.insecure_transport is True


def test_remote_target_supports_vcs_aliases_and_forced_backend_with_prefixed_url():
    bazaar = remote.parse_remote_target("bzr+https://code.example.net/team/project", vcs="bazaar")
    perforce = remote.parse_remote_target(
        "p4+ssl://perforce.example.net:1666/depot/project", vcs="perforce",
    )
    assert bazaar.vcs == "bzr"
    assert bazaar.clone_url == "https://code.example.net/team/project"
    assert perforce.vcs == "p4"
    assert perforce.clone_url == "ssl://perforce.example.net:1666/depot/project"


def test_url_file_supports_mixed_native_vcs_backends(tmp_path: Path):
    url_file = tmp_path / "mixed-vcs.txt"
    url_file.write_text(
        "https://github.com/acme/git-project\n"
        "hg+https://hg.example.net/team/hg-project\n"
        "svn+https://svn.example.net/repos/svn-project/trunk\n"
        "bzr+https://code.example.net/team/bzr-project\n"
        "darcs+https://code.example.net/team/darcs-project\n"
        "jj+https://github.com/acme/jj-project\n"
        "pijul+https://nest.pijul.com/acme/pijul-project\n"
        "cvs+pserver://cvs.example.net/cvsroot/cvs-project\n"
        "p4+ssl://perforce.example.net:1666/depot/p4-project\n"
        "fossil+https://fossil.example.net/fossil-project\n",
        encoding="utf-8",
    )
    targets = remote.load_remote_targets(url_file)
    assert [target.vcs for target in targets] == [
        "git", "hg", "svn", "bzr", "darcs", "jj", "pijul", "cvs", "p4", "fossil",
    ]


def test_hg_checkout_exports_committed_tree_without_working_copy_update(
    tmp_path: Path, monkeypatch,
):
    target = remote.parse_remote_target("hg+https://hg.example.net/team/project")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    checkout = temporary / "source"
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if "clone" in command:
            Path(command[-1]).mkdir()
        elif "log" in command and "{node}" in command:
            return SimpleNamespace(stdout=b"revision-123")
        elif "log" in command and "{branch}" in command:
            return SimpleNamespace(stdout=b"default")
        elif "archive" in command:
            Path(command[-1]).mkdir()
            (Path(command[-1]) / "main.py").write_text("print('hg')\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._hg_checkout(target, checkout, temporary, timeout=30)

    assert (checkout / "main.py").is_file()
    assert metadata["revision"] == "revision-123"
    assert metadata["branch"] == "default"
    archive_command = next(command for command in commands if "archive" in command)
    assert "--no-decode" in archive_command
    assert not any("update" in command for command in commands)


def test_svn_checkout_uses_export_and_skips_externals(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("svn+https://svn.example.net/repos/project/trunk")
    checkout = tmp_path / "source"
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if "info" in command:
            return SimpleNamespace(stdout=b"42")
        if "export" in command:
            Path(command[-1]).mkdir()
            (Path(command[-1]) / "main.py").write_text("print('svn')\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._svn_checkout(target, checkout, timeout=30)

    assert (checkout / "main.py").is_file()
    assert metadata["revision"] == "42"
    assert metadata["externals_fetched"] is False
    assert any("export" in command and "--ignore-externals" in command for command in commands)


def test_bzr_checkout_exports_remote_branch_without_working_copy_metadata(
    tmp_path: Path, monkeypatch,
):
    target = remote.parse_remote_target("bzr+https://code.example.net/team/project")
    checkout = tmp_path / "source"
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        Path(command[4]).mkdir()
        (Path(command[4]) / "main.py").write_text("print('bzr')\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote.shutil, "which", lambda name: "/usr/bin/brz")
    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._bzr_checkout(target, checkout, temporary, timeout=30)

    assert (checkout / "main.py").is_file()
    assert commands[0][1:4] == ["export", "--quiet", "--format=dir"]
    assert metadata["vcs"] == "bzr"


@pytest.mark.parametrize(
    ("backend", "metadata_directory", "command_prefix"),
    [
        ("darcs", "_darcs", ["darcs", "clone"]),
        ("jj", ".jj", ["jj", "git", "clone"]),
        ("pijul", ".pijul", ["pijul", "clone"]),
    ],
)
def test_native_vcs_checkouts_exclude_control_metadata(
    tmp_path: Path, monkeypatch, backend, metadata_directory, command_prefix,
):
    target_urls = {
        "darcs": "darcs+https://code.example.net/team/project",
        "jj": "jj+https://github.com/acme/project",
        "pijul": "pijul+https://nest.pijul.com/acme/project",
    }
    target = remote.parse_remote_target(target_urls[backend])
    checkout = tmp_path / "source"
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if backend == "jj" and command[1:3] == ["--repository", str(temporary / "jj-repository")]:
            return SimpleNamespace(stdout=b"jj-revision")
        repository = Path(command[-1])
        repository.mkdir(parents=True, exist_ok=True)
        (repository / metadata_directory).mkdir()
        (repository / "main.py").write_text("print('native')\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    if backend == "darcs":
        metadata = remote._darcs_checkout(target, checkout, temporary, timeout=30)
    elif backend == "jj":
        metadata = remote._jj_checkout(target, checkout, temporary, timeout=30)
    else:
        metadata = remote._pijul_checkout(target, checkout, temporary, timeout=30)

    assert commands[0][:len(command_prefix)] == command_prefix
    assert (checkout / "main.py").is_file()
    assert not (checkout / metadata_directory).exists()
    assert metadata["vcs"] == backend


def test_cvs_checkout_uses_noninteractive_native_checkout_and_strips_CVS_metadata(
    tmp_path: Path, monkeypatch,
):
    target = remote.parse_remote_target(
        "cvs+pserver://anonymous@cvs.example.net:2401/cvsroot/project"
    )
    checkout = tmp_path / "source"
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        repository = Path(command[6])
        repository.mkdir()
        (repository / "CVS").mkdir()
        (repository / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._cvs_checkout(target, checkout, temporary, timeout=30)

    assert commands[0][2] == ":pserver:anonymous@cvs.example.net:2401:/cvsroot"
    assert (checkout / "main.c").is_file()
    assert not (checkout / "CVS").exists()
    assert metadata["vcs"] == "cvs"


def test_p4_checkout_uses_depot_file_listing_and_read_only_print(
    tmp_path: Path, monkeypatch,
):
    target = remote.parse_remote_target(
        "p4+ssl://perforce.example.net:1666/depot/project"
    )
    checkout = tmp_path / "source"
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        assert kwargs["env"]["P4PORT"] == "ssl:perforce.example.net:1666"
        if "files" in command:
            return SimpleNamespace(
                stdout=(
                    b"... depotFile //depot/project/src/main.py\n"
                    b"... rev 3\n"
                    b"... change 17\n"
                )
            )
        if "print" in command:
            Path(command[4]).write_text("int main(void) { return 0; }\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._p4_checkout(target, checkout, timeout=30)

    assert (checkout / "src/main.py").is_file()
    assert metadata["revision"] == "17"
    assert metadata["tracked_file_count"] == 1
    assert commands[0][0:3] == ["p4", "-ztag", "files"]
    assert commands[1][0:3] == ["p4", "print", "-q"]



def test_fossil_checkout_clones_opens_without_sync_and_removes_checkout_metadata(
    tmp_path: Path, monkeypatch,
):
    target = remote.parse_remote_target("fossil+https://fossil.example.net/project")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    checkout = temporary / "source"
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        if command[1] == "clone":
            Path(command[-1]).write_bytes(b"fossil repository database")
        elif command[1] == "open":
            workdir = Path(command[command.index("--workdir") + 1])
            workdir.mkdir()
            (workdir / "_FOSSIL_").write_text("local metadata", encoding="utf-8")
            (workdir / "README.md").write_text("project source", encoding="utf-8")
        elif command[1] == "info":
            return SimpleNamespace(stdout=(
                b"project-name: project\n"
                b"checkout: 0123456789abcdef0123456789abcdef01234567 2026-11-05\n"
            ))
        elif command[1:3] == ["branch", "current"]:
            return SimpleNamespace(stdout=b"trunk\n")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._fossil_checkout(target, checkout, temporary, timeout=30)

    clone = next(command for command, _ in commands if command[1] == "clone")
    opened = next(command for command, _ in commands if command[1] == "open")
    assert clone[2] == "--once"
    assert "--nosync" in opened
    assert (checkout / "README.md").read_text(encoding="utf-8") == "project source"
    assert not (checkout / "_FOSSIL_").exists()
    assert metadata["vcs"] == "fossil"
    assert metadata["revision"] == "0123456789abcdef0123456789abcdef01234567"
    assert metadata["branch"] == "trunk"
    assert metadata["history_complete"] is False
    assert all(kwargs.get("cwd") is None or kwargs["cwd"] == checkout for _, kwargs in commands)


def test_remote_vcs_capabilities_reports_installed_native_clients(monkeypatch):
    installed = {
        "git": "/usr/bin/git",
        "brz": None,
        "bzr": "/usr/bin/bzr",
        "fossil": "/usr/bin/fossil",
    }
    monkeypatch.setattr(remote.shutil, "which", lambda name: installed.get(name))

    capabilities = remote.remote_vcs_capabilities()

    assert capabilities["git"]["available"] is True
    assert capabilities["bzr"]["available"] is True
    assert capabilities["bzr"]["executable"] == "/usr/bin/bzr"
    assert capabilities["fossil"]["available"] is True
    assert capabilities["pijul"]["available"] is False
