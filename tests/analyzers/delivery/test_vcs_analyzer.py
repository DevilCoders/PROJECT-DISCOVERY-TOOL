from pathlib import Path

from project_discovery.analyzers.delivery.vcs import VCSHostingAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, relative: str, content: str):
    path = tmp_path / Path(relative).name
    path.write_text(content, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Metadata")
    analyzer = VCSHostingAnalyzer()
    assert analyzer.supports(record), relative
    return analyzer.analyze(path, record)


def test_git_clone_remote_github_and_branch_head(tmp_path: Path):
    findings = _scan(
        tmp_path, ".git/config",
        '[core]\n repositoryformatversion = 0\n'
        '[remote "origin"]\n url = https://token:secret@github.com/acme/private.git?access_token=do-not-leak\n fetch = +refs/heads/*:refs/remotes/origin/*\n'
        '[branch "main"]\n remote = origin\n',
    )
    host = next(item for item in findings if item.category == "hosting_providers")
    joined = repr([item.to_dict() for item in findings])
    assert "GitHub" in host.title
    assert "github.com" in host.detail
    assert "secret" not in joined and "do-not-leak" not in joined
    assert "access_token" not in joined


def test_git_detached_head_and_shallow_clone(tmp_path: Path):
    detached = _scan(tmp_path, ".git/HEAD", "a" * 40 + "\n")
    shallow = _scan(tmp_path, ".git/shallow", "a" * 40 + "\n" + "b" * 40 + "\n")
    assert "detached" in detached[0].title.lower()
    assert "2 commit boundary" in shallow[0].detail


def test_git_file_indicates_worktree_or_submodule_metadata_pointer(tmp_path: Path):
    findings = _scan(tmp_path, ".git", "gitdir: ../.git/worktrees/checkout\n")
    assert "pointer" in findings[0].title.lower()


def test_gitmodules_and_lfs_are_detected(tmp_path: Path):
    submodules = _scan(
        tmp_path, ".gitmodules",
        '[submodule "vendor/core"]\n path = vendor/core\n url = git@bitbucket.org:acme/core.git\n',
    )
    lfs = _scan(tmp_path, ".gitattributes", "*.psd filter=lfs diff=lfs merge=lfs -text\n")
    assert "1 submodule" in submodules[0].detail
    assert "Bitbucket" in repr([item.to_dict() for item in submodules])
    assert "Git LFS" in lfs[0].title


def test_other_vcs_and_hosting_providers(tmp_path: Path):
    hg = _scan(
        tmp_path, ".hg/hgrc",
        "[paths]\ndefault = https://dev.azure.com/org/project/_git/repo\n",
    )
    assert "Azure Repos" in hg[0].detail
    svn = _scan(tmp_path, ".svn/format", "31\n")
    assert "Subversion" in svn[0].title
    bzr = _scan(
        tmp_path, ".bzr/branch/branch.conf",
        "parent_location = https://git-codecommit.us-east-1.amazonaws.com/v1/repos/demo\n",
    )
    assert "AWS CodeCommit" in bzr[0].detail


def test_fossil_checkout_marker_is_recognized(tmp_path: Path):
    findings = _scan(tmp_path, "_FOSSIL_", "local Fossil checkout metadata")
    assert len(findings) == 1
    assert "Fossil" in findings[0].title


def test_ci_and_cloud_delivery_providers(tmp_path: Path):
    checks = [
        (".github/workflows/ci.yml", "name: CI\njobs: {}\n", "GitHub Actions"),
        ("bitbucket-pipelines.yml", "pipelines: {}\n", "Bitbucket Pipelines"),
        ("azure-pipelines.yml", "trigger: none\n", "Azure Pipelines"),
        ("buildspec.yml", "version: 0.2\n", "AWS CodeBuild"),
        ("appspec.yml", "version: 0.0\n", "AWS CodeDeploy"),
        ("cdk.json", '{"app":"npx ts-node app.ts"}\n', "AWS CDK"),
    ]
    for relative, content, expected in checks:
        findings = _scan(tmp_path, relative, content)
        assert any(expected in item.title for item in findings), relative


def test_unrelated_file_is_not_claimed_as_vcs_or_ci():
    analyzer = VCSHostingAnalyzer()
    record = FileRecord("src/main.py", 12, ".py", "Python")
    assert analyzer.supports(record) is False


def test_scp_and_azure_provider_url_sanitization():
    from project_discovery.analyzers.delivery.vcs import _hosting_provider, _remote_host

    host, locator = _remote_host("git@ssh.dev.azure.com:v3/acme/robotics/platform")
    assert host == "ssh.dev.azure.com"
    assert _hosting_provider(host) == "Azure Repos"
    assert locator == "ssh://ssh.dev.azure.com/v3/acme/robotics/platform"

    host, locator = _remote_host("https://user:password@gitlab.com/group/project.git?token=secret")
    assert host == "gitlab.com"
    assert _hosting_provider(host) == "GitLab"
    assert "password" not in locator and "secret" not in locator


def test_scp_remote_query_and_fragment_are_redacted():
    from project_discovery.analyzers.delivery.vcs import _remote_host

    host, locator = _remote_host("git@github.com:acme/project.git?token=private#fragment")
    assert host == "github.com"
    assert locator == "ssh://github.com/acme/project.git"


def test_git_bare_repository_root_is_recognized(tmp_path: Path):
    (tmp_path / "objects").mkdir()
    (tmp_path / "config").write_text("[core]\n bare = true\n", encoding="utf-8")
    head = tmp_path / "HEAD"
    head.write_text("ref: refs/heads/main\n", encoding="utf-8")
    record = FileRecord("HEAD", head.stat().st_size, "", "Metadata")
    analyzer = VCSHostingAnalyzer()
    assert analyzer.supports(record)
    findings = analyzer.analyze(head, record)
    assert any("Git bare repository" in item.title for item in findings)


def test_pijul_config_and_malformed_git_config(tmp_path: Path):
    pijul = _scan(
        tmp_path, ".pijul/config.toml",
        '[remotes.origin]\nurl = "https://gitlab.com/group/project"\n',
    )
    assert any("Pijul repository configuration" in item.title for item in pijul)

    malformed = _scan(tmp_path, ".git/config", "[remote\n url = not-valid\n")
    assert malformed[0].confidence == "UNKNOWN"


def test_nested_git_checkout_is_recognized(tmp_path: Path):
    findings = _scan(
        tmp_path, "vendor/component/.git/config",
        '[remote "origin"]\nurl = https://github.com/acme/component.git\n',
    )
    assert any(item.category == "hosting_providers" and "GitHub" in item.title
               for item in findings)

def test_vcs_metadata_read_rejects_changed_inventory_identity(tmp_path: Path):
    path = tmp_path / "config"
    path.write_text('[remote "origin"]\nurl = https://github.com/acme/project.git\n', encoding="utf-8")
    observed = path.stat()
    record = FileRecord(
        ".git/config", observed.st_size, "", "Metadata",
        analysis_identity=(
            observed.st_dev, observed.st_ino, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns,
        ),
    )
    path.write_text('[remote "origin"]\nurl = https://attacker.invalid/replaced.git\n', encoding="utf-8")
    findings = VCSHostingAnalyzer().analyze(path, record)
    assert findings
    assert findings[0].confidence == "UNKNOWN"
    assert "identity changed" in findings[0].detail.lower()
    assert all("attacker.invalid" not in item.detail for item in findings)



def _scan_tree(tmp_path: Path, files: dict[str, str], relative: str):
    """Write a whole layout, then analyze one of its files (sibling checks need the tree)."""
    for name, content in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    path = tmp_path / relative
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Metadata")
    analyzer = VCSHostingAnalyzer()
    if not analyzer.supports(record):
        return None
    return analyzer.analyze(path, record)


def test_every_vcs_control_directory_gives_one_marker_without_optional_files(tmp_path: Path):
    # Regression: Mercurial was reported only with .hg/hgrc, Darcs only with
    # _darcs/prefs/repos and Jujutsu only with .jj/repo/config.toml, all optional files:
    # "hg init", "darcs init" and ordinary jj repositories produced no finding at all.
    layouts = {
        "Mercurial": ({"hg/.hg/requires": "revlogv1\nstore\nfncache\n",
                       "hg/.hg/store/requires": "revlog-compression-zstd\n"}, "hg/.hg/requires"),
        "Darcs": ({"darcs/_darcs/format": "hashed\ndarcs-2\n"}, "darcs/_darcs/format"),
        "Jujutsu": ({"jj/.jj/repo/store/type": "git"}, "jj/.jj/repo/store/type"),
        "Bazaar": ({"bzr/.bzr/branch-format": "Bazaar-NG meta directory, format 1\n"}, "bzr/.bzr/branch-format"),
        "Pijul": ({"pijul/.pijul/pristine/db": "\0binary"}, "pijul/.pijul/pristine/db"),
        "Subversion": ({"svn/.svn/wc.db": "SQLite format 3\0", "svn/.svn/entries": "12\n"}, "svn/.svn/wc.db"),
        "CVS": ({"cvs/CVS/Root": ":pserver:anonymous@cvs.example.net:/cvsroot\n"}, "cvs/CVS/Root"),
    }
    for vcs, (files, marker) in layouts.items():
        findings = _scan_tree(tmp_path, files, marker)
        assert findings and findings[0].confidence == "CONFIRMED", vcs
        assert findings[0].title == f"{vcs} repository metadata: {marker.split('/')[0]}", vcs
    hg = _scan_tree(tmp_path, {}, "hg/.hg/requires")
    assert "requirements: revlogv1, store, fncache" in hg[0].evidence
    assert "cvs.example.net" in _scan_tree(tmp_path, {}, "cvs/CVS/Root")[0].detail
    # One finding per control directory: the share-safe store requirements and the 1.7
    # entries file next to wc.db add none.
    assert _scan_tree(tmp_path, {}, "hg/.hg/store/requires") is None
    assert _scan_tree(tmp_path, {}, "svn/.svn/entries") == []


def test_jujutsu_git_backend_remotes_and_shared_workspaces(tmp_path: Path):
    findings = _scan_tree(
        tmp_path, {".jj/repo/store/git/config": '[remote "origin"]\n url = https://gitlab.com/acme/project.git\n'},
        ".jj/repo/store/git/config",
    )
    assert any(item.category == "hosting_providers" and "GitLab" in item.title for item in findings)
    assert any(item.title.startswith("Jujutsu Git backend configuration") for item in findings)
    pointer = _scan_tree(tmp_path, {"second/.jj/repo": "../../.jj/repo"}, "second/.jj/repo")
    assert "shared with another workspace" in pointer[0].detail


def test_fossil_checkout_databases_under_every_name(tmp_path: Path):
    for name in ("_FOSSIL_", ".fslckout", ".fos"):
        findings = _scan_tree(tmp_path, {f"checkout/{name}": "SQLite format 3\0"}, f"checkout/{name}")
        assert len(findings) == 1 and "Fossil" in findings[0].title, name


def test_bare_repository_is_recognized_at_any_depth(tmp_path: Path):
    (tmp_path / "mirrors" / "tool.git" / "objects").mkdir(parents=True)
    findings = _scan_tree(
        tmp_path, {"mirrors/tool.git/HEAD": "ref: refs/heads/main\n",
                   "mirrors/tool.git/config": "[core]\n bare = true\n"},
        "mirrors/tool.git/HEAD",
    )
    assert findings[0].title == "Git bare repository metadata: mirrors/tool.git"
    # A HEAD file that is not part of a repository is not claimed.
    assert _scan_tree(tmp_path, {"docs/HEAD": "notes\n"}, "docs/HEAD") == []


def test_cvs_and_old_subversion_report_a_working_copy_once(tmp_path: Path):
    # Both keep a control directory in every directory of a working copy.
    files = {
        "cvs/CVS/Root": ":pserver:anonymous@cvs.example.net:/cvsroot\n",
        "cvs/src/CVS/Root": ":pserver:anonymous@cvs.example.net:/cvsroot\n",
        "svn/.svn/entries": "10\n",
        "svn/lib/.svn/entries": "10\n",
    }
    assert _scan_tree(tmp_path, files, "cvs/CVS/Root")
    assert _scan_tree(tmp_path, files, "cvs/src/CVS/Root") == []
    assert _scan_tree(tmp_path, files, "svn/.svn/entries")
    assert _scan_tree(tmp_path, files, "svn/lib/.svn/entries") == []


def test_files_without_a_handler_are_not_claimed():
    analyzer = VCSHostingAnalyzer()
    for relative in (".git/commondir", ".git/description", ".bzr/branch/last-revision",
                     "CVS/Repository", "CVS/Entries", ".hg/store/requires", ".jj/repo/op_store/type"):
        assert analyzer.supports(FileRecord(relative, 1, "", "Metadata")) is False, relative
    assert analyzer.supports(FileRecord(".git/worktrees/feature/gitdir", 1, "", "Metadata"))


def test_git_config_valueless_keys_remote_heads_nested_files_and_codeberg(tmp_path: Path):
    # Regressions: a valueless Git boolean ("logallrefupdates") made the whole config one
    # UNKNOWN read error; refs/remotes/origin/HEAD was a second checkout HEAD; nested
    # .gitmodules were ignored; codeberg.org was "Self-hosted or unclassified".
    findings = _scan(tmp_path, ".git/config", (
        "[core]\n\tlogallrefupdates\n[remote \"origin\"]\n\turl = https://codeberg.org/acme/app.git\n"
    ))
    host = next(item for item in findings if item.category == "hosting_providers")
    assert host.title == "Git remote provider: Forgejo"
    remote_head = _scan(tmp_path, ".git/refs/remotes/origin/HEAD", "ref: refs/remotes/origin/main\n")
    assert remote_head[0].title.startswith("Git remote default branch")
    nested = _scan(tmp_path, "vendor/lib/.gitmodules", '[submodule "x"]\n\tpath = x\n\turl = https://github.com/a/x\n')
    assert "1 submodule" in nested[0].detail


def test_multiple_remotes_and_linked_worktrees(tmp_path: Path):
    secret = "hunter2" + "-remote"
    config = (
        '[core]\n\trepositoryformatversion = 0\n'
        '[remote "origin"]\n\turl = https://github.com/acme/app.git\n'
        '[remote "upstream"]\n\turl = git@gitlab.com:upstream/app.git\n'
        '[remote "mirror"]\n\turl = ssh://git@bitbucket.org/acme/app.git\n'
        f'[remote "backup"]\n\turl = https://deployer-x9:{secret}@git.example.com/acme/app.git?token=q8Z4#part-7Q2\n'
        '[branch "main"]\n\tremote = origin\n[branch "dev"]\n\tremote = upstream\n'
    )
    findings = _scan_tree(tmp_path, {".git/config": config}, ".git/config")
    # One provider finding per remote, and one configuration finding that counts them.
    assert sorted(item.title for item in findings if item.category == "hosting_providers") == [
        "Git remote provider: Bitbucket", "Git remote provider: GitHub", "Git remote provider: GitLab",
        "Git remote provider: Self-hosted or unclassified"]
    summary = next(item for item in findings if item.title.startswith("Git repository configuration"))
    assert "Detected 4 remote(s) and 2 local branch configuration section(s)" in summary.detail
    backup = next(item for item in findings if "'backup'" in item.detail)
    assert "sanitized locator: https://git.example.com/acme/app.git." in backup.detail
    upstream = next(item for item in findings if "'upstream'" in item.detail)
    assert "ssh://gitlab.com/upstream/app.git" in upstream.detail
    text = repr([item.to_dict() for item in findings])
    for private in (secret, "deployer-x9", "q8Z4", "part-7Q2"):
        assert private not in text, private
    # A linked worktree is named; the path its gitdir file points to is not followed or reported.
    worktree = _scan_tree(tmp_path, {".git/worktrees/feature/gitdir": "/home/alice/src/app-feature/.git\n"},
                          ".git/worktrees/feature/gitdir")
    assert [item.title for item in worktree] == ["Git linked worktree: feature"]
    assert "alice" not in repr(worktree[0].to_dict())
