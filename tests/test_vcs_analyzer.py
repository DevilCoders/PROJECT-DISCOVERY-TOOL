from pathlib import Path

from project_discovery.analyzers.vcs_analyzer import VCSHostingAnalyzer
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
    from project_discovery.analyzers.vcs_analyzer import _hosting_provider, _remote_host

    host, locator = _remote_host("git@ssh.dev.azure.com:v3/acme/robotics/platform")
    assert host == "ssh.dev.azure.com"
    assert _hosting_provider(host) == "Azure Repos"
    assert locator == "ssh://ssh.dev.azure.com/v3/acme/robotics/platform"

    host, locator = _remote_host("https://user:password@gitlab.com/group/project.git?token=secret")
    assert host == "gitlab.com"
    assert _hosting_provider(host) == "GitLab"
    assert "password" not in locator and "secret" not in locator


def test_scp_remote_query_and_fragment_are_redacted():
    from project_discovery.analyzers.vcs_analyzer import _remote_host

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

