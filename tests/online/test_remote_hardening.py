"""Regression tests for the online-mode security audit of remote.py.

Each test pins one fixed defect or hardening property: URL/option injection, credential and
control-sequence redaction, process-tree termination, bounded output, Windows-unsafe paths,
materialization budgets, the extraction watchdog, temporary-tree cleanup and the per-backend
client invocations.
"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from project_discovery.online import repositories as remote
from project_discovery.online.repositories import RemoteLimits, RemoteScanError


def _symlinks_supported(directory: Path) -> bool:
    probe = directory / ".symlink-probe"
    try:
        probe.symlink_to("target")
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "git@-oProxyCommand=calc:repo.git",
        "-oProxyCommand=calc@host:repo.git",
        "git@host:-uhelp",
        "ssh://-oProxyCommand=calc/repo.git",
        "ssh://-user@example.net/repo.git",
        "hg+ssh://-oProxyCommand=calc/repo",
        "cvs+pserver://cvs.example.net/cvsroot/-project",
        "p4+ssl://perforce.example.net:1666/depot/-project",
        "https://github.com/acme/project name",
        "https://github.com/acme/pro\tject",
    ],
)
def test_remote_target_rejects_option_injection_and_whitespace(url: str):
    with pytest.raises(RemoteScanError):
        remote.parse_remote_target(url)


def test_svn_and_bzr_keep_their_ssh_tunnel_schemes():
    svn = remote.parse_remote_target("svn+ssh://svn.example.net/repos/project/trunk")
    bzr = remote.parse_remote_target("bzr+ssh://bzr.example.net/team/project")
    assert svn.vcs == "svn" and svn.clone_url == "svn+ssh://svn.example.net/repos/project/trunk"
    assert bzr.vcs == "bzr" and bzr.clone_url == "bzr+ssh://bzr.example.net/team/project"
    assert not svn.insecure_transport and not bzr.insecure_transport
    # Other backends still receive plain ssh:// URLs.
    assert remote.parse_remote_target("hg+ssh://hg.example.net/repo").clone_url == "ssh://hg.example.net/repo"


def test_transport_flags_and_policy():
    secure = remote.parse_remote_target("https://github.com/acme/widgets")
    plain = remote.parse_remote_target("git://git.example.net/project.git")
    assert secure.transport == "https" and not secure.insecure_transport
    assert plain.transport == "git" and plain.insecure_transport
    remote.check_transport_policy(secure, allow_insecure=False)
    remote.check_transport_policy(plain, allow_insecure=True)
    with pytest.raises(RemoteScanError, match="--allow-insecure-transport"):
        remote.check_transport_policy(plain, allow_insecure=False)


def test_output_names_are_stable_and_refs_create_distinct_targets():
    plain = remote.parse_remote_target("https://github.com/acme/widgets")
    expected = hashlib.sha256(b"git|https://github.com/acme/widgets").hexdigest()[:10]
    assert plain.identity == expected
    assert plain.output_name == f"widgets-{expected}"
    tagged = remote.parse_remote_target("https://github.com/acme/widgets", ref="v1.2.0")
    assert tagged.ref == "v1.2.0"
    assert tagged.identity != plain.identity


@pytest.mark.parametrize(
    ("ref", "vcs"),
    [
        ("-upload-pack=evil", "git"),
        ("main..other", "git"),
        ("feature/", "git"),
        ("release.lock", "git"),
        ("HEAD@{1}", "git"),
        ("v1 2", "git"),
        ("trunk", "svn"),
        ("main", "jj"),
    ],
)
def test_invalid_or_unsupported_refs_are_rejected(ref: str, vcs: str):
    url = {
        "git": "https://github.com/acme/widgets",
        "svn": "svn+https://svn.example.net/repos/project",
        "jj": "jj+https://github.com/acme/widgets",
    }[vcs]
    with pytest.raises(RemoteScanError):
        remote.parse_remote_target(url, ref=ref)


def test_valid_refs_per_backend():
    assert remote.parse_remote_target("https://github.com/a/b", ref="release/2.x").ref == "release/2.x"
    sha = "a" * 40
    assert remote.parse_remote_target("https://github.com/a/b", ref=sha).ref == sha
    assert remote.parse_remote_target("svn+https://svn.example.net/r/p", ref="1234").ref == "1234"
    assert remote.parse_remote_target("hg+https://hg.example.net/p", ref="stable").ref == "stable"


def test_url_file_line_options_and_comments(tmp_path: Path):
    url_file = tmp_path / "repos.txt"
    url_file.write_text(
        "https://github.com/acme/widgets ref=v1.0   # pinned release\n"
        "https://code.example.net/team/project vcs=hg\n"
        "https://github.com/acme/widgets\n",
        encoding="utf-8",
    )
    targets = remote.load_remote_targets(url_file, ref=None)
    assert [(item.vcs, item.ref) for item in targets] == [("git", "v1.0"), ("hg", None), ("git", None)]
    # A command-line --ref is the default for lines without their own ref=.
    defaulted = remote.load_remote_targets(url_file, ref="main")
    assert [item.ref for item in defaulted] == ["v1.0", "main", "main"]


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("https://github.com/acme/widgets branch=main", "Unsupported URL option"),
        ("https://github.com/acme/widgets ref=a ref=b", "given twice"),
        ("https://github.com/acme/widgets vcs=cvsnt", "not one of"),
        ("https://github.com/acme/widgets ref=", "Unsupported URL option"),
    ],
)
def test_url_file_rejects_bad_line_options_with_line_number(tmp_path: Path, line: str, message: str):
    url_file = tmp_path / "repos.txt"
    url_file.write_text("# header\n" + line + "\n", encoding="utf-8")
    with pytest.raises(RemoteScanError, match=r"repos\.txt:2: .*" + message):
        remote.load_remote_targets(url_file)


# ---------------------------------------------------------------------------
# Output sanitization and hardened execution
# ---------------------------------------------------------------------------

def test_client_output_is_stripped_of_control_sequences_and_credentials():
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    raw = (
        "\x1b[31mfatal:\x1b[0m unable to access "
        f"'https://x-access-token:{token}@github.com/acme/private.git/'\x07\r\n"
        "remote: \x1b]0;pwned title\x07Repository not found.\x00"
    ).encode()
    cleaned = remote.sanitize_client_output(raw)
    assert token not in cleaned
    assert "x-access-token" not in cleaned
    assert "\x1b" not in cleaned and "\x07" not in cleaned and "\x00" not in cleaned
    assert "https://<redacted>@github.com/acme/private.git" in cleaned
    assert "Repository not found." in cleaned
    assert len(remote.sanitize_client_output("x" * 5_000)) < 1_600


def test_run_reports_missing_client():
    with pytest.raises(RemoteScanError, match="requires the 'pdt-no-such-vcs-client' client"):
        remote._run(
            ["pdt-no-such-vcs-client", "--version"], timeout=5,
            env=os.environ.copy(), label="Probe",
        )


def test_run_failure_message_is_sanitized():
    script = (
        "import sys\n"
        "sys.stderr.write('\\x1b[1mfatal\\x1b[0m: https://user:hunter2@example.net/repo failed\\n')\n"
        "sys.exit(7)\n"
    )
    with pytest.raises(RemoteScanError) as error:
        remote._run([sys.executable, "-c", script], timeout=30, env=os.environ.copy(), label="Probe")
    message = str(error.value)
    assert "exit code 7" in message
    assert "hunter2" not in message and "\x1b" not in message
    assert "https://<redacted>@example.net/repo" in message


def test_run_bounds_captured_output():
    script = "import sys; sys.stdout.write('x' * 3_000_000)"
    with pytest.raises(RemoteScanError, match="more than 1,000,000 bytes"):
        remote._run(
            [sys.executable, "-c", script], timeout=60, env=os.environ.copy(),
            label="Probe", max_output_bytes=1_000_000,
        )


def test_run_returns_output_of_successful_command():
    result = remote._run(
        [sys.executable, "-c", "print('revision-abc')"], timeout=30,
        env=os.environ.copy(), label="Probe",
    )
    assert result.returncode == 0
    assert result.stdout.strip() == b"revision-abc"


def test_run_kills_the_client_and_its_children_on_timeout(tmp_path: Path):
    heartbeat = tmp_path / "grandchild-heartbeat.txt"
    grandchild = (
        "import pathlib, time\n"
        f"path = pathlib.Path({str(heartbeat)!r})\n"
        "while True:\n"
        "    path.write_text(repr(time.time()))\n"
        "    time.sleep(0.05)\n"
    )
    parent = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
        "time.sleep(120)\n"
    )
    started = time.monotonic()
    with pytest.raises(RemoteScanError, match="2-second remote operation timeout"):
        remote._run([sys.executable, "-c", parent], timeout=2, env=os.environ.copy(), label="Probe")
    assert time.monotonic() - started < 40
    deadline = time.monotonic() + 10
    while not heartbeat.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert heartbeat.exists(), "grandchild never started"
    time.sleep(0.6)
    first = heartbeat.read_text()
    time.sleep(0.6)
    assert heartbeat.read_text() == first, "the client's child process survived the timeout"


def test_run_stops_when_the_disk_guard_trips(monkeypatch):
    monkeypatch.setattr(remote, "_free_bytes", lambda path: 1)
    started = time.monotonic()
    with pytest.raises(RemoteScanError, match="free disk space"):
        remote._run(
            [sys.executable, "-c", "import time; time.sleep(60)"], timeout=60,
            env=os.environ.copy(), label="Probe", disk_guard=(Path.cwd(), 1024),
        )
    assert time.monotonic() - started < 30


def test_run_kills_the_client_on_keyboard_interrupt(monkeypatch):
    killed = []

    class InterruptedProcess:
        pid = None
        returncode = None

        def __init__(self, *args, **kwargs):
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return -9

        def poll(self):
            return self.returncode

        def kill(self):
            killed.append(True)
            self.returncode = -9

    monkeypatch.setattr(remote.subprocess, "Popen", InterruptedProcess)
    with pytest.raises(KeyboardInterrupt):
        remote._run(["git", "clone"], timeout=60, env={}, label="Git clone")
    assert killed


def test_vcs_environment_is_non_interactive_and_drops_repository_overrides(monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/elsewhere")
    environment = remote._vcs_environment(EXTRA="1")
    assert "GIT_DIR" not in environment and "GIT_WORK_TREE" not in environment
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GCM_INTERACTIVE"] == "never"
    assert environment["SSH_ASKPASS_REQUIRE"] == "never"
    assert environment["EXTRA"] == "1"


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name", ["CON", "con.txt", "aux.c", "NUL.tar.gz", "COM1", "lpt9.log", "CONIN$",
             "a:b", "name.", "name ", "bad?", "pipe|name", 'quote"d'],
)
def test_windows_unsafe_names_are_refused_on_windows_only(name: str):
    assert remote._unsafe_component(name, windows=True) is not None
    if name not in {"a:b", "bad?", "pipe|name", 'quote"d'} or os.name != "nt":
        # POSIX filesystems store these names faithfully (the Linux kernel has aux.c).
        assert remote._unsafe_component(name, windows=False) is None


@pytest.mark.parametrize("relative", ["a//b", "a/./b", "dir/", "./x", "a/../b"])
def test_safe_destination_rejects_non_canonical_paths(tmp_path: Path, relative: str):
    with pytest.raises(RemoteScanError):
        remote._safe_destination(tmp_path, relative.encode())


def test_safe_destination_rejects_windows_device_names_when_on_windows(tmp_path: Path):
    with pytest.raises(RemoteScanError, match="reserved Windows device name"):
        remote._safe_destination(tmp_path, b"drivers/i2c/aux.c", windows=True)
    assert remote._safe_destination(tmp_path, b"drivers/i2c/aux.c", windows=False).name == "aux.c"


def test_safe_destination_rejects_undecodable_names_cleanly(tmp_path: Path, monkeypatch):
    def failing_decode(value):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(remote.os, "fsdecode", failing_decode)
    with pytest.raises(RemoteScanError, match="file-name encoding"):
        remote._safe_destination(tmp_path, b"\xff.py")


# ---------------------------------------------------------------------------
# Git tree extraction
# ---------------------------------------------------------------------------

class _RecordingStdin(io.BytesIO):
    """cat-file request stream that keeps what was written after the extractor closes it."""

    requests = b""

    def close(self):
        if not self.closed:
            self.requests = self.getvalue()
        super().close()

    def getvalue(self):
        return self.requests if self.closed else super().getvalue()


class _FakeGitProcess:
    def __init__(self, *, stdout):
        self.stdin = _RecordingStdin()
        self.stdout = stdout if not isinstance(stdout, bytes) else io.BytesIO(stdout)
        self.stderr = io.BytesIO()
        self.returncode = None
        self.killed = False

    def wait(self, timeout=None):
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9
        closer = getattr(self.stdout, "unblock", None)
        if closer is not None:
            closer()


def _install_fake_git(monkeypatch, tree_stdout, blob_stdout):
    created = {}

    def fake_popen(command, **kwargs):
        if "ls-tree" in command:
            created["tree"] = _FakeGitProcess(stdout=tree_stdout)
            created["tree_command"] = command
            return created["tree"]
        if "cat-file" in command:
            created["blobs"] = _FakeGitProcess(stdout=blob_stdout)
            return created["blobs"]
        raise AssertionError(command)

    monkeypatch.setattr(remote.subprocess, "Popen", fake_popen)
    return created


def test_git_extraction_lists_sizes_and_enforces_the_materialization_budget(tmp_path: Path, monkeypatch):
    first, second, third = b"1" * 40, b"2" * 40, b"3" * 40
    tree = (
        b"100644 blob " + first + b"      11\tsrc/a.py\0"
        + b"100644 blob " + second + b"      11\tsrc/b.py\0"
        + b"100644 blob " + third + b"       5\tsrc/c.py\0"
    )
    # Only the blobs that fit the 16-byte budget are requested: a.py (11) and c.py (5).
    blobs = first + b" blob 11\nprint('a')\n\n" + third + b" blob 5\nx = 1\n"
    created = _install_fake_git(monkeypatch, tree, blobs)
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    counts = remote._extract_git_tree(
        checkout, {}, timeout=30, limits=RemoteLimits(max_bytes=16, max_files=10),
    )

    assert "-l" in created["tree_command"]
    assert (checkout / "src" / "a.py").read_bytes() == b"print('a')\n"
    assert not (checkout / "src" / "b.py").exists()
    assert (checkout / "src" / "c.py").read_bytes() == b"x = 1"
    assert counts["tracked_file_count"] == 2
    assert counts["materialized_bytes"] == 16
    assert counts["budget_omitted_file_count"] == 1
    assert counts["budget_omitted_bytes"] == 11
    assert created["blobs"].stdin.getvalue() == first + b"\n" + third + b"\n"


def test_git_extraction_counts_missing_blobs_and_windows_unsafe_paths(tmp_path: Path, monkeypatch):
    good, missing, device = b"a" * 40, b"b" * 40, b"c" * 40
    tree = (
        b"100644 blob " + device + b"       4\tdrivers/aux.c\0"
        + b"100644 blob " + good + b"       3\tmain.py\0"
        + b"100644 blob " + missing + b"       3\tlost.py\0"
    )
    blobs = good + b" blob 3\nok\n\n" + missing + b" missing\n"
    created = _install_fake_git(monkeypatch, tree, blobs)
    monkeypatch.setattr(remote, "_WINDOWS", True)
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    counts = remote._extract_git_tree(checkout, {}, timeout=30)

    assert (checkout / "main.py").read_bytes() == b"ok\n"
    assert not (checkout / "lost.py").exists()
    assert not (checkout / "drivers" / "aux.c").exists()
    assert counts["omitted_tree_path_count"] == 1
    assert counts["missing_blob_count"] == 1
    # The device-named blob was never requested.
    assert device not in created["blobs"].stdin.getvalue()


class _BlockingStream:
    """A pipe whose reader blocks until the owning process is killed."""

    def __init__(self):
        self._released = threading.Event()

    def unblock(self):
        self._released.set()

    def read(self, size=-1):
        self._released.wait(30)
        return b""

    def readline(self, size=-1):
        return self.read(size)


def test_git_extraction_watchdog_kills_a_stalled_listing(tmp_path: Path, monkeypatch):
    created = _install_fake_git(monkeypatch, _BlockingStream(), b"")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    started = time.monotonic()
    with pytest.raises(RemoteScanError, match="1-second remote operation timeout"):
        remote._extract_git_tree(checkout, {}, timeout=1)
    assert time.monotonic() - started < 20
    assert created["tree"].killed and created["blobs"].killed


def test_git_extraction_kills_both_processes_on_keyboard_interrupt(tmp_path: Path, monkeypatch):
    class InterruptingStream:
        def read(self, size=-1):
            raise KeyboardInterrupt

    created = _install_fake_git(monkeypatch, InterruptingStream(), b"")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    with pytest.raises(KeyboardInterrupt):
        remote._extract_git_tree(checkout, {}, timeout=30)
    assert created["tree"].killed and created["blobs"].killed


def test_symlink_targets_that_escape_are_refused():
    assert remote._safe_symlink_target(b"src/link", b"../README.md") == "../README.md"
    assert remote._safe_symlink_target(b"link", b"../outside") is None
    assert remote._safe_symlink_target(b"link", b"/etc/passwd") is None
    assert remote._safe_symlink_target(b"link", b"C:\\Windows") is None
    assert remote._safe_symlink_target(b"link", b"") is None
    assert remote._safe_symlink_target(b"link", b"x" * 5000) is None


# ---------------------------------------------------------------------------
# Git adapter commands
# ---------------------------------------------------------------------------

def _fake_git_run(commands, *, revision=b"abc123\n"):
    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        if "clone" in command or "init" in command:
            checkout_path = Path(command[-1])
            checkout_path.mkdir(exist_ok=True)
            git_dir = Path(command[command.index("--separate-git-dir") + 1])
            (checkout_path / ".git").write_text(f"gitdir: {git_dir}\n", encoding="utf-8")
        if "rev-parse" in command:
            return SimpleNamespace(stdout=revision)
        if "symbolic-ref" in command:
            return SimpleNamespace(stdout=b"main\n")
        return SimpleNamespace(stdout=b"")
    return fake_run


_EMPTY_COUNTS = {
    "tracked_file_count": 0, "materialized_symlink_count": 0, "omitted_symlink_count": 0,
    "submodule_count": 0, "submodule_paths_sample": [], "git_lfs_pointer_count": 0,
    "omitted_tree_path_count": 0,
}


def test_git_clone_pins_the_transport_and_selects_a_branch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    target = remote.parse_remote_target("https://github.com/acme/platform", ref="release/2.x")
    commands = []
    seen = {}
    monkeypatch.setattr(remote, "_run", _fake_git_run(commands))
    monkeypatch.setattr(
        remote, "_extract_git_tree",
        lambda checkout, env, **kwargs: seen.update(env=env, **kwargs) or dict(_EMPTY_COUNTS),
    )
    metadata = remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)

    clone, kwargs = commands[0]
    assert clone[clone.index("--branch") + 1] == "release/2.x"
    assert clone[clone.index("--") + 1] == "https://github.com/acme/platform"
    assert "protocol.https.allow=always" in clone and "protocol.allow=never" in clone
    assert kwargs["env"]["GIT_ALLOW_PROTOCOL"] == "https"
    assert "GIT_DIR" not in kwargs["env"]
    assert kwargs["disk_guard"][0] == tmp_path
    assert seen["tree_ish"] == "HEAD"
    assert metadata["branch"] == "main"
    assert metadata["coverage"] == []


def test_git_commit_ref_uses_init_and_fetch_of_that_commit(tmp_path: Path, monkeypatch):
    sha = "0123456789abcdef0123456789abcdef01234567"
    target = remote.parse_remote_target("https://github.com/acme/platform", ref=sha)
    commands = []
    seen = {}
    monkeypatch.setattr(remote, "_run", _fake_git_run(commands, revision=sha.encode() + b"\n"))
    monkeypatch.setattr(
        remote, "_extract_git_tree",
        lambda checkout, env, **kwargs: seen.update(kwargs) or dict(_EMPTY_COUNTS),
    )
    metadata = remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)

    assert commands[0][0][:2] == ["git", "init"]
    fetch = commands[1][0]
    assert "fetch" in fetch and fetch[-1] == sha and fetch[-2] == "https://github.com/acme/platform"
    assert seen["tree_ish"] == "FETCH_HEAD"
    assert metadata["revision"] == sha
    assert metadata["branch"] is None


def test_git_commit_ref_rejects_a_different_fetched_commit(tmp_path: Path, monkeypatch):
    sha = "0123456789abcdef0123456789abcdef01234567"
    target = remote.parse_remote_target("https://github.com/acme/platform", ref=sha)
    monkeypatch.setattr(remote, "_run", _fake_git_run([], revision=b"f" * 40 + b"\n"))
    monkeypatch.setattr(remote, "_extract_git_tree", lambda *a, **k: dict(_EMPTY_COUNTS))
    with pytest.raises(RemoteScanError, match="different commit"):
        remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)


def test_git_ssh_clone_fails_fast_instead_of_prompting(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.delenv("GIT_SSH", raising=False)
    target = remote.parse_remote_target("git@github.com:acme/platform.git")
    commands = []
    monkeypatch.setattr(remote, "_run", _fake_git_run(commands))
    monkeypatch.setattr(remote, "_extract_git_tree", lambda *a, **k: dict(_EMPTY_COUNTS))
    remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)

    lookup, lookup_kwargs = commands[0]
    assert lookup == ["git", "config", "--get", "core.sshCommand"]
    assert lookup_kwargs["cwd"] == tmp_path
    clone = commands[1][0]
    assert "core.sshCommand=ssh -o BatchMode=yes" in clone
    assert commands[1][1]["env"]["GIT_ALLOW_PROTOCOL"] == "ssh"


def test_git_ssh_clone_respects_a_configured_ssh_command(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i ~/.ssh/deploy")
    target = remote.parse_remote_target("ssh://git@github.com/acme/platform.git")
    commands = []
    monkeypatch.setattr(remote, "_run", _fake_git_run(commands))
    monkeypatch.setattr(remote, "_extract_git_tree", lambda *a, **k: dict(_EMPTY_COUNTS))
    remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)
    assert all("core.sshCommand=ssh -o BatchMode=yes" not in command for command, _ in commands)


def test_empty_git_repository_is_reported_clearly(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("https://github.com/acme/empty")
    monkeypatch.setattr(remote, "_run", _fake_git_run([], revision=b""))
    monkeypatch.setattr(remote, "_extract_git_tree", lambda *a, **k: dict(_EMPTY_COUNTS))
    with pytest.raises(RemoteScanError, match="no commits"):
        remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)


def test_git_coverage_separates_missing_content_from_notes(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("https://github.com/acme/platform")
    monkeypatch.setattr(remote, "_run", _fake_git_run([]))
    monkeypatch.setattr(remote, "_extract_git_tree", lambda *a, **k: {
        **_EMPTY_COUNTS, "submodule_count": 2, "omitted_tree_path_count": 3,
        "budget_omitted_file_count": 4, "budget_omitted_bytes": 400,
    })
    metadata = remote._git_checkout(target, tmp_path / "source", tmp_path / "git", tmp_path, timeout=30)
    by_kind = {item["kind"]: item for item in metadata["coverage"]}
    assert by_kind["git_submodules_not_fetched"]["incomplete"] is False
    assert by_kind["paths_not_materialized"]["incomplete"] is True
    assert by_kind["materialization_budget"]["count"] == 4


# ---------------------------------------------------------------------------
# remote_checkout lifecycle
# ---------------------------------------------------------------------------

def _fake_materializer(captured):
    def fake_checkout(_target, checkout, _git_dir, temporary, *, timeout, **_kwargs):
        checkout.mkdir()
        (checkout / "main.py").write_text("print('ok')\n", encoding="utf-8")
        captured["path"] = checkout
        captured["temporary"] = temporary
        return {"mode": "remote", "vcs": "git", "coverage": [], "warnings": ["note"]}
    return fake_checkout


def test_scan_errors_inside_the_checkout_are_not_relabelled(tmp_path: Path, monkeypatch):
    captured = {}
    monkeypatch.setattr(remote, "_git_checkout", _fake_materializer(captured))
    target = remote.parse_remote_target("https://github.com/acme/platform")
    with pytest.raises(FileNotFoundError, match="vulnerability database"):
        with remote.remote_checkout(target, timeout=15, workdir=tmp_path / "work"):
            raise FileNotFoundError("vulnerability database missing")
    assert not captured["temporary"].exists()


def test_keyboard_interrupt_inside_the_checkout_still_cleans_up(tmp_path: Path, monkeypatch):
    captured = {}
    monkeypatch.setattr(remote, "_git_checkout", _fake_materializer(captured))
    target = remote.parse_remote_target("https://github.com/acme/platform")
    with pytest.raises(KeyboardInterrupt):
        with remote.remote_checkout(target, timeout=15, workdir=tmp_path / "work"):
            raise KeyboardInterrupt
    assert not captured["temporary"].exists()


def test_materialization_errors_are_wrapped_and_cleaned_up(tmp_path: Path, monkeypatch):
    created = {}

    def failing_checkout(_target, checkout, _git_dir, temporary, *, timeout, **_kwargs):
        created["temporary"] = temporary
        (temporary / "partial").write_text("x", encoding="utf-8")
        raise PermissionError("denied")

    monkeypatch.setattr(remote, "_git_checkout", failing_checkout)
    target = remote.parse_remote_target("https://github.com/acme/platform")
    with pytest.raises(RemoteScanError, match="Remote checkout failed for GitHub repository 'platform'"):
        with remote.remote_checkout(target, timeout=15, workdir=tmp_path / "work"):
            pass
    assert not created["temporary"].exists()


def test_remote_checkout_uses_workdir_and_finalizes_metadata(tmp_path: Path, monkeypatch):
    captured = {}
    monkeypatch.setattr(remote, "_git_checkout", _fake_materializer(captured))
    target = remote.parse_remote_target("https://github.com/acme/platform", ref="main")
    workdir = tmp_path / "work"
    with remote.remote_checkout(target, timeout=15, workdir=workdir) as checkout:
        assert checkout.path.parent.parent == workdir.resolve()
        metadata = checkout.metadata
    assert metadata["acquisition"] == "download"
    assert metadata["ref"] == "main"
    assert metadata["url"] == "https://github.com/acme/platform"
    assert metadata["transport"] == "https" and metadata["transport_insecure"] is False
    assert metadata["coverage_gaps"] == []
    assert metadata["acquisition_seconds"] >= 0
    assert metadata["warnings"] == ["note"]
    assert list(workdir.iterdir()) == []


def test_remote_checkout_refuses_plain_text_transport_before_fetching(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        remote, "_git_checkout",
        lambda *a, **k: pytest.fail("must not fetch over an insecure transport"),
    )
    target = remote.parse_remote_target("git://git.example.net/project.git")
    with pytest.raises(RemoteScanError, match="plain-text git://"):
        with remote.remote_checkout(target, timeout=15, workdir=tmp_path):
            pass


def test_insecure_transport_is_a_note_not_a_coverage_gap(tmp_path: Path, monkeypatch):
    captured = {}
    monkeypatch.setattr(remote, "_git_checkout", _fake_materializer(captured))
    target = remote.parse_remote_target("git://git.example.net/project.git")
    with remote.remote_checkout(
        target, timeout=15, workdir=tmp_path, allow_insecure_transport=True,
    ) as checkout:
        metadata = checkout.metadata
    assert metadata["transport_insecure"] is True
    assert any("without TLS" in note for note in metadata["warnings"])
    assert metadata["coverage_gaps"] == []


def test_remote_checkout_refuses_a_nearly_full_filesystem(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(remote, "_free_bytes", lambda path: 10)
    target = remote.parse_remote_target("https://github.com/acme/platform")
    with pytest.raises(RemoteScanError, match="MiB are free"):
        with remote.remote_checkout(target, timeout=15, workdir=tmp_path):
            pass


def test_cleanup_failures_are_reported_not_swallowed(tmp_path: Path, monkeypatch):
    captured = {}
    reported = []
    monkeypatch.setattr(remote, "_git_checkout", _fake_materializer(captured))
    monkeypatch.setattr(remote, "_remove_tree", lambda path: f"could not remove {path}")
    target = remote.parse_remote_target("https://github.com/acme/platform")
    with remote.remote_checkout(
        target, timeout=15, workdir=tmp_path, on_cleanup_error=reported.append,
    ):
        pass
    assert reported and "could not remove" in reported[0]
    with pytest.warns(RuntimeWarning, match="could not remove"):
        with remote.remote_checkout(target, timeout=15, workdir=tmp_path):
            pass


def test_remove_tree_deletes_read_only_files(tmp_path: Path):
    tree = tmp_path / "tree"
    (tree / "objects" / "pack").mkdir(parents=True)
    pack = tree / "objects" / "pack" / "pack-1.pack"
    pack.write_bytes(b"PACK")
    os.chmod(pack, 0o444)
    assert remote._remove_tree(tree) is None
    assert not tree.exists()


def test_strip_metadata_removes_nested_control_dirs_without_following_links(tmp_path: Path):
    root = tmp_path / "checkout"
    (root / "src" / "CVS").mkdir(parents=True)
    (root / "CVS").mkdir()
    (root / "src" / "main.c").write_text("int x;\n", encoding="utf-8")
    outside = tmp_path / "outside"
    (outside / "CVS").mkdir(parents=True)
    linked = _symlinks_supported(tmp_path)
    if linked:
        (root / "link").symlink_to(outside, target_is_directory=True)

    removed = remote._strip_metadata(root, ("CVS",), recursive=True)

    assert removed == 2
    assert not (root / "CVS").exists() and not (root / "src" / "CVS").exists()
    assert (root / "src" / "main.c").is_file()
    assert (outside / "CVS").is_dir(), "metadata stripping followed a directory link"


# ---------------------------------------------------------------------------
# Native backends
# ---------------------------------------------------------------------------

def test_fossil_checkout_removes_every_checkout_database_name(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("fossil+https://fossil.example.net/project", ref="release-1")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    checkout = temporary / "source"
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1] == "clone":
            Path(command[-1]).write_bytes(b"fossil repository database")
        elif command[1] == "open":
            workdir = Path(command[command.index("--workdir") + 1])
            workdir.mkdir()
            (workdir / ".fslckout").write_bytes(b"SQLite format 3\x00")
            (workdir / "main.c").write_text("int main;\n", encoding="utf-8")
        elif command[1] == "info":
            return SimpleNamespace(stdout=b"checkout: " + b"ab" * 20 + b" 2026-11-06\n")
        return SimpleNamespace(stdout=b"trunk\n")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._fossil_checkout(target, checkout, temporary, timeout=30)

    opened = next(command for command in commands if command[1] == "open")
    assert opened[3] == "release-1"
    assert not (checkout / ".fslckout").exists()
    assert (checkout / "main.c").is_file()
    assert metadata["revision"] == "ab" * 20


def test_hg_checkout_archives_the_resolved_default_head_without_metadata_file(tmp_path: Path, monkeypatch):
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
            revset = command[command.index("-r") + 1]
            return SimpleNamespace(stdout=b"" if "bookmark" in revset else b"f00d" * 10)
        elif "{branch}" in command:
            return SimpleNamespace(stdout=b"default")
        elif "archive" in command:
            Path(command[-1]).mkdir()
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._hg_checkout(target, checkout, temporary, timeout=30)

    lookups = [command[command.index("-r") + 1] for command in commands if "{node}" in command]
    assert lookups == ["present(bookmark('@'))", "max(head() and present(branch('default')))"]
    archive = next(command for command in commands if "archive" in command)
    assert "ui.archivemeta=false" in archive
    assert archive[archive.index("--rev") + 1] == "f00d" * 10
    assert metadata["revision"] == "f00d" * 10
    assert all("ui.ssh=ssh -o BatchMode=yes" in command for command in commands)


def test_svn_export_pins_the_looked_up_revision(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("svn+https://svn.example.net/repos/project/trunk")
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if "info" in command:
            return SimpleNamespace(stdout=b"42\n")
        Path(command[-1]).mkdir()
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    remote._svn_checkout(target, tmp_path / "source", timeout=30)
    assert "--non-interactive" in commands[0]
    export = commands[1]
    assert export[export.index("-r") + 1] == "42"
    assert "https://svn.example.net/repos/project/trunk@42" in export

    pinned = remote.parse_remote_target("svn+https://svn.example.net/repos/project/trunk", ref="7")
    commands.clear()
    remote._svn_checkout(pinned, tmp_path / "pinned", timeout=30)
    assert len(commands) == 1 and "trunk@7" in commands[0][-2]


def test_svn_ssh_tunnel_runs_in_batch_mode(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SVN_SSH", raising=False)
    target = remote.parse_remote_target("svn+ssh://svn.example.net/repos/project", ref="9")
    seen = {}

    def fake_run(command, **kwargs):
        seen["env"] = kwargs["env"]
        Path(command[-1]).mkdir()
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    remote._svn_checkout(target, tmp_path / "source", timeout=30)
    assert seen["env"]["SVN_SSH"] == "ssh -o BatchMode=yes"


def test_jj_reports_the_fetched_commit_not_the_working_copy(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("jj+https://github.com/acme/project")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1:3] == ["git", "clone"]:
            repository = Path(command[-1])
            (repository / ".jj").mkdir(parents=True)
            (repository / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            return SimpleNamespace(stdout=b"")
        return SimpleNamespace(stdout=b"c0ffee")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._jj_checkout(target, temporary / "source", temporary, timeout=30)
    log = commands[1]
    assert log[log.index("-r") + 1] == "@-"
    assert metadata["revision"] == "c0ffee"
    assert (temporary / "source" / "main.rs").is_file()
    assert not (temporary / "source" / ".jj").exists()


def test_native_working_copy_symlinks_survive_metadata_removal(tmp_path: Path, monkeypatch):
    if not _symlinks_supported(tmp_path):
        pytest.skip("symlink creation is unavailable on this platform")
    target = remote.parse_remote_target("darcs+https://code.example.net/team/project", ref="v1")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        repository = Path(command[-1])
        (repository / "_darcs").mkdir(parents=True)
        (repository / "main.hs").write_text("main = pure ()\n", encoding="utf-8")
        (repository / "entry.hs").symlink_to("main.hs")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    remote._darcs_checkout(target, temporary / "source", temporary, timeout=30)
    assert "--tag=v1" in commands[0]
    assert (temporary / "source" / "entry.hs").is_symlink()
    assert not (temporary / "source" / "_darcs").exists()


def test_p4_lists_only_live_files_and_unescapes_depot_names(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("p4+ssl://perforce.example.net:1666/depot/project", ref="rel-1")
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if "files" in command:
            return SimpleNamespace(stdout=(
                b"... depotFile //depot/project/docs/user%40host.txt\n... rev 2\n... change 30\n"
                b"... action edit\n"
                b"... depotFile //depot/project/old.c\n... rev 4\n... change 31\n"
                b"... action move/delete\n"
            ))
        Path(command[4]).write_text("content\n", encoding="utf-8")
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._p4_checkout(target, tmp_path / "source", timeout=30)

    listing = commands[0]
    assert listing[:4] == ["p4", "-ztag", "files", "-e"]
    assert listing[4] == "//depot/project/...@rel-1"
    assert (tmp_path / "source" / "docs" / "user@host.txt").is_file()
    assert not (tmp_path / "source" / "old.c").exists()
    assert commands[1][-1] == "//depot/project/docs/user%40host.txt#2"
    assert metadata["tracked_file_count"] == 1


def _svn_export_of(files: dict[str, bytes]):
    """A fake _run for Subversion that exports ``files`` into the checkout."""

    def fake_run(command, **kwargs):
        if "info" in command:
            return SimpleNamespace(stdout=b"42")
        if "export" in command:
            root = Path(command[-1])
            for relative, content in files.items():
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_bytes(content)
        return SimpleNamespace(stdout=b"")

    return fake_run


@pytest.mark.parametrize(
    ("limits", "kept", "removed_bytes"),
    [
        (RemoteLimits(max_files=2), {"a.txt", "b.txt"}, 24),
        # First fit in path order: a smaller later file still fits.
        (RemoteLimits(max_bytes=25), {"a.txt", "b.txt", "sub/small.txt"}, 20),
        (RemoteLimits(max_bytes=19), {"a.txt", "sub/small.txt"}, 30),
    ],
)
def test_non_git_exports_are_trimmed_to_the_materialization_budget(
    tmp_path: Path, monkeypatch, limits, kept, removed_bytes,
):
    # Regression: --remote-max-gb and the file budget were enforced only by Git extraction;
    # every other backend analyzed whatever its client exported and recorded no gap.
    files = {"a.txt": b"x" * 10, "b.txt": b"x" * 10, "c.txt": b"x" * 10, "sub/small.txt": b"x" * 4,
             "sub/z.txt": b"x" * 10}
    monkeypatch.setattr(remote, "_run", _svn_export_of(files))
    target = remote.parse_remote_target("svn+https://svn.example.net/repos/project/trunk")
    checkout, metadata = remote._materialize(target, tmp_path, timeout=30, limits=limits)

    present = {path.relative_to(checkout).as_posix() for path in checkout.rglob("*") if path.is_file()}
    assert present == kept
    budget = next(item for item in metadata["coverage"] if item["kind"] == "materialization_budget")
    assert budget["count"] == len(files) - len(kept)
    assert budget["incomplete"] is True
    assert f"({removed_bytes:,} bytes)" in budget["detail"]


def test_non_git_exports_within_the_budget_record_no_gap(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(remote, "_run", _svn_export_of({"main.py": b"print(1)\n"}))
    target = remote.parse_remote_target("svn+https://svn.example.net/repos/project/trunk")
    checkout, metadata = remote._materialize(target, tmp_path, timeout=30, limits=RemoteLimits())
    assert (checkout / "main.py").is_file()
    assert not any(item["kind"] == "materialization_budget" for item in metadata["coverage"])


def test_p4_stops_fetching_at_the_byte_budget(tmp_path: Path, monkeypatch):
    target = remote.parse_remote_target("p4+ssl://perforce.example.net:1666/depot/project")
    printed = []

    def fake_run(command, **kwargs):
        if "files" in command:
            return SimpleNamespace(stdout=b"".join(
                f"... depotFile //depot/project/f{index}.txt\n... rev 1\n... change {index}\n".encode()
                for index in range(4)
            ))
        printed.append(command[-1])
        Path(command[4]).write_bytes(b"x" * 10)
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(remote, "_run", fake_run)
    metadata = remote._p4_checkout(target, tmp_path / "source", timeout=30,
                                   limits=RemoteLimits(max_bytes=25))

    assert sorted(path.name for path in (tmp_path / "source").iterdir()) == ["f0.txt", "f1.txt"]
    # The third file crossed the budget and was removed; the fourth was never fetched.
    assert len(printed) == 3
    assert metadata["tracked_file_count"] == 2
    assert metadata["omitted_file_count"] == 2
    budget = next(item for item in metadata["coverage"] if item["kind"] == "materialization_budget")
    assert budget["count"] == 2 and budget["incomplete"] is True


def _folds_case(directory: Path) -> bool:
    probe = directory / "Case-Probe"
    probe.mkdir()
    try:
        return (directory / "case-probe").exists()
    finally:
        probe.rmdir()


def test_git_extraction_never_merges_directories_that_differ_only_in_case(tmp_path: Path, monkeypatch):
    first, second = b"1" * 40, b"2" * 40
    tree = (
        b"100644 blob " + first + b"       2\tSrc/a.py\0"
        + b"100644 blob " + second + b"       2\tsrc/b.py\0"
    )
    folds = _folds_case(tmp_path)
    blobs = first + b" blob 2\na\n\n" + (b"" if folds else second + b" blob 2\nb\n\n")
    created = _install_fake_git(monkeypatch, tree, blobs)
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    counts = remote._extract_git_tree(checkout, {}, timeout=30)

    assert (checkout / "Src" / "a.py").read_bytes() == b"a\n"
    if folds:
        # Regression: b.py was written into Src/, and reports cited Src/b.py, a path the
        # repository does not have. It is refused and counted as not materialized.
        assert os.listdir(checkout) == ["Src"]
        assert os.listdir(checkout / "Src") == ["a.py"]
        assert counts["omitted_tree_path_count"] == 1
        assert created["blobs"].stdin.getvalue() == first + b"\n"
    else:
        assert (checkout / "src" / "b.py").read_bytes() == b"b\n"
        assert counts["omitted_tree_path_count"] == 0


@pytest.mark.parametrize("message", [
    "fatal: unable to look up user:hunter2pass@git.example.net (port 9418)",
    "ssh: Could not resolve hostname deploy:s3cr3t-value@build.example.org: Name or service not known",
])
def test_client_output_redacts_userinfo_without_a_scheme(message):
    # Regression: only scheme://user:pass@ was redacted; git prints some destinations
    # without a scheme, and a credential from an insteadOf rule reached reports.
    cleaned = remote.sanitize_client_output(message)
    assert "hunter2pass" not in cleaned and "s3cr3t-value" not in cleaned
    assert "<redacted>@" in cleaned
    # scp-style user names and ordinary text are untouched.
    assert remote.sanitize_client_output("git@github.com:acme/app.git at 12:30") == "git@github.com:acme/app.git at 12:30"
