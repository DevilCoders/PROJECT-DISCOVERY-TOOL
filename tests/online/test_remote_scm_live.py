"""End-to-end remote scans against live servers of the version control systems other than Git.

Each test builds a repository with the VCS's own client, serves it with that VCS's own server on
the loopback interface (`hg serve`, `brz serve`, `fossil server`), and runs `pdt scan` on its URL
exactly as on a hosted repository: the default head, then a branch, tag or revision. No network
beyond localhost is used. A test skips when its client is not installed.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from project_discovery import cli
from project_discovery.online import repositories as remote


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _accepts(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _run(*command: str, cwd: Path, env: dict) -> str:
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, check=True, timeout=120).stdout.decode(
        "utf-8", errors="replace").strip()


@contextlib.contextmanager
def _serving(command: list[str], port: int, env: dict, cwd: Path):
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, **remote._isolation_kwargs())
    try:
        deadline = time.monotonic() + 30
        while not _accepts(port):
            if time.monotonic() > deadline or process.poll() is not None:
                pytest.skip(f"{command[0]} could not serve on the loopback interface")
            time.sleep(0.2)
        yield
    finally:
        remote._kill_process_tree(process)
        process.wait(timeout=30)


def _seed(directory: Path) -> None:
    (directory / "src").mkdir(parents=True, exist_ok=True)
    (directory / "src" / "app.py").write_text("import os\n\n\ndef main():\n    print(os.getcwd())\n", encoding="utf-8")
    (directory / "README.md").write_text("# Demo repository\n", encoding="utf-8")


def _scan(monkeypatch, output: Path, url: str, *options: str) -> dict:
    monkeypatch.setattr(sys, "argv", ["pdt", "scan", url, *options, "--allow-insecure-transport", "--output", str(output),
                                      "--format", "json", "--quiet"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == cli.EXIT_OK
    return json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))


def _files(report: dict) -> set[str]:
    return {item["path"] for item in report["files"]}


def _remote(report: dict) -> dict:
    return report["metrics"]["source"]["remote"]


@pytest.mark.skipif(shutil.which("hg") is None, reason="Mercurial client not installed")
def test_mercurial_server_end_to_end(tmp_path: Path, monkeypatch):
    env = {**os.environ, "HGUSER": "PDT <pdt@example.invalid>", "HGRCPATH": "", "HGPLAIN": "1"}
    repository = tmp_path / "hg"
    _seed(repository)

    def hg(*args: str) -> str:
        return _run("hg", *args, cwd=repository, env=env)

    hg("init")
    hg("add", "-q")
    hg("commit", "-q", "-m", "initial")
    (repository / "src" / "more.py").write_text("x = 1\n", encoding="utf-8")
    hg("add", "-q")
    hg("commit", "-q", "-m", "second")
    hg("tag", "-q", "v1.0")  # tags "second"; the tag itself is a commit that adds .hgtags
    tagged = hg("log", "-r", "v1.0", "-T", "{node}")
    hg("branch", "-q", "feature")
    (repository / "src" / "feature.py").write_text("y = 2\n", encoding="utf-8")
    hg("add", "-q")
    hg("commit", "-q", "-m", "feature")
    feature = hg("log", "-r", "feature", "-T", "{node}")
    hg("update", "-q", "default")
    default = hg("log", "-r", "default", "-T", "{node}")
    port = _free_port()
    with _serving(["hg", "serve", "-R", str(repository), "-a", "127.0.0.1", "-p", str(port)], port, env, tmp_path):
        url = f"hg+http://127.0.0.1:{port}/"
        report = _scan(monkeypatch, tmp_path / "default", url)
        source = _remote(report)
        assert (source["vcs"], source["provider"], source["revision"]) == ("hg", "Mercurial server", default)
        assert source["transport"] == "http" and source["transport_insecure"] is True
        assert _files(report) == {".hgtags", "README.md", "src/app.py", "src/more.py"}
        branch = _scan(monkeypatch, tmp_path / "branch", url, "--ref", "feature")
        assert (_remote(branch)["revision"], _remote(branch)["branch"]) == (feature, "feature")
        assert "src/feature.py" in _files(branch)
        tag = _scan(monkeypatch, tmp_path / "tag", url, "--ref", "v1.0")
        assert _remote(tag)["revision"] == tagged
        assert _files(tag) == {"README.md", "src/app.py", "src/more.py"}
    assert not any(path.name == ".hg" for path in tmp_path.joinpath("default").rglob(".hg"))


@pytest.mark.skipif(shutil.which("brz") is None, reason="Breezy client not installed")
def test_bazaar_server_end_to_end(tmp_path: Path, monkeypatch):
    env = {**os.environ, "BRZ_EMAIL": "PDT <pdt@example.invalid>", "BRZ_HOME": str(tmp_path / "brz-home"),
           "BRZ_LOG": os.devnull}
    root = tmp_path / "bzr"
    branch = root / "trunk"
    _seed(branch)

    def brz(*args: str) -> str:
        return _run("brz", *args, cwd=branch, env=env)

    brz("init", "-q")
    brz("add", "-q")
    brz("commit", "-q", "-m", "initial")
    (branch / "src" / "more.py").write_text("x = 1\n", encoding="utf-8")
    brz("add", "-q")
    brz("commit", "-q", "-m", "second")
    port = _free_port()
    with _serving(["brz", "serve", "--directory", str(root), "--listen", "127.0.0.1", "--port", str(port)], port, env,
                  root):
        url = f"bzr+bzr://127.0.0.1:{port}/trunk"
        report = _scan(monkeypatch, tmp_path / "latest", url)
        source = _remote(report)
        assert (source["vcs"], source["provider"], source["transport"]) == ("bzr", "Bazaar server", "bzr")
        assert source["revision"]
        assert _files(report) == {"README.md", "src/app.py", "src/more.py"}
        first = _scan(monkeypatch, tmp_path / "first", url, "--ref", "1")
        assert _files(first) == {"README.md", "src/app.py"}
        assert _remote(first)["revision"] != source["revision"]


@pytest.mark.skipif(any(shutil.which(tool) is None for tool in ("svn", "svnadmin", "svnserve")),
                    reason="Subversion client and server not installed")
def test_subversion_server_end_to_end(tmp_path: Path, monkeypatch):
    home = tmp_path / "svn-home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home)}
    root = tmp_path / "svn"
    repository = root / "project"
    root.mkdir()
    _run("svnadmin", "create", str(repository), cwd=tmp_path, env=env)
    layout = tmp_path / "layout"
    for directory in ("trunk", "branches", "tags"):
        (layout / directory).mkdir(parents=True)
    _seed(layout / "trunk")
    local = repository.as_uri()

    def svn(*args: str, cwd: Path = tmp_path) -> str:
        return _run("svn", *args, "--non-interactive", cwd=cwd, env=env)

    svn("import", "-q", str(layout), local, "-m", "initial")
    svn("copy", "-q", f"{local}/trunk", f"{local}/tags/v1.0", "-m", "tag")
    svn("checkout", "-q", f"{local}/trunk", str(tmp_path / "wc"))
    (tmp_path / "wc" / "src" / "more.py").write_text("x = 1\n", encoding="utf-8")
    svn("add", "-q", "src/more.py", cwd=tmp_path / "wc")
    svn("commit", "-q", "-m", "second", cwd=tmp_path / "wc")
    head = svn("info", "--show-item", "revision", local)
    port = _free_port()
    with _serving(["svnserve", "-d", "--foreground", "-r", str(root), "--listen-host", "127.0.0.1",
                   "--listen-port", str(port)], port, env, tmp_path):
        trunk = f"svn+svn://127.0.0.1:{port}/project/trunk"
        report = _scan(monkeypatch, tmp_path / "trunk", trunk)
        source = _remote(report)
        assert (source["vcs"], source["provider"], source["transport"]) == ("svn", "Subversion server", "svn")
        assert source["revision"] == head == "3"
        assert _files(report) == {"README.md", "src/app.py", "src/more.py"}
        tag = _scan(monkeypatch, tmp_path / "tag", f"svn+svn://127.0.0.1:{port}/project/tags/v1.0")
        assert _files(tag) == {"README.md", "src/app.py"}
        pinned = _scan(monkeypatch, tmp_path / "pinned", trunk, "--ref", "2")
        assert (_remote(pinned)["revision"], _files(pinned)) == ("2", {"README.md", "src/app.py"})


@pytest.mark.skipif(shutil.which("jj") is None or shutil.which("git") is None,
                    reason="Jujutsu and Git clients not installed")
def test_git_backed_jujutsu_end_to_end(tmp_path: Path, monkeypatch):
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "PDT", "GIT_AUTHOR_EMAIL": "pdt@example.invalid",
           "GIT_COMMITTER_NAME": "PDT", "GIT_COMMITTER_EMAIL": "pdt@example.invalid", "HOME": str(tmp_path)}
    work = tmp_path / "work"
    work.mkdir()
    _seed(work)

    def git(*args: str, cwd: Path = work) -> str:
        return _run("git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", *args, cwd=cwd, env=env)

    git("init", "-q")
    git("add", ".")
    git("commit", "-q", "-m", "initial")
    head = git("rev-parse", "HEAD")
    served = tmp_path / "served"
    served.mkdir()
    git("clone", "-q", "--bare", str(work), str(served / "repo.git"), cwd=tmp_path)
    port = _free_port()
    with _serving(["git", "daemon", "--reuseaddr", "--export-all", f"--base-path={served}", "--listen=127.0.0.1",
                   f"--port={port}", str(served)], port, env, tmp_path):
        report = _scan(monkeypatch, tmp_path / "report", f"jj+git://127.0.0.1:{port}/repo.git")
        source = _remote(report)
        assert (source["vcs"], source["revision"], source["transport"]) == ("jj", head, "git")
        assert _files(report) == {"README.md", "src/app.py"}
    assert not any(path.name in {".jj", ".git"} for path in tmp_path.joinpath("report").rglob("*"))


@pytest.mark.skipif(shutil.which("fossil") is None, reason="Fossil client not installed")
def test_fossil_server_end_to_end(tmp_path: Path, monkeypatch):
    home = tmp_path / "fossil-home"
    home.mkdir()
    env = {**os.environ, "FOSSIL_HOME": str(home), "HOME": str(home), "USER": "pdt"}
    repository = tmp_path / "repo.fossil"
    work = tmp_path / "fossil-work"
    work.mkdir()

    def fossil(*args: str) -> str:
        return _run("fossil", *args, cwd=work, env=env)

    fossil("init", str(repository))
    fossil("open", str(repository))
    _seed(work)
    fossil("add", ".")
    fossil("commit", "-m", "initial", "--no-warnings")
    fossil("tag", "add", "v1.0", "trunk")
    (work / "src" / "more.py").write_text("x = 1\n", encoding="utf-8")
    fossil("add", "src/more.py")
    fossil("commit", "-m", "second", "--no-warnings")
    port = _free_port()
    with _serving(["fossil", "server", str(repository), "--port", str(port), "--localhost"], port, env, tmp_path):
        url = f"fossil+http://127.0.0.1:{port}/"
        report = _scan(monkeypatch, tmp_path / "latest", url)
        source = _remote(report)
        assert (source["vcs"], source["provider"], source["transport"]) == ("fossil", "Fossil server", "http")
        assert _files(report) == {"README.md", "src/app.py", "src/more.py"}
        tag = _scan(monkeypatch, tmp_path / "tag", url, "--ref", "v1.0")
        assert _files(tag) == {"README.md", "src/app.py"}
        assert _remote(tag)["revision"] != source["revision"]


@pytest.mark.skipif(os.environ.get("PDT_LIVE_NETWORK_TESTS") != "1" or shutil.which("pijul") is None,
                    reason="set PDT_LIVE_NETWORK_TESTS=1, with the Pijul client installed, to clone from the public Nest")
def test_pijul_repository_on_the_nest(tmp_path: Path, monkeypatch):
    # Pijul has no standalone server (its HTTP remotes speak the Nest's protocol), so this reads a
    # small public repository on the Nest itself.
    report = _scan(monkeypatch, tmp_path / "nest", "pijul+https://nest.pijul.com/pijul/manual")
    source = _remote(report)
    assert (source["vcs"], source["provider"], source["branch"], source["transport"]) == (
        "pijul", "Pijul Nest", "main", "https")
    assert re.fullmatch(r"[A-Z2-7]{40,64}", source["revision"] or "")
    files = _files(report)
    assert {"README.md", "book.toml"} <= files
    assert not any(".pijul" in path.split("/") for path in files)


def _darcs_head(repository: Path, env: dict) -> str:
    log = _run("darcs", "log", "--last", "1", "--xml-output", cwd=repository, env=env)
    return log.split(" hash='", 1)[1][:40]


@contextlib.contextmanager
def _static_http(directory: Path):
    """Serve ``directory`` over plain HTTP on the loopback interface (a Darcs repository needs
    nothing else)."""
    import functools
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=str(directory)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(10)


@pytest.mark.skipif(shutil.which("darcs") is None, reason="the Darcs client is not installed")
def test_darcs_repository_over_http(tmp_path: Path, monkeypatch):
    env = {**os.environ, "DARCS_DONT_COLOR": "1"}
    author = "PDT Test <pdt-test@example.invalid>"
    repository = tmp_path / "served" / "repo"
    repository.mkdir(parents=True)
    _run("darcs", "init", "--quiet", cwd=repository, env=env)
    _seed(repository)
    _run("darcs", "add", "--quiet", "-r", "src", "README.md", cwd=repository, env=env)
    _run("darcs", "record", "--quiet", "-a", "-m", "initial", "--author", author, cwd=repository, env=env)
    _run("darcs", "tag", "--quiet", "v1", "--author", author, cwd=repository, env=env)
    tagged_head = _darcs_head(repository, env)
    (repository / "later.txt").write_text("later\n", encoding="utf-8")
    _run("darcs", "add", "--quiet", "later.txt", cwd=repository, env=env)
    _run("darcs", "record", "--quiet", "-a", "-m", "later", "--author", author, cwd=repository, env=env)
    head = _darcs_head(repository, env)
    with _static_http(tmp_path / "served") as port:
        latest = _scan(monkeypatch, tmp_path / "latest", f"darcs+http://127.0.0.1:{port}/repo")
        tagged = _scan(monkeypatch, tmp_path / "tagged", f"darcs+http://127.0.0.1:{port}/repo", "--ref", "v1")
    assert {"README.md", "src/app.py", "later.txt"} <= _files(latest)
    assert (_remote(latest)["revision"], _remote(latest)["provider"]) == (head, "Darcs server")
    assert "later.txt" not in _files(tagged) and "src/app.py" in _files(tagged)
    assert _remote(tagged)["revision"] == tagged_head
    for report in (latest, tagged):
        assert not any(path.startswith("_darcs") for path in _files(report))
        assert "pdt-test@example.invalid" not in json.dumps(report)  # patch authors are not recorded


@contextlib.contextmanager
def _cvs_pserver(cvsroot: Path):
    """A CVS pserver on the loopback interface, run as this user: an inetd-style listener that
    starts ``cvs pserver`` for each connection."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.5)
    stop = threading.Event()

    def serve(connection: socket.socket) -> None:
        with connection:
            connection.setblocking(True)
            subprocess.run(["cvs", "-f", f"--allow-root={cvsroot}", "pserver"], stdin=connection.fileno(),
                           stdout=connection.fileno(), stderr=subprocess.DEVNULL, timeout=120, check=False)

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=serve, args=(connection,), daemon=True).start()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        thread.join(10)


@pytest.mark.skipif(shutil.which("cvs") is None or os.name == "nt", reason="the CVS client is not installed")
def test_cvs_repository_over_pserver(tmp_path: Path, monkeypatch):
    import getpass

    env = {**os.environ, "CVS_PASSFILE": str(tmp_path / "cvspass")}
    monkeypatch.setenv("CVS_PASSFILE", str(tmp_path / "cvspass"))
    cvsroot = tmp_path / "cvsroot"
    _run("cvs", "-d", str(cvsroot), "init", cwd=tmp_path, env=env)
    # An account without a password, mapped to the user the server runs as.
    (cvsroot / "CVSROOT" / "passwd").write_text(f"anonymous::{getpass.getuser()}\n", encoding="utf-8")
    source = tmp_path / "import"
    _seed(source)
    _run("cvs", "-Q", "-d", str(cvsroot), "import", "-m", "initial", "project", "vendor", "start", cwd=source, env=env)
    _run("cvs", "-Q", "-d", str(cvsroot), "checkout", "-d", "work", "project", cwd=tmp_path, env=env)
    work = tmp_path / "work"
    _run("cvs", "-Q", "tag", "release-1", cwd=work, env=env)
    (work / "later.txt").write_text("later\n", encoding="utf-8")
    _run("cvs", "-Q", "add", "later.txt", cwd=work, env=env)
    _run("cvs", "-Q", "commit", "-m", "later", cwd=work, env=env)
    with _cvs_pserver(cvsroot) as port:
        url = f"cvs+pserver://anonymous@127.0.0.1:{port}{cvsroot.as_posix()}/project"
        latest = _scan(monkeypatch, tmp_path / "latest", url)
        tagged = _scan(monkeypatch, tmp_path / "tagged", url, "--ref", "release-1")
    assert {"README.md", "src/app.py", "later.txt"} <= _files(latest)
    assert (_remote(latest)["revision"], _remote(latest)["provider"]) == (None, "CVS server")
    assert "later.txt" not in _files(tagged) and _remote(tagged)["revision"] == "release-1"
    for report in (latest, tagged):
        assert not any(path == "CVS" or path.startswith("CVS/") or "/CVS/" in path for path in _files(report))
