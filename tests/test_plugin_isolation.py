"""Isolated plugin execution: sandbox enforcement, protocol safety and failure handling.

The plugins below are real modules written to a temporary directory and loaded through
real entry points, so each scan exercises the whole path: host start, operating-system
sandbox, probes, plugin import, the JSON protocol and PDT's validation.
"""
import errno
import io
import json
import os
import socket
import struct
import sys
import time
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

import project_discovery.analyzers as registry
from project_discovery import plugin_isolation, plugin_sandbox
from project_discovery.cli import capabilities_report, run_scan
from project_discovery.plugin_isolation import (
    PluginHost,
    finding_from_plugin,
    probe_sandbox,
    validate_metadata,
)
from project_discovery.plugin_protocol import (
    MAX_FINDINGS_PER_FILE,
    ProtocolError,
    encode_frame,
    read_frame,
)

WINDOWS = sys.platform == "win32"
# What sandbox mode must verify here (Windows cannot restrict reads or network access).
REQUIRED = set(plugin_sandbox.required_restrictions())

PLUGIN_SOURCE = '''
import json, os, socket, subprocess, sys, time
from pathlib import Path
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import CodeEvidence, Finding
from project_discovery.plugin_sandbox import is_denial

OUTSIDE = Path(__OUTSIDE__)
PORT = __PORT__

# Import-time code must already run inside the sandbox.
try:
    (OUTSIDE / "written-at-import.txt").write_text("escaped")
except OSError:
    pass


def attempt(action):
    try:
        action()
    except Exception as exc:
        return "denied" if is_denial(exc) else "failed: " + type(exc).__name__
    return "allowed"


def connect():
    with socket.create_connection(("127.0.0.1", PORT), timeout=5):
        pass


def spawn():
    subprocess.run([sys.executable, "-I", "-S", "-c", "pass"], check=True, timeout=60)


class Base(Analyzer):
    version = "1.0"

    def supports(self, record):
        return record.extension == ".txt"


class Echo(Base):
    name = "fixture-echo"
    version = "1.2.3"
    domains = ("testing",)
    languages = ("Text",)

    def analyze(self, path, record):
        print("stdout noise that must not reach the protocol")
        text = Path(path).read_text(encoding="utf-8").strip()
        return [Finding(
            "plugin_fixture", "Echo " + record.path, text, evidence=[record.path],
            analyzer="secret-patterns", severity="LOW",
            code_evidence=[CodeEvidence(1, "password = 'hunter2hunter2'")],
        )]


class Escape(Base):
    name = "fixture-escape"

    def supports(self, record):
        return record.path == "a.txt"

    def analyze(self, path, record):
        report = {
            "read_outside": attempt(lambda: (OUTSIDE / "canary.txt").read_bytes()),
            "write_outside": attempt(lambda: (OUTSIDE / "written.txt").write_text("x")),
            "network": attempt(connect),
            "spawn": attempt(spawn),
            "environment": sorted(os.environ),
            "staged_path": str(path),
            "pid": os.getpid(),
        }
        return [Finding("plugin_fixture", "Escape attempts", json.dumps(report))]


class Crash(Base):
    name = "fixture-crash"

    def analyze(self, path, record):
        if record.path == "crash.txt":
            os._exit(3)
        return [Finding("plugin_fixture", "Survived " + record.path, "")]


class AlwaysCrash(Base):
    name = "fixture-always-crash"

    def analyze(self, path, record):
        os._exit(4)


class Hang(Base):
    name = "fixture-hang"

    def analyze(self, path, record):
        if record.path == "hang.txt":
            time.sleep(120)
        return [Finding("plugin_fixture", "Finished " + record.path, "")]


class Flood(Base):
    name = "fixture-flood"

    def analyze(self, path, record):
        findings = [Finding("plugin_fixture", f"Item {index}", "") for index in range(__FLOOD__)]
        return ["not a finding"] + findings


class Raise(Base):
    name = "fixture-raise"

    def analyze(self, path, record):
        raise ValueError("bad input password=hunter2hunter2")


class Duplicate(Base):
    name = "secret-patterns"

    def analyze(self, path, record):
        return []


NOT_AN_ANALYZER = object()
'''

IN_PROCESS_SOURCE = '''
import os
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import Finding


class InProcess(Analyzer):
    name = "fixture-in-process"

    def supports(self, record):
        return record.path == "a.txt"

    def analyze(self, path, record):
        # In-process plugins attribute their own findings; isolated ones cannot.
        return [Finding("plugin_fixture", "Process id", str(os.getpid()), analyzer=self.name)]
'''

ENTRY_POINTS = {
    "echo": "pdt_fixture_plugins:Echo",
    "escape": "pdt_fixture_plugins:Escape",
    "crash": "pdt_fixture_plugins:Crash",
    "always-crash": "pdt_fixture_plugins:AlwaysCrash",
    "hang": "pdt_fixture_plugins:Hang",
    "flood": "pdt_fixture_plugins:Flood",
    "raise": "pdt_fixture_plugins:Raise",
    "duplicate": "pdt_fixture_plugins:Duplicate",
    "not-analyzer": "pdt_fixture_plugins:NOT_AN_ANALYZER",
    "broken": "pdt_fixture_broken:Anything",
    "in-process": "pdt_fixture_inprocess:InProcess",
}


@pytest.fixture
def plugins(tmp_path, monkeypatch):
    """Write the fixture plugins; the returned function installs entry points by name."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.txt").write_text("canary", encoding="utf-8")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    directory = tmp_path / "plugins"
    directory.mkdir()
    source = (
        PLUGIN_SOURCE.replace("__OUTSIDE__", repr(str(outside)))
        .replace("__PORT__", str(listener.getsockname()[1]))
        .replace("__FLOOD__", str(MAX_FINDINGS_PER_FILE + 10))
    )
    (directory / "pdt_fixture_plugins.py").write_text(source, encoding="utf-8")
    (directory / "pdt_fixture_broken.py").write_text('raise RuntimeError("import failed on purpose")\n', encoding="utf-8")
    (directory / "pdt_fixture_inprocess.py").write_text(IN_PROCESS_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(directory))

    def install(*names: str) -> None:
        points = [EntryPoint(name=name, value=ENTRY_POINTS[name], group="pdt.analyzers") for name in names]
        monkeypatch.setattr(registry, "entry_points", lambda **_kwargs: points)

    install.outside = outside
    yield install
    listener.close()


def _project(root: Path, *names: str) -> Path:
    root.mkdir()
    for name in names or ("a.txt",):
        (root / name).write_text(f"content of {name}\n", encoding="utf-8")
    return root


def _scan(project: Path, output: Path, **options) -> dict:
    options.setdefault("quiet", True)
    options.setdefault("executor", "thread")
    code = run_scan(project, output, {"json"}, 1, **options)
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    report["exit_code"] = code
    return report


def _from(report: dict, analyzer: str) -> list[dict]:
    return [item for item in report["findings"] if item["analyzer"] == analyzer]


def _failure(report: dict, analyzer: str, path: str) -> dict:
    [item] = [item for item in report["findings"] if item["title"] == f"Analyzer failed: {analyzer}: {path}"]
    assert item["confidence"] == "UNKNOWN"
    return item


def _denied(restrictions: dict) -> set[str]:
    return {name for name, denied in restrictions.items() if denied}


def test_sandbox_probe_verifies_this_platforms_restrictions():
    probe = probe_sandbox()
    assert probe["available"], probe.get("error")
    sandbox = probe["sandbox"]
    assert _denied(sandbox["restrictions"]) >= REQUIRED
    if WINDOWS:
        assert {"job-object", "untrusted-integrity", "no-child-processes"} <= set(sandbox["mechanisms"])
    elif sys.platform.startswith("linux"):
        assert any(item.startswith("landlock-abi-") for item in sandbox["mechanisms"])
        assert "seccomp-bpf" in sandbox["mechanisms"]
    elif sys.platform == "darwin":
        assert "seatbelt" in sandbox["mechanisms"]


def test_isolated_plugin_findings_are_validated_and_attributed(tmp_path, plugins):
    plugins("echo")
    project = _project(tmp_path / "project", "a.txt", "b.txt", "c.md")
    report = _scan(project, tmp_path / "out", strict=True)
    assert report["exit_code"] == 0
    findings = _from(report, "fixture-echo")
    # The plugin read its staged copies; it claimed to be secret-patterns but cannot be.
    assert sorted((item["title"], item["detail"]) for item in findings) == [
        ("Echo a.txt", "content of a.txt"), ("Echo b.txt", "content of b.txt"),
    ]
    assert not [item for item in _from(report, "secret-patterns") if item["title"].startswith("Echo")]
    assert all("hunter2" not in json.dumps(item) for item in findings)
    status = report["metrics"]["plugin_isolation"]["plugins"][0]
    assert (status["status"], status["name"], status["version"]) == ("loaded", "fixture-echo", "1.2.3")
    assert _denied(status["sandbox"]["restrictions"]) >= REQUIRED
    entry = next(item for item in report["metrics"]["analyzer_registry"] if item["name"] == "fixture-echo")
    assert (entry["origin"], entry["isolation"]) == ("plugin", "sandbox")
    assert not (tmp_path / "out" / ".pdt-cache" / "plugins").exists()


def test_sandbox_denies_escape_attempts_including_import_time_code(tmp_path, plugins, monkeypatch):
    monkeypatch.setenv("PDT_FIXTURE_SECRET_TOKEN", "do-not-leak")
    plugins("escape")
    project = _project(tmp_path / "project")
    report = _scan(project, tmp_path / "out")
    [finding] = _from(report, "fixture-escape")
    attempts = json.loads(finding["detail"])
    observed = {
        "filesystem_reads": attempts["read_outside"] == "denied",
        "filesystem_writes": attempts["write_outside"] == "denied",
        "network": attempts["network"] == "denied",
        "process_creation": attempts["spawn"] == "denied",
    }
    # What the plugin experienced matches what the probes verified, and meets the minimum.
    assert observed == report["metrics"]["plugin_isolation"]["plugins"][0]["sandbox"]["restrictions"]
    assert _denied(observed) >= REQUIRED
    assert not (plugins.outside / "written.txt").exists()
    assert not (plugins.outside / "written-at-import.txt").exists()
    assert "PDT_FIXTURE_SECRET_TOKEN" not in attempts["environment"]
    assert not Path(attempts["staged_path"]).is_relative_to(project)
    assert attempts["pid"] != os.getpid()


def test_host_crash_is_contained_and_the_next_file_gets_a_new_host(tmp_path, plugins):
    plugins("crash")
    project = _project(tmp_path / "project", "a.txt", "crash.txt", "z.txt")
    report = _scan(project, tmp_path / "out", jobs=1)
    assert {"Survived a.txt", "Survived z.txt"} <= {item["title"] for item in _from(report, "fixture-crash")}
    assert "exit status 3" in _failure(report, "fixture-crash", "crash.txt")["detail"]


def test_hung_plugin_is_stopped_at_the_timeout(tmp_path, plugins):
    plugins("hang")
    project = _project(tmp_path / "project", "a.txt", "hang.txt", "z.txt")
    started = time.monotonic()
    report = _scan(project, tmp_path / "out", jobs=1, plugin_timeout=2)
    assert time.monotonic() - started < 60
    assert "did not answer within 2 s" in _failure(report, "fixture-hang", "hang.txt")["detail"]
    assert {"Finished a.txt", "Finished z.txt"} <= {item["title"] for item in _from(report, "fixture-hang")}


def test_repeated_host_failures_disable_the_plugin(tmp_path, plugins):
    plugins("always-crash")
    project = _project(tmp_path / "project", *(f"f{index}.txt" for index in range(8)))
    report = _scan(project, tmp_path / "out", jobs=1)
    failures = [
        item for item in report["findings"]
        if item["title"].startswith("Analyzer failed: fixture-always-crash")
    ]
    assert len(failures) == plugin_isolation.HOST_FAILURE_LIMIT
    assert "disabled for the rest of this scan" in failures[-1]["detail"]


def test_plugin_output_is_bounded_and_invalid_items_are_reported(tmp_path, plugins):
    plugins("flood")
    report = _scan(_project(tmp_path / "project"), tmp_path / "out")
    findings = _from(report, "fixture-flood")
    items = [item for item in findings if item["title"].startswith("Item ")]
    [note] = [item for item in findings if item["title"].startswith("Plugin output rejected")]
    assert len(items) == MAX_FINDINGS_PER_FILE - 1  # the invalid item took one slot
    assert note["confidence"] == "UNKNOWN"
    assert "1 invalid finding(s)" in note["detail"] and "were dropped" in note["detail"]


def test_plugin_exception_becomes_a_redacted_coverage_finding(tmp_path, plugins):
    plugins("raise")
    report = _scan(_project(tmp_path / "project"), tmp_path / "out")
    detail = _failure(report, "fixture-raise", "a.txt")["detail"]
    assert "ValueError: bad input" in detail and "hunter2" not in detail


def test_invalid_plugins_are_reported_and_not_loaded(tmp_path, plugins):
    plugins("broken", "not-analyzer", "duplicate", "echo")
    project = _project(tmp_path / "project")
    report = _scan(project, tmp_path / "out")
    statuses = {item["entry_point"]: item for item in report["metrics"]["plugin_isolation"]["plugins"]}
    assert statuses["echo"]["status"] == "loaded"
    assert "import failed on purpose" in statuses["broken"]["error"]
    assert "Analyzer subclass" in statuses["not-analyzer"]["error"]
    assert "duplicate analyzer name" in statuses["duplicate"]["error"]
    assert len(report["metrics"]["plugin_diagnostics"]) == 3
    assert _from(report, "fixture-echo")
    assert _scan(project, tmp_path / "strict", strict=True)["exit_code"] == 3


def test_process_executor_runs_isolated_plugins_in_its_workers(tmp_path, plugins):
    plugins("echo")
    project = _project(tmp_path / "project", "a.txt", "b.txt", "c.txt")
    threads = _scan(project, tmp_path / "threads", executor="thread")
    processes = _scan(project, tmp_path / "processes", executor="process", jobs=2)
    assert processes["metrics"]["execution"]["executor"] == "process"

    def titles(report):
        return sorted(item["title"] for item in _from(report, "fixture-echo"))

    assert titles(processes) == titles(threads) == ["Echo a.txt", "Echo b.txt", "Echo c.txt"]


def test_process_mode_runs_out_of_process_without_os_restrictions(tmp_path, plugins, monkeypatch):
    monkeypatch.setenv("PDT_FIXTURE_SECRET_TOKEN", "do-not-leak")
    plugins("escape")
    report = _scan(_project(tmp_path / "project"), tmp_path / "out", plugin_isolation="process")
    [finding] = _from(report, "fixture-escape")
    attempts = json.loads(finding["detail"])
    status = report["metrics"]["plugin_isolation"]["plugins"][0]
    assert status["isolation"] == "process"
    assert not _denied(status["sandbox"]["restrictions"])
    assert attempts["write_outside"] == "allowed"
    assert "PDT_FIXTURE_SECRET_TOKEN" not in attempts["environment"]
    assert attempts["pid"] != os.getpid()


def test_off_mode_loads_plugins_in_process(tmp_path, plugins):
    plugins("in-process")
    report = _scan(_project(tmp_path / "project"), tmp_path / "out", plugin_isolation="off")
    [finding] = _from(report, "fixture-in-process")
    assert finding["detail"] == str(os.getpid())
    assert report["metrics"]["plugin_isolation"]["plugins"][0]["isolation"] == "off"


def test_interrupt_stops_every_plugin_host(tmp_path, plugins, monkeypatch):
    import project_discovery.cli as cli

    hosts = []
    original = PluginHost.__init__

    def tracking(self, *args, **kwargs):
        hosts.append(self)
        original(self, *args, **kwargs)

    class Interrupting:
        name, version, api_version = "interrupting", "1", 1
        domains, languages, concurrent_safe = (), (), True

        def supports(self, record):
            return record.path == "b.txt"

        def analyze(self, path, record):
            raise KeyboardInterrupt

    def loading(**options):
        result = registry.load_analyzers(**options)
        result.analyzers.append(Interrupting())
        return result

    monkeypatch.setattr(PluginHost, "__init__", tracking)
    monkeypatch.setattr(cli, "load_analyzers", loading)
    plugins("echo")
    project = _project(tmp_path / "project", "a.txt", "b.txt")
    with pytest.raises(KeyboardInterrupt):
        run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, executor="thread", jobs=1)
    assert hosts and all(host.process.poll() is not None for host in hosts)


def test_files_over_the_plugin_limit_are_not_handed_over(tmp_path, plugins, monkeypatch):
    monkeypatch.setattr(plugin_isolation, "MAX_PLUGIN_FILE_BYTES", 8)
    plugins("echo")
    report = _scan(_project(tmp_path / "project"), tmp_path / "out")
    assert "isolated-plugin limit" in _failure(report, "fixture-echo", "a.txt")["detail"]


def test_capabilities_report_the_sandbox_and_plugins(plugins):
    plugins("echo")
    report = capabilities_report()
    assert report["plugin_sandbox"]["available"], report["plugin_sandbox"].get("error")
    assert [(item["name"], item["status"]) for item in report["plugins"]] == [("fixture-echo", "loaded")]


def test_plugin_options_are_validated_before_scanning(tmp_path):
    project = _project(tmp_path / "project")
    for options in ({"plugin_isolation": "chroot"}, {"plugin_timeout": 0}, {"plugin_memory_mb": 10}):
        with pytest.raises(ValueError, match="--plugin-"):
            run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, **options)


def test_frames_reject_oversized_truncated_and_non_object_payloads():
    def reader(data: bytes):
        return io.BytesIO(data).read

    frame = encode_frame({"ok": True, "name": "undecodable \udcff"})
    assert read_frame(reader(frame), 1024) == {"ok": True, "name": "undecodable \udcff"}
    assert read_frame(reader(b""), 1024) is None

    def raw(payload: bytes) -> bytes:
        return len(payload).to_bytes(4, "big") + payload

    with pytest.raises(ProtocolError, match="exceeds"):
        read_frame(reader(raw(b"x" * 2048)), 1024)
    for data, message in (
        (frame[:-1], "truncated"),
        (frame[:2], "truncated"),
        (raw(b"[1]"), "object"),
        (raw(b"{"), "JSON"),
        (raw(b"[" * 200_000), "JSON"),
    ):
        with pytest.raises(ProtocolError, match=message):
            read_frame(reader(data), 1024 * 1024)


def test_plugin_findings_are_rebuilt_strictly():
    finding = finding_from_plugin({
        "category": "plugin_fixture", "title": "Colour \x1b[31m title",
        "detail": "token ghp_" + "A" * 36, "analyzer": "secret-patterns",
        "severity": "HIGH", "confidence": "INFERRED", "evidence": ["x.py"],
        "code_evidence": [{"line_number": 3, "code": "api_key = 'abcdefghijklmnop'", "vulnerable": True}],
    }, "fixture")
    assert finding.analyzer == "fixture"
    assert "\x1b" not in finding.title
    assert "ghp_" not in finding.detail
    assert "abcdefghijklmnop" not in finding.code_evidence[0].code
    assert len(finding_from_plugin({"category": "c", "title": "t" * 5000}, "fixture").title) < 400
    for invalid in (
        "not an object",
        {"category": "bad category!", "title": "t"},
        {"category": "c", "title": ""},
        {"category": "c", "title": "t", "severity": "SEVERE"},
        {"category": "c", "title": "t", "evidence": ["x"] * 65},
        {"category": "c", "title": "t", "evidence": [1]},
        {"category": "c", "title": "t", "code_evidence": [{"line_number": True, "code": "x"}]},
        {"category": "c", "title": "t", "code_evidence": [{"line_number": 1, "code": 5}]},
    ):
        with pytest.raises(ValueError):
            finding_from_plugin(invalid, "fixture")


def test_plugin_metadata_is_validated():
    good = {"name": "ok", "version": "1", "api_version": 1, "description": "", "domains": [], "languages": ["Python"]}
    assert validate_metadata(good, set())["name"] == "ok"
    for change in (
        {"name": ""}, {"name": " padded"}, {"name": "x" * 65}, {"name": "unnamed"},
        {"name": "tab\there"}, {"api_version": 2}, {"api_version": True},
        {"domains": "testing"}, {"languages": [1]},
    ):
        with pytest.raises(ValueError):
            validate_metadata({**good, **change}, set())
    with pytest.raises(ValueError, match="duplicate"):
        validate_metadata(good, {"ok"})


def _run_bpf(program, number: int, architecture: int, arguments=()) -> int:
    """Execute the filter the way the kernel does for one system call."""
    arguments = (list(arguments) + [0] * 6)[:6]
    data = struct.pack("<iIQ6Q", number, architecture, 0, *arguments)
    counter, accumulator = 0, 0
    while True:
        code, true_offset, false_offset, constant = program[counter]
        if code == 0x20:
            accumulator = struct.unpack_from("<I", data, constant)[0]
            counter += 1
        elif code in (0x15, 0x35, 0x45):
            taken = {
                0x15: accumulator == constant,
                0x35: accumulator >= constant,
                0x45: bool(accumulator & constant),
            }[code]
            counter += 1 + (true_offset if taken else false_offset)
        elif code == 0x06:
            return constant
        else:
            raise AssertionError(f"unexpected BPF instruction {code:#x}")


@pytest.mark.parametrize("architecture", ["x86_64", "aarch64"])
def test_seccomp_filter_semantics(architecture):
    table = {**plugin_sandbox._SYSCALLS[architecture], **plugin_sandbox._UNIFIED_SYSCALLS}
    native = table["audit_arch"]
    program = plugin_sandbox.seccomp_program(architecture, own_pid=4242)
    allow, kill = 0x7FFF0000, 0x80000000

    def call(name, *arguments):
        return _run_bpf(program, table[name], native, arguments)

    def errno_result(code):
        return 0x00050000 | code

    assert call("socket", 2, 1) == errno_result(errno.EACCES)
    assert call("socketpair", 1) == allow
    assert call("socketpair", 2) == errno_result(errno.EACCES)
    assert call("clone", 0x00010000 | 0x00000100) == allow  # CLONE_THREAD | CLONE_VM
    assert call("clone", 17) == errno_result(errno.EPERM)   # fork: SIGCHLD only
    assert call("clone3") == errno_result(errno.ENOSYS)
    assert call("execve") == call("execveat") == call("ptrace") == errno_result(errno.EPERM)
    assert call("kill", 4242, 9) == call("tgkill", 4242, 4243, 9) == allow
    assert call("kill", 1, 9) == call("tgkill", 1, 1, 9) == errno_result(errno.EPERM)
    assert call("ioctl", 0, 0x5412) == errno_result(errno.EPERM)  # TIOCSTI
    assert call("ioctl", 0, 0x5401) == allow                       # TCGETS
    # Metadata writes that Landlock does not cover.
    for name in ("fchmodat", "fchmod", "fchownat", "utimensat", "fsetxattr", "truncate", "fchmodat2"):
        assert call(name) == errno_result(errno.EPERM), name
    # Resource and scheduling calls only on the calling process.
    assert call("prlimit64", 0, 7) == call("sched_setaffinity", 0) == allow
    assert call("prlimit64", 1, 7) == call("sched_setaffinity", 1) == errno_result(errno.EPERM)
    assert call("setpriority", 0, 0, 19) == errno_result(errno.EPERM)
    read = 0 if architecture == "x86_64" else 63
    assert _run_bpf(program, read, native) == allow
    assert _run_bpf(program, read, 0x40000003) == kill  # another architecture's ABI
    if architecture == "x86_64":
        assert _run_bpf(program, 0x40000000 | read, native) == kill  # x32 ABI
    for index, (code, true_offset, false_offset, _) in enumerate(program):
        if code in (0x15, 0x35, 0x45):
            assert index + 1 + max(true_offset, false_offset) < len(program)


def test_seatbelt_profile_is_deny_only_and_quotes_paths():
    profile = plugin_sandbox.seatbelt_profile(['/opt/py "x"', "/usr"], ["/etc/localtime"])
    lines = profile.splitlines()
    assert lines[:2] == ["(version 1)", "(allow default)"]
    assert not [line for line in lines[2:] if not line.startswith("(deny ")]
    for rule in ("(deny network*)", "(deny process-fork)", "(deny process-exec*)", "(deny mach-lookup)"):
        assert rule in lines
    assert '(require-not (subpath "/opt/py \\"x\\""))' in profile
    assert '(require-not (literal "/etc/localtime"))' in profile


def test_read_allowlist_keeps_the_runtime_and_hides_the_project(tmp_path, monkeypatch):
    project, output, library = tmp_path / "project", tmp_path / "out", tmp_path / "lib"
    environment = project / ".venv"
    for directory in (environment, output / "scratch", library):
        directory.mkdir(parents=True)
    monkeypatch.setattr(sys, "path", [str(project), str(environment), str(library), str(tmp_path)])
    config = {"exclude_paths": [str(project), str(output)], "scratch": str(output / "scratch")}

    def real(path) -> str:
        return os.path.realpath(path)

    directories, _files, exposed = plugin_sandbox.read_allowlist(config, [str(environment)])
    assert real(library) in directories and real(output / "scratch") in directories
    assert real(environment) in directories  # an interpreter inside the project stays usable
    assert real(project) not in directories and real(tmp_path) not in directories
    assert exposed == []
    _, _, exposed = plugin_sandbox.read_allowlist(config, [str(tmp_path)])
    assert {real(project), real(output)} <= set(exposed)


def test_host_environment_carries_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    environment = plugin_isolation._host_environment(tmp_path)
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["HOME"] == environment["TMPDIR"] == str(tmp_path)


def test_host_request_handlers(tmp_path, plugins):
    # The handlers run here in-process; lock-down and the descriptor swap only in hosts.
    from project_discovery import plugin_host
    from project_discovery.analyzers.base import Analyzer
    from project_discovery.models import FileRecord

    plugins()
    fixtures = ("pdt_fixture_inprocess", "pdt_fixture_plugins")
    for module in fixtures:  # import this test's copies, not ones cached by earlier tests
        sys.modules.pop(module, None)
    point = {"name": "in-process", "value": ENTRY_POINTS["in-process"], "group": "pdt.analyzers"}
    analyzer = plugin_host._load(point)
    metadata = validate_metadata(plugin_host._metadata(analyzer), set())
    assert (metadata["name"], metadata["api_version"]) == ("fixture-in-process", 1)
    assert plugin_host._plugin_locations(point["value"])[-1].endswith("pdt_fixture_inprocess.py")
    assert plugin_host._plugin_locations("no_such_module_anywhere:X") == []

    record = FileRecord("a.txt", 4, ".txt", "Text").to_dict()
    assert plugin_host._supports(analyzer, record) is True
    assert plugin_host._supports(analyzer, {**record, "path": "b.txt"}) is False
    assert plugin_host._supports(analyzer, {"unexpected": 1})["error"].startswith("TypeError")
    staged = tmp_path / "a.txt"
    staged.write_text("x", encoding="utf-8")
    [finding] = plugin_host._analyze(analyzer, {"record": record, "path": str(staged)})
    assert finding["detail"] == str(os.getpid())

    class Mixed(Analyzer):
        name = "mixed"

        def supports(self, record):
            return True

        def analyze(self, path, record):
            return ["not a finding"]

    assert plugin_host._analyze(Mixed(), {"record": record, "path": str(staged)}) == [{"invalid": "str"}]
    for value, error in (
        ("pdt_fixture_plugins:NOT_AN_ANALYZER", TypeError),
        ("pdt_fixture_broken:Anything", RuntimeError),
    ):
        with pytest.raises(error):
            plugin_host._load({**point, "value": value})
    for module in fixtures:
        sys.modules.pop(module, None)


def test_status_lines_print_markup_literally():
    # PDT-233: a path containing "[/x]" crashed the scan with a Rich MarkupError.
    from rich.console import Console

    from project_discovery.cli import _status

    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=200)
    _status(console, "INFO", "Read-only discovery: /work/repo[/x] [bold]y", "cyan")
    assert "/work/repo[/x] [bold]y" in buffer.getvalue()
