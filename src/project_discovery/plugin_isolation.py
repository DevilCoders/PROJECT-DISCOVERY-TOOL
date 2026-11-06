"""Run third-party analyzer plugins in sandboxed host processes.

PDT never imports a plugin itself. Each plugin runs in host processes
(``plugin_host``) that apply and verify the operating-system sandbox from
``plugin_sandbox`` before they import any plugin code. A host sees one file at a time,
as a private staged copy, and has no PDT state or environment secrets. Its answers are
plain JSON that is validated, bounded, redacted and attributed to the plugin here. A
host that crashes, hangs or breaks the protocol is killed and the file gets an
``UNKNOWN`` coverage finding; repeated host failures disable the plugin.
"""
from __future__ import annotations

import atexit
import os
import queue
import re
import shutil
import signal
import site
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .analyzers.base import Analyzer
from .models import CodeEvidence, FileRecord, Finding
from .plugin_protocol import (
    MAX_FINDINGS_PER_FILE,
    MAX_RESPONSE_BYTES,
    ProtocolError,
    encode_frame,
    read_frame,
)
from .plugin_sandbox import RESTRICTIONS, WindowsJob, required_restrictions
from .source_utils import open_verified_binary, redact_source_excerpt

ISOLATION_MODES = ("sandbox", "process", "off")
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MEMORY_LIMIT_MB = 4096
# Hosts get a private copy of each file; larger files are not handed to plugins.
MAX_PLUGIN_FILE_BYTES = 1024 * 1024 * 1024
# Consecutive host failures (crash, timeout, protocol violation) that disable a plugin.
HOST_FAILURE_LIMIT = 3
# Starting a host includes importing the plugin and its dependencies.
START_TIMEOUT_SECONDS = 60.0
_STDERR_TAIL_BYTES = 8192
_ENTRY_POINT_GROUP = "pdt.analyzers"
_WINDOWS = os.name == "nt"

# Started with ``python -I -B -c``: no environment variables, user site or current
# directory influence the interpreter, and no bytecode is written. The first frame on
# stdin carries the configuration, including PDT's import path.
_BOOTSTRAP = """\
import os, sys
def _read(size):
    data = b""
    while len(data) < size:
        chunk = os.read(0, size - len(data))
        if not chunk:
            raise SystemExit(70)
        data += chunk
    return data
import json, site
config = json.loads(_read(int.from_bytes(_read(4), "big")))
for directory in config["site_dirs"]:
    if directory not in sys.path:
        site.addsitedir(directory)
sys.path[:] = config["sys_path"] + [entry for entry in sys.path if entry not in config["sys_path"]]
from project_discovery.plugin_host import main
main(config)
"""
# Variables a host needs to run; everything else (tokens, keys, cloud credentials) stays
# with PDT. HOME and the temporary-directory variables point at the host's own folder.
_ENVIRONMENT_ALLOWLIST = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
_PRIVATE_DIRECTORY_VARIABLES = ("HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP")


class PluginHostError(RuntimeError):
    """A plugin host could not start, crashed, timed out or broke the protocol."""

    def __init__(self, message: str, *, sandbox: dict | None = None) -> None:
        super().__init__(message)
        self.sandbox = sandbox


class IsolatedPluginError(RuntimeError):
    """The plugin's own code raised, or its input or output was rejected."""


@dataclass(frozen=True)
class PluginPolicy:
    """How third-party plugins run. ``isolation`` is sandbox, process or off."""

    isolation: str = "sandbox"
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB
    # Where hosts get their staging directories (default: a private temp directory).
    work_dir: str | None = None
    # The scanned project and PDT's output: never on a host's import path or readable.
    exclude_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.isolation not in ISOLATION_MODES:
            raise ValueError(f"--plugin-isolation must be one of: {', '.join(ISOLATION_MODES)}")
        if not 0 < self.timeout_seconds <= 3600:
            raise ValueError("--plugin-timeout must be greater than 0 and at most 3600 seconds")
        if self.memory_limit_mb and not 256 <= self.memory_limit_mb <= 1024 * 1024:
            raise ValueError("--plugin-memory-mb must be 0 (no limit) or between 256 and 1048576")

    @property
    def required(self) -> tuple[str, ...]:
        return required_restrictions() if self.isolation == "sandbox" else ()


@dataclass(frozen=True)
class PluginSpec:
    """A plugin validated by the coordinator; worker processes rebuild proxies from it."""

    entry_point: str
    value: str
    distribution: str | None = None
    metadata: dict = field(default_factory=dict)


# ------------------------------------------------------------------ host processes

_default_work_dir: Path | None = None
_probe_paths_cache: dict[tuple[int, str], tuple[str, str]] = {}
_lock = threading.Lock()


def _work_dir(policy: PluginPolicy) -> Path:
    global _default_work_dir
    if policy.work_dir:
        path = Path(policy.work_dir)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path
    with _lock:
        if _default_work_dir is None or not _default_work_dir.is_dir():
            _default_work_dir = Path(tempfile.mkdtemp(prefix="pdt-plugins-"))
            atexit.register(shutil.rmtree, _default_work_dir, True)
        return _default_work_dir


def _probe_paths(work_dir: Path) -> tuple[str, str]:
    """A canary file and a directory outside every host's allowlist, per process."""
    key = (os.getpid(), str(work_dir))
    with _lock:
        if key not in _probe_paths_cache:
            root = Path(tempfile.mkdtemp(prefix="probe-", dir=work_dir))
            canary = root / "canary"
            canary.write_bytes(os.urandom(16))
            writes = root / "writes"
            writes.mkdir()
            _probe_paths_cache[key] = (str(canary), str(writes))
        return _probe_paths_cache[key]


def _interpreter() -> str:
    if getattr(sys, "frozen", False) or not sys.executable:
        raise PluginHostError("isolated plugins need a Python interpreter, and none is available")
    if _WINDOWS:
        # A virtual environment's python.exe is a launcher that starts the base
        # interpreter as a child process, which the host's job would forbid.
        return getattr(sys, "_base_executable", None) or sys.executable
    return sys.executable


def _host_import_path(excluded: Sequence[str]) -> tuple[list[str], list[str]]:
    import project_discovery

    excluded = [os.path.normcase(os.path.realpath(item)) for item in excluded]

    def inside_excluded(path: str) -> bool:
        real = os.path.normcase(os.path.realpath(path))
        return any(real == item or real.startswith(item.rstrip(os.sep) + os.sep) for item in excluded)

    # The PDT the coordinator runs comes first, so the host runs the same code.
    entries = [os.path.dirname(os.path.dirname(os.path.abspath(project_discovery.__file__)))]
    for entry in sys.path:
        if entry and not inside_excluded(entry):
            absolute = os.path.abspath(entry)
            if absolute not in entries:
                entries.append(absolute)
    site_dirs = [item for item in getattr(site, "getsitepackages", list)() if os.path.isdir(item)]
    if site.ENABLE_USER_SITE and os.path.isdir(site.getusersitepackages()):
        site_dirs.append(site.getusersitepackages())
    return entries, site_dirs


def _host_environment(scratch: Path) -> dict[str, str]:
    environment = {key: os.environ[key] for key in _ENVIRONMENT_ALLOWLIST if key in os.environ}
    environment.update(dict.fromkeys(_PRIVATE_DIRECTORY_VARIABLES, str(scratch)))
    return environment


class _Watchdog:
    """Kill hosts whose request deadline passed, even while PDT blocks on their pipes."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._deadlines: dict[PluginHost, float] = {}
        self._thread: threading.Thread | None = None

    def arm(self, host: "PluginHost", seconds: float) -> None:
        with self._condition:
            self._deadlines[host] = time.monotonic() + seconds
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="pdt-plugin-watchdog", daemon=True)
                self._thread.start()
            self._condition.notify()

    def disarm(self, host: "PluginHost") -> None:
        with self._condition:
            self._deadlines.pop(host, None)

    def _run(self) -> None:
        while True:
            with self._condition:
                if not self._deadlines:
                    self._condition.wait()
                    continue
                host, deadline = min(self._deadlines.items(), key=lambda item: item[1])
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    self._condition.wait(remaining)
                    continue
                del self._deadlines[host]
            host.kill("timeout")


_WATCHDOG = _Watchdog()


def _reset_after_fork() -> None:
    # A forked worker must not inherit a lock or deadlines from the coordinator.
    global _WATCHDOG, _lock
    _WATCHDOG = _Watchdog()
    _lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


def _text_list(value: Any, limit: int, item_limit: int, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"plugin {label} must be a list of at most {limit} strings")
    if not all(isinstance(item, str) and 0 < len(item) <= item_limit for item in value):
        raise ValueError(f"plugin {label} must be strings of 1-{item_limit} characters")
    return list(value)


def _validated_sandbox(value: Any, parent_mechanisms: list[str], policy: PluginPolicy) -> dict:
    report = value if isinstance(value, dict) else {}

    def strings(key: str, limit: int, length: int) -> list[str]:
        items = report.get(key)
        return [item[:length] for item in items[:limit] if isinstance(item, str)] if isinstance(items, list) else []

    restrictions = report.get("restrictions") if isinstance(report.get("restrictions"), dict) else {}
    mechanisms = parent_mechanisms + strings("mechanisms", 32, 80)
    memory_enforced = "rlimit-as" in mechanisms or "job-object" in mechanisms
    return {
        "platform": str(report.get("platform", sys.platform))[:40],
        "mechanisms": mechanisms,
        "restrictions": {name: restrictions.get(name) is True for name in RESTRICTIONS},
        "memory_limit_mb": policy.memory_limit_mb if memory_enforced and policy.memory_limit_mb else None,
        "environment": "allowlisted variables only",
        "file_access": "private staged copy of each analyzed file",
        "errors": strings("errors", 32, 500),
        "exposed_paths": strings("exposed_paths", 16, 1000),
    }


class PluginHost:
    """One host interpreter; it holds at most one plugin instance and serves one request at a time."""

    def __init__(self, policy: PluginPolicy, entry_point: dict | None) -> None:
        self.policy = policy
        self.closed = False
        self.sandbox: dict | None = None
        self.metadata: dict | None = None
        self._frames: queue.SimpleQueue = queue.SimpleQueue()
        self._stderr = b""
        self._sequence = 0
        self._staged = 0
        self._job: WindowsJob | None = None
        self._kill_reason: str | None = None
        work_dir = _work_dir(policy)
        self.scratch = Path(tempfile.mkdtemp(prefix="host-", dir=work_dir))
        (self.scratch / "readable.probe").write_bytes(b"ok")
        canary, write_dir = _probe_paths(work_dir)
        sys_path, site_dirs = _host_import_path(policy.exclude_paths)
        config = {
            "mode": policy.isolation,
            "required": list(policy.required),
            "sys_path": sys_path,
            "site_dirs": site_dirs,
            "scratch": str(self.scratch),
            "probe_canary": canary,
            "probe_write_dir": write_dir,
            "exclude_paths": list(policy.exclude_paths),
            "memory_limit_bytes": policy.memory_limit_mb * 1024 * 1024,
            "parent_pid": os.getpid(),
            "entry_point": entry_point,
        }
        if _WINDOWS:
            options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            options = {"start_new_session": True}  # no terminal signals, own process group
        appcontainer = _WINDOWS and policy.isolation == "sandbox"
        parent_mechanisms: list[str] = []
        try:
            if appcontainer:
                self.process = self._start_in_appcontainer(config, work_dir, entry_point)
                parent_mechanisms.append("job-object")
            else:
                self.process = subprocess.Popen(
                    [_interpreter(), "-I", "-B", "-c", _BOOTSTRAP],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    cwd=self.scratch, env=_host_environment(self.scratch), close_fds=True, **options,
                )
        except (OSError, PluginHostError) as exc:
            if self._job is not None:
                self._job.close()
                self._job = None
            shutil.rmtree(self.scratch, ignore_errors=True)
            if isinstance(exc, PluginHostError):
                raise
            raise PluginHostError(f"could not start a plugin host: {exc}") from exc
        try:
            if _WINDOWS and not appcontainer:
                try:
                    # The host waits for its configuration, so no plugin code has run yet.
                    self._job = WindowsJob(config["memory_limit_bytes"], confine=policy.isolation == "sandbox")
                    self._job.assign(self.process.pid)
                    parent_mechanisms.append("job-object")
                except OSError as exc:
                    if policy.isolation == "sandbox":
                        raise PluginHostError(f"could not confine the plugin host in a job object: {exc}") from exc
            threading.Thread(target=self._read_frames, name="pdt-plugin-reader", daemon=True).start()
            threading.Thread(target=self._drain_stderr, name="pdt-plugin-stderr", daemon=True).start()
            reply = self._exchange(config, max(START_TIMEOUT_SECONDS, policy.timeout_seconds))
            self.sandbox = _validated_sandbox(reply.get("sandbox"), parent_mechanisms, policy)
            if reply.get("ok") is not True:
                stage = "sandbox setup" if reply.get("stage") == "sandbox" else "plugin load"
                error = str(reply.get("error", "unknown error"))[:2000]
                raise PluginHostError(f"{stage} failed: {error}", sandbox=self.sandbox)
            missing = [name for name in policy.required if not self.sandbox["restrictions"][name]]
            if missing:
                raise PluginHostError(
                    "the sandbox could not deny " + ", ".join(missing).replace("_", " "),
                    sandbox=self.sandbox,
                )
            self.metadata = reply.get("metadata")
        except BaseException:
            self.close(graceful=False)
            raise

    def _start_in_appcontainer(self, config: dict, work_dir: Path, entry_point: dict | None):
        """Windows sandbox mode: start the host suspended in the capability-free AppContainer.

        The host imports only staged copies: the standard-library runtime, PDT's package and
        the plugin with its dependencies, all in folders PDT granted to the container.
        """
        from . import plugin_appcontainer as appcontainer

        try:
            shared = appcontainer.prepared()
            site = appcontainer.stage_site(shared.container, work_dir, entry_point)
            shared.container.grant_read(self.scratch)  # inherited by every staged input
        except OSError as exc:
            raise PluginHostError(f"could not prepare the Windows AppContainer: {exc}") from exc
        config.update(
            sys_path=[str(site)], site_dirs=[str(site)], appcontainer=True, probe_port=shared.probe_port,
        )
        try:
            self._job = WindowsJob(config["memory_limit_bytes"], confine=True)
        except OSError as exc:
            raise PluginHostError(f"could not confine the plugin host in a job object: {exc}") from exc
        python = str(shared.runtime / "python.exe")
        return appcontainer.AppContainerProcess(
            [python, "-I", "-B", "-c", _BOOTSTRAP], executable=python, cwd=str(self.scratch),
            env=appcontainer.host_environment(self.scratch), container=shared.container, job=self._job,
        )

    # The protocol stream is read by a thread so that PDT can apply timeouts portably.
    def _read_frames(self) -> None:
        try:
            while True:
                message = read_frame(self.process.stdout.read, MAX_RESPONSE_BYTES)
                if message is None:
                    self._frames.put(("exit", "exited"))
                    return
                self._frames.put(("frame", message))
        except ProtocolError as exc:
            self._frames.put(("violation", f"broke the protocol ({exc})"))
        except (OSError, ValueError):
            self._frames.put(("exit", "exited"))

    def _drain_stderr(self) -> None:
        try:
            while chunk := self.process.stderr.read1(65536):
                self._stderr = (self._stderr + chunk)[-_STDERR_TAIL_BYTES:]
        except (OSError, ValueError):
            pass

    def stderr_tail(self) -> str:
        lines = [line for line in self._stderr.decode("utf-8", "replace").splitlines() if line.strip()]
        return redact_source_excerpt(" | ".join(lines[-2:]), max_chars=160) if lines else ""

    def _failure(self, detail: str, timeout: float) -> PluginHostError:
        if self._kill_reason == "timeout":
            message = f"plugin host did not answer within {timeout:g} s and was stopped"
        else:
            message = f"plugin host {detail}"
            try:
                code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                code = None
            if code is not None:
                if code < 0 and not _WINDOWS:
                    try:
                        message += f" (killed by {signal.Signals(-code).name})"
                    except ValueError:
                        message += f" (killed by signal {-code})"
                else:
                    message += f" (exit status {code})"
        tail = self.stderr_tail()
        return PluginHostError(message + (f"; last output: {tail}" if tail else ""))

    def _exchange(self, message: dict, timeout: float) -> dict:
        _WATCHDOG.arm(self, timeout)
        try:
            try:
                self.process.stdin.write(encode_frame(message))
                self.process.stdin.flush()
            except (OSError, ValueError):
                self.kill("exited")
                raise self._failure("stopped accepting requests", timeout) from None
            try:
                kind, value = self._frames.get(timeout=timeout + 10)
            except queue.Empty:
                self.kill("timeout")
                raise self._failure("timed out", timeout) from None
        finally:
            _WATCHDOG.disarm(self)
        if kind != "frame":
            self.kill(kind)
            raise self._failure(value, timeout)
        return value

    def request(self, message: dict, timeout: float) -> dict:
        self._sequence += 1
        reply = self._exchange({**message, "id": self._sequence}, timeout)
        if reply.get("id") != self._sequence or not isinstance(reply.get("ok"), bool):
            self.kill("violation")
            raise PluginHostError("plugin host broke the protocol (reply does not match the request)")
        return reply

    def stage(self, path: Path, record: FileRecord) -> Path:
        """Copy the verified file into the host's private folder, under its own name."""
        self._staged += 1
        folder = self.scratch / "in" / str(self._staged)
        folder.mkdir(parents=True)
        name = path.name if path.name not in {"", ".", ".."} and len(path.name) <= 200 else "content" + path.suffix[:16]
        target = folder / name
        remaining = MAX_PLUGIN_FILE_BYTES
        try:
            with open_verified_binary(path, record.analysis_identity) as source, open(target, "xb") as sink:
                while chunk := source.read(1024 * 1024):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise IsolatedPluginError(
                            f"file exceeds the {MAX_PLUGIN_FILE_BYTES // (1024 * 1024):,} MiB "
                            "isolated-plugin limit and was not handed to the plugin"
                        )
                    sink.write(chunk)
        except BaseException:
            self.unstage(target)
            raise
        return target

    def unstage(self, target: Path) -> None:
        shutil.rmtree(target.parent, ignore_errors=True)

    @property
    def alive(self) -> bool:
        return not self.closed and self._kill_reason is None and self.process.poll() is None

    def kill(self, reason: str | None = None) -> None:
        if reason and self._kill_reason is None:
            self._kill_reason = reason
        if self.process.poll() is not None:
            return
        try:
            if self._job is not None:
                self._job.terminate()
            elif not _WINDOWS:
                os.killpg(self.process.pid, signal.SIGKILL)  # also any process it started
            else:
                self.process.kill()
        except OSError:
            try:
                self.process.kill()
            except OSError:
                pass

    def close(self, *, graceful: bool = True) -> None:
        if self.closed:
            return
        self.closed = True
        _WATCHDOG.disarm(self)
        try:
            if graceful and self.process.poll() is None:
                try:
                    self.process.stdin.write(encode_frame({"op": "exit"}))
                    self.process.stdin.flush()
                    self.process.wait(timeout=2)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
        finally:
            self.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
            release = getattr(self.process, "close_handle", None)
            if release is not None:
                release()
            if self._job is not None:
                self._job.close()
            shutil.rmtree(self.scratch, ignore_errors=True)


# ------------------------------------------------------------------ validation

_NAME_LIMIT = 64
_CATEGORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
# C0/C1 controls (except tab and newline) could rewrite terminal output.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_CONFIDENCES = {"CONFIRMED", "INFERRED", "UNKNOWN"}
_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_MAX_EVIDENCE_ITEMS = 64


def _bounded_text(value: Any, limit: int, label: str, *, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{label} must be {'a non-empty' if required else 'a'} string")
    return redact_source_excerpt(_CONTROL_CHARACTERS.sub("�", value), max_chars=limit)


def validate_metadata(value: Any, reserved_names: set[str]) -> dict:
    """Check what a host reports about its plugin before PDT relies on it."""
    if not isinstance(value, dict):
        raise ValueError("the plugin host returned no analyzer metadata")
    name = value.get("name")
    if (
        not isinstance(name, str) or not 0 < len(name) <= _NAME_LIMIT
        or not name.isprintable() or name.strip() != name or name == "unnamed"
    ):
        raise ValueError(f"plugin analyzer must define a stable name of 1-{_NAME_LIMIT} printable characters")
    if name in reserved_names:
        raise ValueError(f"duplicate analyzer name: {name}")
    if value.get("api_version") != 1 or isinstance(value.get("api_version"), bool):
        raise ValueError(f"unsupported analyzer API version: {value.get('api_version')!r}")
    return {
        "name": name,
        "version": _bounded_text(value.get("version", ""), 64, "version"),
        "api_version": 1,
        "description": _bounded_text(value.get("description", ""), 1000, "description"),
        "domains": _text_list(value.get("domains", []), 64, 64, "domains"),
        "languages": _text_list(value.get("languages", []), 256, 64, "languages"),
    }


def finding_from_plugin(item: Any, analyzer_name: str) -> Finding:
    """Rebuild one plugin finding from JSON. The plugin cannot choose ``analyzer``."""
    if not isinstance(item, dict):
        raise ValueError("finding is not an object")
    category = item.get("category")
    if not isinstance(category, str) or not _CATEGORY.fullmatch(category):
        raise ValueError("finding category must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
    confidence = item.get("confidence", "CONFIRMED")
    severity = item.get("severity", "INFO")
    if confidence not in _CONFIDENCES or severity not in _SEVERITIES:
        raise ValueError("finding confidence or severity is not a PDT value")
    evidence = item.get("evidence") or []
    code_evidence = item.get("code_evidence") or []
    if not isinstance(evidence, list) or len(evidence) > _MAX_EVIDENCE_ITEMS:
        raise ValueError(f"finding evidence must be a list of at most {_MAX_EVIDENCE_ITEMS} strings")
    if not isinstance(code_evidence, list) or len(code_evidence) > _MAX_EVIDENCE_ITEMS:
        raise ValueError(f"finding code evidence must be a list of at most {_MAX_EVIDENCE_ITEMS} lines")
    lines = []
    for entry in code_evidence:
        if not isinstance(entry, dict):
            raise ValueError("code evidence must be objects")
        number, code, vulnerable = entry.get("line_number"), entry.get("code"), entry.get("vulnerable", True)
        if not isinstance(number, int) or isinstance(number, bool) or not 0 <= number <= 10**9:
            raise ValueError("code evidence line numbers must be integers")
        if not isinstance(code, str) or not isinstance(vulnerable, bool):
            raise ValueError("code evidence must carry a source line string")
        # CodeEvidence redacts and bounds the line itself.
        lines.append(CodeEvidence(number, _CONTROL_CHARACTERS.sub("�", code[:4000]), vulnerable))
    return Finding(
        category=category,
        title=_bounded_text(item.get("title"), 300, "title", required=True),
        detail=_bounded_text(item.get("detail", ""), 8000, "detail"),
        confidence=confidence,
        evidence=[_bounded_text(entry, 1000, "evidence") for entry in evidence],
        analyzer=analyzer_name,
        severity=severity,
        code_evidence=lines,
        impact=_bounded_text(item.get("impact"), 4000, "impact") or None,
        recommendation=_bounded_text(item.get("recommendation"), 4000, "recommendation") or None,
    )


# ------------------------------------------------------------------ the proxy

class IsolatedAnalyzer(Analyzer):
    """Presents a sandboxed plugin to the analysis engine as an ordinary analyzer.

    Each host holds its own plugin instance and serves one request at a time, so the
    proxy is safe to call concurrently: it starts another host when all are busy.
    """

    concurrent_safe = True

    def __init__(self, spec: PluginSpec, policy: PluginPolicy, host: PluginHost | None = None) -> None:
        metadata = spec.metadata
        self.spec = spec
        self.policy = policy
        self.name = metadata["name"]
        self.version = metadata["version"]
        self.description = metadata["description"]
        self.domains = tuple(metadata["domains"])
        self.languages = tuple(metadata["languages"])
        self.sandbox = host.sandbox if host is not None else None
        self._lock = threading.Lock()
        self._idle: list[PluginHost] = [host] if host is not None else []
        self._hosts: set[PluginHost] = set(self._idle)
        self._local = threading.local()
        self._failures = 0
        self._disabled: str | None = None
        self._closed = False

    def _acquire(self) -> PluginHost:
        dead, ready = [], None
        with self._lock:
            if self._closed:
                raise PluginHostError("plugin hosts were shut down")
            while self._idle and ready is None:
                host = self._idle.pop()
                if host.alive:
                    ready = host
                else:
                    self._hosts.discard(host)
                    dead.append(host)
        for host in dead:
            host.close(graceful=False)
        if ready is not None:
            return ready
        host = PluginHost(self.policy, {
            "name": self.spec.entry_point, "value": self.spec.value, "group": _ENTRY_POINT_GROUP,
            "distribution": self.spec.distribution,
        })
        if not isinstance(host.metadata, dict) or host.metadata.get("name") != self.name:
            host.close(graceful=False)
            raise PluginHostError("the plugin reported a different analyzer name in a new host")
        if self.sandbox is None:
            self.sandbox = host.sandbox
        with self._lock:
            if self._closed:
                host.close(graceful=False)
                raise PluginHostError("plugin hosts were shut down")
            self._hosts.add(host)
        return host

    def _release(self, host: PluginHost) -> None:
        with self._lock:
            if host.alive and not self._closed:
                self._idle.append(host)
                return
            self._hosts.discard(host)
        host.close(graceful=False)

    def _host_failed(self, host: PluginHost | None, error: PluginHostError) -> Exception:
        if host is not None:
            host.kill("failed")
        with self._lock:
            self._failures += 1
            if self._failures < HOST_FAILURE_LIMIT or self._disabled:
                return error
            self._disabled = str(error)
        # First, so the notice survives the excerpt length limit of coverage findings.
        return PluginHostError(
            f"plugin disabled for the rest of this scan after {HOST_FAILURE_LIMIT} consecutive "
            f"host failures, so later files were not analyzed by it. Last failure: {error}"
        )

    def _succeeded(self) -> None:
        with self._lock:
            self._failures = 0

    def _call(self, message: dict, prepare=None) -> dict:
        try:
            host = self._acquire()
        except PluginHostError as exc:  # a replacement host could not start
            raise self._host_failed(None, exc) from None
        try:
            staged = prepare(host) if prepare is not None else None
            try:
                reply = host.request(
                    {**message, "path": str(staged)} if staged is not None else message,
                    self.policy.timeout_seconds,
                )
            finally:
                if staged is not None:
                    host.unstage(staged)
        except PluginHostError as exc:
            raise self._host_failed(host, exc) from None
        finally:
            self._release(host)
        self._succeeded()
        return reply

    def _support_decisions(self, records: Sequence[FileRecord]) -> list:
        reply = self._call({"op": "supports", "records": [record.to_dict() for record in records]})
        results = reply.get("results")
        if reply.get("ok") is not True:
            raise IsolatedPluginError(str(reply.get("error", "supports() failed"))[:2000])
        if not isinstance(results, list) or len(results) != len(records):
            raise IsolatedPluginError("plugin host returned malformed supports() results")
        decisions = []
        for result in results:
            if isinstance(result, bool):
                decisions.append(result)
            elif isinstance(result, dict) and isinstance(result.get("error"), str):
                decisions.append(IsolatedPluginError(result["error"][:2000]))
            else:
                decisions.append(IsolatedPluginError("plugin host returned a malformed supports() result"))
        return decisions

    def supports_many(self, records: Sequence[FileRecord]) -> None:
        """Ask the plugin about a whole batch in one round trip; supports() uses the answers."""
        self._local.decisions = None
        if self._disabled or not records:
            return
        decisions = self._support_decisions(records)
        self._local.decisions = dict(zip((record.path for record in records), decisions, strict=True))

    def supports(self, record: FileRecord) -> bool:
        if self._disabled:
            return False
        pending = getattr(self._local, "decisions", None)
        if pending is not None and record.path in pending:
            decision = pending.pop(record.path)
        else:
            decision = self._support_decisions([record])[0]
        if isinstance(decision, Exception):
            raise decision
        return decision

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if self._disabled:
            return []
        if record.size_bytes > MAX_PLUGIN_FILE_BYTES:
            raise IsolatedPluginError(
                f"file exceeds the {MAX_PLUGIN_FILE_BYTES // (1024 * 1024):,} MiB isolated-plugin "
                "limit and was not handed to the plugin"
            )
        reply = self._call(
            {"op": "analyze", "record": record.to_dict()},
            prepare=lambda host: host.stage(Path(path), record),
        )
        if reply.get("ok") is not True:
            raise IsolatedPluginError(str(reply.get("error", "analyze() failed"))[:2000])
        items = reply.get("findings")
        if not isinstance(items, list):
            raise IsolatedPluginError("plugin host returned malformed findings")
        findings, rejected = [], []
        for item in items[:MAX_FINDINGS_PER_FILE]:
            try:
                findings.append(finding_from_plugin(item, self.name))
            except ValueError as exc:
                rejected.append(str(exc))
        truncated = len(items) > MAX_FINDINGS_PER_FILE
        if rejected or truncated:
            problems = []
            if rejected:
                problems.append(f"{len(rejected):,} invalid finding(s) were discarded ({rejected[0]})")
            if truncated:
                problems.append(f"findings beyond the first {MAX_FINDINGS_PER_FILE:,} were dropped")
            findings.append(Finding(
                "analysis_coverage",
                f"Plugin output rejected: {self.name}: {record.path}",
                "; ".join(problems) + ". This plugin's results for the file are incomplete.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            ))
        return findings

    def release_hosts(self) -> None:
        """Stop idle hosts now; the proxy starts new ones if it is used again."""
        with self._lock:
            idle, self._idle = self._idle, []
            self._hosts.difference_update(idle)
        for host in idle:
            host.close()

    def close(self, *, graceful: bool = True) -> None:
        with self._lock:
            self._closed = True
            hosts, self._hosts, self._idle = list(self._hosts), set(), []
        for host in hosts:
            host.close(graceful=graceful)


# ------------------------------------------------------------------ loading

@dataclass
class IsolatedLoadResult:
    analyzers: list[IsolatedAnalyzer] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    statuses: list[dict] = field(default_factory=list)
    specs: list[PluginSpec] = field(default_factory=list)


def load_isolated_plugins(points, policy: PluginPolicy, *, reserved_names: set[str]) -> IsolatedLoadResult:
    """Start one host per plugin to load and validate it; keep the host for reuse."""
    result = IsolatedLoadResult()
    names = set(reserved_names)
    for point in points:
        name = str(getattr(point, "name", "?"))
        value = getattr(point, "value", None)
        distribution = getattr(getattr(point, "dist", None), "name", None)
        status: dict[str, Any] = {"entry_point": name, "distribution": distribution, "isolation": policy.isolation}
        host = None
        try:
            if not isinstance(value, str) or not value.strip():
                raise PluginHostError("the entry point does not name an importable object")
            host = PluginHost(policy, {
                "name": name, "value": value, "group": _ENTRY_POINT_GROUP, "distribution": distribution,
            })
            metadata = validate_metadata(host.metadata, names)
        except (PluginHostError, ValueError, OSError) as exc:
            if host is not None:
                host.close(graceful=False)
            result.diagnostics.append(f"Plugin {name!r} failed to load: {exc}")
            status.update(status="failed", error=str(exc)[:2000])
            if getattr(exc, "sandbox", None) or (host is not None and host.sandbox):
                status["sandbox"] = getattr(exc, "sandbox", None) or host.sandbox
            result.statuses.append(status)
            continue
        names.add(metadata["name"])
        spec = PluginSpec(name, value, distribution, metadata)
        result.analyzers.append(IsolatedAnalyzer(spec, policy, host))
        result.specs.append(spec)
        status.update(status="loaded", name=metadata["name"], version=metadata["version"], sandbox=host.sandbox)
        result.statuses.append(status)
    return result


def isolated_analyzers(specs: Sequence[PluginSpec], policy: PluginPolicy) -> list[IsolatedAnalyzer]:
    """Proxies for already-validated plugins; their hosts start on first use."""
    return [IsolatedAnalyzer(spec, policy) for spec in specs]


def probe_sandbox(policy: PluginPolicy | None = None) -> dict:
    """Start a host without a plugin and report which restrictions it verified."""
    policy = policy or PluginPolicy()
    if policy.isolation == "off":
        return {"available": False, "isolation": "off", "error": "plugins run in-process"}
    try:
        host = PluginHost(policy, None)
    except PluginHostError as exc:
        return {"available": False, "isolation": policy.isolation, "error": str(exc), "sandbox": exc.sandbox}
    try:
        return {"available": True, "isolation": policy.isolation, "sandbox": host.sandbox}
    finally:
        host.close()
