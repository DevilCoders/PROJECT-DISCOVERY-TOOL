"""Isolated plugin host: one third-party analyzer in a sandboxed interpreter.

PDT starts this module in a fresh interpreter (``python -I -B``) for every host. The
host moves its protocol pipes to private descriptors, applies and verifies the
operating-system sandbox, and only then imports the plugin, so plugin code (including
its import-time code) never runs unconfined. It then answers ``supports`` and
``analyze`` requests until PDT closes the pipe. Nothing here is trusted by PDT: every
reply is validated by ``plugin_isolation`` before it reaches a report.
"""
from __future__ import annotations

import importlib.util
import os
import signal
import sys
import threading
import time
from importlib.metadata import EntryPoint
from pathlib import Path

from . import plugin_sandbox
from . import source_utils  # noqa: F401  # imported before lock-down for plugins to use
from .analyzers.base import Analyzer
from .models import FileRecord, Finding
from .plugin_protocol import (
    MAX_FINDINGS_PER_FILE,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ProtocolError,
    encode_frame,
    read_frame,
)


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:2000]


class _Channel:
    """The protocol stream, moved off the standard descriptors.

    Afterwards descriptor 0 reads from the null device and descriptor 1 writes to
    stderr, so a plugin that reads stdin or prints cannot corrupt the protocol.
    """

    def __init__(self) -> None:
        self._input = os.dup(0)
        self._output = os.dup(1)
        try:
            null = os.open(os.devnull, os.O_RDWR)
        except OSError:
            # A Windows AppContainer may not open the null device; a pipe whose writer
            # is closed reads as end-of-file just the same.
            null, writer = os.pipe()
            os.close(writer)
        os.dup2(null, 0)
        os.dup2(2, 1)
        os.close(null)

    def _read(self, size: int) -> bytes:
        chunks, remaining = [], size
        while remaining:
            chunk = os.read(self._input, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def receive(self) -> dict | None:
        return read_frame(self._read, MAX_REQUEST_BYTES)

    def send(self, message: dict) -> None:
        try:
            data = encode_frame(message)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ValueError(f"result of {len(data):,} bytes exceeds the {MAX_RESPONSE_BYTES:,}-byte limit")
        except (TypeError, ValueError) as exc:
            data = encode_frame({
                "id": message.get("id"), "ok": False,
                "error": f"plugin result could not be sent: {_describe(exc)}",
            })
        view = memoryview(data)
        while view:
            view = view[os.write(self._output, view):]


def _plugin_locations(value: str) -> list[str]:
    """Locate the plugin's top-level package without executing any of its code."""
    top_level = value.split(":", 1)[0].strip().split(".", 1)[0]
    try:
        spec = importlib.util.find_spec(top_level)
    except (ImportError, ValueError):
        return []
    if spec is None:
        return []
    locations = list(spec.submodule_search_locations or [])
    if spec.origin and os.path.isabs(spec.origin):
        locations.append(spec.origin)
    return locations


def _load(point: dict) -> Analyzer:
    loaded = EntryPoint(name=point["name"], value=point["value"], group=point["group"]).load()
    candidate = loaded() if callable(loaded) and not isinstance(loaded, Analyzer) else loaded
    if not isinstance(candidate, Analyzer):
        raise TypeError("entry point must load an Analyzer subclass or instance")
    if candidate.api_version != 1:
        raise ValueError(f"unsupported analyzer API version: {candidate.api_version!r}")
    if not candidate.name or candidate.name == "unnamed":
        raise ValueError("plugin analyzer must define a stable non-empty name")
    return candidate


def _metadata(analyzer: Analyzer) -> dict:
    return {
        "name": str(analyzer.name),
        "version": str(analyzer.version),
        "api_version": analyzer.api_version,
        "description": str(analyzer.description),
        "domains": [str(item) for item in analyzer.domains],
        "languages": [str(item) for item in analyzer.languages],
    }


def _watch_parent(parent_pid: int) -> None:
    """Exit if PDT goes away while plugin code is busy (POSIX reparents orphans)."""
    def watch() -> None:
        while True:
            time.sleep(1.0)
            if os.getppid() != parent_pid:
                os._exit(0)

    threading.Thread(target=watch, name="pdt-parent-watch", daemon=True).start()


def _supports(analyzer: Analyzer, item: dict):
    try:
        return bool(analyzer.supports(FileRecord(**item)))
    except BaseException as exc:  # plugin code may raise SystemExit
        return {"error": _describe(exc)}


def _analyze(analyzer: Analyzer, request: dict) -> list[dict]:
    record = FileRecord(**request["record"])
    findings: list[dict] = []
    for item in analyzer.analyze(Path(request["path"]), record):
        if len(findings) > MAX_FINDINGS_PER_FILE:
            break  # PDT reports the truncation
        findings.append(item.to_dict() if isinstance(item, Finding) else {"invalid": type(item).__name__})
    return findings


def _serve(channel: _Channel, analyzer: Analyzer) -> None:
    while True:
        try:
            request = channel.receive()
        except ProtocolError:
            return
        if request is None or request.get("op") == "exit":
            return
        try:
            operation = request.get("op")
            if operation == "supports":
                reply = {"results": [_supports(analyzer, item) for item in request["records"]]}
            elif operation == "analyze":
                reply = {"findings": _analyze(analyzer, request)}
            else:
                raise ValueError(f"unknown request {operation!r}")
            reply.update(id=request.get("id"), ok=True)
        except BaseException as exc:  # plugin code may raise SystemExit or KeyboardInterrupt
            reply = {"id": request.get("id"), "ok": False, "error": _describe(exc)}
        channel.send(reply)


def main(config: dict) -> None:
    channel = _Channel()
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # PDT handles Ctrl-C and stops hosts
    report = {
        "platform": sys.platform, "mechanisms": [], "errors": [], "exposed_paths": [],
        "restrictions": dict.fromkeys(plugin_sandbox.RESTRICTIONS, False),
    }
    point = config.get("entry_point")
    try:
        if config["mode"] == "sandbox":
            essential = [os.path.dirname(os.path.abspath(__file__))]
            if point is not None:
                essential += _plugin_locations(point["value"])
            directories, files, exposed = plugin_sandbox.read_allowlist(config, essential)
            listener = plugin_sandbox.prepare_probes()
            report.update(plugin_sandbox.lock_down(config, directories, files))
            report["restrictions"] = plugin_sandbox.run_probes(config, listener)
            if exposed:
                report["restrictions"][plugin_sandbox.FILESYSTEM_READS] = False
                report["exposed_paths"] = exposed
                report["errors"].append(
                    "reads cannot be restricted: a runtime path contains " + ", ".join(exposed)
                )
            missing = [name for name in config["required"] if not report["restrictions"][name]]
            if missing:
                channel.send({
                    "ok": False, "stage": "sandbox", "sandbox": report,
                    "error": "the sandbox could not deny " + ", ".join(missing).replace("_", " "),
                })
                return
        else:
            report["mechanisms"] = plugin_sandbox.resource_limits(config, sandbox=False)
    except Exception as exc:
        channel.send({"ok": False, "stage": "sandbox", "sandbox": report, "error": _describe(exc)})
        return
    if os.name != "nt":
        _watch_parent(config["parent_pid"])
    if point is None:
        channel.send({"ok": True, "sandbox": report})
        return
    try:
        analyzer = _load(point)
        metadata = _metadata(analyzer)
    except BaseException as exc:  # an import may raise anything, including SystemExit
        channel.send({"ok": False, "stage": "load", "sandbox": report, "error": _describe(exc)})
        return
    channel.send({"ok": True, "sandbox": report, "metadata": metadata})
    _serve(channel, analyzer)
