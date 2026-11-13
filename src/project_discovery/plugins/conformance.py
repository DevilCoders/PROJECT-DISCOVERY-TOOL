"""Conformance checks for third-party analyzer plugins (``pdt plugin-check``).

A plugin is loaded the way a scan loads it: in a host process under the requested
isolation (the operating-system sandbox by default), through the same JSON protocol, and
its metadata and findings are validated by the same code that validates them during a
scan. The check then runs ``supports()`` and ``analyze()`` on sample files and reports
every problem a scan would turn into a load failure, an ``UNKNOWN`` coverage finding or a
silently changed finding, so plugin authors can see and fix them before release.

Use it from a test suite with :func:`assert_conformant`, or from the command line::

    pdt plugin-check my_package.analyzer:MyAnalyzer tests/samples/
"""
from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Sequence

from ..catalog.languages import detect_language
from ..core.source_utils import neutralize_controls, redact_source_excerpt
from ..inventory.scanner import _classify_file, _is_hidden, _size_bucket
from ..inventory.signatures import apply_classification
from ..models import FileRecord
from .isolation import (
    MAX_PLUGIN_FILE_BYTES,
    PluginHost,
    PluginHostError,
    PluginPolicy,
    finding_from_plugin,
    validate_metadata,
)
from .protocol import MAX_FINDINGS_PER_FILE, MAX_RESPONSE_BYTES

ENTRY_POINT_GROUP = "pdt.analyzers"
MAX_SAMPLE_FILES = 200


def _clean(text: str) -> str:
    return redact_source_excerpt(neutralize_controls(str(text)), max_chars=2000)


@dataclass(frozen=True)
class Problem:
    severity: str   # "error": a scan would fail or drop results; "warning": worth fixing
    check: str
    message: str
    path: str = ""

    def to_dict(self) -> dict:
        return {"severity": self.severity, "check": self.check, "message": self.message, "path": self.path}


@dataclass
class ConformanceReport:
    entry_point: str
    isolation: str
    metadata: dict | None = None
    sandbox: dict | None = None
    files: list[dict] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(problem.severity == "error" for problem in self.problems)

    # Messages carry plugin-supplied text (exception messages, load errors): they are
    # neutralized and redacted like scan diagnostics, so a plugin under test cannot rewrite
    # the verdict on the operator's terminal or print a credential.
    def error(self, check: str, message: str, path: str = "") -> None:
        self.problems.append(Problem("error", check, _clean(message), _clean(path)))

    def warning(self, check: str, message: str, path: str = "") -> None:
        self.problems.append(Problem("warning", check, _clean(message), _clean(path)))

    def to_dict(self) -> dict:
        return {
            "entry_point": self.entry_point, "isolation": self.isolation, "ok": self.ok,
            "metadata": self.metadata, "sandbox": self.sandbox, "files": self.files,
            "problems": [problem.to_dict() for problem in self.problems],
        }


def resolve_entry_point(target: str) -> tuple[str, str, str | None]:
    """(entry-point name, ``module:attribute`` value, distribution) for a value or an installed name."""
    if ":" in target:
        return "plugin-check", target, None
    for point in entry_points(group=ENTRY_POINT_GROUP):
        if point.name == target:
            return point.name, point.value, getattr(getattr(point, "dist", None), "name", None)
    raise ValueError(f"no installed {ENTRY_POINT_GROUP} entry point is named {target!r}; "
                     "pass a module:attribute value instead")


def _sample_files(samples: Sequence[Path]) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for sample in samples:
        sample = Path(sample)
        if sample.is_dir():
            for directory, names, filenames in os.walk(sample):
                names.sort()
                for name in sorted(filenames):
                    path = Path(directory, name)
                    if not path.is_symlink():
                        files.append((path, path.relative_to(sample).as_posix()))
        elif sample.is_file():
            files.append((sample, sample.name))
        else:
            raise ValueError(f"sample not found: {sample}")
    return files  # check_plugin checks the first MAX_SAMPLE_FILES and reports the rest


def _record(path: Path, relative: str) -> FileRecord:
    """The FileRecord a scan builds for ``path``: the same classification and metadata.

    A stub with a fixed file type and default size bucket, hidden flag, permissions and
    modification time made plugins that decide on those fields behave differently here
    than in a scan, which defeated the check.
    """
    info = path.lstat()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    classification, opened_identity = _classify_file(path, relative, identity)
    record = FileRecord(
        relative, info.st_size, Path(relative).suffix.lower(), detect_language(relative),
        size_bucket=_size_bucket(info.st_size),
        is_hidden=_is_hidden(path.name, info), permissions=stat.S_IMODE(info.st_mode),
        mtime_ns=info.st_mtime_ns, analysis_identity=opened_identity or identity,
    )
    apply_classification(record, classification)
    return record


def check_plugin(target: str, samples: Sequence[Path] = (), *, isolation: str = "sandbox",
                 timeout_seconds: float = 60.0, memory_limit_mb: int = 4096,
                 reserved_names: set[str] | None = None) -> ConformanceReport:
    """Load ``target`` (``module:attribute`` or an installed entry-point name) and check it."""
    name, value, distribution = resolve_entry_point(target)
    report = ConformanceReport(value, isolation)
    if reserved_names is None:
        from ..analyzers import builtin_analyzers

        reserved_names = {analyzer.name for analyzer in builtin_analyzers()}
    policy = PluginPolicy(isolation=isolation, timeout_seconds=timeout_seconds, memory_limit_mb=memory_limit_mb)
    try:
        host = PluginHost(policy, {"name": name, "value": value, "group": ENTRY_POINT_GROUP,
                                   "distribution": distribution})
    except PluginHostError as exc:
        report.sandbox = exc.sandbox
        report.error("load", str(exc))
        return report
    try:
        report.sandbox = host.sandbox
        try:
            metadata = validate_metadata(host.metadata, reserved_names)
        except ValueError as exc:
            report.error("metadata", str(exc))
            return report
        report.metadata = metadata
        if not metadata["version"]:
            report.warning("metadata", "set a version so reports can say which release produced a finding")
        if not metadata["description"]:
            report.warning("metadata", "add a description; pdt capabilities shows it")
        files = _sample_files(samples)
        if not files:
            report.warning("samples", "no sample files were given, so supports() and analyze() were not run")
        if len(files) > MAX_SAMPLE_FILES:
            # Never a silent omission: say how many sample files were not checked.
            report.warning("samples", f"only the first {MAX_SAMPLE_FILES:,} of {len(files):,} sample files "
                           f"were checked; {len(files) - MAX_SAMPLE_FILES:,} were not")
            files = files[:MAX_SAMPLE_FILES]
        for path, relative in files:
            _check_file(host, metadata["name"], path, relative, report)
        if files and not any(entry["supported"] for entry in report.files):
            report.warning("supports", "the plugin supported none of the sample files")
    finally:
        host.close()
    return report


def _request(host: PluginHost, message: dict, timeout: float) -> dict:
    reply = host.request(message, timeout)
    if reply.get("ok") is not True:
        raise RuntimeError(str(reply.get("error", "the request failed"))[:2000])
    return reply


def _check_file(host: PluginHost, plugin: str, path: Path, relative: str, report: ConformanceReport) -> None:
    record = _record(path, relative)
    entry = {"path": relative, "supported": False, "findings": 0, "rejected": 0, "seconds": 0.0}
    report.files.append(entry)
    timeout = host.policy.timeout_seconds
    try:
        result = _request(host, {"op": "supports", "records": [record.to_dict()]}, timeout)["results"][0]
    except (RuntimeError, PluginHostError, KeyError, IndexError, TypeError) as exc:
        report.error("supports", f"supports() failed: {exc}", relative)
        return
    if isinstance(result, dict):
        report.error("supports", f"supports() raised {result.get('error', 'an error')}", relative)
        return
    if not isinstance(result, bool):
        report.error("supports", "supports() must return a bool", relative)
        return
    entry["supported"] = result
    if not result:
        return
    if record.size_bytes > MAX_PLUGIN_FILE_BYTES:
        report.warning("analyze", "the sample exceeds the isolated-plugin file limit and is not handed over", relative)
        return
    runs = []
    cut = False
    for _ in range(2):
        staged = host.stage(path, record)
        started = time.perf_counter()
        try:
            reply = _request(host, {"op": "analyze", "record": record.to_dict(), "path": str(staged)}, timeout)
            items = reply["findings"]
        except (RuntimeError, PluginHostError, KeyError) as exc:
            report.error("analyze", f"analyze() failed: {exc}", relative)
            return
        finally:
            host.unstage(staged)
        entry["seconds"] = round(max(entry["seconds"], time.perf_counter() - started), 4)
        runs.append(items if isinstance(items, list) else [])
        cut = cut or reply.get("truncated") == "response_bytes"
    first = runs[0]
    if cut:
        report.error("findings", f"the findings exceed the {MAX_RESPONSE_BYTES // (1024 * 1024)} MiB response "
                     "limit for one file; the rest are dropped", relative)
    if len(first) > MAX_FINDINGS_PER_FILE:
        report.error("findings", f"more than {MAX_FINDINGS_PER_FILE:,} findings for one file; the rest are dropped",
                     relative)
    rebuilt = []
    for index, item in enumerate(first[:MAX_FINDINGS_PER_FILE]):
        if isinstance(item, dict) and "invalid" in item and len(item) == 1:
            report.error("findings", f"finding {index} is a {item['invalid']}, not a Finding", relative)
            entry["rejected"] += 1
            continue
        try:
            finding = finding_from_plugin(item, plugin)
        except ValueError as exc:
            report.error("findings", f"finding {index} is rejected: {exc}", relative)
            entry["rejected"] += 1
            continue
        rebuilt.append(finding)
        if item.get("analyzer") not in (None, "", "core", plugin):  # "core" is Finding's default
            report.warning("findings", f"finding {index} sets analyzer={item['analyzer']!r}; PDT replaces it with "
                           f"{plugin!r}", relative)
        # CodeEvidence redacts as it is created (in the plugin's process, too), so a
        # redacted line arrives carrying the marker.
        for line in finding.code_evidence:
            if "[REDACTED" in line.code:
                report.warning("redaction", f"finding {index} code evidence line {line.line_number} is redacted "
                               "in reports (it looks like a secret or personal data)", relative)
                break
    entry["findings"] = len(rebuilt)
    second = [finding_from_plugin(item, plugin).to_dict() for item in runs[1][:MAX_FINDINGS_PER_FILE]
              if _rebuildable(item, plugin)]
    if [finding.to_dict() for finding in rebuilt] != second:
        report.warning("determinism", "two runs on the same file produced different findings", relative)


def _rebuildable(item, plugin: str) -> bool:
    try:
        finding_from_plugin(item, plugin)
    except ValueError:
        return False
    return True


def assert_conformant(target: str, samples: Sequence[Path] = (), **options) -> ConformanceReport:
    """Raise AssertionError listing every error; for plugin authors' test suites."""
    report = check_plugin(target, samples, **options)
    if not report.ok:
        lines = [f"{problem.check}: {problem.message}" + (f" ({problem.path})" if problem.path else "")
                 for problem in report.problems if problem.severity == "error"]
        raise AssertionError("plugin is not conformant:\n" + "\n".join(lines))
    return report


def format_report(report: ConformanceReport) -> str:
    """Plain-text summary for the console."""
    lines = [f"Plugin {report.entry_point} ({report.isolation} isolation): "
             + ("conformant" if report.ok else "NOT conformant")]
    if report.metadata:
        lines.append(f"  name {report.metadata['name']!r}, version {report.metadata['version'] or '(none)'}")
    if report.sandbox:
        denied = [name for name, value in report.sandbox.get("restrictions", {}).items() if value]
        lines.append("  sandbox denies: " + (", ".join(denied).replace("_", " ") or "nothing"))
    for entry in report.files:
        state = f"{entry['findings']} finding(s)" if entry["supported"] else "not supported"
        if entry["rejected"]:
            state += f", {entry['rejected']} rejected"
        lines.append(f"  {entry['path']}: {state}")
    for problem in report.problems:
        lines.append(f"  {problem.severity.upper()} {problem.check}: {problem.message}"
                     + (f" ({problem.path})" if problem.path else ""))
    return "\n".join(lines)


def report_json(report: ConformanceReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
