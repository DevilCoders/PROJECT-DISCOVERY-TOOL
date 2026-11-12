"""Per-file analysis execution in a thread pool or a multi-process pool.

Analyzers are CPU-bound Python, so threads share one interpreter lock; large scans use
worker processes instead. Workers never touch the scan databases: they return outcomes
that the coordinator persists in deterministic submission order.
"""
from __future__ import annotations

import hashlib
import os
import signal
import stat
import threading
from collections import deque
from concurrent.futures import CancelledError, Future, ProcessPoolExecutor, ThreadPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

from ..core.source_utils import (
    identity_matches,
    open_verified_binary,
    prefetched_content,
    redact_source_excerpt,
    stat_identity,
)
from ..intelligence.facts import FileFacts, collecting_facts
from ..inventory.scanner import sha256_file
from ..models import FileRecord, Finding

# Files up to this size are read once per worker and served to every analyzer.
PREFETCH_MAX_BYTES = 4 * 1024 * 1024
# Small files are grouped into one task to amortize inter-process overhead.
BATCH_MAX_FILES = 32
BATCH_MAX_BYTES = 4 * 1024 * 1024
# Below this many files a process pool's start-up cost outweighs its parallelism.
PROCESS_POOL_MIN_FILES = 1000
EXECUTOR_MODES = ("auto", "process", "thread")
# A dead worker breaks its pool; the pool's queued futures fail or are cancelled with it.
POOL_FAILURES = (BrokenProcessPool, CancelledError)


@dataclass(slots=True)
class FileOutcome:
    digest: str | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    file_error: str | None = None
    analyzed: bool = False
    # Cross-file code facts emitted by built-in analyzers (symbols, calls, ...).
    facts: FileFacts | None = None
    # Process workers: (GPU dispatches, CPU fallbacks) during this batch, carried by its
    # last outcome. The native counters are per process, so the coordinator sums them.
    gpu_counts: tuple[int, int] | None = None


@dataclass(slots=True)
class FileTask:
    record: FileRecord
    path: str
    digest_hint: str | None
    expected_stat: os.stat_result


def verified_regular_file_stat(path: Path, expected=None) -> os.stat_result:
    """Reject symlink/non-regular substitutions and detect file identity changes."""
    current = path.lstat()
    if not stat.S_ISREG(current.st_mode):
        raise OSError(f"refusing to analyze non-regular or symlink entry: {path}")
    if expected is not None and not identity_matches(expected, stat_identity(current)):
        raise OSError(f"file identity changed during scan; refusing analysis: {path}")
    return current


def _run_analyzers(analyzers, locks, record: FileRecord, path: Path, outcome: FileOutcome) -> None:
    for analyzer in analyzers:
        try:
            lock = locks.get(id(analyzer))
            with lock if lock is not None else nullcontext():
                if analyzer.supports(record):
                    produced = analyzer.analyze(path, record)
                    if getattr(analyzer, "_pdt_in_process_plugin", False):
                        # The isolated modes' validation, redaction and bounds; the plugin
                        # cannot choose the analyzer name either (PDT-317).
                        from ..plugins.isolation import rebuild_plugin_findings

                        produced = rebuild_plugin_findings(
                            [item.to_dict() if isinstance(item, Finding) else item for item in produced],
                            analyzer.name, record.path,
                        )
                    outcome.findings.extend(produced)
                    outcome.analyzed = True
        except Exception as exc:
            message = redact_source_excerpt(f"{type(exc).__name__}: {exc}")
            outcome.errors.append(f"{record.path} [{analyzer.name}]: {message}")
            # Keep coverage gaps visible in the findings, not only in diagnostics.
            outcome.findings.append(Finding(
                "analysis_coverage",
                f"Analyzer failed: {analyzer.name}: {record.path}",
                f"{message}. This analyzer did not complete for the file; absence of "
                "its findings is not evidence of absence.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=analyzer.name,
                severity="LOW",
            ))


def analyze_file(analyzers, locks, task: FileTask) -> FileOutcome:
    """Analyze one inventoried file; file_error is set only if the file is untrusted."""
    record, path = task.record, Path(task.path)
    outcome = FileOutcome(digest=task.digest_hint)
    content = None
    try:
        verified_regular_file_stat(path, task.expected_stat)
        if record.size_bytes <= PREFETCH_MAX_BYTES:
            # Read once through the verified descriptor; hash and analyze that buffer.
            with open_verified_binary(path, stat_identity(task.expected_stat)) as stream:
                content = stream.read(record.size_bytes + 1)
            if len(content) != record.size_bytes:
                raise OSError(f"file changed while being read: {path}")
            if outcome.digest is None:
                outcome.digest = hashlib.sha256(content).hexdigest()
        elif outcome.digest is None:
            outcome.digest = sha256_file(path, expected_info=task.expected_stat)
    except OSError as exc:
        outcome.file_error = f"{record.path}: {type(exc).__name__}: {exc}"
        outcome.errors.append(outcome.file_error)
        outcome.digest = None
        return outcome
    with (
        prefetched_content(path, content, stat_identity(task.expected_stat))
        if content is not None else nullcontext()
    ), collecting_facts() as facts:
        _run_analyzers(analyzers, locks, record, path, outcome)
    outcome.facts = facts or None
    try:
        verified_regular_file_stat(path, task.expected_stat)
    except OSError as exc:
        # Findings produced while the path changed are not trustworthy.
        outcome.findings.clear()
        outcome.facts = None
        outcome.analyzed = False
        outcome.digest = None
        outcome.file_error = f"{record.path}: {type(exc).__name__}: {exc}"
        outcome.errors.append(outcome.file_error)
    return outcome


def analyze_tasks(analyzers, locks, tasks: Sequence[FileTask]) -> list[FileOutcome]:
    """Analyze one batch. Isolated plugins answer supports() for the whole batch at once."""
    records = [task.record for task in tasks]
    for analyzer in analyzers:
        prefilter = getattr(analyzer, "supports_many", None)
        if prefilter is not None:
            try:
                prefilter(records)
            except Exception:
                pass  # supports() then asks per file and reports any failure for that file
    return [analyze_file(analyzers, locks, task) for task in tasks]


_worker_state: dict[str, Any] = {}


def _initialize_worker(vulnerability_db: str | None, plugin_setup=None) -> None:
    """Load this worker process's own analyzer instances (built-ins and plugins)."""
    # Ctrl-C reaches the whole process group. Only the coordinator handles it and stops
    # the workers itself, so workers do not die mid-queue printing KeyboardInterrupt
    # tracebacks or hand interrupts back as task results.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    from ..analyzers import load_analyzers
    from ..analyzers.dependencies.vulnerabilities import LocalVulnerabilityAnalyzer

    policy, specs = plugin_setup or (None, None)
    # Isolated plugins were validated by the coordinator; workers only rebuild proxies,
    # whose sandboxed hosts start on first use.
    analyzers = load_analyzers(plugin_policy=policy, plugin_specs=specs).analyzers
    if vulnerability_db:
        analyzers.append(LocalVulnerabilityAnalyzer(Path(vulnerability_db)))
    _worker_state["analyzers"] = analyzers


def _cancel_and_terminate(pool: ProcessPoolExecutor) -> None:
    """Cancel queued batches and stop every worker process immediately."""
    terminate = getattr(pool, "terminate_workers", None)  # public since Python 3.14
    if terminate is not None:
        terminate()
        return
    # shutdown() drops the private process table, so take the workers first.
    workers = list((getattr(pool, "_processes", None) or {}).values())
    pool.shutdown(wait=False, cancel_futures=True)
    for process in workers:
        if process.is_alive():
            process.terminate()


def _parse_imports_batch(root: str, records: list[FileRecord]) -> list[tuple]:
    from ..intelligence.python_graph import parse_python_imports

    return [parse_python_imports(Path(root), record) for record in records]


def _gpu_counters() -> tuple[int, int]:
    from .native import capabilities

    values = capabilities()
    return int(values.get("gpu_dispatches", 0)), int(values.get("gpu_fallbacks", 0))


def _analyze_batch_in_worker(tasks: list[FileTask]) -> list[FileOutcome]:
    before = _gpu_counters()
    outcomes = analyze_tasks(_worker_state["analyzers"], {}, tasks)
    after = _gpu_counters()
    if outcomes and after != before:
        outcomes[-1].gpu_counts = (after[0] - before[0], after[1] - before[1])
    return outcomes


class AnalysisExecutor:
    """Submit batches of FileTasks to a thread or process pool and return futures."""

    def __init__(
        self,
        mode: str,
        workers: int,
        analyzers: Sequence[Any],
        *,
        file_count: int,
        vulnerability_db: Path | None = None,
        plugin_setup: tuple | None = None,
    ) -> None:
        if mode not in EXECUTOR_MODES:
            raise ValueError(f"--executor must be one of: {', '.join(EXECUTOR_MODES)}")
        if mode == "auto":
            mode = "process" if workers > 1 and file_count >= PROCESS_POOL_MIN_FILES else "thread"
        self.mode = mode
        self.workers = workers
        self._analyzers = list(analyzers)
        self._vulnerability_db = str(vulnerability_db) if vulnerability_db else None
        # (PluginPolicy, validated PluginSpecs) for worker processes to rebuild plugins.
        self._plugin_setup = plugin_setup
        self._locks = {
            id(analyzer): threading.Lock()
            for analyzer in self._analyzers
            if not getattr(analyzer, "concurrent_safe", True)
        }
        if mode == "process":
            from ..plugins.isolation import IsolatedAnalyzer

            # Workers start their own plugin hosts; the coordinator's load-time hosts would
            # only sit idle (and be inherited by forked workers).
            for analyzer in self._analyzers:
                if isinstance(analyzer, IsolatedAnalyzer):
                    analyzer.release_hosts()
        self._pool = self._create_pool()

    def _create_pool(self):
        if self.mode == "process":
            return ProcessPoolExecutor(
                max_workers=self.workers,
                initializer=_initialize_worker,
                initargs=(self._vulnerability_db, self._plugin_setup),
            )
        return ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="pdt-analyzer")

    def restart(self, failed: Future | None = None) -> None:
        """Replace a broken process pool; in-flight work on the old pool is abandoned.

        When a worker dies, every future of its pool fails. Passing the ``failed`` future
        replaces the pool only if that future's pool is still the current one, so the
        replacement (and the work already submitted to it) is never torn down again.
        """
        if failed is not None and getattr(failed, "pdt_pool", self._pool) is not self._pool:
            return
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._pool = self._create_pool()

    def _submit(self, function, *arguments) -> Future:
        """Queue work, replacing the pool first if a dead worker has already broken it.

        A broken pool refuses new work at once (``submit`` raises ``BrokenProcessPool``),
        which happens when the death is noticed before the next batch is queued.
        """
        for attempt in range(2):
            try:
                future = self._pool.submit(function, *arguments)
            except BrokenProcessPool:
                if attempt:
                    raise
                self.restart()
                continue
            future.pdt_pool = self._pool
            return future
        raise AssertionError("unreachable")

    def submit(self, tasks: list[FileTask]) -> Future:
        if self.mode == "process":
            return self._submit(_analyze_batch_in_worker, tasks)
        return self._submit(analyze_tasks, self._analyzers, self._locks, tasks)

    def map_python_imports(self, root: Path, records: list[FileRecord]) -> Iterator[tuple]:
        """Parse Python imports in the pool; yield results in input order, bounded in flight."""
        pending: deque = deque()

        def drain_one():
            future, batch = pending.popleft()
            try:
                return future.result()
            except POOL_FAILURES:
                self.restart(future)
                return _parse_imports_batch(str(root), batch)

        for start in range(0, len(records), BATCH_MAX_FILES):
            batch = records[start:start + BATCH_MAX_FILES]
            pending.append((self._submit(_parse_imports_batch, str(root), batch), batch))
            while len(pending) >= self.workers * 2:
                yield from drain_one()
        while pending:
            yield from drain_one()

    def _close_plugin_hosts(self, *, graceful: bool) -> None:
        from ..plugins.isolation import IsolatedAnalyzer

        for analyzer in self._analyzers:
            if isinstance(analyzer, IsolatedAnalyzer):
                analyzer.close(graceful=graceful)

    def shutdown(self, *, cancel: bool = False) -> None:
        if cancel:
            if self.mode == "process":
                # Workers hold no state the coordinator still needs, so a cancelled scan
                # stops them now instead of waiting for their in-flight batches to finish.
                _cancel_and_terminate(self._pool)
            # Killing plugin hosts unblocks threads waiting on them.
            self._close_plugin_hosts(graceful=False)
        self._pool.shutdown(wait=True, cancel_futures=cancel)
        self._close_plugin_hosts(graceful=not cancel)

    def __enter__(self) -> "AnalysisExecutor":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.shutdown(cancel=exc_type is not None)
