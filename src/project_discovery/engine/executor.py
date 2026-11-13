"""Per-file analysis execution in a thread pool or a multi-process pool.

Analyzers are CPU-bound Python, so threads share one interpreter lock; large scans use
worker processes instead. Workers never touch the scan databases: they return outcomes
that the coordinator persists in deterministic submission order.
"""
from __future__ import annotations

import hashlib
import multiprocessing
import os
import signal
import stat
import threading
import time
from collections import deque
from concurrent.futures import CancelledError, Future, ProcessPoolExecutor, ThreadPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import nullcontext
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Iterator, Sequence

from ..core.limits import accounting
from ..core.source_utils import (
    identity_matches,
    open_verified_binary,
    prefetched_content,
    PythonSourceTooLarge,
    SourceBudgetExceeded,
    redact_source_excerpt,
    stat_identity,
)
from ..intelligence.facts import FileFacts, collecting_facts, current_facts
from ..inventory.scanner import sha256_file
from ..models import FileRecord, Finding
from . import budgets
from .budgets import BudgetStop


def _isolated_analyzer_type() -> type:
    from ..plugins.isolation import IsolatedAnalyzer

    return IsolatedAnalyzer

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
    gpu_counts: tuple[int, int, dict[str, int]] | None = None
    # (analyzer, seconds, sampled peak memory growth in MiB or None, bytes read) per analyzer
    # call; (analyzer, kind, limit, used) per call a time or memory budget stopped; and
    # (analyzer, kind, limit, used) per content limit a completed call reached.
    budget_usage: list[tuple[str, float, float | None, int]] = field(default_factory=list)
    budget_stops: list[tuple[str, str, float, float]] = field(default_factory=list)
    limit_hits: list[tuple[str, str, float, float]] = field(default_factory=list)


@dataclass(slots=True)
class FileTask:
    record: FileRecord
    path: str
    digest_hint: str | None
    expected_stat: os.stat_result
    # The change time the fingerprint cache records (Windows: NTFS ChangeTime).
    change_time_ns: int | None = None


def verified_regular_file_stat(path: Path, expected=None) -> os.stat_result:
    """Reject symlink/non-regular substitutions and detect file identity changes."""
    current = path.lstat()
    if not stat.S_ISREG(current.st_mode):
        raise OSError(f"refusing to analyze non-regular or symlink entry: {path}")
    if expected is not None and not identity_matches(expected, stat_identity(current)):
        raise OSError(f"file identity changed during scan; refusing analysis: {path}")
    return current


def _budget_stop_finding(analyzer, record: FileRecord, stop: BudgetStop) -> Finding:
    if stop.kind == "time":
        what, limit = f"after {stop.used:.1f} s", f"{stop.limit:g}-second time budget"
    elif stop.kind == "cpu":
        what, limit = f"after {stop.used:.1f} s of CPU time", f"{stop.limit:g}-second CPU budget"
    elif stop.kind == "read":
        what, limit = f"after reading {stop.used:,.1f} MiB", f"{stop.limit:,.0f} MiB read budget"
    else:
        what, limit = f"at {stop.used:,.0f} MiB of memory growth", f"{stop.limit:,.0f} MiB memory budget"
    return Finding(
        "analysis_coverage",
        f"Analyzer {stop.kind} budget exceeded: {analyzer.name}: {record.path}",
        f"The analyzer was stopped {what}: its {limit} per file (--analyzer-timeout, "
        "--analyzer-cpu-seconds, --analyzer-memory-mb, --analyzer-read-mb, --domain-budget). Its findings for "
        "the file were discarded, so "
        "absence of its findings is not evidence of absence.",
        confidence="UNKNOWN", evidence=[record.path], analyzer=analyzer.name, severity="LOW",
    )


def _rollback_facts(sizes: tuple[int, int, int] | None) -> None:
    """Drop the code facts a stopped analyzer emitted for the file."""
    facts = current_facts()
    if facts is not None and sizes is not None:
        del facts.symbols[sizes[0]:], facts.calls[sizes[1]:], facts.facts[sizes[2]:]


def _run_analyzers(analyzers, locks, record: FileRecord, path: Path, outcome: FileOutcome) -> None:
    policy = budgets.current_policy()
    for analyzer in analyzers:
        account = None
        try:
            lock = locks.get(id(analyzer))
            with lock if lock is not None else nullcontext():
                if analyzer.supports(record):
                    # Isolated plugins run in their own hosts under --plugin-timeout/--plugin-memory-mb.
                    budget = None if isinstance(analyzer, _isolated_analyzer_type()) else policy.for_analyzer(analyzer)
                    facts = current_facts()
                    sizes = (len(facts.symbols), len(facts.calls), len(facts.facts)) if facts is not None else None
                    read_limit = budget.read_mb * 1024 * 1024 if budget is not None and budget.read_mb else None
                    with accounting(read_limit) as account:
                        run = budgets.run_with_budget(budget, partial(analyzer.analyze, path, record))
                    outcome.budget_usage.append((analyzer.name, run.seconds, run.peak_mb, account.bytes_read))
                    if run.stop is not None:
                        _rollback_facts(sizes)
                        outcome.budget_stops.append((analyzer.name, run.stop.kind, run.stop.limit, run.stop.used))
                        outcome.findings.append(_budget_stop_finding(analyzer, record, run.stop))
                        continue
                    produced = run.result
                    outcome.limit_hits.extend((analyzer.name, *limit) for limit in account.limits)
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
        except budgets.AnalyzerBudgetExceeded:
            # A stop delivered outside the guarded call (it fired as the call ended): already
            # counted when it carried a stop; never let it escape and fail the whole batch.
            continue
        except Exception as exc:
            if account is not None:
                # A bounded read past its budget raises inside the analyzer: keep its record.
                outcome.limit_hits.extend((analyzer.name, *limit) for limit in account.limits)
            message = redact_source_excerpt(f"{type(exc).__name__}: {exc}")
            outcome.errors.append(f"{record.path} [{analyzer.name}]: {message}")
            # A content budget the analyzer did not handle is a limit, not a failure.
            limited = isinstance(exc, (SourceBudgetExceeded, PythonSourceTooLarge))
            what = "content limit reached" if limited else "failed"
            # Keep coverage gaps visible in the findings, not only in diagnostics.
            outcome.findings.append(Finding(
                "analysis_coverage",
                f"Analyzer {what}: {analyzer.name}: {record.path}",
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


def _watch_coordinator() -> None:
    """Exit this worker process when the coordinator is gone.

    A coordinator that is killed, rather than stopped with Ctrl-C, cannot terminate its
    pool, and its workers would wait on the task queue for good, holding memory and the
    native extensions open. Two signals cover every start method:

    - the parent sentinel multiprocessing gives each child: a handle to the coordinator
      (Windows), or a pipe whose write end only the coordinator holds (spawn, forkserver);
      it becomes ready when the coordinator ends. A forkserver outlives the coordinator,
      because every worker holds its "alive" pipe, so the worker's parent never changes.
    - getppid(): with fork, the sibling workers inherit each other's sentinel pipes, but
      the parent is the coordinator, and POSIX reparents an orphan.
    """
    from multiprocessing.connection import wait

    parent = multiprocessing.parent_process()
    sentinel = None if parent is None else parent.sentinel
    parent_pid = os.getppid()

    def watch() -> None:
        while True:
            try:
                if sentinel is not None and wait([sentinel], timeout=1.0):
                    os._exit(0)
            except (OSError, ValueError):  # an unusable sentinel: rely on getppid()
                break
            if sentinel is None:
                time.sleep(1.0)
            if os.name != "nt" and os.getppid() != parent_pid:
                os._exit(0)
        while True:
            time.sleep(1.0)
            if os.name != "nt" and os.getppid() != parent_pid:
                os._exit(0)

    threading.Thread(target=watch, name="pdt-coordinator-watch", daemon=True).start()


def _initialize_worker(vulnerability_db: str | None, plugin_setup=None, budget_policy=None, gpu=None) -> None:
    """Load this worker process's own analyzer instances (built-ins and plugins)."""
    budgets.set_policy(budget_policy)
    if gpu is not None:
        # The coordinator's --gpu setting; a spawned worker starts with GPU counting off.
        from .native import configure_gpu

        configure_gpu(*gpu)
    # Ctrl-C reaches the whole process group. Only the coordinator handles it and stops
    # the workers itself, so workers do not die mid-queue printing KeyboardInterrupt
    # tracebacks or hand interrupts back as task results.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    _watch_coordinator()
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


def _gpu_counters() -> tuple[int, int, dict[str, int]]:
    from .native import capabilities

    values = capabilities()
    return (int(values.get("gpu_dispatches", 0)), int(values.get("gpu_fallbacks", 0)),
            dict(values.get("gpu_fallback_reasons") or {}))


def gpu_delta(before: tuple, after: tuple) -> tuple[int, int, dict[str, int]]:
    """Dispatches, fallbacks and fallbacks by reason between two _gpu_counters() readings."""
    reasons = {name: count - before[2].get(name, 0) for name, count in after[2].items()
               if count != before[2].get(name, 0)}
    return after[0] - before[0], after[1] - before[1], reasons


def _analyze_batch_in_worker(tasks: list[FileTask]) -> list[FileOutcome]:
    before = _gpu_counters()
    outcomes = analyze_tasks(_worker_state["analyzers"], {}, tasks)
    after = _gpu_counters()
    if outcomes and after != before:
        outcomes[-1].gpu_counts = gpu_delta(before, after)
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
        budget_policy: budgets.BudgetPolicy | None = None,
        max_memory_mb: int | None = None,
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
        # Analyzer time and memory budgets: thread workers share this process's policy,
        # process workers receive it when they start. The policy it replaced comes back
        # at shutdown, so one scan's budgets never outlive it in a library caller.
        self._budget_policy = budget_policy or budgets.BudgetPolicy()
        self._replaced_policy = budgets.current_policy()
        budgets.set_policy(self._budget_policy)
        from .native import gpu_settings

        self._gpu = gpu_settings()  # thread workers share it; process workers receive it
        # --max-memory-mb: callers ask it for room before they queue work (make_room).
        self.scan_memory = budgets.ScanMemoryBudget(max_memory_mb, self.worker_pids)
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
                initargs=(self._vulnerability_db, self._plugin_setup, self._budget_policy, self._gpu),
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

    def worker_pids(self) -> tuple[int, ...]:
        """The process pool's live worker processes (none for the thread executor)."""
        processes = getattr(self._pool, "_processes", None) if self.mode == "process" else None
        for _attempt in range(3):
            try:
                # pid -> Process; the pool's own table, read without changing it.
                return tuple(processes or ())
            except RuntimeError:  # the pool's manager thread changed it during the copy
                continue
        return ()

    def map_python_imports(self, root: Path, records: list[FileRecord]) -> Iterator[tuple]:
        """Parse Python imports in the pool; yield results in input order, bounded in flight."""
        pending: deque = deque()
        ready: list = []

        def drain_one():
            future, batch = pending.popleft()
            try:
                return future.result()
            except POOL_FAILURES:
                self.restart(future)
                return _parse_imports_batch(str(root), batch)

        for start in range(0, len(records), BATCH_MAX_FILES):
            batch = records[start:start + BATCH_MAX_FILES]
            self.scan_memory.make_room(lambda: len(pending), lambda: ready.extend(drain_one()))
            yield from ready
            ready.clear()
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
        budgets.set_policy(self._replaced_policy)

    def __enter__(self) -> "AnalysisExecutor":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.shutdown(cancel=exc_type is not None)
