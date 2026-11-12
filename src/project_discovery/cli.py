"""PDT command line."""
import argparse
import heapq
import importlib
import json
import os
import platform
import shutil
import sqlite3
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from . import __version__
from .analyzers import load_analyzers
from .analyzers.code.tree_sitter_syntax import parser_capabilities
from .analyzers.dependencies.lockfile_parsers import LOCKFILE_NAMES, MAX_LOCKFILE_BYTES
from .analyzers.dependencies.vulnerabilities import LocalVulnerabilityAnalyzer
from .catalog.domains import analyzer_domain_catalog, analyzer_domain_count
from .catalog.languages import language_catalog, recognized_language_count
from .core.source_utils import neutralize_controls, read_text_bounded
from .engine.executor import (
    BATCH_MAX_BYTES,
    BATCH_MAX_FILES,
    EXECUTOR_MODES,
    POOL_FAILURES,
    AnalysisExecutor,
    FileOutcome,
    FileTask,
    verified_regular_file_stat,
)
from .engine.metrics import PhaseTimer, peak_rss_bytes
from .engine.native import capabilities as native_capabilities
from .engine.native import native_available
from .intelligence.architecture import analyze_project_architecture
from .intelligence.index import QUERY_KINDS, analyze_code_index, query_code_index
from .intelligence.python_graph import analyze_python_dependencies
from .inventory.cache import ScanCache
from .inventory.scanner import discover_inventory
from .inventory.store import (
    InventoryStore,
    StoredDiagnosticRecords,
    StoredFileRecords,
    StoredFindingRecords,
    StoredRecordSequence,
)
from .models import DirectoryRecord, Finding, ScanResult, SpecialEntryRecord, SymlinkRecord
from .online.cache import default_cache_path as default_vulnerability_cache_path
from .online.http import DEFAULT_TIMEOUT as DEFAULT_NETWORK_TIMEOUT
from .online.http import NetworkError, resolve_ca_bundle, validate_service_url
from .online.memory_scan import (
    DEFAULT_API_MAX_BYTES,
    DEFAULT_API_MAX_FILE_BYTES,
    DEFAULT_API_MAX_FILES,
    DEFAULT_API_MAX_REQUESTS,
    DEFAULT_API_WORKERS,
    ApiLimits,
    NoDownloadOptions,
    NoDownloadSource,
)
from .online.providers import API_PROVIDERS
from .online.repositories import (
    DEFAULT_REMOTE_MAX_BYTES,
    DEFAULT_REMOTE_TIMEOUT,
    REMOTE_VCS,
    RemoteLimits,
    check_transport_policy,
    is_remote_target,
    load_remote_targets,
    parse_remote_target,
    remote_checkout,
    remote_vcs_capabilities,
    sanitize_client_output,
)
from .online.vulnerabilities import (
    ENRICHMENT_SOURCES,
    LockfileSource,
    OnlineVulnerabilityLookup,
    OnlineVulnerabilityOptions,
)
from .plugins.isolation import (
    DEFAULT_MEMORY_LIMIT_MB,
    DEFAULT_TIMEOUT_SECONDS,
    ISOLATION_MODES,
    PluginPolicy,
    probe_sandbox,
)
from .projects.catalog import ProjectCatalog
from .projects.comparison import compare_many_reports, load_report, write_comparison
from .reporting.writers import write_remote_batch_summary, write_reports
from .vulnerabilities.database import VulnerabilityDatabase, default_database_path


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Kept under its historical name; the guard lives in the analysis engine.
_verified_regular_file_stat = verified_regular_file_stat


def _status(console: Console, label: str, message: str, style: str) -> None:
    # Messages carry paths and plugin text: "[...]" in them must not be read as markup,
    # and escape sequences must not reach the terminal.
    console.print(f"[bold {style}][ {label} ][/bold {style}] {escape(neutralize_controls(message))}")


_BANNER = r"""
 ____  ____ _____     //  PROJECT DISCOVERY TOOL
|  _ \/ ___|_   _|    POLYGLOT INTELLIGENCE CORE
| |_) \___ \ | |     FILESYSTEM // SECURITY // ARCHITECTURE
|  __/ ___) || |      LOCAL-FIRST // READ-ONLY // OFFLINE
|_|   |____/ |_|      2GB -> 100GB+ // EVIDENCE-DRIVEN
"""


def _render_banner(console: Console) -> None:
    if console.is_terminal:
        console.clear()
    console.print(Panel(
        _BANNER,
        title="[bold bright_cyan]PDT // DISCOVERY COMMAND CENTER[/bold bright_cyan]",
        subtitle="[dim]STATIC INTELLIGENCE • NO TARGET EXECUTION • NO NETWORK PROBING[/dim]",
        border_style="bright_cyan",
        padding=(1, 2),
    ))
    capabilities = native_capabilities()
    gpu_status = (
        f"GPU: {capabilities.get('gpu_vendor', '')} {capabilities.get('gpu_name', '')}".strip()
        if capabilities.get("gpu_available")
        else "GPU: CPU fallback (no usable OpenCL GPU)"
    )
    native_status = (
        f"C/ASM: {capabilities.get('backend', 'unknown')}  //  "
        f"{gpu_status}  //  "
        f"C++ signatures: {'ONLINE' if capabilities.get('cpp_signature_classifier') else 'FALLBACK'}  //  "
        f"Rust walker: {'ONLINE' if capabilities.get('rust_filesystem_walker') else 'FALLBACK'}"
    )
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(style="bold bright_cyan", width=12)
    grid.add_column(style="white")
    grid.add_row("CONTROL", "Python orchestration // analyzer registry // evidence correlation")
    grid.add_row("NATIVE", native_status)
    grid.add_row("REPORT", "JavaScript offline client // bundled HTML // paged findings")
    console.print(Panel(grid, title="[bold]ENGINE STATUS[/bold]", border_style="blue"))
    console.print("[dim]Inventory  >  Analyze  >  Correlate  >  Report[/dim]\n")

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Process exit codes are part of the CLI contract for CI pipelines.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_INTERRUPTED = 130

# Analyzed file records are written back in batches of this size.
RECORD_UPDATE_BATCH = 512


def _print_security_findings(console: Console, findings, *, limit: int = 25) -> None:
    """Print top redacted security findings without materializing the full result set."""
    severity_rank = SEVERITY_RANK
    is_security = lambda finding: finding.category in {"security", "secrets", "privacy"}
    sort_key = lambda finding: (
        severity_rank.get(finding.severity, 5),
        finding.title.casefold(),
        finding.analyzer,
    )
    security_count = sum(1 for finding in findings if is_security(finding))
    if not security_count:
        return
    security_findings = heapq.nsmallest(
        limit, (finding for finding in findings if is_security(finding)),
        key=sort_key,
    )

    console.print()
    console.print("[bold red]SECURITY FINDINGS // REDACTED SOURCE EVIDENCE[/bold red]")
    for finding in security_findings[:limit]:
        severity_style = (
            "bold red" if finding.severity in {"CRITICAL", "HIGH"}
            else "bold yellow" if finding.severity == "MEDIUM"
            else "bold cyan"
        )
        heading = Text(f"[{finding.severity}] ", style=severity_style)
        heading.append(finding.title)
        console.print(heading)
        if finding.evidence:
            location = Text("  at ", style="dim")
            location.append(finding.evidence[0], style="bold")
            if len(finding.evidence) > 1:
                location.append(f" (+{len(finding.evidence) - 1} more)", style="dim")
            console.print(location)
        console.print(Text(f"  {finding.detail}", style="dim"))
        for evidence in finding.code_evidence[:3]:
            line = Text(f"  L{evidence.line_number:>5}  ", style="bold red")
            line.append(evidence.code, style="bold red")
            console.print(line)
        if finding.impact:
            impact = Text("  Attacker impact: ", style="bold yellow")
            impact.append(finding.impact)
            console.print(impact)
        if finding.recommendation:
            remediation = Text("  Remediation: ", style="bold green")
            remediation.append(finding.recommendation)
            console.print(remediation)
        console.print()
    omitted = security_count - len(security_findings)
    if omitted > 0:
        console.print(
            f"[dim]... {omitted:,} additional security findings are available in the reports.[/dim]"
        )


def _resumable_walk_stats(inventory_path: Path, root: Path) -> dict | None:
    """Return the stored walk statistics when an inventory for ``root`` can be resumed."""
    if not inventory_path.is_file():
        return None
    with InventoryStore(inventory_path) as store:
        if (
            store.get_metadata("root") != str(root)
            or not store.get_metadata("traversal_finished", False)
            or store.get_metadata("inventory_status") not in {"complete", "partial"}
        ):
            return None
        stats = store.get_metadata("walk_stats")
    return stats if isinstance(stats, dict) else None


def _report_plugins(console: Console, policy: PluginPolicy, analyzer_load) -> None:
    """Say how each loaded plugin runs, and what its sandbox could not restrict."""
    for status in analyzer_load.plugins:
        if status.get("status") != "loaded":
            continue
        label = f"Plugin {status.get('name')} {status.get('version', '')}".rstrip()
        if policy.isolation == "off":
            _status(console, "WARNING", f"{label}: runs in-process with PDT's permissions (--plugin-isolation off)", "yellow")
            continue
        if policy.isolation == "process":
            _status(console, "WARNING", f"{label}: runs in a separate process without OS restrictions", "yellow")
            continue
        sandbox = status.get("sandbox") or {}
        _status(console, "INFO", f"{label}: sandboxed ({', '.join(sandbox.get('mechanisms', []))})", "cyan")
        unrestricted = [
            name.replace("_", " ") for name, denied in sandbox.get("restrictions", {}).items() if not denied
        ]
        if unrestricted:
            _status(
                console, "WARNING",
                f"{label}: this platform's sandbox does not restrict {', '.join(unrestricted)}", "yellow",
            )
    for diagnostic in analyzer_load.diagnostics:
        _status(console, "WARNING", diagnostic, "yellow")


class _EphemeralScanCache:
    """Fingerprint-cache stand-in for temporary remote checkouts.

    Every remote scan materializes a fresh directory, so stored fingerprints could never
    be reused; recording them would only grow the output's cache with dead roots.
    """

    def __enter__(self) -> "_EphemeralScanCache":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def get(self, root: str, relative_path: str) -> None:
        return None

    def put(self, *args, **kwargs) -> None:
        return None

    def prune_missing(self, root: str, current_paths) -> int:
        return 0


def _remote_coverage_findings(source_metadata: dict) -> list[Finding]:
    """Represent remote content that was not materialized as UNKNOWN coverage findings."""
    findings = []
    location = str(source_metadata.get("url") or "remote source")
    for item in source_metadata.get("coverage") or []:
        if not isinstance(item, dict) or not item.get("detail"):
            continue
        incomplete = bool(item.get("incomplete"))
        findings.append(Finding(
            "analysis_coverage",
            "Remote source coverage gap: " + str(item.get("kind", "unknown")).replace("_", " "),
            str(item["detail"]) + (
                " This content is missing from the analyzed tree; absence of findings for it "
                "is not evidence of absence." if incomplete else
                " The referenced content was not analyzed."
            ),
            confidence="UNKNOWN",
            evidence=[f"source: {location}", f"count: {item.get('count', 0)}"],
            analyzer="remote-source",
            severity="LOW" if incomplete else "INFO",
        ))
    return findings


def _lockfile_sources(root: Path, records, skipped: list[str], memory_source=None):
    """Yield the inventoried lockfiles for the online lookup, read bounded and identity-pinned.

    In no-download mode the texts come from memory; a lockfile whose content was not
    fetched (budget, rate limit) is reported as unreadable with that reason.
    """
    for record in records:
        if Path(record.path).name.lower() not in LOCKFILE_NAMES:
            continue
        if record.content_skipped_reason and record.content_skipped_reason.startswith("Explicit --skip"):
            skipped.append(record.path)
            continue
        if memory_source is not None:
            yield LockfileSource(record.path, lambda path=record.path: memory_source.lockfile_text(path))
            continue
        if record.content_skipped_reason:
            skipped.append(record.path)
            continue
        if record.error:
            def unreadable(error=record.error):
                raise OSError(error)
            yield LockfileSource(record.path, unreadable)
            continue
        yield LockfileSource(
            record.path,
            lambda record=record: read_text_bounded(
                root / record.path, MAX_LOCKFILE_BYTES, expected_identity=record.analysis_identity,
            ),
        )


def _run_online_vulnerability_lookup(
    console: Console, options: OnlineVulnerabilityOptions, root: Path, records,
    finding_store, *, inventory_only: bool, memory_source=None,
) -> dict:
    """Run the opt-in OSV.dev lookup in the coordinator and persist its findings."""
    if inventory_only:
        return {"enabled": True, **options.describe(), "coverage": "skipped",
                "reason": "inventory-only scan: lockfile contents were not read"}
    _status(
        console, "INFO",
        "Online vulnerability lookup: " + options.describe()["endpoint"]
        + " (sends package ecosystem, name and version only)", "cyan",
    )
    skipped: list[str] = []
    result = OnlineVulnerabilityLookup(options).run(
        _lockfile_sources(root, records, skipped, memory_source),
    )
    finding_store.extend_findings(result.findings)
    finding_store.extend_diagnostics(result.diagnostics)
    status = result.status
    if skipped:
        status["lockfiles_content_skipped"] = len(skipped)
        finding_store.append_finding(Finding(
            "vulnerabilities",
            f"Lockfile(s) not checked online because of --skip: {len(skipped):,}",
            f"{len(skipped):,} lockfile(s) exceeded --max-file-mb and their content was skipped by "
            "request, so their packages were not looked up. This is not evidence that they are "
            "free of known vulnerabilities.",
            confidence="UNKNOWN", evidence=skipped[:20], analyzer="online-vulnerability-intelligence",
            severity="LOW",
        ))
    if status.get("coverage") in {"partial", "unavailable"}:
        _status(
            console, "WARNING",
            f"Online vulnerability lookup is {status['coverage']}: "
            f"{status.get('packages_failed', 0):,} package(s) could not be checked; "
            "see the UNKNOWN findings.", "yellow",
        )
    else:
        _status(
            console, "INFO",
            f"Online vulnerability lookup: {status.get('packages_queried', 0):,} package(s) checked, "
            f"{status.get('vulnerable_packages', 0):,} with known advisories "
            f"({status.get('cache', {}).get('hits', 0):,} cache hits).", "cyan",
        )
    return status


def run_scan(
    root: Path, output: Path | None, formats: set[str], max_file_mb: int,
    *, skip_oversized: bool = False, ignores: set[str] | None = None,
    vulnerability_db: Path | None = None, jobs: int = 0,
    fail_on: str | None = None, strict: bool = False,
    quiet: bool = False, no_color: bool = False, executor: str = "auto",
    resume: bool = False, inventory_only: bool = False,
    plugin_isolation: str = "sandbox", plugin_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    plugin_memory_mb: int = DEFAULT_MEMORY_LIMIT_MB,
    source_metadata: dict | None = None,
    display_root: str | None = None,
    online_vulnerabilities: OnlineVulnerabilityOptions | None = None,
    memory_source: NoDownloadSource | None = None,
) -> int:
    # no_color=None lets Rich honor the NO_COLOR environment convention.
    console = Console(stderr=True, quiet=quiet, no_color=True if no_color else None)
    if jobs < 0 or jobs > 64:
        raise ValueError("--jobs must be 0 (automatic) or between 1 and 64")
    if fail_on is not None and fail_on not in SEVERITY_RANK:
        raise ValueError(f"--fail-on must be one of: {', '.join(SEVERITY_RANK)}")
    # Validates the plugin options before the (potentially long) inventory walk.
    PluginPolicy(plugin_isolation, plugin_timeout, plugin_memory_mb)
    if memory_source is not None:
        # No-download mode: the root is a namespace for in-memory files, never a directory.
        if resume:
            raise ValueError("--resume is not available in no-download mode")
        if output is None:
            raise ValueError("no-download scans need an output directory")
        root = memory_source.virtual_root
        output = output.expanduser().resolve()
        executor = "thread"
    else:
        root = root.expanduser().absolute()
        root_info = root.lstat()
        if root_info.st_mode and root.is_symlink():
            raise ValueError("The scan root itself is a symlink; pass its real directory path explicitly.")
        root = root.resolve(strict=True)
        if output is None:
            project_name = root.name or "root"
            output = root.parent / f"{project_name}-pdt-report"
        output = output.expanduser().resolve()
        if not root.is_dir():
            raise NotADirectoryError(root)
        if output == root or root in output.parents:
            raise ValueError("Report output must be outside the analyzed project directory.")

    # Validate the advisory database before the (potentially long) inventory walk.
    vulnerability_db_status = {"enabled": False, "advisory_count": 0}
    if vulnerability_db is not None:
        vulnerability_db = vulnerability_db.expanduser().resolve(strict=True)
        if not vulnerability_db.is_file():
            raise FileNotFoundError(
                f"Local vulnerability database is not a file: {vulnerability_db}"
            )
        if vulnerability_db == root or root in vulnerability_db.parents:
            raise ValueError("The vulnerability database must be outside the analyzed project.")
        with VulnerabilityDatabase(vulnerability_db, read_only=True) as advisory_store:
            vulnerability_db_status = {
                "enabled": True,
                **advisory_store.status(),
            }
    vulnerability_db_status["sources"] = (["local-database"] if vulnerability_db is not None else []) + (
        ["osv.dev"] if online_vulnerabilities is not None else []
    )
    if online_vulnerabilities is not None and online_vulnerabilities.cache_path is not None:
        cache_location = online_vulnerabilities.cache_path.expanduser().resolve()
        if cache_location == root or root in cache_location.parents:
            raise ValueError("The online vulnerability cache must be outside the analyzed project.")

    _render_banner(console)
    if source_metadata is not None:
        _status(
            console, "INFO",
            f"Read-only discovery: {display_root or source_metadata.get('url', 'remote source')} "
            "(temporary read-only checkout)", "cyan",
        )
    else:
        _status(console, "INFO", "Read-only discovery: " + str(root), "cyan")
    started = now()
    timer = PhaseTimer()
    inventory_path = output / ".pdt-cache" / "inventory.sqlite3"
    walk_stats = _resumable_walk_stats(inventory_path, root) if resume else None
    resumed = walk_stats is not None
    if resume and not resumed:
        _status(
            console, "WARNING",
            "No completed inventory of this root to resume; starting a fresh scan.", "yellow",
        )
    if resumed:
        # Continue the interrupted scan: reuse its inventory and stored findings, and skip
        # files whose analysis already completed. New or removed files are not picked up.
        _status(console, "INFO", "Resuming from the stored inventory: " + str(inventory_path), "cyan")
        records = StoredFileRecords(inventory_path)
        directories = StoredRecordSequence(inventory_path, "directory", DirectoryRecord)
        symlinks = StoredRecordSequence(inventory_path, "symlink", SymlinkRecord)
        special_entries = StoredRecordSequence(inventory_path, "special", SpecialEntryRecord)
    else:
        with InventoryStore(inventory_path) as inventory_store, console.status(
            "Inventorying filesystem entries…", spinner="dots",
        ):
            if memory_source is not None:
                records, directories, symlinks, special_entries, walk_stats = memory_source.build_inventory(
                    inventory_store, ignores=ignores,
                    max_file_bytes=max_file_mb * 1024 * 1024, skip_oversized=skip_oversized,
                )
            else:
                records, directories, symlinks, special_entries, walk_stats = discover_inventory(
                    root,
                    max_file_bytes=max_file_mb * 1024 * 1024,
                    skip_oversized=skip_oversized,
                    ignores=ignores,
                    store=inventory_store,
                )
    timer.lap("inventory")
    resumed_skipped = 0
    counts = Counter()
    cache_path = output / ".pdt-cache" / "fingerprints.sqlite3"
    hardware_threads = max(1, int(native_capabilities().get("hardware_threads", os.cpu_count() or 1)))
    worker_count = jobs or max(1, min(8, hardware_threads * 2))
    record_updates = []

    def commit_record_updates():
        # Findings first: a record with a sha256 counts as analyzed, so committing it before
        # its findings would let --resume after a crash skip the file and lose them.
        finding_store.flush()
        records.update_records(record_updates)
        record_updates.clear()

    def persist_record(record):
        if isinstance(records, StoredFileRecords):
            record_updates.append(record)
            if len(record_updates) >= RECORD_UPDATE_BATCH:
                commit_record_updates()

    progress_columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )
    plugin_work_dir = output / ".pdt-cache" / "plugins"
    shutil.rmtree(plugin_work_dir, ignore_errors=True)  # staging left by a killed scan
    plugin_policy = PluginPolicy(
        plugin_isolation, plugin_timeout, plugin_memory_mb,
        work_dir=str(plugin_work_dir), exclude_paths=(str(root), str(output)),
    )
    analyzer_load = load_analyzers(plugin_policy=plugin_policy)
    analyzers = analyzer_load.analyzers
    if memory_source is not None:
        # Sandboxed plugins receive a copy of each file on disk; no-download mode never
        # writes repository content, so only the built-in analyzers run.
        plugin_names = {item["name"] for item in analyzer_load.plugins if item.get("status") == "loaded"}
        if plugin_names:
            analyzers = [item for item in analyzers if item.name not in plugin_names]
            memory_source.excluded_plugins = sorted(plugin_names)
    try:
        if vulnerability_db is not None:
            analyzers.append(LocalVulnerabilityAnalyzer(vulnerability_db))
        # The worker pool serves both per-file analysis and import-graph parsing.
        engine = AnalysisExecutor(
            executor, worker_count, analyzers,
            file_count=len(records), vulnerability_db=vulnerability_db,
            plugin_setup=(plugin_policy, analyzer_load.plugin_specs),
        )
    except BaseException:
        analyzer_load.close()
        raise
    _report_plugins(console, plugin_policy, analyzer_load)
    fingerprint_cache = ScanCache(cache_path) if source_metadata is None else _EphemeralScanCache()
    try:
        with InventoryStore(inventory_path) as finding_store, fingerprint_cache as cache:
            finding_store.extend_diagnostics(analyzer_load.diagnostics)
            if source_metadata is not None and memory_source is None:
                # Missing content makes the scan incomplete (--strict); notes such as
                # "history not imported" stay report metadata only.
                finding_store.extend_diagnostics(source_metadata.get("coverage_gaps", []))
                finding_store.extend_findings(_remote_coverage_findings(source_metadata))
            with Progress(*progress_columns, console=console) as progress:
                task = progress.add_task("Analyzing project files", total=len(records))
                max_pending = max(2, engine.workers * 2)
                pending: deque = deque()
                batch: list[FileTask] = []
                batch_bytes = 0

                def batch_outcomes(future, tasks):
                    try:
                        return future.result()
                    except POOL_FAILURES:
                        # A worker died (native fault or OOM kill). Replace the pool once and
                        # rerun this batch file by file, so only the culprit file is lost.
                        engine.restart(future)
                        return [rerun_alone(item) for item in tasks]

                def rerun_alone(item: FileTask) -> FileOutcome:
                    # A pool can also break because of another in-flight batch, so a file is
                    # blamed only when it fails twice on its own.
                    for _attempt in range(2):
                        single = engine.submit([item])
                        try:
                            [outcome] = single.result()
                            return outcome
                        except POOL_FAILURES:
                            engine.restart(single)
                    message = f"{item.record.path}: analysis worker process terminated"
                    return FileOutcome(file_error=message, errors=[message])

                def collect_one():
                    future, tasks = pending.popleft()
                    for item, outcome in zip(tasks, batch_outcomes(future, tasks), strict=True):
                        apply_outcome(item, outcome)

                def flush_batch():
                    nonlocal batch, batch_bytes
                    if batch:
                        pending.append((engine.submit(batch), batch))
                        batch, batch_bytes = [], 0
                    while len(pending) >= max_pending:
                        collect_one()

                def apply_outcome(item: FileTask, outcome: FileOutcome):
                    record, file_stat = item.record, item.expected_stat
                    cache_miss = item.digest_hint is None
                    try:
                        record.analyzed = outcome.analyzed
                        finding_store.extend_findings(outcome.findings)
                        if outcome.facts:
                            finding_store.extend_code_facts(record.path, outcome.facts)
                        finding_store.extend_diagnostics(outcome.errors)
                        digest = outcome.digest
                        if outcome.file_error:
                            record.error = outcome.file_error
                        elif digest and not cache_miss:
                            record.sha256 = digest
                        elif digest:
                            current_stat = _verified_regular_file_stat(root / record.path, file_stat)
                            stable = (
                                current_stat.st_size == file_stat.st_size
                                and current_stat.st_mtime_ns == file_stat.st_mtime_ns
                                and current_stat.st_ctime_ns == file_stat.st_ctime_ns
                                and current_stat.st_ino == file_stat.st_ino
                            )
                            if stable:
                                record.sha256 = digest
                                cache.put(
                                    str(root), record.path, file_stat.st_size,
                                    file_stat.st_mtime_ns, file_stat.st_ctime_ns,
                                    file_stat.st_ino, digest,
                                )
                            else:
                                message = f"{record.path}: file changed while scan was in progress"
                                record.error = message
                                finding_store.append_diagnostic(message)
                    except Exception as exc:
                        message = f"{record.path}: {type(exc).__name__}: {exc}"
                        record.error = message
                        finding_store.append_diagnostic(message)
                    finally:
                        persist_record(record)
                        progress.advance(task)

                def apply_memory_result(record, outcome, reason, fetched_size):
                    walk_stats[f"file_type:{record.file_type}"] += 1
                    if outcome is None:
                        record.content_skipped_reason = f"no-download: {reason}"
                        memory_source.record_skip(record, reason)
                    else:
                        record.analyzed = outcome.analyzed
                        record.sha256 = outcome.digest
                        finding_store.extend_findings(outcome.findings)
                        if outcome.facts:
                            finding_store.extend_code_facts(record.path, outcome.facts)
                        finding_store.extend_diagnostics(outcome.errors)
                        delta = fetched_size - record.size_bytes
                        if delta:
                            # Providers that list no sizes (GitLab): correct the aggregates.
                            walk_stats[f"size_bucket:{record.size_bucket}"] -= 1
                            record.size_bytes = fetched_size
                            record.size_bucket = memory_source.size_bucket(fetched_size)
                            walk_stats[f"size_bucket:{record.size_bucket}"] += 1
                            walk_stats["total_bytes"] += delta
                            for ancestor in memory_source.ancestors(record.path):
                                finding_store.adjust_directory(ancestor, total_bytes_delta=delta)
                    persist_record(record)
                    progress.advance(task)

                def eligible_memory_records():
                    for record in records:
                        counts[record.language] += 1
                        if record.error or record.content_skipped_reason or inventory_only:
                            walk_stats[f"file_type:{record.file_type}"] += 1
                            progress.advance(task)
                            continue
                        yield record

                try:
                    if memory_source is not None:
                        memory_source.analyze_records(
                            eligible_memory_records(), analyzers, {}, record_callback=apply_memory_result,
                        )
                    for record in (records if memory_source is None else ()):
                        counts[record.language] += 1
                        if record.error or record.content_skipped_reason or inventory_only:
                            progress.advance(task)
                            continue
                        if resumed and record.sha256:
                            resumed_skipped += 1
                            progress.advance(task)
                            continue
                        path = root / record.path
                        try:
                            file_stat = _verified_regular_file_stat(path, record.analysis_identity)
                            if (
                                file_stat.st_size != record.size_bytes
                                or (record.mtime_ns is not None and file_stat.st_mtime_ns != record.mtime_ns)
                            ):
                                raise OSError(f"file changed after inventory; refusing analysis: {record.path}")
                            cached = cache.get(str(root), record.path)
                            cache_hit = bool(
                                cached
                                and cached[0] == file_stat.st_size
                                and cached[1] == file_stat.st_mtime_ns
                                and cached[2] == file_stat.st_ctime_ns
                                and cached[3] == file_stat.st_ino
                            )
                            digest_hint = cached[4] if cache_hit else None
                        except OSError as exc:
                            record.error = str(exc)
                            finding_store.append_diagnostic(record.path + ": " + str(exc))
                            persist_record(record)
                            progress.advance(task)
                            continue
                        batch.append(FileTask(record, str(path), digest_hint, file_stat))
                        batch_bytes += record.size_bytes
                        if len(batch) >= BATCH_MAX_FILES or batch_bytes >= BATCH_MAX_BYTES:
                            flush_batch()
                    flush_batch()
                    while pending:
                        collect_one()
                finally:
                    # Also on Ctrl-C: keep completed files for --resume (findings first).
                    if record_updates:
                        commit_record_updates()

            timer.lap("analysis")
            if walk_stats.get("walk_errors", 0) == 0:
                cache.prune_missing(str(root), (record.path for record in records))
            timer.lap("cache_maintenance")

        with InventoryStore(inventory_path) as finding_store:
            if memory_source is not None:
                memory_metadata = memory_source.finalize()
                finding_store.extend_diagnostics(memory_metadata.get("coverage_gaps", []))
                finding_store.extend_findings(_remote_coverage_findings(memory_metadata))
            if online_vulnerabilities is not None:
                # Coordinator only: worker processes never touch the network.
                vulnerability_db_status["online"] = _run_online_vulnerability_lookup(
                    console, online_vulnerabilities, root, records, finding_store,
                    inventory_only=inventory_only, memory_source=memory_source,
                )
                timer.lap("online_vulnerabilities")
            if inventory_only:
                python_graph = {"summary": {"skipped": "inventory-only scan"}}
                graph_findings = []
            else:
                python_graph, graph_findings = analyze_python_dependencies(
                    root, records, finding_sink=finding_store.append_finding,
                    import_parser=(
                        (lambda items: engine.map_python_imports(root, items)) if memory_source is None
                        else (lambda items: (
                            memory_source.python_imports.get(item.path, ("read_error", "ContentNotFetched", None))
                            for item in items
                        ))
                    ),
                )
            timer.lap("python_graph")
            architecture_layout, architecture_findings = analyze_project_architecture(records)
            finding_store.extend_findings(graph_findings)
            finding_store.extend_findings(architecture_findings)
            if inventory_only:
                code_index = {"skipped": "inventory-only scan"}
            else:
                # Symbol index, call graph, module graph and other cross-file passes.
                code_index, index_findings = analyze_code_index(inventory_path, records)
                finding_store.extend_findings(index_findings)
            timer.lap("code_index")
    except BaseException:
        engine.shutdown(cancel=True)  # also stops plugin hosts
        shutil.rmtree(plugin_work_dir, ignore_errors=True)
        raise
    engine.shutdown()
    shutil.rmtree(plugin_work_dir, ignore_errors=True)
    timer.lap("architecture")
    findings = StoredFindingRecords(inventory_path)
    errors = StoredDiagnosticRecords(inventory_path)
    domain_catalog = analyzer_domain_catalog()
    plugin_names = {item["name"] for item in analyzer_load.plugins if item.get("status") == "loaded"}
    vcs_provider_categories = Counter(
        item.category for item in findings
        if item.category in {"vcs", "hosting_providers", "ci_cd", "cloud_services"}
    )
    vcs_provider_signal_count = sum(vcs_provider_categories.values())
    metrics = {
        "source": {
            "mode": "remote" if source_metadata is not None else "local",
            "remote": source_metadata,
        },
        "vcs_provider_signal_count": vcs_provider_signal_count,
        "vcs_provider_categories": dict(sorted(vcs_provider_categories.items())),
        "native_backend": native_capabilities(),
        "native_extension_available": native_available(),
        "execution": {
            "mode": f"bounded-{engine.mode}-pool",
            "executor": engine.mode,
            "worker_count": engine.workers,
            "max_pending_tasks": max_pending,
            "batch_max_files": BATCH_MAX_FILES,
            "ordering": "deterministic-submission-order",
            "analysis_mode": "inventory-only" if inventory_only else "full",
            "resumed": resumed,
            "resumed_files_skipped": resumed_skipped,
        },
        "vulnerability_intelligence": vulnerability_db_status,
        "finding_persistence": {
            "backend": "sqlite",
            "record_count": len(findings),
            "deduplicate_identical": True,
            "public_schema_unchanged": True,
        },
        "inventory_persistence": {
            "backend": "sqlite",
            "enabled": bool(walk_stats.get("inventory_store_enabled", 0)),
            "record_count": walk_stats.get("inventory_store_record_count", 0),
            "integrity_check": (
                "ok" if walk_stats.get("inventory_store_integrity_ok", 0) else "failed"
            ),
            "status": "partial" if walk_stats.get("inventory_store_partial", 0) else "complete",
            "scope": "filesystem metadata only",
            "end_to_end_bounded_memory": False,
        },
        "file_count": len(records),
        "directory_count": len(directories) - 1,
        "symlink_count": len(symlinks),
        "special_entry_count": len(special_entries),
        "special_entry_types": {
            key.split(":", 1)[1]: value
            for key, value in walk_stats.items() if key.startswith("special_type:")
        },
        "pruned_directory_count": walk_stats.get("pruned_directory_count", 0),
        "entry_count": walk_stats.get("entry_count", 0) + 1,
        "hidden_entry_count": walk_stats.get("hidden_entry_count", 0),
        "development_directory_count": walk_stats.get("development_directory_count", 0),
        "development_directories": {
            key.split(":", 1)[1]: value
            for key, value in walk_stats.items() if key.startswith("development_dir:")
        },
        "file_types": {
            key.split(":", 1)[1]: value
            for key, value in walk_stats.items() if key.startswith("file_type:")
        },
        "size_buckets": {
            key.split(":", 1)[1]: value
            for key, value in walk_stats.items() if key.startswith("size_bucket:")
        },
        "total_bytes": walk_stats.get("total_bytes", 0),
        "walk_errors": walk_stats.get("walk_errors", 0),
        "oversized_files": walk_stats.get("oversized_content_skipped", 0),
        "content_skip_enabled": skip_oversized,
        "host_os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "languages": dict(sorted(counts.items())),
        "language_catalog": language_catalog(),
        "recognized_language_count": recognized_language_count(),
        "local_parser_capabilities": parser_capabilities(set(counts)),
        "analyzer_domain_catalog": domain_catalog,
        "analyzer_domain_count": analyzer_domain_count(),
        "plugin_diagnostics": analyzer_load.diagnostics,
        "plugin_isolation": {
            "mode": plugin_policy.isolation,
            "timeout_seconds": plugin_policy.timeout_seconds,
            "memory_limit_mb": plugin_policy.memory_limit_mb or None,
            "required_restrictions": list(plugin_policy.required),
            "plugins": analyzer_load.plugins,
        },
        "active_analyzer_domains": sorted({
            domain for analyzer in analyzers for domain in analyzer.domains
        }),
        "analyzer_registry": [
            {
                "name": analyzer.name,
                "version": analyzer.version,
                "api_version": analyzer.api_version,
                "domains": list(analyzer.domains),
                "languages": list(analyzer.languages),
                "origin": "plugin" if analyzer.name in plugin_names else "builtin",
                "isolation": plugin_policy.isolation if analyzer.name in plugin_names else "in-process",
            }
            for analyzer in analyzers
        ],
        "implemented_analyzer_domains": [
            item["id"] for item in domain_catalog if item["status"] == "implemented"
        ],
        "partial_analyzer_domains": [
            item["id"] for item in domain_catalog if item["status"] == "partial"
        ],
        "python_dependency_graph": python_graph,
        "code_index": code_index,
        "performance": {
            "phase_seconds": dict(timer.phases),
            "elapsed_seconds_before_reporting": timer.elapsed(),
            "files_per_second": round(len(records) / max(timer.elapsed(), 1e-9), 1),
            "bytes_per_second": round(walk_stats.get("total_bytes", 0) / max(timer.elapsed(), 1e-9)),
            "peak_rss_bytes": peak_rss_bytes(),
            "peak_rss_scope": "coordinator process (worker processes are separate)",
        },
        "architecture_layout": architecture_layout,
    }
    result = ScanResult(
        display_root or str(root), started, now(), records, findings, metrics, errors,
        [analyzer.name for analyzer in analyzers] + ["python-module-graph"],
        directories=directories,
        symlinks=symlinks,
        special_entries=special_entries,
    )
    reports = write_reports(result, output, formats)
    timer.lap("reporting")
    for report in reports:
        _status(console, "SUCCESS", "Report: " + str(report), "green")

    summary = Table(
        title="PROJECT DISCOVERY SUMMARY",
        show_header=True,
        header_style="bold cyan",
    )
    summary.add_column("Metric")
    summary.add_column("Value", justify="right")
    if source_metadata is not None:
        revision = source_metadata.get("revision")
        summary.add_row(
            "Remote source",
            escape(f"{source_metadata.get('url', '')}" + (f" @ {revision}" if revision else "")),
        )
    summary.add_row("Files inventoried", str(len(records)))
    summary.add_row("Directories inventoried", str(metrics["directory_count"]))
    summary.add_row("Symbolic links", str(metrics["symlink_count"]))
    summary.add_row("Special filesystem entries", str(metrics["special_entry_count"]))
    summary.add_row("Explicitly pruned directories", str(metrics["pruned_directory_count"]))
    summary.add_row("Hidden entries", str(metrics["hidden_entry_count"]))
    summary.add_row("Development/cache trees", str(metrics["development_directory_count"]))
    summary.add_row("Total size", f"{metrics['total_bytes']:,} bytes")
    summary.add_row("Languages / formats detected", str(len(counts)))
    summary.add_row("Findings", str(len(findings)))
    summary.add_row("Scan errors", str(len(errors) + metrics["walk_errors"]))
    summary.add_row("Large files skipped by request", str(metrics["oversized_files"]))
    summary.add_row("Analyzer domains catalogued", str(metrics["analyzer_domain_count"]))
    summary.add_row("Native backend", metrics["native_backend"]["backend"])
    summary.add_row("GPU acceleration", metrics["native_backend"].get("gpu_status", "cpu-fallback"))
    summary.add_row("GPU byte-count dispatches", str(metrics["native_backend"].get("gpu_dispatches", 0)))
    summary.add_row("GPU CPU fallbacks", str(metrics["native_backend"].get("gpu_fallbacks", 0)))
    summary.add_row(
        "Analysis workers",
        f"{metrics['execution']['worker_count']} ({metrics['execution']['executor']}s)",
    )
    summary.add_row(
        "Phase timings",
        " / ".join(f"{name} {seconds:.1f}s" for name, seconds in timer.phases.items()),
    )
    rss = metrics["performance"]["peak_rss_bytes"]
    summary.add_row("Peak coordinator memory", f"{rss / 1024 / 1024:,.0f} MiB" if rss else "unavailable")
    summary.add_row(
        "Local vulnerability advisories",
        str(vulnerability_db_status.get("advisory_count", 0))
        if vulnerability_db_status["enabled"] else "not configured",
    )
    online_status = vulnerability_db_status.get("online")
    if online_status:
        summary.add_row(
            "Online vulnerability lookup",
            f"{online_status.get('packages_queried', 0):,} checked / "
            f"{online_status.get('vulnerable_packages', 0):,} vulnerable "
            f"({online_status.get('coverage', 'unknown')})",
        )
    summary.add_row("VCS / hosting / delivery signals", str(metrics["vcs_provider_signal_count"]))
    console.print(summary)
    _print_security_findings(console, findings)
    _status(
        console,
        "SUCCESS",
        f"Scan complete: {len(records)} files; {len(findings)} findings; reports in {output}",
        "green",
    )
    error_count = len(errors)
    if error_count:
        _status(
            console,
            "WARNING",
            f"{error_count} file/analyzer errors recorded in JSON report.",
            "yellow",
        )

    exit_code = EXIT_OK
    if strict and (error_count or metrics["walk_errors"]):
        exit_code = EXIT_INCOMPLETE
        _status(
            console, "FAILED",
            "--strict: the scan is incomplete because of file, analyzer or traversal errors.",
            "red",
        )
    if fail_on is not None:
        # UNKNOWN findings describe coverage gaps; --strict is the gate for those.
        threshold = SEVERITY_RANK[fail_on]
        gated = sum(
            1 for finding in findings
            if finding.confidence != "UNKNOWN"
            and SEVERITY_RANK.get(finding.severity, len(SEVERITY_RANK)) <= threshold
        )
        if gated:
            exit_code = EXIT_FINDINGS
            _status(
                console, "FAILED",
                f"--fail-on {fail_on}: {gated:,} finding(s) at or above {fail_on} severity.",
                "red",
            )
    return exit_code


def capabilities_report() -> dict:
    """Describe this installation: native backends, optional parsers and analyzers."""
    from importlib import metadata

    def version_of(distribution: str) -> str | None:
        try:
            return metadata.version(distribution)
        except metadata.PackageNotFoundError:
            return None

    grammars: list[str] | None = None
    try:
        pack = importlib.import_module("tree_sitter_language_pack")
        # downloaded_languages() only reads the local cache; it never downloads.
        if hasattr(pack, "downloaded_languages"):
            grammars = sorted(pack.downloaded_languages())
    except ImportError:
        pass
    loaded = load_analyzers()
    loaded.close()  # metadata only; no analysis runs here
    domains = analyzer_domain_catalog()
    from .intelligence.model.tree_sitter_model import MODEL_GRAMMARS, model_grammar

    # Languages whose code model a provisioned grammar refines (else the lexer models them).
    code_model = {
        language: {
            "grammar": grammar,
            "backend": "tree-sitter" if grammars and grammar in grammars and model_grammar(language, "")
            else "lexical",
        }
        for language, grammar in sorted(MODEL_GRAMMARS.items())
    }
    return {
        "pdt_version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "native_backend": native_capabilities(),
        "remote_vcs_clients": remote_vcs_capabilities(),
        "optional_integrations": {
            "tree-sitter-language-pack": version_of("tree-sitter-language-pack"),
            "provisioned_grammars": grammars,
            "code_model": code_model,
            "pypdf": version_of("pypdf"),
            "python-docx": version_of("python-docx"),
            "PyYAML": version_of("PyYAML"),
        },
        "analyzers": [
            {"name": analyzer.name, "version": analyzer.version, "domains": list(analyzer.domains)}
            for analyzer in loaded.analyzers
        ],
        "plugin_diagnostics": loaded.diagnostics,
        "plugins": loaded.plugins,
        # A host started without a plugin shows what the default sandbox verifies here.
        "plugin_sandbox": probe_sandbox(),
        "domain_status_counts": dict(Counter(item["status"] for item in domains)),
        "recognized_language_count": recognized_language_count(),
    }


def _sandbox_summary(probe: dict) -> str:
    sandbox = probe.get("sandbox") or {}
    restrictions = sandbox.get("restrictions", {})
    denied = [name.replace("_", " ") for name, value in restrictions.items() if value]
    open_ = [name.replace("_", " ") for name, value in restrictions.items() if not value]
    summary = "available" if probe.get("available") else f"unavailable ({probe.get('error')})"
    if sandbox.get("mechanisms"):
        summary += f" via {', '.join(sandbox['mechanisms'])}"
    if denied:
        summary += f"; denies {', '.join(denied)}"
    if open_:
        summary += f"; does not restrict {', '.join(open_)}"
    return summary


_REMOTE_STATUS_BY_EXIT = {
    EXIT_OK: "completed",
    EXIT_FINDINGS: "findings",
    EXIT_INCOMPLETE: "incomplete",
}


def _remote_batch_exit_code(results: list[dict], *, multiple: bool) -> int:
    """Combine per-target outcomes; a --fail-on hit takes precedence, as in a local scan.

    A single remote target that cannot be fetched is a fatal error (2), like a missing
    local path. In a batch the other repositories are still scanned, so an unreachable
    repository makes the batch incomplete (3).
    """
    statuses = {entry["status"] for entry in results}
    if "findings" in statuses:
        return EXIT_FINDINGS
    if "failed" in statuses:
        return EXIT_INCOMPLETE if multiple else EXIT_USAGE
    if "incomplete" in statuses:
        return EXIT_INCOMPLETE
    return EXIT_OK


def _remote_target_entry(index: int, target, report_directory: Path, status: str) -> dict:
    return {
        "index": index,
        "url": target.clone_url,
        "provider": target.provider,
        "vcs": target.vcs,
        "repository": target.repository_name,
        "ref": target.ref,
        "identity": target.identity,
        "transport_insecure": target.insecure_transport,
        "report_directory": str(report_directory),
        "status": status,
        "exit_code": None,
        "revision": None,
        "error": None,
        "cleanup_error": None,
        "started_at": None,
        "finished_at": None,
        "seconds": None,
    }


def _run_remote_targets(
    targets,
    *,
    output: Path | None,
    formats: set[str],
    max_file_mb: int,
    remote_timeout: int,
    scan_options: dict,
    remote_options: dict | None = None,
    no_download: NoDownloadOptions | None = None,
) -> int:
    """Scan one or more remote repositories, continuing after target-specific failures.

    Each target gets its own report directory. A batch also writes batch-summary.json
    and batch-summary.md (per-target status, revision, exit code and error) into the
    output directory, including when the batch is interrupted.
    """
    remote_options = dict(remote_options or {})
    allow_insecure = bool(remote_options.get("allow_insecure_transport", False))
    multiple = len(targets) > 1
    base_output = output
    if multiple and base_output is None:
        base_output = Path.cwd() / "pdt-remote-reports"
    console = Console(
        stderr=True, quiet=bool(scan_options.get("quiet")),
        no_color=True if scan_options.get("no_color") else None,
    )
    # --quiet suppresses progress, never errors: failures and cleanup problems always print.
    error_console = Console(stderr=True, no_color=True if scan_options.get("no_color") else None)

    def report_directory(target) -> Path:
        if multiple:
            return base_output / target.output_name
        return base_output or Path.cwd() / f"{target.output_name}-pdt-report"

    batch_started = now()
    results: list[dict] = []

    def summarize(exit_code: int) -> None:
        if not multiple:
            return
        for path in write_remote_batch_summary(
            base_output, results, started_at=batch_started, finished_at=now(), exit_code=exit_code,
        ):
            _status(console, "SUCCESS", "Batch summary: " + str(path), "green")

    try:
        for index, target in enumerate(targets, 1):
            target_output = report_directory(target)
            entry = _remote_target_entry(index, target, target_output, "running")
            entry["started_at"] = now()
            results.append(entry)
            _status(
                console, "REMOTE",
                f"[{index}/{len(targets)}] {target.provider} / {target.repository_name} "
                f"({target.vcs}) {target.clone_url}" + (f" @ {target.ref}" if target.ref else ""),
                "cyan",
            )
            started = time.monotonic()

            def cleanup_failed(message: str, entry=entry) -> None:
                entry["cleanup_error"] = message
                _status(error_console, "WARNING", message, "yellow")

            try:
                if no_download is not None:
                    # Analyze through the provider API in memory; nothing is cloned.
                    source = NoDownloadSource(target, no_download)
                    source.open()
                    entry["revision"] = source.metadata.get("revision")
                    entry["acquisition"] = "api"
                    code = run_scan(
                        source.virtual_root, target_output, formats, max_file_mb,
                        source_metadata=source.metadata, display_root=target.clone_url,
                        memory_source=source, **scan_options,
                    )
                else:
                    check_transport_policy(target, allow_insecure=allow_insecure)
                    with remote_checkout(
                        target, timeout=remote_timeout, on_cleanup_error=cleanup_failed,
                        **remote_options,
                    ) as checkout:
                        entry["revision"] = checkout.metadata.get("revision")
                        for note in checkout.metadata.get("warnings", []):
                            _status(console, "WARNING", str(note), "yellow")
                        code = run_scan(
                            checkout.path,
                            target_output,
                            formats,
                            max_file_mb,
                            source_metadata=checkout.metadata,
                            display_root=target.clone_url,
                            **scan_options,
                        )
                entry["exit_code"] = code
                entry["status"] = _REMOTE_STATUS_BY_EXIT.get(code, "failed")
            except KeyboardInterrupt:
                entry["status"] = "interrupted"
                entry["exit_code"] = EXIT_INTERRUPTED
                raise
            except (OSError, ValueError, sqlite3.Error, NetworkError) as exc:
                entry["status"] = "failed"
                entry["error"] = sanitize_client_output(str(exc), max_chars=4_000)
                _status(
                    error_console, "FAILED",
                    f"{target.provider} / {target.repository_name}: {entry['error']}", "red",
                )
            finally:
                entry["finished_at"] = now()
                entry["seconds"] = round(time.monotonic() - started, 3)
    except KeyboardInterrupt:
        for index, target in enumerate(targets[len(results):], len(results) + 1):
            results.append(_remote_target_entry(index, target, report_directory(target), "not_started"))
        summarize(EXIT_INTERRUPTED)
        raise

    exit_code = _remote_batch_exit_code(results, multiple=multiple)
    summarize(exit_code)
    counts = Counter(entry["status"] for entry in results)
    _status(
        console, "SUCCESS" if exit_code == EXIT_OK else "WARNING",
        f"Remote scan complete: {counts.get('completed', 0) + counts.get('findings', 0)}/"
        f"{len(targets)} repository scan(s) completed; {counts.get('failed', 0)} failed; "
        f"{counts.get('incomplete', 0)} incomplete; {counts.get('findings', 0)} hit --fail-on.",
        "green" if exit_code == EXIT_OK else "yellow",
    )
    return exit_code


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pdt", description="Local-first project intelligence analyzer"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="Analyze a local project or scan a remote VCS repository",
    )
    scan.add_argument("path", nargs="?", type=str, metavar="PATH_OR_URL")
    scan.add_argument(
        "--url", type=Path, default=None, metavar="FILE",
        help="Read one repository per line from a UTF-8 text file (URL [ref=NAME] [vcs=BACKEND]); "
             "providers and VCS backends may be mixed",
    )
    scan.add_argument(
        "--vcs", choices=REMOTE_VCS, default="auto",
        help="Remote VCS backend: auto, git, hg, svn, bzr/bazaar, darcs, jj, pijul, cvs, "
             "p4/perforce or fossil",
    )
    scan.add_argument(
        "--ref", default=None, metavar="REF",
        help="Branch, tag or revision of a remote repository to scan (Git also accepts a full "
             "commit ID; Subversion a revision number). Default: the remote default branch",
    )
    scan.add_argument(
        "--remote-timeout", type=int, default=None, metavar="SECONDS",
        help=f"Timeout for each remote clone/checkout operation (default: {DEFAULT_REMOTE_TIMEOUT})",
    )
    scan.add_argument(
        "--remote-workdir", type=Path, default=None, metavar="DIR",
        help="Directory for temporary remote checkouts (default: the system temporary directory); "
             "they are deleted when each scan ends",
    )
    scan.add_argument(
        "--remote-max-gb", type=float, default=None, metavar="GIB",
        help="Stop materializing a remote repository after this much file content; the rest is "
             f"reported as a coverage gap (default: {DEFAULT_REMOTE_MAX_BYTES // 1024 ** 3})",
    )
    scan.add_argument(
        "--no-download", action="store_true",
        help="Analyze a remote GitHub, GitLab, Bitbucket Cloud or Gitea/Forgejo repository "
             "through its provider API in memory, without cloning or writing it to disk",
    )
    scan.add_argument(
        "--api-provider", choices=API_PROVIDERS, default="auto",
        help="With --no-download: provider API to use (default: detected from the URL host)",
    )
    scan.add_argument(
        "--api-url", default=None, metavar="URL",
        help="With --no-download and one URL: API base URL (GitHub Enterprise, self-managed "
             "GitLab, Gitea); PDT_API_URL_<HOST> sets it per host for batches",
    )
    scan.add_argument(
        "--api-max-files", type=int, default=None, metavar="N",
        help=f"With --no-download: fetch at most N file contents (default: {DEFAULT_API_MAX_FILES:,})",
    )
    scan.add_argument(
        "--api-max-mb", type=int, default=None, metavar="MB",
        help=f"With --no-download: fetch at most this much content (default: {DEFAULT_API_MAX_BYTES // 1024 ** 2})",
    )
    scan.add_argument(
        "--api-max-file-mb", type=int, default=None, metavar="MB",
        help=f"With --no-download: skip larger files (default: {DEFAULT_API_MAX_FILE_BYTES // 1024 ** 2})",
    )
    scan.add_argument(
        "--api-max-requests", type=int, default=None, metavar="N",
        help=f"With --no-download: API request budget per repository (default: {DEFAULT_API_MAX_REQUESTS:,})",
    )
    scan.add_argument(
        "--api-workers", type=int, default=None, metavar="N",
        help=f"With --no-download: parallel content requests (default: {DEFAULT_API_WORKERS})",
    )
    scan.add_argument(
        "--use-credential-helper", action="store_true",
        help="With --no-download: ask your Git credential helper for the repository host's token "
             "(non-interactive) when no token variable is set",
    )
    scan.add_argument(
        "--allow-insecure-transport", action="store_true",
        help="Allow plain-text transports (git://, http://, svn://, bzr://, CVS pserver, Perforce "
             "tcp); refused by default because fetched source could be altered in transit",
    )
    scan.add_argument("--output", type=Path, default=None)
    scan.add_argument("--format", default="json,markdown,html")
    scan.add_argument(
        "--jobs", type=int, default=0,
        help="Concurrent analysis workers; 0 auto-detects a bounded worker count (default: 0)",
    )
    scan.add_argument(
        "--skip", action="store_true",
        help="Opt in to skipping content analysis for files above --max-file-mb",
    )
    scan.add_argument(
        "--max-file-mb", type=int, default=128,
        help="Size threshold used only with --skip (default: 128 MiB)",
    )
    scan.add_argument(
        "--exclude-dir", action="append", default=[],
        metavar="NAME",
        help="Explicitly prune a directory name or relative path; the directory remains inventoried",
    )
    scan.add_argument(
        "--vuln-db", type=Path, default=None,
        help="Use a local OSV advisory SQLite database; scanning performs no network access",
    )
    scan.add_argument(
        "--vuln-online", action="store_true",
        help="Opt in to looking up lockfile packages in OSV.dev (sends only ecosystem, package "
             "name and version; never file contents). Failures are reported as UNKNOWN coverage",
    )
    scan.add_argument(
        "--vuln-enrich", default=None, metavar="SOURCES",
        help="With --vuln-online: add CVE details from 'nvd' (NVD CVE API 2.0) and/or 'ghsa' "
             "(GitHub Advisory Database), comma-separated. Keys: NVD_API_KEY, GITHUB_TOKEN",
    )
    scan.add_argument(
        "--vuln-cache", type=Path, default=None, metavar="FILE",
        help="With --vuln-online: SQLite response cache (default: ~/.pdt/online-vulnerability-cache.sqlite3)",
    )
    scan.add_argument(
        "--vuln-cache-ttl", type=float, default=None, metavar="HOURS",
        help="With --vuln-online: reuse cached answers for this long; 0 disables the cache (default: 24)",
    )
    scan.add_argument(
        "--network-timeout", type=float, default=None, metavar="SECONDS",
        help=f"Per-request timeout for online services (default: {DEFAULT_NETWORK_TIMEOUT:.0f})",
    )
    scan.add_argument(
        "--ca-bundle", type=Path, default=None, metavar="FILE",
        help="PEM CA bundle for HTTPS to online services (private or intercepting CAs); "
             "certificate verification is never disabled",
    )
    scan.add_argument(
        "--fail-on", choices=tuple(SEVERITY_RANK), type=str.upper, default=None,
        metavar="SEVERITY",
        help="Exit with status 1 when a CONFIRMED/INFERRED finding is at or above this "
             "severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)",
    )
    scan.add_argument(
        "--strict", action="store_true",
        help="Exit with status 3 when any file, analyzer or traversal error left the scan incomplete",
    )
    scan.add_argument(
        "--executor", choices=EXECUTOR_MODES, default="auto",
        help="Analysis executor: worker processes (parallel CPU), threads, or auto "
             "(processes for large inventories; default: auto)",
    )
    scan.add_argument(
        "--resume", action="store_true",
        help="Continue an interrupted scan of the same root into the same --output: reuse its "
             "inventory and stored findings and analyze only files not yet processed",
    )
    scan.add_argument(
        "--inventory-only", action="store_true",
        help="Inventory files, directories and links without reading file contents "
             "(no hashing or content analyzers)",
    )
    scan.add_argument(
        "--plugin-isolation", choices=ISOLATION_MODES, default="sandbox",
        help="How third-party analyzer plugins run: sandbox (a separate process under a "
             "verified OS sandbox; refused where it cannot be applied), process (a separate "
             "process without OS restrictions) or off (in-process with PDT's permissions; "
             "trusted plugins only). Default: sandbox",
    )
    scan.add_argument(
        "--plugin-timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, metavar="SECONDS",
        help="Time a plugin may take per request before its host is stopped (default: 60)",
    )
    scan.add_argument(
        "--plugin-memory-mb", type=int, default=DEFAULT_MEMORY_LIMIT_MB, metavar="MB",
        help="Memory limit per plugin host on Linux and Windows; 0 disables it (default: 4096)",
    )
    scan.add_argument("--quiet", action="store_true", help="Suppress console output except errors")
    scan.add_argument(
        "--no-color", action="store_true",
        help="Disable colored console output (the NO_COLOR environment variable is also honored)",
    )
    capabilities = sub.add_parser(
        "capabilities", help="Show native backends, optional parsers and analyzers available here",
    )
    capabilities.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    plugin_check = sub.add_parser(
        "plugin-check",
        help="Check a third-party analyzer plugin the way a scan loads it, on sample files",
    )
    plugin_check.add_argument(
        "plugin", help="module:attribute of the analyzer, or the name of an installed pdt.analyzers entry point",
    )
    plugin_check.add_argument("samples", type=Path, nargs="*", help="Sample files or directories to analyze")
    plugin_check.add_argument(
        "--isolation", choices=("sandbox", "process"), default="sandbox",
        help="Run the plugin under the OS sandbox (default) or out of process without restrictions",
    )
    plugin_check.add_argument("--timeout", type=float, default=60.0, metavar="SECONDS",
                              help="Time allowed per plugin request (default: 60)")
    plugin_check.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    query = sub.add_parser(
        "query", help="Look up symbols, callers, callees or references in a scan's code index",
    )
    query.add_argument("scan_output", type=Path, help="The --output directory of a completed scan")
    lookup = query.add_mutually_exclusive_group(required=True)
    lookup.add_argument("--symbol", metavar="NAME", help="Definitions named NAME (or Qualified.NAME)")
    lookup.add_argument("--callers", metavar="NAME", help="Call sites that call NAME")
    lookup.add_argument("--callees", metavar="NAME", help="Calls made inside the function NAME")
    lookup.add_argument("--references", metavar="NAME", help="Files that reference the identifier NAME")
    query.add_argument("--limit", type=int, default=200, help="Maximum rows (default: 200)")
    query.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    compare = sub.add_parser("compare", help="Compare two or more independent PDT JSON reports")
    compare.add_argument("reports", type=Path, nargs="+")
    compare.add_argument("--output", type=Path, default=Path("./pdt-comparison"))
    compare.add_argument("--format", default="json,markdown")
    catalog_add = sub.add_parser("catalog-add", help="Register a local PDT JSON report")
    catalog_add.add_argument("report", type=Path)
    catalog_add.add_argument("--db", type=Path, default=Path.home() / ".pdt" / "catalog.sqlite3")
    catalog_list = sub.add_parser("catalog-list", help="List locally registered projects")
    catalog_list.add_argument("--db", type=Path, default=Path.home() / ".pdt" / "catalog.sqlite3")
    catalog_remove = sub.add_parser("catalog-remove", help="Remove a project from the local catalog")
    catalog_remove.add_argument("root", type=Path)
    catalog_remove.add_argument("--db", type=Path, default=Path.home() / ".pdt" / "catalog.sqlite3")
    catalog_compare = sub.add_parser("catalog-compare", help="Compare every registered project report")
    catalog_compare.add_argument("--db", type=Path, default=Path.home() / ".pdt" / "catalog.sqlite3")
    catalog_compare.add_argument("--output", type=Path, default=Path("./pdt-catalog-comparison"))
    catalog_compare.add_argument("--format", default="json,markdown")
    vuln_db = sub.add_parser(
        "vuln-db", help="Manage the local offline vulnerability advisory database"
    )
    vuln_actions = vuln_db.add_subparsers(dest="vuln_action", required=True)
    vuln_import = vuln_actions.add_parser(
        "import", help="Import local OSV JSON records without network access"
    )
    vuln_import.add_argument("source", type=Path, help="Local OSV JSON file or directory tree")
    vuln_import.add_argument("--db", type=Path, default=default_database_path())
    vuln_status = vuln_actions.add_parser(
        "status", help="Show local advisory database coverage"
    )
    vuln_status.add_argument("--db", type=Path, default=default_database_path())
    args = parser.parse_args()
    formats = (
        {item.strip().lower() for item in args.format.split(",") if item.strip()}
        if hasattr(args, "format") else set()
    )
    try:
        if args.command == "vuln-db":
            if args.vuln_action == "import":
                with VulnerabilityDatabase(args.db) as database:
                    imported = database.import_osv(args.source)
                print(
                    f"[ SUCCESS ] Imported {imported['imported_advisories']} advisory record(s); "
                    f"{imported['affected_package_records']} affected package record(s); "
                    f"{imported['skipped_records']} skipped."
                )
                for error in imported["errors"][:20]:
                    print("[ WARNING ] " + error)
                raise SystemExit(0 if imported["skipped_records"] == 0 else 1)
            with VulnerabilityDatabase(args.db) as database:
                status = database.status()
            print("[ VULNERABILITY DATABASE ]")
            print(f"[ INFO ] Database: {status['database']}")
            print(f"[ INFO ] Advisories: {status['advisory_count']}")
            print(f"[ INFO ] Affected package records: {status['affected_package_records']}")
            print(f"[ INFO ] Last import: {status.get('last_imported_at', 'never')}")
            for ecosystem, count in status["ecosystems"].items():
                print(f"[ ECOSYSTEM ] {ecosystem}: {count}")
            raise SystemExit(0)
        if args.command == "query":
            kind, name = next(
                (kind, getattr(args, kind)) for kind in QUERY_KINDS if getattr(args, kind) is not None
            )
            if not 1 <= args.limit <= 100_000:
                parser.error("--limit must be between 1 and 100000")
            rows = query_code_index(
                args.scan_output.expanduser() / ".pdt-cache" / "inventory.sqlite3", kind, name, args.limit,
            )
            if args.json:
                print(json.dumps(rows, indent=2, ensure_ascii=False))
                raise SystemExit(0)
            for row in rows:
                location = f"{row['path']}:{row['line']}" if "line" in row else row["path"]
                detail = {
                    "symbol": lambda r: f"{r['kind']} {r['qualified']} ({r['language']}, lines {r['line']}-{r['end_line']})",
                    "callers": lambda r: f"{r['caller']} calls {name}" + (f" -> {r['target']}" if r["target"] else ""),
                    "callees": lambda r: f"{r['caller']} calls {r['callee']}" + (f" -> {r['target']}" if r["target"] else ""),
                    "references": lambda r: "",
                }[kind](row)
                print(f"{location}  {detail}".rstrip())
            print(f"[ INFO ] {len(rows)} result(s)" + (" (limit reached)" if len(rows) == args.limit else ""))
            raise SystemExit(0)
        if args.command == "plugin-check":
            from .plugins.conformance import check_plugin, format_report, report_json

            if not 0 < args.timeout <= 3600:
                parser.error("--timeout must be greater than 0 and at most 3600 seconds")
            result = check_plugin(args.plugin, args.samples, isolation=args.isolation,
                                  timeout_seconds=args.timeout)
            print(report_json(result) if args.json else format_report(result))
            raise SystemExit(EXIT_OK if result.ok else EXIT_FINDINGS)
        if args.command == "capabilities":
            report = capabilities_report()
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
                raise SystemExit(0)
            console = Console()
            native = report["native_backend"]
            table = Table(title=f"PDT {report['pdt_version']} capabilities", header_style="bold cyan")
            table.add_column("Component")
            table.add_column("Status")
            table.add_row("Python / platform", f"{report['python']} / {report['platform']}")
            table.add_row("C byte counter", f"{native.get('backend')} (assembly: {native.get('assembly_compiled')})")
            table.add_row("GPU (OpenCL)", f"{native.get('gpu_status')} {native.get('gpu_name') or ''}".strip())
            table.add_row("C++ signature classifier", "online" if native.get("cpp_signature_classifier") else "fallback")
            table.add_row("Rust filesystem walker", "online" if native.get("rust_filesystem_walker") else "fallback")
            for backend, client in report["remote_vcs_clients"].items():
                executable = client.get("executable")
                alternatives = " or ".join(client.get("alternatives", []))
                status = (
                    f"available ({Path(str(executable)).name})"
                    if client.get("available") and executable
                    else f"not installed ({alternatives})"
                )
                table.add_row(f"Remote VCS: {backend}", status)
            for name, value in report["optional_integrations"].items():
                if name == "provisioned_grammars":
                    value = "n/a" if value is None else f"{len(value)} grammar(s) provisioned locally"
                elif name == "code_model":
                    refined = sorted(language for language, item in value.items() if item["backend"] == "tree-sitter")
                    value = (
                        f"Tree-sitter for {len(refined)} of {len(value)} languages ({', '.join(refined)})"
                        if refined else f"structural lexer (no grammar provisioned for {len(value)} languages)"
                    )
                    name = "Code model"
                table.add_row(name, str(value) if value else "not installed")
            table.add_row("Analyzers", f"{len(report['analyzers'])} loaded")
            table.add_row("Plugin sandbox", escape(_sandbox_summary(report["plugin_sandbox"])))
            for plugin in report["plugins"]:
                table.add_row(
                    escape(f"Plugin {plugin.get('name') or plugin.get('entry_point')}"),
                    escape(plugin.get("status", "unknown")),
                )
            table.add_row("Analyzer domains", ", ".join(f"{k}: {v}" for k, v in sorted(report["domain_status_counts"].items())))
            table.add_row("Recognized languages/formats", str(report["recognized_language_count"]))
            console.print(table)
            for diagnostic in report["plugin_diagnostics"]:
                console.print("[ WARNING ] " + escape(diagnostic))
            raise SystemExit(0)
        if args.command == "catalog-add":
            with ProjectCatalog(args.db) as catalog:
                item = catalog.add_report(args.report)
            print("[ SUCCESS ] Registered project: " + item["root"])
            raise SystemExit(0)
        if args.command == "catalog-list":
            with ProjectCatalog(args.db) as catalog:
                projects = catalog.list_projects()
            for item in projects:
                print(
                    f"[ PROJECT ] {item['name']} | {item['file_count']} files | "
                    f"{item['finding_count']} findings | {item['root']}"
                )
            print(f"[ INFO ] {len(projects)} projects registered")
            raise SystemExit(0)
        if args.command == "catalog-remove":
            with ProjectCatalog(args.db) as catalog:
                removed = catalog.remove_project(args.root)
            print("[ SUCCESS ] Project removed" if removed else "[ INFO ] Project not found")
            raise SystemExit(0)
        if args.command == "catalog-compare":
            if not formats or formats - {"json", "markdown"}:
                parser.error("catalog-compare --format accepts json, markdown")
            with ProjectCatalog(args.db) as catalog:
                reports = catalog.load_reports()
            comparison = compare_many_reports(reports)
            for report in write_comparison(comparison, args.output, formats):
                print("[ SUCCESS ] Catalog comparison: " + str(report))
            raise SystemExit(0)
        if args.command == "scan":
            if not formats or formats - {"json", "markdown", "html"}:
                parser.error("scan --format accepts json, markdown, html")
            if args.max_file_mb < 1:
                parser.error("--max-file-mb must be >= 1")
            if args.url is not None and args.path is not None:
                parser.error("Use either scan --url FILE or scan PATH_OR_URL, not both")
            if args.url is None and args.path is None:
                parser.error("Provide a local PATH, a remote URL, or --url FILE")
            remote_scan = args.url is not None or is_remote_target(args.path or "")
            if args.resume and remote_scan:
                parser.error("--resume is supported for local scan roots, not temporary remote checkouts")
            if not remote_scan:
                for option, value in (
                    ("--vcs", args.vcs != "auto"), ("--ref", args.ref is not None),
                    ("--remote-timeout", args.remote_timeout is not None),
                    ("--remote-workdir", args.remote_workdir is not None),
                    ("--remote-max-gb", args.remote_max_gb is not None),
                    ("--allow-insecure-transport", args.allow_insecure_transport),
                ):
                    if value:
                        parser.error(f"{option} can be used only when scanning a remote repository URL")
            remote_timeout = DEFAULT_REMOTE_TIMEOUT if args.remote_timeout is None else args.remote_timeout
            if remote_timeout < 1 or remote_timeout > 86_400:
                parser.error("--remote-timeout must be between 1 and 86400 seconds")
            max_gib = DEFAULT_REMOTE_MAX_BYTES / 1024 ** 3 if args.remote_max_gb is None else args.remote_max_gb
            if not 0 < max_gib <= 1_048_576:
                parser.error("--remote-max-gb must be greater than 0 and at most 1048576")
            if args.vuln_db is not None and not args.vuln_db.expanduser().is_file():
                parser.error(f"--vuln-db is not a file: {args.vuln_db}")
            no_download_options = None
            api_options = (
                ("--api-provider", args.api_provider != "auto"), ("--api-url", args.api_url is not None),
                ("--api-max-files", args.api_max_files is not None),
                ("--api-max-mb", args.api_max_mb is not None),
                ("--api-max-file-mb", args.api_max_file_mb is not None),
                ("--api-max-requests", args.api_max_requests is not None),
                ("--api-workers", args.api_workers is not None),
                ("--use-credential-helper", args.use_credential_helper),
            )
            if not args.no_download:
                for option, value in api_options:
                    if value:
                        parser.error(f"{option} requires --no-download")
            else:
                if not remote_scan:
                    parser.error("--no-download can be used only with a remote repository URL or --url FILE")
                for option, value in (
                    ("--remote-workdir", args.remote_workdir is not None),
                    ("--remote-max-gb", args.remote_max_gb is not None),
                    ("--allow-insecure-transport", args.allow_insecure_transport),
                ):
                    if value:
                        parser.error(f"{option} applies to the download mode, not --no-download")
                if args.vcs not in {"auto", "git"}:
                    parser.error("--no-download reads Git hosting provider APIs; --vcs must be auto or git")
                if args.api_url is not None and args.url is not None:
                    parser.error("--api-url applies to one URL; use PDT_API_URL_<HOST> variables for --url batches")
                if args.api_url is not None:
                    validate_service_url(args.api_url, label="--api-url")
                for option, value, upper in (
                    ("--api-max-files", args.api_max_files, 10_000_000),
                    ("--api-max-mb", args.api_max_mb, 1_048_576),
                    ("--api-max-file-mb", args.api_max_file_mb, 102_400),
                    ("--api-max-requests", args.api_max_requests, 10_000_000),
                    ("--api-workers", args.api_workers, 32),
                ):
                    if value is not None and not 1 <= value <= upper:
                        parser.error(f"{option} must be between 1 and {upper:,}")
                if args.network_timeout is not None and not 0 < args.network_timeout <= 600:
                    parser.error("--network-timeout must be greater than 0 and at most 600 seconds")
                no_download_options = NoDownloadOptions(
                    provider=args.api_provider,
                    api_url=args.api_url,
                    use_credential_helper=args.use_credential_helper,
                    timeout=args.network_timeout or DEFAULT_NETWORK_TIMEOUT,
                    ca_bundle=resolve_ca_bundle(args.ca_bundle),
                    limits=ApiLimits(
                        max_files=args.api_max_files or DEFAULT_API_MAX_FILES,
                        max_bytes=(args.api_max_mb * 1024 ** 2) if args.api_max_mb else DEFAULT_API_MAX_BYTES,
                        max_file_bytes=(args.api_max_file_mb * 1024 ** 2) if args.api_max_file_mb else DEFAULT_API_MAX_FILE_BYTES,
                        max_requests=args.api_max_requests or DEFAULT_API_MAX_REQUESTS,
                        workers=args.api_workers or DEFAULT_API_WORKERS,
                    ),
                )
            online_vulnerabilities = None
            if not args.vuln_online:
                for option, value in (
                    ("--vuln-enrich", args.vuln_enrich), ("--vuln-cache", args.vuln_cache),
                    ("--vuln-cache-ttl", args.vuln_cache_ttl),
                ):
                    if value is not None:
                        parser.error(f"{option} requires --vuln-online")
                if not args.no_download:
                    for option, value in (
                        ("--network-timeout", args.network_timeout), ("--ca-bundle", args.ca_bundle),
                    ):
                        if value is not None:
                            parser.error(f"{option} requires --vuln-online or --no-download")
            else:
                enrich = [item.strip().lower() for item in (args.vuln_enrich or "").split(",") if item.strip()]
                if set(enrich) - set(ENRICHMENT_SOURCES):
                    parser.error(f"--vuln-enrich accepts: {', '.join(ENRICHMENT_SOURCES)}")
                if args.vuln_cache_ttl is not None and not 0 <= args.vuln_cache_ttl <= 87_600:
                    parser.error("--vuln-cache-ttl must be between 0 and 87600 hours")
                if args.network_timeout is not None and not 0 < args.network_timeout <= 600:
                    parser.error("--network-timeout must be greater than 0 and at most 600 seconds")
                online_vulnerabilities = OnlineVulnerabilityOptions.from_environment(
                    cache_path=args.vuln_cache or default_vulnerability_cache_path(),
                    cache_ttl_hours=args.vuln_cache_ttl,
                    ca_bundle=resolve_ca_bundle(args.ca_bundle),
                    timeout=args.network_timeout,
                    enrich=enrich,
                )
                validate_service_url(online_vulnerabilities.osv_url, label="PDT_OSV_API_URL")
                if "nvd" in enrich:
                    validate_service_url(online_vulnerabilities.nvd_url, label="PDT_NVD_API_URL")
                if "ghsa" in enrich:
                    validate_service_url(online_vulnerabilities.github_url, label="PDT_GITHUB_API_URL")

            scan_options = {
                "skip_oversized": args.skip,
                "ignores": set(args.exclude_dir),
                "vulnerability_db": args.vuln_db,
                "jobs": args.jobs,
                "fail_on": args.fail_on,
                "strict": args.strict,
                "quiet": args.quiet,
                "no_color": args.no_color,
                "executor": args.executor,
                "resume": args.resume,
                "inventory_only": args.inventory_only,
                "plugin_isolation": args.plugin_isolation,
                "plugin_timeout": args.plugin_timeout,
                "plugin_memory_mb": args.plugin_memory_mb,
                "online_vulnerabilities": online_vulnerabilities,
            }
            if remote_scan:
                remote_options = {
                    "workdir": args.remote_workdir,
                    "limits": RemoteLimits(max_bytes=max(1, int(max_gib * 1024 ** 3))),
                    "allow_insecure_transport": args.allow_insecure_transport,
                }
                if args.url is not None:
                    targets = load_remote_targets(args.url, vcs=args.vcs, ref=args.ref)
                else:
                    targets = [parse_remote_target(args.path, vcs=args.vcs, ref=args.ref)]
                raise SystemExit(_run_remote_targets(
                    targets,
                    output=args.output,
                    formats=formats,
                    max_file_mb=args.max_file_mb,
                    remote_timeout=remote_timeout,
                    scan_options=scan_options,
                    remote_options=remote_options,
                    no_download=no_download_options,
                ))
            raise SystemExit(run_scan(
                Path(args.path), args.output, formats, args.max_file_mb,
                skip_oversized=args.skip, ignores=set(args.exclude_dir),
                vulnerability_db=args.vuln_db, jobs=args.jobs,
                fail_on=args.fail_on, strict=args.strict,
                quiet=args.quiet, no_color=args.no_color, executor=args.executor,
                resume=args.resume, inventory_only=args.inventory_only,
                plugin_isolation=args.plugin_isolation, plugin_timeout=args.plugin_timeout,
                plugin_memory_mb=args.plugin_memory_mb,
                online_vulnerabilities=online_vulnerabilities,
            ))

        if not formats or formats - {"json", "markdown"}:
            parser.error("compare --format accepts json, markdown")
        if len(args.reports) < 2:
            parser.error("compare requires at least two report JSON files")
        comparison = compare_many_reports([load_report(path) for path in args.reports])
        for report in write_comparison(comparison, args.output, formats):
            print("[ SUCCESS ] Comparison report: " + str(report))
        raise SystemExit(0)
    except KeyboardInterrupt:
        parser.exit(EXIT_INTERRUPTED, "\n[ INTERRUPTED ] Scan cancelled; partial output may remain.\n")
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(EXIT_USAGE, "[ ERROR ] " + str(exc) + "\n")


if __name__ == "__main__":
    main()
