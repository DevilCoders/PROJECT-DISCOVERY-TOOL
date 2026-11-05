"""PDT command line."""
import argparse
import heapq
import importlib
import json
import os
import platform
import shutil
import sqlite3
from collections import Counter, deque
from concurrent.futures.process import BrokenProcessPool
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.markup import escape
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
from rich.panel import Panel

from . import __version__
from .analysis_engine import (
    BATCH_MAX_BYTES, BATCH_MAX_FILES, EXECUTOR_MODES, AnalysisExecutor, FileOutcome, FileTask,
    verified_regular_file_stat,
)
from .analyzer_catalog import analyzer_domain_catalog, analyzer_domain_count
from .analyzers import load_analyzers
from .analyzers.tree_sitter_analyzer import parser_capabilities
from .cache import ScanCache
from .inventory_store import (
    InventoryStore, StoredDiagnosticRecords, StoredFileRecords, StoredFindingRecords,
    StoredRecordSequence,
)
from .comparison import compare_many_reports, load_report, write_comparison
from .project_catalog import ProjectCatalog
from .language_catalog import language_catalog, recognized_language_count
from .models import DirectoryRecord, ScanResult, SpecialEntryRecord, SymlinkRecord
from .python_graph import analyze_python_dependencies
from .code_index import QUERY_KINDS, analyze_code_index, query_code_index
from .architecture_analyzer import analyze_project_architecture
from .reporting import write_reports
from .runtime_metrics import PhaseTimer, peak_rss_bytes
from .scanner import discover_inventory
from .native_backend import capabilities as native_capabilities, native_available
from .plugin_isolation import (
    DEFAULT_MEMORY_LIMIT_MB, DEFAULT_TIMEOUT_SECONDS, ISOLATION_MODES, PluginPolicy, probe_sandbox,
)
from .vulnerability_db import VulnerabilityDatabase, default_database_path
from .analyzers.vulnerability_analyzer import LocalVulnerabilityAnalyzer


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Kept under its historical name; the guard lives in the analysis engine.
_verified_regular_file_stat = verified_regular_file_stat


def _status(console: Console, label: str, message: str, style: str) -> None:
    # Messages carry paths and plugin text; "[...]" in them must not be read as markup.
    console.print(f"[bold {style}][ {label} ][/bold {style}] {escape(message)}")


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


def run_scan(
    root: Path, output: Path | None, formats: set[str], max_file_mb: int,
    *, skip_oversized: bool = False, ignores: set[str] | None = None,
    vulnerability_db: Path | None = None, jobs: int = 0,
    fail_on: str | None = None, strict: bool = False,
    quiet: bool = False, no_color: bool = False, executor: str = "auto",
    resume: bool = False, inventory_only: bool = False,
    plugin_isolation: str = "sandbox", plugin_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    plugin_memory_mb: int = DEFAULT_MEMORY_LIMIT_MB,
) -> int:
    # no_color=None lets Rich honor the NO_COLOR environment convention.
    console = Console(stderr=True, quiet=quiet, no_color=True if no_color else None)
    if jobs < 0 or jobs > 64:
        raise ValueError("--jobs must be 0 (automatic) or between 1 and 64")
    if fail_on is not None and fail_on not in SEVERITY_RANK:
        raise ValueError(f"--fail-on must be one of: {', '.join(SEVERITY_RANK)}")
    # Validates the plugin options before the (potentially long) inventory walk.
    PluginPolicy(plugin_isolation, plugin_timeout, plugin_memory_mb)
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

    _render_banner(console)
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
    try:
        with InventoryStore(inventory_path) as finding_store, ScanCache(cache_path) as cache:
            finding_store.extend_diagnostics(analyzer_load.diagnostics)
            with Progress(*progress_columns, console=console) as progress:
                task = progress.add_task("Analyzing project files", total=len(records))
                max_pending = max(2, engine.workers * 2)
                pending: deque = deque()
                batch: list[FileTask] = []
                batch_bytes = 0

                def batch_outcomes(future, tasks):
                    try:
                        return future.result()
                    except BrokenProcessPool:
                        # A worker died (native fault or OOM kill). Restart the pool and rerun
                        # this batch file by file so only the culprit file is lost.
                        engine.restart()
                        outcomes = []
                        for item in tasks:
                            try:
                                outcomes.extend(engine.submit([item]).result())
                            except BrokenProcessPool:
                                engine.restart()
                                message = f"{item.record.path}: analysis worker process terminated"
                                outcomes.append(FileOutcome(file_error=message, errors=[message]))
                        return outcomes

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

                try:
                    for record in records:
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
            if inventory_only:
                python_graph = {"summary": {"skipped": "inventory-only scan"}}
                graph_findings = []
            else:
                python_graph, graph_findings = analyze_python_dependencies(
                    root, records, finding_sink=finding_store.append_finding,
                    import_parser=lambda items: engine.map_python_imports(root, items),
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
        str(root), started, now(), records, findings, metrics, errors,
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
    return {
        "pdt_version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "native_backend": native_capabilities(),
        "optional_integrations": {
            "tree-sitter-language-pack": version_of("tree-sitter-language-pack"),
            "provisioned_grammars": grammars,
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pdt", description="Local-first project intelligence analyzer"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Analyze a project without modifying it")
    scan.add_argument("path", type=Path)
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
            for name, value in report["optional_integrations"].items():
                if name == "provisioned_grammars":
                    value = "n/a" if value is None else f"{len(value)} grammar(s) provisioned locally"
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
            raise SystemExit(run_scan(
                args.path, args.output, formats, args.max_file_mb,
                skip_oversized=args.skip, ignores=set(args.exclude_dir),
                vulnerability_db=args.vuln_db, jobs=args.jobs,
                fail_on=args.fail_on, strict=args.strict,
                quiet=args.quiet, no_color=args.no_color, executor=args.executor,
                resume=args.resume, inventory_only=args.inventory_only,
                plugin_isolation=args.plugin_isolation, plugin_timeout=args.plugin_timeout,
                plugin_memory_mb=args.plugin_memory_mb,
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
