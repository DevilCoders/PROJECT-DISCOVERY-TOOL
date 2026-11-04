"""PDT command line."""
import argparse
import os
import platform
import sqlite3
import stat
import threading
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
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
from .analyzer_catalog import analyzer_domain_catalog, analyzer_domain_count
from .analyzers import load_analyzers
from .analyzers.tree_sitter_analyzer import parser_capabilities
from .cache import ScanCache
from .inventory_store import InventoryStore, StoredFileRecords
from .comparison import compare_many_reports, load_report, write_comparison
from .project_catalog import ProjectCatalog
from .language_catalog import language_catalog, recognized_language_count
from .models import Finding, ScanResult
from .python_graph import analyze_python_dependencies
from .architecture_analyzer import analyze_project_architecture
from .reporting import write_reports
from .scanner import discover_inventory, sha256_file
from .native_backend import capabilities as native_capabilities, native_available
from .vulnerability_db import VulnerabilityDatabase, default_database_path
from .analyzers.vulnerability_analyzer import LocalVulnerabilityAnalyzer


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verified_regular_file_stat(path: Path, expected=None):
    """Reject symlink/non-regular substitutions and detect file identity changes.

    This narrows path-based TOCTOU exposure. Analyzer adapters still open paths
    independently, so descriptor-pinned reads remain a separate hardening task.
    """
    current = path.lstat()
    if not stat.S_ISREG(current.st_mode):
        raise OSError(f"refusing to analyze non-regular or symlink entry: {path}")
    if expected is not None:
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if isinstance(expected, tuple):
            expected_values = expected
        else:
            expected_values = tuple(getattr(expected, key) for key in identity)
        current_values = tuple(getattr(current, key, None) for key in identity)
        if any(
            wanted is not None and wanted != observed
            for wanted, observed in zip(expected_values, current_values)
        ):
            raise OSError(f"file identity changed during scan; refusing analysis: {path}")
    return current


def _status(console: Console, label: str, message: str, style: str) -> None:
    console.print(f"[bold {style}][ {label} ][/bold {style}] {message}")


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

def _print_security_findings(console: Console, findings: list[Finding], *, limit: int = 25) -> None:
    """Print bounded, redacted security evidence with severity, impact and remediation."""
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    security_findings = sorted(
        (
            finding for finding in findings
            if finding.category in {"security", "secrets", "privacy"}
        ),
        key=lambda finding: (
            severity_rank.get(finding.severity, 5),
            finding.title.casefold(),
            finding.analyzer,
        ),
    )
    if not security_findings:
        return

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
    omitted = len(security_findings) - limit
    if omitted > 0:
        console.print(
            f"[dim]... {omitted:,} additional security findings are available in the reports.[/dim]"
        )


def run_scan(
    root: Path, output: Path | None, formats: set[str], max_file_mb: int,
    *, skip_oversized: bool = False, ignores: set[str] | None = None,
    vulnerability_db: Path | None = None, jobs: int = 0,
) -> int:
    console = Console(stderr=True)
    if jobs < 0 or jobs > 64:
        raise ValueError("--jobs must be 0 (automatic) or between 1 and 64")
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

    _render_banner(console)
    _status(console, "INFO", "Read-only discovery: " + str(root), "cyan")
    started = now()
    inventory_path = output / ".pdt-cache" / "inventory.sqlite3"
    with InventoryStore(inventory_path) as inventory_store:
        records, directories, symlinks, special_entries, walk_stats = discover_inventory(
            root,
            max_file_bytes=max_file_mb * 1024 * 1024,
            skip_oversized=skip_oversized,
            ignores=ignores,
            store=inventory_store,
        )
    analyzer_load = load_analyzers()
    analyzers = analyzer_load.analyzers
    vulnerability_db_status = {"enabled": False, "advisory_count": 0}
    if vulnerability_db is not None:
        vulnerability_db = vulnerability_db.expanduser().resolve(strict=True)
        if not vulnerability_db.is_file():
            raise FileNotFoundError(
                f"Local vulnerability database is not a file: {vulnerability_db}"
            )
        if vulnerability_db == root or root in vulnerability_db.parents:
            raise ValueError("The vulnerability database must be outside the analyzed project.")
        with VulnerabilityDatabase(vulnerability_db) as advisory_store:
            vulnerability_db_status = {
                "enabled": True,
                **advisory_store.status(),
            }
        analyzers.append(LocalVulnerabilityAnalyzer(vulnerability_db))
    findings = []
    errors = list(analyzer_load.diagnostics)
    counts = Counter()
    cache_path = output / ".pdt-cache" / "fingerprints.sqlite3"
    hardware_threads = max(1, int(native_capabilities().get("hardware_threads", os.cpu_count() or 1)))
    worker_count = jobs or max(1, min(8, hardware_threads * 2))
    max_pending = max(worker_count, worker_count * 2)
    analyzer_locks = {
        id(analyzer): threading.Lock()
        for analyzer in analyzers
        if not getattr(analyzer, "concurrent_safe", True)
    }
    record_updates = []

    def persist_record(record):
        if isinstance(records, StoredFileRecords):
            record_updates.append(record)
            if len(record_updates) >= 512:
                records.update_records(record_updates)
                record_updates.clear()

    def analyze_one(record, path, digest_hint, expected_stat):
        local_findings = []
        local_errors = []
        digest = digest_hint
        try:
            _verified_regular_file_stat(path, expected_stat)
            if digest is None:
                digest = sha256_file(path, expected_info=expected_stat)
        except OSError as exc:
            return None, [], [f"{record.path}: {type(exc).__name__}: {exc}"]
        for analyzer in analyzers:
            try:
                lock = analyzer_locks.get(id(analyzer))
                if lock is None:
                    supported = analyzer.supports(record)
                    if supported:
                        local_findings.extend(analyzer.analyze(path, record))
                        record.analyzed = True
                else:
                    with lock:
                        supported = analyzer.supports(record)
                        if supported:
                            local_findings.extend(analyzer.analyze(path, record))
                            record.analyzed = True
            except Exception as exc:
                local_errors.append(
                    f"{record.path} [{analyzer.name}]: {type(exc).__name__}: {exc}"
                )
        try:
            _verified_regular_file_stat(path, expected_stat)
        except OSError as exc:
            # Findings produced while the path changed are not trustworthy.
            local_findings.clear()
            record.analyzed = False
            local_errors.append(f"{record.path}: {type(exc).__name__}: {exc}")
        return digest, local_findings, local_errors

    progress_columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )
    with ScanCache(cache_path) as cache:
        with Progress(*progress_columns, console=console) as progress:
            task = progress.add_task("Analyzing project files", total=len(records))
            pending = deque()

            def collect_one():
                future, record, file_stat, cache_miss = pending.popleft()
                try:
                    digest, file_findings, file_errors = future.result()
                    findings.extend(file_findings)
                    errors.extend(file_errors)
                    if file_errors:
                        record.error = file_errors[0]
                    if cache_miss and digest:
                        current_stat = _verified_regular_file_stat(root / record.path, file_stat)
                        stable = (
                            current_stat.st_size == file_stat.st_size
                            and current_stat.st_mtime_ns == file_stat.st_mtime_ns
                            and current_stat.st_ctime_ns == file_stat.st_ctime_ns
                            and current_stat.st_ino == file_stat.st_ino
                        )
                        if stable:
                            cache.put(
                                str(root), record.path, file_stat.st_size,
                                file_stat.st_mtime_ns, file_stat.st_ctime_ns,
                                file_stat.st_ino, digest,
                            )
                        else:
                            message = f"{record.path}: file changed while scan was in progress"
                            record.error = message
                            errors.append(message)
                except Exception as exc:
                    message = f"{record.path}: {type(exc).__name__}: {exc}"
                    record.error = message
                    errors.append(message)
                finally:
                    persist_record(record)
                    progress.advance(task)

            with ThreadPoolExecutor(
                max_workers=worker_count, thread_name_prefix="pdt-analyzer"
            ) as executor:
                for record in records:
                    counts[record.language] += 1
                    if record.error or record.content_skipped_reason:
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
                        future = executor.submit(analyze_one, record, path, digest_hint, file_stat)
                        pending.append((future, record, file_stat, not cache_hit))
                        if len(pending) >= max_pending:
                            collect_one()
                    except OSError as exc:
                        record.error = str(exc)
                        errors.append(record.path + ": " + str(exc))
                        persist_record(record)
                        progress.advance(task)
                while pending:
                    collect_one()
            if record_updates:
                records.update_records(record_updates)
                record_updates.clear()

        if walk_stats.get("walk_errors", 0) == 0:
            cache.prune_missing(str(root), (record.path for record in records))

    python_graph, graph_findings = analyze_python_dependencies(root, records)
    findings.extend(graph_findings)
    architecture_layout, architecture_findings = analyze_project_architecture(records)
    findings.extend(architecture_findings)
    domain_catalog = analyzer_domain_catalog()
    vcs_provider_findings = [
        item for item in findings
        if item.category in {"vcs", "hosting_providers", "ci_cd", "cloud_services"}
    ]
    metrics = {
        "vcs_provider_signal_count": len(vcs_provider_findings),
        "vcs_provider_categories": dict(sorted(Counter(
            item.category for item in vcs_provider_findings
        ).items())),
        "native_backend": native_capabilities(),
        "native_extension_available": native_available(),
        "execution": {
            "mode": "bounded-thread-pool",
            "worker_count": worker_count,
            "max_pending_tasks": max_pending,
            "ordering": "deterministic-submission-order",
        },
        "vulnerability_intelligence": vulnerability_db_status,
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
    summary.add_row("Analysis workers", str(metrics["execution"]["worker_count"]))
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
    if errors:
        _status(
            console,
            "WARNING",
            f"{len(errors)} file/analyzer errors recorded in JSON report.",
            "yellow",
        )
    return 0


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
            ))

        if not formats or formats - {"json", "markdown"}:
            parser.error("compare --format accepts json, markdown")
        if len(args.reports) < 2:
            parser.error("compare requires at least two report JSON files")
        comparison = compare_many_reports([load_report(path) for path in args.reports])
        for report in write_comparison(comparison, args.output, formats):
            print("[ SUCCESS ] Comparison report: " + str(report))
        raise SystemExit(0)
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(2, "[ ERROR ] " + str(exc) + "\n")


if __name__ == "__main__":
    main()
