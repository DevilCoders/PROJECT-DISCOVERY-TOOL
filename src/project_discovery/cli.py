"""PDT command line."""
import argparse
from collections import Counter
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

from . import __version__
from .analyzer_catalog import analyzer_domain_catalog, analyzer_domain_count
from .analyzers import load_analyzers
from .analyzers.tree_sitter_analyzer import parser_capabilities
from .cache import ScanCache
from .comparison import compare_many_reports, load_report, write_comparison
from .project_catalog import ProjectCatalog
from .language_catalog import language_catalog, recognized_language_count
from .models import ScanResult
from .python_graph import analyze_python_dependencies
from .reporting import write_reports
from .scanner import discover_files, sha256_file


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _status(console: Console, label: str, message: str, style: str) -> None:
    console.print(f"[bold {style}][ {label} ][/bold {style}] {message}")


def run_scan(
    root: Path, output: Path | None, formats: set[str], max_file_mb: int
) -> int:
    console = Console(stderr=True)
    root = root.expanduser().resolve(strict=True)
    if output is None:
        project_name = root.name or "root"
        output = root.parent / f"{project_name}-pdt-report"
    output = output.expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if output == root or root in output.parents:
        raise ValueError("Report output must be outside the analyzed project directory.")

    _status(console, "INFO", "Read-only discovery: " + str(root), "cyan")
    started = now()
    records, walk_stats = discover_files(root, max_file_bytes=max_file_mb * 1024 * 1024)
    analyzer_load = load_analyzers()
    analyzers = analyzer_load.analyzers
    findings = []
    errors = list(analyzer_load.diagnostics)
    counts = Counter()
    cache_path = output / ".pdt-cache" / "fingerprints.sqlite3"

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
            for record in records:
                counts[record.language] += 1
                try:
                    if record.error:
                        continue
                    path = root / record.path
                    stat = path.stat()
                    cached = cache.get(str(root), record.path)
                    if (
                        cached
                        and cached[0] == stat.st_size
                        and cached[1] == stat.st_mtime_ns
                        and cached[2] == stat.st_ctime_ns
                        and cached[3] == stat.st_ino
                    ):
                        record.sha256 = cached[4]
                    else:
                        record.sha256 = sha256_file(path)
                        cache.put(
                            str(root),
                            record.path,
                            stat.st_size,
                            stat.st_mtime_ns,
                            stat.st_ctime_ns,
                            stat.st_ino,
                            record.sha256,
                        )
                    for analyzer in analyzers:
                        if analyzer.supports(record):
                            try:
                                findings.extend(analyzer.analyze(path, record))
                                record.analyzed = True
                            except Exception as exc:
                                message = (
                                    f"{record.path} [{analyzer.name}]: "
                                    f"{type(exc).__name__}: {exc}"
                                )
                                errors.append(message)
                                record.error = message
                except OSError as exc:
                    record.error = str(exc)
                    errors.append(record.path + ": " + str(exc))
                finally:
                    progress.advance(task)

        if walk_stats.get("walk_errors", 0) == 0:
            cache.prune_missing(str(root), (record.path for record in records))

    python_graph, graph_findings = analyze_python_dependencies(root, records)
    findings.extend(graph_findings)
    domain_catalog = analyzer_domain_catalog()
    metrics = {
        "file_count": len(records),
        "total_bytes": walk_stats.get("total_bytes", 0),
        "walk_errors": walk_stats.get("walk_errors", 0),
        "oversized_files": walk_stats.get("oversized", 0),
        "languages": dict(sorted(counts.items())),
        "language_catalog": language_catalog(),
        "recognized_language_count": recognized_language_count(),
        "local_parser_capabilities": parser_capabilities(set(counts)),
        "analyzer_domain_catalog": domain_catalog,
        "analyzer_domain_count": analyzer_domain_count(),
        "plugin_diagnostics": analyzer_load.diagnostics,
        "implemented_analyzer_domains": [
            item["id"] for item in domain_catalog if item["status"] == "implemented"
        ],
        "python_dependency_graph": python_graph,
    }
    result = ScanResult(
        str(root), started, now(), records, findings, metrics, errors,
        [analyzer.name for analyzer in analyzers] + ["python-module-graph"],
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
    summary.add_row("Total size", f"{metrics['total_bytes']:,} bytes")
    summary.add_row("Languages / formats detected", str(len(counts)))
    summary.add_row("Findings", str(len(findings)))
    summary.add_row("Scan errors", str(len(errors) + metrics["walk_errors"]))
    summary.add_row("Oversized files skipped", str(metrics["oversized_files"]))
    summary.add_row("Analyzer domains catalogued", str(metrics["analyzer_domain_count"]))
    console.print(summary)
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
    scan.add_argument("--max-file-mb", type=int, default=8)
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
    args = parser.parse_args()
    formats = (
        {item.strip().lower() for item in args.format.split(",") if item.strip()}
        if hasattr(args, "format") else set()
    )
    try:
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
            raise SystemExit(run_scan(args.path, args.output, formats, args.max_file_mb))

        if not formats or formats - {"json", "markdown"}:
            parser.error("compare --format accepts json, markdown")
        if len(args.reports) < 2:
            parser.error("compare requires at least two report JSON files")
        comparison = compare_many_reports([load_report(path) for path in args.reports])
        for report in write_comparison(comparison, args.output, formats):
            print("[ SUCCESS ] Comparison report: " + str(report))
        raise SystemExit(0)
    except (OSError, ValueError) as exc:
        parser.exit(2, "[ ERROR ] " + str(exc) + "\n")


if __name__ == "__main__":
    main()
