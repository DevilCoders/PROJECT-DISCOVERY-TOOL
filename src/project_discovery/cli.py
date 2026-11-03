"""PDT command line."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer_catalog import analyzer_domain_catalog, analyzer_domain_count
from .analyzers import load_analyzers
from .analyzers.tree_sitter_analyzer import parser_capabilities
from .cache import ScanCache
from .language_catalog import language_catalog, recognized_language_count
from .models import ScanResult
from .python_graph import analyze_python_dependencies
from .reporting import write_reports
from .scanner import discover_files, sha256_file


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_scan(
    root: Path, output: Path | None, formats: set[str], max_file_mb: int
) -> int:
    root = root.expanduser().resolve(strict=True)
    if output is None:
        project_name = root.name or "root"
        output = root.parent / f"{project_name}-pdt-report"
    output = output.expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if output == root or root in output.parents:
        raise ValueError("Report output must be outside the analyzed project directory.")

    print("[ INFO ] Read-only discovery: " + str(root))
    started = now()
    records, walk_stats = discover_files(root, max_file_bytes=max_file_mb * 1024 * 1024)
    analyzers = load_analyzers()
    findings, errors = [], []
    counts = Counter()

    with ScanCache(output / ".pdt-cache" / "fingerprints.sqlite3") as cache:
        for index, record in enumerate(records, 1):
            counts[record.language] += 1
            if record.error:
                continue
            path = root / record.path
            try:
                stat = path.stat()
                cached = cache.get(str(root), record.path)
                if cached and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
                    record.sha256 = cached[2]
                else:
                    record.sha256 = sha256_file(path)
                    cache.put(
                        str(root), record.path, stat.st_size, stat.st_mtime_ns,
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
            if index % 250 == 0 or index == len(records):
                print(f"[ PROGRESS ] {index}/{len(records)} files")

    python_graph, graph_findings = analyze_python_dependencies(root, records)
    findings.extend(graph_findings)
    metrics = {
        "file_count": len(records),
        "total_bytes": walk_stats.get("total_bytes", 0),
        "walk_errors": walk_stats.get("walk_errors", 0),
        "oversized_files": walk_stats.get("oversized", 0),
        "languages": dict(sorted(counts.items())),
        "language_catalog": language_catalog(),
        "recognized_language_count": recognized_language_count(),
        "local_parser_capabilities": parser_capabilities(set(counts)),
        "analyzer_domain_catalog": analyzer_domain_catalog(),
        "analyzer_domain_count": analyzer_domain_count(),
        "implemented_analyzer_domains": [
            item["id"] for item in analyzer_domain_catalog()
            if item["status"] == "implemented"
        ],
        "python_dependency_graph": python_graph,
    }
    result = ScanResult(
        str(root), started, now(), records, findings, metrics, errors,
        [analyzer.name for analyzer in analyzers] + ["python-module-graph"],
    )
    for report in write_reports(result, output, formats):
        print("[ SUCCESS ] Report: " + str(report))
    print(f"[ SUCCESS ] Scan complete: {len(records)} files; {len(findings)} findings")
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
    args = parser.parse_args()
    formats = {
        item.strip().lower() for item in args.format.split(",") if item.strip()
    }
    if not formats or formats - {"json", "markdown", "html"}:
        parser.error("--format accepts json, markdown, html")
    if args.max_file_mb < 1:
        parser.error("--max-file-mb must be >= 1")
    try:
        raise SystemExit(run_scan(args.path, args.output, formats, args.max_file_mb))
    except (OSError, ValueError) as exc:
        parser.exit(2, "[ ERROR ] " + str(exc) + "\n")


if __name__ == "__main__":
    main()
