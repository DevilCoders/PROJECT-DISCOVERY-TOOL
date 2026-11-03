from pathlib import Path

from project_discovery.analyzers.observability_analyzer import ObservabilityAnalyzer
from project_discovery.models import FileRecord


def _scan(root: Path, relative: str, content: str, language: str = "Other"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), language)
    analyzer = ObservabilityAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_source_logging_metrics_tracing_and_health_markers(tmp_path: Path):
    findings = _scan(
        tmp_path, "src/server.ts",
        'import pino from "pino";\n'
        'logger.info("started");\n'
        'const tracer = trace.getTracer("api");\n'
        'const meter = meterProvider.CreateCounter("requests");\n'
        'app.get("/healthz", healthHandler);\n',
        "TypeScript",
    )
    categories = {item.category for item in findings}
    titles = [item.title for item in findings]
    assert "logging" in categories
    assert "observability" in categories
    assert any("Tracing" in title for title in titles)
    assert any("Metrics" in title for title in titles)
    assert any("Health-check" in title for title in titles)


def test_go_and_dotnet_instrumentation_markers_are_recognized(tmp_path: Path):
    go = _scan(
        tmp_path, "internal/metrics.go",
        'counter := prometheus.NewCounter(opts)\n'
        'tracer := otel.Tracer("worker")\n'
        'slog.Info("ready")\n', "Go",
    )
    dotnet = _scan(
        tmp_path, "src/Telemetry.cs",
        'private readonly ILogger logger;\n'
        'private static readonly ActivitySource Source = new("api");\n', "C#",
    )
    assert any("Metrics" in item.title for item in go)
    assert any("Tracing" in item.title for item in go)
    assert any(item.category == "logging" for item in go)
    assert any(item.category == "logging" for item in dotnet)
    assert any("Tracing" in item.title for item in dotnet)


def test_observability_config_inventory_does_not_expose_values(tmp_path: Path):
    secret_value = "should-not-appear-in-report"
    findings = _scan(
        tmp_path, "monitoring/prometheus.yml",
        "global:\n  scrape_interval: 15s\nscrape_configs:\n"
        "  - job_name: private-service\n    static_configs: []\n"
        f"# token: {secret_value}\n", "YAML",
    )
    assert len(findings) == 1
    assert findings[0].category == "observability"
    assert secret_value not in str([item.to_dict() for item in findings])


def test_analyzer_ignores_unrelated_documentation(tmp_path: Path):
    path = tmp_path / "guide.md"
    path.write_text("This document explains logging and metrics.", encoding="utf-8")
    record = FileRecord("guide.md", path.stat().st_size, ".md", "Markdown")
    assert not ObservabilityAnalyzer().supports(record)
