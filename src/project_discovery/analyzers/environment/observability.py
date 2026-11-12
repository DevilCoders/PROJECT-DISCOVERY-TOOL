"""Static logging and observability instrumentation discovery.

This analyzer inventories source/configuration markers only. It never contacts
telemetry backends or claims that instrumentation is active at runtime.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...catalog.languages import is_source_path, source_language_names
from ...core.source_utils import describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_CONFIG_NAMES = {
    "prometheus.yml", "prometheus.yaml", "otel-collector.yml", "otel-collector.yaml",
    "otelcol.yml", "otelcol.yaml", "opentelemetry-collector.yml",
    "opentelemetry-collector.yaml", "promtail.yml", "promtail.yaml",
    "loki.yml", "loki.yaml", "tempo.yml", "tempo.yaml", "jaeger.yml", "jaeger.yaml",
    "fluent-bit.conf", "fluentd.conf", "filebeat.yml", "filebeat.yaml",
    "datadog.yaml", "newrelic.yml", "grafana.ini", "logback.xml", "log4j2.xml",
    "sentry.properties", "alloy.hcl", "vector.toml", "logging.yml", "logging.yaml",
}
_CONFIG_DIRS = {
    "observability", "monitoring", "telemetry", "logging", "grafana",
    "prometheus", "opentelemetry", "otel", "loki", "jaeger", "tempo",
}
_SOURCE_MARKERS = {
    "logging": re.compile(
        r"(?i)\b(?:logging\.getLogger|LoggerFactory\.getLogger|LogManager\.getLogger|"
        r"Serilog|NLog|ILogger\b|winston|pino|bunyan|zerolog|zap\.(?:New|L)|"
        r"slog\.(?:New|Info|Debug|Error)|tracing::|log::|"
        r"console\.(?:debug|info|warn|error)|logger\.(?:debug|info|warn|error))"
    ),
    "metrics": re.compile(
        r"(?i)\b(?:prometheus_client|prometheus\.New(?:Counter|Gauge|Histogram)|"
        r"CounterVec|MeterProvider|CreateCounter|CreateHistogram|StatsD|DogStatsD|"
        r"Counter\.builder|Meter\.counter|metrics::(?:counter|gauge|histogram))"
    ),
    "tracing": re.compile(
        r"(?i)\b(?:TracerProvider|trace\.getTracer|tracer\.startSpan|startSpan\s*\(|"
        r"@WithSpan|ActivitySource|DiagnosticSource|opentelemetry|jaeger|zipkin|"
        r"sentry_sdk|Sentry\.init|Datadog|NewRelic|otel)"
    ),
    "health_checks": re.compile(
        r"(?i)(?:/health(?:z|check)?\b|readinessProbe|livenessProbe|"
        r"@Health\b|HealthCheck|IHealthCheck)"
    ),
}
_CONFIG_MARKERS = re.compile(
    r"(?i)\b(scrape_configs|receivers|exporters|processors|service|"
    r"prometheus|grafana|loki|jaeger|tempo|sentry|datadog|newrelic|"
    r"fluentbit|filebeat|opentelemetry|traces|metrics|logs)\b"
)


class ObservabilityAnalyzer(Analyzer):
    """Discover logging, metrics, tracing and health-check instrumentation."""

    name = "observability-intelligence"
    domains = ("logging", "observability")
    languages = source_language_names()

    def supports(self, record: FileRecord) -> bool:
        if record.error is not None:
            return False
        name = Path(record.path).name.lower()
        parts = {part.lower() for part in Path(record.path).parts[:-1]}
        return is_source_path(record.path) or name in _CONFIG_NAMES or bool(parts & _CONFIG_DIRS)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "observability", f"Observability scan unavailable: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]

        findings: list[Finding] = []
        if is_source_path(record.path):
            for domain, pattern in _SOURCE_MARKERS.items():
                hits = [
                    (line_number, match.group(0))
                    for line_number, line in enumerate(source.splitlines(), 1)
                    if (match := pattern.search(line))
                ]
                if not hits:
                    continue
                category = "logging" if domain == "logging" else "observability"
                label = {
                    "logging": "Logging API references",
                    "metrics": "Metrics instrumentation references",
                    "tracing": "Tracing and telemetry references",
                    "health_checks": "Health-check references",
                }[domain]
                findings.append(Finding(
                    category, f"{label}: {record.path}",
                    f"Detected {len(hits)} static marker(s). Presence does not establish "
                    "runtime initialization, exporter connectivity, sampling behavior "
                    "or production activation.",
                    confidence="CONFIRMED",
                    evidence=[
                        f"{record.path}:{line_number} ({marker[:80]})"
                        for line_number, marker in hits[:100]
                    ],
                    analyzer=self.name,
                ))

        name = Path(record.path).name.lower()
        parts = {part.lower() for part in Path(record.path).parts[:-1]}
        if name in _CONFIG_NAMES or bool(parts & _CONFIG_DIRS):
            markers = [
                f"{record.path}:{line_number}"
                for line_number, line in enumerate(source.splitlines(), 1)
                if _CONFIG_MARKERS.search(line)
            ]
            if name in _CONFIG_NAMES or markers:
                findings.append(Finding(
                    "observability", f"Observability configuration: {record.path}",
                    f"Recognized observability/logging configuration context; "
                    f"{len(markers)} relevant marker line(s). Configuration presence "
                    "does not prove that a collector, dashboard or backend is deployed.",
                    confidence="CONFIRMED" if name in _CONFIG_NAMES else "INFERRED",
                    evidence=markers[:100] or [record.path], analyzer=self.name,
                ))
        return findings
