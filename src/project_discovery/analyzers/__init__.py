"""Built-in analyzer loading and plugin entry-point discovery.

Built-in analyzers are imported when they are instantiated, not when this package is
imported, so a plugin host (which imports ``analyzers.base``) stays lightweight.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any

from .base import Analyzer

ENTRY_POINT_GROUP = "pdt.analyzers"


@dataclass(slots=True)
class AnalyzerLoadResult:
    analyzers: list[Analyzer]
    diagnostics: list[str]
    # One status entry per discovered plugin (loaded or failed), for reports.
    plugins: list[dict[str, Any]] = field(default_factory=list)
    # Validated isolated-plugin specs that worker processes rebuild proxies from.
    plugin_specs: list[Any] = field(default_factory=list)

    def close(self) -> None:
        """Stop the plugin host processes owned by isolated analyzers."""
        from ..plugin_isolation import IsolatedAnalyzer

        for analyzer in self.analyzers:
            if isinstance(analyzer, IsolatedAnalyzer):
                analyzer.close()


def builtin_analyzers() -> list[Analyzer]:
    """Instantiate PDT's own analyzers in their deterministic execution order."""
    from .accessibility_analyzer import AccessibilityAnalyzer
    from .api_analyzer import APIContractAnalyzer
    from .api_source_analyzer import APIEndpointAnalyzer
    from .api_type_analyzer import APITypeAnalyzer
    from .archive_analyzer import ArchiveIntelligenceAnalyzer
    from .build_analyzer import BuildManifestAnalyzer
    from .code_index_analyzer import CodeIndexAnalyzer
    from .concurrency_analyzer import ConcurrencyAnalyzer
    from .configuration_analyzer import ConfigurationAnalyzer
    from .coverage_analyzer import CoverageArtifactAnalyzer
    from .data_exposure_analyzer import DataExposureAnalyzer
    from .dataflow_analyzer import DataFlowAnalyzer
    from .dependency_manifest_analyzer import DependencyManifestAnalyzer
    from .deployment_analyzer import DeploymentIntelligenceAnalyzer
    from .docs_analyzer import MarkdownAnalyzer
    from .document_analyzer import DocumentAnalyzer
    from .game_engine_analyzer import GameEngineIntelligenceAnalyzer
    from .identity_analyzer import IdentityIntelligenceAnalyzer
    from .license_analyzer import LicenseAnalyzer
    from .localization_analyzer import LocalizationAnalyzer
    from .lockfile_analyzer import LockfileAnalyzer
    from .messaging_analyzer import MessagingIntelligenceAnalyzer
    from .migration_analyzer import MigrationIntelligenceAnalyzer
    from .ml_analyzer import AIMLIntelligenceAnalyzer
    from .mobile_analyzer import MobileIntelligenceAnalyzer
    from .network_analyzer import NetworkIndicatorAnalyzer
    from .nosql_analyzer import NoSQLIntelligenceAnalyzer
    from .observability_analyzer import ObservabilityAnalyzer
    from .os_analyzer import OperatingSystemAnalyzer
    from .performance_analyzer import PerformanceHotspotAnalyzer
    from .prisma_analyzer import PrismaSchemaAnalyzer
    from .resource_analyzer import ResourceManagementAnalyzer
    from .python_analyzer import PythonAnalyzer
    from .ros_analyzer import ROSIntelligenceAnalyzer
    from .secure_code_analyzer import SecureCodePatternAnalyzer
    from .security_analyzer import SecretPatternAnalyzer
    from .sql_analyzer import SQLSchemaAnalyzer
    from .test_analyzer import TestDiscoveryAnalyzer
    from .tree_sitter_analyzer import TreeSitterAnalyzer
    from .type_system_analyzer import TypeSystemAnalyzer
    from .vcs_analyzer import VCSHostingAnalyzer

    return [
        PythonAnalyzer(),
        CodeIndexAnalyzer(),
        PerformanceHotspotAnalyzer(),
        ConcurrencyAnalyzer(),
        ResourceManagementAnalyzer(),
        TypeSystemAnalyzer(),
        DataFlowAnalyzer(),
        MarkdownAnalyzer(),
        DocumentAnalyzer(),
        DeploymentIntelligenceAnalyzer(),
        ArchiveIntelligenceAnalyzer(),
        DataExposureAnalyzer(),
        NetworkIndicatorAnalyzer(),
        OperatingSystemAnalyzer(),
        APITypeAnalyzer(),
        DependencyManifestAnalyzer(),
        LockfileAnalyzer(),
        LicenseAnalyzer(),
        LocalizationAnalyzer(),
        IdentityIntelligenceAnalyzer(),
        GameEngineIntelligenceAnalyzer(),
        ConfigurationAnalyzer(),
        CoverageArtifactAnalyzer(),
        APIContractAnalyzer(),
        APIEndpointAnalyzer(),
        AccessibilityAnalyzer(),
        SQLSchemaAnalyzer(),
        MigrationIntelligenceAnalyzer(),
        PrismaSchemaAnalyzer(),
        TestDiscoveryAnalyzer(),
        BuildManifestAnalyzer(),
        SecretPatternAnalyzer(),
        SecureCodePatternAnalyzer(),
        AIMLIntelligenceAnalyzer(),
        MobileIntelligenceAnalyzer(),
        NoSQLIntelligenceAnalyzer(),
        ObservabilityAnalyzer(),
        MessagingIntelligenceAnalyzer(),
        ROSIntelligenceAnalyzer(),
        TreeSitterAnalyzer(),
        VCSHostingAnalyzer(),
    ]


def load_analyzers(*, plugin_policy=None, plugin_specs=None) -> AnalyzerLoadResult:
    """Load built-ins and validated third-party plugins without hiding failures.

    Plugins run in sandboxed host processes unless ``plugin_policy.isolation`` is
    ``"off"``. Worker processes pass the coordinator's validated ``plugin_specs`` so
    plugins are not probed again in every worker.
    """
    from ..plugin_isolation import PluginPolicy, isolated_analyzers, load_isolated_plugins

    policy = plugin_policy or PluginPolicy()
    analyzers = builtin_analyzers()
    names = {analyzer.name for analyzer in analyzers}
    if policy.isolation != "off":
        if plugin_specs is not None:
            plugins = isolated_analyzers(plugin_specs, policy)
            return AnalyzerLoadResult(analyzers + plugins, [], [], list(plugin_specs))
        points = sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda item: item.name)
        loaded = load_isolated_plugins(points, policy, reserved_names=names)
        return AnalyzerLoadResult(
            analyzers + loaded.analyzers, loaded.diagnostics, loaded.statuses, loaded.specs,
        )

    diagnostics: list[str] = []
    statuses: list[dict[str, Any]] = []
    for point in sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda item: item.name):
        try:
            loaded = point.load()
            candidate = loaded() if callable(loaded) and not isinstance(loaded, Analyzer) else loaded
            if not isinstance(candidate, Analyzer):
                raise TypeError("entry point must load an Analyzer subclass or instance")
            if candidate.api_version != 1:
                raise ValueError(
                    f"unsupported analyzer API version: {candidate.api_version!r}"
                )
            if not candidate.name or candidate.name == "unnamed":
                raise ValueError("plugin analyzer must define a stable non-empty name")
            if candidate.name in names:
                raise ValueError(f"duplicate analyzer name: {candidate.name}")
            names.add(candidate.name)
            analyzers.append(candidate)
            statuses.append({
                "entry_point": point.name, "name": candidate.name,
                "version": candidate.version, "status": "loaded", "isolation": "off",
            })
        except Exception as exc:
            diagnostics.append(
                f"Plugin {point.name!r} failed to load: {type(exc).__name__}: {exc}"
            )
            statuses.append({
                "entry_point": point.name, "status": "failed", "isolation": "off",
                "error": f"{type(exc).__name__}: {exc}",
            })
    return AnalyzerLoadResult(analyzers, diagnostics, statuses)
