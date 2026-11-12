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
    # What worker processes load: validated isolated-plugin specs to rebuild proxies from,
    # or with ``--plugin-isolation off`` the entry points the coordinator loaded.
    plugin_specs: list[Any] = field(default_factory=list)

    def close(self) -> None:
        """Stop the plugin host processes owned by isolated analyzers."""
        from ..plugins.isolation import IsolatedAnalyzer

        for analyzer in self.analyzers:
            if isinstance(analyzer, IsolatedAnalyzer):
                analyzer.close()


def builtin_analyzers() -> list[Analyzer]:
    """Instantiate PDT's own analyzers in their deterministic execution order."""
    from .api.contracts import APIContractAnalyzer
    from .api.integration import IntegrationAnalyzer
    from .api.messaging import MessagingIntelligenceAnalyzer
    from .api.routes import APIEndpointAnalyzer
    from .api.styles import APITypeAnalyzer
    from .code.concurrency import ConcurrencyAnalyzer
    from .code.index import CodeIndexAnalyzer
    from .code.performance import PerformanceHotspotAnalyzer
    from .code.python import PythonAnalyzer
    from .code.resources import ResourceManagementAnalyzer
    from .code.tree_sitter_syntax import TreeSitterAnalyzer
    from .code.type_systems import TypeSystemAnalyzer
    from .content.accessibility import AccessibilityAnalyzer
    from .content.archives import ArchiveIntelligenceAnalyzer
    from .content.documents import DocumentAnalyzer
    from .content.localization import LocalizationAnalyzer
    from .content.markdown import MarkdownAnalyzer
    from .databases.migrations import MigrationIntelligenceAnalyzer
    from .databases.nosql import NoSQLIntelligenceAnalyzer
    from .databases.prisma import PrismaSchemaAnalyzer
    from .databases.sql import SQLSchemaAnalyzer
    from .delivery.builds import BuildManifestAnalyzer
    from .delivery.coverage_reports import CoverageArtifactAnalyzer
    from .delivery.deployment import DeploymentIntelligenceAnalyzer
    from .delivery.testing import TestDiscoveryAnalyzer
    from .delivery.vcs import VCSHostingAnalyzer
    from .dependencies.licenses import LicenseAnalyzer
    from .dependencies.lockfiles import LockfileAnalyzer
    from .dependencies.manifests import DependencyManifestAnalyzer
    from .domains.embedded import EmbeddedAnalyzer
    from .domains.firmware import FirmwareAnalyzer
    from .domains.frontend import FrontendAnalyzer
    from .domains.game_engines import GameEngineIntelligenceAnalyzer
    from .domains.hdl import HardwareDescriptionAnalyzer
    from .domains.ml import AIMLIntelligenceAnalyzer
    from .domains.mobile import MobileIntelligenceAnalyzer
    from .domains.ros import ROSIntelligenceAnalyzer
    from .domains.shaders import ShaderAnalyzer
    from .environment.configuration import ConfigurationAnalyzer
    from .environment.network import NetworkIndicatorAnalyzer
    from .environment.observability import ObservabilityAnalyzer
    from .environment.operating_systems import OperatingSystemAnalyzer
    from .security.dataflow import DataFlowAnalyzer
    from .security.identity import IdentityIntelligenceAnalyzer
    from .security.privacy import DataExposureAnalyzer
    from .security.secrets import SecretPatternAnalyzer
    from .security.secure_code import SecureCodePatternAnalyzer

    return [
        PythonAnalyzer(),
        CodeIndexAnalyzer(),
        PerformanceHotspotAnalyzer(),
        ConcurrencyAnalyzer(),
        ResourceManagementAnalyzer(),
        TypeSystemAnalyzer(),
        DataFlowAnalyzer(),
        EmbeddedAnalyzer(),
        FirmwareAnalyzer(),
        HardwareDescriptionAnalyzer(),
        ShaderAnalyzer(),
        FrontendAnalyzer(),
        IntegrationAnalyzer(),
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
    from ..plugins.isolation import PluginPolicy, isolated_analyzers, load_isolated_plugins

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
    # Worker processes load exactly the entry points the coordinator loaded, instead of
    # rediscovering them (a different set, or failures nobody would see).
    points = (
        list(plugin_specs) if plugin_specs is not None
        else sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda item: item.name)
    )
    loaded_points = []
    for point in points:
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
            try:
                # The engine sets this plugin's name on its findings, as isolated modes do:
                # an in-process plugin never reports as "core" or as a built-in analyzer.
                candidate._pdt_in_process_plugin = True
            except AttributeError:  # __slots__ without room for the marker
                raise TypeError("plugin analyzer instances must accept attributes") from None
            analyzers.append(candidate)
            loaded_points.append(point)
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
    if plugin_specs is not None and diagnostics:
        # A worker could not load what the coordinator loaded: running on would silently
        # analyze files without that plugin.
        raise RuntimeError("; ".join(diagnostics))
    return AnalyzerLoadResult(analyzers, diagnostics, statuses, loaded_points)
