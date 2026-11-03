"""Built-in analyzer loading and plugin entry-point discovery."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import entry_points

from .api_analyzer import APIContractAnalyzer
from .api_source_analyzer import APIEndpointAnalyzer
from .base import Analyzer
from .build_analyzer import BuildManifestAnalyzer
from .configuration_analyzer import ConfigurationAnalyzer
from .dependency_manifest_analyzer import DependencyManifestAnalyzer
from .docs_analyzer import MarkdownAnalyzer
from .ml_analyzer import AIMLIntelligenceAnalyzer
from .migration_analyzer import MigrationIntelligenceAnalyzer
from .mobile_analyzer import MobileIntelligenceAnalyzer
from .messaging_analyzer import MessagingIntelligenceAnalyzer
from .nosql_analyzer import NoSQLIntelligenceAnalyzer
from .document_analyzer import DocumentAnalyzer
from .deployment_analyzer import DeploymentIntelligenceAnalyzer
from .lockfile_analyzer import LockfileAnalyzer
from .license_analyzer import LicenseAnalyzer
from .identity_analyzer import IdentityIntelligenceAnalyzer
from .game_engine_analyzer import GameEngineIntelligenceAnalyzer
from .prisma_analyzer import PrismaSchemaAnalyzer
from .python_analyzer import PythonAnalyzer
from .ros_analyzer import ROSIntelligenceAnalyzer
from .security_analyzer import SecretPatternAnalyzer
from .secure_code_analyzer import SecureCodePatternAnalyzer
from .sql_analyzer import SQLSchemaAnalyzer
from .test_analyzer import TestDiscoveryAnalyzer
from .tree_sitter_analyzer import TreeSitterAnalyzer


@dataclass(slots=True)
class AnalyzerLoadResult:
    analyzers: list[Analyzer]
    diagnostics: list[str]


def load_analyzers() -> AnalyzerLoadResult:
    """Load built-ins and validated third-party plugins without hiding failures."""
    analyzers: list[Analyzer] = [
        PythonAnalyzer(),
        MarkdownAnalyzer(),
        DocumentAnalyzer(),
        DeploymentIntelligenceAnalyzer(),
        DependencyManifestAnalyzer(),
        LockfileAnalyzer(),
        LicenseAnalyzer(),
        IdentityIntelligenceAnalyzer(),
        GameEngineIntelligenceAnalyzer(),
        ConfigurationAnalyzer(),
        APIContractAnalyzer(),
        APIEndpointAnalyzer(),
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
        MessagingIntelligenceAnalyzer(),
        ROSIntelligenceAnalyzer(),
        TreeSitterAnalyzer(),
    ]
    diagnostics: list[str] = []
    names = {analyzer.name for analyzer in analyzers}

    for point in sorted(entry_points(group="pdt.analyzers"), key=lambda item: item.name):
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
        except Exception as exc:
            diagnostics.append(
                f"Plugin {point.name!r} failed to load: {type(exc).__name__}: {exc}"
            )
    return AnalyzerLoadResult(analyzers, diagnostics)
