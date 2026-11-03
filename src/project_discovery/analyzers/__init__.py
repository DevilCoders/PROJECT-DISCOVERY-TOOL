"""Built-in and third-party analyzer discovery."""
from importlib.metadata import entry_points

from .api_analyzer import APIContractAnalyzer
from .base import Analyzer
from .build_analyzer import BuildManifestAnalyzer
from .configuration_analyzer import ConfigurationAnalyzer
from .dependency_manifest_analyzer import DependencyManifestAnalyzer
from .docs_analyzer import MarkdownAnalyzer
from .document_analyzer import DocumentAnalyzer
from .prisma_analyzer import PrismaSchemaAnalyzer
from .python_analyzer import PythonAnalyzer
from .security_analyzer import SecretPatternAnalyzer
from .sql_analyzer import SQLSchemaAnalyzer
from .test_analyzer import TestDiscoveryAnalyzer
from .tree_sitter_analyzer import TreeSitterAnalyzer


def load_analyzers() -> list[Analyzer]:
    result: list[Analyzer] = [
        PythonAnalyzer(),
        MarkdownAnalyzer(),
        DocumentAnalyzer(),
        DependencyManifestAnalyzer(),
        ConfigurationAnalyzer(),
        APIContractAnalyzer(),
        SQLSchemaAnalyzer(),
        PrismaSchemaAnalyzer(),
        TestDiscoveryAnalyzer(),
        BuildManifestAnalyzer(),
        SecretPatternAnalyzer(),
        TreeSitterAnalyzer(),
    ]
    for point in entry_points(group="pdt.analyzers"):
        try:
            candidate = point.load()()
            if isinstance(candidate, Analyzer):
                result.append(candidate)
        except Exception:
            # A broken optional plugin must not abort core discovery.
            continue
    return result
