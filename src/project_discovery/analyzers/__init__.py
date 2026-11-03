"""Built-in and third-party analyzer discovery."""
from importlib.metadata import entry_points

from .base import Analyzer
from .dependency_manifest_analyzer import DependencyManifestAnalyzer
from .docs_analyzer import MarkdownAnalyzer
from .python_analyzer import PythonAnalyzer
from .tree_sitter_analyzer import TreeSitterAnalyzer


def load_analyzers() -> list[Analyzer]:
    result: list[Analyzer] = [
        PythonAnalyzer(),
        MarkdownAnalyzer(),
        DependencyManifestAnalyzer(),
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
