"""Built-in and third-party analyzer discovery."""
from importlib.metadata import entry_points
from .base import Analyzer
from .python_analyzer import PythonAnalyzer
from .docs_analyzer import MarkdownAnalyzer

def load_analyzers() -> list[Analyzer]:
    result: list[Analyzer] = [PythonAnalyzer(), MarkdownAnalyzer()]
    for point in entry_points(group="pdt.analyzers"):
        try:
            candidate = point.load()()
            if isinstance(candidate, Analyzer):
                result.append(candidate)
        except Exception:
            # A broken optional plugin must not abort core discovery.
            continue
    return result
