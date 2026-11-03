from project_discovery.analyzers import load_analyzers
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import FileRecord


def test_builtin_registry_returns_unique_stable_names():
    result = load_analyzers()
    names = [analyzer.name for analyzer in result.analyzers]
    assert len(names) == len(set(names))
    assert "python-ast" in names
    assert "secret-patterns" in names
    assert result.diagnostics == []


def test_analyzer_contract_exposes_version_and_capabilities():
    result = load_analyzers()
    analyzer = next(item for item in result.analyzers if item.name == "python-ast")
    assert analyzer.api_version == 1
    assert isinstance(analyzer.domains, tuple)
    assert isinstance(analyzer.languages, tuple)
