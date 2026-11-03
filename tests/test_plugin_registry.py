from project_discovery.analyzers import load_analyzers
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import FileRecord


def test_builtin_registry_returns_unique_stable_names():
    result = load_analyzers()
    names = [analyzer.name for analyzer in result.analyzers]
    assert len(names) == len(set(names))
    assert "python-ast" in names
    assert "secret-patterns" in names
    assert "secure-code-patterns" in names
    assert "deployment-intelligence" in names
    assert "ai-ml-intelligence" in names
    assert "ros-intelligence" in names
    assert "nosql-intelligence" in names
    assert result.diagnostics == []


def test_analyzer_contract_exposes_version_and_capabilities():
    result = load_analyzers()
    analyzer = next(item for item in result.analyzers if item.name == "python-ast")
    assert analyzer.api_version == 1
    assert isinstance(analyzer.domains, tuple)
    assert isinstance(analyzer.languages, tuple)


def test_registry_reports_invalid_plugin_without_aborting(monkeypatch):
    import project_discovery.analyzers as registry

    class EntryPoint:
        name = "broken-plugin"

        def load(self):
            return object

    monkeypatch.setattr(registry, "entry_points", lambda **_kwargs: [EntryPoint()])
    result = registry.load_analyzers()
    assert any("broken-plugin" in item for item in result.diagnostics)
    assert any(item.name == "python-ast" for item in result.analyzers)


def test_registry_loads_valid_plugin_and_rejects_duplicate_names(monkeypatch):
    import project_discovery.analyzers as registry
    from pathlib import Path

    class CustomAnalyzer(Analyzer):
        name = "custom-test-plugin"

        def supports(self, record: FileRecord) -> bool:
            return False

        def analyze(self, path: Path, record: FileRecord):
            return []

    class EntryPoint:
        name = "custom-plugin"

        def load(self):
            return CustomAnalyzer

    monkeypatch.setattr(registry, "entry_points", lambda **_kwargs: [EntryPoint(), EntryPoint()])
    result = registry.load_analyzers()
    assert sum(item.name == "custom-test-plugin" for item in result.analyzers) == 1
    assert any("duplicate analyzer name" in item for item in result.diagnostics)
