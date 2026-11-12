from project_discovery.analyzers import load_analyzers
from project_discovery.analyzers.base import Analyzer
from project_discovery.models import FileRecord
from project_discovery.plugins.isolation import PluginPolicy

# These fakes have no importable module, so they exercise in-process loading. Isolated
# loading is covered by tests/test_plugin_isolation.py.
IN_PROCESS = PluginPolicy(isolation="off")


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
    assert "messaging-intelligence" in names
    assert "api-endpoints" in names
    assert "archive-intelligence" in names
    assert "data-exposure-indicators" in names
    assert "network-indicators" in names
    assert "operating-system-intelligence" in names
    assert "api-type-classifier" in names
    assert "identity-intelligence" in names
    assert "mobile-intelligence" in names
    assert "game-engine-intelligence" in names
    assert "migration-intelligence" in names
    assert "vcs-hosting-intelligence" in names
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
    result = registry.load_analyzers(plugin_policy=IN_PROCESS)
    assert any("broken-plugin" in item for item in result.diagnostics)
    assert any(item.name == "python-ast" for item in result.analyzers)


def test_registry_loads_valid_plugin_and_rejects_duplicate_names(monkeypatch):
    from pathlib import Path

    import project_discovery.analyzers as registry

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
    result = registry.load_analyzers(plugin_policy=IN_PROCESS)
    assert sum(item.name == "custom-test-plugin" for item in result.analyzers) == 1
    assert any("duplicate analyzer name" in item for item in result.diagnostics)


def test_builtin_registry_metadata_is_well_formed():
    # Regression: three analyzers declared languages as a bare string, which serialized
    # into the registry as a list of single characters.
    from project_discovery.analyzers import load_analyzers

    analyzers = load_analyzers().analyzers
    assert len({analyzer.name for analyzer in analyzers}) == len(analyzers)
    for analyzer in analyzers:
        for field in ("languages", "domains"):
            value = getattr(analyzer, field)
            assert isinstance(value, tuple), (analyzer.name, field)
            # Single letters are only legitimate as language names (C, D, R, V).
            assert all(
                isinstance(item, str) and (len(item) > 1 or item in {"C", "D", "R", "V"})
                for item in value
            ), analyzer.name


def test_in_process_plugin_findings_carry_the_plugin_name(tmp_path):
    # Regression: with --plugin-isolation off, a plugin's findings kept whatever analyzer
    # they named ("core" by default, or a built-in such as "secret-patterns").
    from project_discovery.analyzers.base import Analyzer
    from project_discovery.engine.executor import FileOutcome, _run_analyzers
    from project_discovery.models import FileRecord, Finding

    class Poser(Analyzer):
        name = "poser"

        def supports(self, record):
            return True

        def analyze(self, path, record):
            return [Finding("x", "plain", ""), Finding("x", "posing", "", analyzer="secret-patterns")]

    plugin = Poser()
    plugin._pdt_in_process_plugin = True
    outcome = FileOutcome()
    path = tmp_path / "a.txt"
    path.write_text("x", encoding="utf-8")
    _run_analyzers([plugin], {}, FileRecord("a.txt", 1, ".txt", "Text"), path, outcome)
    assert {finding.analyzer for finding in outcome.findings} == {"poser"}
