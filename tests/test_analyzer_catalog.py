from project_discovery.analyzer_catalog import (
    analyzer_domain_catalog,
    analyzer_domain_count,
)


def test_analyzer_coverage_catalog_is_broad_and_explicit():
    catalog = analyzer_domain_catalog()
    assert analyzer_domain_count() >= 50
    assert len({item["id"] for item in catalog}) == len(catalog)
    implemented = {item["id"] for item in catalog if item["status"] in {"implemented", "partial"}}
    assert {
        "source_structure",
        "imports",
        "documentation",
        "dependency_manifests",
    } <= implemented
    assert {item["status"] for item in catalog} <= {"implemented", "partial", "planned"}


def test_domains_with_analyzers_are_not_planned():
    from project_discovery.analyzers import builtin_analyzers

    claimed = {domain for analyzer in builtin_analyzers() for domain in analyzer.domains}
    statuses = {item["id"]: item["status"] for item in analyzer_domain_catalog()}
    for domain in (
        "symbol_index", "call_graph", "type_systems", "performance", "concurrency", "memory", "dataflow",
        "embedded", "firmware", "hardware_description", "graphics_shaders", "frontend", "multi_project",
    ):
        assert domain in claimed, domain
        assert statuses[domain] == "partial", domain
    # A domain still marked planned must not be claimed by a shipped analyzer.
    assert not {domain for domain, status in statuses.items() if status == "planned"} & claimed
