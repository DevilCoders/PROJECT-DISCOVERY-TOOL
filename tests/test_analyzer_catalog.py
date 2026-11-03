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
    assert any(item["status"] == "planned" for item in catalog)
