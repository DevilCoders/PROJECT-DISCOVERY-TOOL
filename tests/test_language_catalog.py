from pathlib import Path

from project_discovery.language_catalog import (
    detect_language,
    language_catalog,
    recognized_language_count,
)


def test_catalog_recognizes_more_than_forty_languages_and_formats():
    assert recognized_language_count() >= 40
    assert detect_language("src/main.rs") == "Rust"
    assert detect_language("src/component.tsx") == "TypeScript"
    assert detect_language("src/kernel.cu") == "CUDA"
    assert detect_language("Dockerfile") == "Dockerfile"
    assert detect_language("CMakeLists.txt") == "CMake"


def test_catalog_does_not_claim_unimplemented_parsers():
    catalog = language_catalog()
    assert len(catalog) >= 40
    assert all(item["recognition"] == "CONFIRMED" for item in catalog)
    assert all(
        item["analysis_status"] == "implemented"
        for item in catalog if item["name"] == "Python"
    )
    assert any(item["analysis_status"] == "inventory_only" for item in catalog)


def test_scanner_uses_filename_detection(tmp_path: Path):
    from project_discovery.scanner import discover_files

    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    records, _ = discover_files(tmp_path, max_file_bytes=1024)
    assert records[0].language == "Dockerfile"
