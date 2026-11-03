from pathlib import Path

from project_discovery.analyzers.license_analyzer import LicenseAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Source")
    analyzer = LicenseAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_manifest_license_declaration_is_confirmed(tmp_path: Path):
    findings = _scan(tmp_path, "package.json", '{"name":"demo","license":"MIT"}')
    assert findings[0].confidence == "CONFIRMED"
    assert "MIT" in findings[0].detail


def test_spdx_source_header_is_confirmed(tmp_path: Path):
    findings = _scan(
        tmp_path, "module.py",
        "# SPDX-License-Identifier: Apache-2.0\nprint('hello')\n",
    )
    assert findings[0].confidence == "CONFIRMED"
    assert "Apache-2.0" in findings[0].detail


def test_license_text_pattern_is_inferred(tmp_path: Path):
    findings = _scan(
        tmp_path, "LICENSE",
        "MIT License\n\nPermission is hereby granted, free of charge.\n",
    )
    assert findings[0].confidence == "INFERRED"
    assert "MIT" in findings[0].detail
