from pathlib import Path

from project_discovery.analyzers.dependencies.licenses import LicenseAnalyzer
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


def _scan_bytes(tmp_path: Path, filename: str, content: bytes):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Source")
    analyzer = LicenseAnalyzer()
    if not analyzer.supports(record):
        return None
    return analyzer.analyze(path, record)


def test_workspace_inheritance_poetry_and_license_file_names(tmp_path: Path):
    # Regression: ``license.workspace = true`` was reported as the license "{'workspace': True}",
    # [workspace.package] and [tool.poetry] licenses were ignored, and LICENSE-MIT,
    # LICENSE-APACHE or COPYING.LESSER were not license files.
    member = _scan_bytes(tmp_path, "crates/core/Cargo.toml", b'[package]\nname = "core"\nlicense.workspace = true\n')
    assert "(inherited from the workspace)" in member[0].detail and "workspace': True" not in member[0].detail
    root = _scan_bytes(tmp_path, "Cargo.toml", b'[workspace.package]\nlicense = "MIT OR Apache-2.0"\n')
    assert "MIT OR Apache-2.0" in root[0].detail
    poetry = _scan_bytes(tmp_path, "pyproject.toml", b'[tool.poetry]\nname = "p"\nlicense = "BSD-3-Clause"\n')
    assert "BSD-3-Clause" in poetry[0].detail
    for name in ("LICENSE-MIT", "LICENSE-APACHE", "COPYING.LESSER"):
        assert _scan_bytes(tmp_path, name, b"MIT License\n\nPermission is hereby granted\n") is not None, name


def test_spdx_headers_need_a_comment_and_any_encoding_or_size_works(tmp_path: Path):
    # Regression: strict UTF-8 failed on Latin-1 files, files over 8 MiB failed the budget,
    # and an SPDX tag inside a string literal was reported as the file's license.
    latin = _scan_bytes(tmp_path, "codec.c", b"/* SPDX-License-Identifier: GPL-2.0-only */\nchar *name = \"caf\xe9\";\n")
    assert latin and "GPL-2.0-only" in latin[0].detail and latin[0].confidence == "CONFIRMED"
    big = _scan_bytes(tmp_path, "bundle.js", b"// SPDX-License-Identifier: MIT\n" + b"x;" * (5 * 1024 * 1024))
    assert big and "MIT" in big[0].detail
    literal = _scan_bytes(tmp_path, "test_spdx.py", b'HEADER = "SPDX-License-Identifier: Apache-2.0"\n')
    assert literal == []
