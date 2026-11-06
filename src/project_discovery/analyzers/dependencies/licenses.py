"""Offline license declaration and SPDX header inventory."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from ...core.source_utils import read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_LICENSE_NAMES = {
    "license", "license.md", "license.txt", "licence", "licence.md",
    "copying", "copying.txt", "notice", "notice.md",
}
_SPDX = re.compile(r"(?im)SPDX-License-Identifier:\s*([A-Za-z0-9.+() -]+)")
_LICENSE_HINTS = (
    ("MIT", re.compile(r"(?i)\bMIT License\b")),
    ("Apache-2.0", re.compile(r"(?i)Apache License\s*,?\s*Version 2\.0")),
    ("GPL-3.0", re.compile(r"(?i)GNU GENERAL PUBLIC LICENSE\s+Version 3")),
    ("GPL-2.0", re.compile(r"(?i)GNU GENERAL PUBLIC LICENSE\s+Version 2")),
    ("BSD-3-Clause", re.compile(r"(?i)BSD 3-Clause License")),
    ("MPL-2.0", re.compile(r"(?i)Mozilla Public License\s+Version 2\.0")),
)
_SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".c",
    ".h", ".cpp", ".hpp", ".cc", ".cxx", ".java", ".kt", ".swift", ".cs", ".rb", ".php",
    ".sh", ".yaml", ".yml", ".toml", ".json",
}


def _manifest_license(path: Path, record: FileRecord) -> list[str]:
    name = Path(record.path).name.lower()
    content = read_text_bounded(
        path, 8 * 1024 * 1024, expected_identity=record.analysis_identity,
    )
    if name == "package.json":
        data: Any = json.loads(content)
        value = data.get("license")
        if isinstance(value, dict):
            value = value.get("type")
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)] if value else []
    if name == "pyproject.toml":
        data = tomllib.loads(content)
        value = data.get("project", {}).get("license")
        if isinstance(value, dict):
            value = value.get("text")
        return [str(value)] if value else []
    if name == "cargo.toml":
        data = tomllib.loads(content)
        value = data.get("package", {}).get("license")
        return [str(value)] if value else []
    if name == "composer.json":
        data = json.loads(content)
        value = data.get("license")
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)] if value else []
    return []


class LicenseAnalyzer(Analyzer):
    """Inventory SPDX headers and package-level license declarations."""

    name = "license-intelligence"
    domains = ("licenses",)

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        is_manifest = name in {"package.json", "pyproject.toml", "cargo.toml", "composer.json"}
        is_source = record.extension in {
            ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go",
            ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".java", ".kt",
            ".swift", ".cs", ".rb", ".php", ".sh",
        }
        return record.error is None and (
            name in _LICENSE_NAMES or is_manifest or is_source
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        try:
            content = read_text_bounded(
                path, 8 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
            declared = _manifest_license(path, record) if name in {
                "package.json", "pyproject.toml", "cargo.toml", "composer.json"
            } else []
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            return [Finding(
                "license",
                f"License inspection error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        spdx = [item.strip() for item in _SPDX.findall(content)]
        hints = [
            identifier for identifier, pattern in _LICENSE_HINTS if pattern.search(content)
        ] if name in _LICENSE_NAMES else []
        identifiers = sorted(set(declared + spdx + hints))
        if not identifiers:
            return []
        source = (
            "package manifest declaration" if declared
            else "SPDX source header" if spdx
            else "license text pattern"
        )
        confidence = "CONFIRMED" if declared or spdx else "INFERRED"
        return [Finding(
            "license",
            f"License declaration: {record.path}",
            f"Detected license identifier(s): {', '.join(identifiers)} via {source}. "
            "This is an inventory signal, not a legal compatibility assessment.",
            confidence=confidence,
            evidence=[record.path],
            analyzer=self.name,
        )]
