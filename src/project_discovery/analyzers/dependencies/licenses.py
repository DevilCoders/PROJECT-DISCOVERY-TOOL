"""Offline license declaration and SPDX header inventory."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from ...core.source_utils import describe_error, open_verified_binary, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

# LICENSE, LICENCE.md, LICENSE-MIT, LICENSE-APACHE, COPYING.LESSER, NOTICE, UNLICENSE, ...
_LICENSE_FILE = re.compile(r"(?i)^(?:licen[cs]e|copying|notice|unlicense)(?:[-._][^/]{0,80}+)?$")
# REUSE puts SPDX tags in header comments; a tag inside a string literal is not a header.
_SPDX = re.compile(
    r"(?im)^[ \t]*+(?:#|//|/\*|\*|--|;|<!--|%|'|\(\*)[ \t]*+SPDX-License-Identifier:[ \t]*+([A-Za-z0-9.+() -]{1,200}+)"
)
# Only the start of a source file is read: SPDX headers are there, and large bundles
# neither fail the budget nor cost a full read. Tags are ASCII, so any encoding works.
_HEADER_WINDOW_BYTES = 64 * 1024
_MANIFESTS = {"package.json", "pyproject.toml", "cargo.toml", "composer.json"}
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


def _identifiers(value: Any) -> list[str]:
    """License identifiers from a manifest value: a string or a list of strings only."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item.strip()]
    return []


def _table(data: Any, *keys: str) -> dict:
    for key in keys:
        data = data.get(key) if isinstance(data, dict) else None
    return data if isinstance(data, dict) else {}


def _manifest_license(path: Path, record: FileRecord) -> list[str]:
    name = Path(record.path).name.lower()
    content = read_text_bounded(
        path, 8 * 1024 * 1024, expected_identity=record.analysis_identity,
    )
    if name in {"package.json", "composer.json"}:
        data: Any = json.loads(content)
        value = data.get("license") if isinstance(data, dict) else None
        if isinstance(value, dict):  # the deprecated {"type": "MIT"} form
            value = value.get("type")
        return _identifiers(value)
    if name == "pyproject.toml":
        data = tomllib.loads(content)
        value = _table(data, "project").get("license")
        if isinstance(value, dict):
            value = value.get("text")
        # Poetry projects declare it under [tool.poetry].
        return _identifiers(value) or _identifiers(_table(data, "tool", "poetry").get("license"))
    if name == "cargo.toml":
        data = tomllib.loads(content)
        value = _table(data, "package").get("license")
        if isinstance(value, dict) and value.get("workspace") is True:
            # ``license.workspace = true`` (Rust 1.64+): the workspace root declares it.
            return ["(inherited from the workspace)"]
        return _identifiers(value) or _identifiers(_table(data, "workspace", "package").get("license"))
    return []


class LicenseAnalyzer(Analyzer):
    """Inventory SPDX headers and package-level license declarations."""

    name = "license-intelligence"
    domains = ("licenses",)

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and record.content_skipped_reason is None and (
            bool(_LICENSE_FILE.match(name)) or name in _MANIFESTS or record.extension in _SOURCE_EXTENSIONS
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        license_file = bool(_LICENSE_FILE.match(name))
        try:
            with open_verified_binary(path, record.analysis_identity) as handle:
                content = handle.read(_HEADER_WINDOW_BYTES).decode("utf-8", errors="replace")
            declared = _manifest_license(path, record) if name in _MANIFESTS else []
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            return [Finding(
                "license",
                f"License inspection error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        spdx = [item.strip() for item in _SPDX.findall(content)]
        hints = [
            identifier for identifier, pattern in _LICENSE_HINTS if pattern.search(content)
        ] if license_file else []
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
