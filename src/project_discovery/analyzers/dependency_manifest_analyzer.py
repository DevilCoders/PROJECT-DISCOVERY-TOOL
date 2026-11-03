"""Static dependency manifest analysis; declarations are not treated as installed packages."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding

_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_GO_REQUIRE = re.compile(r"^\s*([A-Za-z0-9._~+/-]+)\s+(v?[^\s]+)")


def _constraint(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        version = value.get("version")
        if version is not None:
            return str(version)
        if "git" in value:
            return "git=" + str(value["git"])
        if "path" in value:
            return "path=" + str(value["path"])
        return "table declaration"
    return str(value)


def _python_requirement(value: str) -> tuple[str, str] | None:
    text = value.strip()
    if not text or text.startswith("#") or text.startswith("-"):
        return None
    if "#egg=" in text:
        name = text.split("#egg=", 1)[1].split("&", 1)[0]
        return (name, "direct URL") if name else None
    match = _REQUIREMENT.match(text)
    if not match:
        return None
    return match.group(1), text[match.end():].strip() or "unspecified"


class DependencyManifestAnalyzer(Analyzer):
    """Extract explicitly declared dependencies from common project manifests."""

    name = "dependency-manifests"
    _supported_names = {
        "pyproject.toml", "cargo.toml", "go.mod", "package.json", "composer.json",
    }

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            name in self._supported_names
            or (name.startswith("requirements") and record.extension == ".txt")
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            declarations = self._extract(path, record)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            return [Finding(
                "configuration",
                "Dependency manifest parse error",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        return [
            Finding(
                "dependency",
                f"Declared dependency: {name}",
                f"Manifest declaration in {group}; constraint: {constraint}. "
                "This confirms declaration only, not installation or runtime use.",
                confidence="CONFIRMED",
                evidence=[record.path],
                analyzer=self.name,
            )
            for name, constraint, group in declarations
        ]

    def _extract(self, path: Path, record: FileRecord) -> list[tuple[str, str, str]]:
        name = Path(record.path).name.lower()
        declarations: list[tuple[str, str, str]] = []

        def add(dep_name: str, constraint: Any, group: str) -> None:
            declarations.append((dep_name, _constraint(constraint), group))

        if name == "pyproject.toml":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            project = data.get("project", {})
            for item in project.get("dependencies", []):
                parsed = _python_requirement(item)
                if parsed:
                    add(parsed[0], parsed[1], "project.dependencies")
            for group, items in project.get("optional-dependencies", {}).items():
                for item in items:
                    parsed = _python_requirement(item)
                    if parsed:
                        add(parsed[0], parsed[1], f"project.optional-dependencies.{group}")
            poetry = data.get("tool", {}).get("poetry", {})
            for group, dependencies in [("poetry.dependencies", poetry.get("dependencies", {}))]:
                for dep_name, constraint in dependencies.items():
                    if dep_name.lower() != "python":
                        add(dep_name, constraint, group)
            for group_name, group_data in poetry.get("group", {}).items():
                for dep_name, constraint in group_data.get("dependencies", {}).items():
                    add(dep_name, constraint, f"tool.poetry.group.{group_name}")
        elif name.startswith("requirements") and path.suffix.lower() == ".txt":
            for line in path.read_text(encoding="utf-8").splitlines():
                parsed = _python_requirement(line.split(" #", 1)[0])
                if parsed:
                    add(parsed[0], parsed[1], "requirements")
        elif name in {"package.json", "composer.json"}:
            data = json.loads(path.read_text(encoding="utf-8"))
            groups = (
                ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
                if name == "package.json" else ("require", "require-dev")
            )
            for group in groups:
                for dep_name, constraint in data.get(group, {}).items():
                    add(dep_name, constraint, group)
        elif name == "cargo.toml":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                for dep_name, constraint in data.get(group, {}).items():
                    add(dep_name, constraint, group)
            for target, target_data in data.get("target", {}).items():
                for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for dep_name, constraint in target_data.get(group, {}).items():
                        add(dep_name, constraint, f"target.{target}.{group}")
        elif name == "go.mod":
            lines = path.read_text(encoding="utf-8").splitlines()
            in_require_block = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("require ("):
                    in_require_block = True
                    continue
                if in_require_block and stripped == ")":
                    in_require_block = False
                    continue
                candidate = stripped
                if candidate.startswith("require "):
                    candidate = candidate[len("require "):]
                elif not in_require_block:
                    continue
                match = _GO_REQUIRE.match(candidate)
                if match:
                    add(match.group(1), match.group(2), "go.mod require")
        return sorted(set(declarations), key=lambda item: (item[2], item[0].lower(), item[1]))
