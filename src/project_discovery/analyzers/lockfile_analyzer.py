"""Offline dependency lockfile inventory."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding


_LOCK_NAMES = {
    "package-lock.json", "composer.lock", "cargo.lock", "poetry.lock",
    "pipfile.lock", "pnpm-lock.yaml", "yarn.lock", "gemfile.lock",
    "go.sum", "mix.lock",
}
_YARN_HEADER = re.compile(r"""(?m)^"?([^"\n]+?)@[^:\n]+:\s*$""")
_YARN_VERSION = re.compile(r'(?m)^\s+version\s+"?([^"\s]+)"?')
_GEM_SPEC = re.compile(r"(?m)^\s{4}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)")
_GO_SUM = re.compile(r"(?m)^([A-Za-z0-9_./-]+)\s+(v[^\s]+?)(?:/go.mod)?\s+")
_PNPM_PACKAGE = re.compile(r"""(?m)^\s{2,}['"]?(@[^@\s]+/[^@\s]+|[^@\s/]+)@([^:\s'"]+)['"]?:\s*$""")
_MIX_PACKAGE = re.compile(r'(?m)^\s*"([^"]+)":\s*\{:[^,]+,\s*:[^,]+,\s*"([^"]+)"')


def _json_packages(data: Any, name: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    if name == "package-lock.json":
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for path, item in packages.items():
                if path and isinstance(item, dict) and item.get("version"):
                    package_name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
                    result.append((str(package_name), str(item["version"])))
        if not result and isinstance(data.get("dependencies"), dict):
            stack = list(data["dependencies"].items())
            while stack:
                package, item = stack.pop()
                if isinstance(item, dict):
                    if item.get("version"):
                        result.append((str(package), str(item["version"])))
                    stack.extend(item.get("dependencies", {}).items())
    elif name == "composer.lock":
        for group in ("packages", "packages-dev"):
            for item in data.get(group, []):
                if item.get("name") and item.get("version"):
                    result.append((str(item["name"]), str(item["version"])))
    elif name == "pipfile.lock":
        for group in ("default", "develop"):
            for package, item in data.get(group, {}).items():
                version = item.get("version") if isinstance(item, dict) else item
                if version:
                    result.append((str(package), str(version).lstrip("=")))
    return result


def _toml_packages(data: dict[str, Any]) -> list[tuple[str, str]]:
    result = []
    for item in data.get("package", []):
        if item.get("name") and item.get("version"):
            result.append((str(item["name"]), str(item["version"])))
    return result


class LockfileAnalyzer(Analyzer):
    """Extract pinned/resolved package versions from common lockfile formats."""

    name = "dependency-lockfiles"
    domains = ("dependency_resolution", "supply_chain")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and Path(record.path).name.lower() in _LOCK_NAMES

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        try:
            content = path.read_text(encoding="utf-8")
            if name in {"package-lock.json", "composer.lock", "pipfile.lock"}:
                packages = _json_packages(json.loads(content), name)
            elif name in {"cargo.lock", "poetry.lock"}:
                packages = _toml_packages(tomllib.loads(content))
            elif name == "yarn.lock":
                packages = []
                lines = content.splitlines()
                index = 0
                while index < len(lines):
                    header = _YARN_HEADER.match(lines[index])
                    if header:
                        version = None
                        cursor = index + 1
                        while cursor < len(lines) and (
                            not lines[cursor].strip() or lines[cursor][:1].isspace()
                        ):
                            version_match = _YARN_VERSION.match(lines[cursor])
                            if version_match:
                                version = version_match.group(1)
                                break
                            cursor += 1
                        if version:
                            selector = header.group(1).split(",", 1)[0].strip().strip('"')
                            package = selector
                            packages.append((package, version))
                    index += 1
            elif name == "gemfile.lock":
                packages = _GEM_SPEC.findall(content)
            elif name == "go.sum":
                packages = _GO_SUM.findall(content)
            elif name == "pnpm-lock.yaml":
                packages = _PNPM_PACKAGE.findall(content)
            elif name == "mix.lock":
                packages = _MIX_PACKAGE.findall(content)
            else:
                packages = []
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            return [Finding(
                "dependency",
                f"Lockfile parse error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        unique = sorted(set(packages), key=lambda item: (item[0].lower(), item[1]))
        return [Finding(
            "dependency",
            f"Resolved dependency inventory: {record.path}",
            f"Extracted {len(unique)} package/version entries from a lockfile. "
            "This records declared resolution state; it does not prove packages are installed "
            "or that the lockfile is current.",
            confidence="CONFIRMED",
            evidence=[
                f"{package}=={version}" for package, version in unique[:200]
            ] or [record.path],
            analyzer=self.name,
        )]
