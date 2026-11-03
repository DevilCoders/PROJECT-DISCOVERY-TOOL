"""Offline dependency lockfile inventory."""
from __future__ import annotations

import io
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding
from ..source_utils import SourceBudgetExceeded, read_text_bounded, redact_source_excerpt


_MAX_LOCKFILE_INVENTORY_BYTES = 128 * 1024 * 1024
_MAX_LOCKFILE_PACKAGE_ENTRIES = 250_000


class LockfileEntryBudgetExceeded(ValueError):
    """Raised when a lockfile contains more package entries than the analyzer can retain."""


def _append_package(
    result: list[tuple[str, str]], package: Any, version: Any
) -> None:
    if not package or not version:
        return
    if len(result) >= _MAX_LOCKFILE_PACKAGE_ENTRIES:
        raise LockfileEntryBudgetExceeded(
            f"lockfile exceeded the {_MAX_LOCKFILE_PACKAGE_ENTRIES:,}-package entry budget"
        )
    result.append((str(package), str(version)))


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
                    _append_package(result, package_name, item["version"])
        if not result and isinstance(data.get("dependencies"), dict):
            stack = [iter(data["dependencies"].items())]
            while stack:
                try:
                    package, item = next(stack[-1])
                except StopIteration:
                    stack.pop()
                    continue
                if isinstance(item, dict):
                    _append_package(result, package, item.get("version"))
                    dependencies = item.get("dependencies", {})
                    if isinstance(dependencies, dict) and dependencies:
                        stack.append(iter(dependencies.items()))
    elif name == "composer.lock":
        for group in ("packages", "packages-dev"):
            for item in data.get(group, []):
                if item.get("name") and item.get("version"):
                    _append_package(result, item["name"], item["version"])
    elif name == "pipfile.lock":
        for group in ("default", "develop"):
            for package, item in data.get(group, {}).items():
                version = item.get("version") if isinstance(item, dict) else item
                if version:
                    _append_package(result, package, str(version).lstrip("="))
    return result


def _toml_packages(data: dict[str, Any]) -> list[tuple[str, str]]:
    result = []
    for item in data.get("package", []):
        if item.get("name") and item.get("version"):
            _append_package(result, item["name"], item["version"])
    return result


class LockfileAnalyzer(Analyzer):
    """Extract pinned/resolved package versions from common lockfile formats."""

    name = "dependency-lockfiles"
    domains = ("dependency_resolution", "supply_chain")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and Path(record.path).name.lower() in _LOCK_NAMES

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        if record.size_bytes > _MAX_LOCKFILE_INVENTORY_BYTES:
            return [Finding(
                "dependency",
                f"Lockfile inventory resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the lockfile inventory "
                f"{_MAX_LOCKFILE_INVENTORY_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            content = read_text_bounded(path, _MAX_LOCKFILE_INVENTORY_BYTES)
            if name in {"package-lock.json", "composer.lock", "pipfile.lock"}:
                packages = _json_packages(json.loads(content), name)
            elif name in {"cargo.lock", "poetry.lock"}:
                packages = _toml_packages(tomllib.loads(content))
            elif name == "yarn.lock":
                packages = []
                selectors: list[str] = []
                for line in io.StringIO(content, newline=None):
                    header = _YARN_HEADER.match(line)
                    if header:
                        header_value = header.group(1)
                        selectors = [
                            value.strip().strip('"')
                            for value in header_value.split(",")
                            if value.strip()
                        ]
                        continue
                    if selectors:
                        version_match = _YARN_VERSION.match(line)
                        if version_match:
                            for selector in selectors:
                                package = selector.split("@", 1)[0] if not selector.startswith("@") else selector.rsplit("@", 1)[0]
                                _append_package(packages, package, version_match.group(1))
                            selectors = []
            elif name == "gemfile.lock":
                packages = []
                for match in _GEM_SPEC.finditer(content):
                    _append_package(packages, match.group(1), match.group(2))
            elif name == "go.sum":
                packages = []
                for match in _GO_SUM.finditer(content):
                    _append_package(packages, match.group(1), match.group(2))
            elif name == "pnpm-lock.yaml":
                packages = []
                for match in _PNPM_PACKAGE.finditer(content):
                    _append_package(packages, match.group(1), match.group(2))
            elif name == "mix.lock":
                packages = []
                for match in _MIX_PACKAGE.finditer(content):
                    _append_package(packages, match.group(1), match.group(2))
            else:
                packages = []
        except (SourceBudgetExceeded, LockfileEntryBudgetExceeded) as exc:
            return [Finding(
                "dependency", f"Lockfile inventory resource limit: {record.path}",
                redact_source_excerpt(str(exc)), confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError, RecursionError, MemoryError) as exc:
            return [Finding(
                "dependency",
                f"Lockfile parse error: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
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
