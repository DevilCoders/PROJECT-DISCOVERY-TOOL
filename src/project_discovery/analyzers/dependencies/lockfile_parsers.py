"""Shared offline parsers for resolved-dependency lockfiles.

The lockfile inventory analyzer and local vulnerability matching both use these parsers, so
a format is supported (or reported as unsupported) consistently across the report.
"""
from __future__ import annotations

import io
import json
import re
import tomllib
from dataclasses import dataclass
from typing import Any

MAX_LOCKFILE_BYTES = 128 * 1024 * 1024
MAX_LOCKFILE_PACKAGE_ENTRIES = 250_000

# Lockfile name (case-folded) -> OSV ecosystem of the resolved packages.
LOCKFILE_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "cargo.lock": "crates.io",
    "poetry.lock": "PyPI",
    "pipfile.lock": "PyPI",
    "uv.lock": "PyPI",
    "pdm.lock": "PyPI",
    "composer.lock": "Packagist",
    "gemfile.lock": "RubyGems",
    "go.sum": "Go",
    "mix.lock": "Hex",
    "package.resolved": "SwiftURL",
    "packages.lock.json": "NuGet",
    "pubspec.lock": "Pub",
}
LOCKFILE_NAMES = frozenset(LOCKFILE_ECOSYSTEMS)


class LockfileEntryBudgetExceeded(ValueError):
    """Raised when a lockfile resolves more packages than the parser may retain."""


@dataclass(frozen=True, slots=True, order=True)
class ResolvedPackage:
    ecosystem: str
    name: str
    version: str


def normalize_version(value: Any, *, strip_prefix: bool = False) -> str:
    """Trim quoting and pin operators; strip_prefix also drops a "v" for comparisons.

    Lockfile versions are reported as written (Go module versions keep their "v").
    """
    text = str(value).strip().strip("'\"")
    if text.startswith("=="):
        text = text[2:]
    elif text.startswith("="):
        text = text[1:]
    if strip_prefix and text[:1] in {"v", "V"} and text[1:2].isdigit():
        text = text[1:]
    return text


# Lockfile "versions" that name a source instead of a registry release: git and local
# dependencies, tarball URLs and workspace links. npm v1 lockfiles write them as the
# version itself ("git+https://user:token@host/repo.git#sha", "file:../lib"), and they can
# carry credentials and local paths. Registry versions never contain "/", "\", "@" or
# whitespace (pnpm peer suffixes are stripped before this point).
_NON_REGISTRY_VERSION = re.compile(
    r"(?i)^(?:git|github|gitlab|bitbucket|gist|file|link|portal|patch|workspace|exec|https?|ssh)[+:]"
    r"|^[a-z][a-z0-9+.-]{0,20}+://|[/\\@\s]"
)


class ParsedLockfile(list):
    """Resolved registry packages, plus the names of dependencies that resolve elsewhere.

    ``non_registry`` holds names whose lockfile entry points at git, a path, a URL or a
    workspace link. They have no registry version, so they are not matched to advisories.
    """

    non_registry: list[str]


class _Collector:
    def __init__(self, ecosystem: str, max_entries: int) -> None:
        self.ecosystem = ecosystem
        self.max_entries = max_entries
        self.packages: set[ResolvedPackage] = set()
        self.non_registry: set[str] = set()

    def add(self, name: Any, version: Any) -> None:
        if not name or not version:
            return
        name, text = str(name).strip(), normalize_version(version)
        if text[:4].lower() == "npm:":
            # npm alias ("npm:real-name@1.2.3"): the real package and its version.
            real, _, aliased = text[4:].rpartition("@")
            if real and aliased:
                name, text = real, aliased
        if _NON_REGISTRY_VERSION.search(text):
            # Only the name is kept: the specifier can hold credentials or local paths.
            if name and len(self.non_registry) < self.max_entries:
                self.non_registry.add(name)
            return
        package = ResolvedPackage(self.ecosystem, name, text)
        if not package.name or not package.version or package in self.packages:
            return
        if len(self.packages) >= self.max_entries:
            raise LockfileEntryBudgetExceeded(
                f"lockfile exceeded the {self.max_entries:,}-package entry budget"
            )
        self.packages.add(package)


def _npm_lock(data: Any, out: _Collector) -> None:
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for item_path, item in packages.items():
            # The "" key is the root project; linked workspaces carry no resolved version.
            if not item_path or not isinstance(item, dict) or item.get("link"):
                continue
            name = item.get("name") or item_path.rsplit("node_modules/", 1)[-1]
            out.add(name, item.get("version"))
    if out.packages or not isinstance(data.get("dependencies"), dict):
        return
    stack = [iter(data["dependencies"].items())]
    while stack:
        try:
            name, item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(item, dict):
            out.add(name, item.get("version"))
            nested = item.get("dependencies")
            if isinstance(nested, dict) and nested:
                stack.append(iter(nested.items()))


_YARN_SELECTOR = re.compile(r"^(@[^/@]+/[^@]+|[^@]+)@(.+)$")
_YARN_VERSION = re.compile(r"""^\s+version:?\s+["']?([^"'\s]+)""")


def _yarn_lock(source: str, out: _Collector) -> None:
    """Parse Yarn v1 and Berry (v2+) lockfiles without a YAML dependency."""
    names: list[str] = []
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.endswith(":"):
            names = []
            for selector in line[:-1].split(","):
                match = _YARN_SELECTOR.match(selector.strip().strip("\"'"))
                if match:
                    names.append(match.group(1))
            continue
        if names:
            match = _YARN_VERSION.match(line)
            if match:
                for name in names:
                    out.add(name, match.group(1))
                names = []


_PNPM_KEY = re.compile(r"""^ {2}(?P<key>['"]?[^\s'":][^'":]*['"]?):\s*$""")
# v5 keys are "/name/1.0.0" or "/@scope/name/1.0.0", optionally with "_peer@1.0.0".
_PNPM_V5_KEY = re.compile(r"^(?P<name>(?:@[^/@]+/)?[^/@]+)/(?P<version>\d[^/_()]*)")


def _pnpm_package_key(key: str) -> tuple[str, str] | None:
    key = key.strip().strip("'\"").lstrip("/")
    v5 = _PNPM_V5_KEY.match(key)
    if v5:
        return v5.group("name"), v5.group("version")
    key = key.split("(", 1)[0]  # v6/v9 peer-dependency suffix: name@1.0.0(react@18.0.0)
    at = key.rfind("@")
    if at <= 0:  # scoped names start with "@", so the separator is never at index 0
        return None
    name, version = key[:at], key[at + 1:]
    if not version[:1].isdigit():
        return None
    return name, version


def _pnpm_lock(source: str, out: _Collector) -> None:
    section = None
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line and not line[0].isspace():
            section = line.rstrip(":").strip()
            continue
        if section not in {"packages", "snapshots"}:
            continue
        match = _PNPM_KEY.match(line)
        if match:
            parsed = _pnpm_package_key(match.group("key"))
            if parsed:
                out.add(*parsed)


def _toml_packages(source: str, out: _Collector) -> None:
    data = tomllib.loads(source)
    for item in data.get("package", []):
        if isinstance(item, dict):
            out.add(item.get("name"), item.get("version"))


def _composer_lock(data: Any, out: _Collector) -> None:
    for group in ("packages", "packages-dev"):
        for item in data.get(group, []) if isinstance(data, dict) else []:
            if isinstance(item, dict):
                out.add(item.get("name"), item.get("version"))


def _pipfile_lock(data: Any, out: _Collector) -> None:
    for group in ("default", "develop"):
        entries = data.get(group, {}) if isinstance(data, dict) else {}
        for name, item in entries.items() if isinstance(entries, dict) else ():
            version = item.get("version") if isinstance(item, dict) else item
            out.add(name, version)


_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$")


def _gemfile_lock(source: str, out: _Collector) -> None:
    in_specs = False
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            match = _GEM_SPEC.match(line)
            if match:
                # Platform gems are locked as "1.15.4-x86_64-linux"; gem versions never contain "-".
                out.add(match.group(1), match.group(2).split("-", 1)[0])


_GO_SUM = re.compile(r"^(\S+)\s+(v\S+?)(/go\.mod)?\s+h\d+:")


def _go_sum(source: str, out: _Collector) -> None:
    for raw_line in io.StringIO(source, newline=None):
        match = _GO_SUM.match(raw_line)
        # "/go.mod"-only lines record module-graph resolution, not a downloaded build input.
        if match and not match.group(3):
            out.add(match.group(1), match.group(2))


_MIX_PACKAGE = re.compile(r'^\s*"([^"]+)":\s*\{:[^,]+,\s*:[^,]+,\s*"([^"]+)"')


def _mix_lock(source: str, out: _Collector) -> None:
    for raw_line in io.StringIO(source, newline=None):
        match = _MIX_PACKAGE.match(raw_line)
        if match:
            out.add(match.group(1), match.group(2))


def _swift_identity(item: dict[str, Any]) -> str | None:
    location = item.get("location") or item.get("repositoryURL")
    if isinstance(location, str) and location:
        value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", location.strip(), flags=re.I)
        value = re.sub(r"^git@([^:]+):", r"\1/", value)
        return value.removesuffix("/").removesuffix(".git")
    return item.get("identity") or item.get("package")


def _package_resolved(data: Any, out: _Collector) -> None:
    if not isinstance(data, dict):
        return
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    for item in pins:
        if isinstance(item, dict):
            state = item.get("state") or {}
            out.add(_swift_identity(item), state.get("version") if isinstance(state, dict) else None)


def _nuget_lock(data: Any, out: _Collector) -> None:
    # packages.lock.json is keyed by target framework, then package id.
    frameworks = data.get("dependencies", {}) if isinstance(data, dict) else {}
    for packages in frameworks.values() if isinstance(frameworks, dict) else ():
        for name, item in packages.items() if isinstance(packages, dict) else ():
            if isinstance(item, dict) and item.get("type") != "Project":
                out.add(name, item.get("resolved"))


_PUB_PACKAGE = re.compile(r"^ {2}([A-Za-z0-9_]+):\s*$")
_PUB_VERSION = re.compile(r"""^ {4}version:\s*["']?([^"'\s]+)""")


def _pubspec_lock(source: str, out: _Collector) -> None:
    in_packages, current = False, None
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line and not line[0].isspace():
            in_packages, current = line.strip() == "packages:", None
            continue
        if not in_packages:
            continue
        package = _PUB_PACKAGE.match(line)
        if package:
            current = package.group(1)
            continue
        version = _PUB_VERSION.match(line)
        if current and version:
            out.add(current, version.group(1))
            current = None


def parse_lockfile(
    filename: str, source: str, *, max_entries: int = MAX_LOCKFILE_PACKAGE_ENTRIES,
) -> ParsedLockfile:
    """Return de-duplicated resolved registry packages in deterministic order.

    Dependencies resolved from git, paths, URLs or workspaces are listed by name only in
    the result's ``non_registry`` attribute.

    Raises ValueError subclasses (including JSON/TOML decode errors and
    LockfileEntryBudgetExceeded) for malformed or over-budget input.
    """
    name = filename.casefold()
    ecosystem = LOCKFILE_ECOSYSTEMS.get(name)
    if ecosystem is None:
        raise ValueError(f"unsupported lockfile format: {filename}")
    out = _Collector(ecosystem, max_entries)
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        _npm_lock(json.loads(source), out)
    elif name == "yarn.lock":
        _yarn_lock(source, out)
    elif name == "pnpm-lock.yaml":
        _pnpm_lock(source, out)
    elif name in {"cargo.lock", "poetry.lock", "uv.lock", "pdm.lock"}:
        _toml_packages(source, out)
    elif name == "composer.lock":
        _composer_lock(json.loads(source), out)
    elif name == "pipfile.lock":
        _pipfile_lock(json.loads(source), out)
    elif name == "gemfile.lock":
        _gemfile_lock(source, out)
    elif name == "go.sum":
        _go_sum(source, out)
    elif name == "mix.lock":
        _mix_lock(source, out)
    elif name == "package.resolved":
        _package_resolved(json.loads(source), out)
    elif name == "packages.lock.json":
        _nuget_lock(json.loads(source), out)
    elif name == "pubspec.lock":
        _pubspec_lock(source, out)
    result = ParsedLockfile(sorted(out.packages, key=lambda p: (p.name.casefold(), p.name, p.version)))
    result.non_registry = sorted(out.non_registry - {package.name for package in out.packages})
    return result
