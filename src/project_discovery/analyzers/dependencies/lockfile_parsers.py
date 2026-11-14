"""Shared offline parsers for resolved-dependency lockfiles.

The lockfile inventory analyzer and local vulnerability matching both use these parsers, so
a format is supported (or reported as unsupported) consistently across the report.
"""
from __future__ import annotations

import io
import json
import re
import tomllib
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Any
from ...core.limits import limit_reached

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
# version itself (a git+https URL that can embed a user and token, or "file:../lib"),
# so they can carry credentials and local paths. Registry versions never contain "/", "\", "@" or
# whitespace (pnpm peer suffixes are stripped before this point).
# The project's own code: workspace members, local paths and links.
_LOCAL_SPECIFIER = re.compile(r"(?i)^(?:file|link|portal|workspace|exec):|^\.{1,2}[/\\]|^~[/\\]|^[/\\]|^[a-z]:[/\\]")
# Third-party code from outside a registry: git, tarball URLs, ``user/repo#ref`` shorthands.
_REMOTE_SPECIFIER = re.compile(
    r"(?i)^(?:git|github|gitlab|bitbucket|gist|https?|ssh)[+:]|^[a-z][a-z0-9+.-]{0,20}+://|[/\\@\s]"
)
# Distinct registry hosts kept per lockfile.
MAX_REGISTRY_HOSTS = 1_000


def registry_host(value: Any) -> str | None:
    """The host a package resolved from, from a download or index URL (Cargo's ``registry+``
    and ``sparse+`` forms too); None for anything else. Only the host is kept: these URLs can
    carry credentials and private paths. crates.io's index, wherever it is served, is crates.io."""
    if not isinstance(value, str):
        return None
    text = value.strip().removeprefix("registry+").removeprefix("sparse+")
    if "://" not in text[:16]:
        return None
    try:
        host = urllib.parse.urlsplit(text).hostname
    except ValueError:
        return None
    if not host:
        return None
    if host == "index.crates.io" or text.rstrip("/").endswith("github.com/rust-lang/crates.io-index"):
        return "crates.io"
    return host.lower()


class ParsedLockfile(list):
    """Resolved registry packages, plus the names of entries that resolve elsewhere.

    ``local`` holds the project's own packages: the root project, workspace members and
    path or linked packages. ``non_registry`` holds third-party dependencies taken from
    git or a URL. Neither has a registry version, so neither is looked up or matched
    against advisories; only ``non_registry`` is a coverage gap.
    """

    local: list[str]
    non_registry: list[str]
    # Registry hosts by the number of packages resolved from each, where the format records
    # it (npm and Yarn v1 download URLs, pnpm tarballs, Cargo sources, uv and Poetry indexes,
    # Pipfile.lock sources, Composer dists, Gemfile.lock remotes, Hex, SwiftPM and pub).
    registries: dict[str, int]


class _Collector:
    def __init__(self, ecosystem: str, max_entries: int) -> None:
        self.ecosystem = ecosystem
        self.max_entries = max_entries
        self.packages: set[ResolvedPackage] = set()
        self.local_names: set[str] = set()
        self.non_registry: set[str] = set()
        self.registries: Counter[str] = Counter()
        # The registry of packages that name none, where the format implies one (Poetry: PyPI).
        self.default_registry: str | None = None

    def count_registry(self, value: Any, number: int = 1) -> None:
        host = value if value in self.registries else registry_host(value)
        if host and number > 0 and (host in self.registries or len(self.registries) < MAX_REGISTRY_HOSTS):
            self.registries[host] += number

    def add(self, name: Any, version: Any, registry: Any = None) -> bool:
        """Record one registry package; True when it is new (``registry``: where it came from)."""
        if not name or not version:
            return False
        name, text = str(name).strip(), normalize_version(version)
        if text[:4].lower() == "npm:":
            # npm alias ("npm:real-name@1.2.3"): the real package and its version.
            real, _, aliased = text[4:].rpartition("@")
            if real and aliased:
                name, text = real, aliased
        # Only the name is kept: a specifier can hold credentials or local paths.
        if _LOCAL_SPECIFIER.search(text):
            self.local(name)
            return False
        if _REMOTE_SPECIFIER.search(text):
            self.remote(name)
            return False
        package = ResolvedPackage(self.ecosystem, name, text)
        if not package.name or not package.version or package in self.packages:
            return False
        if len(self.packages) >= self.max_entries:
            limit_reached("entries", self.max_entries, len(self.packages) + 1)
            raise LockfileEntryBudgetExceeded(
                f"lockfile exceeded the {self.max_entries:,}-package entry budget"
            )
        self.packages.add(package)
        if registry is not None:
            self.count_registry(registry)
        elif self.default_registry:
            self.registries[self.default_registry] += 1
        return True

    def local(self, name: Any) -> None:
        """Record one of the project's own packages (never sent anywhere or matched)."""
        if name and len(self.local_names) < self.max_entries:
            self.local_names.add(str(name).strip())

    def remote(self, name: Any) -> None:
        """Record a third-party dependency taken from git or a URL (a coverage gap)."""
        if name and len(self.non_registry) < self.max_entries:
            self.non_registry.add(str(name).strip())


def _npm_lock(data: Any, out: _Collector) -> None:
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for item_path, item in packages.items():
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item_path.rsplit("node_modules/", 1)[-1]
            # "" is the root project; keys outside node_modules/ are workspace members,
            # and links point at them: the project's own code.
            if not item_path or "node_modules/" not in item_path or item.get("link"):
                out.local(name or item_path)
                continue
            out.add(name, item.get("version"), item.get("resolved"))
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
            out.add(name, item.get("version"), item.get("resolved"))
            nested = item.get("dependencies")
            if isinstance(nested, dict) and nested:
                stack.append(iter(nested.items()))


_YARN_SELECTOR = re.compile(r"^(@[^/@]+/[^@]+|[^@]+)@(.+)$")
_YARN_VERSION = re.compile(r"""^\s+version:?\s+["']?([^"'\s]+)""")


def _yarn_lock(source: str, out: _Collector) -> None:
    """Parse Yarn v1 and Berry (v2+) lockfiles without a YAML dependency."""
    names: list[str] = []
    added = 0  # the packages of the last entry, for its v1 "resolved" download URL
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.endswith(":"):
            names = []
            for selector in line[:-1].split(","):
                match = _YARN_SELECTOR.match(selector.strip().strip("\"'"))
                if not match:
                    continue
                name, specifier = match.group(1), match.group(2)
                if specifier.startswith("npm:"):
                    # Alias ("lodash4@npm:lodash@^4.17.15"): the real package is "lodash".
                    real = specifier[4:].rpartition("@")[0]
                    name = real or name
                elif specifier.split(":", 1)[0] in {"workspace", "portal", "link", "file"}:
                    out.local(name)   # a Berry workspace member or local package
                    continue
                names.append(name)
            continue
        if names:
            match = _YARN_VERSION.match(line)
            if match:
                added = sum(out.add(name, match.group(1)) for name in names)
                names = []
                continue
        stripped = line.strip()
        if added and stripped.startswith("resolved "):
            out.count_registry(stripped[9:].strip().strip("\"'"), added)
            added = 0


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
    section, added = None, False
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
            added = bool(parsed) and out.add(*parsed)
            continue
        # A package from another registry or a URL records its tarball; the default registry
        # (from .npmrc) is not in the lockfile.
        at = line.find("tarball:")
        if added and at >= 0:
            out.count_registry(line[at + 8:].strip().split(",", 1)[0].strip().strip("}\"' "))
            added = False


def _toml_packages(source: str, out: _Collector, *, cargo: bool = False) -> None:
    data = tomllib.loads(source)
    for item in data.get("package", []):
        registry = None
        if not isinstance(item, dict):
            continue
        origin = item.get("source")
        if isinstance(origin, str) or cargo:
            # Cargo: crates.io and other registries are registry+/sparse+; no source is
            # the project's own crate or a workspace or path member.
            if not origin:
                out.local(item.get("name"))
                continue
            if not origin.startswith(("registry+", "sparse+")):
                out.remote(item.get("name"))
                continue
            registry = origin
        elif isinstance(origin, dict):
            # uv: {registry = ...} or editable/virtual/path/directory/git/url;
            # poetry: [package.source] with type directory/file/git/url (legacy = an index).
            kind = origin.get("type") or next(iter(origin), "")
            if kind in {"editable", "virtual", "path", "directory", "file"}:
                out.local(item.get("name"))
                continue
            if kind in {"git", "url"}:
                out.remote(item.get("name"))
                continue
            registry = origin.get("registry") or origin.get("url")
        elif item.get("path") or item.get("editable"):
            out.local(item.get("name"))   # pdm: a local or editable package
            continue
        elif item.get("git") or item.get("url"):
            out.remote(item.get("name"))
            continue
        out.add(item.get("name"), item.get("version"), registry)


def _composer_lock(data: Any, out: _Collector) -> None:
    for group in ("packages", "packages-dev"):
        for item in data.get(group, []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            dist = item.get("dist") if isinstance(item.get("dist"), dict) else {}
            if dist.get("type") == "path":
                out.local(item.get("name"))   # a path repository: the project's own code
                continue
            origin = item.get("source") if isinstance(item.get("source"), dict) else {}
            out.add(item.get("name"), item.get("version"), dist.get("url") or origin.get("url"))


def _pipfile_lock(data: Any, out: _Collector) -> None:
    meta = data.get("_meta") if isinstance(data, dict) and isinstance(data.get("_meta"), dict) else {}
    sources = [item for item in meta.get("sources") or [] if isinstance(item, dict)]
    indexes = {str(item.get("name")): item.get("url") for item in sources}
    default_index = sources[0].get("url") if sources else None
    for group in ("default", "develop"):
        entries = data.get(group, {}) if isinstance(data, dict) else {}
        for name, item in entries.items() if isinstance(entries, dict) else ():
            if isinstance(item, dict) and (item.get("path") or item.get("file") or item.get("editable")):
                out.local(name)
                continue
            if isinstance(item, dict) and item.get("git"):
                out.remote(name)
                continue
            version = item.get("version") if isinstance(item, dict) else item
            index = item.get("index") if isinstance(item, dict) else None
            out.add(name, version, indexes.get(str(index), default_index) if index else default_index)


_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$")


def _gemfile_lock(source: str, out: _Collector) -> None:
    in_specs, section, remote = False, "", None
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs, section, remote = False, line.strip(), None
        if section == "GEM" and line.startswith("  remote:"):
            remote = line.split(":", 1)[1].strip()
            continue
        if in_specs:
            match = _GEM_SPEC.match(line)
            if match and section == "PATH":
                out.local(match.group(1))     # a gem from the project's own tree
            elif match and section == "GIT":
                out.remote(match.group(1))
            elif match:
                # Platform gems are locked as "1.15.4-x86_64-linux"; gem versions never contain "-".
                out.add(match.group(1), match.group(2).split("-", 1)[0], remote)


_GO_SUM = re.compile(r"^(\S+)\s+(v\S+?)(/go\.mod)?\s+h\d+:")


def _go_sum(source: str, out: _Collector) -> None:
    for raw_line in io.StringIO(source, newline=None):
        match = _GO_SUM.match(raw_line)
        # "/go.mod"-only lines record module-graph resolution, not a downloaded build input.
        if match and not match.group(3):
            out.add(match.group(1), match.group(2))


# "key": {:hex, :package_atom, "version", ...}; the key can differ from the package.
_MIX_PACKAGE = re.compile(r'^\s*"([^"]+)":\s*\{:(\w+),\s*(?::(\w+)\s*,\s*"([^"]+)")?')


def _mix_lock(source: str, out: _Collector) -> None:
    for raw_line in io.StringIO(source, newline=None):
        match = _MIX_PACKAGE.match(raw_line)
        if not match:
            continue
        if match.group(2) == "hex" and match.group(3):
            out.add(match.group(3), match.group(4), "https://repo.hex.pm")
        elif match.group(2) in {"git", "path"}:
            (out.local if match.group(2) == "path" else out.remote)(match.group(1))


def _swift_identity(item: dict[str, Any]) -> str | None:
    location = item.get("location") or item.get("repositoryURL")
    if isinstance(location, str) and location:
        value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", location.strip(), flags=re.I)
        value = re.sub(r"^[^/@:]+@(?=[^/]+/)", "", value)   # ssh://git@host/... -> host/...
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
            location = item.get("location") or item.get("repositoryURL")
            out.add(_swift_identity(item), state.get("version") if isinstance(state, dict) else None,
                    location if isinstance(location, str) and "://" in location else None)


def _nuget_lock(data: Any, out: _Collector) -> None:
    # packages.lock.json is keyed by target framework, then package id.
    frameworks = data.get("dependencies", {}) if isinstance(data, dict) else {}
    for packages in frameworks.values() if isinstance(frameworks, dict) else ():
        for name, item in packages.items() if isinstance(packages, dict) else ():
            if not isinstance(item, dict):
                continue
            if item.get("type") == "Project":
                out.local(name)   # a project reference in the same solution
            else:
                out.add(name, item.get("resolved"))


_PUB_PACKAGE = re.compile(r"^ {2}([A-Za-z0-9_]+):\s*$")
_PUB_VERSION = re.compile(r"""^ {4}version:\s*["']?([^"'\s]+)""")
_PUB_SOURCE = re.compile(r"""^ {4}source:\s*["']?(\w+)""")
_PUB_URL = re.compile(r"""^ {6}url:\s*["']?([^"'\s]+)""")


def _pubspec_lock(source: str, out: _Collector) -> None:
    in_packages, current, origin, registry = False, None, "hosted", None
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line and not line[0].isspace():
            in_packages, current = line.strip() == "packages:", None
            continue
        if not in_packages:
            continue
        package = _PUB_PACKAGE.match(line)
        if package:
            current, origin, registry = package.group(1), "hosted", None
            continue
        url = _PUB_URL.match(line)
        if current and url:
            registry = url.group(1)
            continue
        source_line = _PUB_SOURCE.match(line)
        if current and source_line:
            origin = source_line.group(1)
            continue
        version = _PUB_VERSION.match(line)
        if current and version:
            if origin in {"path", "sdk"}:
                out.local(current)
            elif origin == "git":
                out.remote(current)
            else:
                out.add(current, version.group(1), registry)
            current = None


def parse_lockfile(
    filename: str, source: str, *, max_entries: int = MAX_LOCKFILE_PACKAGE_ENTRIES,
) -> ParsedLockfile:
    """Return de-duplicated resolved registry packages in deterministic order.

    The project's own packages (root, workspace and path members) are listed by name in
    the result's ``local`` attribute, third-party dependencies from git or a URL in
    ``non_registry``.

    Raises ValueError subclasses (including JSON/TOML decode errors and
    LockfileEntryBudgetExceeded) for malformed or over-budget input.
    """
    name = filename.casefold()
    ecosystem = LOCKFILE_ECOSYSTEMS.get(name)
    if ecosystem is None:
        raise ValueError(f"unsupported lockfile format: {filename}")
    out = _Collector(ecosystem, max_entries)
    if name == "poetry.lock":
        out.default_registry = "pypi.org"  # Poetry records a source only for packages from another index
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        _npm_lock(json.loads(source), out)
    elif name == "yarn.lock":
        _yarn_lock(source, out)
    elif name == "pnpm-lock.yaml":
        _pnpm_lock(source, out)
    elif name in {"cargo.lock", "poetry.lock", "uv.lock", "pdm.lock"}:
        _toml_packages(source, out, cargo=name == "cargo.lock")
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
    registry_names = {package.name for package in out.packages}
    result.local = sorted(out.local_names - registry_names)
    result.non_registry = sorted(out.non_registry - registry_names - out.local_names)
    result.registries = dict(sorted(out.registries.items(), key=lambda item: (-item[1], item[0])))
    return result
