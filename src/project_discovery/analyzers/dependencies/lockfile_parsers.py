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
    "podfile.lock": "CocoaPods",
    "gradle.lockfile": "Maven",
    "buildscript-gradle.lockfile": "Maven",
    "settings-gradle.lockfile": "Maven",
    "conan.lock": "ConanCenter",
    "vcpkg-status": "vcpkg",  # vcpkg_installed/vcpkg/status (see lockfile_key)
    "bun.lock": "npm",
    "deno.lock": "npm",
    "renv.lock": "CRAN",
    "manifest.toml": "Julia",
    "juliamanifest.toml": "Julia",
    "cabal.project.freeze": "Hackage",
    "stack.yaml.lock": "Hackage",
    "rebar.lock": "Hex",
    "cpanfile.snapshot": "CPAN",
    "shard.lock": "Crystal",
    "dub.selections.json": "DUB",
    "packages.config": "NuGet",
    "pylock.toml": "PyPI",
    "cartfile.resolved": "Carthage",
    # Installed packages and SBOM components (see os_packages): each package carries its own
    # ecosystem (the distribution release, a purl's ecosystem); these are the defaults.
    "dpkg-status": "Debian",
    "apk-installed": "Alpine",
    "rpmdb-sqlite": "RPM",
    "sbom-json": "SBOM",
}
LOCKFILE_NAMES = frozenset(name for name in LOCKFILE_ECOSYSTEMS if "." in name)
# The ecosystems OSV.dev has advisories for, of those the lockfiles name. The others (CocoaPods,
# vcpkg, JSR, Julia, CPAN, Crystal, DUB, Carthage) cannot be checked online.
OSV_ECOSYSTEMS = frozenset({
    "npm", "PyPI", "crates.io", "Packagist", "RubyGems", "Go", "Hex", "SwiftURL", "NuGet", "Pub", "Maven",
    "ConanCenter", "CRAN", "Bioconductor", "Hackage", "Debian", "Ubuntu", "Alpine", "AlmaLinux", "Rocky Linux",
    "Wolfi",
})
# OSV names these distributions with their release ("Debian:12"): without one, nothing matches.
_RELEASED_ECOSYSTEMS = frozenset({"Debian", "Ubuntu", "Alpine", "AlmaLinux", "Rocky Linux"})


def osv_covers(ecosystem: str) -> bool:
    """Whether OSV.dev publishes advisories for this (OSV-named) ecosystem."""
    base, separator, _ = ecosystem.partition(":")
    return base in OSV_ECOSYSTEMS and (bool(separator) or base not in _RELEASED_ECOSYSTEMS)


def lockfile_key(path: str) -> str | None:
    """The lockfile format of a path, as LOCKFILE_ECOSYSTEMS keys it; None for other files.
    Most formats are a file name; vcpkg's installed database is a path
    (``vcpkg_installed/vcpkg/status``), and PEP 751 also allows ``pylock.<name>.toml``."""
    normalized = str(path).replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1].casefold()
    if name in LOCKFILE_ECOSYSTEMS and name != "vcpkg-status":
        return name
    if name.startswith("pylock.") and name.endswith(".toml") and name.count(".") == 2:
        return "pylock.toml"
    lowered = normalized.casefold()
    if name == "status" and lowered.endswith(("vcpkg_installed/vcpkg/status", "installed/vcpkg/status")):
        return "vcpkg-status"
    if lowered.endswith("var/lib/dpkg/status"):
        return "dpkg-status"
    if lowered.endswith("lib/apk/db/installed"):
        return "apk-installed"
    if lowered.endswith(("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite")):
        return "rpmdb-sqlite"
    if name in {"bom.json", "sbom.json"} or name.endswith((".cdx.json", ".cyclonedx.json", ".spdx.json")):
        return "sbom-json"
    return None


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

    def add(self, name: Any, version: Any, registry: Any = None, ecosystem: str | None = None) -> bool:
        """Record one registry package; True when it is new (``registry``: where it came from;
        ``ecosystem``: another than the lockfile's, as in a Deno lockfile's JSR packages)."""
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
        package = ResolvedPackage(ecosystem or self.ecosystem, name, text)
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


def _url_name(url: Any) -> str:
    """A URL dependency as a name: its host and path, without user information, query or
    fragment (they can carry credentials)."""
    text = str(url).strip()
    try:
        parts = urllib.parse.urlsplit(text)
        host = parts.hostname or ""
    except ValueError:
        host = ""
    if host:
        return (host + parts.path)[:200]
    return text.split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[-1][:200]


def _podfile_lock(source: str, out: _Collector) -> None:
    """CocoaPods: the PODS entries ("Name (1.2.3)"; subspecs "Name/Sub" are the pod "Name"), with
    EXTERNAL SOURCES (a path is the project's own pod, git or a URL a pod outside a spec repo) and
    the SPEC REPOS each pod came from (trunk is the CocoaPods CDN)."""
    section, heading = "", ""
    pods: list[tuple[str, str]] = []
    external: dict[str, str] = {}
    repositories: dict[str, str] = {}
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        if not line[0].isspace():
            section, heading = line.split(":", 1)[0].strip(), ""
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if section == "PODS" and indent == 2 and stripped.startswith("- "):
            entry = stripped[2:].strip().rstrip(":").strip("\"'")
            name, _, rest = entry.partition(" (")
            pods.append((name.split("/", 1)[0].strip(), rest.rstrip(")").strip()))
        elif section in {"EXTERNAL SOURCES", "SPEC REPOS"} and indent == 2 and stripped.endswith(":"):
            heading = stripped[:-1].strip("\"'")
        elif section == "EXTERNAL SOURCES" and heading and indent >= 4 and stripped.startswith(":"):
            key = stripped.split(":", 2)[1]
            if key == "path":
                external[heading] = "path"
            elif key in {"git", "http", "podspec"}:
                external.setdefault(heading, "remote")
        elif section == "SPEC REPOS" and heading and indent >= 4 and stripped.startswith("- "):
            repositories[stripped[2:].strip().strip("\"'")] = heading
    for name, version in pods:
        origin = external.get(name)
        if origin == "path":
            out.local(name)
        elif origin == "remote":
            out.remote(name)
        else:
            repository = repositories.get(name, "trunk")
            out.add(name, version, "https://cdn.cocoapods.org/" if repository == "trunk" else repository)


def _gradle_lockfile(source: str, out: _Collector) -> None:
    """Gradle dependency locking: "group:artifact:version=configurations" lines (Maven names)."""
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        parts = line.split("=", 1)[0].split(":")
        if len(parts) >= 3:
            out.add(f"{parts[0]}:{parts[1]}", parts[2])


def _conan_reference(reference: Any) -> tuple[str, str] | None:
    """(name, version) of a Conan reference "name/version[@user/channel][#revision][%time]"."""
    if not isinstance(reference, str):
        return None
    name, slash, version = reference.split("#", 1)[0].split("@", 1)[0].strip().partition("/")
    return (name, version) if slash and name and version else None


def _conan_lock(data: Any, out: _Collector) -> None:
    """Conan 2 lockfiles (requires, build_requires, python_requires) and Conan 1 graph locks."""
    if not isinstance(data, dict):
        return
    references: list[Any] = []
    for key in ("requires", "build_requires", "python_requires", "config_requires"):
        references.extend(data.get(key) or [])
    graph = data.get("graph_lock") if isinstance(data.get("graph_lock"), dict) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    for node in nodes.values():
        if isinstance(node, dict) and not node.get("path"):  # a node with a path is the consumer
            references.append(node.get("ref") or node.get("pref"))
    for reference in references:
        parsed = _conan_reference(reference)
        if parsed:
            out.add(*parsed)


def _vcpkg_status(source: str, out: _Collector) -> None:
    """vcpkg's database of installed ports (vcpkg_installed/vcpkg/status): one paragraph per
    installed port; feature paragraphs repeat the port and are skipped. A port version is
    written ``1.3.1#2``, as vcpkg names it."""
    fields: dict[str, str] = {}

    def flush() -> None:
        if (fields.get("Package") and fields.get("Version") and "Feature" not in fields
                and "install ok installed" in fields.get("Status", "")):
            port = fields.get("Port-Version", "0")
            out.add(fields["Package"], fields["Version"] + (f"#{port}" if port not in {"", "0"} else ""))

    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            flush()
            fields = {}
        elif not line[0].isspace():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
    flush()


def _strip_trailing_commas(text: str) -> str:
    """JSON with trailing commas (bun.lock is JSONC) as strict JSON: a comma followed only by
    white space and a closing bracket is dropped; strings are left alone."""
    result: list[str] = []
    in_string = escaped = False
    pending = -1  # the index of a comma that only white space follows so far
    for char in text:
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char in "}]" and pending >= 0:
            result[pending] = ""
        if char == ",":
            pending = len(result)
        elif not char.isspace():
            pending = -1
            in_string = char == '"'
        result.append(char)
    return "".join(result)


def _bun_lock(data: Any, out: _Collector) -> None:
    """Bun's text lockfile: each package is ["name@version", registry, ...]."""
    packages = data.get("packages") if isinstance(data, dict) else None
    for value in packages.values() if isinstance(packages, dict) else ():
        if not isinstance(value, list) or not value or not isinstance(value[0], str):
            continue
        ident = value[0]
        at = ident.find("@", 1)
        if at <= 0:
            continue
        name, specifier = ident[:at], ident[at + 1:]
        if specifier.startswith(("workspace:", "link:", "file:", "./", "../")):
            out.local(name)
        elif specifier.startswith(("github:", "git+", "git:", "http:", "https:")) or "/" in specifier:
            out.remote(name)
        else:
            registry = value[1] if len(value) > 1 and isinstance(value[1], str) and value[1] else None
            out.add(name, specifier, registry)


def _deno_lock(data: Any, out: _Collector) -> None:
    """Deno lockfiles (v3 nests the sections under "packages"): npm and JSR packages
    ("name@version", a peer suffix after "_"), and remote modules imported by URL."""
    if not isinstance(data, dict):
        return
    sections = data["packages"] if isinstance(data.get("packages"), dict) else data
    for kind, ecosystem in (("npm", "npm"), ("jsr", "JSR")):
        entries = sections.get(kind)
        for key in entries if isinstance(entries, dict) else ():
            text = str(key)
            at = text.find("@", 1)
            if at > 0:
                out.add(text[:at], text[at + 1:].split("_", 1)[0], None, ecosystem)
    remote = data.get("remote")
    for url in remote if isinstance(remote, dict) else ():
        out.remote(_url_name(url))


def _renv_lock(data: Any, out: _Collector) -> None:
    """renv lockfiles: CRAN and other repository packages, Bioconductor packages, and packages
    from GitHub, GitLab, Bitbucket, git or a URL (outside a repository) or the local tree."""
    if not isinstance(data, dict):
        return
    settings = data.get("R") if isinstance(data.get("R"), dict) else {}
    repositories = {str(item.get("Name")): item.get("URL") for item in settings.get("Repositories") or []
                    if isinstance(item, dict)}
    packages = data.get("Packages") if isinstance(data.get("Packages"), dict) else {}
    for key, item in packages.items():
        if not isinstance(item, dict):
            continue
        name, source = item.get("Package") or key, str(item.get("Source") or "Repository")
        if source in {"Local", "Cellar"}:
            out.local(name)
        elif source in {"GitHub", "GitLab", "Bitbucket", "git", "URL"}:
            out.remote(name)
        elif source == "Bioconductor":
            out.add(name, item.get("Version"), None, "Bioconductor")
        else:
            out.add(name, item.get("Version"), repositories.get(str(item.get("Repository") or "CRAN")))


def _julia_manifest(data: Any, out: _Collector) -> None:
    """Julia manifests: format 2 ([[deps.Name]]) and format 1 ([[Name]] at the top). A package
    without a version ships with Julia (a standard library); a path or repo-url is the
    project's own package or one outside the registry."""
    if not isinstance(data, dict):
        return
    if "manifest_format" in data:
        deps = data.get("deps") if isinstance(data.get("deps"), dict) else {}
    else:
        deps = {key: value for key, value in data.items() if isinstance(value, list)}
    for name, entries in deps.items():
        for item in entries if isinstance(entries, list) else ():
            if not isinstance(item, dict) or "uuid" not in item:
                continue
            if item.get("path"):
                out.local(name)
            elif item.get("repo-url"):
                out.remote(name)
            elif item.get("version"):
                out.add(name, item["version"])


_CABAL_CONSTRAINT = re.compile(r"\bany\.([A-Za-z0-9][A-Za-z0-9-]{0,100}) ==([0-9][0-9.]{0,50})")


def _cabal_freeze(source: str, out: _Collector) -> None:
    """cabal.project.freeze: "any.name ==version" constraints (installed GHC packages have none)."""
    for match in _CABAL_CONSTRAINT.finditer(source):
        out.add(match.group(1), match.group(2).rstrip("."), "https://hackage.haskell.org/")


def _stack_lock(source: str, out: _Collector) -> None:
    """stack.yaml.lock: Hackage packages ("hackage: name-1.2.3@sha256:...") and git or archive
    packages, which are outside the registry."""
    for raw_line in io.StringIO(source, newline=None):
        key, _, value = raw_line.strip().lstrip("- ").partition(":")
        value = value.strip()
        if key == "hackage":
            package = value.split("@", 1)[0]
            name, dash, version = package.rpartition("-")
            if dash and name and version[:1].isdigit():
                out.add(name, version, "https://hackage.haskell.org/")
        elif key in {"git", "url", "archive"} and value:
            out.remote(_url_name(value))


_REBAR_PACKAGE = re.compile(r'\{<<"([^"\n]{1,200})">>,\s*+\{pkg,\s*+<<"([^"\n]{1,200})">>,\s*+<<"([^"\n]{1,100})">>')
_REBAR_SOURCE = re.compile(r'\{<<"([^"\n]{1,200})">>,\s*+\{(?:git|git_subdir|raw)\b')


def _rebar_lock(source: str, out: _Collector) -> None:
    """rebar3 lockfiles: Hex packages ({pkg, Name, Version}) and git dependencies."""
    for match in _REBAR_PACKAGE.finditer(source):
        out.add(match.group(2), match.group(3), "https://repo.hex.pm")
    for match in _REBAR_SOURCE.finditer(source):
        out.remote(match.group(1))


def _carton_snapshot(source: str, out: _Collector) -> None:
    """Carton's cpanfile.snapshot: the DISTRIBUTIONS, each "Name-Version" (from CPAN)."""
    in_distributions = False
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line and not line[0].isspace():
            in_distributions = line.strip() == "DISTRIBUTIONS"
            continue
        if in_distributions and line.startswith("  ") and not line.startswith("   "):
            name, dash, version = line.strip().rpartition("-")
            if dash and name and (version[:1].isdigit() or (version[:1] == "v" and version[1:2].isdigit())):
                out.add(name, version, "https://cpan.metacpan.org/")


def _shard_lock(source: str, out: _Collector) -> None:
    """Crystal shard.lock: each shard's version and the git host it is fetched from."""
    in_shards, current, origin = False, None, None
    hosts = {"github": "https://github.com/", "gitlab": "https://gitlab.com/", "bitbucket": "https://bitbucket.org/",
             "codeberg": "https://codeberg.org/"}
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if line and not line[0].isspace():
            in_shards, current = line.strip() == "shards:", None
            continue
        if not in_shards or not line.strip():
            continue
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            current, origin = line.strip()[:-1], None
            continue
        key, _, value = line.strip().partition(":")
        value = value.strip().strip("\"'")
        if not current:
            continue
        if key in {"git", "hg", "fossil"}:
            origin = value
        elif key in hosts:
            origin = hosts[key] + value
        elif key == "path":
            out.local(current)
            current = None
        elif key == "version":
            out.add(current, value, origin)
            current = None


def _dub_selections(data: Any, out: _Collector) -> None:
    """DUB's dub.selections.json: registry versions, paths and repositories."""
    versions = data.get("versions") if isinstance(data, dict) else None
    for name, value in versions.items() if isinstance(versions, dict) else ():
        if isinstance(value, str):
            out.add(name, value, "https://code.dlang.org/")
        elif isinstance(value, dict) and value.get("path"):
            out.local(name)
        elif isinstance(value, dict) and value.get("repository"):
            out.remote(name)
        elif isinstance(value, dict) and isinstance(value.get("version"), str):
            out.add(name, value["version"], "https://code.dlang.org/")


_PACKAGE_TAG = re.compile(r"<package\b([^<>]{0,4000})>")
_XML_ATTRIBUTE = re.compile(r'\b([A-Za-z]{1,40})\s*+=\s*+"([^"]{0,400})"')


def _packages_config(source: str, out: _Collector) -> None:
    """NuGet packages.config: each <package id="..." version="..."> is an installed version.
    Read with patterns, not an XML parser: no entity or DTD is ever expanded."""
    for tag in _PACKAGE_TAG.finditer(source):
        attributes = {key.lower(): value for key, value in _XML_ATTRIBUTE.findall(tag.group(1))}
        if attributes.get("id") and attributes.get("version"):
            out.add(attributes["id"], attributes["version"])


def _pylock(data: Any, out: _Collector) -> None:
    """PEP 751 pylock.toml: packages from an index, a directory (the project's own) or a VCS
    or archive URL (outside a registry)."""
    for item in data.get("packages", []) if isinstance(data, dict) else ():
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if item.get("directory"):
            out.local(name)
        elif item.get("vcs") or item.get("archive"):
            out.remote(name)
        else:
            out.add(name, item.get("version"), item.get("index"))


def _cartfile_resolved(source: str, out: _Collector) -> None:
    """Carthage's Cartfile.resolved: every dependency is a git repository or a binary URL, so
    every one is outside a registry."""
    for raw_line in io.StringIO(source, newline=None):
        parts = raw_line.strip().split('"')
        if len(parts) >= 4 and parts[0].strip() in {"github", "git", "binary"}:
            out.remote(parts[1][:200] if parts[0].strip() == "github" else _url_name(parts[1]))


def parse_lockfile(
    filename: str, source: str | bytes, *, max_entries: int = MAX_LOCKFILE_PACKAGE_ENTRIES,
    context: dict | None = None,
) -> ParsedLockfile:
    """Return de-duplicated resolved registry packages in deterministic order.

    The project's own packages (root, workspace and path members) are listed by name in
    the result's ``local`` attribute, third-party dependencies from git or a URL in
    ``non_registry``.

    Raises ValueError subclasses (including JSON/TOML decode errors and
    LockfileEntryBudgetExceeded) for malformed or over-budget input.
    """
    name = lockfile_key(filename) or filename.casefold()
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
    elif name == "podfile.lock":
        _podfile_lock(source, out)
    elif name in {"gradle.lockfile", "buildscript-gradle.lockfile", "settings-gradle.lockfile"}:
        _gradle_lockfile(source, out)
    elif name == "conan.lock":
        _conan_lock(json.loads(source), out)
    elif name == "vcpkg-status":
        _vcpkg_status(source, out)
    elif name == "bun.lock":
        _bun_lock(json.loads(_strip_trailing_commas(source)), out)
    elif name == "deno.lock":
        _deno_lock(json.loads(source), out)
    elif name == "renv.lock":
        _renv_lock(json.loads(source), out)
    elif name in {"manifest.toml", "juliamanifest.toml"}:
        _julia_manifest(tomllib.loads(source), out)
    elif name == "cabal.project.freeze":
        _cabal_freeze(source, out)
    elif name == "stack.yaml.lock":
        _stack_lock(source, out)
    elif name == "rebar.lock":
        _rebar_lock(source, out)
    elif name == "cpanfile.snapshot":
        _carton_snapshot(source, out)
    elif name == "shard.lock":
        _shard_lock(source, out)
    elif name == "dub.selections.json":
        _dub_selections(json.loads(source), out)
    elif name == "packages.config":
        _packages_config(source, out)
    elif name == "pylock.toml":
        _pylock(tomllib.loads(source), out)
    elif name == "cartfile.resolved":
        _cartfile_resolved(source, out)
    elif name in {"dpkg-status", "apk-installed", "rpmdb-sqlite"}:
        from . import os_packages

        # The distribution release from the root's os-release: "Debian:12", "Alpine:v3.19".
        ecosystem = os_packages.os_ecosystem((context or {}).get("os_release", ""), out.ecosystem)
        if name == "dpkg-status":
            os_packages.dpkg_status(source, out, ecosystem)
        elif name == "apk-installed":
            os_packages.apk_installed(source, out, ecosystem)
        else:
            os_packages.rpmdb(source if isinstance(source, bytes) else source.encode("utf-8", "surrogateescape"),
                              out, ecosystem)
    elif name == "sbom-json":
        from . import os_packages

        os_packages.sbom(json.loads(source), out)
    result = ParsedLockfile(sorted(out.packages, key=lambda p: (p.name.casefold(), p.name, p.version)))
    registry_names = {package.name for package in out.packages}
    result.local = sorted(out.local_names - registry_names)
    result.non_registry = sorted(out.non_registry - registry_names - out.local_names)
    result.registries = dict(sorted(out.registries.items(), key=lambda item: (-item[1], item[0])))
    return result
