"""Static dependency manifest analysis; declarations are not treated as installed packages."""
from __future__ import annotations

import configparser
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding
from ..source_utils import SourceBudgetExceeded, read_text_bounded, redact_source_excerpt

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


_MAX_DEPENDENCY_MANIFEST_BYTES = 32 * 1024 * 1024


class DependencyManifestAnalyzer(Analyzer):
    """Extract explicitly declared dependencies from common project manifests."""

    name = "dependency-manifests"
    domains = ("dependency_manifests",)
    _supported_names = {
        "pyproject.toml", "cargo.toml", "go.mod", "package.json", "composer.json",
        "pom.xml", "build.gradle", "build.gradle.kts", "package.swift",
        "pubspec.yaml", "pubspec.yml", "gemfile", "mix.exs", "rebar.config",
        "pipfile", "project.toml", "deps.edn", "project.clj", "build.sbt",
        "cpanfile", "cmakelists.txt", "conanfile.txt", "conanfile.py",
        "platformio.ini", "description", "package.xml", "vcpkg.json",
        "dub.json", "haxelib.json", "shard.yml", "fpm.toml",
    }

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            name in self._supported_names
            or (name.startswith("requirements") and record.extension == ".txt")
            or name.endswith((".csproj", ".fsproj", ".vbproj", ".gemspec", ".cabal", ".opam", ".nimble", ".rockspec"))
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > _MAX_DEPENDENCY_MANIFEST_BYTES:
            return [Finding(
                "configuration",
                f"Dependency manifest resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the dependency-manifest "
                f"{_MAX_DEPENDENCY_MANIFEST_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            content = read_text_bounded(
                path, _MAX_DEPENDENCY_MANIFEST_BYTES,
                expected_identity=record.analysis_identity,
            )
            declarations = self._extract(path, record, content)
        except SourceBudgetExceeded as exc:
            return [Finding(
                "configuration", f"Dependency manifest resource limit: {record.path}",
                str(exc), confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError, configparser.Error, ValueError) as exc:
            return [Finding(
                "configuration",
                "Dependency manifest parse error",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
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

    def _extract(
        self, path: Path, record: FileRecord, content: str
    ) -> list[tuple[str, str, str]]:
        name = Path(record.path).name.lower()
        declarations: list[tuple[str, str, str]] = []

        def add(dep_name: str, constraint: Any, group: str) -> None:
            declarations.append((dep_name, _constraint(constraint), group))

        if name == "pyproject.toml":
            data = tomllib.loads(content)
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
            for line in content.splitlines():
                parsed = _python_requirement(line.split(" #", 1)[0])
                if parsed:
                    add(parsed[0], parsed[1], "requirements")
        elif name in {"package.json", "composer.json"}:
            data = json.loads(content)
            groups = (
                ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
                if name == "package.json" else ("require", "require-dev")
            )
            for group in groups:
                for dep_name, constraint in data.get(group, {}).items():
                    add(dep_name, constraint, group)
        elif name == "cargo.toml":
            data = tomllib.loads(content)
            for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                for dep_name, constraint in data.get(group, {}).items():
                    add(dep_name, constraint, group)
            for target, target_data in data.get("target", {}).items():
                for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for dep_name, constraint in target_data.get(group, {}).items():
                        add(dep_name, constraint, f"target.{target}.{group}")
        elif name == "go.mod":
            lines = content.splitlines()
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
        elif name in {"pom.xml", "package.xml", "packages.config", "directory.packages.props"} or name.endswith((".csproj", ".fsproj", ".vbproj")):
            root = ET.fromstring(content)
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1].lower()
                if tag == "dependency" and name == "pom.xml":
                    fields = {
                        child.tag.rsplit("}", 1)[-1].lower(): (child.text or "").strip()
                        for child in element
                    }
                    artifact = fields.get("artifactid")
                    if artifact:
                        group_id = fields.get("groupid", "")
                        add(f"{group_id}:{artifact}" if group_id else artifact,
                            fields.get("version") or "managed/unspecified",
                            f"pom.xml dependency ({fields.get('scope', 'compile')})")
                elif tag in {"packagereference", "packageversion"}:
                    attributes = {
                        key.rsplit("}", 1)[-1].lower(): value
                        for key, value in element.attrib.items()
                    }
                    dep_name = attributes.get("include") or attributes.get("update")
                    version = attributes.get("version")
                    for child in element:
                        if child.tag.rsplit("}", 1)[-1].lower() == "version":
                            version = (child.text or "").strip()
                    if dep_name:
                        add(dep_name, version or "central/unspecified", tag)
                elif tag == "package" and name == "packages.config":
                    attributes = {
                        key.rsplit("}", 1)[-1].lower(): value
                        for key, value in element.attrib.items()
                    }
                    dep_name = attributes.get("id")
                    if dep_name:
                        add(dep_name, attributes.get("version", "unspecified"), "packages.config")
                elif tag in {"depend", "build_depend", "buildtool_depend", "exec_depend", "test_depend"} and name == "package.xml":
                    if element.text and element.text.strip():
                        add(element.text.strip(), "unspecified", f"ROS {tag}")
        elif name in {"build.gradle", "build.gradle.kts"}:
            pattern = re.compile(
                r"""(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|classpath|kapt|annotationProcessor|debugImplementation|releaseImplementation)\s*(?:\(\s*)?["']([^"']+)["']"""
            )
            for group, coordinate in pattern.findall(content):
                parts = coordinate.split(":")
                if len(parts) >= 2:
                    add(f"{parts[0]}:{parts[1]}", parts[2] if len(parts) > 2 else "unspecified", f"Gradle {group}")
        elif name == "package.swift":
            source = content
            pattern = re.compile(
                r"""\.package\s*\(\s*(?:name\s*:\s*["']([^"']+)["']\s*,\s*)?url\s*:\s*["']([^"']+)["']\s*,\s*(?:from|exact|branch|revision)\s*:\s*["']([^"']+)["']"""
            )
            for explicit_name, url, constraint in pattern.findall(source):
                dep_name = explicit_name or url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                add(dep_name, constraint, "Package.swift")
        elif name == "gemfile":
            pattern = re.compile(r"""(?m)^\s*gem\s+["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint or "unspecified", "Gemfile")
        elif name.endswith(".gemspec"):
            pattern = re.compile(r"""(?m)\.add_(?:development_)?dependency\s*\(?\s*["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint or "unspecified", "Ruby gemspec")
        elif name == "mix.exs":
            pattern = re.compile(r"""\{\s*:([A-Za-z0-9_]+)\s*,\s*["']([^"']+)["']""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint, "mix.exs deps")
        elif name in {"pubspec.yaml", "pubspec.yml", "shard.yml"}:
            try:
                import yaml
            except ImportError:
                source = content
                pattern = re.compile(r"""(?m)^\s{2}([A-Za-z0-9_.-]+):\s*([^\s#]+)\s*$""")
                for dep_name, constraint in pattern.findall(source):
                    add(dep_name, constraint, "YAML dependencies")
            else:
                try:
                    data = yaml.safe_load(content) or {}
                except yaml.YAMLError as exc:
                    raise ValueError(f"YAML dependency manifest parse error: {exc}") from exc
                groups = (
                    ("dependencies", "dependencies"),
                    ("dev_dependencies", "dev_dependencies"),
                    ("dependency_overrides", "dependency_overrides"),
                )
                for group, key in groups:
                    for dep_name, constraint in data.get(key, {}).items():
                        if dep_name not in {"flutter", "sdk"}:
                            add(dep_name, constraint, group)
        elif name == "pipfile":
            data = tomllib.loads(content)
            for group in ("packages", "dev-packages"):
                for dep_name, constraint in data.get(group, {}).items():
                    add(dep_name, constraint, f"Pipfile [{group}]")
        elif name == "project.toml":
            data = tomllib.loads(content)
            dependencies = data.get("deps", {})
            compatibility = data.get("compat", {})
            for dep_name, uuid in dependencies.items():
                add(dep_name, compatibility.get(dep_name, f"uuid:{uuid}"), "Julia Project.toml [deps]")
        elif name == "description":
            fields: dict[str, list[str]] = {}
            current = None
            for line in content.splitlines():
                if line and not line[0].isspace() and ":" in line:
                    current, value = line.split(":", 1)
                    if current in {"Imports", "Depends", "Suggests", "LinkingTo", "Enhances"}:
                        fields.setdefault(current, []).append(value.strip())
                    else:
                        current = None
                elif current and line.strip():
                    fields[current].append(line.strip())
            for group, values in fields.items():
                for item in ",".join(values).split(","):
                    match = re.match(r"\s*([A-Za-z][A-Za-z0-9.]*)", item)
                    if match and match.group(1) != "R":
                        add(match.group(1), item[match.end():].strip() or "unspecified", f"R DESCRIPTION {group}")
        elif name == "cmakelists.txt":
            source = content
            for dep_name, version in re.findall(
                r"""(?im)^\s*find_package\s*\(\s*([A-Za-z0-9_.+-]+)(?:\s+([0-9][^\s)]+))?""",
                source,
            ):
                add(dep_name, version or "unspecified", "CMake find_package")
            for dep_name in re.findall(
                r"""(?im)^\s*FetchContent_Declare\s*\(\s*([A-Za-z0-9_.+-]+)""",
                source,
            ):
                add(dep_name, "FetchContent declaration", "CMake FetchContent")
        elif name in {"conanfile.txt", "conanfile.py"}:
            source = content
            for dep_name, version in re.findall(
                r"""(?im)^\s*([A-Za-z0-9_.+-]+)/([A-Za-z0-9.*+_-]+)\s*$""", source
            ):
                add(dep_name, version, "Conan [requires]")
            for coordinate in re.findall(
                r"""(?:requires\s*=\s*["']|self\.requires\s*\(\s*["'])([^"']+)""",
                source,
            ):
                if "/" in coordinate:
                    dep_name, version = coordinate.split("/", 1)
                    add(dep_name, version, "Conan requires")
        elif name == "deps.edn":
            pattern = re.compile(r"""([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\s+\{\s*:mvn/version\s+["']([^"']+)["']""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint, "Clojure deps.edn")
        elif name == "project.clj":
            pattern = re.compile(r"""\[([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\s+["']([^"']+)["']\]""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint, "Leiningen project.clj")
        elif name == "build.sbt":
            pattern = re.compile(
                r"""["']([^"']+)["']\s*(?:%%|%)\s*["']([^"']+)["']\s*%\s*["']([^"']+)["']"""
            )
            for group_id, artifact, constraint in pattern.findall(content):
                add(f"{group_id}:{artifact}", constraint, "sbt libraryDependencies")
        elif name == "cpanfile":
            pattern = re.compile(r"""(?im)^\s*requires\s+["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint or "unspecified", "cpanfile requires")
        elif name.endswith(".cabal"):
            active = False
            for line in content.splitlines():
                if re.match(r"^\s*(?:build-depends|library|executable|test-suite)\s*:", line, re.I):
                    active = True
                    value = line.split(":", 1)[1]
                elif active and line[:1].isspace():
                    value = line.strip()
                else:
                    active = False
                    continue
                for item in value.split(","):
                    match = re.match(r"\s*([A-Za-z][A-Za-z0-9-]*)", item)
                    if match:
                        add(match.group(1), item[match.end():].strip() or "unspecified", "Cabal build-depends")
        elif name.endswith(".opam"):
            source = content
            for dep_name, constraint in re.findall(
                r"""["']([A-Za-z0-9_.+-]+)["']\s*\{\s*([<>=!~]+\s*["'][^"']+["'])""",
                source,
            ):
                add(dep_name, constraint, "opam depends")
        elif name.endswith(".nimble"):
            pattern = re.compile(r"""(?im)^\s*requires\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""")
            for dep_name, constraint in pattern.findall(content):
                add(dep_name, constraint or "unspecified", "Nimble requires")
        elif name == "package.xml":
            root = ET.fromstring(content)
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1].lower()
                if tag in {"depend", "build_depend", "buildtool_depend", "exec_depend", "test_depend"} and element.text:
                    add(element.text.strip(), "unspecified", f"ROS {tag}")
        elif name == "vcpkg.json":
            data = json.loads(content)
            for dependency in data.get("dependencies", []):
                if isinstance(dependency, str):
                    add(dependency, "baseline/unspecified", "vcpkg dependencies")
                elif isinstance(dependency, dict) and dependency.get("name"):
                    add(dependency["name"], dependency.get("version>=", dependency.get("version", "unspecified")), "vcpkg dependencies")
        elif name == "dub.json":
            data = json.loads(content)
            for dep_name, constraint in data.get("dependencies", {}).items():
                add(dep_name, constraint, "DUB dependencies")
        elif name == "haxelib.json":
            data = json.loads(content)
            for dep_name, constraint in data.get("dependencies", {}).items():
                add(dep_name, constraint, "Haxelib dependencies")
        elif name == "fpm.toml":
            data = tomllib.loads(content)
            for dep_name, constraint in data.get("dependencies", {}).items():
                add(dep_name, constraint, "Fortran fpm dependencies")
        elif name == "rebar.config":
            source = content
            block = re.search(r"\{\s*deps\s*,\s*\[(.*?)\]\s*\}", source, re.S)
            if block:
                for dep_name, constraint in re.findall(
                    r"""\{\s*([A-Za-z0-9_]+)\s*,\s*["']([^"']+)["']\s*\}""",
                    block.group(1),
                ):
                    add(dep_name, constraint, "rebar.config deps")
        elif name == "platformio.ini":
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(content)
            for section in parser.sections():
                if parser.has_option(section, "lib_deps"):
                    for line in parser.get(section, "lib_deps").splitlines():
                        item = line.strip()
                        if not item or item.startswith(";"):
                            continue
                        coordinate, separator, version = item.partition("@")
                        add(coordinate.strip(), version.strip() if separator else "unspecified",
                            f"PlatformIO {section} lib_deps")
        elif name.endswith(".rockspec"):
            source = content
            block = re.search(r"dependencies\s*=\s*\{(.*?)\}", source, re.S)
            if block:
                for item in re.findall(r"""["']([^"']+)["']""", block.group(1)):
                    match = re.match(r"([A-Za-z0-9_.-]+)\s*(.*)", item)
                    if match:
                        add(match.group(1), match.group(2).strip() or "unspecified",
                            "Lua rockspec dependencies")
        return sorted(set(declarations), key=lambda item: (item[2], item[0].lower(), item[1]))
