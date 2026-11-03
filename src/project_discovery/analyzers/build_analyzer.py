"""Static build-system and CI manifest inventory."""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


_BUILD_NAMES = {
    "makefile", "gnumakefile", "cmakelists.txt", "cmakepresets.json",
    "meson.build", "meson.options", "meson_options.txt",
    "pom.xml", "build.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts", "gradle.properties",
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "tox.ini",
    "pipfile", "cargo.toml", "go.mod", "build.sbt", "justfile",
    "taskfile.yml", "taskfile.yaml", "dockerfile", "containerfile",
    ".gitlab-ci.yml", "build", "build.bazel", "workspace",
    "workspace.bazel", "module.bazel", "bazelisk.rc", "buck",
    ".buckconfig", "sconstruct", "sconscript", "package.swift",
    "jenkinsfile", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", ".travis.yml", "appveyor.yml",
    "build.ninja", "build.zig", "build.zig.zon", "makefile.am",
    "configure.ac", "configure.in", "rakefile", "gemfile", "mix.exs",
    "composer.json", "requirements.txt", "procfile", "earthfile",
    "tiltfile", "brewfile", "podfile", "cartfile", "fastfile",
    "appfile", "vcpkg.json", "conanfile.py", "conanfile.txt",
    "pants", "pants.toml", "gradlew", "mvnw", "modulefile",
}
_BUILD_EXTENSIONS = {
    ".gradle", ".mk", ".sbt", ".bzl", ".ninja", ".pro", ".pri",
    ".csproj", ".fsproj", ".vbproj", ".sln", ".slnx", ".pbxproj",
    ".am", ".ac",
}
_MAKE_TARGET = re.compile(r"(?m)^([A-Za-z0-9_.-]+)\s*:(?![=])")
_CMAKE_TARGET = re.compile(r"(?i)\b(add_executable|add_library)\s*\(\s*([A-Za-z0-9_.-]+)")
_DOCKER_INSTRUCTION = re.compile(r"(?mi)^\s*(FROM|RUN|COPY|ADD|WORKDIR|USER|EXPOSE|ENTRYPOINT|CMD)\b")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class BuildManifestAnalyzer(Analyzer):
    """Inventory build targets, scripts and CI workflow files."""

    name = "build-manifests"
    domains = ("build_systems", "ci_cd")

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            name in _BUILD_NAMES
            or record.extension in _BUILD_EXTENSIONS
            or (name.startswith("requirements") and record.extension == ".txt")
            or record.path.startswith(".github/workflows/")
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        try:
            content = path.read_text(encoding="utf-8")
            targets: list[str] = []
            metadata: list[str] = []
            if name in {"makefile", "gnumakefile", "justfile"} or record.extension == ".mk":
                targets = [
                    target for target in _MAKE_TARGET.findall(content)
                    if target not in {".PHONY", ".SUFFIXES", ".DEFAULT"}
                ]
            elif name == "cmakelists.txt" or record.extension == ".cmake":
                targets = [f"{kind}: {target}" for kind, target in _CMAKE_TARGET.findall(content)]
            elif name == "package.json":
                data = json.loads(content)
                scripts = data.get("scripts", {})
                targets = [f"script: {key}" for key in scripts]
                metadata.extend(
                    f"package: {data[key]}" for key in ("name", "version") if data.get(key)
                )
            elif name == "pyproject.toml":
                data = tomllib.loads(content)
                build = data.get("build-system", {})
                project = data.get("project", {})
                if build.get("build-backend"):
                    metadata.append(f"build-backend: {build['build-backend']}")
                targets = [f"script: {key}" for key in project.get("scripts", {})]
            elif name == "cargo.toml":
                data = tomllib.loads(content)
                package = data.get("package", {})
                metadata.extend(
                    f"package: {package[key]}" for key in ("name", "version") if package.get(key)
                )
                targets.extend(
                    f"target: {item.get('name', 'unnamed')}"
                    for item in data.get("bin", []) + data.get("example", [])
                )
            elif name in {
                "build", "build.bazel", "workspace", "workspace.bazel",
                "module.bazel", "buck",
            } or record.extension == ".bzl":
                rules = re.findall(
                    r"(?im)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*name\s*=\s*['\"]([^'\"]+)['\"]",
                    content,
                )
                targets = [f"{kind}: {target}" for kind, target in rules]
                metadata.append("Bazel/Buck rule inventory; labels are not resolved.")
            elif name in {"sconstruct", "sconscript"}:
                targets = [
                    f"target: {target.strip()}" for target in re.findall(
                        r"\b(?:Program|Library|SharedLibrary|StaticLibrary|Alias|Command)\s*\(\s*['\"]?([^,'\")]+)",
                        content,
                    )
                ]
                metadata.append("SCons build script")
            elif name == "build.xml":
                root = ET.fromstring(content)
                project_name = root.attrib.get("name")
                if project_name:
                    metadata.append(f"project: {project_name}")
                targets = [
                    f"target: {element.attrib['name']}"
                    for element in root.iter()
                    if _local_name(element.tag) == "target" and element.attrib.get("name")
                ]
            elif name == "package.swift":
                targets = [
                    f"target: {target}" for target in re.findall(
                        r"\.(?:executableTarget|target|testTarget|binaryTarget|plugin|macro)\s*\(\s*name\s*:\s*['\"]([^'\"]+)",
                        content,
                    )
                ]
                metadata.append("Swift Package Manager manifest")
            elif record.extension in {".csproj", ".fsproj", ".vbproj", ".slnx"}:
                root = ET.fromstring(content)
                for element in root.iter():
                    tag = _local_name(element.tag)
                    if tag in {"TargetFramework", "TargetFrameworks", "AssemblyName", "OutputType"}:
                        if element.text and element.text.strip():
                            metadata.append(f"{tag}: {element.text.strip()}")
                    if tag in {"ProjectReference", "PackageReference"}:
                        include = element.attrib.get("Include") or element.attrib.get("Update")
                        if include:
                            targets.append(f"{tag}: {include}")
                metadata.append(".NET project manifest")
            elif record.extension == ".sln":
                targets = [
                    f"project: {project}" for project in re.findall(
                        r'(?m)^Project\("[^"]+"\)\s*=\s*"([^"]+)"', content
                    )
                ]
                metadata.append("Visual Studio solution")
            elif name == "build.ninja" or record.extension == ".ninja":
                targets = [
                    f"target: {target}" for target in re.findall(
                        r"(?m)^build\s+([^:\s]+)\s*:", content
                    )
                ]
                metadata.append("Ninja build graph declarations")
            elif record.extension in {".pro", ".pri"}:
                targets = [
                    f"{key.lower()}: {value.strip()}" for key, value in re.findall(
                        r"(?m)^\s*(TARGET|TEMPLATE)\s*=\s*(.+?)\s*$", content
                    )
                ]
                metadata.append("QMake project manifest")
            elif name == "jenkinsfile":
                targets = [
                    f"stage: {stage}" for stage in re.findall(
                        r"\bstage\s*\(\s*['\"]([^'\"]+)", content
                    )
                ]
                metadata.append("Jenkins pipeline script")
            elif record.path.startswith(".github/workflows/"):
                targets = [
                    f"job: {job}" for job in re.findall(
                        r"(?m)^\s{2}([A-Za-z0-9_.-]+):\s*(?:#.*)?$", content
                    )
                ]
                metadata.append("GitHub Actions workflow")
            elif name in {
                ".gitlab-ci.yml", "azure-pipelines.yml", "azure-pipelines.yaml",
                "bitbucket-pipelines.yml", ".travis.yml", "appveyor.yml",
            }:
                ci_jobs = re.findall(
                    r"(?m)^\s*-\s*job:\s*([A-Za-z0-9_.-]+)\s*$", content
                )
                ci_jobs.extend(re.findall(
                    r"(?m)^([A-Za-z0-9_.-]+):\s*$", content
                ))
                targets = [
                    f"job: {job}" for job in dict.fromkeys(ci_jobs)
                    if job not in {
                        "name", "on", "permissions", "env", "defaults", "stages",
                        "variables", "image", "services", "cache", "before_script",
                        "after_script", "workflow", "jobs", "steps", "trigger",
                    }
                ]
                metadata.append("CI pipeline manifest")
            elif name in {"taskfile.yml", "taskfile.yaml"}:
                targets = [
                    f"task: {task}" for task in re.findall(
                        r"(?m)^\s{2}([A-Za-z0-9_.-]+):\s*(?:#.*)?$", content
                    )
                ]
                metadata.append("Taskfile task runner manifest")
            elif name in {"makefile.am", "configure.ac", "configure.in"}:
                targets = [
                    f"build macro: {macro}" for macro in re.findall(
                        r"(?m)^\s*(AC_INIT|AM_INIT_AUTOMAKE|AC_CONFIG_FILES|AC_PROG_[A-Z_]+)\s*\(",
                        content,
                    )
                ]
                metadata.append("GNU Autotools manifest")
            elif name == "pom.xml":
                root = ET.fromstring(content)
                metadata.extend(
                    f"{_local_name(element.tag)}: {element.text.strip()}"
                    for element in root.iter()
                    if _local_name(element.tag) in {"groupId", "artifactId", "version"}
                    and element.text and element.text.strip()
                )
                targets = [
                    _local_name(element.tag) for element in root.iter()
                    if _local_name(element.tag) in {"plugin", "execution"}
                ]
            elif name in {"dockerfile", "containerfile"}:
                targets = [f"instruction: {kind.upper()}" for kind in _DOCKER_INSTRUCTION.findall(content)]
            elif record.path.startswith(".github/workflows/") or name == ".gitlab-ci.yml":
                targets = [
                    f"job: {job}" for job in re.findall(
                        r"(?m)^([A-Za-z0-9_.-]+):\s*$", content
                    )
                    if job not in {"name", "on", "permissions", "env", "defaults"}
                ]
                metadata.append("CI workflow manifest")
            elif record.extension in {".gradle", ".sbt"} or name.startswith("build.gradle"):
                targets = [
                    f"task: {task}" for task in re.findall(
                        r"(?m)\b(?:task|register)\s*\(?\s*['\"]?([A-Za-z0-9_.-]+)", content
                    )
                ]
            elif name in {
                "setup.py", "setup.cfg", "tox.ini", "pipfile", "rakefile",
                "gemfile", "mix.exs", "composer.json", "requirements.txt",
                "procfile", "earthfile", "tiltfile", "brewfile", "podfile",
                "cartfile", "fastfile", "appfile", "vcpkg.json",
                "conanfile.py", "conanfile.txt", "pants", "pants.toml",
                "gradlew", "mvnw", "modulefile",
            } or (name.startswith("requirements") and record.extension == ".txt"):
                metadata.append(f"recognized build ecosystem manifest: {name}")
                if name in {"gemfile", "rakefile"}:
                    targets = [
                        f"dependency/task: {item}" for item in re.findall(
                            r"(?m)^\s*(?:gem|task)\s+['\"]([^'\"]+)", content
                        )
                    ]
                elif name == "mix.exs":
                    targets = [
                        f"Elixir task: {item}" for item in re.findall(
                            r':([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*"[^"]+"',
                            content,
                        )
                    ]
            else:
                metadata.append("recognized build manifest; specialized extraction pending")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, ET.ParseError) as exc:
            return [Finding(
                "build",
                f"Build manifest parse error: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        return [Finding(
            "build",
            f"Build manifest: {record.path}",
            f"Detected {len(targets)} build targets/jobs and {len(metadata)} metadata items. "
            + ("; ".join(metadata[:20]) if metadata else "No additional metadata extracted."),
            confidence="CONFIRMED",
            evidence=[record.path] + targets[:100],
            analyzer=self.name,
        )]
