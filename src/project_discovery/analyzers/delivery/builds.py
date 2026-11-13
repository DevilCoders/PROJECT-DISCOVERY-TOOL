"""Static build-system and CI manifest inventory."""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from ...core.safe_parsers import safe_xml_fromstring
from ...core.source_utils import SourceBudgetExceeded, describe_error, read_text_bounded, redact_source_excerpt
from ...models import FileRecord, Finding
from ..base import Analyzer

_MAX_BUILD_MANIFEST_BYTES = 16 * 1024 * 1024


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
    ".cmake", ".gradle", ".mk", ".sbt", ".bzl", ".ninja", ".pro", ".pri",
    ".csproj", ".fsproj", ".vbproj", ".sln", ".slnx", ".pbxproj",
    ".am", ".ac",
}
_MAKE_TARGET = re.compile(r"(?m)^([A-Za-z0-9_.-]+)\s*:(?![=])")
_CMAKE_TARGET = re.compile(r"(?i)\b(add_executable|add_library)\s*\(\s*([A-Za-z0-9_.-]+)")
_DOCKER_INSTRUCTION = re.compile(r"(?mi)^[ \t]*(FROM|RUN|COPY|ADD|WORKDIR|USER|EXPOSE|ENTRYPOINT|CMD)\b")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# PyYAML is optional (the infrastructure extra); without it, jobs are read line by line.
_NO_YAML = "jobs read line by line: PyYAML (the infrastructure extra) is not installed"
# A key starts at a word boundary, so a search inside a long identifier run fails at once.
_MAPPING_KEY = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]++)[ \t]*+:(?:[ \t]|$)")


def _mapping_keys(content: str, parent: str) -> list[str]:
    """Keys directly below the top-level ``parent:`` mapping, read line by line."""
    keys: list[str] = []
    inside, indent = False, None
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[0].isspace():
            inside = stripped.split("#", 1)[0].rstrip() == f"{parent}:"
            indent = None
            continue
        if inside:
            width = len(line) - len(line.lstrip())
            indent = width if indent is None else indent
            key = _MAPPING_KEY.match(stripped)
            if width == indent and key:
                keys.append(key.group(1))
    return keys


def _workflow_jobs(content: str, provider: str) -> list[str] | None:
    """Job names of a GitHub, GitLab or Azure pipeline: empty when the YAML does not parse,
    None when PyYAML is not installed (the caller then reads the jobs line by line)."""
    try:
        import yaml  # noqa: F401 - availability check for the optional extra
    except ImportError:
        return None
    from ...core.safe_parsers import safe_yaml_load
    from .deployment import _azure_jobs, _gitlab_jobs

    try:
        data = safe_yaml_load(content, allow_unknown_tags=True)  # GitLab's !reference
    except Exception:  # noqa: BLE001 - deployment-intelligence reports YAML parse failures
        return []
    if not isinstance(data, dict):
        return []
    if provider == "gitlab":
        return _gitlab_jobs(data)
    if provider == "azure":
        return _azure_jobs(data)
    jobs = data.get("jobs")
    return [str(name) for name in jobs] if isinstance(jobs, dict) else []


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
        if record.size_bytes > _MAX_BUILD_MANIFEST_BYTES:
            return [Finding(
                "build",
                f"Build manifest resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the build analyzer's "
                f"{_MAX_BUILD_MANIFEST_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            content = read_text_bounded(
                path, _MAX_BUILD_MANIFEST_BYTES,
                expected_identity=record.analysis_identity,
            )
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
                data = data if isinstance(data, dict) else {}  # valid JSON need not be an object
                scripts = data.get("scripts")
                targets = [f"script: {key}" for key in scripts] if isinstance(scripts, dict) else []
                metadata.extend(
                    f"package: {data[key]}" for key in ("name", "version") if isinstance(data.get(key), str)
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
                    r"(?im)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*name\s*=\s*['\"]([^'\"]+)['\"]",
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
                root = safe_xml_fromstring(content)
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
                root = safe_xml_fromstring(content)
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
                        r"(?m)^[ \t]*(TARGET|TEMPLATE)\s*=\s*(.+?)\s*$", content
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
                # Jobs are the keys of the jobs mapping, not every indented key (triggers).
                jobs = _workflow_jobs(content, "github")
                if jobs is None:
                    jobs = _mapping_keys(content, "jobs")
                    metadata.append(_NO_YAML)
                targets = [f"job: {job}" for job in jobs]
                metadata.append("GitHub Actions workflow")
            elif name in {
                ".gitlab-ci.yml", "azure-pipelines.yml", "azure-pipelines.yaml",
                "bitbucket-pipelines.yml", ".travis.yml", "appveyor.yml",
            }:
                ci_jobs = None
                if name in {".gitlab-ci.yml", "azure-pipelines.yml", "azure-pipelines.yaml"}:
                    ci_jobs = _workflow_jobs(content, "gitlab" if name == ".gitlab-ci.yml" else "azure")
                    if ci_jobs is None:
                        metadata.append(_NO_YAML)
                if ci_jobs is None:
                    ci_jobs = re.findall(
                        r"(?m)^[ \t]*-\s*job:\s*([A-Za-z0-9_.-]+)\s*$", content
                    )
                    ci_jobs.extend(re.findall(
                        r"(?m)^([A-Za-z0-9_.-]+):\s*$", content
                    ))
                    # Hidden keys (.template) are GitLab templates, not jobs.
                    ci_jobs = [job for job in ci_jobs if not job.startswith(".")]
                targets = [
                    f"job: {job}" for job in dict.fromkeys(ci_jobs)
                    if job not in {
                        "name", "on", "permissions", "env", "defaults", "stages",
                        "variables", "image", "services", "cache", "before_script",
                        "after_script", "workflow", "jobs", "steps", "trigger", "default", "include",
                    }
                ]
                metadata.append("CI pipeline manifest")
            elif name in {"taskfile.yml", "taskfile.yaml"}:
                targets = [
                    f"task: {task}" for task in re.findall(
                        r"(?m)^[ \t]{2}([A-Za-z0-9_.-]+):\s*(?:#.*)?$", content
                    )
                ]
                metadata.append("Taskfile task runner manifest")
            elif name in {"makefile.am", "configure.ac", "configure.in"}:
                targets = [
                    f"build macro: {macro}" for macro in re.findall(
                        r"(?m)^[ \t]*(AC_INIT|AM_INIT_AUTOMAKE|AC_CONFIG_FILES|AC_PROG_[A-Z_]+)\s*\(",
                        content,
                    )
                ]
                metadata.append("GNU Autotools manifest")
            elif name == "pom.xml":
                root = safe_xml_fromstring(content)
                metadata.extend(
                    f"{_local_name(element.tag)}: {element.text.strip()}"
                    for element in root.iter()
                    if _local_name(element.tag) in {"groupId", "artifactId", "version"}
                    and element.text and element.text.strip()
                )
                targets = [
                    f"plugin: {artifact.text.strip()}"
                    for element in root.iter() if _local_name(element.tag) == "plugin"
                    for artifact in element if _local_name(artifact.tag) == "artifactId"
                    and artifact.text and artifact.text.strip()
                ]
            elif name in {"dockerfile", "containerfile"}:
                targets = [f"instruction: {kind.upper()}" for kind in _DOCKER_INSTRUCTION.findall(content)]
            elif record.extension in {".gradle", ".sbt"} or name.startswith("build.gradle"):
                task_patterns = (
                    r"""(?m)\btasks?\s*\.\s*(?:register|create|named)\s*(?:<[^>]+>\s*)?\(\s*['"]([^'"]+)['"]""",
                    r"""(?m)\btask\s*\(\s*['"]([^'"]+)['"]""",
                    r"(?m)^[ \t]*task\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                )
                task_names = []
                for pattern in task_patterns:
                    task_names.extend(re.findall(pattern, content))
                targets = [f"task: {task}" for task in dict.fromkeys(task_names)]
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
                            r"(?m)^[ \t]*(?:gem|task)\s+['\"]([^'\"]+)", content
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
        except SourceBudgetExceeded as exc:
            return [Finding(
                "build",
                f"Build manifest resource limit: {record.path}",
                redact_source_excerpt(str(exc)),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]
        except (
            OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError,
            ET.ParseError, ValueError, RecursionError, MemoryError,
        ) as exc:
            return [Finding(
                "build",
                f"Build manifest parse error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
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
