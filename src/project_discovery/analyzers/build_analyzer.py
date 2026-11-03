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
    "makefile", "gnumakefile", "cmakelists.txt", "meson.build",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "settings.gradle.kts", "package.json", "pyproject.toml", "cargo.toml",
    "go.mod", "build.sbt", "justfile", "taskfile.yml", "taskfile.yaml",
    "dockerfile", "containerfile", ".gitlab-ci.yml",
}
_BUILD_EXTENSIONS = {".gradle", ".mk", ".sbt"}
_MAKE_TARGET = re.compile(r"(?m)^([A-Za-z0-9_.-]+)\s*:(?![=])")
_CMAKE_TARGET = re.compile(r"(?i)\b(add_executable|add_library)\s*\(\s*([A-Za-z0-9_.-]+)")
_DOCKER_INSTRUCTION = re.compile(r"(?mi)^\s*(FROM|RUN|COPY|ADD|WORKDIR|USER|EXPOSE|ENTRYPOINT|CMD)\b")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class BuildManifestAnalyzer(Analyzer):
    """Inventory build targets, scripts and CI workflow files."""

    name = "build-manifests"
    domains = ("build_systems",)

    def supports(self, record: FileRecord) -> bool:
        name = Path(record.path).name.lower()
        return record.error is None and (
            name in _BUILD_NAMES
            or record.extension in _BUILD_EXTENSIONS
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
