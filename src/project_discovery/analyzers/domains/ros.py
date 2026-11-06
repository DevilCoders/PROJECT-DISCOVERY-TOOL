"""Static ROS 1/ROS 2 package, node and interface discovery."""
from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ...core.safe_parsers import safe_xml_fromstring
from ...core.source_utils import parse_python, read_bytes_bounded, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_ROS_IMPORTS = {"rclpy": "ROS 2 Python", "rospy": "ROS 1 Python"}
_COMMUNICATION = {
    "create_publisher": ("publisher", 1),
    "create_subscription": ("subscription", 1),
    "create_service": ("service_server", 1),
    "create_client": ("service_client", 1),
    "Publisher": ("publisher", 0),
    "Subscriber": ("subscription", 0),
    "Service": ("service_server", 0),
    "ServiceProxy": ("service_client", 0),
    "ActionServer": ("action_server", 2),
    "ActionClient": ("action_client", 2),
}
_CPP_APIS = {
    "create_publisher": "publisher", "create_subscription": "subscription",
    "create_service": "service_server", "create_client": "service_client",
    "advertise": "publisher", "subscribe": "subscription",
    "advertiseService": "service_server", "serviceClient": "service_client",
}
_INTERFACE_EXTENSIONS = {".msg", ".srv", ".action"}
_ROS_PATHS = {"src", "scripts", "nodes", "launch", "msg", "srv", "action", "config", "urdf", "description"}


def _literal_string(node: ast.AST) -> str | None:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


class ROSIntelligenceAnalyzer(Analyzer):
    """Inspect ROS manifests, Python/C++ APIs, launch files and interfaces offline."""

    name = "ros-intelligence"
    domains = ("robotics_ros",)
    languages = ("Python", "C++", "XML", "ROS interfaces")

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        name = Path(record.path).name.lower()
        parts = {part.lower() for part in Path(record.path).parts}
        return (
            name == "package.xml"
            or record.extension in _INTERFACE_EXTENSIONS
            or record.path.endswith((".launch", ".launch.xml", ".launch.py"))
            or (record.extension == ".py" and (
                bool(parts & _ROS_PATHS) or name.endswith(("_node.py", "_ros.py"))
            ))
            or record.extension in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".h"}
            or name == "cmakelists.txt" and bool(parts & {"src", "ros"})
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        if name == "package.xml":
            return self._package(path, record)
        if record.extension in _INTERFACE_EXTENSIONS:
            return self._interface(path, record)
        if record.path.endswith((".launch", ".launch.xml", ".launch.py")):
            return [Finding(
                "robotics", f"ROS launch description: {record.path}",
                "A ROS launch-description file is present. Node composition and runtime "
                "startup behavior require deeper launch-format analysis.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "robotics", f"ROS source read error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        if record.extension == ".py":
            return self._python(source, record)
        if record.extension in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".h"}:
            return self._cpp(source, record)
        if name == "cmakelists.txt":
            matches = re.findall(
                r"(?im)^\s*find_package\s*\(\s*(catkin|ament_cmake|rclcpp|roscpp|rosidl_default_generators)",
                source,
            )
            if matches:
                return [Finding(
                    "robotics", f"ROS build dependencies: {record.path}",
                    "Detected CMake package references: " + ", ".join(sorted(set(matches))),
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                )]
        return []

    def _python(self, source: str, record: FileRecord) -> list[Finding]:
        try:
            tree = parse_python(source, filename=record.path)
        except SyntaxError as exc:
            return [Finding(
                "robotics", f"ROS Python parse error: {record.path}",
                str(exc), confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
            )]
        imports: dict[str, int] = {}
        apis: list[tuple[str, str | None, int]] = []
        nodes: list[tuple[str, int]] = []
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                for alias in item.names:
                    root = alias.name.split(".", 1)[0]
                    if root in _ROS_IMPORTS:
                        imports.setdefault(root, item.lineno)
            elif isinstance(item, ast.ImportFrom) and item.module:
                root = item.module.split(".", 1)[0]
                if root in _ROS_IMPORTS:
                    imports.setdefault(root, item.lineno)
            elif isinstance(item, ast.ClassDef):
                if any(
                    isinstance(base, ast.Name) and base.id == "Node"
                    or isinstance(base, ast.Attribute) and base.attr == "Node"
                    for base in item.bases
                ):
                    nodes.append((item.name, item.lineno))
            elif isinstance(item, ast.Call):
                func = item.func
                method = func.attr if isinstance(func, ast.Attribute) else (
                    func.id if isinstance(func, ast.Name) else ""
                )
                if method in _COMMUNICATION:
                    kind, index = _COMMUNICATION[method]
                    target = _literal_string(item.args[index]) if len(item.args) > index else None
                    apis.append((kind, target, item.lineno))
        if not imports and not apis and not nodes:
            return []
        findings: list[Finding] = []
        if imports:
            findings.append(Finding(
                "robotics", f"ROS framework imports: {record.path}",
                "Detected: " + ", ".join(_ROS_IMPORTS[key] for key in sorted(imports)),
                confidence="CONFIRMED",
                evidence=[f"{record.path}:{line}" for line in imports.values()],
                analyzer=self.name,
            ))
        if nodes:
            findings.append(Finding(
                "robotics", f"ROS node classes: {record.path}",
                f"Detected {len(nodes)} class declaration(s) with a Node base class.",
                confidence="CONFIRMED",
                evidence=[f"{record.path}:{line} ({name})" for name, line in nodes],
                analyzer=self.name,
            ))
        if apis:
            counts: dict[str, int] = {}
            for kind, _, _ in apis:
                counts[kind] = counts.get(kind, 0) + 1
            evidence = [
                f"{record.path}:{line} ({kind}" + (f": {target}" if target else "") + ")"
                for kind, target, line in apis
            ]
            findings.append(Finding(
                "robotics", f"ROS communication API references: {record.path}",
                "Static call-site inventory: "
                + ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
                + ". This is not a runtime topic/service graph.",
                confidence="CONFIRMED", evidence=evidence[:100], analyzer=self.name,
            ))
        return findings

    def _cpp(self, source: str, record: FileRecord) -> list[Finding]:
        includes = [
            (match.group(1), source.count("\n", 0, match.start()) + 1)
            for match in re.finditer(
                r'#\s*include\s*[<"]([^>"]*(?:rclcpp|ros/ros\.h)[^>"]*)[>"]',
                source,
            )
        ]
        calls: list[tuple[str, int]] = []
        for method, kind in _CPP_APIS.items():
            calls.extend(
                (kind, source.count("\n", 0, match.start()) + 1)
                for match in re.finditer(r"\b" + re.escape(method) + r"\s*<", source)
            )
        findings: list[Finding] = []
        if includes:
            findings.append(Finding(
                "robotics", f"ROS C++ includes: {record.path}",
                "Detected ROS C++ client-library include directives.",
                confidence="CONFIRMED",
                evidence=[f"{record.path}:{line} ({name})" for name, line in includes],
                analyzer=self.name,
            ))
        if calls:
            findings.append(Finding(
                "robotics", f"ROS C++ communication API references: {record.path}",
                f"Detected {len(calls)} statically recognizable communication call site(s).",
                confidence="CONFIRMED",
                evidence=[f"{record.path}:{line} ({kind})" for kind, line in calls[:100]],
                analyzer=self.name,
            ))
        return findings

    def _package(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            root = safe_xml_fromstring(read_bytes_bounded(
                path, 16 * 1024 * 1024, expected_identity=record.analysis_identity,
            ))
        except (OSError, ValueError, ET.ParseError) as exc:
            return [Finding(
                "robotics", f"ROS package manifest parse error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        values: dict[str, list[str]] = {}
        for child in root:
            tag = child.tag.rsplit("}", 1)[-1]
            text = (child.text or "").strip()
            if text:
                values.setdefault(tag, []).append(text)
        package_name = (values.get("name") or ["unknown"])[0]
        deps = sorted({
            dep for key in (
                "depend", "build_depend", "buildtool_depend", "exec_depend",
                "run_depend", "test_depend",
            ) for dep in values.get(key, [])
        })
        ecosystems = []
        if set(deps) & {"rclcpp", "rclpy", "ament_cmake", "ament_python"}:
            ecosystems.append("ROS 2")
        if set(deps) & {"roscpp", "rospy", "catkin"}:
            ecosystems.append("ROS 1")
        return [Finding(
            "robotics", f"ROS package: {package_name}",
            "Package manifest parsed; ecosystem: "
            + (", ".join(ecosystems) if ecosystems else "undetermined")
            + f"; {len(deps)} declared dependencies.",
            confidence="CONFIRMED",
            evidence=[record.path] + [f"dependency: {dep}" for dep in deps[:100]],
            analyzer=self.name,
        )]

    def _interface(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            lines = read_text_bounded(
                path, 4 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            ).splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "robotics", f"ROS interface read error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        content = [
            line.strip() for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        ]
        separators = sum(line == "---" for line in content)
        return [Finding(
            "robotics", f"ROS {record.extension[1:].upper()} interface: {record.path}",
            f"Detected {len(content)} non-comment definition lines and {separators} "
            "section separator(s). Field types are not semantically resolved.",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]
