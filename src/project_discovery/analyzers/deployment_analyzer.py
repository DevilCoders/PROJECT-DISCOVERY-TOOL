"""Static container, orchestration, CI/CD and infrastructure manifest analysis."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import Analyzer
from ..models import FileRecord, Finding


class _SafeDeploymentLoader:
    """Construct only YAML scalar/list/map values, including unknown CloudFormation tags."""

    @staticmethod
    def load_all(text: str) -> list[Any]:
        try:
            import yaml
            from yaml.nodes import MappingNode, ScalarNode, SequenceNode
        except ImportError as exc:
            raise RuntimeError("PyYAML is not installed; install the infrastructure extra") from exc

        class Loader(yaml.SafeLoader):
            pass

        def unknown_tag(loader, _tag_suffix, node):
            if isinstance(node, ScalarNode):
                return loader.construct_scalar(node)
            if isinstance(node, SequenceNode):
                return loader.construct_sequence(node)
            if isinstance(node, MappingNode):
                return loader.construct_mapping(node)
            return None

        Loader.add_multi_constructor("!", unknown_tag)
        try:
            return list(yaml.load_all(text, Loader=Loader))
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML: {exc}") from exc


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        result.extend(_mapping(item) for item in _items(pod_spec.get(key)))
    return result


class DeploymentIntelligenceAnalyzer(Analyzer):
    """Inspect deployment manifests without executing commands or contacting services."""

    name = "deployment-intelligence"
    domains = (
        "ci_cd", "containers", "orchestration", "infrastructure_as_code",
        "supply_chain", "networking",
    )

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        name = Path(record.path).name.lower()
        path = record.path.lower()
        return (
            name in {"dockerfile", "containerfile", "jenkinsfile", "chart.yaml",
                     "docker-compose.yml", "docker-compose.yaml", "compose.yml",
                     "compose.yaml", ".gitlab-ci.yml", "azure-pipelines.yml"}
            or name.startswith("dockerfile.")
            or path.startswith(".github/workflows/")
            or record.extension in {".tf", ".tfvars"}
            or record.extension in {".yaml", ".yml"}
            or name.endswith((".template.json", ".template.yaml", ".template.yml"))
            or name == "template.json"
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        if name in {"dockerfile", "containerfile"} or name.startswith("dockerfile."):
            return self._dockerfile(path, record)
        if record.extension in {".tf", ".tfvars"}:
            return self._terraform(path, record)
        if name == "jenkinsfile":
            return self._jenkins(path, record)
        if record.path.lower().startswith(".github/workflows/") or name in {
            ".gitlab-ci.yml", "azure-pipelines.yml",
        }:
            return self._pipeline_yaml(path, record)
        if name == "chart.yaml":
            return self._helm_chart(path, record)
        if record.extension in {".yaml", ".yml"}:
            return self._yaml_deployment(path, record)
        if record.extension == ".json" or name.endswith(".template.json"):
            return self._json_deployment(path, record)
        return []

    def _read_yaml(self, path: Path, record: FileRecord) -> tuple[list[Any] | None, Finding | None]:
        try:
            text = path.read_text(encoding="utf-8")
            return _SafeDeploymentLoader.load_all(text), None
        except (OSError, UnicodeDecodeError, RuntimeError, ValueError) as exc:
            return None, Finding(
                "deployment",
                f"Deployment manifest unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )

    def _dockerfile(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "containers", f"Dockerfile read error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        instructions: dict[str, list[tuple[int, str]]] = {}
        for number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or " " not in stripped:
                continue
            key, value = stripped.split(None, 1)
            instructions.setdefault(key.upper(), []).append((number, value.strip()))
        bases = instructions.get("FROM", [])
        stages = [value.split()[-1] for _, value in bases]
        ports = [value for _, value in instructions.get("EXPOSE", [])]
        users = instructions.get("USER", [])
        evidence = [
            f"{record.path}:{line} ({key})"
            for key, values in instructions.items() for line, _ in values
        ][:100]
        findings = [Finding(
            "containers",
            f"Container build recipe: {record.path}",
            f"Detected {len(bases)} build stage(s), {len(instructions.get('RUN', []))} RUN "
            f"instruction(s), {len(ports)} exposed-port declaration(s), and "
            f"{len(instructions)} instruction types. Base images: "
            + (", ".join(value.split()[0] for _, value in bases) or "not declared"),
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer=self.name,
        )]
        for line, value in bases:
            if ":" not in value.split()[0] or value.split()[0].endswith(":latest"):
                findings.append(Finding(
                    "supply_chain",
                    f"Mutable container base image reference: {record.path}",
                    "A base image uses an implicit or latest tag. Pinning by immutable digest "
                    "improves reproducibility and supply-chain integrity.",
                    confidence="INFERRED",
                    evidence=[f"{record.path}:{line}"],
                    analyzer=self.name,
                ))
        for line, user in users:
            if user.lower() in {"root", "0"}:
                findings.append(Finding(
                    "security",
                    f"Container explicitly runs as root: {record.path}",
                    "A USER instruction selects root. Review whether the workload requires "
                    "this privilege and prefer a dedicated non-root identity.",
                    confidence="INFERRED",
                    evidence=[f"{record.path}:{line}"],
                    analyzer=self.name,
                ))
        return findings

    def _terraform(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "infrastructure", f"Terraform file read error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        blocks = re.findall(
            r'(?m)^\s*(resource|data|module|provider|variable|output)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
            source,
        )
        findings = []
        if blocks:
            counts: dict[str, int] = {}
            for kind, _, _ in blocks:
                counts[kind] = counts.get(kind, 0) + 1
            findings.append(Finding(
                "infrastructure",
                f"Terraform declarations: {record.path}",
                "Detected static HCL block headers: "
                + ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
                + ". HCL expressions and interpolation semantics are not evaluated.",
                confidence="CONFIRMED",
                evidence=[
                    f"{record.path}:{source.count(chr(10), 0, match.start()) + 1} "
                    f"({kind} {first} {second})"
                    for match in re.finditer(
                        r'(?m)^\s*(resource|data|module|provider|variable|output)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
                        source,
                    )
                    for kind, first, second in [match.groups()]
                ][:100],
                analyzer=self.name,
            ))
        risks = (
            ("public_ingress", r'(?is)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"'),
            ("public_database", r'(?is)publicly_accessible\s*=\s*true'),
            ("destructive_force_destroy", r'(?im)force_destroy\s*=\s*true'),
        )
        for label, pattern in risks:
            match = re.search(pattern, source)
            if match:
                line = source.count("\n", 0, match.start()) + 1
                findings.append(Finding(
                    "security",
                    f"Potential Terraform risk: {label}",
                    "A security-sensitive Terraform expression was found. Review resource "
                    "context, variable interpolation, and intended exposure.",
                    confidence="INFERRED",
                    evidence=[f"{record.path}:{line}"],
                    analyzer=self.name,
                ))
        return findings

    def _pipeline_yaml(self, path: Path, record: FileRecord) -> list[Finding]:
        documents, error = self._read_yaml(path, record)
        if error:
            return [error]
        root = _mapping(documents[0] if documents else {})
        if not root:
            return []
        jobs = _mapping(root.get("jobs"))
        steps = []
        for job_name, job_value in jobs.items():
            job = _mapping(job_value)
            for step in _items(job.get("steps")):
                step = _mapping(step)
                if step.get("uses"):
                    steps.append((str(job_name), str(step["uses"])))
        job_names = list(jobs)
        findings = [Finding(
            "ci_cd",
            f"CI/CD workflow: {record.path}",
            f"Detected {len(job_names)} job(s) and {len(steps)} action reference(s). "
            "Shell command bodies and environment values are intentionally excluded.",
            confidence="CONFIRMED",
            evidence=[f"job: {name}" for name in job_names[:100]]
            + [f"action: {job} -> {uses}" for job, uses in steps[:100]],
            analyzer=self.name,
        )]
        permissions = root.get("permissions")
        if permissions == "write-all" or (
            isinstance(permissions, dict) and any(
                str(value).lower() == "write" for value in permissions.values()
            )
        ):
            findings.append(Finding(
                "security",
                f"Broad CI workflow permissions: {record.path}",
                "The workflow declares write permissions. Apply least-privilege permissions "
                "at workflow and job scope.",
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
            ))
        if root.get("on", root.get(True)) == "pull_request_target":
            findings.append(Finding(
                "security",
                f"Privileged pull_request_target workflow: {record.path}",
                "The workflow uses pull_request_target. Review checkout behavior, untrusted "
                "contributions, secrets exposure, and write-capable tokens.",
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
            ))
        for job, uses in steps:
            if "@" in uses and not re.search(r"@[0-9a-fA-F]{40}$", uses):
                findings.append(Finding(
                    "supply_chain",
                    f"Mutable CI action reference: {uses}",
                    "The action is referenced by a tag or branch rather than a full commit SHA.",
                    confidence="INFERRED",
                    evidence=[record.path, f"job: {job}"],
                    analyzer=self.name,
                ))
        return findings

    def _yaml_deployment(self, path: Path, record: FileRecord) -> list[Finding]:
        documents, error = self._read_yaml(path, record)
        if error:
            return [error]
        findings = []
        for index, document in enumerate(documents or []):
            if isinstance(document, list):
                if name_is_ansible(record.path, {"plays": document}):
                    findings.append(Finding(
                        "infrastructure", f"Ansible playbook: {record.path}",
                        f"Detected {len(document)} top-level play item(s). Tasks and module "
                        "arguments are not executed or evaluated.",
                        confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                    ))
                continue
            root = _mapping(document)
            if not root:
                continue
            if isinstance(root.get("services"), dict):
                findings.extend(self._compose(root, record))
            elif root.get("apiVersion") and root.get("kind") and isinstance(root.get("metadata"), dict):
                findings.extend(self._kubernetes(root, record, index))
            elif "Resources" in root and isinstance(root["Resources"], dict):
                findings.extend(self._cloudformation(root, record))
            elif name_is_ansible(record.path, root):
                findings.append(Finding(
                    "infrastructure",
                    f"Ansible playbook: {record.path}",
                    f"Detected {len(_items(root))} top-level play item(s). Tasks and module "
                    "arguments are not executed or evaluated.",
                    confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
                ))
        return findings

    def _compose(self, root: dict[str, Any], record: FileRecord) -> list[Finding]:
        services = _mapping(root.get("services"))
        evidence = []
        risks = []
        for service_name, value in services.items():
            service = _mapping(value)
            if service.get("image"):
                evidence.append(f"service {service_name}: image {service['image']}")
            if service.get("build"):
                evidence.append(f"service {service_name}: build context declared")
            for key in ("ports", "depends_on", "volumes", "networks"):
                if service.get(key):
                    evidence.append(f"service {service_name}: {key} declared")
            if service.get("privileged") is True:
                risks.append((str(service_name), "privileged container"))
            if service.get("network_mode") == "host":
                risks.append((str(service_name), "host network mode"))
        findings = [Finding(
            "containers",
            f"Container compose project: {record.path}",
            f"Detected {len(services)} service(s). Environment variable values are not "
            "copied into reports.",
            confidence="CONFIRMED",
            evidence=evidence[:100] or [record.path],
            analyzer=self.name,
        )]
        findings.extend(Finding(
            "security",
            f"Potential compose risk: {risk}",
            f"Service {service} enables {risk}; review isolation and operational need.",
            confidence="INFERRED",
            evidence=[record.path, f"service: {service}"],
            analyzer=self.name,
        ) for service, risk in risks)
        return findings

    def _kubernetes(self, root: dict[str, Any], record: FileRecord, index: int) -> list[Finding]:
        metadata = _mapping(root.get("metadata"))
        spec = _mapping(root.get("spec"))
        template = _mapping(spec.get("template"))
        pod_spec = _mapping(template.get("spec")) or _mapping(spec.get("jobTemplate"))
        if "spec" in pod_spec:
            pod_spec = _mapping(pod_spec.get("spec"))
        containers = _containers(pod_spec)
        name = str(metadata.get("name", "unnamed"))
        kind = str(root.get("kind"))
        evidence = [record.path, f"document: {index + 1}"]
        for container in containers:
            if container.get("image"):
                evidence.append(f"image: {container['image']}")
            for port in _items(container.get("ports")):
                port = _mapping(port)
                if port.get("containerPort"):
                    evidence.append(f"containerPort: {port['containerPort']}")
        findings = [Finding(
            "orchestration",
            f"Kubernetes {kind}: {name}",
            f"Detected Kubernetes resource {kind}; {len(containers)} container declaration(s). "
            "No cluster connection or manifest application was attempted.",
            confidence="CONFIRMED", evidence=evidence[:100], analyzer=self.name,
        )]
        security_context = _mapping(pod_spec.get("securityContext"))
        for container in containers:
            security_context.update(_mapping(container.get("securityContext")))
        risky = []
        if security_context.get("privileged") is True:
            risky.append("privileged container")
        if security_context.get("allowPrivilegeEscalation") is True:
            risky.append("privilege escalation allowed")
        if security_context.get("runAsNonRoot") is False:
            risky.append("runAsNonRoot disabled")
        if spec.get("hostNetwork") is True or pod_spec.get("hostNetwork") is True:
            risky.append("host network enabled")
        volumes = _items(pod_spec.get("volumes"))
        if any("hostPath" in _mapping(volume) for volume in volumes):
            risky.append("hostPath volume mounted")
        findings.extend(Finding(
            "security",
            f"Potential Kubernetes risk: {risk}",
            "A security-sensitive pod configuration was observed. Validate workload "
            "requirements, namespace policy, and effective admission controls.",
            confidence="INFERRED", evidence=[record.path, f"resource: {name}"],
            analyzer=self.name,
        ) for risk in risky)
        return findings

    def _helm_chart(self, path: Path, record: FileRecord) -> list[Finding]:
        documents, error = self._read_yaml(path, record)
        if error:
            return [error]
        chart = _mapping(documents[0] if documents else {})
        if not chart.get("apiVersion") or not chart.get("name"):
            return []
        dependencies = _items(chart.get("dependencies"))
        return [Finding(
            "orchestration",
            f"Helm chart: {chart['name']}",
            f"Chart API {chart['apiVersion']}; version {chart.get('version', 'unspecified')}; "
            f"{len(dependencies)} declared chart dependency(ies).",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _cloudformation(self, root: dict[str, Any], record: FileRecord) -> list[Finding]:
        resources = _mapping(root.get("Resources"))
        types = sorted({
            str(_mapping(value).get("Type"))
            for value in resources.values() if _mapping(value).get("Type")
        })
        return [Finding(
            "infrastructure",
            f"CloudFormation template: {record.path}",
            f"Detected {len(resources)} resource declaration(s); types: "
            + (", ".join(types[:30]) or "not resolved"),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _json_deployment(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            root = _mapping(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [Finding(
                "infrastructure", f"Deployment JSON parse error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        if "Resources" in root and isinstance(root["Resources"], dict):
            return self._cloudformation(root, record)
        return []

    def _jenkins(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "ci_cd", f"Jenkinsfile read error: {record.path}",
                f"{type(exc).__name__}: {exc}", confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]
        stages = re.findall(r"""(?m)\bstage\s*\(\s*['"]([^'"]+)['"]\s*\)""", source)
        agents = re.findall(r"(?m)^\s*agent\s+([A-Za-z_][A-Za-z0-9_]*)", source)
        return [Finding(
            "ci_cd", f"Jenkins pipeline: {record.path}",
            f"Detected {len(stages)} named stage(s) and {len(agents)} agent declaration(s). "
            "Pipeline Groovy is inventoried statically and never executed.",
            confidence="CONFIRMED",
            evidence=[f"stage: {stage}" for stage in stages[:100]] or [record.path],
            analyzer=self.name,
        )]


def name_is_ansible(path: str, root: dict[str, Any]) -> bool:
    parts = {part.lower() for part in Path(path).parts}
    return (
        bool(parts & {"ansible", "playbooks"})
        or any(isinstance(item, dict) and ("hosts" in item or "tasks" in item)
               for item in _items(root))
    )
