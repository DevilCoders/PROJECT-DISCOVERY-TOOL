"""Static container, orchestration, CI/CD and infrastructure manifest analysis."""
from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Any

from ...core.limits import AnalyzerLimits
from ...core.safe_parsers import safe_yaml_load_all
from ...core.source_utils import LineIndex, describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer


class _SafeDeploymentLoader:
    """Construct only YAML scalar/list/map values, including unknown CloudFormation tags."""

    @staticmethod
    def load_all(text: str) -> list[Any]:
        try:
            import yaml  # noqa: F401 - availability check for the optional extra
        except ImportError as exc:
            raise RuntimeError("PyYAML is not installed; install the infrastructure extra") from exc
        # Alias expansion is bounded before Kubernetes/Compose walkers traverse the data.
        return safe_yaml_load_all(text, allow_unknown_tags=True)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _pod_spec(kind: str, spec: dict[str, Any]) -> dict[str, Any]:
    """A workload's pod spec: a Pod's own spec, a CronJob's job template's pod template, and
    the pod template of every other workload kind."""
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = _mapping(_mapping(spec.get("jobTemplate")).get("spec"))
        return _mapping(_mapping(job.get("template")).get("spec"))
    return _mapping(_mapping(spec.get("template")).get("spec"))


def _workflow_triggers(root: dict[str, Any]) -> set[str]:
    """Event names of a GitHub workflow's ``on`` (a string, a list or a mapping).

    YAML 1.1 reads the key ``on`` as True, so both keys are tried.
    """
    value = root.get("on", root.get(True))
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, dict):
        return {str(key) for key in value}
    return set()


def _writes(permissions: Any) -> bool:
    return permissions == "write-all" or (
        isinstance(permissions, dict) and any(str(value).lower() == "write" for value in permissions.values())
    )


# Top-level GitLab CI keys that configure the pipeline rather than name a job.
_GITLAB_RESERVED = frozenset({
    "stages", "variables", "default", "include", "workflow", "image", "services", "before_script",
    "after_script", "cache", "types",
})


def _gitlab_jobs(root: dict[str, Any]) -> list[str]:
    """Jobs are top-level mappings with a script, trigger or stage; hidden (.name) keys are templates."""
    return [
        str(name) for name, value in root.items()
        if isinstance(name, str) and not name.startswith(".") and name not in _GITLAB_RESERVED
        and isinstance(value, dict) and ({"script", "trigger", "stage", "extends", "needs", "run"} & set(value))
    ]


def _azure_jobs(root: dict[str, Any]) -> list[str]:
    """Jobs of stages[].jobs[], a top-level jobs list, or the single implicit job of steps."""
    jobs = []
    for stage in _items(root.get("stages")):
        jobs.extend(_items(_mapping(stage).get("jobs")))
    jobs.extend(_items(root.get("jobs")))
    names = [
        str(_mapping(job).get("job") or _mapping(job).get("deployment") or _mapping(job).get("template") or "job")
        for job in jobs if isinstance(job, dict)
    ]
    if not names and root.get("steps"):
        names = ["(implicit job)"]
    return names


def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Dockerfile instructions with backslash continuations joined, by starting line."""
    logical: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or (not pending and not stripped):
            continue
        if not pending:
            start = number
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        logical.append((start, pending + stripped))
        pending = ""
    if pending:
        logical.append((start, pending))
    return logical


def _from_image(value: str) -> tuple[str, str | None]:
    """(image, stage name) of a FROM instruction; --platform and other flags are skipped."""
    tokens = [token for token in value.split() if not token.startswith("--")]
    if not tokens:
        return "", None
    stage = tokens[2] if len(tokens) >= 3 and tokens[1].lower() == "as" else None
    return tokens[0], stage


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        result.extend(_mapping(item) for item in _items(pod_spec.get(key)))
    return result


_TERRAFORM_BLOCK = re.compile(
    r'(?m)^[ \t]*(resource|data|module|provider|variable|output)\s+"([^"\n]+)"(?:\s+"([^"\n]+)")?\s*\{'
)
_CIDR_BLOCKS = re.compile(r"(?i)cidr_blocks\s*=\s*\[")


def _public_ingress(source: str):
    """The first ``cidr_blocks = [ ... "0.0.0.0/0" ... ]`` (lists may span lines), in linear time.

    ``cidr_blocks = \\[[^\\]]*"0.0.0.0/0"`` rescanned to the next ``]`` (or the end of the
    file) from every list that never closes, which is quadratic.
    """
    position = 0
    while (head := _CIDR_BLOCKS.search(source, position)) is not None:
        close = source.find("]", head.end())
        stop = len(source) if close == -1 else close
        if source.find('"0.0.0.0/0"', head.end(), stop) != -1 or source.find('"::/0"', head.end(), stop) != -1:
            return head
        position = stop + 1
    return None


_MAX_DEPLOYMENT_BYTES = 16 * 1024 * 1024


class DeploymentIntelligenceAnalyzer(Analyzer):
    """Inspect deployment manifests without executing commands or contacting services."""

    name = "deployment-intelligence"
    limits = AnalyzerLimits(
        _MAX_DEPLOYMENT_BYTES,
        "whole",
        outcome="UNKNOWN finding on oversize, growth or read failure",
    )
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
            text = read_text_bounded(
                path, _MAX_DEPLOYMENT_BYTES,
                expected_identity=record.analysis_identity,
            )
            return _SafeDeploymentLoader.load_all(text), None
        except Exception as exc:
            return None, Finding(
                "deployment",
                f"Deployment manifest unavailable: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
                evidence=[record.path],
                analyzer=self.name,
            )

    def _dockerfile(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            lines = read_text_bounded(
                path, _MAX_DEPLOYMENT_BYTES,
                expected_identity=record.analysis_identity,
            ).splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "containers", f"Dockerfile read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        instructions: dict[str, list[tuple[int, str]]] = {}
        for number, text in _logical_lines(lines):
            if " " not in text:
                continue
            key, value = text.split(None, 1)
            instructions.setdefault(key.upper(), []).append((number, value.strip()))
        bases = instructions.get("FROM", [])
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
            + (", ".join(_from_image(value)[0] for _, value in bases) or "not declared"),
            confidence="CONFIRMED",
            evidence=evidence,
            analyzer=self.name,
        )]
        stages: set[str] = set()
        for line, value in bases:
            image, stage = _from_image(value)
            # Earlier build stages, scratch and ARG-supplied images are not registry tags.
            mutable = bool(image) and image.lower() not in stages and image != "scratch" and "$" not in image and (
                ":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")
            ) and "@" not in image
            if stage:
                stages.add(stage.lower())
            if mutable:
                findings.append(Finding(
                    "supply_chain",
                    f"Mutable container base image reference: {record.path}",
                    "A base image uses an implicit or latest tag. Pinning by immutable digest "
                    "improves reproducibility and supply-chain integrity.",
                    confidence="INFERRED",
                    evidence=[f"{record.path}:{line}"],
                    analyzer=self.name,
                ))
        for entry in users:
            if not isinstance(entry, (tuple, list)) or len(entry) < 2:
                continue
            line, user = entry[0], entry[1]
            if str(user).lower() in {"root", "0"}:
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
            source = read_text_bounded(
                path, _MAX_DEPLOYMENT_BYTES,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "infrastructure", f"Terraform file read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        blocks = re.findall(
            r'(?m)^[ \t]*(resource|data|module|provider|variable|output)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
            source,
        )
        findings = []
        lines = LineIndex(source)
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
                    f"{record.path}:{lines.line(match.start(1))} ({kind} {first} {second})"
                    for match in itertools.islice(_TERRAFORM_BLOCK.finditer(source), 100)
                    for kind, first, second in [match.groups()]
                ],
                analyzer=self.name,
            ))
        risks = (
            ("public_ingress", _public_ingress(source)),
            ("public_database", re.search(r'(?is)publicly_accessible\s*=\s*true', source)),
            ("destructive_force_destroy", re.search(r'(?im)force_destroy\s*=\s*true', source)),
        )
        for label, match in risks:
            if match:
                line = lines.line(match.start())
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
        name = Path(record.path).name.lower()
        github = record.path.lower().replace("\\", "/").startswith(".github/workflows/")
        jobs = _mapping(root.get("jobs")) if github else {}
        steps = []
        for job_name, job_value in jobs.items():
            job = _mapping(job_value)
            for step in _items(job.get("steps")):
                step = _mapping(step)
                if step.get("uses"):
                    steps.append((str(job_name), str(step["uses"])))
        if name == ".gitlab-ci.yml":
            job_names = _gitlab_jobs(root)
        elif name == "azure-pipelines.yml":
            job_names = _azure_jobs(root)
        else:
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
        if github and any(_writes(scope) for scope in (
            root.get("permissions"), *(_mapping(job).get("permissions") for job in jobs.values())
        )):
            findings.append(Finding(
                "security",
                f"Broad CI workflow permissions: {record.path}",
                "The workflow declares write permissions. Apply least-privilege permissions "
                "at workflow and job scope.",
                confidence="INFERRED",
                evidence=[record.path],
                analyzer=self.name,
            ))
        if github and "pull_request_target" in _workflow_triggers(root):
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
        kind = str(root.get("kind"))
        pod_spec = _pod_spec(kind, spec)
        containers = _containers(pod_spec)
        name = str(metadata.get("name", "unnamed"))
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
        # Each container's effective context (pod defaults, container overrides): a later
        # unprivileged container no longer hides a privileged one.
        pod_context = _mapping(pod_spec.get("securityContext"))
        contexts = [
            {**pod_context, **_mapping(container.get("securityContext"))} for container in containers
        ] or [pod_context]
        risky = []
        if any(context.get("privileged") is True for context in contexts):
            risky.append("privileged container")
        if any(context.get("allowPrivilegeEscalation") is True for context in contexts):
            risky.append("privilege escalation allowed")
        if any(context.get("runAsNonRoot") is False for context in contexts):
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
            root = _mapping(json.loads(read_text_bounded(
                path, _MAX_DEPLOYMENT_BYTES,
                expected_identity=record.analysis_identity,
            )))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [Finding(
                "infrastructure", f"Deployment JSON parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if "Resources" in root and isinstance(root["Resources"], dict):
            return self._cloudformation(root, record)
        return []

    def _jenkins(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, _MAX_DEPLOYMENT_BYTES,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "ci_cd", f"Jenkinsfile read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        stages = re.findall(r"""(?m)\bstage\s*\(\s*['"]([^'"]+)['"]\s*\)""", source)
        agents = re.findall(r"(?m)^[ \t]*agent\s+([A-Za-z_][A-Za-z0-9_]*)", source)
        return [Finding(
            "ci_cd", f"Jenkins pipeline: {record.path}",
            f"Detected {len(stages)} named stage(s) and {len(agents)} agent declaration(s). "
            "Pipeline Groovy is inventoried statically and never executed.",
            confidence="CONFIRMED",
            evidence=[f"stage: {stage}" for stage in stages[:100]] or [record.path],
            analyzer=self.name,
        )]


def name_is_ansible(path: str, root: Any) -> bool:
    """Whether a YAML document is an Ansible playbook: a list of plays.

    A play is a mapping with ``hosts`` (or a playbook import). A mapping document is never a
    playbook, so configuration whose values hold ``hosts`` (filebeat.yml) is not one.
    """
    plays = root.get("plays") if isinstance(root, dict) and set(root) == {"plays"} else root
    if not isinstance(plays, list) or not plays or not all(isinstance(item, dict) for item in plays):
        return False
    return any({"hosts", "import_playbook", "ansible.builtin.import_playbook"} & set(item) for item in plays)
