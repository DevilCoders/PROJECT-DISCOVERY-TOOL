"""Static container, orchestration, CI/CD and infrastructure manifest analysis."""
from __future__ import annotations

import itertools
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from ...core.limits import AnalyzerLimits
from ...core.safe_parsers import safe_yaml_load_all
from ...core.source_utils import LineIndex, describe_error, read_text_bounded
from ...intelligence import facts as code_facts
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
        # Compose, Kubernetes and CI services read YAML 1.2, which has no base-60 numbers:
        # an unquoted 8080:22 port mapping stays text.
        return safe_yaml_load_all(text, allow_unknown_tags=True, base60=False)


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


def _azure_steps(root: dict[str, Any]) -> list[dict[str, Any]]:
    """The steps of an Azure Pipelines file: the implicit job's, every job's and the hooks of
    deployment jobs' strategies (runOnce, rolling, canary), at most 5,000."""
    jobs = list(_items(root.get("jobs")))
    for stage in _items(root.get("stages")):
        jobs.extend(_items(_mapping(stage).get("jobs")))
    steps: list[dict[str, Any]] = []
    for job in [root, *(_mapping(job) for job in jobs)]:
        steps.extend(_mapping(step) for step in _items(job.get("steps")))
        for phase in _mapping(job.get("strategy")).values():
            for hook in _mapping(phase).values():
                steps.extend(_mapping(step) for step in _items(_mapping(hook).get("steps")))
        if len(steps) >= 5000:
            break
    return steps[:5000]


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


# Publish and deploy steps in CI workflows, by a command or an action/task name they contain
# (lower case): the target they publish to or the platform they deploy to.
_PUBLISH_COMMANDS = (
    ("docker push", "container registry"), ("podman push", "container registry"), ("buildah push", "container registry"),
    ("docker buildx build --push", "container registry"), ("npm publish", "npm"), ("pnpm publish", "npm"),
    ("yarn npm publish", "npm"), ("yarn publish", "npm"), ("twine upload", "PyPI"), ("uv publish", "PyPI"),
    ("poetry publish", "PyPI"), ("flit publish", "PyPI"), ("hatch publish", "PyPI"), ("cargo publish", "crates.io"),
    ("gem push", "RubyGems"), ("mvn deploy", "Maven repository"), ("gradle publish", "Maven repository"),
    ("gradlew publish", "Maven repository"), ("dotnet nuget push", "NuGet"), ("nuget push", "NuGet"),
    ("helm push", "Helm repository"), ("gh release create", "GitHub release"), ("gh release upload", "GitHub release"),
    ("goreleaser", "release artifacts"),
)
_PUBLISH_ACTIONS = (
    ("docker/build-push-action", "container registry"), ("redhat-actions/push-to-registry", "container registry"),
    ("pypa/gh-action-pypi-publish", "PyPI"), ("js-devtools/npm-publish", "npm"),
    ("softprops/action-gh-release", "GitHub release"), ("ncipollo/release-action", "GitHub release"),
    ("goreleaser/goreleaser-action", "release artifacts"), ("docker@", "container registry"),
)
_DEPLOY_COMMANDS = (
    ("kubectl apply", "Kubernetes"), ("kubectl rollout", "Kubernetes"), ("kubectl set image", "Kubernetes"),
    ("helm upgrade", "Kubernetes (Helm)"), ("helm install", "Kubernetes (Helm)"), ("terraform apply", "Terraform"),
    ("pulumi up", "Pulumi"), ("cdk deploy", "AWS CDK"), ("sam deploy", "AWS SAM"),
    ("aws ecs update-service", "AWS ECS"), ("aws lambda update-function-code", "AWS Lambda"),
    ("aws cloudformation deploy", "AWS CloudFormation"), ("aws s3 sync", "AWS S3"),
    ("gcloud run deploy", "Google Cloud Run"), ("gcloud app deploy", "Google App Engine"),
    ("gcloud functions deploy", "Google Cloud Functions"), ("az webapp", "Azure App Service"),
    ("az containerapp", "Azure Container Apps"), ("az functionapp", "Azure Functions"),
    ("serverless deploy", "Serverless Framework"), ("sls deploy", "Serverless Framework"),
    ("firebase deploy", "Firebase"), ("vercel deploy", "Vercel"), ("vercel --prod", "Vercel"),
    ("netlify deploy", "Netlify"), ("flyctl deploy", "Fly.io"), ("fly deploy", "Fly.io"),
    ("wrangler deploy", "Cloudflare Workers"), ("wrangler publish", "Cloudflare Workers"),
)
_DEPLOY_ACTIONS = (
    ("aws-actions/amazon-ecs-deploy-task-definition", "AWS ECS"),
    ("aws-actions/aws-cloudformation-github-deploy", "AWS CloudFormation"),
    ("google-github-actions/deploy-cloudrun", "Google Cloud Run"),
    ("google-github-actions/deploy-appengine", "Google App Engine"), ("azure/webapps-deploy", "Azure App Service"),
    ("azure/functions-action", "Azure Functions"), ("azure/k8s-deploy", "Kubernetes"),
    ("cloudflare/wrangler-action", "Cloudflare Workers"), ("amondnet/vercel-action", "Vercel"),
    ("nwtgck/actions-netlify", "Netlify"), ("superfly/flyctl-actions", "Fly.io"),
    ("firebaseextended/action-hosting-deploy", "Firebase"), ("actions/deploy-pages", "GitHub Pages"),
    ("peaceiris/actions-gh-pages", "GitHub Pages"), ("kubernetesmanifest@", "Kubernetes"),
    ("helmdeploy@", "Kubernetes (Helm)"), ("azurewebapp@", "Azure App Service"),
    ("azurefunctionapp@", "Azure Functions"), ("azurermwebappdeployment@", "Azure App Service"),
)
# Terraform providers and resource prefixes, by the platform they manage.
_TERRAFORM_PLATFORMS = {
    "aws": "AWS", "google": "Google Cloud", "google-beta": "Google Cloud", "azurerm": "Azure", "azuread": "Azure",
    "kubernetes": "Kubernetes", "helm": "Kubernetes (Helm)", "cloudflare": "Cloudflare", "digitalocean": "DigitalOcean",
    "oci": "Oracle Cloud", "alicloud": "Alibaba Cloud", "ibm": "IBM Cloud", "vercel": "Vercel", "netlify": "Netlify",
    "fastly": "Fastly", "heroku": "Heroku", "hcloud": "Hetzner Cloud", "linode": "Akamai Cloud (Linode)",
    "vsphere": "VMware vSphere", "openstack": "OpenStack", "docker": "Docker",
}
_MAX_STEP_TEXT = 4096


def _steps_targets(texts: list[str]) -> tuple[list[str], list[str]]:
    """(publish targets, deploy platforms) the commands and action names of a workflow name."""
    publishes: list[str] = []
    deploys: list[str] = []
    for text in texts:
        lowered = " ".join(text[:_MAX_STEP_TEXT].lower().split())
        for table, found in ((_PUBLISH_COMMANDS, publishes), (_PUBLISH_ACTIONS, publishes),
                             (_DEPLOY_COMMANDS, deploys), (_DEPLOY_ACTIONS, deploys)):
            for needle, target in table:
                if needle in lowered and target not in found and len(found) < _MAX_FACT_ITEMS:
                    found.append(target)
    return publishes, deploys


def image_registry(image: str) -> str:
    """The registry host of a container image reference: its first path component when that is
    a host (a dot or port, or localhost), else Docker Hub; "" for a reference built from variables."""
    if not image or "$" in image or "{{" in image:
        return ""
    first, slash, _ = image.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        return first.lower()[:200]
    return "docker.io"


def _emit_image(image: Any, source: str, role: str) -> None:
    if not isinstance(image, str) or not image.strip():
        return
    image = image.strip()[:300]
    code_facts.emit_fact("container_image", image, source=source, role=role, registry=image_registry(image),
                         pinned="@sha256:" in image)


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

# ----------------------------------------------------------------------------- port facts
# The ports deployment files declare are recorded as code facts (``net_declared``), and the
# services they name as ``net_service``; the code index joins them with the ports code
# listens on into the network service map (intelligence/index.py, "network_services"). A
# declaration's scope says what it is: "workload" ports are the ones the program inside
# should listen on, "edge" ports a load balancer's own, "firewall" ports what an allow rule
# opens.

_MAX_FACT_ITEMS = 20


def _labels(value: Any) -> dict[str, str]:
    """Up to 20 entries of a mapping (Kubernetes labels, a selector), as text."""
    return {str(key)[:100]: str(item)[:200] for key, item in itertools.islice(_mapping(value).items(), _MAX_FACT_ITEMS)}


def _plain(value: Any) -> Any:
    """A fact detail value: numbers, flags and short text as they are, anything else as text."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, dict):
        return _labels(value)
    if isinstance(value, list):
        return [str(item)[:200] for item in value[:_MAX_FACT_ITEMS]]
    return str(value)[:200]


def _transport(protocol: Any) -> str | None:
    """The transport a declared protocol stands for (tcp, udp, sctp or "any"), or None for
    protocols without ports (ICMP, ESP, AH, GRE)."""
    value = "tcp" if protocol is None else str(protocol).strip().lower()
    if value in {"udp", "17"}:
        return "udp"
    if value in {"sctp", "132"}:
        return "sctp"
    if value in {"-1", "all", "*", "any", "asterisk", "tcp_udp"}:
        return "any"
    if value in {"icmp", "icmpv6", "ipv6-icmp", "1", "58", "esp", "ah", "gre", "50", "51", "47"}:
        return None
    return "tcp"  # tcp, 6, and the protocols carried over TCP (HTTP, HTTPS, TLS)


def _number(text: str) -> int | None:
    return int(text) if text.isascii() and text.isdigit() and len(text) <= 5 else None


def _port_span(value: Any) -> str | None:
    """A port ("8080") or range ("8000-8010"; "0-65535" is every port) as text, or None for
    variables, names and other text."""
    if value is None or isinstance(value, bool):
        return None
    low, separator, high = str(value).strip().partition("-")
    first, last = _number(low), _number(high) if separator else _number(low)
    if first is None or last is None:
        return None
    if separator and first == 0:
        first = 1  # port 0 is no port: 0-65535 is every port
    if not 0 < first <= last < 65536:
        return None
    return str(first) if first == last else f"{first}-{last}"


def _emit_port(value: Any, source: str, /, protocol: Any = None, scope: str = "workload", named: bool = False,
               **detail: Any) -> None:
    """Record one declared port or port range; with ``named``, a port name (a Kubernetes
    targetPort) is recorded as "?" with the name."""
    span = _port_span(value)
    transport = _transport(protocol)
    if span is None and named and isinstance(value, str) and value.strip():
        span, detail["target_name"] = "?", value.strip()
    if span is None or transport is None:
        return
    code_facts.emit_fact("net_declared", span, source=source, protocol=transport, scope=scope, **{
        key: _plain(item) for key, item in detail.items() if item is not None and item is not False and item != ""})


def _compose_ports(value: Any):
    """(target, protocol, published, host IP) of each entry of a Compose service's ``ports``,
    in the short ("127.0.0.1:8080:80/tcp", "[::1]:8080:80") or long syntax."""
    for item in _items(value):
        if isinstance(item, dict):
            yield item.get("target"), item.get("protocol"), item.get("published"), item.get("host_ip")
            continue
        text, _, protocol = str(item).strip().partition("/")
        host_ip = None
        if text.startswith("["):
            close = text.find("]")
            if close < 0:
                continue
            host_ip, text = text[1:close], text[close + 1:].removeprefix(":")
        parts = text.rsplit(":", 2)
        if len(parts) == 3:
            host_ip = parts[0]
        yield parts[-1], protocol or None, (parts[-2] or None) if len(parts) > 1 else None, host_ip


def _pod_labels(kind: str, root: dict[str, Any], spec: dict[str, Any]) -> dict[str, str]:
    """The labels a workload's pods carry: a Pod's own, else its pod template's."""
    if kind == "Pod":
        return _labels(_mapping(root.get("metadata")).get("labels"))
    if kind == "CronJob":
        spec = _mapping(_mapping(spec.get("jobTemplate")).get("spec"))
    return _labels(_mapping(_mapping(spec.get("template")).get("metadata")).get("labels"))


# Terraform resources that open, serve or front ports, by the nested block path that holds
# each rule (an empty path: the resource's own attributes).
_TF_PORT_RESOURCES = {
    "aws_security_group": ("ingress",), "aws_security_group_rule": (),
    "aws_vpc_security_group_ingress_rule": (), "google_compute_firewall": ("allow",),
    "azurerm_network_security_group": ("security_rule",), "azurerm_network_security_rule": (),
    "aws_lb_listener": (), "aws_alb_listener": (), "aws_lb_target_group": (), "aws_alb_target_group": (),
    "kubernetes_service": ("spec", "port"), "kubernetes_service_v1": ("spec", "port"),
}
_TF_PUBLIC_SOURCES = frozenset({"0.0.0.0/0", "::/0", "*", "internet", "any"})
_TF_SOURCE_FIELDS = ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6", "source_ranges",
                     "source_address_prefix", "source_address_prefixes")
_TF_RESOURCE = re.compile(r'(?m)^[ \t]*resource[ \t]+"([\w-]{1,128})"[ \t]+"([\w-]{1,128})"[ \t]*\{')
_TF_NESTED = re.compile(r'(?m)^[ \t]*([A-Za-z_][\w-]{0,63})(?:[ \t]+"[^"\n]{0,128}"){0,2}[ \t]*\{')
_TF_FIELD = re.compile(
    r"(?m)^[ \t]*(from_port|to_port|port|target_port|node_port|destination_port_ranges?|ports|protocol|"
    r"ip_protocol|type|direction|access|cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6|source_ranges|"
    r"source_address_prefix(?:es)?)[ \t]*=[ \t]*"
)
_HCL_SPECIAL = re.compile(r'["#/<{}]')
_HCL_STRING_REST = re.compile(r'(?:[^"\\\n]|\\.)*"?')
_HCL_HEREDOC = re.compile(r"<<-?([A-Za-z_][\w-]{0,63})[ \t]*\r?\n")


def _block_end(source: str, opening: int) -> int:
    """The offset of the brace that closes the HCL block opening at ``opening``, skipping
    strings, comments and heredocs; the end of the text when it never closes."""
    depth, position, length = 0, opening, len(source)
    while (special := _HCL_SPECIAL.search(source, position)) is not None:
        position = special.start()
        char = source[position]
        if char == '"':
            position = _HCL_STRING_REST.match(source, position + 1).end()
            continue
        if char == "#" or source.startswith("//", position):
            newline = source.find("\n", position)
            if newline < 0:
                return length
            position = newline + 1
            continue
        if source.startswith("/*", position):
            close = source.find("*/", position + 2)
            if close < 0:
                return length
            position = close + 2
            continue
        if char == "<" and (heredoc := _HCL_HEREDOC.match(source, position)) is not None:
            terminator = re.compile(rf"^[ \t]*{re.escape(heredoc.group(1))}[ \t]*\r?$", re.MULTILINE)
            close = terminator.search(source, heredoc.end())
            if close is None:
                return length
            position = close.end()
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return position
        position += 1
    return length


def _tf_values(text: str) -> list[str]:
    """The strings and numbers of an HCL value (one value, or a list's inside), skipping
    comments and references such as ``var.ports``."""
    values: list[str] = []
    position, length = 0, len(text)
    while position < length and len(values) < 256:
        char = text[position]
        if char == '"':
            close = text.find('"', position + 1)
            if close < 0:
                break
            values.append(text[position + 1:close])
            position = close + 1
        elif char == "#" or text.startswith("//", position):
            newline = text.find("\n", position)
            if newline < 0:
                break
            position = newline + 1
        elif char.isascii() and (char.isalnum() or char in "_-."):
            end = position + 1
            while end < length and text[end].isascii() and (text[end].isalnum() or text[end] in "_-."):
                end += 1
            if char.isdigit() or char == "-":
                values.append(text[position:end])
            position = end
        else:
            position += 1
    return values


def _tf_value(text: str, start: int) -> tuple[list[str], int]:
    """The items of the value assigned at ``start`` (a list may span lines) and its end."""
    if text.startswith("[", start):
        close = text.find("]", start, start + 8192)
        if close < 0:
            return [], min(len(text), start + 8192)
        return _tf_values(text[start + 1:close]), close + 1
    newline = text.find("\n", start, start + 512)
    end = newline if newline >= 0 else min(len(text), start + 512)
    return _tf_values(text[start:end])[:1], end


def _tf_fields(text: str) -> dict[str, list[str]]:
    """The port, protocol, direction and source attributes of an HCL block's own text."""
    fields: dict[str, list[str]] = {}
    position = 0
    while (match := _TF_FIELD.search(text, position)) is not None:
        values, end = _tf_value(text, match.end())
        fields.setdefault(match.group(1), values)
        position = max(end, match.end())
    return fields


def _tf_children(body: str) -> tuple[list[tuple[str, str]], str]:
    """A block body's nested blocks, as (type, body) pairs, and its own text without them."""
    children, own, position = [], [], 0
    while (match := _TF_NESTED.search(body, position)) is not None:
        end = _block_end(body, match.end() - 1)
        own.append(body[position:match.start()])
        children.append((match.group(1), body[match.end():end]))
        position = end + 1
    own.append(body[position:])
    return children, "".join(own)


def _tf_rules(body: str, path: tuple[str, ...]) -> tuple[list[dict[str, list[str]]], dict[str, list[str]]]:
    """The attributes of each rule block along ``path``, and the resource's own attributes."""
    children, own = _tf_children(body)
    outer = _tf_fields(own)
    if not path:
        return [outer], outer
    level = [child for kind, child in children if kind == path[0]]
    for name in path[1:]:
        level = [child for block in level for kind, child in _tf_children(block)[0] if kind == name]
    return [_tf_fields(_tf_children(block)[1]) for block in level], outer


def _tf_emit(kind: str, resource: str, line: int, fields: dict[str, list[str]], outer: dict[str, list[str]]) -> None:
    def first(key: str) -> str:
        values = fields.get(key) or outer.get(key) or [""]
        return values[0].strip()

    if kind == "aws_security_group_rule" and first("type").lower() != "ingress":
        return
    if first("direction").lower() in {"egress", "outbound"} or first("access").lower() == "deny":
        return
    protocol = first("protocol") or first("ip_protocol") or None
    detail = {"resource": resource, "line": line}
    if kind.endswith(("_listener", "_target_group")):
        _emit_port(first("port"), "terraform", protocol=protocol,
                   scope="edge" if kind.endswith("_listener") else "workload", **detail)
        return
    if kind.startswith("kubernetes_service"):
        _emit_port(first("target_port") or first("port"), "terraform", protocol=protocol,
                   port=_number(first("port")), node_port=_number(first("node_port")), **detail)
        return
    public = any(value.strip().lower() in _TF_PUBLIC_SOURCES for key in _TF_SOURCE_FIELDS
                 for value in fields.get(key, []) + outer.get(key, []))
    spans = []
    if kind.startswith("aws_") and _transport(protocol) == "any":
        spans.append("1-65535")  # protocol -1: every port, whatever from_port and to_port say
    elif first("from_port"):
        spans.append(f"{first('from_port')}-{first('to_port') or first('from_port')}")
    for key in ("destination_port_range", "destination_port_ranges", "ports"):
        spans.extend(fields.get(key, []))
    if kind == "google_compute_firewall" and not fields.get("ports"):
        spans.append("1-65535")  # an allow block without ports allows every port of its protocol
    for span in spans:
        _emit_port("1-65535" if span.strip() == "*" else span, "terraform", protocol=protocol, scope="firewall",
                   public=public, **detail)


def _terraform_ports(source: str, lines: LineIndex) -> None:
    """Record the ports Terraform resources open (security groups, firewall rules), serve
    (target groups, Kubernetes services) or front (load balancer listeners)."""
    position = 0
    while (match := _TF_RESOURCE.search(source, position)) is not None:
        kind, name = match.groups()
        position = match.end()
        path = _TF_PORT_RESOURCES.get(kind)
        if path is None:
            continue
        end = _block_end(source, match.end() - 1)
        position = end + 1
        rules, outer = _tf_rules(source[match.end():end], path)
        for fields in rules:
            _tf_emit(kind, f"{kind}.{name}", lines.line(match.start()), fields, outer)


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
        for line, value in instructions.get("EXPOSE", []):
            for token in value.split():
                port, _, protocol = token.partition("/")
                _emit_port(port, "dockerfile", protocol=protocol or None, line=line)
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
            if image and image.lower() not in stages and image != "scratch":
                _emit_image(image, "dockerfile", "base")
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
        _terraform_ports(source, lines)
        platforms: list[str] = []
        for kind, first, _ in blocks:
            if kind in {"provider", "resource", "data"}:
                prefix = first if kind == "provider" else first.split("_", 1)[0]
                platform = _TERRAFORM_PLATFORMS.get(prefix.lower())
                if platform and platform not in platforms:
                    platforms.append(platform)
        for platform in platforms[:_MAX_FACT_ITEMS]:
            code_facts.emit_fact("deploy_target", platform, source="terraform")
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
        texts: list[str] = []  # commands and action names, read for publish and deploy steps only
        for job_name, job_value in jobs.items():
            job = _mapping(job_value)
            for step in _items(job.get("steps")):
                step = _mapping(step)
                if step.get("uses"):
                    steps.append((str(job_name), str(step["uses"])))
                    texts.append(str(step["uses"]))
                if isinstance(step.get("run"), str):
                    texts.append(step["run"])
        if name == ".gitlab-ci.yml":
            job_names = _gitlab_jobs(root)
            for job in job_names:
                for key in ("before_script", "script", "after_script"):
                    texts.extend(str(line) for line in _items(_mapping(root.get(job)).get(key)) if isinstance(line, str))
        elif name == "azure-pipelines.yml":
            job_names = _azure_jobs(root)
            for step in _azure_steps(root):
                for key in ("script", "bash", "powershell", "pwsh", "task"):
                    if isinstance(step.get(key), str):
                        texts.append(step[key])
                if str(step.get("task", "")).lower().startswith("docker@") and "push" in str(
                        _mapping(step.get("inputs")).get("command", "")).lower():
                    texts.append("docker push")
        else:
            job_names = list(jobs)
        publishes, deploys = _steps_targets(texts)
        unpinned = sum(1 for _, uses in steps if "@" in uses and not re.search(r"@[0-9a-fA-F]{40}$", uses))
        code_facts.emit_fact(
            "ci_workflow", "GitHub Actions" if github else "GitLab CI" if name == ".gitlab-ci.yml" else "Azure Pipelines",
            jobs=len(job_names), actions=sorted({uses[:200] for _, uses in steps})[:50], unpinned_actions=unpinned,
            publishes=publishes, deploys=deploys,
            write_permissions=bool(github and any(_writes(scope) for scope in (
                root.get("permissions"), *(_mapping(job).get("permissions") for job in jobs.values())))),
        )
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
                    code_facts.emit_fact("deploy_target", "Ansible", source="ansible", plays=len(document))
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
        code_facts.emit_fact("deploy_target", "Docker Compose", source="compose", services=len(services))
        for service_name, value in services.items():
            service = _mapping(value)
            if service.get("image"):
                evidence.append(f"service {service_name}: image {service['image']}")
                _emit_image(service["image"], "compose", "service")
            if service.get("build"):
                evidence.append(f"service {service_name}: build context declared")
            for key in ("ports", "depends_on", "volumes", "networks"):
                if service.get(key):
                    evidence.append(f"service {service_name}: {key} declared")
            aliases = [service.get("container_name"), service.get("hostname")]
            for network in _items(service.get("networks")):
                aliases.extend(_items(_mapping(network).get("aliases")))
            aliases = [alias[:200] for alias in aliases if isinstance(alias, str) and alias][:_MAX_FACT_ITEMS]
            code_facts.emit_fact("net_service", str(service_name)[:200], source="compose",
                                 **({"aliases": aliases} if aliases else {}))
            for target, protocol, published, host_ip in _compose_ports(service.get("ports")):
                _emit_port(target, "compose", protocol=protocol, service=str(service_name),
                           published=None if published is None else str(published), host_ip=host_ip)
            for exposed in _items(service.get("expose")):
                port, _, protocol = str(exposed).partition("/")
                _emit_port(port, "compose", protocol=protocol or None, service=str(service_name), internal=True)
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
        namespace = metadata.get("namespace")
        labels = _pod_labels(kind, root, spec) if containers else {}
        code_facts.emit_fact("deploy_target", "Kubernetes", source="kubernetes", resource=f"{kind}/{name}"[:200])
        for container in containers:
            if container.get("image"):
                evidence.append(f"image: {container['image']}")
                _emit_image(container["image"], "kubernetes", "workload")
            for port in _items(container.get("ports")):
                port = _mapping(port)
                if port.get("containerPort"):
                    evidence.append(f"containerPort: {port['containerPort']}")
                    _emit_port(port["containerPort"], "kubernetes", protocol=port.get("protocol"),
                               workload=f"{kind}/{name}", container=container.get("name"),
                               port_name=port.get("name"), host_port=port.get("hostPort"), namespace=namespace,
                               labels=labels or None)
        if kind == "Service":
            self._service_ports(spec, name, namespace)
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

    @staticmethod
    def _service_ports(spec: dict[str, Any], name: str, namespace: Any) -> None:
        """A Kubernetes Service as a ``net_service`` fact, and each of its ports by the target
        port the selected pods listen on (a named targetPort as "?" with its name)."""
        selector = _labels(spec.get("selector"))
        code_facts.emit_fact("net_service", name[:200], source="kubernetes", **{
            key: _plain(value) for key, value in (("namespace", namespace), ("external_name", spec.get("externalName")))
            if value})
        for port in _items(spec.get("ports")):
            port = _mapping(port)
            _emit_port(port.get("targetPort", port.get("port")), "kubernetes-service", protocol=port.get("protocol"),
                       named=True, service=name, namespace=namespace, port=port.get("port"),
                       node_port=port.get("nodePort"), type=spec.get("type") or "ClusterIP",
                       port_name=port.get("name"), selector=selector or None)

    def _helm_chart(self, path: Path, record: FileRecord) -> list[Finding]:
        documents, error = self._read_yaml(path, record)
        if error:
            return [error]
        chart = _mapping(documents[0] if documents else {})
        if not chart.get("apiVersion") or not chart.get("name"):
            return []
        dependencies = _items(chart.get("dependencies"))
        code_facts.emit_fact("deploy_target", "Kubernetes (Helm)", source="helm", chart=str(chart["name"])[:200])
        hosts: dict[str, int] = {}
        for dependency in dependencies:
            repository = _mapping(dependency).get("repository")
            if isinstance(repository, str) and "://" in repository:
                host = urllib.parse.urlsplit(repository).hostname
                if host and (host in hosts or len(hosts) < _MAX_FACT_ITEMS):
                    hosts[host.lower()] = hosts.get(host.lower(), 0) + 1
        for host, count in hosts.items():
            code_facts.emit_fact("package_registry", host, ecosystem="Helm", packages=count)
        return [Finding(
            "orchestration",
            f"Helm chart: {chart['name']}",
            f"Chart API {chart['apiVersion']}; version {chart.get('version', 'unspecified')}; "
            f"{len(dependencies)} declared chart dependency(ies).",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _cloudformation(self, root: dict[str, Any], record: FileRecord) -> list[Finding]:
        resources = _mapping(root.get("Resources"))
        code_facts.emit_fact("deploy_target", "AWS CloudFormation", source="cloudformation", resources=len(resources))
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
        publishes, deploys = _steps_targets(source.splitlines()[:20_000])
        code_facts.emit_fact("ci_workflow", "Jenkins", jobs=len(stages), actions=[], unpinned_actions=0,
                             publishes=publishes, deploys=deploys, write_permissions=False)
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
