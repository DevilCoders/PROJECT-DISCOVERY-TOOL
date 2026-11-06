"""Integration points: what a project provides to, and consumes from, other systems.

Per file PDT records, as code facts:

* **Outbound HTTP calls** with a literal URL or path (requests/httpx/aiohttp/urllib,
  fetch/axios/Angular HttpClient/ky/got, Spring RestTemplate/WebClient, OkHttp, Go
  net/http, .NET HttpClient). Interpolated parts become ``{}``.
* **Message topics and queues** produced or consumed (Kafka, RabbitMQ, NATS, MQTT, SQS,
  Google Pub/Sub, Redis pub/sub, Celery task names, Socket.IO events, Spring
  ``@KafkaListener``/``@RabbitListener``/``@JmsListener``).
* **gRPC services** defined in ``.proto`` files, implemented by servers and called
  through client stubs.
* **Package identity** from manifests (pyproject/setup.cfg, package.json, Cargo.toml,
  go.mod, pom.xml, settings.gradle, .csproj, composer.json, gemspec).

The code index turns them into the scan's integration summary, and ``pdt compare``
joins summaries of several scans into an integration map (which project calls,
publishes to or depends on which other project).
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path, PurePosixPath

from ...core.source_utils import SourceBudgetExceeded, read_text_bounded
from ...intelligence import facts as code_facts
from ...intelligence.model import model_for
from ...models import FileRecord, Finding
from ..base import Analyzer

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FACTS = 400
_LEXICAL = frozenset({"JavaScript", "TypeScript", "Vue", "Svelte", "Java", "Kotlin", "Scala", "Groovy", "Go", "C#"})
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
# Named quote group: patterns put their own groups before the string.
_STRING = r"(?P<q>[\"'`])((?:(?!(?P=q))[^\\\n]|\\.){1,400}+)(?P=q)"

# (system, role, pattern with the name in the last group)
_LEXICAL_MESSAGING = (
    ("Kafka", "produce", re.compile(r"\.send[ \t]*+\([ \t]*+\{[ \t\r\n]*+topic[ \t]*+:[ \t]*+" + _STRING)),
    ("Kafka", "consume", re.compile(r"\.subscribe[ \t]*+\([ \t]*+\{[ \t\r\n]*+topics?[ \t]*+:[ \t]*+\[?[ \t]*+" + _STRING)),
    ("Kafka", "consume", re.compile(r"@KafkaListener[ \t]*+\([^)]{0,200}?topics[ \t]*+=[ \t]*+\{?[ \t]*+" + _STRING)),
    ("Kafka", "produce", re.compile(r"(?i)kafkaTemplate\.send[ \t]*+\([ \t]*+" + _STRING)),
    ("Kafka", "produce", re.compile(r"(?:kafka\.Writer|sarama\.ProducerMessage)[ \t]*+\{[^;]{0,400}?Topic[ \t]*+:[ \t]*+"
                                    + _STRING)),
    ("Kafka", "consume", re.compile(r"kafka\.ReaderConfig[ \t]*+\{[^;]{0,400}?Topic[ \t]*+:[ \t]*+" + _STRING)),
    ("RabbitMQ", "consume", re.compile(r"@RabbitListener[ \t]*+\([^)]{0,200}?queues[ \t]*+=[ \t]*+\{?[ \t]*+" + _STRING)),
    ("RabbitMQ", "produce", re.compile(r"(?i)rabbitTemplate\.convertAndSend[ \t]*+\([ \t]*+" + _STRING)),
    ("RabbitMQ", "produce", re.compile(r"\.sendToQueue[ \t]*+\([ \t]*+" + _STRING)),
    ("RabbitMQ", "consume", re.compile(r"\.consume[ \t]*+\([ \t]*+" + _STRING)),
    ("RabbitMQ", "declare", re.compile(r"\.assertQueue[ \t]*+\([ \t]*+" + _STRING)),
    ("JMS", "consume", re.compile(r"@JmsListener[ \t]*+\([^)]{0,200}?destination[ \t]*+=[ \t]*+" + _STRING)),
    ("JMS", "produce", re.compile(r"(?i)jmsTemplate\.convertAndSend[ \t]*+\([ \t]*+" + _STRING)),
    ("SQS", "consume", re.compile(r"@SqsListener[ \t]*+\([ \t]*+(?:value[ \t]*+=[ \t]*+)?\{?[ \t]*+" + _STRING)),
    ("NATS", "produce", re.compile(r"(?<![\w$])(?:nc|nats|natsConn|js)\.(?:publish|Publish)[ \t]*+\([ \t]*+" + _STRING)),
    ("NATS", "consume", re.compile(r"(?<![\w$])(?:nc|nats|natsConn|js)\.(?:subscribe|Subscribe|QueueSubscribe)[ \t]*+\([ \t]*+" + _STRING)),
    ("MQTT", "produce", re.compile(r"(?<![\w$])(?:mqtt|mqttClient|client)\.publish[ \t]*+\([ \t]*+" + _STRING)),
    ("MQTT", "consume", re.compile(r"(?<![\w$])(?:mqtt|mqttClient|client)\.subscribe[ \t]*+\([ \t]*+" + _STRING)),
    ("Socket.IO", "produce", re.compile(r"(?<![\w$])(?:socket|io|client)\.emit[ \t]*+\([ \t]*+" + _STRING)),
    ("Socket.IO", "consume", re.compile(r"(?<![\w$])socket\.on[ \t]*+\([ \t]*+" + _STRING)),
    ("Azure Service Bus", "produce", re.compile(r"\.CreateSender[ \t]*+\([ \t]*+" + _STRING)),
    ("Azure Service Bus", "consume", re.compile(r"\.CreateProcessor[ \t]*+\([ \t]*+" + _STRING)),
)
_LEXICAL_HTTP = (
    (None, re.compile(r"(?<![\w$.])fetch[ \t]*+\([ \t]*+" + _STRING)),
    ("method", re.compile(r"(?<![\w$])(?:axios|ky|got|superagent|http|this\.http|\$http|httpClient|api)\."
                          r"(get|post|put|patch|delete|head)[ \t]*+(?:<[^<>()\n]{0,120}+>)?\([ \t]*+" + _STRING)),
    ("method", re.compile(r"(?i)restTemplate\.(get|post|put|delete|patch)(?:ForObject|ForEntity|ForLocation)?"
                          r"[ \t]*+\([ \t]*+" + _STRING)),
    ("method", re.compile(r"\.(get|post|put|patch|delete)\(\)[ \t\r\n]*+\.uri[ \t]*+\([ \t]*+" + _STRING)),
    ("GET", re.compile(r"Request\.Builder\(\)[ \t\r\n]*+\.url[ \t]*+\([ \t]*+" + _STRING)),
    ("method", re.compile(r"(?<![\w$])http\.(Get|Head|Post|PostForm)[ \t]*+\([ \t]*+" + _STRING)),
    ("verb", re.compile(r"(?<![\w$])http\.NewRequest(?:WithContext)?[ \t]*+\((?:[ \t]*+ctx[ \t]*+,)?[ \t]*+"
                        r"(?:\"(\w{3,7}+)\"|http\.Method(\w{3,7}+))[ \t]*+,[ \t]*+" + _STRING)),
    ("method", re.compile(r"\.(Get|Post|Put|Patch|Delete)(?:Async|StringAsync|FromJsonAsync|AsJsonAsync|ByteArrayAsync|"
                          r"StreamAsync)[ \t]*+\([ \t]*+\$?" + _STRING)),
)
_PROTO_PACKAGE = re.compile(r"(?m)^[ \t]*+package[ \t]++([\w.]{1,200}+)[ \t]*+;")
_PROTO_SERVICE = re.compile(r"(?<![\w$])service[ \t]++(\w{1,120}+)[ \t\r\n]*+\{")
_PROTO_RPC = re.compile(r"(?<![\w$])rpc[ \t]++(\w{1,120}+)")
_GRPC_CLIENTS = (
    re.compile(r"(\w{1,120}?)_pb2_grpc\.(\w{1,120}?)Stub[ \t]*+\("),
    re.compile(r"\.New(\w{1,120}?)Client[ \t]*+\("),
    re.compile(r"(\w{1,120}?)Grpc\.new(?:Blocking|Future)?Stub[ \t]*+\("),
    re.compile(r"new[ \t]++(?:\w{1,120}+\.)?(\w{1,120}+)\.\1Client[ \t]*+\("),
)
_GRPC_SERVERS = (
    re.compile(r"add_(\w{1,120}?)Servicer_to_server"),
    re.compile(r"\.Register(\w{1,120}?)Server[ \t]*+\("),
    re.compile(r"(\w{1,120}?)Grpc\.\1ImplBase"),
    re.compile(r":[ \t]*+(?:\w{1,120}+\.)?(\w{1,120}+)\.\1Base\b"),
    re.compile(r"(\w{1,120}?)_pb2_grpc\.(\w{1,120}?)Servicer\b"),
)
_MANIFESTS = {"pyproject.toml", "setup.cfg", "package.json", "cargo.toml", "go.mod", "pom.xml", "settings.gradle",
              "settings.gradle.kts", "composer.json"}


def _normalize_url(url: str) -> tuple[str, str]:
    """(host, path template) with interpolations, numbers and UUIDs as ``{}``."""
    value = re.sub(r"\$\{[^{}]{0,200}+\}|\{[^{}]{0,200}+\}|%[sd]|:[A-Za-z_]\w{0,60}+(?=/|$)", "{}", url.strip())
    host = ""
    match = re.match(r"(?i)^(?:https?|wss?|grpc)://([^/?#]{1,253}+)(.*)$", value)
    if match:
        host, value = match.group(1).split("@")[-1].split(":")[0].lower(), match.group(2) or "/"
    elif value.startswith("{}") and "/" in value:
        value = value[value.index("/"):]  # "${BASE}/users" -> "/users"
    path = value.split("?", 1)[0].split("#", 1)[0] or "/"
    segments = []
    for segment in path.split("/"):
        if re.fullmatch(r"\d{1,20}+|[0-9a-fA-F-]{32,36}+|\{\}", segment):
            segment = "{}"
        segments.append(segment)
    path = "/".join(segments)
    if not path.startswith("/"):
        path = "/" + path
    return host, path


def normalize_route(route: str) -> str:
    """Server route template (Flask ``<int:id>``, FastAPI/Spring ``{id}``, Express ``:id``) as ``/a/{}``."""
    return _normalize_url(re.sub(r"<[^<>]{1,80}+>", "{}", route.strip() or "/"))[1]


def route_segments(path: str) -> list[str]:
    return [segment for segment in path.strip("/").split("/") if segment]


def route_matches(call: str, endpoint: str) -> str:
    """'exact', 'prefixed' (the caller adds a gateway or mount prefix) or '' for two templates."""
    caller, served = route_segments(call), route_segments(endpoint)
    if not served or all(segment == "{}" for segment in served) or len(caller) < len(served):
        return ""
    tail = caller[len(caller) - len(served):]
    # A served parameter accepts any caller segment; a served literal needs the same literal
    # (an interpolated caller segment is unknown, so it does not prove a match).
    if not all(right == "{}" or left == right for left, right in zip(tail, served, strict=True)):
        return ""
    return "exact" if len(caller) == len(served) else "prefixed"


class EndpointIndex:
    """Served endpoints indexed by their last literal segment, for fast call matching."""

    def __init__(self, endpoints) -> None:
        self.by_segment: dict[str, list[tuple[str, str]]] = {}
        for method, route in endpoints:
            literal = [segment for segment in route_segments(route) if segment != "{}"]
            if literal:
                self.by_segment.setdefault(literal[-1], []).append((method, route))

    def match(self, method: str, route: str) -> tuple[str, str, str] | None:
        """(served method, served route, 'exact'|'prefixed') of the first match, or None."""
        for segment in dict.fromkeys(route_segments(route)):
            for served_method, served in self.by_segment.get(segment, ()):
                wildcard = {"?", "ANY", "ALL", "*"}
                if method and served_method and method != served_method and not wildcard & {method, served_method}:
                    continue
                kind = route_matches(route, served)
                if kind:
                    return served_method, served, kind
        return None


def _js_string(raw: str) -> str:
    """Template literal text with ${...} replaced by {}."""
    return re.sub(r"\$\{[^{}]{0,200}+\}", "{}", raw)


class IntegrationAnalyzer(Analyzer):
    name = "integration-points"
    version = "1.0.0"
    description = ("Outbound HTTP calls, message topics, gRPC services and package identity for integration maps "
                   "across projects.")
    domains = ("multi_project", "api_rest", "messaging", "api_rpc")

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.content_skipped_reason:
            return False
        name = PurePosixPath(record.path.replace("\\", "/")).name.lower()
        return (record.language in _LEXICAL or record.language in {"Python", "Protocol Buffers"} or name in _MANIFESTS
                or name.endswith((".csproj", ".gemspec")))

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = PurePosixPath(record.path.replace("\\", "/")).name.lower()
        if name in _MANIFESTS or name.endswith((".csproj", ".gemspec")) or record.language == "Protocol Buffers":
            if record.size_bytes > MAX_MANIFEST_BYTES:
                return []
            try:
                text = read_text_bounded(path, MAX_MANIFEST_BYTES, errors="replace",
                                         expected_identity=record.analysis_identity)
            except (OSError, SourceBudgetExceeded):
                return []
            if record.language == "Protocol Buffers":
                self._proto(text)
            else:
                self._manifest(name, record.path, text)
            return []
        model = model_for(path, record)
        if model is None:
            return []
        emitted = [0]

        def emit(kind: str, value: str, **detail) -> None:
            if emitted[0] < MAX_FACTS and value:
                emitted[0] += 1
                code_facts.emit_fact(kind, value[:300], **detail)

        if model.tree is not None:
            self._python(model.tree, emit)
        else:
            self._lexical(model, emit)
        return []

    # -- Python -------------------------------------------------------------------------
    def _python(self, tree: ast.Module, emit) -> None:
        def literal(node: ast.AST | None) -> str | None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.JoinedStr):
                return "".join(part.value if isinstance(part, ast.Constant) else "{}" for part in node.values)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = literal(node.left)
                return (left + "{}") if left is not None else None
            return None

        def keyword(call: ast.Call, name: str) -> ast.AST | None:
            return next((item.value for item in call.keywords if item.arg == name), None)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and \
                            decorator.func.attr in {"task", "shared_task"}:
                        task = literal(keyword(decorator, "name"))
                        if task:
                            emit("message_topic", task, system="Celery", role="consume")
                continue
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            method, receiver = node.func.attr, node.func.value
            receiver_name = ast.unparse(receiver)[:80] if isinstance(receiver, ast.Name | ast.Attribute) else ""
            first = literal(node.args[0]) if node.args else None
            lowered = receiver_name.lower()
            if method in _HTTP_VERBS and first and (lowered in {"requests", "httpx"} or re.search(
                    r"session|client|http", lowered)) and ("/" in first or first.startswith("http")):
                host, route = _normalize_url(first)
                emit("http_call", f"{method.upper()} {route}", host=host)
            elif method == "request" and lowered in {"requests", "httpx"} and len(node.args) >= 2:
                verb, url = literal(node.args[0]), literal(node.args[1])
                if verb and url:
                    host, route = _normalize_url(url)
                    emit("http_call", f"{verb.upper()} {route}", host=host)
            elif method == "urlopen" and first and first.startswith("http"):
                host, route = _normalize_url(first)
                emit("http_call", f"GET {route}", host=host)
            elif method in {"send", "produce"} and first and re.search(r"produc|kafka", lowered):
                emit("message_topic", first, system="Kafka", role="produce")
            elif method == "subscribe" and node.args and isinstance(node.args[0], ast.List | ast.Tuple) and \
                    re.search(r"consum|kafka", lowered):
                for element in node.args[0].elts:
                    topic = literal(element)
                    if topic:
                        emit("message_topic", topic, system="Kafka", role="consume")
            elif method == "basic_publish":
                key = literal(keyword(node, "routing_key"))
                if key:
                    emit("message_topic", key, system="RabbitMQ", role="produce")
            elif method == "basic_consume":
                queue = literal(keyword(node, "queue")) or first
                if queue:
                    emit("message_topic", queue, system="RabbitMQ", role="consume")
            elif method == "queue_declare":
                queue = literal(keyword(node, "queue")) or first
                if queue:
                    emit("message_topic", queue, system="RabbitMQ", role="declare")
            elif method == "send_task" and first:
                emit("message_topic", first, system="Celery", role="produce")
            elif method in {"send_message", "receive_message"}:
                url = literal(keyword(node, "QueueUrl"))
                if url:
                    emit("message_topic", url.rstrip("/").rsplit("/", 1)[-1], system="SQS",
                         role="produce" if method == "send_message" else "consume")
            elif method in {"topic_path", "subscription_path"} and len(node.args) >= 2:
                topic = literal(node.args[1])
                if topic:
                    emit("message_topic", topic, system="Google Pub/Sub",
                         role="produce" if method == "topic_path" else "consume")
            elif method in {"publish", "subscribe"} and first and re.search(r"nats|nc$|mqtt|client|redis|pubsub|^r$", lowered):
                system = "NATS" if re.search(r"nats|nc$", lowered) else "MQTT" if "mqtt" in lowered or lowered == "client" \
                    else "Redis"
                emit("message_topic", first, system=system, role="produce" if method == "publish" else "consume")
            elif method == "emit" and first and re.search(r"socket|sio", lowered):
                emit("message_topic", first, system="Socket.IO", role="produce")
            name = ast.unparse(node.func)
            for pattern in _GRPC_CLIENTS[:1]:
                match = pattern.search(name + "(")
                if match:
                    emit("grpc_client", match.group(2))
            server = re.search(r"add_(\w{1,120}?)Servicer_to_server", name)
            if server:
                emit("grpc_server", server.group(1))

    # -- lexical languages ----------------------------------------------------------------
    def _lexical(self, model, emit) -> None:
        text, clean = model.text, model.clean or model.text

        def in_code(offset: int) -> bool:
            return clean[offset:offset + 1] == text[offset:offset + 1] and not clean[offset:offset + 1].isspace()

        for verb, pattern in _LEXICAL_HTTP:
            for match in pattern.finditer(text):
                if not in_code(match.start()):
                    continue
                groups = match.groups()
                url = _js_string(groups[-1])
                if not ("/" in url or url.startswith(("http", "{}"))):
                    continue
                if verb == "verb":
                    method = (groups[0] or groups[1] or "GET").upper()
                elif verb == "method":
                    method = groups[0].upper().replace("FORM", "")
                elif verb is None:
                    close = model.parens.get(text.find("(", match.start()))
                    window = text[match.end():close if close else match.end() + 400]
                    declared = re.search(r"method[ \t]*+:[ \t]*+[\"'](\w{3,7}+)[\"']", window)
                    method = declared.group(1).upper() if declared else "GET"
                else:
                    method = verb
                host, route = _normalize_url(url)
                emit("http_call", f"{method} {route}", host=host)
        lowered = text.lower()
        broker = "MQTT" if "mqtt" in lowered else "Redis" if "redis" in lowered else "pub/sub"
        for system, role, pattern in _LEXICAL_MESSAGING:
            for match in pattern.finditer(text):
                if in_code(match.start()):
                    emit("message_topic", match.groups()[-1], system=broker if system == "MQTT" else system, role=role)
        for pattern in _GRPC_CLIENTS[1:]:
            for match in pattern.finditer(clean):
                emit("grpc_client", match.groups()[-1])
        for pattern in _GRPC_SERVERS[1:4]:
            for match in pattern.finditer(clean):
                emit("grpc_server", match.groups()[-1])

    # -- contracts and manifests -----------------------------------------------------------
    @staticmethod
    def _proto(text: str) -> None:
        clean = re.sub(r"//[^\n]*+", "", text)
        package = _PROTO_PACKAGE.search(clean)
        prefix = f"{package.group(1)}." if package else ""
        for match in _PROTO_SERVICE.finditer(clean):
            end = clean.find("}", match.end())
            rpcs = _PROTO_RPC.findall(clean, match.end(), end if end != -1 else len(clean))
            code_facts.emit_fact("grpc_service", f"{prefix}{match.group(1)}", rpcs=rpcs[:100])

    @staticmethod
    def _manifest(name: str, path: str, text: str) -> None:
        text = text.replace("\r\n", "\n").replace("\r", "\n")  # section anchors expect LF line ends
        found: list[tuple[str, str]] = []
        if name == "pyproject.toml":
            section = re.search(r"(?ms)^\[(?:project|tool\.poetry)\][ \t]*+$(.*?)(?=^\[|\Z)", text)
            if section:
                match = re.search(r"(?m)^name[ \t]*+=[ \t]*+[\"']([^\"'\n]{1,200}+)[\"']", section.group(1))
                if match:
                    found.append(("pypi", match.group(1)))
        elif name == "setup.cfg":
            section = re.search(r"(?ms)^\[metadata\][ \t]*+$(.*?)(?=^\[|\Z)", text)
            match = re.search(r"(?m)^name[ \t]*+=[ \t]*+([\w.-]{1,200}+)", section.group(1)) if section else None
            if match:
                found.append(("pypi", match.group(1)))
        elif name in {"package.json", "composer.json"}:
            try:
                data = json.loads(text)
            except ValueError:
                data = {}
            if isinstance(data, dict) and isinstance(data.get("name"), str):
                found.append(("npm" if name == "package.json" else "packagist", data["name"]))
        elif name == "cargo.toml":
            section = re.search(r"(?ms)^\[package\][ \t]*+$(.*?)(?=^\[|\Z)", text)
            match = re.search(r"(?m)^name[ \t]*+=[ \t]*+\"([^\"\n]{1,200}+)\"", section.group(1)) if section else None
            if match:
                found.append(("cargo", match.group(1)))
        elif name == "go.mod":
            match = re.search(r"(?m)^module[ \t]++(\S{1,300}+)", text)
            if match:
                found.append(("go", match.group(1)))
        elif name == "pom.xml":
            body = re.sub(r"(?s)<parent>.*?</parent>|<dependencies>.*|<!--.*?-->", "", text[:200_000])
            group = re.search(r"<groupId>([^<]{1,200}+)</groupId>", body)
            artifact = re.search(r"<artifactId>([^<]{1,200}+)</artifactId>", body)
            if artifact:
                found.append(("maven", f"{group.group(1).strip()}:{artifact.group(1).strip()}" if group else artifact.group(1).strip()))
        elif name.startswith("settings.gradle"):
            match = re.search(r"rootProject\.name[ \t]*+=[ \t]*+[\"']([^\"'\n]{1,200}+)[\"']", text)
            if match:
                found.append(("gradle", match.group(1)))
        elif name.endswith(".csproj"):
            match = re.search(r"<PackageId>([^<]{1,200}+)</PackageId>", text) or re.search(
                r"<AssemblyName>([^<]{1,200}+)</AssemblyName>", text)
            found.append(("nuget", match.group(1).strip() if match else PurePosixPath(path.replace("\\", "/")).stem))
        elif name.endswith(".gemspec"):
            match = re.search(r"\.name[ \t]*+=[ \t]*+[\"']([^\"'\n]{1,200}+)[\"']", text)
            if match:
                found.append(("rubygems", match.group(1)))
        for ecosystem, package in found:
            code_facts.emit_fact("package_name", package, ecosystem=ecosystem)
