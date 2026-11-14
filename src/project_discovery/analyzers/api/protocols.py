"""Protocol endpoints: JSON-RPC, SOAP, WebSocket, Server-Sent Events, webhooks, MQTT and
message-driven endpoints in code, and the AsyncAPI, OpenRPC and OpenAPI webhook documents that
describe them.

Contracts are recognized by content, not by file name: a YAML or JSON file whose top-level
``asyncapi``, ``openrpc`` or ``openapi`` key holds a version. AsyncAPI 2.x and 3.0 documents are
read for their servers and protocols, channels (addresses), operations (2.x ``publish`` and
``subscribe``, 3.0 ``send`` and ``receive``) and messages; OpenRPC documents for their methods,
parameters and results; OpenAPI 3.1 documents for the webhooks the API sends. ``serverless.yml``
and Azure ``function.json`` files are read for the queues, topics, streams and WebSocket routes
their functions are triggered by.

In code, by protocol and framework: the JSON-RPC methods servers register and the requests
clients send; SOAP services and operations and their clients; WebSocket endpoints, hubs,
channels and message handlers, and the URLs clients open; Server-Sent Events streams and
EventSource clients; webhook receivers, by the provider signature checks they make, and the
incoming-webhook services code posts to (named by service, never by URL: the token is in it);
MQTT topics subscribed to and published with their QoS, and broker addresses; and message-driven
endpoints: the queues, topics and channels listeners consume, task, job and actor handlers, and
the triggers serverless functions declare. Forms ordinary code also uses count only in files that
import the framework. URLs keep their scheme, host, port and a path template; credentials,
queries and opaque path segments are removed. Nothing is connected to or called.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, over_limit
from ...core.safe_parsers import UnsafeDocumentError, safe_yaml_load
from ...core.source_utils import (
    SourceBudgetExceeded,
    describe_error,
    open_verified_binary,
    read_text_bounded,
)
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer
from .integration import _normalize_url
from .rpc import _Lines

MAX_PROTOCOL_BYTES = 16 * 1024 * 1024
MAX_PROTOCOL_EVIDENCE = 100
MAX_PROTOCOL_FACTS = 1000
_HEAD_BYTES = 8192

_PY = frozenset({".py"})
_JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_JVM = frozenset({".java", ".kt", ".kts", ".scala", ".groovy"})
_CS = frozenset({".cs"})
_GO = frozenset({".go"})
_RUST = frozenset({".rs"})
_RUBY = frozenset({".rb"})
_PHP = frozenset({".php"})
_ELIXIR = frozenset({".ex", ".exs"})
_C = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".ino"})
_CODE = _PY | _JS | _JVM | _CS | _GO | _RUST | _RUBY | _PHP | _ELIXIR | _C
_DATA = frozenset({".json", ".yaml", ".yml"})

# --------------------------------------------------------------------------- contracts

_CONTRACT_KEY = re.compile(r'''(?:^|[{,\n])[ \t]*+["']?(asyncapi|openrpc|openapi)["']?[ \t]*+:[ \t]*+["']?(\d[\w.-]{0,20})''')
_SERVERLESS_NAMES = frozenset({"serverless.yml", "serverless.yaml"})
# serverless.yml event types that are message-driven endpoints, with the key that names them.
_SERVERLESS_EVENTS = {"sqs": "arn", "sns": "topicName", "kafka": "topic", "msk": "topic", "stream": "arn",
                      "rabbitmq": "queue", "activemq": "queue", "eventBridge": "eventBus", "iot": "sql",
                      "s3": "bucket", "websocket": "route"}
_AZURE_NAME_KEYS = ("queueName", "topicName", "eventHubName", "topic", "path", "subscriptionName")


def _message_names(value) -> list[str]:
    """The message names an AsyncAPI ``message``/``messages`` value gives: references, names, oneOf."""
    if isinstance(value, list):
        return [name for item in value[:50] for name in _message_names(item)]
    if not isinstance(value, dict):
        return []
    if isinstance(value.get("$ref"), str):
        return [value["$ref"].rsplit("/", 1)[-1]]
    if isinstance(value.get("oneOf"), list):
        return _message_names(value["oneOf"])
    if isinstance(value.get("name"), str):
        return [value["name"]]
    if "payload" in value or "headers" in value:
        return []
    return [str(key) for key in list(value)[:50]]  # a 3.0 channel's messages map


def asyncapi_channels(data: dict) -> tuple[str, list[dict], list[dict]]:
    """(version, servers, channels) of an AsyncAPI 2.x or 3.0 document. Each channel has its
    address, actions (2.x publish/subscribe, 3.0 send/receive), operations and messages."""
    version = str(data.get("asyncapi", ""))
    three = version.startswith("3")
    servers = []
    raw_servers = data.get("servers")
    for name, server in (list(raw_servers.items())[:200] if isinstance(raw_servers, dict) else []):
        if isinstance(server, dict):
            servers.append({"name": str(name), "protocol": str(server.get("protocol", "")),
                            "host": safe_target(str(server.get("host") or server.get("url") or ""))})
    raw_channels = data.get("channels")
    channels: dict[str, dict] = {}
    for key, channel in (list(raw_channels.items())[:MAX_PROTOCOL_FACTS] if isinstance(raw_channels, dict) else []):
        if not isinstance(channel, dict):
            continue
        address = channel.get("address", key) if three else key
        entry = channels.setdefault(str(key), {"address": str(key if address is None else address), "actions": [],
                                               "operations": [], "messages": []})
        if three:
            entry["messages"] += _message_names(channel.get("messages"))
            continue
        for action in ("publish", "subscribe"):
            operation = channel.get(action)
            if isinstance(operation, dict):
                entry["actions"].append(action)
                if operation.get("operationId"):
                    entry["operations"].append(str(operation["operationId"]))
                entry["messages"] += _message_names(operation.get("message"))
    operations = data.get("operations")
    for key, operation in (list(operations.items())[:MAX_PROTOCOL_FACTS] if three and isinstance(operations, dict) else []):
        if not isinstance(operation, dict) or not isinstance(operation.get("channel"), dict):
            continue
        reference = str(operation["channel"].get("$ref", ""))
        entry = channels.get(reference.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~"))
        if entry is not None:
            entry["actions"].append(str(operation.get("action", "")))
            entry["operations"].append(str(key))
    return version, servers, list(channels.values())


def openrpc_methods(data: dict) -> list[tuple[str, list[str], str]]:
    """(name, parameter names, result name) of an OpenRPC document's methods."""
    methods = data.get("methods")
    found = []
    for method in (methods[:MAX_PROTOCOL_FACTS] if isinstance(methods, list) else []):
        if isinstance(method, dict) and isinstance(method.get("name"), str):
            params = method.get("params")
            names = [str(item.get("name")) for item in params if isinstance(item, dict) and item.get("name")] \
                if isinstance(params, list) else []
            result = method.get("result")
            found.append((method["name"], names[:20], str(result.get("name", "")) if isinstance(result, dict) else ""))
    return found


def openapi_webhooks(data: dict) -> list[tuple[str, list[str]]]:
    """(name, HTTP methods) of the webhooks an OpenAPI 3.1 document says the API sends."""
    webhooks = data.get("webhooks")
    return [(str(name), sorted(method.upper() for method in item if method in
                               {"get", "put", "post", "delete", "options", "head", "patch", "trace"}))
            for name, item in (list(webhooks.items())[:MAX_PROTOCOL_FACTS] if isinstance(webhooks, dict) else [])
            if isinstance(item, dict)]


def serverless_events(data: dict) -> list[tuple[str, str, str]]:
    """(function, event type, name) of the message and WebSocket events serverless.yml functions declare."""
    functions = data.get("functions")
    found = []
    for function, spec in (list(functions.items())[:MAX_PROTOCOL_FACTS] if isinstance(functions, dict) else []):
        events = spec.get("events") if isinstance(spec, dict) else None
        for event in (events[:100] if isinstance(events, list) else []):
            if not isinstance(event, dict):
                continue
            for kind, value in event.items():
                if kind not in _SERVERLESS_EVENTS:
                    continue
                if isinstance(value, dict):
                    value = value.get(_SERVERLESS_EVENTS[kind]) or value.get("arn") or value.get("queue") or ""
                name = value if isinstance(value, str) else ""
                if kind in {"sqs", "sns", "stream"} and name.startswith("arn:"):
                    name = name.rsplit(":", 1)[-1].rsplit("/", 1)[-1]  # the queue, topic or stream's name
                found.append((str(function), kind, name))
    return found


def azure_bindings(data: dict) -> list[tuple[str, str, str]]:
    """(binding type, direction, name) of an Azure Functions function.json's message bindings."""
    bindings = data.get("bindings")
    found = []
    for binding in (bindings[:100] if isinstance(bindings, list) else []):
        if not isinstance(binding, dict) or not isinstance(binding.get("type"), str):
            continue
        kind = binding["type"]
        if kind.lower().startswith(("http", "timer")) or kind == "orchestrationTrigger":
            continue
        name = next((str(binding[key]) for key in _AZURE_NAME_KEYS if binding.get(key)), "")
        found.append((kind, str(binding.get("direction", "in")), name))
    return found


# ------------------------------------------------------------------------------- code

_URL = re.compile(r"(?P<scheme>[A-Za-z][\w+.-]{0,20})://(?:[^@/\s]{0,200}@)?(?P<host>[^/:?#\s]{1,253})(?::(?P<port>\d{1,5}))?")


def safe_target(value: str) -> str:
    """A URL as evidence keeps its scheme, host, port and a path template: never credentials,
    queries or opaque path segments. Paths, topics and names are returned as they are."""
    match = _URL.match(value)
    if not match:
        return value
    scheme, port = match.group("scheme").lower(), match.group("port")
    address = f"{scheme}://{match.group('host').lower()}" + (f":{port}" if port else "")
    if scheme in {"http", "https", "ws", "wss"}:
        _, route = _normalize_url(value)
        return address + (route if route != "/" else "")
    return address


# Imports that must be present before forms ordinary code also uses count.
_JSONRPCSERVER = re.compile(r"\bjsonrpcserver\b")
_PY_JSONRPC = re.compile(r"\bjsonrpc\b")
_JSONRPCLIB = re.compile(r"\bjsonrpclib\b|SimpleJSONRPCServer")
_FASTAPI_JSONRPC = re.compile(r"\bfastapi_jsonrpc\b")
_MODERNRPC = re.compile(r"\bmodernrpc\b")
_JSONRPC2 = re.compile(r"json-rpc-2\.0")
_JSONRPSEE = re.compile(r"\bjsonrpsee\b")
_JSONRPC_CORE = re.compile(r"\bjsonrpc_core\b|\bjsonrpc_http_server\b")
_GORILLA_RPC = re.compile(r"gorilla/rpc")
_PHP_JSONRPC = re.compile(r"JsonRPC\\\\?Server|fguillot")
_SPRING_WS = re.compile(r"springframework\.ws\b")
_JAXWS = re.compile(r"\b(?:javax|jakarta)\.xml\.ws\b")
_SPYNE = re.compile(r"\bspyne\b")
_ZEEP = re.compile(r"\bzeep\b|\bsuds\b")
_SOAP_SERVER = re.compile(r"\bSoapServer\b")
_NODE_SOAP = re.compile(r"""(?:require\s*+\(\s*+|from\s++)["']soap["']""")
_WASH_OUT = re.compile(r"\bwash_out\b|\bsoap_service\b")
_SPRING_WEBSOCKET = re.compile(r"\bWebSocketHandlerRegistry\b|@EnableWebSocket\b")
_SPRING_STOMP = re.compile(r"\bStompEndpointRegistry\b|@EnableWebSocketMessageBroker\b")
_MESSAGE_MAPPING = re.compile(r"@MessageMapping\b")
_FLASK_SOCK = re.compile(r"\bflask_sock\b")
_TORNADO = re.compile(r"\btornado\b")
_AIOHTTP = re.compile(r"\baiohttp\b")
_PY_SOCKETIO = re.compile(r"\bsocketio\b")
_WS_JS = re.compile(r"""(?:require\s*+\(\s*+|from\s++)["']ws["']""")
_EXPRESS_WS = re.compile(r"express-ws|uWebSockets|\buws\b")
_SOCKET_IO = re.compile(r"""["']socket\.io["']""")
_SOCKET_IO_CLIENT = re.compile(r"socket\.io-client")
_SIGNALR_JS = re.compile(r"@microsoft/signalr")
_GORILLA_WS = re.compile(r"gorilla/websocket")
_GO_WS_ACCEPT = re.compile(r"nhooyr\.io/websocket|coder/websocket")
_SIGNALR_CLIENT = re.compile(r"\bHubConnectionBuilder\b")
_AXUM = re.compile(r"\baxum\b")
_ACTIX_WS = re.compile(r"\bactix_web_actors\b|\bactix_ws\b")
_TUNGSTENITE = re.compile(r"tungstenite")
_SLACK_SDK = re.compile(r"\bslack_sdk\b|@slack/")
_TWILIO = re.compile(r"(?i)\btwilio\b")
_SVIX = re.compile(r"\bsvix\b|standardwebhooks")
_PAHO = re.compile(r"\bpaho\b")
_MQTT_JS = re.compile(r"""(?:require\s*+\(\s*+|from\s++)["'](?:mqtt|async-mqtt)["']""")
_PAHO_JAVA = re.compile(r"org\.eclipse\.paho")
_PAHO_GO = re.compile(r"paho\.mqtt\.golang")
_ESP_MQTT = re.compile(r"\besp_mqtt")
_PUBSUBCLIENT = re.compile(r"\bPubSubClient\b")
_RUMQTTC = re.compile(r"\brumqttc\b")
_MQTTNET = re.compile(r"\bMQTTnet\b")
_CELERY = re.compile(r"\bcelery\b")
_FAUST = re.compile(r"\bfaust\b")
_CONFLUENT_PY = re.compile(r"\bconfluent_kafka\b")
_AZURE_PY = re.compile(r"\bazure\.functions\b")
_BULLMQ = re.compile(r"""\bbullmq\b|["']bull["']""")
_AZURE_JS = re.compile(r"@azure/functions")
_FIREBASE = re.compile(r"firebase-functions")
_CONFLUENT_CS = re.compile(r"\bConfluent\.Kafka\b")
_WATERMILL = re.compile(r"\bwatermill\b")
_SARAMA = re.compile(r"\bsarama\b")
_CONFLUENT_GO = re.compile(r"confluent-kafka-go")
_KARAFKA = re.compile(r"\bKarafka\b|\bkarafka\b")
_MICRONAUT_KAFKA = re.compile(r"\bio\.micronaut\.configuration\.kafka\b|@KafkaListener\b|@KafkaClient\b")

_Q = r"""["'`]"""
_NAME = r"""(?P<name>[^"'`\n]{1,200})"""
_PATH = r"""(?P<name>/[^"'`\n]{0,200})"""
_METHOD = r"(?P<name>[\w.$/:-]{1,120})"
# A decorator's function: the def on the next line, after up to four more decorators.
_DEF = r"[ \t]*+\r?\n(?:[ \t]*+@[^\n]{0,200}\r?\n){0,4}[ \t]*+(?:async[ \t]++)?def[ \t]++(?P<fn>\w{1,120})"
_ALL = _CODE

# (protocol, framework, role, what, pattern, extensions, import the file must hold). Name
# groups, in order of preference: name or name2; names in "args"; the function "fn"; the
# declaration after the match ("after", an empty group); the enclosing class ("before").
# A "client" group that matched makes the role client; "qos" is an MQTT QoS.
_ENDPOINTS = (
    # JSON-RPC
    ("JSON-RPC", "jsonrpcserver", "server", "method", re.compile(
        r"@method\b(?:[ \t]*+\([ \t]*+name[ \t]*+=[ \t]*+[\"'](?P<name>[\w.$/:-]{1,120})[\"'][ \t]*+\))?" + _DEF), _PY,
     _JSONRPCSERVER),
    ("JSON-RPC", "json-rpc (Python)", "server", "method", re.compile(
        r"@(?:\w{1,40}\.)?add_method\b(?:[ \t]*+\([^)\n]{0,200}\))?" + _DEF), _PY, _PY_JSONRPC),
    ("JSON-RPC", "json-rpc (Python)", "server", "method", re.compile(
        r"\.add_method\s*+\(\s*+(?P<fn>[\w.]{1,120})\s*+(?:,\s*+name\s*+=\s*+[\"'](?P<name>[\w.$/:-]{1,120})[\"'])?"),
     _PY, _PY_JSONRPC),
    ("JSON-RPC", "jsonrpclib", "server", "method", re.compile(
        r"\.register_function\s*+\(\s*+(?P<fn>[\w.]{1,120})(?:\s*+,\s*+(?:name\s*+=\s*+)?[\"'](?P<name>[\w.$/:-]{1,120})[\"'])?"),
     _PY, _JSONRPCLIB),
    ("JSON-RPC", "fastapi-jsonrpc", "server", "method", re.compile(r"@\w{1,40}\.method\s*+\([^)\n]{0,200}\)" + _DEF), _PY,
     _FASTAPI_JSONRPC),
    ("JSON-RPC", "django-modern-rpc", "server", "method", re.compile(r"@rpc_method\b[^\n]{0,200}" + _DEF), _PY, _MODERNRPC),
    ("JSON-RPC", "json-rpc-2.0", "server", "method", re.compile(r"\.addMethod(?:Advanced)?\s*+\(\s*+" + _Q + _METHOD + _Q),
     _JS, _JSONRPC2),
    ("JSON-RPC", "jsonrpc4j", "server", "endpoint", re.compile(
        r"@JsonRpcService\s*+\(\s*+(?:value\s*+=\s*+)?\"(?P<name>[^\"\n]{1,200})\""), _JVM, None),
    ("JSON-RPC", "Java JSON-RPC", "server", "method", re.compile(
        r"@JsonRpcMethod\s*+\(\s*+(?:value\s*+=\s*+)?\"" + _METHOD + "\""), _JVM, None),
    ("JSON-RPC", "StreamJsonRpc", "server", "method", re.compile(r"\[JsonRpcMethod\s*+\(\s*+\"" + _METHOD + "\""), _CS, None),
    ("JSON-RPC", "StreamJsonRpc", "server", "endpoint", re.compile(r"\bJsonRpc\.Attach\s*+\("), _CS, None),
    ("JSON-RPC", "jsonrpsee", "server", "method", re.compile(
        r"#\[(?:method|subscription)\s*+\(\s*+name\s*+=\s*+\"" + _METHOD + "\""), _RUST, _JSONRPSEE),
    ("JSON-RPC", "jsonrpc-core", "server", "method", re.compile(r"\.add_(?:sync_)?method\s*+\(\s*+\"" + _METHOD + "\""),
     _RUST, _JSONRPC_CORE),
    ("JSON-RPC", "gorilla/rpc", "server", "service", re.compile(
        r"\.RegisterService\s*+\(\s*+new\s*+\(\s*+(?P<name>\w{1,120})\s*+\)"), _GO, _GORILLA_RPC),
    ("JSON-RPC", "JsonRPC (PHP)", "server", "method", re.compile(
        r"->with(?:Callback|ClassAndMethod)\s*+\(\s*+[\"']" + _METHOD + "[\"']"), _PHP, _PHP_JSONRPC),
    ("JSON-RPC", "JSON-RPC request", "client", "call", re.compile(
        r"[\"']?jsonrpc[\"']?\s*+[:=]\s*+[\"']2\.0[\"']\s*+,\s*+(?:[\"']?id[\"']?\s*+[:=]\s*+[\w\"'-]{1,40}\s*+,\s*+)?"
        r"[\"']?method[\"']?\s*+[:=]\s*+[\"']" + _METHOD + "[\"']"), _ALL, None),
    ("JSON-RPC", "JSON-RPC request", "client", "call", re.compile(
        r"[\"']?method[\"']?\s*+[:=]\s*+[\"']" + _METHOD + r"[\"']\s*+,\s*+(?:[\"']?id[\"']?\s*+[:=]\s*+[\w\"'-]{1,40}\s*+,"
        r"\s*+)?[\"']?jsonrpc[\"']?\s*+[:=]\s*+[\"']2\.0[\"']"), _ALL, None),
    # SOAP
    ("SOAP", "JAX-WS", "server", "service", re.compile(r"@WebService\b(?:\s*+\((?P<args>[^)]{0,500})\))?(?P<after>)"), _JVM,
     None),
    ("SOAP", "JAX-WS", "server", "operation", re.compile(r"@WebMethod\b(?:\s*+\((?P<args>[^)]{0,300})\))?(?P<after>)"),
     _JVM, None),
    ("SOAP", "JAX-WS", "server", "endpoint", re.compile(r"\bEndpoint\.publish\s*+\(\s*+\"(?P<name>[^\"\n]{1,300})\""), _JVM,
     None),
    ("SOAP", "Spring-WS", "server", "operation", re.compile(r"@PayloadRoot\s*+\((?P<args>[^)]{0,500})\)"), _JVM, None),
    ("SOAP", "JAX-WS", "client", "client", re.compile(r"@WebServiceClient\b(?:\s*+\((?P<args>[^)]{0,500})\))?"), _JVM, None),
    ("SOAP", "JAX-WS", "client", "client", re.compile(r"\bService\.create\s*+\("), _JVM, _JAXWS),
    ("SOAP", "Spring-WS", "client", "client", re.compile(
        r"\bmarshalSendAndReceive\s*+\(|\bextends\s++WebServiceGatewaySupport\b"), _JVM, _SPRING_WS),
    ("SOAP", "WCF", "server", "service", re.compile(r"\[ServiceContract\b[^\]\n]{0,300}\](?P<after>)"), _CS, None),
    ("SOAP", "WCF", "server", "operation", re.compile(r"\[OperationContract\b[^\]\n]{0,300}\](?P<after>)"), _CS, None),
    ("SOAP", "ASP.NET Web Services", "server", "operation", re.compile(r"\[WebMethod\b[^\]\n]{0,300}\](?P<after>)"), _CS,
     None),
    ("SOAP", "CoreWCF", "server", "endpoint", re.compile(
        r"\.AddServiceEndpoint\s*+<[^>\n]{1,250}>\s*+\([^;\n]{0,300}?\"(?P<name>/[^\"\n]{0,200})\""), _CS, None),
    ("SOAP", "WCF", "client", "client", re.compile(  # not gRPC's grpc::ClientBase<T>
        r"(?<![:.\w])(?:ClientBase|ChannelFactory)\s*+<\s*+(?P<name>\w{1,120})\s*+>"), _CS, None),
    ("SOAP", "spyne", "server", "service", re.compile(r"\bclass\s++(?P<name>\w{1,120})\s*+\(\s*+ServiceBase\s*+\)"), _PY,
     _SPYNE),
    ("SOAP", "spyne", "server", "operation", re.compile(r"@rpc\s*+\([^\n]{0,300}\)" + _DEF), _PY, _SPYNE),
    ("SOAP", "zeep/suds", "client", "client", re.compile(
        r"(?<![\w.])(?:zeep\.|suds\.client\.)?Client\s*+\(\s*+(?:wsdl\s*+=\s*+)?[\"'](?P<name>[^\"'\n]{1,300})[\"']"), _PY,
     _ZEEP),
    ("SOAP", "PHP SOAP", "server", "service", re.compile(
        r"\bnew\s++\\?SoapServer\s*+\((?:\s*+[\"'](?P<name>[^\"'\n]{1,300})[\"'])?"), _PHP, None),
    ("SOAP", "PHP SOAP", "server", "operation", re.compile(r"->addFunction\s*+\(\s*+[\"'](?P<name>\w{1,120})[\"']"), _PHP,
     _SOAP_SERVER),
    ("SOAP", "PHP SOAP", "client", "client", re.compile(
        r"\bnew\s++\\?SoapClient\s*+\((?:\s*+[\"'](?P<name>[^\"'\n]{1,300})[\"'])?"), _PHP, None),
    ("SOAP", "node-soap", "server", "endpoint", re.compile(r"\bsoap\.listen\s*+\(\s*+\w{1,60}\s*+,\s*+" + _Q + _PATH + _Q),
     _JS, _NODE_SOAP),
    ("SOAP", "node-soap", "client", "client", re.compile(
        r"\bsoap\.createClient(?:Async)?\s*+\((?:\s*+" + _Q + _NAME + _Q + ")?"), _JS, _NODE_SOAP),
    ("SOAP", "Savon", "client", "client", re.compile(r"\bSavon\.client\s*+\("), _RUBY, None),
    ("SOAP", "WashOut", "server", "operation", re.compile(r"\bsoap_action\s++[\"':](?P<name>\w{1,120})"), _RUBY, _WASH_OUT),
    # WebSocket: Java, Kotlin, Scala
    ("WebSocket", "Jakarta WebSocket", "server", "endpoint", re.compile(
        r"@ServerEndpoint\s*+\(\s*+(?:value\s*+=\s*+)?\"(?P<name>[^\"\n]{1,200})\""), _JVM, None),
    ("WebSocket", "Spring WebSocket", "server", "endpoint", re.compile(
        r"\.addHandler\s*+\(\s*+[^,;\n]{1,200}?,\s*+\"(?P<name>/[^\"\n]{0,200})\""), _JVM, _SPRING_WEBSOCKET),
    ("WebSocket", "Spring STOMP", "server", "endpoint", re.compile(r"\.addEndpoint\s*+\(\s*+\"(?P<name>/[^\"\n]{0,200})\""),
     _JVM, _SPRING_STOMP),
    ("WebSocket", "Spring messaging", "server", "message", re.compile(
        r"@MessageMapping\s*+\(\s*+(?:value\s*+=\s*+)?\"(?P<name>[^\"\n]{1,200})\""), _JVM, None),
    ("WebSocket", "Spring messaging", "produce", "destination", re.compile(  # Kafka listeners use @SendTo too
        r"@SendTo(?:User)?\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _JVM, _MESSAGE_MAPPING),
    ("WebSocket", "Micronaut", "server", "endpoint", re.compile(r"@ServerWebSocket\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""),
     _JVM, None),
    ("WebSocket", "Micronaut", "client", "client", re.compile(r"@ClientWebSocket\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""),
     _JVM, None),
    ("WebSocket", "Java WebSocket client", "client", "client", re.compile(
        r"\bnewWebSocketBuilder\s*+\(|\bnew\s++StandardWebSocketClient\s*+\(|\.connectToServer\s*+\("), _JVM, None),
    # WebSocket: Python
    ("WebSocket", "FastAPI/Starlette/Quart/Sanic", "server", "endpoint", re.compile(
        r"@\w{1,40}\.websocket(?:_route)?\s*+\(\s*+[\"']" + _PATH + "[\"']"), _PY, None),
    ("WebSocket", "Starlette", "server", "endpoint", re.compile(r"\bWebSocketRoute\s*+\(\s*+[\"']" + _PATH + "[\"']"), _PY,
     None),
    ("WebSocket", "Flask-Sock", "server", "endpoint", re.compile(r"@sock\.route\s*+\(\s*+[\"']" + _PATH + "[\"']"), _PY,
     _FLASK_SOCK),
    ("WebSocket", "Django Channels", "server", "endpoint", re.compile(
        r"\b(?:re_)?path\s*+\(\s*+r?[\"'](?P<name>[^\"'\n]{1,200})[\"']\s*+,\s*+[\w.]{1,120}\.as_asgi\s*+\("), _PY, None),
    ("WebSocket", "websockets", "server", "server", re.compile(r"\bwebsockets\.(?:serve|server\.serve)\s*+\("), _PY, None),
    ("WebSocket", "Tornado", "server", "handler", re.compile(
        r"\bclass\s++(?P<name>\w{1,120})\s*+\(\s*+(?:tornado\.websocket\.)?WebSocketHandler\s*+\)"), _PY, _TORNADO),
    ("WebSocket", "aiohttp", "server", "handler", re.compile(r"\bweb\.WebSocketResponse\s*+\(" + "(?P<before>)"), _PY,
     _AIOHTTP),
    ("WebSocket", "python-socketio", "server", "event", re.compile(r"@\w{1,40}\.on\s*+\(\s*+[\"']" + _NAME + "[\"']"), _PY,
     _PY_SOCKETIO),
    ("WebSocket", "Python WebSocket client", "client", "client", re.compile(
        r"\b(?:websockets\.connect|websocket\.create_connection|websocket\.WebSocketApp|ws_connect)\s*+\(\s*+"
        r"[\"'](?P<name>wss?://[^\"'\n]{1,300})[\"']"), _PY, None),
    # WebSocket: JavaScript and TypeScript
    ("WebSocket", "ws", "server", "server", re.compile(
        r"\bnew\s++(?:WebSocket\.|ws\.)?(?:WebSocketServer|Server)\s*+\(\s*+\{(?P<args>[^{}]{0,400})"), _JS, _WS_JS),
    ("WebSocket", "NestJS", "server", "gateway", re.compile(r"@WebSocketGateway\s*+\((?P<args>[^)\n]{0,300})\)"), _JS, None),
    ("WebSocket", "NestJS", "server", "message", re.compile(r"@SubscribeMessage\s*+\(\s*+" + _Q + _NAME + _Q), _JS, None),
    ("WebSocket", "express-ws/uWebSockets.js", "server", "endpoint", re.compile(r"\.ws\s*+\(\s*+" + _Q + _PATH + _Q), _JS,
     _EXPRESS_WS),
    ("WebSocket", "Fastify", "server", "endpoint", re.compile(
        r"\.get\s*+\(\s*+" + _Q + _PATH + _Q + r"\s*+,\s*+\{\s*+websocket\s*+:\s*+true\b"), _JS, None),
    ("WebSocket", "Hono", "server", "endpoint", re.compile(
        r"\.get\s*+\(\s*+" + _Q + _PATH + _Q + r"\s*+,\s*+upgradeWebSocket\b"), _JS, None),
    ("WebSocket", "Socket.IO", "server", "server", re.compile(
        r"""\brequire\s*+\(\s*+["']socket\.io["']\s*+\)\s*+\(|\bnew\s++(?:SocketIO)?Server\s*+\((?!\s*+\{)"""), _JS,
     _SOCKET_IO),
    ("WebSocket", "Socket.IO", "server", "namespace", re.compile(r"\bio\.of\s*+\(\s*+" + _Q + _PATH + _Q), _JS, _SOCKET_IO),
    ("WebSocket", "Bun", "server", "server", re.compile(r"\bBun\.serve\s*+\(\s*+\{[^}]{0,2000}?\bwebsocket\s*+:"), _JS, None),
    ("WebSocket", "Deno", "server", "server", re.compile(r"\bDeno\.upgradeWebSocket\s*+\("), _JS, None),
    ("WebSocket", "SignalR", "client", "client", re.compile(r"\.withUrl\s*+\(\s*+" + _Q + _NAME + _Q), _JS, _SIGNALR_JS),
    ("WebSocket", "WebSocket API", "client", "client", re.compile(
        r"\bnew\s++WebSocket\s*+\(\s*+" + _Q + r"(?P<name>(?:wss?://|/)[^\"'`\n]{0,300})" + _Q), _JS, None),
    ("WebSocket", "Socket.IO", "client", "client", re.compile(
        r"\bio\s*+\(\s*+" + _Q + r"(?P<name>(?:https?://|wss?://|/)[^\"'`\n]{0,300})" + _Q), _JS, _SOCKET_IO_CLIENT),
    # WebSocket: Go (routes to handlers that upgrade are found separately), C#, Rust, Elixir, Ruby, PHP
    ("WebSocket", "gorilla/websocket", "server", "upgrade", re.compile(
        r"\.Upgrade\s*+\(\s*+\w{1,40}\s*+,\s*+\w{1,40}\s*+,"), _GO, _GORILLA_WS),
    ("WebSocket", "golang.org/x/net/websocket", "server", "endpoint", re.compile(
        r"\bhttp\.Handle\s*+\(\s*+\"(?P<name>/[^\"\n]{0,200})\"\s*+,\s*+websocket\.Handler\s*+\("), _GO, None),
    ("WebSocket", "coder/websocket", "server", "upgrade", re.compile(r"\bwebsocket\.Accept\s*+\("), _GO, _GO_WS_ACCEPT),
    ("WebSocket", "Go WebSocket client", "client", "client", re.compile(
        r"\bwebsocket\.(?:DefaultDialer\.Dial(?:Context)?|Dial)\s*+\(\s*+(?:\w{1,40}\s*+,\s*+)?\"(?P<name>wss?://[^\"\n]{1,300})\""),
     _GO, None),
    ("WebSocket", "SignalR", "server", "endpoint", re.compile(
        r"\.MapHub\s*+<\s*+\w{1,120}\s*+>\s*+\(\s*+\"(?P<name>/[^\"\n]{0,200})\""), _CS, None),
    ("WebSocket", "SignalR", "server", "hub", re.compile(
        r"\bclass\s++(?P<name>\w{1,120})\s*+:\s*+Hub(?:\s*+<\s*+\w{1,120}\s*+>)?\b"), _CS, None),
    ("WebSocket", "ASP.NET Core", "server", "upgrade", re.compile(r"\.AcceptWebSocketAsync\s*+\("), _CS, None),
    ("WebSocket", ".NET WebSocket client", "client", "client", re.compile(
        r"\.ConnectAsync\s*+\(\s*+new\s++Uri\s*+\(\s*+\"(?P<name>wss?://[^\"\n]{1,300})\""), _CS, None),
    ("WebSocket", "SignalR", "client", "client", re.compile(r"\.WithUrl\s*+\(\s*+\"(?P<name>[^\"\n]{1,300})\""), _CS,
     _SIGNALR_CLIENT),
    ("WebSocket", "actix", "server", "upgrade", re.compile(r"\b(?:ws::start|actix_ws::handle)\s*+\("), _RUST, _ACTIX_WS),
    ("WebSocket", "warp", "server", "upgrade", re.compile(r"\bwarp::ws\s*+\(\s*+\)"), _RUST, None),
    ("WebSocket", "tokio-tungstenite", "server", "upgrade", re.compile(r"\baccept_(?:hdr_)?async\s*+\("), _RUST,
     _TUNGSTENITE),
    ("WebSocket", "tokio-tungstenite", "client", "client", re.compile(
        r"\bconnect_async\s*+\(\s*+\"(?P<name>wss?://[^\"\n]{1,300})\""), _RUST, _TUNGSTENITE),
    ("WebSocket", "Phoenix", "server", "endpoint", re.compile(r"\bsocket\s++\"(?P<name>/[^\"\n]{0,200})\"\s*+,\s*+[A-Z][\w.]{0,200}"),
     _ELIXIR, None),
    ("WebSocket", "Phoenix", "server", "channel", re.compile(r"\bchannel\s++\"(?P<name>[^\"\n]{1,200})\"\s*+,\s*+[A-Z][\w.]{0,200}"),
     _ELIXIR, None),
    ("WebSocket", "Action Cable", "server", "channel", re.compile(
        r"\bclass\s++(?P<name>\w{1,120})\s*+<\s*+ApplicationCable::Channel\b"), _RUBY, None),
    ("WebSocket", "Action Cable", "server", "endpoint", re.compile(
        r"\bmount\s++ActionCable\.server\s*+=>\s*+[\"']" + _PATH + "[\"']"), _RUBY, None),
    ("WebSocket", "Ratchet", "server", "server", re.compile(r"\bnew\s++WsServer\s*+\("), _PHP, None),
    ("WebSocket", "Laravel broadcasting", "server", "channel", re.compile(r"\bBroadcast::channel\s*+\(\s*+[\"']" + _NAME + "[\"']"),
     _PHP, None),
    # Server-Sent Events
    ("SSE", "text/event-stream", "server", "stream", re.compile(
        r"(?P<client>[\"']?Accept[\"']?\s*+[:,=]\s*+)?[\"']text/event-stream[\"']"), _ALL, None),
    ("SSE", "Spring", "server", "stream", re.compile(
        r"@(?:Get|Post|Request)Mapping\s*+\([^()\n]{0,300}?\"(?P<name>/[^\"\n]{0,200})\"[^()\n]{0,300}?TEXT_EVENT_STREAM"),
     _JVM, None),
    ("SSE", "Spring", "server", "stream", re.compile(
        r"\bTEXT_EVENT_STREAM(?:_VALUE)?\b|\bnew\s++SseEmitter\s*+\(|\bServerSentEvent\s*+[<.]"), _JVM, None),
    ("SSE", "sse-starlette", "server", "stream", re.compile(r"\bEventSourceResponse\s*+\("), _PY, None),
    ("SSE", "NestJS", "server", "stream", re.compile(r"@Sse\s*+\(\s*+" + _Q + r"(?P<name>[^\"'`\n]{0,200})" + _Q), _JS, None),
    ("SSE", "Hono", "server", "stream", re.compile(r"\bstreamSSE\s*+\("), _JS, None),
    ("SSE", "ASP.NET Core", "server", "stream", re.compile(r"\b(?:TypedResults|Results)\.ServerSentEvents\s*+\("), _CS, None),
    ("SSE", "axum", "server", "stream", re.compile(r"\bSse::new\s*+\("), _RUST, _AXUM),
    ("SSE", "Rails", "server", "stream", re.compile(r"\bActionController::Live\b|\bSSE\.new\s*+\("), _RUBY, None),
    ("SSE", "EventSource", "client", "client", re.compile(
        r"\bnew\s++EventSource(?:Polyfill)?\s*+\(\s*+" + _Q + r"(?P<name>[^\"'`\n]{1,300})" + _Q), _JS, None),
    ("SSE", "Python SSE client", "client", "client", re.compile(r"\b(?:SSEClient|connect_sse|aconnect_sse)\s*+\("), _PY, None),
    # Webhook receivers, by the provider signature checks they make
    ("Webhook", "Stripe", "server", "receiver", re.compile(
        r"\bWebhook(?:\.|::)construct_?[Ee]vent\b|\bwebhooks\.constructEvent(?:Async)?\b|\bEventUtility\.ConstructEvent\b|"
        r"\bwebhook\.ConstructEvent(?:WithOptions)?\b|(?i:\bstripe-signature\b)"), _ALL, None),
    ("Webhook", "GitHub", "server", "receiver", re.compile(r"(?i)\bx-github-event\b|@octokit/webhooks"), _ALL, None),
    ("Webhook", "X-Hub-Signature (GitHub and others)", "server", "receiver", re.compile(r"(?i)\bx-hub-signature(?:-256)?\b"),
     _ALL, None),
    ("Webhook", "GitLab", "server", "receiver", re.compile(r"(?i)\bx-gitlab-(?:token|event)\b"), _ALL, None),
    ("Webhook", "Slack", "server", "receiver", re.compile(r"(?i)\bx-slack-signature\b"), _ALL, None),
    ("Webhook", "Slack", "server", "receiver", re.compile(r"\bSignatureVerifier\s*+\("), _ALL, _SLACK_SDK),
    ("Webhook", "Shopify", "server", "receiver", re.compile(r"(?i)\bx-shopify-hmac-sha256\b"), _ALL, None),
    ("Webhook", "Twilio", "server", "receiver", re.compile(r"(?i)\bx-twilio-signature\b"), _ALL, None),
    ("Webhook", "Twilio", "server", "receiver", re.compile(r"\bRequestValidator\s*+\("), _ALL, _TWILIO),
    ("Webhook", "SendGrid", "server", "receiver", re.compile(r"(?i)\bx-twilio-email-event-webhook-signature\b"), _ALL, None),
    ("Webhook", "Svix/Standard Webhooks", "server", "receiver", re.compile(r"(?i)\b(?:svix|webhook)-signature\b"), _ALL, None),
    ("Webhook", "Svix/Standard Webhooks", "server", "receiver", re.compile(r"\bnew\s++Webhook\s*+\("), _ALL, _SVIX),
    ("Webhook", "PayPal", "server", "receiver", re.compile(r"(?i)\bpaypal-transmission-sig\b|verify-webhook-signature"), _ALL,
     None),
    ("Webhook", "Paddle", "server", "receiver", re.compile(r"(?i)\bpaddle-signature\b"), _ALL, None),
    ("Webhook", "Square", "server", "receiver", re.compile(r"(?i)\bx-square-(?:hmacsha256-)?signature\b"), _ALL, None),
    ("Webhook", "Discord", "server", "receiver", re.compile(r"(?i)\bx-signature-ed25519\b"), _ALL, None),
    ("Webhook", "Linear", "server", "receiver", re.compile(r"(?i)\blinear-signature\b"), _ALL, None),
    ("Webhook", "Zoom", "server", "receiver", re.compile(r"(?i)\bx-zm-signature\b"), _ALL, None),
    ("Webhook", "Coinbase Commerce", "server", "receiver", re.compile(r"(?i)\bx-cc-webhook-signature\b"), _ALL, None),
    ("Webhook", "HMAC signature header", "server", "receiver", re.compile(r"(?i)\bx-(?:webhook|hook)-signature\b"), _ALL, None),
    # Incoming-webhook services code posts to, named by service: the URL holds the token.
    ("Webhook", "Slack incoming webhook", "client", "sender", re.compile(r"\bhooks\.slack\.com/(?:services|workflows|triggers)/"),
     _ALL, None),
    ("Webhook", "Discord webhook", "client", "sender", re.compile(r"\bdiscord(?:app)?\.com/api/webhooks/"), _ALL, None),
    ("Webhook", "Microsoft Teams incoming webhook", "client", "sender", re.compile(
        r"\.webhook\.office\.com/|\boutlook\.office(?:365)?\.com/webhook/"), _ALL, None),
    ("Webhook", "Google Chat webhook", "client", "sender", re.compile(r"\bchat\.googleapis\.com/v1/spaces/"), _ALL, None),
    ("Webhook", "DingTalk, WeCom or Feishu bot webhook", "client", "sender", re.compile(
        r"\boapi\.dingtalk\.com/robot/send|\bqyapi\.weixin\.qq\.com/cgi-bin/webhook/|\bopen\.(?:feishu\.cn|larksuite\.com)/"
        r"open-apis/bot/"), _ALL, None),
    # MQTT
    ("MQTT", "Eclipse Paho (Python)", "consume", "topic", re.compile(
        r"\.subscribe\s*+\(\s*+[\"']" + _NAME + r"[\"'](?:\s*+,\s*+(?:qos\s*+=\s*+)?(?P<qos>[012])\b)?"), _PY, _PAHO),
    ("MQTT", "Eclipse Paho (Python)", "produce", "topic", re.compile(
        r"\.publish\s*+\(\s*+[\"']" + _NAME + r"[\"'](?:[^)\n]{0,300}?\bqos\s*+=\s*+(?P<qos>[012])\b)?"), _PY, _PAHO),
    ("MQTT", "MQTT.js", "consume", "topic", re.compile(
        r"\.subscribe\s*+\(\s*+" + _Q + _NAME + _Q + r"(?:\s*+,\s*+\{\s*+qos\s*+:\s*+(?P<qos>[012]))?"), _JS, _MQTT_JS),
    ("MQTT", "MQTT.js", "produce", "topic", re.compile(
        r"\.publish\s*+\(\s*+" + _Q + _NAME + _Q + r"(?:[^)\n]{0,300}?\bqos\s*+:\s*+(?P<qos>[012]))?"), _JS, _MQTT_JS),
    ("MQTT", "MQTT.js", "client", "broker", re.compile(
        r"\bmqtt\.connect(?:Async)?\s*+\(\s*+" + _Q + r"(?P<name>(?:mqtts?|wss?|tcp|ssl)://[^\"'`\n]{1,300})" + _Q), _JS, None),
    ("MQTT", "Eclipse Paho (Java)", "consume", "topic", re.compile(
        r"\.subscribe\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"(?:\s*+,\s*+(?P<qos>[012])\b)?"), _JVM, _PAHO_JAVA),
    ("MQTT", "Eclipse Paho (Java)", "produce", "topic", re.compile(r"\.publish\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _JVM,
     _PAHO_JAVA),
    ("MQTT", "Eclipse Paho (Java)", "client", "broker", re.compile(
        r"\bnew\s++Mqtt(?:Async)?Client\s*+\(\s*+\"(?P<name>(?:tcp|ssl|ws|wss|mqtt|mqtts)://[^\"\n]{1,300})\""), _JVM, None),
    ("MQTT", "Spring Integration MQTT", "consume", "topic", re.compile(
        r"\bnew\s++Mqtt(?:Paho|v5)?MessageDrivenChannelAdapter\s*+\("), _JVM, None),
    ("MQTT", "Spring Integration MQTT", "produce", "topic", re.compile(r"\bnew\s++Mqtt(?:Paho|v5)?MessageHandler\s*+\("), _JVM,
     None),
    ("MQTT", "Eclipse Paho (Go)", "consume", "topic", re.compile(
        r"\.Subscribe\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"\s*+,\s*+(?P<qos>[012])\b"), _GO, _PAHO_GO),
    ("MQTT", "Eclipse Paho (Go)", "produce", "topic", re.compile(
        r"\.Publish\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"\s*+,\s*+(?P<qos>[012])\b"), _GO, _PAHO_GO),
    ("MQTT", "Eclipse Paho (Go)", "client", "broker", re.compile(
        r"\.AddBroker\s*+\(\s*+\"(?P<name>(?:tcp|ssl|ws|wss|mqtt|mqtts)://[^\"\n]{1,300})\""), _GO, None),
    ("MQTT", "Mosquitto", "consume", "topic", re.compile(
        r"\bmosquitto_subscribe\s*+\(\s*+[\w&>.-]{1,60}\s*+,\s*+[\w&>.-]{1,60}\s*+,\s*+\"(?P<name>[^\"\n]{1,200})\"\s*+,"
        r"\s*+(?P<qos>[012])\b"), _C, None),
    ("MQTT", "Mosquitto", "produce", "topic", re.compile(
        r"\bmosquitto_publish\s*+\(\s*+[\w&>.-]{1,60}\s*+,\s*+[\w&>.-]{1,60}\s*+,\s*+\"(?P<name>[^\"\n]{1,200})\""), _C, None),
    ("MQTT", "ESP-MQTT", "consume", "topic", re.compile(
        r"\besp_mqtt_client_subscribe(?:_single)?\s*+\(\s*+[\w&>.-]{1,60}\s*+,\s*+\"(?P<name>[^\"\n]{1,200})\"\s*+,"
        r"\s*+(?P<qos>[012])\b"), _C, None),
    ("MQTT", "ESP-MQTT", "produce", "topic", re.compile(
        r"\besp_mqtt_client_(?:publish|enqueue)\s*+\(\s*+[\w&>.-]{1,60}\s*+,\s*+\"(?P<name>[^\"\n]{1,200})\""), _C, None),
    ("MQTT", "ESP-MQTT", "client", "broker", re.compile(
        r"\.(?:uri|address\.uri)\s*+=\s*+\"(?P<name>mqtts?://[^\"\n]{1,300})\""), _C, _ESP_MQTT),
    ("MQTT", "PubSubClient", "consume", "topic", re.compile(
        r"\.subscribe\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"(?:\s*+,\s*+(?P<qos>[01])\b)?"), _C, _PUBSUBCLIENT),
    ("MQTT", "PubSubClient", "produce", "topic", re.compile(r"\.publish\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _C,
     _PUBSUBCLIENT),
    ("MQTT", "rumqttc", "consume", "topic", re.compile(
        r"\.subscribe\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"\s*+,\s*+QoS::(?P<qos>AtMostOnce|AtLeastOnce|ExactlyOnce)\b"),
     _RUST, _RUMQTTC),
    ("MQTT", "rumqttc", "produce", "topic", re.compile(
        r"\.publish\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"\s*+,\s*+QoS::(?P<qos>AtMostOnce|AtLeastOnce|ExactlyOnce)\b"),
     _RUST, _RUMQTTC),
    ("MQTT", "MQTTnet", "consume", "topic", re.compile(
        r"\.WithTopicFilter\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\"|\bf\.WithTopic\s*+\(\s*+\"(?P<name2>[^\"\n]{1,200})\""), _CS,
     _MQTTNET),
    ("MQTT", "MQTTnet", "produce", "topic", re.compile(
        r"\bMqttApplicationMessageBuilder\s*+\(\s*+\)\s*+\.WithTopic\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _CS, _MQTTNET),
    ("MQTT", "MQTTnet", "client", "broker", re.compile(r"\.WithTcpServer\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _CS,
     _MQTTNET),
    ("MQTT", "MQTT broker URL", "client", "broker", re.compile(r"[\"'](?P<name>mqtts?://[^\"'\s]{1,300})[\"']"), _ALL, None),
    # Message-driven endpoints: Java, Kotlin, Scala
    ("Messaging", "Kafka listener", "consume", "topic", re.compile(r"@KafkaListener\s*+\((?P<args>[^)]{0,600})\)"), _JVM,
     None),
    ("Messaging", "Spring AMQP", "consume", "queue", re.compile(r"@RabbitListener\s*+\((?P<args>[^)]{0,600})\)"), _JVM, None),
    ("Messaging", "Spring JMS", "consume", "queue", re.compile(r"@JmsListener\s*+\((?P<args>[^)]{0,600})\)"), _JVM, None),
    ("Messaging", "Spring Cloud AWS", "consume", "queue", re.compile(r"@SqsListener\s*+\((?P<args>[^)]{0,600})\)"), _JVM,
     None),
    ("Messaging", "Spring Cloud Azure", "consume", "queue", re.compile(r"@ServiceBusListener\s*+\((?P<args>[^)]{0,600})\)"),
     _JVM, None),
    ("Messaging", "Spring for Apache Pulsar", "consume", "topic", re.compile(r"@PulsarListener\s*+\((?P<args>[^)]{0,600})\)"),
     _JVM, None),
    ("Messaging", "Spring Cloud Stream", "consume", "channel", re.compile(r"@StreamListener\s*+\((?P<args>[^)]{0,300})\)"),
     _JVM, None),
    ("Messaging", "SmallRye Reactive Messaging", "consume", "channel", re.compile(
        r"@Incoming\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _JVM, None),
    ("Messaging", "SmallRye Reactive Messaging", "produce", "channel", re.compile(
        r"@Outgoing\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""), _JVM, None),
    ("Messaging", "Micronaut Kafka", "consume", "topic", re.compile(
        r"@Topic\s*+\(\s*+(?:value\s*+=\s*+)?\"(?P<name>[^\"\n]{1,200})\""), _JVM, _MICRONAUT_KAFKA),
    ("Messaging", "Azure Functions", "consume", "trigger", re.compile(
        r"@(?:ServiceBusQueue|ServiceBusTopic|EventHub|Kafka|Queue|RabbitMQ|EventGrid|CosmosDB|Blob)Trigger\s*+\("
        r"(?P<args>[^)]{0,600})\)"), _JVM, None),
    # Message-driven endpoints: C#
    ("Messaging", "Azure Functions", "consume", "trigger", re.compile(
        r"\[(?:ServiceBus|Queue|EventHub|Kafka|RabbitMQ|EventGrid|CosmosDB|Blob)Trigger\s*+\(\s*+(?:\"(?P<name>[^\"\n]{1,200})\")?"),
     _CS, None),
    ("Messaging", "MassTransit", "consume", "message", re.compile(
        r"\bclass\s++\w{1,120}\s*+:\s*+(?:[\w.]{1,120}\s*+,\s*+){0,4}IConsumer\s*+<\s*+(?P<name>[\w.]{1,120})\s*+>"), _CS, None),
    ("Messaging", "MassTransit", "consume", "queue", re.compile(r"\.ReceiveEndpoint\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""),
     _CS, None),
    ("Messaging", "NServiceBus", "consume", "message", re.compile(r"\bIHandleMessages\s*+<\s*+(?P<name>[\w.]{1,120})\s*+>"),
     _CS, None),
    ("Messaging", "Confluent.Kafka", "consume", "topic", re.compile(r"\.Subscribe\s*+\(\s*+\"(?P<name>[^\"\n]{1,200})\""),
     _CS, _CONFLUENT_CS),
    # Message-driven endpoints: Python
    ("Messaging", "Celery", "consume", "task", re.compile(
        r"@(?:\w{1,40}\.)?(?:task|shared_task)\b(?:[ \t]*+\((?P<args>[^)\n]{0,300})\))?" + _DEF), _PY, _CELERY),
    ("Messaging", "Dramatiq", "consume", "actor", re.compile(
        r"@dramatiq\.actor\b(?:[ \t]*+\((?P<args>[^)\n]{0,300})\))?" + _DEF), _PY, None),
    ("Messaging", "Faust", "consume", "agent", re.compile(r"@\w{1,40}\.agent\s*+\(\s*+(?P<name>[\w.]{1,120})"), _PY, _FAUST),
    ("Messaging", "kafka-python/aiokafka", "consume", "topic", re.compile(
        r"\b(?:AIO)?KafkaConsumer\s*+\(\s*+[\"']" + _NAME + "[\"']"), _PY, None),
    ("Messaging", "confluent-kafka", "consume", "topic", re.compile(r"\.subscribe\s*+\(\s*+\[\s*+[\"']" + _NAME + "[\"']"),
     _PY, _CONFLUENT_PY),
    ("Messaging", "pika", "consume", "queue", re.compile(
        r"\.basic_consume\s*+\(\s*+(?:queue\s*+=\s*+)?[\"']" + _NAME + "[\"']"), _PY, None),
    ("Messaging", "pika", "produce", "queue", re.compile(
        r"\.basic_publish\s*+\([^)]{0,300}?routing_key\s*+=\s*+[\"']" + _NAME + "[\"']"), _PY, None),
    ("Messaging", "Azure Functions", "consume", "trigger", re.compile(
        r"@\w{1,40}\.(?:service_bus_queue|service_bus_topic|event_hub_message|queue|kafka|event_grid|blob|cosmos_db)_trigger"
        r"\s*+\((?P<args>[^)]{0,600})\)"), _PY, _AZURE_PY),
    # Message-driven endpoints: JavaScript and TypeScript
    ("Messaging", "NestJS microservices", "consume", "message", re.compile(
        r"@MessagePattern\s*+\(\s*+(?:" + _Q + _NAME + _Q + r"|\{\s*+cmd\s*+:\s*+" + _Q + r"(?P<name2>[^\"'`\n]{1,200})"
        + _Q + ")"), _JS, None),
    ("Messaging", "NestJS microservices", "consume", "event", re.compile(r"@EventPattern\s*+\(\s*+" + _Q + _NAME + _Q), _JS,
     None),
    ("Messaging", "BullMQ", "consume", "queue", re.compile(r"\bnew\s++Worker\s*+\(\s*+" + _Q + _NAME + _Q), _JS, _BULLMQ),
    ("Messaging", "BullMQ", "produce", "queue", re.compile(r"\bnew\s++Queue\s*+\(\s*+" + _Q + _NAME + _Q), _JS, _BULLMQ),
    ("Messaging", "Azure Functions", "consume", "trigger", re.compile(
        r"\bapp\.(?:serviceBusQueue|serviceBusTopic|eventHub|storageQueue|eventGrid|cosmosDB|storageBlob)\s*+\(\s*+" + _Q
        + r"(?P<fn>[^\"'`\n]{1,200})" + _Q + r"\s*+,\s*+\{(?P<args>[^}]{0,600})"), _JS, _AZURE_JS),
    ("Messaging", "Cloud Functions for Firebase", "consume", "topic", re.compile(
        r"\b(?:pubsub\.topic|onMessagePublished)\s*+\(\s*+" + _Q + _NAME + _Q), _JS, _FIREBASE),
    # Message-driven endpoints: Go, Ruby, PHP, Elixir
    ("Messaging", "Watermill", "consume", "topic", re.compile(
        r"\.Add(?:NoPublisher)?Handler\s*+\(\s*+\"[^\"\n]{1,200}\"\s*+,\s*+\"(?P<name>[^\"\n]{1,200})\""), _GO, _WATERMILL),
    ("Messaging", "Sarama", "consume", "topic", re.compile(
        r"\.Consume\s*+\(\s*+\w{1,40}\s*+,\s*+\[\]string\s*+\{\s*+\"(?P<name>[^\"\n]{1,200})\"|\.ConsumePartition\s*+\(\s*+"
        r"\"(?P<name2>[^\"\n]{1,200})\""), _GO, _SARAMA),
    ("Messaging", "confluent-kafka-go", "consume", "topic", re.compile(
        r"\.SubscribeTopics\s*+\(\s*+\[\]string\s*+\{\s*+\"(?P<name>[^\"\n]{1,200})\"|\.Subscribe\s*+\(\s*+"
        r"\"(?P<name2>[^\"\n]{1,200})\""), _GO, _CONFLUENT_GO),
    ("Messaging", "Sidekiq", "consume", "job", re.compile(r"\binclude\s++Sidekiq::(?:Job|Worker)\b(?P<before>)"), _RUBY, None),
    ("Messaging", "Sidekiq", "consume", "queue", re.compile(
        r"\bsidekiq_options\b[^\n]{0,200}?\bqueue:\s*+[:\"']?(?P<name>[\w-]{1,120})"), _RUBY, None),
    ("Messaging", "Active Job", "consume", "queue", re.compile(r"\bqueue_as\s++[:\"']?(?P<name>[\w-]{1,120})"), _RUBY, None),
    ("Messaging", "Karafka", "consume", "topic", re.compile(r"\btopic\s++:(?P<name>\w{1,120})\s++do\b"), _RUBY, _KARAFKA),
    ("Messaging", "Laravel queues", "consume", "job", re.compile(
        r"\bclass\s++(?P<name>\w{1,120})(?:\s++extends\s++[\w\\]{1,200})?\s++implements\s++(?:[\w\\]{1,200}\s*+,\s*+){0,4}"
        r"ShouldQueue\b"), _PHP, None),
    ("Messaging", "Symfony Messenger", "consume", "handler", re.compile(
        r"#\[AsMessageHandler\b[^\]\n]{0,300}\](?P<after>)|\bclass\s++(?P<name>\w{1,120})\s++implements\s++(?:[\w\\]{1,200}"
        r"\s*+,\s*+){0,4}MessageHandlerInterface\b"), _PHP, None),
    ("Messaging", "Broadway", "consume", "pipeline", re.compile(
        r"\bBroadway(?:Kafka|RabbitMQ|SQS|CloudPubSub)\.Producer\b"), _ELIXIR, None),
)

# Families: a protocol's patterns run only when one of its words is in the lower-cased text.
_FAMILY_WORDS = {
    "JSON-RPC": ("jsonrpc", "json-rpc", "jayson", "jsonrpsee", "modernrpc", "gorilla/rpc"),
    "SOAP": ("soap", "wsdl", "webservice", "webmethod", "servicecontract", "operationcontract", "payloadroot",
             "endpoint.publish", "servicebase", "clientbase", "channelfactory", "addserviceendpoint", "savon"),
    "WebSocket": ("websocket", "socket.io", "socketio", "signalr", "hub", "serverendpoint", "messagemapping", "sendto",
                  "stomp", "as_asgi", "subscribemessage", "channel", "actioncable", "wsserver", "warp::ws", "ws::start",
                  "accept_async", "accept_hdr_async", "connect_async", "sock.route", ".ws(", "bun.serve", "upgrade",
                  "actix_ws"),
    "SSE": ("event-stream", "event_stream", "eventsource", "sseemitter", "serversentevent", "@sse", "streamsse",
            "sse::new", "sse.new", "actioncontroller::live", "connect_sse", "sseclient"),
    "Webhook": ("signature", "x-github-event", "octokit/webhooks", "x-gitlab-", "constructevent", "construct_event",
                "requestvalidator", "new webhook(", "hooks.slack.com", "/api/webhooks/", "webhook.office", "office.com/webhook",
                "office365.com/webhook", "chat.googleapis.com", "dingtalk.com", "qyapi.weixin", "open-apis/bot"),
    "MQTT": ("mqtt", "mosquitto", "pubsubclient", "rumqttc"),
    "Messaging": ("listener", "@incoming", "@outgoing", "@topic", "trigger", "messagepattern", "eventpattern", "celery",
                  "shared_task", "dramatiq", "faust", "kafkaconsumer", "confluent_kafka", "basic_consume", "basic_publish",
                  "bullmq", "bull", "iconsumer", "receiveendpoint", "ihandlemessages", "confluent.kafka", "watermill",
                  "sarama", "confluent-kafka-go", "sidekiq", "queue_as", "karafka", "shouldqueue", "asmessagehandler",
                  "messagehandlerinterface", "broadway", "pubsub.topic", "onmessagepublished"),
}
# Argument keys that name an endpoint, by priority: what is consumed or served, then a plain name
# or value, then a namespace.
_ARG_KEYS = tuple(re.compile(r"\b(?:" + keys + r")[ \t]*+[=:][ \t]*+(?P<open>[{\[])?") for keys in (
    (r"queues?|queue_name|queueName|queueNames|topics?|topicName|topic_name|topicPattern|destination|eventHubName|"
     r"event_hub_name|serviceName|operationName|localPart|path"),
    r"name|value",
    r"namespace",
))
_ARG_STRING = re.compile(r"""["'`]([^"'`\n]{1,200})["'`]""")
_DECLARED = re.compile(r"\b(?:class|interface|struct|record|object|trait|enum)[ \t]++(\w{1,120})|(\w{1,120})[ \t]*+\(")
_ENCLOSING = re.compile(r"\b(?:class|def|function|func|fn)[ \t]++(\w{1,120})")
_NOT_MEMBERS = frozenset({"if", "for", "while", "switch", "return", "new", "throw", "catch", "function", "def", "fn"})
_QOS = {"AtMostOnce": "0", "AtLeastOnce": "1", "ExactlyOnce": "2"}
# jayson: new jayson.Server({ add(args, callback) {...}, sub: function... }) names its methods by key.
_JAYSON_SERVER = re.compile(r"\bjayson\.[Ss]erver\s*+\(\s*+\{")
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$.]{0,99}")
_OBJECT_KEY = re.compile(r"""(?:^|[{,])\s*+["']?(?P<key>[A-Za-z_$][\w$.]{0,99})["']?\s*+[:(,}]""")
# Go: routes to handlers that upgrade the connection to a WebSocket.
_GO_FUNC = re.compile(r"(?m)^func[ \t]++(?:\([^)\n]{0,200}\)[ \t]*+)?(?P<name>\w{1,120})[ \t]*+\(")
_GO_UPGRADE = re.compile(r"\.Upgrade\s*+\(\s*+\w{1,40}\s*+,\s*+\w{1,40}\s*+,|\bwebsocket\.Accept\s*+\(")
_GO_ROUTE = re.compile(r"\.(?:HandleFunc|Handle|GET|Get|Any|Handler)\s*+\(\s*+(?:\"[A-Z]{3,7}\"\s*+,\s*+)?"
                       r"\"(?P<path>/[^\"\n]{0,200})\"\s*+,\s*+(?:[\w.]{1,120}\.)?(?P<handler>\w{1,120})\s*+[,)]")
_GO_INLINE_ROUTE = re.compile(r"\.(?:HandleFunc|GET|Get|Any)\s*+\(\s*+\"(?P<path>/[^\"\n]{0,200})\"\s*+,\s*+func\s*+\(")
# axum: routes to handlers that take a WebSocketUpgrade.
_RUST_FN = re.compile(r"\bfn[ \t]++(?P<name>\w{1,120})")
_RUST_ROUTE = re.compile(r"\.route\s*+\(\s*+\"(?P<path>/[^\"\n]{0,200})\"\s*+,\s*+(?:get|any|on)\s*+\(\s*+"
                         r"(?:[\w:]{1,120}::)?(?P<handler>\w{1,120})\s*+\)")


def _arg_names(args: str) -> list[str]:
    """The names an annotation's or decorator's arguments give (queues, topics, destinations,
    paths, every one of a list), or its first positional string."""
    for pattern in _ARG_KEYS:
        for match in pattern.finditer(args):
            rest = args[match.end():]
            if match.group("open"):
                close = rest.find("}" if match.group("open") == "{" else "]")
                names = _ARG_STRING.findall(rest[:close if close != -1 else len(rest)])
            else:
                string = _ARG_STRING.match(rest)
                names = [string.group(1)] if string else []
            if names:
                return names[:20]
    first = _ARG_STRING.match(args.strip())
    return [first.group(1)] if first else []


def _member_after(text: str, offset: int) -> str:
    """The name the declaration after an annotation or attribute declares: its class, interface
    or method, skipping further annotations, attributes and comments."""
    for line in text[offset:offset + 800].split("\n")[:10]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("@", "[", "//", "#", "*", "/*", "<")):
            continue
        for match in _DECLARED.finditer(stripped):
            name = match.group(1) or match.group(2)
            if name not in _NOT_MEMBERS:
                return name
        return ""
    return ""


def _enclosing(text: str, offset: int) -> str:
    """The class or function a statement is in: the last declared before it, nearby."""
    names = _ENCLOSING.findall(text, max(0, offset - 600), offset)
    return names[-1] if names else ""


def _object_keys(text: str, brace: int) -> tuple[list[tuple[str, int]], int]:
    """(key, offset) of an object literal's own keys, and the offset its scan ended at. What nested
    objects, parameter lists and arrays hold is blanked, and strings other than names, so only the
    literal's top level is read; the blanked text keeps every offset."""
    flat: list[str] = []
    depth = 0
    quote = ""
    string: list[str] = []
    end = min(len(text), brace + 200_000)
    position = brace
    while position < end:
        character = text[position]
        position += 1
        if quote:
            if character == "\\":
                string.append(" " if position >= end else "  ")
                position += 1
            elif character != quote:
                string.append(character)
            else:
                content = "".join(string)
                keep = depth == 1 and _IDENTIFIER.fullmatch(content)
                flat.append(quote + (content if keep else " " * len(content)) + quote)
                quote, string = "", []
            continue
        if character in "\"'`":
            quote = character
        elif character in "{([":
            depth += 1
            flat.append(character if depth <= 2 else " ")
        elif character in "})]":
            depth -= 1
            flat.append(character if depth <= 1 else " ")
            if depth == 0:
                break
        else:
            flat.append(character if depth == 1 else " ")
    return [(match.group("key"), brace + match.start("key")) for match in _OBJECT_KEY.finditer("".join(flat))], position


def _go_websocket_routes(text: str) -> list[tuple[str, int]]:
    """(path, offset) of the routes that lead to Go handlers that upgrade to a WebSocket."""
    starts = [(match.start(), match.group("name")) for match in _GO_FUNC.finditer(text)]
    handlers = set()
    for index, (start, name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(text)
        if _GO_UPGRADE.search(text, start, end):
            handlers.add(name)
    found = [(match.group("path"), match.start()) for match in _GO_ROUTE.finditer(text) if match.group("handler") in handlers]
    inline = list(_GO_INLINE_ROUTE.finditer(text))
    for index, match in enumerate(inline):
        end = min(len(text), match.end() + 2000, inline[index + 1].start() if index + 1 < len(inline) else len(text))
        if _GO_UPGRADE.search(text, match.end(), end):
            found.append((match.group("path"), match.start()))
    return found


def _rust_websocket_routes(text: str) -> list[tuple[str, int]]:
    """(path, offset) of the axum routes that lead to handlers taking a WebSocketUpgrade."""
    handlers = set()
    for match in _RUST_FN.finditer(text):
        body = text.find("{", match.end(), match.end() + 800)
        if "WebSocketUpgrade" in text[match.end():body if body != -1 else match.end() + 800]:
            handlers.add(match.group("name"))
    return [(match.group("path"), match.start()) for match in _RUST_ROUTE.finditer(text) if match.group("handler") in handlers]


def code_endpoints(text: str, extension: str) -> list[tuple[str, str, str, str, str, str, int]]:
    """(protocol, framework, role, what, name, qos, line) of the protocol endpoints a source file declares."""
    lowered = text.lower()
    families = {family for family, words in _FAMILY_WORDS.items() if any(word in lowered for word in words)}
    if not families:
        return []
    found: list[tuple[str, str, str, str, str, str, int]] = []
    lines = _Lines(text)
    imports: dict[int, bool] = {}

    def add(protocol, framework, role, what, name, qos, offset):
        if len(found) < MAX_PROTOCOL_FACTS:
            found.append((protocol, framework, role, what, name, qos, lines.line(offset)))

    for protocol, framework, role, what, pattern, extensions, marker in _ENDPOINTS:
        if protocol not in families or extension not in extensions:
            continue
        if marker is not None:
            if id(marker) not in imports:
                imports[id(marker)] = marker.search(text) is not None
            if not imports[id(marker)]:
                continue
        for match in pattern.finditer(text):
            groups = match.groupdict()
            chosen = groups.get("name") or groups.get("name2")
            names = [chosen] if chosen else _arg_names(groups["args"]) if groups.get("args") else []
            if not names:
                fallback = groups.get("fn") or (
                    _member_after(text, match.end()) if groups.get("after") is not None else
                    _enclosing(text, match.start()) if groups.get("before") is not None else "")
                names = [fallback]
            qos = groups.get("qos") or ""
            actual = "client" if groups.get("client") else role
            for name in names:
                add(protocol, framework, actual, what, safe_target(name), _QOS.get(qos, qos), match.start())
    if "JSON-RPC" in families and extension in _JS:
        scanned = 0  # a literal's scan covers the servers inside it, so each character is read once
        for match in _JAYSON_SERVER.finditer(text):
            if match.end() <= scanned:
                continue
            keys, scanned = _object_keys(text, match.end() - 1)
            for key, offset in keys:
                add("JSON-RPC", "jayson", "server", "method", key, "", offset)
    if "WebSocket" in families and extension in _GO and (_GORILLA_WS.search(text) or _GO_WS_ACCEPT.search(text)):
        for path, offset in _go_websocket_routes(text):
            add("WebSocket", "Go net/http", "server", "endpoint", path, "", offset)
    if "WebSocket" in families and extension in _RUST and _AXUM.search(text):
        for path, offset in _rust_websocket_routes(text):
            add("WebSocket", "axum", "server", "endpoint", path, "", offset)
    return sorted(_deduplicated(found), key=lambda item: (item[6], item[0], item[2], item[3], item[4]))


def _deduplicated(found: list[tuple[str, str, str, str, str, str, int]]) -> list[tuple[str, str, str, str, str, str, int]]:
    """One entry per protocol, role, what, name and line (the most specific framework first);
    unnamed server entries of a protocol are dropped where the file names its endpoints."""
    seen = set()
    unique = []
    for item in found:
        key = (item[0], item[2], item[3], item[4], item[6])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    named = {(item[0], item[2]) for item in unique if item[4] and item[3] in {"endpoint", "stream"}}
    return [item for item in unique if item[4] or item[3] not in {"upgrade", "stream", "server"}
            or (item[0], item[2]) not in named]


class ProtocolEndpointAnalyzer(Analyzer):
    """JSON-RPC, SOAP, WebSocket, SSE, webhook, MQTT and message-driven endpoints, statically."""

    name = "api-protocols"
    limits = AnalyzerLimits(MAX_PROTOCOL_BYTES, "whole", {"head_bytes": _HEAD_BYTES, "evidence_lines": MAX_PROTOCOL_EVIDENCE},
                            outcome="UNKNOWN finding for a contract past the budget")
    domains = ("api_event", "api_soap", "messaging")
    languages = ("Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Scala", "Groovy", "C#", "Go", "Rust", "Ruby",
                 "PHP", "Elixir", "C", "C++", "C/C++ Header", "Arduino Sketch", "JSON", "YAML")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and (record.extension in _CODE or record.extension in _DATA)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.extension in _DATA:
            return self._document(path, record)
        if over_limit(record.size_bytes, MAX_PROTOCOL_BYTES):
            return []
        try:
            text = read_text_bounded(path, MAX_PROTOCOL_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, ValueError, SourceBudgetExceeded):
            return []
        return self._code(record, code_endpoints(text, record.extension))

    # -- documents -------------------------------------------------------------------------
    def _document(self, path: Path, record: FileRecord) -> list[Finding]:
        name = PurePosixPath(record.path.replace("\\", "/")).name.lower()
        config = name in _SERVERLESS_NAMES or name == "function.json"
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                head = stream.read(_HEAD_BYTES).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return []
        contract = _CONTRACT_KEY.search(head)
        if not (config or contract):
            return []
        if over_limit(record.size_bytes, MAX_PROTOCOL_BYTES):
            return [Finding("api", f"API document scan budget reached: {record.path}",
                            f"The file is larger than the {MAX_PROTOCOL_BYTES:,}-byte budget and was not read.",
                            confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
        try:
            text = read_text_bounded(path, MAX_PROTOCOL_BYTES, errors="replace", expected_identity=record.analysis_identity)
            if contract and contract.group(1) == "openapi" and "webhooks" not in text:
                return []  # api-contracts reads the routes of OpenAPI documents
            data = json.loads(text) if record.extension == ".json" else safe_yaml_load(text, allow_unknown_tags=True)
        except ImportError:
            return [Finding("api", f"API document unavailable: {record.path}",
                            "Reading this YAML document needs PyYAML (the optional infrastructure extra).",
                            confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
        except (OSError, ValueError, UnsafeDocumentError, SourceBudgetExceeded, RecursionError) as exc:
            return [Finding("api", f"API document unreadable: {record.path}", describe_error(exc),
                            confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
        if not isinstance(data, dict):
            return []
        if name in _SERVERLESS_NAMES:
            return self._serverless(record, serverless_events(data))
        if name == "function.json":
            return self._azure(record, azure_bindings(data))
        kind = contract.group(1) if contract else ""
        if kind == "asyncapi" and "asyncapi" in data:
            return self._asyncapi(record, *asyncapi_channels(data))
        if kind == "openrpc" and "openrpc" in data:
            return self._openrpc(record, str(data.get("openrpc")), openrpc_methods(data))
        if kind == "openapi" and "openapi" in data:
            return self._webhooks(record, openapi_webhooks(data))
        return []

    def _asyncapi(self, record: FileRecord, version: str, servers: list[dict], channels: list[dict]) -> list[Finding]:
        protocols = sorted({server["protocol"] for server in servers if server["protocol"]})
        for channel in channels:
            code_facts.emit_fact("async_channel", channel["address"], actions=channel["actions"],
                                 operations=channel["operations"][:50], messages=channel["messages"][:50],
                                 protocols=protocols, version=version)
        actions = Counter(action for channel in channels for action in channel["actions"])
        messages = {message for channel in channels for message in channel["messages"]}
        return [Finding(
            "api", f"AsyncAPI channels: {record.path}",
            f"AsyncAPI {version}: {len(servers)} server(s)" + (f" ({', '.join(protocols)})" if protocols else "")
            + f", {len(channels)} channel(s) with {sum(actions.values())} operation(s)"
            + (" (" + ", ".join(f"{count} {action}" for action, count in sorted(actions.items())) + ")" if actions else "")
            + f" and {len(messages)} message(s). A contract does not prove a broker is reachable.",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"server {server['name']}: {server['protocol'] or '?'} {server['host']}".rstrip() for server in servers[:20]]
            + [f"channel {channel['address']}: {', '.join(channel['actions']) or 'no operations'}"
               + (f" ({', '.join(channel['messages'][:6])})" if channel["messages"] else "")
               for channel in channels[:MAX_PROTOCOL_EVIDENCE]] or [record.path],
        )]

    def _openrpc(self, record: FileRecord, version: str, methods: list[tuple[str, list[str], str]]) -> list[Finding]:
        for name, params, result in methods:
            code_facts.emit_fact("jsonrpc_method", name, params=params, result=result, source="OpenRPC")
        return [Finding(
            "api", f"OpenRPC methods: {record.path}", f"OpenRPC {version}: {len(methods)} JSON-RPC method(s).",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"method {name}({', '.join(params)})" + (f" -> {result}" if result else "")
                      for name, params, result in methods[:MAX_PROTOCOL_EVIDENCE]] or [record.path],
        )]

    def _webhooks(self, record: FileRecord, webhooks: list[tuple[str, list[str]]]) -> list[Finding]:
        if not webhooks:
            return []
        for name, methods in webhooks:
            code_facts.emit_fact("webhook_contract", name, methods=methods)
        return [Finding(
            "api", f"OpenAPI webhooks: {record.path}",
            f"{len(webhooks)} webhook(s) the API sends to its subscribers: "
            + ", ".join(name for name, _ in webhooks[:12]) + ".",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"webhook {name}: {', '.join(methods) or '(no operations)'}" for name, methods in webhooks[:MAX_PROTOCOL_EVIDENCE]],
        )]

    def _serverless(self, record: FileRecord, events: list[tuple[str, str, str]]) -> list[Finding]:
        if not events:
            return []
        for function, kind, name in events:
            protocol = "WebSocket" if kind == "websocket" else "Messaging"
            code_facts.emit_fact("protocol_endpoint", name or kind, protocol=protocol, framework="Serverless Framework",
                                 role="server" if protocol == "WebSocket" else "consume", what=kind, line=None,
                                 target=name, function=function)
        kinds = Counter(kind for _, kind, _ in events)
        return [Finding(
            "api", f"Serverless event sources: {record.path}",
            f"{len({function for function, _, _ in events})} function(s) triggered by "
            + ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items())) + " event(s).",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"{function}: {kind} {name}".rstrip() for function, kind, name in events[:MAX_PROTOCOL_EVIDENCE]],
        )]

    def _azure(self, record: FileRecord, bindings: list[tuple[str, str, str]]) -> list[Finding]:
        if not bindings:
            return []
        for kind, direction, name in bindings:
            code_facts.emit_fact("protocol_endpoint", name or kind, protocol="Messaging", framework="Azure Functions",
                                 role="consume" if direction == "in" else "produce", what=kind, line=None, target=name)
        return [Finding(
            "api", f"Azure Functions bindings: {record.path}",
            f"{len(bindings)} message binding(s): " + ", ".join(f"{kind} ({direction})" for kind, direction, _ in bindings[:12])
            + ".", confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"{record.path}: {kind} {direction} {name}".rstrip() for kind, direction, name in bindings],
        )]

    # -- code ------------------------------------------------------------------------------
    def _code(self, record: FileRecord, found: list[tuple[str, str, str, str, str, str, int]]) -> list[Finding]:
        if not found:
            return []
        for protocol, framework, role, what, name, qos, line in found:
            code_facts.emit_fact("protocol_endpoint", name or framework, protocol=protocol, framework=framework, role=role,
                                 what=what, line=line, target=name, **({"qos": qos} if qos else {}))
        summary = Counter((protocol, role) for protocol, _, role, _, _, _, _ in found)
        protocols = sorted({protocol for protocol, _ in summary})
        return [Finding(
            "api", f"Protocol endpoints: {record.path}",
            "; ".join(f"{protocol}: " + ", ".join(f"{count} {role}" for (other, role), count in sorted(summary.items())
                                                  if other == protocol) for protocol in protocols)
            + ". Declarations in code, not proof that an endpoint is deployed or reachable.",
            confidence="INFERRED", analyzer=self.name,
            evidence=[f"{record.path}:{line} {protocol} {role} {what}" + (f" {name}" if name else "") + (f" QoS {qos}" if qos else "")
                      + f" ({framework})" for protocol, framework, role, what, name, qos, line in found[:MAX_PROTOCOL_EVIDENCE]],
        )]
