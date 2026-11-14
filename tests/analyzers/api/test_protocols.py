"""Protocol endpoints: JSON-RPC, SOAP, WebSocket, SSE, webhooks, MQTT and message-driven endpoints,
and AsyncAPI, OpenRPC and OpenAPI webhook documents."""
import json
import time
from pathlib import Path

import pytest

from project_discovery.analyzers.api import protocols
from project_discovery.analyzers.api.protocols import (ProtocolEndpointAnalyzer, _go_websocket_routes, _object_keys,
                                                       _rust_websocket_routes, code_endpoints, safe_target)
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord


def _found(source: str, extension: str) -> set[tuple]:
    return {(protocol, framework, role, what, name) + ((qos,) if qos else ())
            for protocol, framework, role, what, name, qos, _ in code_endpoints(source, extension)}


def _analyze(tmp_path: Path, relative: str, source: str):
    path = tmp_path / "source"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Source")
    analyzer = ProtocolEndpointAnalyzer()
    assert analyzer.supports(record)
    return {finding.title.split(":", 1)[0]: finding for finding in analyzer.analyze(path, record)}


def _facts(facts, kind: str) -> list[tuple[str, dict]]:
    return [(name, json.loads(detail)) for fact_kind, name, detail in facts.facts if fact_kind == kind]


def test_json_rpc_servers_and_clients():
    python = ('from jsonrpcserver import method, serve\n@method\ndef ping():\n    return "pong"\n'
              '@method(name="math.add")\nasync def add(a, b):\n    return a + b\n'
              'payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}\n')
    assert _found(python, ".py") == {("JSON-RPC", "jsonrpcserver", "server", "method", "ping"),
                                     ("JSON-RPC", "jsonrpcserver", "server", "method", "math.add"),
                                     ("JSON-RPC", "JSON-RPC request", "client", "call", "eth_blockNumber")}
    dispatcher = ("from jsonrpc import JSONRPCResponseManager, dispatcher\n@dispatcher.add_method\ndef foobar(**kwargs):\n"
                  "    pass\ndispatcher.add_method(echo, name='tools.echo')\n")
    assert {item[4] for item in _found(dispatcher, ".py")} == {"foobar", "tools.echo"}
    # jayson names methods by the keys of its object; nested keys are not methods.
    jayson = ("const jayson = require('jayson');\nconst server = new jayson.Server({\n"
              "  add(args, callback) { callback(null, { nested: args[0], other: 1 }); },\n"
              "  'multiply': function (args, callback) { callback(null, args[0] * args[1]); },\n"
              "  sub: (args, cb) => cb(null, args[0] - args[1]),\n  ping,\n});\n")
    assert [item[4] for item in code_endpoints(jayson, ".js")] == ["add", "multiply", "sub", "ping"]
    assert {item[4] for item in _found("import { JSONRPCServer } from 'json-rpc-2.0';\nserver.addMethod('echo', fn);\n",
                                       ".ts")} == {"echo"}
    java = ('@JsonRpcService("/calculator")\npublic interface Calculator {\n  @JsonRpcMethod("calc.add")\n'
            "  int add(int a, int b);\n}\n")
    assert _found(java, ".java") == {("JSON-RPC", "jsonrpc4j", "server", "endpoint", "/calculator"),
                                     ("JSON-RPC", "Java JSON-RPC", "server", "method", "calc.add")}
    assert {item[4] for item in _found('[JsonRpcMethod("getStatus")] public Task<Status> GetStatusAsync() {}\n'
                                       "JsonRpc.Attach(stream, server);\n", ".cs")} == {"getStatus", ""}
    rust = ('use jsonrpsee::proc_macros::rpc;\n#[method(name = "say_hello")]\nasync fn say_hello(&self) -> String;\n'
            'use jsonrpc_core::IoHandler;\nio.add_sync_method("ping", |_| Ok(Value::from("pong")));\n')
    assert {item[4] for item in _found(rust, ".rs")} == {"say_hello", "ping"}
    go = 'import "github.com/gorilla/rpc"\ns.RegisterService(new(HelloService), "")\n'
    assert _found(go, ".go") == {("JSON-RPC", "gorilla/rpc", "server", "service", "HelloService")}


def test_soap_services_operations_and_clients():
    java = ('@WebService(serviceName = "CalculatorService")\npublic class Calculator {\n'
            '    @WebMethod(operationName = "add")\n    public int add(int a, int b) { return a + b; }\n'
            "    @WebMethod\n    public int subtract(int a, int b) { return a - b; }\n}\n"
            '@PayloadRoot(namespace = NAMESPACE_URI, localPart = "getCountryRequest")\n'
            'Endpoint.publish("http://admin:secret@localhost:8080/ws/calc?wsdl", new Calculator());\n')
    assert _found(java, ".java") == {
        ("SOAP", "JAX-WS", "server", "service", "CalculatorService"), ("SOAP", "JAX-WS", "server", "operation", "add"),
        ("SOAP", "JAX-WS", "server", "operation", "subtract"),
        ("SOAP", "Spring-WS", "server", "operation", "getCountryRequest"),
        ("SOAP", "JAX-WS", "server", "endpoint", "http://localhost:8080/ws/calc")}
    csharp = ("using System.ServiceModel;\n[ServiceContract]\npublic interface IGreeter\n{\n    [OperationContract]\n"
              "    [FaultContract(typeof(Fault))]\n    Task<string> SayHelloAsync(string name);\n}\n"
              "public class GreeterClient : ClientBase<IGreeter>, IGreeter {}\n"
              "public partial class StubClient : grpc::ClientBase<StubClient> {}\n")
    assert _found(csharp, ".cs") == {("SOAP", "WCF", "server", "service", "IGreeter"),
                                     ("SOAP", "WCF", "server", "operation", "SayHelloAsync"),
                                     ("SOAP", "WCF", "client", "client", "IGreeter")}
    python = ("from spyne import ServiceBase, rpc\nclass HelloWorldService(ServiceBase):\n"
              "    @rpc(Unicode, Integer, _returns=Iterable(Unicode))\n    def say_hello(ctx, name, times):\n        pass\n"
              "import zeep\nclient = zeep.Client('http://www.dneonline.com/calculator.asmx?WSDL')\n")
    assert _found(python, ".py") == {("SOAP", "spyne", "server", "service", "HelloWorldService"),
                                     ("SOAP", "spyne", "server", "operation", "say_hello"),
                                     ("SOAP", "zeep/suds", "client", "client", "http://www.dneonline.com/calculator.asmx")}
    php = "$server = new SoapServer('hello.wsdl');\n$server->addFunction('hello');\n$client = new SoapClient(null, $o);\n"
    assert _found(php, ".php") == {("SOAP", "PHP SOAP", "server", "service", "hello.wsdl"),
                                   ("SOAP", "PHP SOAP", "server", "operation", "hello"),
                                   ("SOAP", "PHP SOAP", "client", "client", "")}
    node = "const soap = require('soap');\nsoap.listen(server, '/wsdl', service, xml);\nsoap.createClient(url, cb);\n"
    assert {item[2:5] for item in _found(node, ".js")} == {("server", "endpoint", "/wsdl"), ("client", "client", "")}


def test_websocket_endpoints_handlers_and_clients():
    java = ('@ServerEndpoint("/chat/{room}")\npublic class ChatEndpoint {}\n@MessageMapping("/chat.send")\n'
            '@SendTo("/topic/public")\npublic ChatMessage send(ChatMessage m) { return m; }\n'
            "@EnableWebSocket\nregistry.addHandler(echoHandler(), \"/echo\").setAllowedOrigins(\"*\");\n")
    assert {item[2:5] for item in _found(java, ".java")} == {
        ("server", "endpoint", "/chat/{room}"), ("server", "message", "/chat.send"), ("produce", "destination", "/topic/public"),
        ("server", "endpoint", "/echo")}
    python = ('@app.websocket("/ws/{room}")\nasync def chat(websocket):\n    pass\n'
              "routes = [WebSocketRoute('/feed', Feed)]\n"
              "websocket_urlpatterns = [re_path(r'ws/chat/(?P<room>\\w+)/$', ChatConsumer.as_asgi())]\n"
              "from aiohttp import web\nasync def websocket_handler(request):\n    ws = web.WebSocketResponse()\n"
              "ws = await websockets.connect('wss://user:secret@stream.example.com/feed?token=abc')\n")
    assert {item[1:5] for item in _found(python, ".py")} == {
        ("FastAPI/Starlette/Quart/Sanic", "server", "endpoint", "/ws/{room}"), ("Starlette", "server", "endpoint", "/feed"),
        ("Django Channels", "server", "endpoint", "ws/chat/(?P<room>\\w+)/$"),
        ("aiohttp", "server", "handler", "websocket_handler"),
        ("Python WebSocket client", "client", "client", "wss://stream.example.com/feed")}
    javascript = ("import { WebSocketServer } from 'ws';\nconst wss = new WebSocketServer({ port: 8080, path: '/live' });\n"
                  "@WebSocketGateway(80, { namespace: 'events' })\nexport class EventsGateway {\n"
                  "  @SubscribeMessage('identity')\n  identity(data) { return data; }\n}\n"
                  "fastify.get('/stream', { websocket: true }, (socket) => {});\n"
                  "app.get('/hono', upgradeWebSocket((c) => ({})));\n"
                  "const socket = new WebSocket(`wss://api.example.com/live?key=secret`);\n")
    assert {item[1:5] for item in _found(javascript, ".ts")} == {
        ("ws", "server", "server", "/live"), ("NestJS", "server", "gateway", "events"), ("NestJS", "server", "message", "identity"),
        ("Fastify", "server", "endpoint", "/stream"), ("Hono", "server", "endpoint", "/hono"),
        ("WebSocket API", "client", "client", "wss://api.example.com/live")}
    go = ('import "github.com/gorilla/websocket"\nvar upgrader = websocket.Upgrader{}\n'
          "func wsHandler(w http.ResponseWriter, r *http.Request) {\n\tconn, _ := upgrader.Upgrade(w, r, nil)\n}\n"
          'func main() {\n\thttp.HandleFunc("/ws", wsHandler)\n\thttp.HandleFunc("/live", func(w http.ResponseWriter, '
          'r *http.Request) {\n\t\tc, _ := upgrader.Upgrade(w, r, nil)\n\t\t_ = c\n\t})\n\thttp.HandleFunc("/health", health)\n}\n')
    # Routes to handlers that upgrade, not the upgrade calls themselves.
    assert _found(go, ".go") == {("WebSocket", "Go net/http", "server", "endpoint", "/ws"),
                                 ("WebSocket", "Go net/http", "server", "endpoint", "/live")}
    csharp = 'app.MapHub<ChatHub>("/chathub");\npublic class ChatHub : Hub<IChatClient> { }\n'
    assert {item[2:5] for item in _found(csharp, ".cs")} == {("server", "endpoint", "/chathub"), ("server", "hub", "ChatHub")}
    rust = ("use axum::{extract::ws::WebSocketUpgrade, routing::get, Router};\n"
            "async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response { ws.on_upgrade(f) }\n"
            'let app = Router::new().route("/ws", get(ws_handler)).route("/", get(root));\n')
    assert _found(rust, ".rs") == {("WebSocket", "axum", "server", "endpoint", "/ws")}
    elixir = 'socket "/socket", MyAppWeb.UserSocket, websocket: true\nchannel "room:*", MyAppWeb.RoomChannel\n'
    assert {item[2:5] for item in _found(elixir, ".ex")} == {("server", "endpoint", "/socket"), ("server", "channel", "room:*")}
    ruby = "class ChatChannel < ApplicationCable::Channel\nend\nmount ActionCable.server => '/cable'\n"
    assert {item[2:5] for item in _found(ruby, ".rb")} == {("server", "channel", "ChatChannel"), ("server", "endpoint", "/cable")}


def test_server_sent_events():
    assert {item[2:5] for item in _found('return StreamingResponse(gen(), media_type="text/event-stream")\n'
                                         'headers = {"Accept": "text/event-stream"}\n', ".py")} == {
        ("server", "stream", ""), ("client", "stream", "")}
    java = ('@GetMapping(path = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)\n'
            "public Flux<ServerSentEvent<String>> stream() { return null; }\n")
    assert _found(java, ".java") == {("SSE", "Spring", "server", "stream", "/stream")}
    assert {item[1:5] for item in _found("@Sse('events')\nsse() {}\nconst source = new EventSource('/api/events');\n",
                                         ".ts")} == {("NestJS", "server", "stream", "events"),
                                                     ("EventSource", "client", "client", "/api/events")}


def test_webhook_receivers_and_senders():
    python = ("event = stripe.Webhook.construct_event(payload, request.headers['Stripe-Signature'], secret)\n"
              "signature = request.headers.get('X-Hub-Signature-256')\n"
              "requests.post('https://hooks.slack.com/services/T0000/B0000/" + "X" * 24 + "', json=data)\n"
              "requests.post('https://discord.com/api/webhooks/123/" + "y" * 30 + "', json=data)\n")
    found = _found(python, ".py")
    assert {item[1:4] for item in found} == {
        ("Stripe", "server", "receiver"), ("X-Hub-Signature (GitHub and others)", "server", "receiver"),
        ("Slack incoming webhook", "client", "sender"), ("Discord webhook", "client", "sender")}
    # Senders are named by service: the URL holds the token.
    assert all(item[4] == "" for item in found)
    assert _found("const verifier = new SignatureVerifier(secret);\n", ".js") == set()  # no Slack SDK import
    assert {item[1] for item in _found("import { Webhook } from 'svix';\nconst wh = new Webhook(secret);\n", ".ts")} == {
        "Svix/Standard Webhooks"}


def test_mqtt_topics_qos_and_brokers():
    python = ('import paho.mqtt.client as mqtt\nclient.subscribe("home/+/temperature", qos=1)\n'
              'client.publish("home/livingroom/light", "on", qos=2, retain=True)\n')
    assert _found(python, ".py") == {
        ("MQTT", "Eclipse Paho (Python)", "consume", "topic", "home/+/temperature", "1"),
        ("MQTT", "Eclipse Paho (Python)", "produce", "topic", "home/livingroom/light", "2")}
    javascript = ("const mqtt = require('mqtt');\nconst client = mqtt.connect('mqtt://user:pw@broker.example.com:1883');\n"
                  "client.subscribe('sensors/#', { qos: 1 });\n")
    assert _found(javascript, ".js") == {
        ("MQTT", "MQTT.js", "client", "broker", "mqtt://broker.example.com:1883"),
        ("MQTT", "MQTT.js", "consume", "topic", "sensors/#", "1")}
    c = ('#include <mosquitto.h>\nmosquitto_subscribe(mosq, NULL, "devices/+/status", 1);\n'
         'mosquitto_publish(mosq, NULL, "devices/42/cmd", len, payload, 0, false);\n'
         'esp_mqtt_client_subscribe(client, "/topic/qos0", 0);\n')
    assert {item[2:] for item in _found(c, ".c")} == {
        ("consume", "topic", "devices/+/status", "1"), ("produce", "topic", "devices/42/cmd"), ("consume", "topic", "/topic/qos0", "0")}
    rust = 'use rumqttc::{MqttOptions, QoS};\nclient.subscribe("hello/rumqtt", QoS::AtLeastOnce).await?;\n'
    assert _found(rust, ".rs") == {("MQTT", "rumqttc", "consume", "topic", "hello/rumqtt", "1")}
    go = 'import mqtt "github.com/eclipse/paho.mqtt.golang"\nopts.AddBroker("tcp://broker.emqx.io:1883")\n' \
         'token := client.Subscribe("topic/test", 1, nil)\n'
    assert {item[2:] for item in _found(go, ".go")} == {("client", "broker", "tcp://broker.emqx.io:1883"),
                                                        ("consume", "topic", "topic/test", "1")}
    # Without the client library's import, subscribe() and publish() are someone else's.
    assert _found('events.subscribe("refresh")\nbus.publish("saved", item)\n', ".py") == set()


def test_message_driven_endpoints():
    java = ('@KafkaListener(topics = {"orders", "refunds"}, groupId = "billing")\npublic void listen(String m) {}\n'
            '@RabbitListener(queues = "emails")\n@SqsListener("jobs")\n@Incoming("prices")\n@Outgoing("quotes")\n'
            '@ServiceBusQueueTrigger(name = "msg", queueName = "orders-queue", connection = "SB")\n'
            '@SendTo("replies")\n')
    assert {item[2:5] for item in _found(java, ".java")} == {
        ("consume", "topic", "orders"), ("consume", "topic", "refunds"), ("consume", "queue", "emails"),
        ("consume", "queue", "jobs"), ("consume", "channel", "prices"), ("produce", "channel", "quotes"),
        ("consume", "trigger", "orders-queue")}  # @SendTo outside a @MessageMapping file is a Kafka reply, not STOMP
    csharp = ('public class OrderConsumer : IConsumer<OrderSubmitted> { }\n'
              '[FunctionName("Process")] public static void Run([ServiceBusTrigger("myqueue", Connection = "SB")] string m) {}\n'
              'cfg.ReceiveEndpoint("order-queue", e => {});\npublic class H : IHandleMessages<PlaceOrder> {}\n')
    assert {item[1:5] for item in _found(csharp, ".cs")} == {
        ("MassTransit", "consume", "message", "OrderSubmitted"), ("Azure Functions", "consume", "trigger", "myqueue"),
        ("MassTransit", "consume", "queue", "order-queue"), ("NServiceBus", "consume", "message", "PlaceOrder")}
    python = ("from celery import shared_task\n@shared_task(name='emails.send')\ndef send_email(to):\n    pass\n"
              "@app.task\n@other\ndef resize(image):\n    pass\nconsumer = KafkaConsumer('clicks')\n"
              "channel.basic_consume(queue='tasks', on_message_callback=cb)\n"
              "channel.basic_publish(exchange='', routing_key='results', body=b'x')\n")
    assert {item[1:5] for item in _found(python, ".py")} == {
        ("Celery", "consume", "task", "emails.send"), ("Celery", "consume", "task", "resize"),
        ("kafka-python/aiokafka", "consume", "topic", "clicks"), ("pika", "consume", "queue", "tasks"),
        ("pika", "produce", "queue", "results")}
    javascript = ("import { Worker, Queue } from 'bullmq';\nnew Worker('video', async (job) => {});\n"
                  "const q = new Queue('mail');\n@MessagePattern({ cmd: 'sum' })\n@EventPattern('user_created')\n")
    assert {item[2:5] for item in _found(javascript, ".ts")} == {
        ("consume", "queue", "video"), ("produce", "queue", "mail"), ("consume", "message", "sum"),
        ("consume", "event", "user_created")}
    ruby = "class HardJob\n  include Sidekiq::Job\n  sidekiq_options queue: 'critical'\nend\nqueue_as :default\n"
    assert {item[2:5] for item in _found(ruby, ".rb")} == {("consume", "job", "HardJob"), ("consume", "queue", "critical"),
                                                           ("consume", "queue", "default")}
    php = "class ProcessPodcast implements ShouldQueue\n{\n}\n#[AsMessageHandler]\nclass SmsHandler\n{\n}\n"
    assert {item[1:5] for item in _found(php, ".php")} == {("Laravel queues", "consume", "job", "ProcessPodcast"),
                                                           ("Symfony Messenger", "consume", "handler", "SmsHandler")}
    # Without Celery imported, @app.task is another framework's (Invoke, Prefect).
    assert _found("@app.task\ndef build(c):\n    pass\n", ".py") == set()


def test_findings_and_facts(tmp_path: Path):
    source = ('import paho.mqtt.client as mqtt\nclient.subscribe("home/+/temperature", qos=1)\n'
              "ws = websockets.connect('wss://user:secret@stream.example.com/feed?token=abc')\n")
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "src/app.py", source)
    found = findings["Protocol endpoints"]
    assert found.confidence == "INFERRED"
    assert found.detail.startswith("MQTT: 1 consume; WebSocket: 1 client.")
    assert "src/app.py:2 MQTT consume topic home/+/temperature QoS 1 (Eclipse Paho (Python))" in found.evidence
    assert not any("secret" in line or "token" in line for line in found.evidence)
    endpoints = dict(_facts(facts, "protocol_endpoint"))
    assert endpoints["home/+/temperature"] == {"framework": "Eclipse Paho (Python)", "line": 2, "protocol": "MQTT", "qos": "1",
                                               "role": "consume", "target": "home/+/temperature", "what": "topic"}
    assert safe_target("mqtts://u:p@broker:8883/x?y=1") == "mqtts://broker:8883"
    assert _analyze(tmp_path, "src/plain.py", "print('hello')\n") == {}


def test_asyncapi_openrpc_and_webhook_documents(tmp_path: Path):
    pytest.importorskip("yaml")
    asyncapi = ("asyncapi: 3.0.0\ninfo:\n  title: Streetlights\n  version: 1.0.0\nservers:\n  production:\n"
                "    host: mqtt://user:pw@broker.example.com:1883\n    protocol: mqtt\nchannels:\n  lightMeasured:\n"
                "    address: smartylighting/{streetlightId}/lighting/measured\n    messages:\n      lightMeasured:\n"
                "        $ref: '#/components/messages/lightMeasured'\n  turnOn:\n    address: smartylighting/{streetlightId}/on\n"
                "operations:\n  receiveLight:\n    action: receive\n    channel:\n      $ref: '#/channels/lightMeasured'\n"
                "  sendTurnOn:\n    action: send\n    channel:\n      $ref: '#/channels/turnOn'\n")
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "docs/streetlights.yaml", asyncapi)  # found by content, not by name
    channels = findings["AsyncAPI channels"]
    assert channels.detail.startswith("AsyncAPI 3.0.0: 1 server(s) (mqtt), 2 channel(s) with 2 operation(s) "
                                      "(1 receive, 1 send) and 1 message(s).")
    assert "server production: mqtt mqtt://broker.example.com:1883" in channels.evidence
    assert dict(_facts(facts, "async_channel"))["smartylighting/{streetlightId}/on"]["actions"] == ["send"]
    two = json.dumps({"asyncapi": "2.6.0", "info": {"title": "x", "version": "1"},
                      "channels": {"user/signedup": {"subscribe": {"operationId": "onSignup",
                                                                   "message": {"$ref": "#/components/messages/Signup"}}}}})
    assert "1 channel(s) with 1 operation(s) (1 subscribe)" in _analyze(tmp_path, "events.json", two)["AsyncAPI channels"].detail
    openrpc = json.dumps({"openrpc": "1.2.6", "info": {"title": "x", "version": "1"}, "methods": [
        {"name": "eth_getBalance", "params": [{"name": "address"}, {"name": "block"}], "result": {"name": "balance"}}]})
    assert _analyze(tmp_path, "api/rpc.json", openrpc)["OpenRPC methods"].evidence == [
        "method eth_getBalance(address, block) -> balance"]
    webhooks = "openapi: 3.1.0\ninfo:\n  title: Pets\n  version: 1.0.0\nwebhooks:\n  newPet:\n    post:\n      summary: x\n"
    assert _analyze(tmp_path, "openapi.yaml", webhooks)["OpenAPI webhooks"].evidence == ["webhook newPet: POST"]
    # OpenAPI routes are the contracts analyzer's; other YAML and JSON is not read past its head.
    assert _analyze(tmp_path, "openapi.yaml", "openapi: 3.0.0\npaths: {}\n") == {}
    assert _analyze(tmp_path, "config.yaml", "name: app\nversion: 2.0.0\n") == {}
    assert _analyze(tmp_path, "package.json", '{"name": "x", "version": "1.0.0"}') == {}


def test_serverless_and_azure_function_bindings(tmp_path: Path):
    pytest.importorskip("yaml")
    serverless = ("service: jobs\nfunctions:\n  worker:\n    handler: handler.run\n    events:\n"
                  "      - sqs: arn:aws:sqs:us-east-1:123456789012:jobs\n      - sns: alerts\n      - http:\n"
                  "          path: /x\n  socket:\n    handler: handler.ws\n    events:\n      - websocket:\n"
                  "          route: $connect\n")
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "serverless.yml", serverless)
    assert findings["Serverless event sources"].detail == "2 function(s) triggered by 1 sns, 1 sqs, 1 websocket event(s)."
    assert {(name, detail["protocol"]) for name, detail in _facts(facts, "protocol_endpoint")} == {
        ("jobs", "Messaging"), ("alerts", "Messaging"), ("$connect", "WebSocket")}
    function = json.dumps({"bindings": [{"type": "serviceBusTrigger", "direction": "in", "queueName": "orders", "name": "m"},
                                        {"type": "queue", "direction": "out", "queueName": "done", "name": "out"},
                                        {"type": "http", "direction": "out", "name": "res"}]})
    assert _analyze(tmp_path, "Process/function.json", function)["Azure Functions bindings"].evidence == [
        "Process/function.json: serviceBusTrigger in orders", "Process/function.json: queue out done"]


def test_oversized_and_unreadable_documents(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(protocols, "MAX_PROTOCOL_BYTES", 10)
    document = json.dumps({"asyncapi": "2.6.0", "channels": {}})
    assert _analyze(tmp_path, "events.json", document)["API document scan budget reached"].confidence == "UNKNOWN"
    assert _analyze(tmp_path, "src/app.py", 'client.subscribe("x")\n') == {}
    monkeypatch.setattr(protocols, "MAX_PROTOCOL_BYTES", 1 << 20)
    assert _analyze(tmp_path, "events.json", '{"asyncapi": "2.6.0", "channels": ')["API document unreadable"].confidence \
        == "UNKNOWN"


def test_the_scanners_are_linear_on_adversarial_input():
    for text in ("{" * 50_000, "{" + "a:" * 50_000, "{" + '"' * 50_000, "{" + "(" * 50_000):
        started = time.perf_counter()
        _object_keys(text, 0)
        assert time.perf_counter() - started < 5
    for text in ("func a(" * 20_000, "func a() { x.Upgrade(w, r," * 10_000, '.HandleFunc("/", func(' * 20_000):
        started = time.perf_counter()
        _go_websocket_routes(text)
        assert time.perf_counter() - started < 5
    for text in ("fn a" * 30_000, 'fn a(ws: WebSocketUpgrade) { .route("/a", get(a))' * 5_000):
        started = time.perf_counter()
        _rust_websocket_routes(text)
        assert time.perf_counter() - started < 5
    for extension, text in ((".js", "jayson.Server({" * 20_000), (".py", "@method\n" * 30_000 + "mqtt paho"),
                            (".java", "@WebMethod\n" * 30_000), (".cs", "[OperationContract]\n" * 30_000)):
        started = time.perf_counter()
        code_endpoints(text, extension)
        assert time.perf_counter() - started < 10, extension


def test_the_code_index_matches_contracts_to_code(tmp_path: Path):
    project = tmp_path / "project"
    asyncapi = {"asyncapi": "2.6.0", "info": {"title": "Users", "version": "1"}, "channels": {
        "users/{userId}/signedup": {"publish": {"message": {"name": "Signup"}}},
        "billing/invoices": {"subscribe": {"message": {"name": "Invoice"}}}}}
    openrpc = {"openrpc": "1.2.6", "info": {"title": "Math", "version": "1"},
               "methods": [{"name": "add", "params": []}, {"name": "sub", "params": []}]}
    files = {
        "contracts/events.json": json.dumps(asyncapi),
        "contracts/math.json": json.dumps(openrpc),
        "src/mqtt_worker.py": ('import paho.mqtt.client as mqtt\nclient.subscribe("users/+/signedup", qos=1)\n'
                               'client.publish("metrics/cpu", "1")\n'),
        "src/rpc.py": ("from jsonrpcserver import method\n@method\ndef add(a, b):\n    return a + b\n"
                       "@method\ndef mul(a, b):\n    return a * b\n"),
        "src/hooks.py": ('from flask import Flask\napp = Flask(__name__)\n@app.route("/webhooks/stripe", methods=["POST"])\n'
                         "def stripe_hook():\n    return ''\n"),
        "src/github.py": ('from flask import Flask\napp = Flask(__name__)\n@app.route("/webhooks/github", methods=["POST"])\n'
                          "def github_hook():\n    return request.headers.get('X-Hub-Signature-256')\n"),
        "contracts/calculator.wsdl": ('<?xml version="1.0"?>\n<definitions name="Calculator" '
                                      'xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:calc">\n'
                                      '  <portType name="CalculatorPort">\n    <operation name="add"/>\n'
                                      '    <operation name="multiply"/>\n  </portType>\n'
                                      '  <service name="CalculatorService"/>\n</definitions>\n'),
        "src/Calculator.java": ('@WebService(serviceName = "CalculatorService")\npublic class Calculator {\n  @WebMethod\n'
                                "  public int add(int a, int b) { return a + b; }\n  @WebMethod\n"
                                "  public int subtract(int a, int b) { return a - b; }\n}\n"),
    }
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    value = report["metrics"]["code_index"]["protocols"]
    assert value["counts"]["MQTT"] == {"consume": 1, "produce": 1}
    assert (value["asyncapi_channels"], value["openrpc_methods"]) == (2, 2)
    # users/+/signedup covers users/{userId}/signedup; billing/invoices has no code, metrics/cpu no contract.
    assert [item["address"] for item in value["unused_channels"]] == ["billing/invoices"]
    assert [item["name"] for item in value["undeclared_topics"]] == ["metrics/cpu"]
    assert (value["unimplemented_methods"], value["undocumented_methods"]) == (["sub"], ["mul"])
    assert sorted((item["path"], item["verified"]) for item in value["webhook_routes"]) == [
        ("/webhooks/github", True), ("/webhooks/stripe", False)]
    assert value["wsdl_operations"] == 2
    assert value["unimplemented_operations"] == [{"operation": "multiply", "file": "contracts/calculator.wsdl"}]
    assert value["undeclared_operations"] == [{"operation": "subtract", "file": "src/Calculator.java", "line": 5}]
    titles = {item["title"] for item in report["findings"] if item["analyzer"] == "code-index"}
    assert {"Protocol endpoints", "AsyncAPI channels no code uses", "Topics no AsyncAPI document declares",
            "OpenRPC methods no JSON-RPC server registers", "JSON-RPC methods no OpenRPC document declares",
            "WSDL operations no SOAP server implements", "SOAP operations no WSDL declares",
            "Webhook routes without a signature check in their file"} <= titles
