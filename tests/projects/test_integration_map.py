"""Integration points per scan and the cross-project integration map."""
import json
from pathlib import Path

from project_discovery.analyzers.api.integration import (
    EndpointIndex,
    IntegrationAnalyzer,
    normalize_route,
    route_matches,
)
from project_discovery.catalog.languages import detect_language
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord
from project_discovery.projects.comparison import (
    compare_many_reports,
    compare_reports,
    write_comparison,
)


def facts_for(tmp_path: Path, name: str, text: str) -> list[tuple[str, str, dict]]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, path.suffix, detect_language(name))
    analyzer = IntegrationAnalyzer()
    assert analyzer.supports(record)
    with collecting_facts() as facts:
        assert analyzer.analyze(path, record) == []
    return [(kind, value, json.loads(detail)) for kind, value, detail in facts.facts]


def test_route_normalization_and_matching():
    assert normalize_route("/users/<int:user_id>/posts/{post}") == "/users/{}/posts/{}"
    assert normalize_route("/teams/:team/") == "/teams/{}/"
    assert route_matches("/api/v1/users/{}", "/users/{}") == "prefixed"
    assert route_matches("/users/{}", "/users/{}") == "exact"
    assert route_matches("/users/{}/posts", "/users/{}") == ""
    assert route_matches("/anything", "/{}") == ""  # all-parameter routes match nothing
    index = EndpointIndex([("GET", "/users/{}"), ("POST", "/users")])
    assert index.match("GET", "/users/{}") == ("GET", "/users/{}", "exact")
    assert index.match("DELETE", "/users/{}") is None


def test_python_http_messaging_and_grpc_points(tmp_path: Path):
    facts = facts_for(tmp_path, "client.py", (
        "import requests, grpc\nfrom kafka import KafkaProducer\nfrom . import users_pb2_grpc\n"
        "producer = KafkaProducer()\n"
        "def run(uid, channel):\n"
        "    requests.get(f'http://users-service:8000/users/{uid}?full=1')\n"
        "    requests.request('DELETE', 'https://api.example.com/items/42')\n"
        "    producer.send('user-created', b'x')\n"
        "    users_pb2_grpc.UserServiceStub(channel)\n"
        "    channel.basic_publish(exchange='', routing_key='jobs', body=b'')\n"
    ))
    assert ("http_call", "GET /users/{}", {"host": "users-service"}) in facts
    assert ("http_call", "DELETE /items/{}", {"host": "api.example.com"}) in facts
    assert ("message_topic", "user-created", {"role": "produce", "system": "Kafka"}) in facts
    assert ("message_topic", "jobs", {"role": "produce", "system": "RabbitMQ"}) in facts
    assert ("grpc_client", "UserService", {}) in facts


def test_lexical_points_ignore_comments(tmp_path: Path):
    facts = facts_for(tmp_path, "api.ts", (
        "export const getUser = (id: number) => fetch(`/api/users/${id}`, { method: 'GET' });\n"
        "export const save = (u: object) => axios.post('/api/users', u);\n"
        "// fetch('/commented/out')\n"
        "await consumer.subscribe({ topic: 'user-created' });\n"
    ))
    calls = {value for kind, value, _ in facts if kind == "http_call"}
    assert calls == {"GET /api/users/{}", "POST /api/users"}
    assert ("message_topic", "user-created", {"role": "consume", "system": "Kafka"}) in facts
    go = facts_for(tmp_path, "main.go", (
        "package main\nfunc main() {\n\tr := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{\"k\"}, Topic: \"orders\"})\n"
        "\tc := pb.NewOrderServiceClient(conn)\n\thttp.Get(\"http://orders/orders/7\")\n}\n"))
    assert ("message_topic", "orders", {"role": "consume", "system": "Kafka"}) in go
    assert ("grpc_client", "OrderService", {}) in go


def test_contracts_and_manifests(tmp_path: Path):
    proto = facts_for(tmp_path, "users.proto",
                      "syntax = \"proto3\";\npackage users.v1;\nservice UserService {\n  rpc GetUser (Req) returns (User);\n}\n")
    assert proto == [("grpc_service", "users.v1.UserService", {"rpcs": ["GetUser"]})]
    assert facts_for(tmp_path, "pyproject.toml", "[project]\nname = \"users-service\"\n") == [
        ("package_name", "users-service", {"ecosystem": "pypi"})]
    assert facts_for(tmp_path, "go.mod", "module github.com/acme/notifier\n") == [
        ("package_name", "github.com/acme/notifier", {"ecosystem": "go"})]
    pom = facts_for(tmp_path, "pom.xml", (
        "<project><parent><groupId>org.springframework.boot</groupId><artifactId>parent</artifactId></parent>"
        "<groupId>com.acme</groupId><artifactId>billing</artifactId></project>"))
    assert pom == [("package_name", "com.acme:billing", {"ecosystem": "maven"})]


def _report(root: str, integration: dict, dependencies: list[str] = ()) -> dict:
    return {
        "schema_version": "1.0", "root": root, "files": [],
        "findings": [{"title": f"Declared dependency: {name}", "category": "dependency", "evidence": []}
                     for name in dependencies],
        "metrics": {"languages": {}, "python_dependency_graph": {"modules": []},
                    "code_index": {"integration": integration}},
    }


def test_integration_map_links_projects(tmp_path: Path):
    provider = _report("/users", {
        "packages": [{"name": "users-service", "ecosystem": "pypi"}],
        "endpoints": [{"method": "GET", "path": "/users/{}", "file": "app.py"}],
        "topics": [{"name": "user-created", "system": "Kafka", "role": "produce", "file": "app.py"}],
        "grpc": {"service": ["users.v1.UserService"], "server": [], "client": []},
    })
    consumer = _report("/web", {
        "http_calls": [{"method": "GET", "path": "/api/users/{}", "host": "", "file": "api.ts"}],
        "topics": [{"name": "user-created", "system": "Kafka", "role": "consume", "file": "worker.ts"}],
        "grpc": {"service": [], "server": [], "client": ["UserService"]},
    }, dependencies=["users_service"])
    mapping = compare_reports(provider, consumer)["integration_map"]
    edges = {(edge["from"], edge["to"], edge["kind"]): edge for edge in mapping["edges"]}
    assert edges[("/web", "/users", "package_dependency")]["confidence"] == "CONFIRMED"
    assert edges[("/web", "/users", "http_api")]["evidence"] == [
        "GET /api/users/{} (api.ts) -> GET /users/{} [prefixed]"]
    assert ("/users", "/web", "messaging") in edges
    assert edges[("/web", "/users", "grpc")]["evidence"] == ["UserService"]
    many = compare_many_reports([provider, consumer, _report("/other", {})])
    assert len(many["integration_map"]["edges"]) == 4
    written = write_comparison(many, tmp_path / "comparison", {"markdown"})
    assert "## Integration map" in written[0].read_text(encoding="utf-8")


def test_old_reports_fall_back_to_endpoint_findings():
    old = {
        "schema_version": "1.0", "root": "/api", "files": [], "metrics": {"languages": {}},
        "findings": [{"title": "API route declarations: app.py", "category": "api",
                      "evidence": ["app.py:3 GET /orders/<int:order_id>"]}],
    }
    caller = _report("/client", {"http_calls": [{"method": "GET", "path": "/orders/{}", "host": "api", "file": "c.py"}]})
    edges = compare_reports(old, caller)["integration_map"]["edges"]
    assert [(edge["from"], edge["kind"]) for edge in edges] == [("/client", "http_api")]


def test_scan_records_integration_summary(tmp_path: Path):
    project = tmp_path / "svc"
    (project / "app").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname = \"svc\"\n", encoding="utf-8")
    (project / "app" / "main.py").write_text(
        "from flask import Flask\nimport requests\napp = Flask(__name__)\n"
        "@app.route('/health')\ndef health():\n    return 'ok'\n"
        "def ping():\n    return requests.get('http://localhost/health')\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    integration = report["metrics"]["code_index"]["integration"]
    assert integration["packages"][0]["name"] == "svc"
    # Flask routes without methods= accept any method; client calls still match them.
    assert {"method": "ANY", "path": "/health", "file": "app/main.py"} in integration["endpoints"]
    assert integration["internal_calls_matched"] == 1
    assert any(item["title"] == "Integration points" for item in report["findings"])
