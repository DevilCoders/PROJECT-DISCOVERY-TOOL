"""The network service map: ports Dockerfiles, Compose, Kubernetes and Terraform declare,
joined with the ports code listens on and the services code connects to."""
import json
import time
from pathlib import Path

import pytest

from project_discovery.analyzers.delivery.deployment import _compose_ports, _terraform_ports
from project_discovery.cli import run_scan
from project_discovery.core.safe_parsers import safe_yaml_load_all
from project_discovery.core.source_utils import LineIndex
from project_discovery.intelligence.facts import collecting_facts


def _scan(tmp_path: Path, files: dict[str, str]) -> tuple[dict, dict[str, dict]]:
    project = tmp_path / "project"
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    findings = {item["title"]: item for item in report["findings"] if item["analyzer"] == "code-index"}
    return report["metrics"]["code_index"]["network_services"], findings


def _port(services: dict, number: int) -> dict:
    return next(item for item in services["ports"] if item["port"] == number)


def _terraform(source: str) -> list[tuple[str, dict]]:
    with collecting_facts() as facts:
        _terraform_ports(source, LineIndex(source))
    return [(name, json.loads(detail)) for kind, name, detail in facts.facts if kind == "net_declared"]


PROJECT = {
    "Dockerfile": "FROM golang:1.22\nEXPOSE 8080/tcp 9090\nEXPOSE $PORT\n",
    "docker-compose.yml": (
        "services:\n"
        "  api:\n"
        "    build: .\n"
        "    ports:\n"
        "      - \"127.0.0.1:8080:8080\"\n"
        "      - 9000:22\n"  # unquoted: YAML 1.1 would read the base-60 number 540022
        "      - target: 9090\n"
        "        published: 19090\n"
        "  db:\n"
        "    image: postgres:16\n"
        "    expose:\n"
        "      - \"5432\"\n"
    ),
    "k8s/app.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n"
        "spec:\n  template:\n    metadata:\n      labels:\n        app: api\n"
        "    spec:\n      containers:\n        - name: api\n          image: api:1\n"
        "          ports:\n            - containerPort: 8080\n              name: http\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"
        "spec:\n  selector:\n    app: api\n  ports:\n    - port: 80\n      targetPort: http\n"
        "    - port: 81\n      targetPort: 8081\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: cache\n  namespace: infra\n"
        "spec:\n  selector:\n    app: redis\n  ports:\n    - port: 6379\n"
    ),
    "infra/main.tf": (
        'resource "aws_security_group" "web" {\n'
        '  ingress {\n    from_port   = 8080\n    to_port     = 8080\n    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
        '  egress {\n    from_port   = 0\n    to_port     = 0\n    protocol    = "-1"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
        '}\n'
        'resource "aws_lb_listener" "front" {\n  port     = 443\n  protocol = "HTTPS"\n'
        '  default_action {\n    type = "forward"\n  }\n}\n'
        'resource "google_compute_firewall" "ops" {\n'
        '  source_ranges = [\n    "0.0.0.0/0", # everyone\n  ]\n'
        '  allow {\n    protocol = "tcp"\n    ports    = ["22", "6000-6010"]\n  }\n}\n'
    ),
    "main.go": (
        'package main\n\nimport (\n\t"net"\n\t"net/http"\n)\n\n'
        'func main() {\n'
        '\tgo http.ListenAndServe(":6060", nil)\n'
        '\tl, _ := net.Listen("tcp", "0.0.0.0:8080")\n\t_ = l\n'
        '\tc, _ := net.Dial("tcp", "db:5433")\n\t_ = c\n'
        '\tr, _ := net.Dial("tcp", "cache.infra.svc.cluster.local:6379")\n\t_ = r\n'
        '}\n'
    ),
    "client.py": "import requests\n\ndef users():\n    return requests.get('http://api:8080/users')\n",
}


def test_declarations_listeners_and_connections_are_joined_by_port(tmp_path: Path):
    pytest.importorskip("yaml")
    services, findings = _scan(tmp_path, PROJECT)

    port = _port(services, 8080)
    sources = sorted(item["source"] for item in port["declared"])
    assert sources == ["compose", "dockerfile", "kubernetes", "kubernetes-service", "terraform"]
    compose = next(item for item in port["declared"] if item["source"] == "compose")
    assert compose["host_ip"] == "127.0.0.1" and compose["published"] == "8080" and compose["service"] == "api"
    # The Service's named targetPort resolves through the selected pods' container port names.
    service = next(item for item in port["declared"] if item["source"] == "kubernetes-service")
    assert service["target_name"] == "http" and service["port"] == 80 and "selector" not in service
    terraform = next(item for item in port["declared"] if item["source"] == "terraform")
    assert terraform["public"] is True and terraform["scope"] == "firewall"
    assert port["listeners"] == [{"file": "main.go", "line": 10, "api": "net.Listen", "address": "0.0.0.0:8080"}]
    # YAML 1.2 numbers: 9000:22 maps host port 9000 to container port 22.
    assert [item["published"] for item in _port(services, 22)["declared"] if item["source"] == "compose"] == ["9000"]
    assert _port(services, 9090)["declared"][1]["published"] == "19090"
    assert _port(services, 443)["declared"][0]["scope"] == "edge"
    assert services["ranges"][0]["ports"] == "6000-6010" and services["ranges"][0]["public"] is True
    # The egress rule (protocol -1 to every address) opens nothing.
    assert all(item["ports"] != "1-65535" for item in services["ranges"])
    assert {item["name"] for item in services["services"]} == {"api", "db", "cache"}
    connections = {item["address"]: item.get("service") for item in services["connections"]}
    assert connections == {"db:5433": "compose db", "cache.infra.svc.cluster.local:6379": "kubernetes cache",
                           "api": "compose api"}

    summary = findings["Network service map"]
    assert "declared and listened on: 8080" in summary["detail"]
    exposed = findings["Ports open to every address that code listens on"]
    assert exposed["severity"] == "MEDIUM" and exposed["category"] == "security"
    assert exposed["evidence"] == [
        "port 8080: infra/main.tf:1 (aws_security_group.web open to every address); main.go:10 (net.Listen 0.0.0.0:8080)"]
    assert findings["Connections to ports a service does not declare"]["evidence"] == [
        "main.go:12 connects to db:5433; compose service db declares 5432"]
    assert findings["Kubernetes Services targeting ports their pods do not declare"]["evidence"] == [
        "k8s/app.yaml: Service api port 81 targets 8081; Deployment/api declare(s) 8080"]
    unserved = findings["Declared ports no code listener uses"]
    assert "(22, 5432, 6379, 8081, 9090)" in unserved["detail"]
    assert findings["Listeners no deployment file declares"]["evidence"] == [
        "port 6060: main.go:9 (http.ListenAndServe :6060)"]


def test_listeners_without_a_literal_port_keep_declared_ports_unjudged(tmp_path: Path):
    files = {
        "Dockerfile": "FROM python:3.12\nEXPOSE 8000 9100\n",
        # The bind names the port; listen(backlog) and accept() name none.
        "app.py": "import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 8000))\ns.listen(5)\nconn, _ = s.accept()\n",
    }
    services, findings = _scan(tmp_path, files)
    assert services["listeners_without_literal_port"] == []
    assert "(9100)" in findings["Declared ports no code listener uses"]["detail"]

    files["metrics.go"] = 'package main\nimport "net"\nfunc serve(addr string) { net.Listen("tcp", addr) }\n'
    services, findings = _scan(tmp_path / "again", files)
    assert [item["api"] for item in services["listeners_without_literal_port"]] == ["net.Listen"]
    assert "Declared ports no code listener uses" not in findings


def test_test_listeners_loopback_listeners_and_server_factories(tmp_path: Path):
    services, findings = _scan(tmp_path, {
        "Dockerfile": "FROM node:20\nEXPOSE 3000\n",
        # createServer names no port: the .listen() on it does.
        "server.js": ('const http = require("http");\nhttp.createServer(h).listen(3000);\n'
                      'http.createServer(h).listen(9229, "127.0.0.1");\n'),
        "tests/server.test.js": 'const net = require("net");\nnet.createServer(h).listen(7000, "0.0.0.0");\n',
    })
    assert services["listeners_without_literal_port"] == []
    assert _port(services, 7000)["listeners"][0]["test"] is True
    assert _port(services, 3000)["declared"][0]["source"] == "dockerfile"
    # 9229 binds loopback and 7000 is a test's: neither is an undeclared listener.
    assert "Listeners no deployment file declares" not in findings
    assert "Declared ports no code listener uses" not in findings


def test_kubernetes_selectors_namespaces_and_named_ports(tmp_path: Path):
    pytest.importorskip("yaml")
    services, findings = _scan(tmp_path, {"k8s.yaml": (
        "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: web\n  namespace: prod\n"
        "spec:\n  template:\n    metadata:\n      labels:\n        app: web\n        tier: front\n"
        "    spec:\n      containers:\n        - name: web\n          image: web:1\n"
        "          ports:\n            - containerPort: 8443\n              name: https\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n  namespace: prod\n"
        "spec:\n  type: NodePort\n  selector:\n    app: web\n  ports:\n"
        "    - port: 443\n      targetPort: https\n      nodePort: 30443\n"
        "    - port: 80\n      targetPort: http\n"
        "---\n"  # another namespace: selects nothing, so it is not judged
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n  namespace: staging\n"
        "spec:\n  selector:\n    app: web\n  ports:\n    - port: 443\n      targetPort: 9999\n"
        "---\n"  # no selector (endpoints managed elsewhere): not judged
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: external\n"
        "spec:\n  ports:\n    - port: 5432\n      targetPort: 5432\n"
    )})
    # The named targetPort resolves through the selected pods' port names, in the Service's namespace.
    resolved = [item for item in _port(services, 8443)["declared"] if item["source"] == "kubernetes-service"]
    assert resolved == [{
        "file": "k8s.yaml", "namespace": "prod", "node_port": 30443, "port": 443, "protocol": "tcp",
        "scope": "workload", "service": "web", "source": "kubernetes-service", "target_name": "https", "type": "NodePort",
    }]
    assert [item["target_name"] for item in services["unresolved_target_ports"]] == ["http"]
    assert findings["Kubernetes Services targeting ports their pods do not declare"]["evidence"] == [
        "k8s.yaml: Service web port 80 targets name 'http'; StatefulSet/web declare(s) https"]


def test_terraform_rules_by_provider():
    facts = _terraform(
        'resource "aws_security_group_rule" "in" {\n  type = "ingress"\n  from_port = 5432\n  to_port = 5432\n'
        '  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]\n}\n'
        'resource "aws_security_group_rule" "out" {\n  type = "egress"\n  from_port = 0\n  to_port = 65535\n'
        '  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        'resource "aws_security_group" "all" {\n'
        '  ingress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    ipv6_cidr_blocks = ["::/0"]\n  }\n'
        '  ingress {\n    from_port = var.port\n    to_port = var.port\n    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
        '  ingress {\n    from_port = 8\n    to_port = 0\n    protocol = "icmp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
        '}\n'
        'resource "aws_vpc_security_group_ingress_rule" "https" {\n  ip_protocol = "tcp"\n  from_port = 443\n'
        '  to_port = 443\n  cidr_ipv4 = "0.0.0.0/0"\n}\n'
        'resource "azurerm_network_security_rule" "web" {\n  direction = "Inbound"\n  access = "Allow"\n'
        '  protocol = "Tcp"\n  destination_port_ranges = ["80", "8000-8100"]\n  source_address_prefix = "Internet"\n}\n'
        'resource "azurerm_network_security_rule" "deny" {\n  direction = "Inbound"\n  access = "Deny"\n'
        '  protocol = "*"\n  destination_port_range = "*"\n  source_address_prefix = "*"\n}\n'
        'resource "azurerm_network_security_group" "nsg" {\n'
        '  security_rule {\n    direction = "Inbound"\n    access = "Allow"\n    protocol = "Tcp"\n'
        '    destination_port_range = "3389"\n    source_address_prefix = "10.1.0.0/16"\n  }\n'
        '  security_rule {\n    direction = "Outbound"\n    access = "Allow"\n    protocol = "*"\n'
        '    destination_port_range = "*"\n    source_address_prefix = "*"\n  }\n}\n'
        'resource "google_compute_firewall" "egress" {\n  direction = "EGRESS"\n'
        '  allow {\n    protocol = "tcp"\n    ports = ["25"]\n  }\n}\n'
        'resource "google_compute_firewall" "internal" {\n  source_ranges = ["10.0.0.0/8"]\n'
        '  allow {\n    protocol = "udp"\n  }\n  allow {\n    protocol = "icmp"\n  }\n'
        '  deny {\n    protocol = "tcp"\n    ports = ["23"]\n  }\n}\n'
        'resource "aws_lb_target_group" "app" {\n  port = 8080\n  protocol = "HTTP"\n'
        '  health_check {\n    port = "traffic-port"\n  }\n}\n'
        'resource "kubernetes_service_v1" "api" {\n  metadata {\n    name = "api"\n  }\n  spec {\n'
        '    type = "NodePort"\n    port {\n      port = 80\n      target_port = 8080\n      node_port = 30080\n'
        '    }\n  }\n}\n'
    )
    summary = [(name, item["resource"], item["protocol"], item["scope"], item.get("public", False)) for name, item in facts]
    assert summary == [
        ("5432", "aws_security_group_rule.in", "tcp", "firewall", False),
        ("1-65535", "aws_security_group.all", "any", "firewall", True),  # protocol -1: every port
        ("443", "aws_vpc_security_group_ingress_rule.https", "tcp", "firewall", True),
        ("80", "azurerm_network_security_rule.web", "tcp", "firewall", True),
        ("8000-8100", "azurerm_network_security_rule.web", "tcp", "firewall", True),
        ("3389", "azurerm_network_security_group.nsg", "tcp", "firewall", False),
        ("1-65535", "google_compute_firewall.internal", "udp", "firewall", False),  # an allow without ports
        ("8080", "aws_lb_target_group.app", "tcp", "workload", False),
        ("8080", "kubernetes_service_v1.api", "tcp", "workload", False),
    ]
    assert facts[-1][1]["port"] == 80 and facts[-1][1]["node_port"] == 30080
    assert facts[0][1]["line"] == 1


def test_terraform_blocks_skip_strings_comments_and_heredocs():
    facts = _terraform(
        'resource "aws_security_group" "doc" {\n'
        '  description = <<EOT\n  }}} not the end {{{\nEOT\n'
        '  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n'
        '    cidr_blocks = ["192.168.0.0/16"] # office } brace in a comment\n  }\n'
        '  /* } */\n'
        '  tags = { Name = "a } b" }\n'
        '}\n'
        'resource "aws_security_group_rule" "after" {\n  type = "ingress"\n  from_port = 6379\n  to_port = 6379\n'
        '  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
    )
    assert [(name, item["resource"], item.get("public", False), item["line"]) for name, item in facts] == [
        ("22", "aws_security_group.doc", False, 1), ("6379", "aws_security_group_rule.after", True, 14)]


@pytest.mark.parametrize("source", [
    'resource "aws_security_group" "x" {\n' * 20_000,  # nested, never closed
    'resource "aws_security_group" "x" {\n' + "  ingress {\n" * 20_000,
    'resource "aws_security_group_rule" "x" {\n' + "  ports = [\n" * 20_000 + "}\n",
    'resource "aws_security_group_rule" "x" {\n  description = "' + "{" * 200_000 + "\n}\n",
    'resource "aws_security_group" "x" {\n' + "  ingress {\n  }\n" * 20_000 + "}\n",
])
def test_terraform_port_extraction_is_linear(source: str):
    started = time.perf_counter()
    _terraform(source)
    assert time.perf_counter() - started < 5


def test_compose_port_syntax():
    assert list(_compose_ports([
        "3000", "8080:80", "127.0.0.1:8001:8001/udp", "[::1]:6001:6001", "127.0.0.1::5000",
        "9090-9091:8080-8081", 9000, {"target": 80, "published": "8080", "host_ip": "0.0.0.0", "protocol": "tcp"},
    ])) == [
        ("3000", None, None, None), ("80", None, "8080", None), ("8001", "udp", "8001", "127.0.0.1"),
        ("6001", None, "6001", "::1"), ("5000", None, None, "127.0.0.1"), ("8080-8081", None, "9090-9091", None),
        ("9000", None, None, None), (80, "tcp", "8080", "0.0.0.0"),
    ]


def test_yaml_1_2_numbers_keep_base_60_forms_as_text():
    pytest.importorskip("yaml")
    text = "a: 8080:22\nb: 1:30.5\nc: 0x10\nd: 12\ne: '1:2'\nf: 2001-12-14 21:59:43\n"
    assert safe_yaml_load_all(text)[0]["a"] == 484822  # YAML 1.1, as PyYAML reads it
    loaded = safe_yaml_load_all(text, base60=False)[0]
    assert {key: loaded[key] for key in "abcde"} == {"a": "8080:22", "b": "1:30.5", "c": 16, "d": 12, "e": "1:2"}
    assert loaded["f"].year == 2001  # timestamps keep their colons and their type
