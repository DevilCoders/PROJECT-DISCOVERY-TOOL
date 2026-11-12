from pathlib import Path

from project_discovery.analyzers.api.contracts import APIContractAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "API")
    analyzer = APIContractAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_openapi_json_extracts_routes_and_component_schemas(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "openapi.json",
        '{"openapi":"3.1.0","paths":{"/users":{"get":{"operationId":"listUsers"}},'
        '"/users/{id}":{"delete":{}}},"components":{"schemas":{"User":{},"Error":{}}}}',
    )
    assert "2 HTTP operations" in findings[0].detail
    assert "2 component schemas" in findings[0].detail
    assert "GET /users (listUsers)" in findings[0].evidence


def test_graphql_schema_and_operations_are_discovered(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "schema.graphql",
        "type User { id: ID! }\n"
        "input UserInput { name: String! }\n"
        "query GetUser { user(id: 1) { id } }\n",
    )
    assert "2 schema/type definitions" in findings[0].detail
    assert "1 named operations" in findings[0].detail
    assert "type User" in findings[0].evidence


def test_proto_service_and_rpc_contracts_are_discovered(tmp_path: Path):
    findings = _scan(
        tmp_path,
        "service.proto",
        "syntax = \"proto3\";\n"
        "message User {}\n"
        "service UserService { rpc GetUser (Request) returns (User); }\n"
        "enum State { UNKNOWN = 0; }\n",
    )
    assert "1 service" in findings[0].detail
    assert "1 rpc" in findings[0].detail
    assert "1 message" in findings[0].detail


def test_yaml_openapi_fallback_does_not_require_pyyaml(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.api.contracts as module

    path = tmp_path / "openapi.yaml"
    path.write_text(
        "openapi: 3.1.0\npaths:\n  /health:\n    get:\n      operationId: health\n",
        encoding="utf-8",
    )
    record = FileRecord("openapi.yaml", path.stat().st_size, ".yaml", "YAML")
    monkeypatch.setattr(
        module.importlib, "import_module", lambda _: (_ for _ in ()).throw(ImportError())
    )
    findings = module.APIContractAnalyzer().analyze(path, record)
    assert "1 HTTP operations" in findings[0].detail
    assert "GET /health (health)" in findings[0].evidence



def test_asyncapi_channels_operations_and_messages_are_discovered(tmp_path: Path):
    findings = _scan(
        tmp_path, "asyncapi.json",
        '{"asyncapi":"3.0.0","channels":{"userEvents":{"address":"users"}},'
        '"operations":{"receiveUser":{"action":"receive","channel":{"$ref":"#/channels/userEvents"}}},'
        '"components":{"messages":{"UserCreated":{}}}}',
    )
    assert "1 channels" in findings[0].detail
    assert "1 publish/subscribe operations" in findings[0].detail
    assert "1 component messages" in findings[0].detail
    assert "channel: userEvents" in findings[0].evidence
    assert "receive: receiveUser -> #/channels/userEvents" in findings[0].evidence


def test_openrpc_methods_and_schemas_are_discovered(tmp_path: Path):
    findings = _scan(
        tmp_path, "openrpc.json",
        '{"openrpc":"1.2.6","methods":[{"name":"system.ping"},{"name":"user.get"}],'
        '"components":{"schemas":{"User":{},"Error":{}}}}',
    )
    assert "2 JSON-RPC methods" in findings[0].detail
    assert "2 component schemas" in findings[0].detail
    assert "method: system.ping" in findings[0].evidence


def test_postman_nested_collection_requests_are_discovered_without_urls(tmp_path: Path):
    findings = _scan(
        tmp_path, "backend.postman_collection.json",
        '{"info":{"name":"Backend"},"item":[{"name":"Users","item":['
        '{"name":"List users","request":{"method":"GET","url":"https://example.test/users?token=secret"}},'
        '{"name":"Create user","request":{"method":"POST","url":"https://example.test/users"}}]}]}',
    )
    assert "2 request definitions" in findings[0].detail
    serialized = repr([item.to_dict() for item in findings])
    assert "List users" in serialized
    assert "token=secret" not in serialized


def test_wsdl_services_operations_and_raml_resources_are_discovered(tmp_path: Path):
    wsdl = _scan(
        tmp_path, "service.wsdl",
        '<definitions xmlns="urn:wsdl"><portType name="UserPort">'
        '<operation name="GetUser"/></portType><binding name="UserBinding"/>'
        '<service name="UserService"/></definitions>',
    )
    raml = _scan(
        tmp_path, "api.raml",
        "#%RAML 1.0\n/users:\n  get:\n  post:\n/users/{id}:\n  delete:\n",
    )
    assert "1 services" in wsdl[0].detail
    assert "1 unique operations" in wsdl[0].detail
    assert "service: UserService" in wsdl[0].evidence
    assert "2 resource paths" in raml[0].detail
    assert "3 HTTP method declarations" in raml[0].detail

def test_api_contract_reports_oversized_and_growing_source_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.api.contracts as module

    path = tmp_path / "openapi.json"
    path.write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_API_CONTRACT_BYTES", 8)
    record = FileRecord(path.name, 1, ".json", "API")
    findings = APIContractAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_api_contract_reports_growth_as_unknown_and_redacts_parser_errors(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.api import contracts as api_analyzer

    path = tmp_path / "openapi.json"
    path.write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")
    record = FileRecord(path.name, 1, ".json", "JSON")
    monkeypatch.setattr(api_analyzer, "_MAX_API_CONTRACT_BYTES", 8)
    budget = APIContractAnalyzer().analyze(path, record)
    assert len(budget) == 1 and budget[0].confidence == "UNKNOWN"
    assert "resource limit" in budget[0].title.lower()

    monkeypatch.setattr(api_analyzer, "_MAX_API_CONTRACT_BYTES", 1024)
    monkeypatch.setattr(
        api_analyzer.json, "loads",
        lambda _: (_ for _ in ()).throw(ValueError('password="api-parser-secret"')),
    )
    error = APIContractAnalyzer().analyze(path, record)
    assert error[0].confidence == "UNKNOWN"
    assert "api-parser-secret" not in error[0].detail


def test_webhook_secrets_never_reach_integration_paths():
    # Regression: Slack and Discord webhook URLs carry the credential in the path, and the
    # integration summary (and pdt compare) stored it verbatim.
    from project_discovery.analyzers.api.integration import _normalize_url

    # Built at run time so no complete webhook URL is committed (secret scanners flag it).
    slack = "https://hooks.slack.com/services/" + "T0FAKE000/B0FAKE000/" + "FakeSlack" + "WebhookSecret24"
    assert _normalize_url(slack) == (
        "hooks.slack.com", "/services/{}/{}/{}",
    )
    assert _normalize_url(
        "https://discord.com/api/webhooks/" + "123456789012345678/" + "FakeDiscordWebhook" + "TokenValue_abcdef"
    ) == ("discord.com", "/api/webhooks/{}/{}")
    assert _normalize_url("https://api.example.com/v1/oauth2-callback/users/42") == (
        "api.example.com", "/v1/oauth2-callback/users/{}",
    )
    assert _normalize_url("https://api.example.com/keys/sk_live_" + "Ab12" * 6) == ("api.example.com", "/keys/{}")
