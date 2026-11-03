from pathlib import Path

from project_discovery.analyzers.api_source_analyzer import APIEndpointAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, relative: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Source")
    analyzer = APIEndpointAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_fastapi_and_flask_python_routes(tmp_path: Path):
    findings = _scan(
        tmp_path, "routes.py", "app/routes.py",
        "@app.get('/health')\ndef health():\n    return {'ok': True}\n"
        "@app.route('/users', methods=['GET', 'POST'])\ndef users():\n    pass\n",
    )
    assert len(findings) == 1
    assert "3 statically recognizable endpoint" in findings[0].detail
    assert any("GET /health" in item for item in findings[0].evidence)
    assert any("POST /users" in item for item in findings[0].evidence)


def test_javascript_and_java_route_declarations(tmp_path: Path):
    js = _scan(
        tmp_path, "routes.ts", "src/routes.ts",
        "app.get('/health', handler);\nrouter.post('/users', handler);\n",
    )
    assert any("GET /health" in item for item in js[0].evidence)
    java = _scan(
        tmp_path, "UserController.java", "src/UserController.java",
        '@GetMapping("/users")\npublic User list() {}\n'
        '@PostMapping("/users")\npublic User create() {}\n',
    )
    assert any("GET /users" in item for item in java[0].evidence)
    assert any("POST /users" in item for item in java[0].evidence)


def test_go_and_ruby_route_patterns(tmp_path: Path):
    go = _scan(
        tmp_path, "routes.go", "server/routes.go",
        'r.GET("/health", health)\nr.POST("/jobs", createJob)\n',
    )
    assert len(go[0].evidence) == 2
    ruby = _scan(
        tmp_path, "routes.rb", "config/routes.rb",
        "get '/health' do\nend\npost '/jobs' do\nend\n",
    )
    assert len(ruby[0].evidence) == 2


def test_non_route_source_produces_no_api_finding(tmp_path: Path):
    assert _scan(tmp_path, "math.py", "math.py", "def add(a, b):\n    return a + b\n") == []


def test_dotnet_minimal_api_and_cpp_crow_routes_are_scanned(tmp_path: Path):
    dotnet = _scan(
        tmp_path, "MinimalApi.cs", "src/MinimalApi.cs",
        'app.MapGet("/health", () => "ok");\n'
        'app.MapPost("/users", createUser);\n',
    )
    crow = _scan(
        tmp_path, "routes.cpp", "server/routes.cpp",
        'CROW_ROUTE(app, "/api/items");\n',
    )
    assert any("GET /health" in item for item in dotnet[0].evidence)
    assert any("POST /users" in item for item in dotnet[0].evidence)
    assert any("ANY /api/items" in item for item in crow[0].evidence)


def test_api_endpoint_analyzer_accepts_the_full_source_language_catalog():
    from project_discovery.language_catalog import source_extensions, source_language_names

    analyzer = APIEndpointAnalyzer()
    assert analyzer.languages == source_language_names()
    for extension in source_extensions():
        record = FileRecord("sample" + extension, 1, extension, "Source")
        assert analyzer.supports(record), extension
