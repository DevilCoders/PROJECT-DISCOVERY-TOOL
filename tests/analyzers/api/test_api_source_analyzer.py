from pathlib import Path

from project_discovery.analyzers.api import routes as api_source_analyzer
from project_discovery.analyzers.api.routes import APIEndpointAnalyzer
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


def test_go_ruby_dotnet_and_cpp_routes(tmp_path: Path):
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
    dotnet = _scan(
        tmp_path, "MinimalApi.cs", "src/MinimalApi.cs",
        'app.MapGet("/health", () => "ok");\n'
        'app.MapPost("/users", createUser);\n',
    )
    assert any("GET /health" in item for item in dotnet[0].evidence)
    assert any("POST /users" in item for item in dotnet[0].evidence)
    crow = _scan(
        tmp_path, "routes.cpp", "server/routes.cpp",
        'CROW_ROUTE(app, "/api/items");\n',
    )
    assert any("ANY /api/items" in item for item in crow[0].evidence)


def test_non_route_source_produces_no_api_finding(tmp_path: Path):
    assert _scan(tmp_path, "math.py", "math.py", "def add(a, b):\n    return a + b\n") == []


def test_api_endpoint_analyzer_accepts_the_full_source_language_catalog():
    from project_discovery.catalog.languages import source_extensions, source_language_names

    analyzer = APIEndpointAnalyzer()
    assert analyzer.languages == source_language_names()
    for extension in source_extensions():
        record = FileRecord("sample" + extension, 1, extension, "Source")
        assert analyzer.supports(record), extension


def test_python_ast_endpoint_budget_returns_unknown(tmp_path: Path, monkeypatch):
    path = tmp_path / "large.py"
    path.write_text("@app.get('/health')\ndef health(): pass\n", encoding="utf-8")
    monkeypatch.setattr(api_source_analyzer, "MAX_PYTHON_ENDPOINT_AST_BYTES", 1)
    record = FileRecord("large.py", path.stat().st_size, ".py", "Python")
    finding = APIEndpointAnalyzer().analyze(path, record)[0]
    assert finding.confidence == "UNKNOWN"
    assert "AST resource limit" in finding.title


def test_polyglot_endpoint_stream_budget_returns_unknown(tmp_path: Path, monkeypatch):
    path = tmp_path / "routes.ts"
    path.write_text(
        "app.get('/first', handler);\n" + ("// " + "x" * 100) +
        "\napp.get('/not-seen', handler);\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(api_source_analyzer, "MAX_SOURCE_ENDPOINT_SCAN_BYTES", 40)
    record = FileRecord("routes.ts", path.stat().st_size, ".ts", "TypeScript")
    findings = APIEndpointAnalyzer().analyze(path, record)
    assert any(item.confidence == "UNKNOWN" and "budget reached" in item.title for item in findings)


def test_crlf_source_is_not_reported_as_truncated(tmp_path: Path, monkeypatch):
    # PDT-234: newline translation shortens decoded CRLF text, so comparing the file size
    # with decoded bytes reported every CRLF source file as over budget.
    path = tmp_path / "routes.ts"
    path.write_bytes(b"app.get('/health', handler);\r\n// comment\r\n" * 3)
    record = FileRecord("routes.ts", path.stat().st_size, ".ts", "TypeScript")
    findings = APIEndpointAnalyzer().analyze(path, record)
    assert [item.title for item in findings] == ["API route declarations: routes.ts"]
    # A budget that ends exactly at the end of the file is not a truncation either.
    exact = len(path.read_text(encoding="utf-8").encode("utf-8"))
    monkeypatch.setattr(api_source_analyzer, "MAX_SOURCE_ENDPOINT_SCAN_BYTES", exact)
    assert not any("budget reached" in item.title for item in APIEndpointAnalyzer().analyze(path, record))


def test_python_api_ast_detects_source_growth_after_inventory(tmp_path: Path, monkeypatch):
    path = tmp_path / "growing_routes.py"
    path.write_text("@app.get('/health')\\ndef health(): pass\\n", encoding="utf-8")
    monkeypatch.setattr(api_source_analyzer, "MAX_PYTHON_ENDPOINT_AST_BYTES", 8)
    record = FileRecord(path.name, 1, ".py", "Python")
    findings = APIEndpointAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def _routes(tmp_path: Path, filename: str, source: str) -> list[str]:
    findings = _scan(tmp_path, filename, filename, source)
    return [item.split(" ", 1)[1] for finding in findings if finding.title.startswith("API route declarations")
            for item in finding.evidence]


def test_framework_route_forms_the_docs_list(tmp_path: Path):
    # Regressions: JAX-RS yielded nothing, Spring needed a string literal first argument and
    # had no @RequestMapping, NestJS @Get(':id') was recorded twice, and Echo and Rails
    # routes were not recognized.
    jaxrs = _routes(tmp_path, "FruitResource.java", (
        '@Path("/fruits")\npublic class FruitResource {\n    @GET\n    public List<Fruit> list() {}\n'
        '    @GET\n    @Path("/{id}")\n    public Fruit get() {}\n}\n'
    ))
    assert "GET /{id}" in jaxrs and len(jaxrs) == 2
    spring = _routes(tmp_path, "UserController.java", (
        '@RequestMapping(path = "/api/users")\nclass C {\n  @GetMapping\n  List<User> all() {}\n'
        '  @PostMapping(value = "/new")\n  User add() {}\n}\n'
    ))
    assert spring == ["ANY /api/users", "GET ", "POST /new"]
    nest = _routes(tmp_path, "cats.controller.ts", "@Get(':id')\nfindOne() {}\n@Post()\ncreate() {}\n")
    assert nest == ["GET :id", "POST "]
    echo = _routes(tmp_path, "main.go", 'e.GET("/users/:id", getUser)\ng.DELETE("/users/:id", del)\n')
    assert echo == ["GET /users/:id", "DELETE /users/:id"]
    rails = _routes(tmp_path, "routes.rb", "get 'photos', to: 'photos#index'\npost '/login' => 'sessions#create'\n")
    assert rails == ["GET photos", "POST /login"]


def test_lookups_and_client_declarations_are_not_served_endpoints(tmp_path: Path):
    lookups = _routes(tmp_path, "views.js", (
        "const name = user.get('name');\nconst type = header.get('Content-Type');\nconst owner = container.get('owner');\n"
    ))
    assert lookups == []
    retrofit = _routes(tmp_path, "GitHubService.java", (
        'interface GitHubService {\n  @GET("users/{user}/repos")\n  Call<List<Repo>> listRepos(@Path("user") String user);\n}\n'
    ))
    assert retrofit == []


def test_endpoint_fact_cap_is_reported(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(api_source_analyzer, "MAX_ENDPOINT_FACTS", 2)
    findings = _scan(tmp_path, "app.js", "app.js", "".join(f"app.get('/r{index}', h);\n" for index in range(4)))
    assert any(item.title == "API endpoint facts truncated: app.js" and item.confidence == "UNKNOWN" for item in findings)
