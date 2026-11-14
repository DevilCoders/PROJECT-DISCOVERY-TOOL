"""The endpoint catalog: routes with their handlers, contract operations, policies, evidence and confidence."""
import json
import time
from pathlib import Path

from project_discovery.analyzers.api.handlers import route_handler
from project_discovery.analyzers.api.routes import APIEndpointAnalyzer
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord

HANDLERS = [
    (["@app.get('/pets/<int:id>')", "def show_pet(id):", "    pass"], 2, "show_pet"),
    (["@router.post('/x')", "async def create(item):"], 2, "create"),
    (['@GetMapping("/users/{id}")', '@PreAuthorize("isAuthenticated()")',
      "public ResponseEntity<User> getUser(@PathVariable Long id) {"], 1, "getUser"),
    (["  @Get(':id')", "  @UseGuards(AuthGuard)", "  findOne(@Param('id') id: string) {"], 1, "findOne"),
    (['[HttpGet("{id}")]', "public async Task<ActionResult<Item>> GetItemAsync(long id)"], 1, "GetItemAsync"),
    (["router.get('/users', auth, users.list);"], 1, "users.list"),
    (["app.post('/login', async (req, res) => {", "  res.send('ok');", "});"], 1, "(inline)"),
    (["app.get('/x', function (req, res) { res.end(); });"], 1, "(inline)"),
    (['r.HandleFunc("/users", listUsers).Methods("GET")'], 1, "listUsers"),
    (['api.GET("/ping", middleware.Auth(), handlers.Ping)'], 1, "handlers.Ping"),
    (['app.MapGet("/todos", TodoEndpoints.GetAll);'], 1, "TodoEndpoints.GetAll"),
    (['app.MapGet("/", () => "Hello");'], 1, "(inline)"),
    (["path('users/', views.user_list, name='user-list'),"], 1, "views.user_list"),
    (["app.add_url_rule('/', view_func=index)"], 1, "index"),
    (["Route::get('/user', [UserController::class, 'index']);"], 1, "UserController@index"),
    (["Route::get('/user', 'UserController@show');"], 1, "UserController@show"),
    (['get "/photos", to: "photos#index"'], 1, "photos#index"),
    (["get 'profile' => 'users#show'"], 1, "users#show"),
    (['get "/users", UserController, :index'], 1, "UserController.index"),
    (['get("/hello") {', '    call.respondText("Hi")', "}"], 1, "(inline)"),
    (["#[Route('/blog', name: 'blog_list')]", "public function list(): Response"], 1, "list"),
    (['@Path("/items")', "@GET", "public List<Item> all() {"], 1, "all"),
    (["export async function GET(request) {"], 1, "GET"),
]


def test_route_handlers_across_languages():
    for lines, line, expected in HANDLERS:
        assert route_handler(lines, line) == expected, lines
    assert route_handler(["x"], 5) == "" and route_handler([], 1) == ""
    # A route whose source does not name a handler.
    assert route_handler(['urlpatterns += router.urls'], 1) == ""


def test_endpoint_facts_carry_the_handler(tmp_path: Path):
    def facts_of(relative: str, source: str) -> list[tuple[str, str]]:
        path = tmp_path / "source"
        path.write_text(source, encoding="utf-8")
        record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Source")
        with collecting_facts() as facts:
            APIEndpointAnalyzer().analyze(path, record)
        return [(name, json.loads(detail).get("handler", "")) for kind, name, detail in facts.facts if kind == "api_endpoint"]

    assert facts_of("app.py", 'from flask import Flask\napp = Flask(__name__)\n\n@app.get("/pets")\ndef list_pets():\n'
                              "    return []\n") == [("GET /pets", "list_pets")]
    assert facts_of("PetController.java", '@RestController\n@RequestMapping("/pets")\npublic class PetController {\n'
                                          '  @GetMapping("/{id}")\n  public Pet show(@PathVariable long id) { return null; }\n}\n') \
        == [("GET /pets/{id}", "show")]


def test_the_handler_reader_is_linear_on_adversarial_input():
    for lines in (["app.get('/x', " + "(" * 50_000], ["@Get()"] + ["@x"] * 50_000, ["f(" + "'a', " * 20_000]):
        started = time.perf_counter()
        route_handler(lines, 1)
        assert time.perf_counter() - started < 5


def test_the_code_index_builds_the_endpoint_catalog(tmp_path: Path):
    project = tmp_path / "project"
    openapi = {"openapi": "3.0.3", "info": {"title": "Pets", "version": "1"},
               "paths": {"/pets": {"get": {"operationId": "listPets"}, "post": {"operationId": "createPet"}}}}
    files = {
        "api/openapi.json": json.dumps(openapi),
        "app.py": ("from flask import Flask\nfrom flask_login import login_required\nfrom flask_limiter import Limiter\n"
                   "app = Flask(__name__)\n\n\n@app.get('/pets')\n@login_required\ndef list_pets():\n    return []\n\n\n"
                   "@app.post('/pets')\n@limiter.limit('5 per minute')\ndef create_pet():\n    return {}\n\n\n"
                   "@app.get('/health')\ndef health():\n    return 'ok'\n"),
        "web/__init__.py": "",
        "web/factory.py": ("from flask import Flask\nfrom .views import bp\n\ndef create_app():\n    app = Flask(__name__)\n"
                           '    app.register_blueprint(bp, url_prefix="/admin")\n    return app\n'),
        "web/views.py": 'from flask import Blueprint\nbp = Blueprint("views", __name__)\n\n@bp.route("/stats")\ndef stats(): ...\n',
    }
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    value = report["metrics"]["code_index"]["endpoint_catalog"]
    catalog = {(item["method"], item["path"]): item for item in value["endpoints"]}
    assert set(catalog) == {("GET", "/pets"), ("POST", "/pets"), ("GET", "/health"), ("GET", "/admin/stats")}
    listed = catalog[("GET", "/pets")]
    assert (listed["handler"], listed["file"], listed["line"], listed["framework"]) == ("list_pets", "app.py", 9, "Flask")
    assert listed["contract"] == "listPets (api/openapi.json)"
    assert listed["auth"] == ["Django/Flask-Login"] and listed["confidence"] == "CONFIRMED"
    created = catalog[("POST", "/pets")]
    assert (created["handler"], created["contract"]) == ("create_pet", "createPet (api/openapi.json)")
    assert created["rate_limit"] == ["Flask-Limiter/slowapi: 5 per minute"] and created["auth"] == []
    assert catalog[("GET", "/health")]["contract"] == ""
    # A prefix mounted from another file completes the path: the full path is inferred.
    mounted = catalog[("GET", "/admin/stats")]
    assert (mounted["handler"], mounted["confidence"]) == ("stats", "INFERRED")
    assert (value["count"], value["with_handler"], value["with_contract"], value["with_auth"]) == (4, 4, 2, 1)
    findings = {item["title"]: item for item in report["findings"] if item["analyzer"] == "code-index"}
    assert "never says" not in findings["Endpoint catalog"]["detail"]
    assert "does not say that a route is deployed, mounted, enabled or reachable" in findings["Endpoint catalog"]["detail"]
    uncovered = findings["Routes without an authentication declaration"]
    assert uncovered["severity"] == "LOW"
    assert len(uncovered["evidence"]) == 3
