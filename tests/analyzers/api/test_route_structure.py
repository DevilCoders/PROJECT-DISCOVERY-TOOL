"""Route structure: class-level mappings, router groups and blocks, indented scopes, mounted
router variables and resource declarations give each route its full path in the file."""
from pathlib import Path

from project_discovery.analyzers.api.route_structure import join_path, singular
from project_discovery.analyzers.api.routes import APIEndpointAnalyzer
from project_discovery.models import FileRecord


def _routes(tmp_path: Path, relative: str, source: str) -> list[str]:
    path = tmp_path / "source"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Source")
    findings = APIEndpointAnalyzer().analyze(path, record)
    return [item.split(" ", 1)[1] for finding in findings if finding.title.startswith("API route declarations")
            for item in finding.evidence]


def test_aspnet_controller_routes_tokens_absolute_templates_and_groups(tmp_path: Path):
    controller = (
        "using Microsoft.AspNetCore.Mvc;\n"
        "[ApiController]\n"
        '[Route("api/[controller]")]\n'
        "public class UsersController : ControllerBase\n"
        "{\n"
        '    [HttpGet("{id}")]\n'
        "    public IActionResult Get(int id) => Ok();\n"
        "    [HttpPost]\n"
        "    public IActionResult Create() => Ok();\n"
        '    [HttpGet("/health")]\n'
        "    public IActionResult Health() => Ok();\n"
        "    [HttpGet]\n"
        '    [Route("search")]\n'
        "    public IActionResult Search() => Ok();\n"
        "}\n"
    )
    assert _routes(tmp_path, "UsersController.cs", controller) == [
        "GET /api/Users/{id}", "POST /api/Users", "GET /health", "GET /api/Users/search"]
    groups = ('var api = app.MapGroup("/api");\nvar users = api.MapGroup("/users");\n'
              'users.MapGet("/{id}", GetUser);\napi.MapPost("/login", Login);\n')
    assert _routes(tmp_path, "Program.cs", groups) == ["GET /api/users/{id}", "POST /api/login"]


def test_class_mappings_on_the_jvm_and_in_php(tmp_path: Path):
    micronaut = (
        "import io.micronaut.http.annotation.*;\n"
        '@Controller("/hello")\n'
        "public class HelloController {\n"
        '    @Get("/{name}")\n'
        "    public String greet(String name) { return name; }\n"
        "    @Post\n"
        "    public void save() {}\n"
        "}\n"
    )
    assert _routes(tmp_path, "HelloController.java", micronaut) == ["GET /hello/{name}", "POST /hello"]
    # A method mapping before another class is not that class's prefix.
    two_classes = (
        "@RestController\nclass A {\n    @GetMapping(\"/a\")\n    String a() { return \"\"; }\n}\n"
        '@RequestMapping("/b")\nclass B {\n    @GetMapping("/x")\n    String x() { return ""; }\n}\n'
    )
    assert _routes(tmp_path, "Controllers.java", two_classes) == ["GET /a", "GET /b/x"]
    symfony = (
        "<?php\n"
        "use Symfony\\Component\\Routing\\Attribute\\Route;\n"
        "#[Route('/blog')]\n"
        "class BlogController extends AbstractController\n"
        "{\n"
        "    #[Route('/{slug}', name: 'blog_show', methods: ['GET'])]\n"
        "    public function show(string $slug): Response {}\n"
        "    #[Route('', methods: ['POST'])]\n"
        "    public function create(): Response {}\n"
        "}\n"
    )
    assert _routes(tmp_path, "src/Controller/BlogController.php", symfony) == ["GET /blog/{slug}", "POST /blog"]


def test_php_groups_and_resources(tmp_path: Path):
    source = (
        "<?php\n"
        "Route::prefix('admin')->group(function () {\n"
        "    Route::get('/users', [AdminController::class, 'users']);\n"
        "});\n"
        "Route::resource('photos', PhotoController::class)->only(['index', 'show']);\n"
        "Route::apiResource('posts.comments', CommentController::class);\n"
        "$app->group('/api', function (RouteCollectorProxy $group) {\n"
        "    $group->get('/users', ListUsers::class);\n"
        "});\n"
    )
    assert _routes(tmp_path, "routes/web.php", source) == [
        "GET /admin/users", "GET /photos", "GET /photos/{photo}",
        "DELETE /posts/{post}/comments/{comment}", "GET /posts/{post}/comments", "GET /posts/{post}/comments/{comment}",
        "PATCH /posts/{post}/comments/{comment}", "POST /posts/{post}/comments", "PUT /posts/{post}/comments/{comment}",
        "GET /api/users",
    ]


def test_ruby_and_elixir_scopes_and_resources(tmp_path: Path):
    rails = (
        "Rails.application.routes.draw do\n"
        "  namespace :admin do\n"
        "    resources :users, only: [:index, :show]\n"
        "  end\n"
        "  scope '/api' do\n"
        "    get 'status', to: 'status#show'\n"
        "  end\n"
        "  resources :posts, only: [:show] do\n"
        "    resources :comments, only: [:index, :create]\n"
        "  end\n"
        "  resource :profile, only: :show\n"
        "end\n"
    )
    assert _routes(tmp_path, "config/routes.rb", rails) == [
        "GET /admin/users", "GET /admin/users/:id", "GET /api/status", "GET /posts/:id",
        "GET /posts/:post_id/comments", "POST /posts/:post_id/comments", "GET /profile",
    ]
    everything = "Rails.application.routes.draw do\n  resources :photos\nend\n"
    assert _routes(tmp_path, "config/routes.rb", everything) == [  # one line: by method, then path
        "DELETE /photos/:id", "GET /photos", "GET /photos/:id", "GET /photos/:id/edit", "GET /photos/new",
        "PATCH /photos/:id", "POST /photos", "PUT /photos/:id",
    ]
    grape = ("class API < Grape::API\n  resource :users do\n    route_param :id do\n      get do\n      end\n"
             "    end\n  end\nend\n")
    assert _routes(tmp_path, "api.rb", grape) == ["GET /users/:id"]
    roda = ('class App < Roda\n  route do |r|\n    r.on "api" do\n      r.get "status" do\n        "ok"\n'
            "      end\n    end\n  end\nend\n")
    assert _routes(tmp_path, "app.rb", roda) == ["GET /api/status"]
    phoenix = (
        'scope "/api", MyAppWeb do\n'
        "  pipe_through :api\n"
        '  resources "/users", UserController, only: [:index, :show]\n'
        '  get "/health", HealthController, :index\n'
        "end\n"
    )
    assert _routes(tmp_path, "lib/my_app_web/router.ex", phoenix) == ["GET /api/users", "GET /api/users/:id", "GET /api/health"]


def test_go_and_javascript_groups_and_mounts(tmp_path: Path):
    go = (
        'import "github.com/go-chi/chi/v5"\n'
        "func routes(r chi.Router) {\n"
        '\tr.Route("/api", func(r chi.Router) {\n'
        '\t\tr.Get("/users", list)\n'
        '\t\tr.Route("/admin", func(r chi.Router) {\n'
        '\t\t\tr.Delete("/cache", purge)\n'
        "\t\t})\n"
        "\t})\n"
        '\tapi := g.Group("/v2")\n'
        '\tv1 := api.Group("/v1")\n'
        '\tv1.GET("/x", h)\n'
        "}\n"
    )
    assert _routes(tmp_path, "routes.go", go) == ["GET /api/users", "DELETE /api/admin/cache", "GET /v2/v1/x"]
    express = ('const express = require("express");\nconst app = express();\nconst users = express.Router();\n'
               'users.get("/:id", show);\napp.use("/api/users", auth, users);\n')
    assert _routes(tmp_path, "server.js", express) == ["GET /api/users/:id"]
    hono = ('import { Hono } from "hono";\nconst app = new Hono();\nconst api = new Hono();\n'
            'api.get("/books", list);\napp.route("/api", api);\n')
    assert _routes(tmp_path, "index.ts", hono) == ["GET /api/books"]


def test_jvm_and_swift_blocks(tmp_path: Path):
    javalin = (
        "import io.javalin.Javalin;\n"
        "import static io.javalin.apibuilder.ApiBuilder.*;\n"
        "class Main {\n"
        "    void routes(Javalin app) {\n"
        "        app.routes(() -> {\n"
        '            path("/api", () -> {\n'
        '                get("/users", UserController::list);\n'
        '                post("/users", UserController::create);\n'
        "            });\n"
        "        });\n"
        "    }\n"
        "}\n"
    )
    assert _routes(tmp_path, "Main.java", javalin) == ["GET /api/users", "POST /api/users"]
    akka = ('import akka.http.scaladsl.server.Directives._\nval route =\n  pathPrefix("api") {\n'
            '    path("users") {\n      get { complete("ok") }\n    }\n  }\n')
    assert _routes(tmp_path, "Routes.scala", akka) == ["ANY /api/users"]
    vapor = ('import Vapor\nfunc routes(_ app: Application) throws {\n    app.group("admin") { admin in\n'
             '        admin.get("stats") { req in "ok" }\n    }\n}\n')
    assert _routes(tmp_path, "routes.swift", vapor) == ["GET /admin/stats"]


def test_rust_nest_and_mount(tmp_path: Path):
    axum = ('use axum::{routing::get, Router};\n\nfn app() -> Router {\n    let api = Router::new()\n'
            '        .route("/users", get(list));\n    Router::new().nest("/api", api)\n}\n')
    assert _routes(tmp_path, "main.rs", axum) == ["GET /api/users"]
    rocket = ('#[macro_use] extern crate rocket;\n\n#[get("/hello")]\nfn hello() -> &\'static str { "hi" }\n\n'
              '#[launch]\nfn rocket() -> _ {\n    rocket::build().mount("/api", routes![hello])\n}\n')
    assert _routes(tmp_path, "main.rs", rocket) == ["GET /api/hello"]


def test_parenthesized_groups_and_router_variables(tmp_path: Path):
    clojure = (
        "(ns app.routes (:require [compojure.core :refer :all]))\n"
        "(defroutes app\n"
        '  (context "/api" []\n'
        '    (GET "/users" [] users)\n'
        '    (POST "/users" [] create))\n'
        '  (GET "/health" [] health))\n'
    )
    assert _routes(tmp_path, "routes.clj", clojure) == ["GET /api/users", "POST /api/users", "GET /health"]
    giraffe = (
        "let webApp =\n    choose [\n        subRoute \"/api\" (\n            choose [\n"
        '                GET >=> route "/users" >=> getUsers\n            ])\n'
        '        GET >=> route "/health" >=> text "ok"\n    ]\n'
    )
    assert _routes(tmp_path, "Program.fs", giraffe) == ["GET /api/users", "GET /health"]
    dream = ('let () =\n  Dream.run\n  @@ Dream.router [\n    Dream.scope "/api" [] [\n'
             '      Dream.get "/users" list_users;\n    ];\n    Dream.get "/health" health;\n  ]\n')
    assert _routes(tmp_path, "main.ml", dream) == ["GET /api/users", "GET /health"]
    mojo = "use Mojolicious::Lite;\nmy $api = $r->under('/api');\n$api->get('/users')->to('users#list');\n"
    assert _routes(tmp_path, "app.pl", mojo) == ["GET /api/users"]


def test_python_router_prefixes_and_mounts(tmp_path: Path):
    fastapi = (
        "from fastapi import APIRouter, FastAPI\n\napp = FastAPI()\nrouter = APIRouter(prefix=\"/items\")\n\n"
        '@router.get("/{item_id}")\nasync def read_item(item_id: int): ...\n\n'
        '@app.get("/health")\nasync def health(): ...\n\n'
        'app.include_router(router, prefix="/v1")\n'
    )
    assert _routes(tmp_path, "main.py", fastapi) == ["GET /v1/items/{item_id}", "GET /health"]
    flask = (
        "from flask import Blueprint, Flask\n\napp = Flask(__name__)\n"
        'bp = Blueprint("admin", __name__, url_prefix="/admin")\n\n'
        '@bp.route("/users", methods=["GET", "POST"])\ndef users(): ...\n\n'
        'app.register_blueprint(bp, url_prefix="/api/admin")\n'
        'shop = Blueprint("shop", __name__, url_prefix="/shop")\n\n@shop.get("/cart")\ndef cart(): ...\n'
    )
    # register_blueprint's url_prefix replaces the blueprint's own.
    assert _routes(tmp_path, "app.py", flask) == ["GET /api/admin/users", "POST /api/admin/users", "GET /shop/cart"]
    aiohttp = ('from aiohttp import web\napp = web.Application()\nadmin = web.Application()\n'
               'admin.router.add_get("/stats", stats)\napp.add_subapp("/admin/", admin)\n')
    assert _routes(tmp_path, "server.py", aiohttp) == ["GET /admin/stats"]
    starlette = (
        "from starlette.routing import Mount, Route\nroutes = [\n    Route(\"/\", homepage),\n"
        '    Mount("/api", routes=[\n        Route("/users", users, methods=["GET"]),\n'
        '        Mount("/v2", routes=[Route("/items", items)]),\n    ]),\n]\n'
    )
    assert _routes(tmp_path, "app.py", starlette) == ["ANY /", "GET /api/users", "ANY /api/v2/items"]
    drf = (
        "from django.urls import include, path\nfrom rest_framework.routers import DefaultRouter\n"
        "router = DefaultRouter()\nrouter.register(r\"users\", UserViewSet)\nurlpatterns = [\n"
        '    path("api/", include(router.urls)),\n    path("health/", views.health),\n]\n'
    )
    assert _routes(tmp_path, "project/urls.py", drf) == ["ANY /api/users/", "ANY /api/users/{pk}/", "ANY health/"]


def test_path_joining_and_singular_names():
    assert join_path(["/api", "users/", ":id"]) == "/api/users/:id"
    assert join_path(["api/", "", "users/"]) == "/api/users/"
    assert join_path(["", ""]) == "/"
    assert [singular(word) for word in ("photos", "categories", "boxes", "addresses", "status", "data")] == [
        "photo", "category", "box", "address", "status", "data"]
