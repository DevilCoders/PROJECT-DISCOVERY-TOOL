"""Endpoint adapters by language and framework (the api-endpoints analyzer): each form, the
markers that keep HTTP client calls out, declarations a formatter wrapped over several lines,
and file-system routers."""
import json
from pathlib import Path

from project_discovery.analyzers.api.routes import APIEndpointAnalyzer
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord


def _analyze(tmp_path: Path, relative: str, source: str):
    path = tmp_path / "source"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Source")
    analyzer = APIEndpointAnalyzer()
    assert analyzer.supports(record), relative
    return analyzer.analyze(path, record)


def _evidence(tmp_path: Path, relative: str, source: str) -> list[str]:
    return [item for finding in _analyze(tmp_path, relative, source)
            if finding.title.startswith("API route declarations") for item in finding.evidence]


def _routes(tmp_path: Path, relative: str, source: str) -> list[str]:
    """"METHOD route" of each declaration, in line order."""
    return [item.split(" ", 1)[1] for item in _evidence(tmp_path, relative, source)]


def _lines(tmp_path: Path, relative: str, source: str) -> list[str]:
    """"line METHOD route" of each declaration."""
    return [f"{item.split(' ', 1)[0].rsplit(':', 1)[1]} {item.split(' ', 1)[1]}"
            for item in _evidence(tmp_path, relative, source)]


def test_javascript_routers_route_objects_chains_and_wrapped_calls(tmp_path: Path):
    source = (
        'import express from "express";\n'
        'import axios from "axios";\n'
        "const app = express();\n"
        "const users = express.Router();\n"
        'users.get("/users/:id", handler);\n'
        "users.delete('/users/:id', handler);\n"
        'axios.get("/remote");\n'
        'api.get("/v1/things");\n'
        'app.route("/books")\n'
        "  .get(listBooks)\n"
        "  .post(createBook);\n"
        'router.all("/health", ok);\n'
        "fastify.route({\n"
        "  method: ['GET', 'HEAD'],\n"
        "  url: '/items',\n"
        "  handler,\n"
        "});\n"
        "server.route({ path: '/hapi/{id}', method: 'PUT', handler });\n"
        "router.get(\n"
        "  '/wrapped',\n"
        "  auth,\n"
        "  handler,\n"
        ");\n"
    )
    assert _routes(tmp_path, "src/server.ts", source) == [
        "GET /users/:id", "DELETE /users/:id", "GET /v1/things", "GET /books", "POST /books", "ANY /health",
        "GET /items", "HEAD /items", "PUT /hapi/{id}", "GET /wrapped",
    ]
    # A wrapped call keeps the line it starts on; a call starting mid-line keeps its own.
    wrapped = ('const express = require("express");\nconst router = express.Router();\nrouter.get(\n  "/first",\n'
               '  handler,\n); router.post("/second", h);\n')
    assert _lines(tmp_path, "routes.js", wrapped) == ["3 GET /first", "6 POST /second"]


def test_http_client_calls_in_a_file_without_a_server_are_not_endpoints(tmp_path: Path):
    source = (
        'import axios from "axios";\n'
        'const api = axios.create({ baseURL: "/api" });\n'
        'export const load = () => api.get("/users");\n'
        'this.http.get("/items").subscribe();\n'
        'client.post("/orders", body);\n'
    )
    assert _routes(tmp_path, "src/store.ts", source) == []


def test_nestjs_and_file_system_routers(tmp_path: Path):
    nest = "@Controller('cats')\nexport class CatsController {\n  @Get(':id')\n  findOne() {}\n  @Post()\n  create() {}\n}\n"
    assert _routes(tmp_path, "cats.controller.ts", nest) == ["GET :id", "POST "]
    handlers = ('import { NextResponse } from "next/server";\n'
                "export async function GET(request: Request) { return NextResponse.json({}); }\n"
                "export const DELETE = async () => new Response(null);\n")
    assert _routes(tmp_path, "app/api/users/[id]/route.ts", handlers) == ["GET /api/users/{id}", "DELETE /api/users/{id}"]
    assert _routes(tmp_path, "src/app/(shop)/cart/route.js", "export function POST() {}\n") == ["POST /cart"]
    assert _routes(tmp_path, "app/_lib/route.ts", "export function GET() {}\n") == []  # private folder
    pages = "export default function handler(req, res) { res.json({}) }\n"
    assert _routes(tmp_path, "pages/api/hello.ts", pages) == ["ANY /api/hello"]
    assert _routes(tmp_path, "src/pages/api/users/index.js", pages) == ["ANY /api/users"]
    svelte = "export const POST = async ({ request }) => new Response();\n"
    assert _routes(tmp_path, "src/routes/api/items/[slug]/+server.ts", svelte) == ["POST /api/items/{slug}"]
    nuxt = "export default defineEventHandler((event) => ({}))\n"
    assert _routes(tmp_path, "server/api/users/[id].delete.ts", nuxt) == ["DELETE /api/users/{id}"]
    assert _routes(tmp_path, "server/routes/health.ts", "export default eventHandler(() => 'ok')\n") == ["ANY /health"]


def test_go_routers(tmp_path: Path):
    source = (
        "package main\n\nimport (\n\t\"net/http\"\n\n\t\"github.com/go-chi/chi/v5\"\n)\n\nfunc main() {\n"
        '\thttp.HandleFunc("/health", health)\n'
        '\tmux.HandleFunc("GET /items/{id}", getItem)\n'
        '\tr.HandleFunc("/books/{id}", book).Methods("GET", "PUT")\n'
        "\tc := chi.NewRouter()\n"
        '\tc.Get("/articles", list)\n'
        '\tc.Method("PATCH", "/articles/{id}", patch)\n'
        '\te.GET("/users/:id", getUser)\n'
        '\tv1 := g.Group("/v1")\n'
        '\tv1.POST("/jobs", createJob)\n'
        '\tresp, _ := http.Get("https://example.com/")\n'
        '\tbeego.Router("/admin", &AdminController{})\n'
        "}\n"
    )
    assert _routes(tmp_path, "main.go", source) == [
        "ANY /health", "GET /items/{id}", "GET /books/{id}", "PUT /books/{id}", "GET /articles",
        "PATCH /articles/{id}", "GET /users/:id", "POST /jobs", "ANY /admin",
    ]


def test_spring_mappings_take_their_arguments_in_any_order(tmp_path: Path):
    source = (
        "@RestController\n"
        '@RequestMapping("/api")\n'
        "class OrderController {\n"
        '  @RequestMapping(method = RequestMethod.POST, value = "/orders")\n'
        "  Order create() { return null; }\n"
        '  @RequestMapping(value = "/orders/{id}", method = {RequestMethod.GET, RequestMethod.HEAD})\n'
        "  Order get() { return null; }\n"
        "  @DeleteMapping(\n"
        '      path = "/orders/{id}")\n'
        "  void delete() {}\n"
        "}\n"
    )
    assert _lines(tmp_path, "OrderController.java", source) == [
        "2 ANY /api", "4 POST /orders", "6 GET /orders/{id}", "6 HEAD /orders/{id}", "8 DELETE /orders/{id}",
    ]


def test_jvm_frameworks(tmp_path: Path):
    java = (
        "import io.javalin.Javalin;\n"
        "import static spark.Spark.*;\n"
        "import io.vertx.ext.web.Router;\n"
        "import io.micronaut.http.annotation.*;\n"
        "import io.quarkus.vertx.web.Route;\n"
        "class Server {\n"
        "  void routes(Javalin app, Router router) {\n"
        '    app.get("/hello", ctx -> ctx.result("Hi"));\n'
        '    get("/spark", (req, res) -> "Hi");\n'
        '    router.route(HttpMethod.POST, "/vertx");\n'
        '    restTemplate.getForObject("/client", String.class);\n'
        "  }\n"
        "  @Get\n"
        '  public String index() { return "Hi"; }\n'
        '  @Post("/save")\n'
        "  public void save() {}\n"
        '  @Route(path = "/quarkus", methods = Route.HttpMethod.PUT)\n'
        "  void quarkus() {}\n"
        "}\n"
    )
    assert _routes(tmp_path, "Server.java", java) == [
        "GET /hello", "GET /spark", "POST /vertx", "GET ", "POST /save", "PUT /quarkus"]
    ktor = (
        "import io.ktor.server.routing.*\n\nfun Application.module() {\n    routing {\n"
        '        get("/") { call.respondText("Hi") }\n'
        '        post("/orders") { }\n'
        '        route("/api") {\n'
        '            get("/items") { }\n'
        "        }\n    }\n"
        '    client.get("https://example.com")\n'
        "}\n"
    )
    assert _routes(tmp_path, "Application.kt", ktor) == ["GET /", "POST /orders", "GET /items"]
    scala = (
        "import org.http4s._\n"
        "import akka.http.scaladsl.server.Directives._\n"
        "object Routes {\n"
        "  val service = HttpRoutes.of[IO] {\n"
        '    case GET -> Root / "hello" / name => Ok(name)\n'
        '    case req @ POST -> Root / "users" / IntVar(id) => Ok()\n'
        "  }\n"
        '  val route = path("orders") { get { complete("ok") } }\n'
        '  @cask.get("/cask")\n'
        '  def cask() = "hi"\n'
        "}\n"
    )
    assert _routes(tmp_path, "Routes.scala", scala) == ["GET /hello/{name}", "POST /users/{id}", "ANY /orders", "GET /cask"]
    play = (
        "# Routes\n"
        "GET     /                    controllers.HomeController.index()\n"
        "POST    /users/:id           controllers.Users.update(id: Long)\n"
        "->      /api                 api.Routes\n"
        'GET     /assets/*file        controllers.Assets.versioned(path="/public", file: Asset)\n'
    )
    assert _routes(tmp_path, "conf/routes", play) == ["GET /", "POST /users/:id", "GET /assets/*file"]
    grails = (
        "class UrlMappings {\n    static mappings = {\n"
        '        "/books"(controller: "book")\n'
        '        get "/api/items"(controller: "item", action: "list")\n'
        '        "/$controller/$action?/$id?(.$format)?"{\n            constraints { }\n        }\n'
        "    }\n}\n"
    )
    assert _routes(tmp_path, "grails-app/controllers/UrlMappings.groovy", grails) == ["ANY /books", "GET /api/items"]


def test_dotnet_attributes_minimal_apis_and_modules(tmp_path: Path):
    source = (
        "using Microsoft.AspNetCore.Mvc;\n"
        "public class UsersController : ControllerBase {\n"
        '    [HttpGet("users/{id}")]\n'
        "    public IActionResult Get(int id) => Ok();\n"
        "    [HttpPost]\n"
        "    public IActionResult Create() => Ok();\n"
        "}\n"
        'app.MapGet("/health", () => "ok");\n'
        'group.MapPut("/items/{id}", Update);\n'
        'app.MapMethods("/ping", new[] { "PATCH", "OPTIONS" }, () => "pong");\n'
        'app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");\n'
        '[Route("/hello", "GET POST")]\n'
        "public class Hello { }\n"
    )
    assert _routes(tmp_path, "Program.cs", source) == [
        "GET users/{id}", "POST ", "GET /health", "PUT /items/{id}", "OPTIONS /ping", "PATCH /ping",
        "ANY {controller=Home}/{action=Index}/{id?}", "GET /hello", "POST /hello",
    ]
    nancy = ("using Nancy;\npublic class HomeModule : NancyModule {\n    public HomeModule() {\n"
             '        Get("/", args => "Hi");\n        Post("/orders", args => HttpStatusCode.Created);\n    }\n}\n')
    assert _routes(tmp_path, "HomeModule.cs", nancy) == ["GET /", "POST /orders"]
    vb = ('Imports Microsoft.AspNetCore.Mvc\nPublic Class ItemsController\n    <HttpGet("items")>\n'
          "    Public Function List() As IActionResult\n    End Function\nEnd Class\n")
    assert _routes(tmp_path, "ItemsController.vb", vb) == ["GET items"]


def test_php_routers_attributes_and_wordpress(tmp_path: Path):
    source = (
        "<?php\n"
        "Route::get('/users', [UserController::class, 'index']);\n"
        "Route::match(['get', 'post'], '/search', fn () => null);\n"
        "Route::any('/hook', HookController::class);\n"
        "$app->get('/hello/{name}', function ($request, $response, $args) { return $response; });\n"
        "$client->get('/remote');\n"
        "$app->map(['GET', 'POST'], '/form', FormAction::class);\n"
        "#[Route('/blog/{slug}', name: 'blog_show', methods: ['GET', 'HEAD'])]\n"
        '/** @Route("/legacy", methods={"POST"}) */\n'
        "register_rest_route('myplugin/v1', '/author/(?P<id>\\d+)', array('methods' => WP_REST_Server::READABLE, "
        "'callback' => 'cb'));\n"
        "register_rest_route( 'shop/v2', '/orders', [\n"
        "    'methods' => 'POST',\n"
        "    'callback' => 'create',\n"
        "] );\n"
        "$routes->get('news', 'News::index');\n"
    )
    assert _routes(tmp_path, "routes/web.php", source) == [
        "GET /users", "GET /search", "POST /search", "ANY /hook", "GET /hello/{name}", "GET /form", "POST /form",
        "GET /blog/{slug}", "HEAD /blog/{slug}", "POST /legacy", "GET /wp-json/myplugin/v1/author/{id}",
        "POST /wp-json/shop/v2/orders", "GET news",
    ]


def test_ruby_routers(tmp_path: Path):
    sinatra = "require 'sinatra'\nget '/hello' do\n  'Hi'\nend\npost('/items') { create }\n"
    assert _routes(tmp_path, "app.rb", sinatra) == ["GET /hello", "POST /items"]
    rails = (
        "Rails.application.routes.draw do\n"
        "  get 'photos', to: 'photos#index'\n"
        "  match 'photos/:id', to: 'photos#show', via: [:get, :post]\n"
        "  root 'pages#home'\n"
        "end\n"
    )
    assert _routes(tmp_path, "config/routes.rb", rails) == ["GET photos", "GET photos/:id", "POST photos/:id", "GET /"]
    grape = "class API < Grape::API\n  resource :users do\n    get ':id' do\n    end\n    post do\n    end\n  end\nend\n"
    assert _routes(tmp_path, "api.rb", grape) == ["GET :id", "POST "]
    with collecting_facts() as facts:
        _analyze(tmp_path, "api.rb", grape)
    # Grape's form names the framework, not the Sinatra form that reads the same line.
    assert {json.loads(detail)["framework"] for kind, _, detail in facts.facts if kind == "api_endpoint"} == {"Grape"}
    roda = 'class App < Roda\n  route do |r|\n    r.get "hello" do\n      "Hi"\n    end\n  end\nend\n'
    assert _routes(tmp_path, "app.rb", roda) == ["GET hello"]


def test_rust_routers(tmp_path: Path):
    axum = (
        "use axum::{routing::get, Router};\n\n"
        '#[get("/hello/{name}")]\nasync fn hello() {}\n\n'
        '#[route("/multi", method = "GET", method = "POST")]\nasync fn multi() {}\n\n'
        "fn app() -> Router {\n"
        "    Router::new()\n"
        '        .route("/", get(root))\n'
        '        .route("/users", get(list).post(create))\n'
        "        .route(\n"
        '            "/users/:id",\n'
        "            get(show).delete(remove),\n"
        "        )\n"
        "}\n"
    )
    assert _lines(tmp_path, "main.rs", axum) == [
        "3 GET /hello/{name}", "6 GET /multi", "6 POST /multi", "11 GET /", "12 GET /users", "12 POST /users",
        "13 DELETE /users/:id", "13 GET /users/:id",
    ]
    others = (
        "use actix_web::{web, App};\nuse warp::Filter;\nuse tide;\n\n"
        "fn config(cfg: &mut web::ServiceConfig) {\n"
        '    cfg.service(web::resource("/items").route(web::get().to(list)).route(web::post().to(add)));\n'
        "}\nfn filters() {\n"
        '    let hello = warp::path!("hello" / String);\n'
        '    app.at("/orders").get(list).post(create);\n'
        "}\n"
    )
    assert _routes(tmp_path, "routes.rs", others) == [
        "GET /items", "POST /items", "ANY /hello/{String}", "GET /orders", "POST /orders"]


def test_swift_and_dart_routers(tmp_path: Path):
    vapor = (
        "import Vapor\n\nfunc routes(_ app: Application) throws {\n"
        '    app.get("hello") { req in "Hello" }\n'
        '    app.post("users", ":id", use: update)\n'
        '    app.on(.PATCH, "items", ":id") { req in "" }\n'
        '    let users = app.grouped("users")\n'
        "    users.get(use: index)\n"
        '    try app.client.get("https://example.com")\n'
        "}\n"
    )
    assert _routes(tmp_path, "routes.swift", vapor) == ["GET /hello", "POST /users/:id", "PATCH /items/:id", "GET "]
    kitura = 'import Kitura\nlet router = Router()\nrouter.get("/hello") { request, response, next in\n    next()\n}\n'
    assert _routes(tmp_path, "main.swift", kitura) == ["GET /hello"]
    shelf = (
        "import 'package:shelf_router/shelf_router.dart';\n\n"
        "final router = Router()\n"
        "  ..get('/hello', (Request request) => Response.ok('Hi'))\n"
        "  ..post('/users/<id>', createUser);\n\n"
        "class Api {\n"
        "  @Route.get('/annotated')\n"
        "  Response annotated(Request request) => Response.ok('');\n"
        "  @Route('PUT', '/items/<id>')\n"
        "  Response put(Request request) => Response.ok('');\n"
        "}\n"
    )
    assert _routes(tmp_path, "server.dart", shelf) == ["GET /hello", "POST /users/<id>", "GET /annotated", "PUT /items/<id>"]
    frog = ("import 'package:dart_frog/dart_frog.dart';\n\n"
            "Response onRequest(RequestContext context, String id) {\n  return Response(body: 'user $id');\n}\n")
    assert _routes(tmp_path, "routes/users/[id].dart", frog) == ["ANY /users/{id}"]
    assert _routes(tmp_path, "routes/index.dart", frog) == ["ANY /"]


def test_c_and_cpp_routers(tmp_path: Path):
    cpp = (
        '#include "crow.h"\n'
        'CROW_ROUTE(app, "/add").methods("POST"_method, "PUT"_method)([](const crow::request& req) { return "ok"; });\n'
        'CROW_WEBSOCKET_ROUTE(app, "/ws")\n'
        "    .onopen([](crow::websocket::connection& conn) {});\n"
        "class UserCtrl : public drogon::HttpController<UserCtrl> {\n"
        "  public:\n"
        "    METHOD_LIST_BEGIN\n"
        '    METHOD_ADD(UserCtrl::get, "/{id}", Get, Head);\n'
        '    ADD_METHOD_TO(UserCtrl::create, "/api/users", Post);\n'
        "    METHOD_LIST_END\n"
        "};\n"
        'Routes::Get(router, "/ready", Routes::bind(&Ready::handle));\n'
        'ENDPOINT("GET", "/users/{id}", getUser, PATH(Int32, id)) { return nullptr; }\n'
    )
    assert _routes(tmp_path, "server.cpp", cpp) == [
        "POST /add", "PUT /add", "WEBSOCKET /ws", "GET /{id}", "HEAD /{id}", "POST /api/users", "GET /ready",
        "GET /users/{id}",
    ]
    httplib = (
        "#include <httplib.h>\nint main() {\n  httplib::Server svr;\n"
        '  svr.Get("/hi", [](const httplib::Request&, httplib::Response& res) { res.set_content("Hi", "text/plain"); });\n'
        '  svr.Post("/echo", handler);\n'
        '  httplib::Client cli("http://localhost:8080");\n'
        '  cli.Get("/hi");\n'
        "}\n"
    )
    assert _lines(tmp_path, "main.cpp", httplib) == ["4 GET /hi", "5 POST /echo"]
    mongoose = (
        '#include "mongoose.h"\n'
        "static void fn(struct mg_connection *c, int ev, void *ev_data) {\n"
        "  struct mg_http_message *hm = (struct mg_http_message *) ev_data;\n"
        '  if (mg_http_match_uri(hm, "/api/status")) {\n'
        '    mg_http_reply(c, 200, "", "ok");\n'
        '  } else if (mg_match(hm->uri, mg_str("/api/items/*"), NULL)) {\n'
        "  }\n}\n"
    )
    assert _routes(tmp_path, "server.c", mongoose) == ["ANY /api/status", "ANY /api/items/*"]


def test_elixir_clojure_crystal_and_perl_routers(tmp_path: Path):
    phoenix = (
        "defmodule MyAppWeb.Router do\n  use MyAppWeb, :router\n\n"
        '  scope "/", MyAppWeb do\n'
        '    get "/", PageController, :home\n'
        '    live "/thermostat", ThermostatLive\n'
        '    forward "/jobs", BackgroundJob.Plug\n'
        '    match :*, "/any", PageController, :any\n'
        "  end\nend\n"
    )
    assert _routes(tmp_path, "lib/my_app_web/router.ex", phoenix) == ["GET /", "GET /thermostat", "ANY /jobs", "ANY /any"]
    plug = ('defmodule MyRouter do\n  use Plug.Router\n  get "/hello" do\n    send_resp(conn, 200, "world")\n  end\n'
            '  match "/multi", via: :post do\n    send_resp(conn, 200, "ok")\n  end\nend\n')
    assert _routes(tmp_path, "router.ex", plug) == ["GET /hello", "POST /multi"]
    clojure = (
        "(ns app.routes\n"
        "  (:require [compojure.core :refer [defroutes GET POST ANY]]\n"
        "            [reitit.ring :as ring]))\n"
        "(defroutes app-routes\n"
        '  (GET "/" [] "Hello")\n'
        '  (POST "/users" req (create req))\n'
        '  (ANY "/echo" [] echo))\n'
        "(def router\n"
        "  (ring/router\n"
        '    [["/api/ping" {:get ping-handler :post ping-post}]]))\n'
    )
    assert _routes(tmp_path, "src/app/routes.clj", clojure) == [
        "GET /", "POST /users", "ANY /echo", "GET /api/ping", "POST /api/ping"]
    crystal = ('require "kemal"\nget "/" do |env|\n  "Hello"\nend\nws "/socket" do |socket|\nend\n'
               'get "/users", UserController, :index\n')
    assert _routes(tmp_path, "src/app.cr", crystal) == ["GET /", "WEBSOCKET /socket", "GET /users"]
    perl = (
        "use Mojolicious::Lite;\n"
        "get '/' => sub { my $c = shift; $c->render(text => 'Hi'); };\n"
        "post '/login' => sub { };\n"
        "any '/x' => sub { };\n"
        "$r->get('/welcome')->to('example#welcome');\n"
        "my $tx = $ua->get('/remote');\n"
    )
    assert _routes(tmp_path, "app.pl", perl) == ["GET /", "POST /login", "ANY /x", "GET /welcome"]


def test_lua_haskell_nim_fsharp_erlang_julia_r_ocaml_d_and_pascal_routers(tmp_path: Path):
    lua = ('local lapis = require("lapis")\nlocal app = lapis.Application()\n'
           'app:get("/", function(self) return "Hi" end)\n'
           'app:match("user", "/user/:id", function(self) end)\n'
           'app:post("/login", function(self) end)\n')
    assert _routes(tmp_path, "app.lua", lua) == ["GET /", "ANY /user/:id", "POST /login"]
    haskell = (
        "import Web.Scotty\n"
        "main = scotty 3000 $ do\n"
        '  get "/" $ do\n    text "Hi"\n'
        '  post (capture "/users/:id") $ do\n    text "ok"\n'
        "type API = \"users\" :> Capture \"id\" Int :> Get '[JSON] User\n"
        "      :<|> \"users\" :> ReqBody '[JSON] User :> Post '[JSON] User\n"
    )
    assert _routes(tmp_path, "Main.hs", haskell) == ["GET /", "POST /users/:id", "GET /users/{id}", "POST /users"]
    nim = 'import jester\nroutes:\n  get "/":\n    resp "Hi"\n  post "/users":\n    resp "ok"\n'
    assert _routes(tmp_path, "app.nim", nim) == ["GET /", "POST /users"]
    fsharp = (
        "open Giraffe\nlet webApp =\n    choose [\n"
        '        GET >=> route "/ping" >=> text "pong"\n'
        '        POST >=> routef "/users/%i" createUser\n'
        "    ]\nlet api = router {\n"
        '    get "/" index\n'
        '    post "/users" createUser\n'
        "}\n"
    )
    assert _routes(tmp_path, "Program.fs", fsharp) == ["GET /ping", "POST /users/%i", "GET /", "POST /users"]
    erlang = ("start(_Type, _Args) ->\n    Dispatch = cowboy_router:compile([\n"
              "        {'_', [{\"/\", hello_handler, []}, {\"/users/:id\", user_handler, []}]}\n    ]),\n")
    assert _routes(tmp_path, "src/app.erl", erlang) == ["ANY /", "ANY /users/:id"]
    julia = ('using Genie, Oxygen, HTTP\nroute("/hello") do\n  "Hi"\nend\nroute("/users", method = POST) do\nend\n'
             '@get "/greet" function(req)\nend\nHTTP.register!(router, "GET", "/api/x", handler)\n')
    assert _routes(tmp_path, "app.jl", julia) == ["ANY /hello", "POST /users", "GET /greet", "GET /api/x"]
    plumber = ('library(plumber)\n#* @get /echo\nfunction(msg = "") { list(msg = msg) }\n#* @post /sum\n'
               'function(a, b) { as.numeric(a) + as.numeric(b) }\npr() %>% pr_get("/hi", function() "hi")\n')
    assert _routes(tmp_path, "api.R", plumber) == ["GET /echo", "POST /sum", "GET /hi"]
    dream = ('let () =\n  Dream.run\n  @@ Dream.router [\n    Dream.get "/" (fun _ -> Dream.html "Hi");\n'
             '    Dream.post "/echo" (fun request -> Dream.html "ok");\n  ]\n')
    assert _routes(tmp_path, "bin/main.ml", dream) == ["GET /", "POST /echo"]
    vibe = ('import vibe.vibe;\nvoid main() {\n    auto router = new URLRouter;\n    router.get("/", &index);\n'
            '    router.post("/login", &login);\n}\n')
    assert _routes(tmp_path, "source/app.d", vibe) == ["GET /", "POST /login"]
    horse = ("uses Horse;\nbegin\n  THorse.Get('/ping',\n    procedure(Req: THorseRequest; Res: THorseResponse)\n"
             "    begin\n      Res.Send('pong');\n    end);\n  THorse.Listen(9000);\nend.\n")
    assert _routes(tmp_path, "Server.pas", horse) == ["GET /ping"]


def test_python_frameworks_beyond_decorators(tmp_path: Path):
    litestar = ('from litestar import Litestar, get, post\n\n@get("/books")\nasync def books() -> list: ...\n\n'
                '@post(path="/books")\nasync def add() -> None: ...\n')
    assert _routes(tmp_path, "app.py", litestar) == ["GET /books", "POST /books"]
    bottle = ("from bottle import route, get, run\n\n@route('/hello')\ndef hello(): return 'Hi'\n\n"
              "@get('/items')\ndef items(): return []\n")
    assert _routes(tmp_path, "app.py", bottle) == ["ANY /hello", "GET /items"]
    aiohttp = (
        "from aiohttp import web\n\napp = web.Application()\n"
        "app.router.add_get('/', handle)\n"
        "app.add_routes([web.get('/x', h), web.post('/y', h), web.route('PATCH', '/z', h)])\n"
        "app.router.add_route('DELETE', '/w', h)\n"
    )
    assert _routes(tmp_path, "server.py", aiohttp) == ["GET /", "GET /x", "PATCH /z", "POST /y", "DELETE /w"]
    starlette = ('from starlette.applications import Starlette\nfrom starlette.routing import Route, WebSocketRoute\n\n'
                 'routes = [\n    Route("/users", users, methods=["GET", "POST"]),\n    WebSocketRoute("/ws", ws),\n]\n')
    assert _routes(tmp_path, "app.py", starlette) == ["GET /users", "POST /users", "WEBSOCKET /ws"]
    flask = ('from flask import Flask\napp = Flask(__name__)\n'
             'app.add_url_rule("/legacy", view_func=legacy, methods=["POST"])\n'
             'app.add_url_rule("/plain", view_func=plain)\n')
    assert _routes(tmp_path, "app.py", flask) == ["POST /legacy", "GET /plain"]
    fastapi = 'from fastapi import FastAPI\napp = FastAPI()\napp.add_api_route("/items", read_items, methods=["GET"])\n'
    assert _routes(tmp_path, "main.py", fastapi) == ["GET /items"]
    falcon = "import falcon\napp = falcon.App()\napp.add_route('/things', ThingsResource())\n"
    assert _routes(tmp_path, "app.py", falcon) == ["ANY /things"]
    pyramid = "from pyramid.config import Configurator\nconfig = Configurator()\nconfig.add_route('home', '/')\n"
    assert _routes(tmp_path, "app.py", pyramid) == ["ANY /"]
    sanic = 'from sanic import Sanic\napp = Sanic("x")\napp.add_route(handler, "/sanic", methods=["POST"])\n'
    assert _routes(tmp_path, "app.py", sanic) == ["POST /sanic"]
    tornado = ('import tornado.web\napp = tornado.web.Application([\n    (r"/", MainHandler),\n'
               '    (r"/story/([0-9]+)", StoryHandler),\n])\n')
    assert _routes(tmp_path, "app.py", tornado) == ["ANY /", "ANY /story/([0-9]+)"]
    django = ('from django.urls import path, re_path\nfrom . import views\n\nurlpatterns = [\n'
              '    path("articles/<int:year>/", views.year_archive),\n    re_path(r"^about/$", views.about),\n]\n')
    assert _routes(tmp_path, "blog/urls.py", django) == ["ANY articles/<int:year>/", "ANY ^about/$"]
    # path() outside Django (no django import, not a urls.py) is not a route.
    assert _routes(tmp_path, "tools/files.py", 'def path(value):\n    return value\n\npath("x", 1)\n') == []


def test_endpoint_facts_name_the_framework(tmp_path: Path):
    with collecting_facts() as facts:
        _analyze(tmp_path, "server.js", 'const express = require("express");\nconst app = express();\n'
                                        'app.get("/health", ok);\n')
        _analyze(tmp_path, "main.go", 'package main\nfunc main() {\n\te.GET("/users", list)\n}\n')
    endpoints = [(name, json.loads(detail)) for kind, name, detail in facts.facts if kind == "api_endpoint"]
    assert endpoints == [("GET /health", {"framework": "Express-style", "line": 3}),
                         ("GET /users", {"framework": "Gin/Echo", "line": 3})]
