# API Contract Intelligence

PDT inventories APIs from three directions.

**Contracts** (`api-contracts`): OpenAPI/Swagger JSON and YAML (HTTP operations and component schemas), AsyncAPI (channels and publish/subscribe operations), OpenRPC, WSDL (services, port types, bindings and operations), RAML, GraphQL schema definitions and named query/mutation/subscription operations, Protocol Buffers messages, enums, services and RPCs, Thrift services, structs, exceptions, enums and typedefs, and Postman collections (request grouping only; request secrets are not reported). JSON is parsed with the standard library; YAML uses PyYAML when installed, otherwise a deliberately shallow line-based fallback inventories common paths, methods and operation IDs. Each contract is read with a 16 MiB budget.

**Source declarations** (`api-endpoints`): framework route declarations found statically in source code, with the method, the path as written, the line and the framework (see [Endpoint adapters](#endpoint-adapters)). Retrofit and Feign interfaces declare calls a client makes, so they are not served endpoints. The first 500 endpoints of a file feed the integration summary; more are reported as an `UNKNOWN` finding. The API-style classifier (`api-type-classifier`) adds REST, GraphQL, gRPC, JSON-RPC, SOAP, WebSocket and event-driven markers. Outbound HTTP calls and served endpoints also feed the scan's integration summary and the cross-project integration map in `pdt compare` (see [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md)).

**Limits.** Contracts and route declarations are static evidence. PDT does not make network requests or claim that an API is deployed, reachable, authorized or behaviorally correct. Route prefixes added at run time, middleware, dynamic registration, compatibility analysis between contract versions and security testing are not covered.

## Endpoint adapters

Python routes come from the syntax tree, the file's imports deciding which framework a decorator or registration call belongs to. Every other language is read as text by the adapters of its family, chosen by file extension. A form that is not distinctive on its own (`router.get('/x')` is also how an HTTP client is called) counts only in a file that imports its framework, and client names (`axios`, `http`, `client`, `cli`, `$ua`, Guzzle's `$client`) never count. A declaration that a formatter wrapped over several lines, or a fluent chain continued on lines that start with `.`, is read joined, up to 8 lines and 2,048 characters, and each route keeps the line it starts on.

| Language | Frameworks and forms |
|---|---|
| Python | Flask, Quart, FastAPI, Sanic, Robyn and Starlette decorators (`@app.get`, `@app.route(..., methods=[...])`, `@router.api_route`, `@app.websocket`); Litestar, BlackSheep and Bottle free decorators (`@get("/x")`, `@route`); Starlette `Route`/`WebSocketRoute`; Flask `add_url_rule`; FastAPI `add_api_route`; aiohttp `web.get`, `web.route`, `router.add_get`, `add_route('GET', ...)`; Sanic `add_route`; Falcon `add_route`; Pyramid `config.add_route`; Tornado handler tuples; Django `path`, `re_path` and `url` (in a file that imports Django, or a `urls.py`) |
| JavaScript, TypeScript | Express-style routers (`app`, `router`, `server`, `fastify`, ... and, in a file importing Express, Koa, Fastify, Hono, Restify, Polka, hapi, Elysia and others, any receiver), Express `route('/x').get(...).post(...)`, Fastify and hapi route objects (`{ method, url }`), NestJS decorators; file-system routers: Next.js App Router (`app/**/route.ts` method exports) and Pages API (`pages/api/**`), SvelteKit (`src/routes/**/+server.ts`), Nuxt (`server/api/**`, `server/routes/**`, method suffixes such as `users.get.ts`) |
| Go | `net/http` `HandleFunc`/`Handle` with Go 1.22 method patterns (`"GET /items/{id}"`), gorilla/mux `.Methods(...)`, Gin, Echo, httprouter and Iris (`r.GET`), chi and Fiber (`r.Get`, `r.Method`), Beego `Router` |
| Java, Kotlin, Scala, Groovy | Spring mappings (arguments in any order, `@RequestMapping(method = RequestMethod.X)`), JAX-RS `@GET` with its `@Path`, Micronaut, Javalin, Spark, Vert.x, Jooby, Ratpack, Quarkus reactive routes, Ktor's routing DSL, http4s (`case GET -> Root / "x"`), Akka/Pekko HTTP `path("x")`, Cask, Scalatra, Play and Revel route files (`conf/routes`), Grails URL mappings |
| C#, Visual Basic | ASP.NET attributes, minimal APIs (`MapGet`, `MapMethods`), `MapControllerRoute` patterns, ServiceStack `[Route("/x", "GET POST")]`, Nancy and FastEndpoints |
| PHP | Laravel `Route::get`/`match`/`any`, Slim, Lumen, CodeIgniter 4 and Mezzio routers, Symfony `#[Route]` attributes and `@Route` annotations with their methods, WordPress `register_rest_route` (served under `/wp-json/`, `WP_REST_Server` method constants) |
| Ruby | Sinatra, Rails (`get 'x', to:`, `match ... via:`, `root`), Hanami, Grape, Roda |
| Rust | actix-web and Rocket attributes (`#[get]`, `#[route(..., method = ...)]`), axum and actix-web `.route("/x", get(h).post(h))`, actix `web::resource`, warp `path!`, tide and poem `.at(...)` |
| Swift, Dart | Vapor, Kitura and Hummingbird (path segments joined); shelf_router calls, cascades and `@Route` annotations, Conduit, and Dart Frog file routes (`routes/**.dart`) |
| C, C++ | Crow (with `.methods(...)` and WebSocket routes), Drogon, Pistache, oat++, cpp-httplib servers; Mongoose URI matching in C |
| Elixir, Clojure, Crystal, Perl, Lua | Phoenix routers and Plug.Router (`via:`); Compojure and Reitit; Kemal and Amber; Mojolicious and Dancer2; Lapis and lor |
| Haskell, Nim, F#, Erlang, Julia, R, OCaml, D, Pascal | Scotty and Servant API types; Jester; Giraffe, Saturn and Falco; Cowboy dispatch rules; Genie, Oxygen and `HTTP.register!`; plumber; Dream; vibe.d; Horse |

Methods are upper-case HTTP methods, `ANY` where the declaration names none (Django's `path()`, `@RequestMapping` without a method, catch-all handlers), and `WEBSOCKET` for WebSocket routes. A route's path includes the prefixes its file declares for it ([Route structure](#route-structure)); a route with none is reported as written.

## Route structure

Each route's full path is resolved from what encloses it in its file:

| Structure | Frameworks |
|---|---|
| Class-level mappings, applied to the routes in the class body | Spring `@RequestMapping`, JAX-RS `@Path`, NestJS and Micronaut `@Controller`, ASP.NET `[Route]`/`[RoutePrefix]` (with the `[controller]` token, and templates starting with `/` or `~/` left absolute), Symfony `#[Route]` and `@Route` |
| Blocks, applied to the routes in their braces | chi and Fiber `Route`, Ktor `route`, Javalin and Spark `path`, Akka and Pekko `pathPrefix`, Laravel `Route::prefix(...)->group` and `Route::group(['prefix' => ...])`, Slim `group`, Vapor `group` closures |
| Parenthesized and bracketed groups | Compojure `context`, Giraffe `subRoute`, Dream `scope` |
| Indented scopes, applied to the routes indented under them | Rails `namespace`, `scope` and nested resources (`/posts/:post_id/comments`), Grape `namespace`, `resource` and `route_param`, Roda `r.on`, Phoenix `scope` and nested resources |
| Router variables, applied to the routes declared on them | Gin, Echo and Fiber `Group`, ASP.NET `MapGroup`, Vapor `grouped`, Mojolicious `under`; Python: FastAPI `APIRouter(prefix=)`, Flask and Sanic `Blueprint(url_prefix=)` |
| Mounts in the same file | Express, Koa and Hono `use`/`route` of a router variable, axum `nest` (a `let` router), Rocket `mount` (by handler name), FastAPI `include_router(..., prefix=)`, Flask `register_blueprint(..., url_prefix=)` (which replaces the blueprint's own), aiohttp `add_subapp`, Starlette `Mount` (nested), Django `include(router.urls)` |
| Resource declarations, expanded to their routes | Rails `resources`/`resource` (`only:`, `except:`, `path:`), Laravel `Route::resource`/`apiResource` (nested names, `->only`, `->except`), Phoenix `resources` (`only:`, `except:`, `singleton:`), Django REST framework `router.register` (list and detail routes, method `ANY`) |

A class-level mapping is one followed within a few lines by a class declaration, with no route and no brace between them; otherwise it maps a method. A method-level JAX-RS `@Path` or ASP.NET `[Route]` completes the method annotation beside it. Spans come from the brace, parenthesis and indentation depth of every line, strings and `//` comments skipped. Not resolved in the file: routers mounted from another file (Django `include('app.urls')`, an imported FastAPI router or Flask blueprint, an Express router `require`d from another module), Visual Basic class-level routes (its classes end with `End Class`, not a brace), actix-web `scope`, Fastify `register` prefixes and NestJS `RouterModule`.
