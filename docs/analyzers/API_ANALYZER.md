# API Contract Intelligence

PDT inventories APIs from three directions, with GraphQL, RPC and other protocols in depth ([GraphQL](#graphql), [RPC services](#rpc-services), [Protocol endpoints](#protocol-endpoints)).

**Contracts** (`api-contracts`): OpenAPI/Swagger JSON and YAML (HTTP operations and component schemas), AsyncAPI (channels and publish/subscribe operations), OpenRPC, WSDL (services, port types, bindings and operations), RAML, GraphQL schema definitions and named query/mutation/subscription operations, Protocol Buffers messages, enums, services and RPCs, Thrift services, structs, exceptions, enums and typedefs, and Postman collections (request grouping only; request secrets are not reported). JSON is parsed with the standard library; YAML uses PyYAML when installed, otherwise a deliberately shallow line-based fallback inventories common paths, methods and operation IDs. Each contract is read with a 16 MiB budget.

**Source declarations** (`api-endpoints`): framework route declarations found statically in source code, with the method, the path as written, the line and the framework (see [Endpoint adapters](#endpoint-adapters)). Retrofit and Feign interfaces declare calls a client makes, so they are not served endpoints. The first 500 endpoints of a file feed the integration summary; more are reported as an `UNKNOWN` finding. The API-style classifier (`api-type-classifier`) adds REST, GraphQL, gRPC, JSON-RPC, SOAP, WebSocket and event-driven markers. Outbound HTTP calls and served endpoints also feed the scan's integration summary and the cross-project integration map in `pdt compare` (see [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md)).

**GraphQL** (`api-graphql`): schemas, operations, resolvers, directives, federation and subscriptions, in GraphQL files and in code ([GraphQL](#graphql)).

**RPC** (`api-rpc`): gRPC services, methods and protobuf messages, Thrift services and Avro protocols, RPC frameworks in code and generated clients and servers ([RPC services](#rpc-services)).

**Protocol endpoints** (`api-protocols`): JSON-RPC, SOAP, WebSocket, Server-Sent Events, webhook, MQTT and message-driven endpoints in code, and AsyncAPI, OpenRPC and OpenAPI webhook documents recognized by content ([Protocol endpoints](#protocol-endpoints)).

**Generated clients** (`api-clients`): the code OpenAPI code generators write, with the operations it calls; the code index cross-references contracts, routes, generated clients and HTTP calls ([Contracts, routes and generated clients](#contracts-routes-and-generated-clients)).

**Policies** (`api-policies`): authentication and authorization, versioning, rate-limit and validation declarations, with their scope and framework ([Policy declarations](#policy-declarations)).

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

## GraphQL

The `api-graphql` analyzer reads GraphQL with a tokenizer and parser of its own (block strings, strings and comments skipped, every character read once): schemas and documents in `.graphql`, `.gql` and `.graphqls` files, and GraphQL embedded in code (`gql` and `graphql` template tags, `/* GraphQL */` templates and `buildSchema` in JavaScript and TypeScript, `gql(...)` and `type_defs = ...` triple-quoted strings in Python, `AddDocumentFromString(@"...")` in C#). Nothing is executed or introspected.

| Finding | What it reports |
|---|---|
| GraphQL schema | The root operation types (`schema { query: ... }` or the default names) and their fields, extensions included: the queries, mutations and subscriptions a service serves; every type by kind; directive definitions and the directives the schema uses |
| GraphQL subscriptions | The subscription root's fields |
| GraphQL federation | An Apollo Federation subgraph schema: its version (from `@link(url: ".../federation/v2.x")`, or 1 when `@key` and friends appear without one), its entities (types with `@key`, `extend type` included) and their keys, and the federation directives it uses |
| GraphQL operations | Each client operation's kind, name and root fields (aliases resolved, fragments and inline fragments skipped), and fragments |
| GraphQL resolvers | The code behind fields, by framework (below) |
| GraphQL federation in code | Code that builds a subgraph (`@apollo/subgraph`, `graphene_federation`, `strawberry.federation`, Ariadne federation, DGS entity fetchers, Hot Chocolate `AddApolloFederation`) or a gateway (`@apollo/gateway`, `IntrospectAndCompose`, schema stitching) |
| GraphQL subscription transport | `graphql-ws`, `subscriptions-transport-ws`, `graphql-sse` and `PubSub` iterators |

Resolvers are found per framework, with field names as each framework derives them (Strawberry's `user_by_id` is `userById`; Hot Chocolate's `GetBookAsync` is `book`):

| Language | Frameworks and forms |
|---|---|
| JavaScript, TypeScript | Apollo and graphql-tools resolver maps (`Query: { user: ..., async search() {} }`), NestJS and TypeGraphQL `@Query`, `@Mutation`, `@Subscription`, `@ResolveField` (with a `name` option), Pothos and Nexus `queryField`/`mutationField`/`subscriptionField` |
| Python | Strawberry (`@strawberry.type` classes, `@strawberry.field`/`mutation`/`subscription`, `strawberry.field(resolver=)`), Graphene (`ObjectType` fields and `resolve_*` methods), Ariadne (`QueryType`, `ObjectType("User")` with `@x.field("...")` and `@x.source`) |
| Go | gqlgen's resolver methods (`func (r *queryResolver) Todos(...)`) |
| Java, Kotlin, Scala, Groovy | Spring for GraphQL `@QueryMapping`, `@MutationMapping`, `@SubscriptionMapping`, `@SchemaMapping`, `@BatchMapping`; Netflix DGS `@DgsQuery`, `@DgsMutation`, `@DgsSubscription`, `@DgsData` |
| C# | Hot Chocolate (`Query`/`Mutation`/`Subscription` classes, `[QueryType]`, `[ExtendObjectType(...)]`), GraphQL.NET (`Field<T>("name")` in an `ObjectGraphType`) |
| Ruby, Rust, Elixir | graphql-ruby (`field :name` in a `QueryType`), async-graphql and juniper (`#[Object]`/`#[graphql_object]` impls), Absinthe (`query do field :name ...`) |

The code index's `graphql` pass matches the scan's schema root fields, resolvers and client operations by type and field name (`metrics.code_index.graphql`): a "GraphQL API" summary, fields a schema declares that no resolver answers (on root types that have resolvers in the scan), resolvers for root fields no schema declares (on root types that have a schema in the scan, so code-first projects are not compared), and client operations that select root fields the scan's schemas do not declare. Each GraphQL file is read with a 16 MiB budget; a larger schema file is an `UNKNOWN` finding.

## RPC services

The `api-rpc` analyzer reads Protocol Buffers with a tokenizer and parser of its own (strings and comments skipped, every character read once), Apache Thrift and Avro IDL with a token scanner, and finds the RPC frameworks code serves and calls and the code protoc plugins and RPC compilers generate. Nothing is compiled, generated or called.

| Finding | What it reports |
|---|---|
| Protocol Buffers schema | The syntax (`proto2`, `proto3`) or edition, the package, imports and language options (`go_package`, `java_package`, `csharp_namespace` and others), and every message and enum, nested ones by qualified name (`Outer.Inner`), with its fields: label (`repeated`, `optional`, `required`), type, number, `map<K, V>` and `oneof` membership. `reserved`, `extensions`, `extend` and options are skipped; a proto2 group is a field |
| gRPC services | Each service's methods with their request and response types, the streaming kind (unary, server streaming, client streaming, bidirectional) and the HTTP routes a `google.api.http` option maps them to (gRPC-Gateway and gRPC transcoding, `additional_bindings` and `custom` verbs included) |
| Apache Thrift services, Avro protocols | Thrift services (`extends` included) and their functions; Avro IDL protocols and their messages. Throws lists, annotations, records, errors, enums, `fixed` and `decimal(p, s)` types are not methods |
| Generated RPC code | Files protoc plugins and RPC compilers write, by name and generator header, with the services they generate clients and servers for (table below) |
| RPC servers and clients | The servers and clients a source file declares, by framework and service (table below), and tRPC procedures with their kind (query, mutation, subscription) |

RPC frameworks in code (`X` is the service name):

| Framework | Servers | Clients |
|---|---|---|
| gRPC, Python | `add_XServicer_to_server(...)` | `x_pb2_grpc.XStub(channel)` |
| gRPC, Go | `pb.RegisterXServer(s, ...)` | `pb.NewXClient(conn)` |
| gRPC, Java and Kotlin | `extends XGrpc.XImplBase`, `XGrpcKt.XCoroutineImplBase` | `XGrpc.newStub`, `newBlockingStub` and `newFutureStub`, `XGrpcKt.XCoroutineStub(...)` |
| gRPC, C# | `: X.XBase` | `new X.XClient(channel)`, `AddGrpcClient<X.XClient>` |
| gRPC, C++ | `: public X::Service` (`AsyncService`, `CallbackService`) | `X::NewStub(channel)` |
| gRPC, Rust (tonic) | `.add_service(XServer::new(...))` | `XClient::connect(...)` |
| gRPC, Node.js | `addService(proto.X.service, ...)`, `addService(XService, ...)` | `new proto.X('host:port', grpc.credentials...)` |
| gRPC, Swift | `class ...: XProvider` (`XAsyncProvider`), `: X.SimpleServiceProtocol` | `XNIOClient(...)`, `XAsyncClient(...)`, `X.Client(wrapping:)` |
| gRPC, Dart | `extends XServiceBase` | `XClient(channel)` |
| gRPC, Ruby | `< X::Service`, `include X::Service` | `X::Stub.new(...)` |
| gRPC, PHP | | `new XClient('host:port', ...)` |
| Connect | Go `xconnect.NewXHandler(...)`, Connect-ES `router.service(X, ...)` | Go `xconnect.NewXClient(...)`, Connect-ES `createClient(X, transport)` |
| Twirp | `NewXServer(...)` | `NewXProtobufClient(...)`, `NewXJSONClient(...)` |
| gRPC-Web | | `new XClient(...)`, `new XPromiseClient(...)` |
| Apache Thrift | Python and JVM `X.Processor(handler)`, Go `NewXProcessor(...)` | Python and JVM `X.Client(protocol)`, Go `NewXClient(...)` and `NewXClientFactory(...)` |
| Apache Dubbo | `@DubboService` | `@DubboReference` |
| tRPC | `initTRPC`, and its procedures (`name: t.procedure... .query(...)`) | `createTRPCProxyClient`, `createTRPCClient`, `createTRPCReact`, `createTRPCNext` |
| Go `net/rpc`, Kitex | `rpc.Register(...)`, Kitex `x.NewServer(...)` | `rpc.Dial(...)`, `rpc.DialHTTP(...)`, `jsonrpc.Dial(...)`, Kitex `x.NewClient("...")` |

Forms that ordinary code also uses count only in files that import the framework: Rust `XClient::new` only with `tonic`, Swift providers only with `import GRPC`, and the Dart, Ruby, Connect-ES, gRPC-Web, Twirp server, Go Thrift, Go `net/rpc` and Kitex forms only with their imports. Swift's `Helloworld_Greeter` is reported as `Greeter`.

Generated code is recognized by file name and, where a hand-written file could have the name, by the generator's mark in the file's first 8 KiB:

| Generator | Files |
|---|---|
| protoc | `*_pb2.py`, `*_pb.js`, `*_pb.ts`, `*_pb.d.ts`, `*_pb.rb`, `*.pb.h` and `*.pb.cc`, and any file headed "Generated by the protocol buffer compiler" (C#, Java and other message code) |
| grpcio-tools, grpc-tools | `*_pb2_grpc.py`; Node.js `*_grpc_pb.js`; Ruby `*_services_pb.rb` |
| protoc-gen-go, protoc-gen-go-grpc, grpc-gateway | `*.pb.go`, `*_grpc.pb.go`, `*.pb.gw.go` |
| Connect, Twirp | `*.connect.go`, `*.twirp.go`, and `*_connect.ts` and `*_connect.js` with the generator's mark |
| gRPC Java, Kotlin and C# | `*Grpc.java`, `*GrpcKt.kt` and `*Grpc.cs`, with the generator's mark |
| gRPC-Web, Swift, Dart, C++ | `*_grpc_web_pb.js`, `*.grpc.swift`, `*.pb.swift`, `*.pbgrpc.dart`, `*.pb.dart` (`.pbenum`, `.pbjson`, `.pbserver`), `*.grpc.pb.h` and `*.grpc.pb.cc` |
| Thrift compiler, thriftgo, Kitex | Files headed "Autogenerated by Thrift Compiler", "Code generated by thriftgo" or "Code generated by Kitex" |

The code index's `rpc` pass (`metrics.code_index.rpc`) matches services by name (the last part of the qualified name, case-folded) across the scan: an "RPC services" summary with each service's definition, generated code, servers and clients; services no server implements, when the scan has servers for other services (Avro protocols are not compared: their servers are not looked for); and servers and clients of services that no definition or generated code in the scan declares. Each file is read with a 16 MiB budget; a larger IDL file is an `UNKNOWN` finding, and larger generated code is still recognized by its name.

## Protocol endpoints

The `api-protocols` analyzer finds the endpoints of APIs that are not REST, GraphQL or gRPC, in code and in the documents that describe them. Nothing is connected to or called.

**Documents, recognized by content.** Any YAML or JSON file whose top-level `asyncapi`, `openrpc` or `openapi` key holds a version is read, whatever its name (`api-contracts` reads `asyncapi.*` and `openrpc.*` files by name, for a shallower inventory, and WSDL documents):

| Finding | What it reports |
|---|---|
| AsyncAPI channels | AsyncAPI 2.x and 3.0: servers and their protocols (credentials removed from server URLs), channels by address, their operations (2.x `publish` and `subscribe` per channel; 3.0 `send` and `receive` operations tied to channels by `$ref`) and messages |
| OpenRPC methods | Each JSON-RPC method with its parameter names and result |
| OpenAPI webhooks | The webhooks an OpenAPI 3.1 document says the API sends (`webhooks`), with their HTTP methods; OpenAPI routes stay with `api-contracts` |
| Serverless event sources | `serverless.yml` functions triggered by `sqs`, `sns`, `kafka`, `msk`, `stream`, `rabbitmq`, `activemq`, `eventBridge`, `iot`, `s3` and `websocket` events, with the queue, topic, stream or route (an ARN is shortened to its name) |
| Azure Functions bindings | `function.json` trigger and output bindings other than HTTP and timers, with their queue, topic or event hub |

Reading YAML documents needs PyYAML (the optional infrastructure extra); without it they are `UNKNOWN` findings.

**In code** (one "Protocol endpoints" finding per file), by protocol:

| Protocol | Servers and handlers | Clients and producers |
|---|---|---|
| JSON-RPC | Methods registered with jsonrpcserver `@method`, json-rpc `dispatcher.add_method`, jsonrpclib `register_function`, fastapi-jsonrpc, django-modern-rpc `@rpc_method`, jayson (the keys of `new jayson.Server({...})`), json-rpc-2.0 `addMethod`, jsonrpc4j `@JsonRpcService` and `@JsonRpcMethod`, StreamJsonRpc `[JsonRpcMethod]` and `JsonRpc.Attach`, jsonrpsee `#[method]` and `#[subscription]`, jsonrpc-core `add_method`, gorilla/rpc `RegisterService`, PHP JsonRPC `withCallback` | Request literals with `"jsonrpc": "2.0"` and a `method`, in any language |
| SOAP | JAX-WS `@WebService`, `@WebMethod` and `Endpoint.publish`; Spring-WS `@PayloadRoot`; WCF `[ServiceContract]` and `[OperationContract]`; ASMX `[WebMethod]`; CoreWCF `AddServiceEndpoint`; spyne services and `@rpc`; PHP `SoapServer` and `addFunction`; node-soap `soap.listen`; WashOut `soap_action` | JAX-WS `@WebServiceClient` and `Service.create`; Spring-WS `marshalSendAndReceive`; WCF `ClientBase<T>` and `ChannelFactory<T>`; zeep and suds; PHP `SoapClient`; node-soap `createClient`; Savon |
| WebSocket | Jakarta `@ServerEndpoint`; Spring `addHandler`, STOMP `addEndpoint`, `@MessageMapping` (and its `@SendTo` destinations); Micronaut `@ServerWebSocket`; FastAPI, Starlette, Quart and Sanic `websocket` routes, `WebSocketRoute`, Flask-Sock, Django Channels `as_asgi()` routes, websockets, Tornado, aiohttp, python-socketio events; ws servers, NestJS gateways and `@SubscribeMessage`, express-ws and uWebSockets.js, Fastify and Hono routes, Socket.IO servers and namespaces, Bun and Deno; Go routes to handlers that upgrade (gorilla/websocket, coder/websocket) and `golang.org/x/net/websocket`; SignalR `MapHub` and hubs, ASP.NET Core `AcceptWebSocketAsync`; axum routes to handlers taking a `WebSocketUpgrade`, actix, warp, tokio-tungstenite; Phoenix sockets and channels; Action Cable channels and mounts; Ratchet; Laravel broadcast channels | `new WebSocket(...)`, Socket.IO and SignalR clients, Python, Java, Go, .NET and Rust clients, with the URL where it is a literal |
| Server-Sent Events | `text/event-stream` responses in any language; Spring `TEXT_EVENT_STREAM` mappings (with their path), `SseEmitter` and `ServerSentEvent`; sse-starlette `EventSourceResponse`; NestJS `@Sse`; Hono `streamSSE`; ASP.NET Core `ServerSentEvents`; axum `Sse`; Rails `ActionController::Live` | `new EventSource(...)`, requests that `Accept: text/event-stream`, Python SSE clients |
| Webhooks | Receivers, by the provider signature checks they make: Stripe, GitHub (`X-GitHub-Event`, `@octokit/webhooks`), `X-Hub-Signature` senders, GitLab, Slack, Shopify, Twilio, SendGrid, Svix and Standard Webhooks, PayPal, Paddle, Square, Discord, Linear, Zoom, Coinbase Commerce and generic `X-Webhook-Signature` headers | The incoming-webhook services code posts to: Slack, Discord, Microsoft Teams, Google Chat, DingTalk, WeCom and Feishu/Lark, named by service only (the URL holds the token) |
| MQTT | Topics subscribed to, with their QoS: Eclipse Paho (Python, Java, Go), MQTT.js, Spring Integration MQTT adapters, Mosquitto, ESP-MQTT, PubSubClient, rumqttc, MQTTnet | Topics published, with their QoS; broker addresses (credentials removed) |
| Message-driven | Kafka listeners (Spring, Micronaut `@Topic`), Spring AMQP, JMS, SQS, Azure Service Bus and Pulsar listeners (every topic or queue of a list), Spring Cloud Stream, SmallRye `@Incoming`; Azure Functions triggers (Java, C#, Python, JavaScript); MassTransit consumers and receive endpoints, NServiceBus handlers, Confluent.Kafka; Celery tasks, Dramatiq actors, Faust agents, kafka-python, aiokafka, confluent-kafka, pika; NestJS `@MessagePattern` and `@EventPattern`, BullMQ workers, Cloud Functions for Firebase Pub/Sub triggers; Watermill, Sarama, confluent-kafka-go; Sidekiq jobs and queues, Active Job queues, Karafka topics; Laravel queued jobs, Symfony Messenger handlers; Broadway pipelines | SmallRye `@Outgoing`, BullMQ queues, pika `basic_publish` |

Forms ordinary code also uses count only in files that import the framework: an MQTT `subscribe("...")` only with an MQTT client imported, `@app.task` only with Celery, `@SendTo` as a WebSocket destination only next to `@MessageMapping` (Kafka listeners reply with it), `.ws("/path")` only with express-ws or uWebSockets.js; gRPC's `grpc::ClientBase<T>` is not a WCF client. URLs keep their scheme, host, port and a path template: credentials, queries and opaque path segments are removed.

The code index's `protocols` pass (`metrics.code_index.protocols`) counts endpoints by protocol and role and matches across the scan:

- AsyncAPI channels with the topics, queues and channels code sends and receives (this analyzer's and the integration analyzer's), level by level, parameters (`{id}`) and MQTT wildcards (`+`, `#`) matching any level: "AsyncAPI channels no code uses" and "Topics no AsyncAPI document declares". Past 2,000,000 wildcard comparisons the matching is marked partial and neither is reported.
- OpenRPC methods with the methods JSON-RPC servers register: "OpenRPC methods no JSON-RPC server registers" and "JSON-RPC methods no OpenRPC document declares".
- WSDL operations (from `api-contracts`) with the SOAP operations code implements, case-folded and without `Request` and `Async`: "WSDL operations no SOAP server implements" and "SOAP operations no WSDL declares".
- POST, PUT and catch-all routes whose path names a webhook, hook or callback, with the signature checks in their files: "Webhook routes without a signature check in their file" (`LOW`; the check may be in middleware).

Each comparison runs only when the scan has both sides. Each file is read with a 16 MiB budget; a larger document is an `UNKNOWN` finding.

## Contracts, routes and generated clients

The code index's `contract_links` pass (`metrics.code_index.contract_links`) cross-references every OpenAPI and Swagger operation with the routes that serve it, the generated clients that call it and the HTTP calls code makes, by method and path template (`{petId}`, `<int:id>`, `:id` and `${id}` are the same parameter):

- **Contract operations** come from `api-contracts` (documents named `openapi.*` and `swagger.*`) and `api-protocols` (any other YAML or JSON document whose top-level `openapi` or `swagger` key holds a version: an "OpenAPI operations" finding), each with its operationId and base path (Swagger's `basePath`, or the path of OpenAPI's first `servers` URL). An operation matches routes with or without its base path, and routes under a longer mount prefix.
- **Routes** are the endpoints pass's routes, mounts resolved ([Route structure](#route-structure)), with the file and line of their declaration: for decorated handlers (Flask, FastAPI, Spring, NestJS and the like) the handler's line.
- **Generated clients** are found by the `api-clients` analyzer from the generator's mark in a source file's first 8 KiB: openapi-generator, swagger-codegen, swagger-typescript-api, NSwag, Kiota, AutoRest, oapi-codegen, ogen, orval, openapi-typescript, @hey-api/openapi-ts and openapi-typescript-codegen ("Generated API client" finding). The operations a client calls are its path literals (template literals, NSwag's `Operation Path` comments and Kiota's `{+baseurl}` URL templates included; RFC 6570 query expressions dropped), each with the HTTP method written nearest it, 400 characters before to 1,500 after (`method: 'GET'`, `HttpMethod.Get`, `http.MethodGet`, `"POST"`, `axios.get(`).
- **HTTP calls** are the integration analyzer's call sites ([CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md)).

| Finding | What it reports |
|---|---|
| API contracts and code | Each operation with its operationId, the route that serves it (file and line, framework), the generated client that calls it and the number of call sites |
| Contract operations no route serves | Operations of a contract whose other operations the scan serves (a contract of an API the project only calls is not compared) |
| Routes no contract declares | Routes in none of the scan's contracts, when the scan serves a contract |
| Generated client operations no contract declares | A client generated from one of the scan's contracts (it calls some of its operations) that calls operations the contract no longer declares: regenerate it |

gRPC services are tied to their generated code, servers and clients by the `rpc` pass ([RPC services](#rpc-services)), and GraphQL operations to schema fields and resolvers by the `graphql` pass ([GraphQL](#graphql)). The handler's symbol (its function or method name) is not recorded yet: the endpoint catalog will add it.

## Policy declarations

The `api-policies` analyzer records where code declares authentication and authorization, API versioning, rate limits and request validation, one "API policy declarations" finding per file. Each declaration has its category, framework, scope and detail: the scope is where it applies as written (`global` middleware or settings, a `router` or route group, a `class` such as a controller or view, a `route`, a `model` or schema that validates input, or an `exemption`), the detail what it says (the guard or role, the rate, the version, the validator). Forms ordinary code also uses count only in files that import the framework: `.limit("...")` only with Flask-Limiter or slowapi, `@Valid` and constraint annotations only with Bean Validation, data annotations only with `System.ComponentModel.DataAnnotations`.

| Category | Declarations |
|---|---|
| Authentication and authorization | Django `@login_required`, `@permission_required`, `@user_passes_test` and the `LoginRequiredMixin` family; Django REST framework `permission_classes`, `authentication_classes` and their `DEFAULT_` settings; Flask-Login and Flask-JWT-Extended `@jwt_required`; FastAPI `Depends`/`Security` on user, token, auth and permission dependencies, and its security schemes (`OAuth2PasswordBearer`, `HTTPBearer`, `APIKeyHeader` and others); Passport `authenticate`, Express `use()` of auth and JWT middleware, NestJS `@UseGuards`, `@Roles` and `APP_GUARD`, Fastify `onRequest`/`preHandler` hooks, Hono and Koa `jwt`, `bearerAuth` and `basicAuth`; Spring Security `@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@RolesAllowed`, filter chains (`authorizeHttpRequests`, `oauth2ResourceServer` and others) and `requestMatchers(...)` rules with their paths; JAX-RS, Quarkus and Micronaut `@PermitAll`, `@DenyAll`, `@Authenticated`; ASP.NET Core `[Authorize]`, `[AllowAnonymous]`, `UseAuthentication`, `UseAuthorization`, `AddJwtBearer` and `RequireAuthorization`; Go `Use()` of auth and JWT middleware, chi `jwtauth`; Rails `before_action :authenticate_*` (and `skip_before_action`), CanCanCan and Pundit; Laravel `auth`, `can:` and `verified` middleware, Symfony `#[IsGranted]`; Phoenix `plug :require_authenticated_*`; actix `HttpAuthentication`, tower `RequireAuthorizationLayer` |
| Versioning | ASP.NET API Versioning `[ApiVersion]`, `[MapToApiVersion]`, `AddApiVersioning`; NestJS `enableVersioning` (URI, header or media type) and `@Version`; Django REST framework `DEFAULT_VERSIONING_CLASS` and `versioning_class`; Spring `version =` mappings and `configureApiVersioning`; `Accept-Version`, `X-API-Version` and `Api-Version` headers; `application/vnd.*.vN+json` media types |
| Rate limiting | express-rate-limit and express-slow-down options; NestJS `ThrottlerModule`, `@Throttle` and `@SkipThrottle`; Flask-Limiter and slowapi `limit(...)` and `default_limits`; django-ratelimit; Django REST framework `DEFAULT_THROTTLE_RATES` and `throttle_classes`; ASP.NET Core `AddRateLimiter`, `[EnableRateLimiting]`, `RequireRateLimiting` and `[DisableRateLimiting]`; Resilience4j `@RateLimiter`, Bucket4j; `golang.org/x/time/rate` limiters, tollbooth; Rack::Attack throttles, Rails `rate_limit`; Laravel `throttle:` middleware and `RateLimiter::for`; tower-governor and actix-governor |
| Validation | Pydantic models, marshmallow schemas, Django REST framework serializers, Django forms, `jsonschema.validate`; Joi and celebrate, express-validator chains (with the field), zod, yup, Ajv, class-validator decorators, NestJS `ValidationPipe` (global or per route), Fastify route schemas; Bean Validation `@Valid`/`@Validated` and constraints; ASP.NET data annotations, `[ApiController]`, FluentValidation validators; go-playground/validator and Gin `validate:`/`binding:` tags; Laravel `$request->validate`, `Validator::make` and form requests, Symfony `#[Assert\...]`; Rails `validates` and strong parameters; Ecto `validate_*`; Rust `#[validate]` and garde |

The code index's `policies` pass (`metrics.code_index.policies`) counts the declarations by category, scope and framework ("API policy declarations") and reads the API versions route paths name (`/v1/users`, `/api/v2.1/orders`), with the versioning schemes declared ("API versions"). A declaration shows that a policy is configured where it is written, not which routes it covers or that it is enforced: the endpoint catalog attaches them to routes. Each file is read with a 16 MiB budget.

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

A class-level mapping is one followed within a few lines by a class declaration, with no route and no brace between them; otherwise it maps a method. A method-level JAX-RS `@Path` or ASP.NET `[Route]` completes the method annotation beside it. Spans come from the brace, parenthesis and indentation depth of every line, strings and `//` comments skipped.

**Across files.** A router mounted from another module is resolved across the scan by the code index's `endpoints` pass: Django `include("app.urls")` (and an imported urls module), FastAPI `include_router` and Flask `register_blueprint` of an imported router (`users.router` after `from app.routers import users`, relative imports included), aiohttp `add_subapp` of an imported application, and Express, Koa and Hono `use()` of a router imported or `require`d from a relative module. Python targets are found by module name, JavaScript ones by the specifier, with the `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx` and `index` forms tried. A mounting file mounted in turn adds its own prefix (a Django `include` inside an included module), up to 8 levels. The routes' full paths are in `metrics.code_index.endpoints`, with the mounts it resolved and those it could not (a package outside the scan), and feed the integration summary and `pdt compare`. A route `methods=` does not name is GET for Flask, Quart, Sanic, Bottle and FastAPI `route()`/`api_route()`, as those frameworks default.

Not resolved: Visual Basic class-level routes (its classes end with `End Class`, not a brace), actix-web `scope`, Fastify `register` prefixes, NestJS `RouterModule`, routers a function or a package builds, and routes registered at run time.
