"""RPC: Protocol Buffers, gRPC, Thrift and Avro services, RPC frameworks in code, generated code."""
import json
import time
from pathlib import Path

from project_discovery.analyzers.api import rpc
from project_discovery.analyzers.api.rpc import (RPCAnalyzer, code_rpc, generated_by, generated_services, idl_services,
                                                 parse_proto)
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord

PROTO = '''// The greeting service { braces in a comment }
syntax = "proto3";
package helloworld.v1;

import "google/api/annotations.proto";
import public "other.proto";
option go_package = "example.com/helloworld/v1;helloworldv1";
option java_multiple_files = true;
option (my.file_option) = { a: 1 };

/* A block comment with message Fake { } inside */
message HelloRequest {
  string name = 1;
  repeated string tags = 2 [packed = false];
  map<string, int32> counts = 3;
  oneof contact {
    string email = 4;
    Phone phone = 5;
  }
  message Phone { string number = 1; }
  enum Kind { KIND_UNSPECIFIED = 0; KIND_A = 1 [deprecated = true]; }
  reserved 9, 10 to 12;
  optional .helloworld.v1.Kind kind = 6;
  string description = 7 [(validate.rules).string = {min_len: 1, max_len: 100}];
}
message HelloReply { string message = 1; }
enum Status { option allow_alias = true; OK = 0; FINE = 0; BAD = -1; }

service Greeter {
  option (my.service_option) = "x";
  rpc SayHello (HelloRequest) returns (HelloReply) {
    option (google.api.http) = {
      get: "/v1/greet/{name}"
      additional_bindings { post: "/v1/greet" body: "*" }
    };
  }
  rpc LotsOfReplies(HelloRequest) returns (stream HelloReply);
  rpc LotsOfGreetings(stream HelloRequest) returns (HelloReply) {}
  rpc Chat(stream HelloRequest) returns (stream HelloReply);
}
service Health { rpc Check(.helloworld.v1.HelloRequest) returns (HelloReply); }
'''

THRIFT = '''include "shared.thrift"
namespace py tutorial
# a comment with service Fake {
/* block comment service Fake2 { } */
enum Operation { ADD = 1, SUBTRACT = 2 }
struct Work { 1: i32 num1 = 0, 2: i32 num2, 3: Operation op, 4: optional string comment }
exception InvalidOperation { 1: i32 whatOp, 2: string why }
service Calculator extends shared.SharedService {
   void ping(),
   i32 add(1:i32 num1, 2:i32 num2),
   i32 calculate(1:i32 logid, 2:Work w) throws (1:InvalidOperation ouch),
   map<string, list<i32>> stats() (api.get = "/stats")
   oneway void zip()
}
service Empty {}
'''

AVRO = '''@namespace("org.example")
protocol Simple {
  /** A greeting, with protocol Fake { } in a comment */
  record Greeting { string message; union { null, string } note = null; }
  error Curse { string message; }
  enum Suit { SPADES, HEARTS } = SPADES;
  fixed MD5(16);
  import idl "other.avdl";
  string hello(string greeting);
  Greeting greet(Greeting g) throws Curse;
  @java-class("java.util.ArrayList") array<string> names();
  union { null, string } maybe(int x);
  decimal(9,2) price(string sku);
  void ping() oneway;
}
'''


def _analyze(tmp_path: Path, relative: str, source: str):
    path = tmp_path / "source"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Source")
    analyzer = RPCAnalyzer()
    assert analyzer.supports(record)
    return {finding.title.split(":", 1)[0]: finding for finding in analyzer.analyze(path, record)}


def _facts(facts, kind: str) -> dict[str, dict]:
    return {name: json.loads(detail) for fact_kind, name, detail in facts.facts if fact_kind == kind}


def test_the_proto_parser_reads_messages_fields_enums_and_options():
    document = parse_proto(PROTO)
    assert (document.syntax, document.package) == ("proto3", "helloworld.v1")
    assert document.imports == ["google/api/annotations.proto", "other.proto"]
    assert document.options == {"go_package": "example.com/helloworld/v1;helloworldv1", "java_multiple_files": "true",
                                 "(my.file_option)": "{ a: 1 }"}
    messages = {message.name: message for message in document.messages}
    # Declarations in comments are not read; nested types are named by their parent.
    assert list(messages) == ["HelloRequest", "HelloRequest.Phone", "HelloRequest.Kind", "HelloReply", "Status"]
    assert messages["HelloRequest"].line == 12 and messages["HelloRequest.Kind"].kind == "enum"
    assert [(item.name, item.type, item.number, item.label, item.oneof) for item in messages["HelloRequest"].fields] == [
        ("name", "string", "1", "", ""), ("tags", "string", "2", "repeated", ""),
        ("counts", "map<string, int32>", "3", "map", ""), ("email", "string", "4", "", "contact"),
        ("phone", "Phone", "5", "", "contact"), ("kind", ".helloworld.v1.Kind", "6", "optional", ""),
        ("description", "string", "7", "", "")]
    # A field may be called "message"; enum values keep their numbers, negative and aliased ones too.
    assert [item.name for item in messages["HelloReply"].fields] == ["message"]
    assert [(item.name, item.number) for item in messages["Status"].fields] == [("OK", "0"), ("FINE", "0"), ("BAD", "-1")]
    assert [item.name for item in messages["HelloRequest.Kind"].fields] == ["KIND_UNSPECIFIED", "KIND_A"]


def test_the_proto_parser_reads_services_streaming_and_http_mappings():
    services = {service.name: service for service in parse_proto(PROTO).services}
    assert list(services) == ["Greeter", "Health"]
    methods = {method.name: method for method in services["Greeter"].methods}
    assert [(name, method.request, method.response, method.streaming) for name, method in methods.items()] == [
        ("SayHello", "HelloRequest", "HelloReply", "unary"),
        ("LotsOfReplies", "HelloRequest", "HelloReply", "server streaming"),
        ("LotsOfGreetings", "HelloRequest", "HelloReply", "client streaming"),
        ("Chat", "HelloRequest", "HelloReply", "bidirectional streaming")]
    assert methods["SayHello"].http == [("GET", "/v1/greet/{name}"), ("POST", "/v1/greet")]
    assert methods["SayHello"].line == 31 and methods["Chat"].line == 39
    check = services["Health"].methods[0]
    assert (check.name, check.request, check.streaming) == ("Check", ".helloworld.v1.HelloRequest", "unary")
    # A message type called "stream", proto2 groups and editions.
    other = parse_proto('edition = "2023";\nmessage M { optional group Result = 1 { string url = 2; } int32 after = 3; }\n'
                        "service S { rpc A(stream) returns (stream); }\n")
    assert other.edition == "2023"
    assert [item.name for item in other.messages[0].fields] == ["Result", "after"]
    method = other.services[0].methods[0]
    assert (method.request, method.response, method.streaming) == ("stream", "stream", "unary")


def test_proto_findings_and_facts(tmp_path: Path):
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "proto/helloworld.proto", PROTO)
    schema = findings["Protocol Buffers schema"]
    assert schema.confidence == "CONFIRMED"
    assert schema.detail.startswith("proto3, package helloworld.v1: 3 message(s) with 9 field(s), 2 enum(s), 2 import(s)")
    assert "go_package=example.com/helloworld/v1;helloworldv1" in schema.detail
    assert "proto/helloworld.proto:12 message HelloRequest (7 field(s))" in schema.evidence
    services = findings["gRPC services"]
    assert services.detail == ("2 service(s) (Greeter, Health) with 5 method(s): 2 unary, 1 bidirectional streaming, "
                               "1 client streaming, 1 server streaming; 1 mapped to HTTP routes by google.api.http "
                               "(gRPC-Gateway or transcoding).")
    assert ("proto/helloworld.proto:39 Greeter.Chat(stream HelloRequest) returns (stream HelloReply)"
            in services.evidence)
    assert "proto/helloworld.proto:31 Greeter.SayHello(HelloRequest) returns (HelloReply) GET /v1/greet/{name} " \
           "POST /v1/greet" in services.evidence
    assert _facts(facts, "rpc_service")["helloworld.v1.Greeter"]["methods"] == [
        "SayHello", "LotsOfReplies", "LotsOfGreetings", "Chat"]
    methods = _facts(facts, "rpc_method")
    assert methods["helloworld.v1.Greeter/SayHello"]["http"] == ["GET /v1/greet/{name}", "POST /v1/greet"]
    assert methods["helloworld.v1.Greeter/Chat"]["streaming"] == "bidirectional streaming"
    assert _facts(facts, "rpc_schema")["helloworld.v1"] == {"enums": 2, "messages": 3, "services": 2, "syntax": "proto3"}


def test_thrift_services_and_avro_protocols(tmp_path: Path):
    assert idl_services(THRIFT, ".thrift") == [("Calculator", ["ping", "add", "calculate", "stats", "zip"], 8),
                                               ("Empty", [], 15)]
    # Records, errors and enums, fixed types, imports, annotations and decimal(p, s) are not messages.
    assert idl_services(AVRO, ".avdl") == [("Simple", ["hello", "greet", "names", "maybe", "price", "ping"], 2)]
    with collecting_facts() as facts:
        thrift = _analyze(tmp_path, "idl/tutorial.thrift", THRIFT)
    assert thrift["Apache Thrift services"].detail == "2 service(s) with 5 method(s)."
    assert "idl/tutorial.thrift:8 Calculator: ping, add, calculate, stats, zip" in thrift["Apache Thrift services"].evidence
    assert _facts(facts, "rpc_service")["Calculator"]["framework"] == "Apache Thrift"
    avro = _analyze(tmp_path, "idl/simple.avdl", AVRO)
    assert avro["Avro protocols"].detail == "1 protocol(s) with 6 message(s)."
    assert _analyze(tmp_path, "idl/types.thrift", "struct A { 1: string service }\n") == {}


CODE = {
    "server.py": ('import grpc\nfrom thrift.transport import TSocket\n'
                  'helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)\n'
                  'stub = helloworld_pb2_grpc.GreeterStub(channel)\n'
                  'processor = Calculator.Processor(handler)\nclient = Calculator.Client(protocol)\n',
                  {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter"),
                   ("Apache Thrift", "server", "Calculator"), ("Apache Thrift", "client", "Calculator")}),
    "main.go": ('import "google.golang.org/grpc"\npb.RegisterGreeterServer(s, &server{})\nc := pb.NewGreeterClient(conn)\n'
                'mux.Handle(greetv1connect.NewGreetServiceHandler(&GreetServer{}))\n'
                'client := greetv1connect.NewGreetServiceClient(http.DefaultClient, "http://localhost:8080")\n'
                'h := NewUserHandler(repo)\nsrv := server.NewHTTPServer(cfg)\n',
                {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter"), ("Connect", "server", "GreetService"),
                 ("Connect", "client", "GreetService")}),
    "twirp.go": ('import "github.com/twitchtv/twirp"\nserver := haberdasher.NewHaberdasherServer(&HaberdasherServer{})\n'
                 'client := haberdasher.NewHaberdasherProtobufClient("http://localhost:8080", &http.Client{})\n',
                 {("Twirp", "server", "Haberdasher"), ("Twirp", "client", "Haberdasher")}),
    "arith.go": ('import "net/rpc"\nrpc.Register(new(Arith))\nclient, _ := rpc.DialHTTP("tcp", "localhost:1234")\n',
                 {("Go net/rpc", "server", ""), ("Go net/rpc", "client", "")}),
    "echo.go": ('import "github.com/cloudwego/kitex-examples/kitex_gen/api/echo"\nsvr := echo.NewServer(new(EchoImpl))\n'
                'cli, _ := echo.NewClient("echo", client.WithHostPorts("0.0.0.0:8888"))\n',
                {("Kitex", "server", "echo"), ("Kitex", "client", "echo")}),
    "calc.go": ('import "github.com/apache/thrift/lib/go/thrift"\nprocessor := tutorial.NewCalculatorProcessor(handler)\n'
                'client := tutorial.NewCalculatorClientFactory(transport, protocolFactory)\n',
                {("Apache Thrift", "server", "Calculator"), ("Apache Thrift", "client", "Calculator")}),
    "Greeter.java": ('import io.grpc.stub.StreamObserver;\nclass GreeterImpl extends GreeterGrpc.GreeterImplBase {}\n'
                     'GreeterGrpc.GreeterBlockingStub stub = GreeterGrpc.newBlockingStub(channel);\n'
                     '@DubboService public class DemoServiceImpl implements DemoService {}\n'
                     '@DubboReference private DemoService demoService;\n'
                     'TProcessor processor = new Calculator.Processor<>(handler);\n',
                     {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter"), ("Apache Dubbo", "server", ""),
                      ("Apache Dubbo", "client", ""), ("Apache Thrift", "server", "Calculator")}),
    "Greeter.kt": ('import io.grpc.kotlin.AbstractCoroutineServerImpl\n'
                   'class GreeterService : GreeterGrpcKt.GreeterCoroutineImplBase() {}\n'
                   'val stub = GreeterGrpcKt.GreeterCoroutineStub(channel)\n',
                   {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter")}),
    "Greeter.cs": ('using Grpc.Core;\npublic class GreeterService : Greeter.GreeterBase {}\n'
                   'var client = new Greeter.GreeterClient(channel);\n'
                   'services.AddGrpcClient<Inventory.InventoryClient>(o => {});\n',
                   {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter"), ("gRPC", "client", "Inventory")}),
    "greeter.cc": ('#include <grpcpp/grpcpp.h>\nclass GreeterServiceImpl final : public helloworld::Greeter::Service {};\n'
                   'auto stub = Greeter::NewStub(channel);\n',
                   {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter")}),
    "main.rs": ('use tonic::{transport::Server, Request};\n'
                'Server::builder().add_service(GreeterServer::new(greeter)).serve(addr).await?;\n'
                'let mut client = GreeterClient::connect("http://[::1]:50051").await?;\n',
                {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter")}),
    "server.js": ("const grpc = require('@grpc/grpc-js');\n"
                  "server.addService(hello_proto.Greeter.service, { sayHello });\n"
                  "server.addService(RouteGuideService, new RouteGuide());\n"
                  "const client = new hello_proto.Greeter('localhost:50051', grpc.credentials.createInsecure());\n",
                  {("gRPC", "server", "Greeter"), ("gRPC", "server", "RouteGuide"), ("gRPC", "client", "Greeter")}),
    "connect.ts": ('import { ConnectRouter } from "@connectrpc/connect";\n'
                   'export default (router: ConnectRouter) => router.service(ElizaService, { say: async (req) => req });\n'
                   'const client = createClient(ElizaService, transport);\n',
                   {("Connect", "server", "ElizaService"), ("Connect", "client", "ElizaService")}),
    "web.js": ("import {GreeterPromiseClient} from './helloworld_grpc_web_pb';\n"
               "const client = new GreeterPromiseClient('http://localhost:8080');\n",
               {("gRPC-Web", "client", "Greeter")}),
    "router.ts": ("import { initTRPC } from '@trpc/server';\nconst t = initTRPC.create();\n"
                  "export const appRouter = t.router({\n"
                  "  userById: t.procedure.input(z.string()).query(({ input }) => db.user.find(input)),\n"
                  "  createUser: publicProcedure.input(z.object({ name: z.string() })).mutation(async ({ input }) => input),\n"
                  "  onAdd: t.procedure.subscription(() => observable(() => {})),\n});\n"
                  "const trpc = createTRPCProxyClient<AppRouter>({ links: [] });\n",
                  {("tRPC", "server", ""), ("tRPC", "query procedure", "userById"),
                   ("tRPC", "mutation procedure", "createUser"), ("tRPC", "subscription procedure", "onAdd"),
                   ("tRPC", "client", "")}),
    "Greeter.swift": ("import GRPC\nfinal class GreeterProvider: Helloworld_GreeterProvider {}\n"
                      "let greeter = Helloworld_GreeterNIOClient(channel: channel)\n",
                      {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter")}),
    "greeter.dart": ("import 'package:grpc/grpc.dart';\nclass GreeterService extends GreeterServiceBase {}\n"
                     "final stub = GreeterClient(channel, options: CallOptions());\n",
                     {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter")}),
    "greeter.rb": ("require 'grpc'\nclass GreeterServer < Helloworld::Greeter::Service; end\n"
                   "stub = Helloworld::Greeter::Stub.new('localhost:50051', :this_channel_is_insecure)\n",
                   {("gRPC", "server", "Greeter"), ("gRPC", "client", "Greeter")}),
    "client.php": ("<?php\n$client = new Helloworld\\GreeterClient('localhost:50051', "
                   "['credentials' => Grpc\\ChannelCredentials::createInsecure()]);\n",
                   {("gRPC", "client", "Greeter")}),
}


def test_rpc_frameworks_in_every_language():
    for name, (source, expected) in CODE.items():
        found = {(framework, role, service) for framework, role, service, _ in code_rpc(source, Path(name).suffix)}
        assert found == expected, name


def test_ordinary_code_is_not_rpc():
    # Names RPC frameworks share with ordinary code count only in files that import the framework.
    assert code_rpc("HttpServer::new(|| App::new()).run().await;\nlet c = RedisClient::new(url);\n", ".rs") == []
    assert code_rpc("struct ContentView_Previews: PreviewProvider {}\nclass A: LocationProvider {}\n", ".swift") == []
    assert code_rpc("h := NewUserHandler(repo)\np := img.NewImageProcessor(cfg)\ns := api.NewAPIServer(cfg)\n", ".go") == []
    assert code_rpc("class Foo < Base::Service; end\n", ".rb") == []
    assert code_rpc("app.service(UserService, {});\nconst c = createClient(Config, opts);\n", ".ts") == []


def test_server_and_client_findings_and_facts(tmp_path: Path):
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "src/server.py", CODE["server.py"][0])
    found = findings["RPC servers and clients"]
    assert found.confidence == "INFERRED"
    assert found.detail == "Apache Thrift, gRPC: 2 client(s), 2 server(s)."
    assert "src/server.py:3 gRPC server Greeter" in found.evidence
    assert _facts(facts, "rpc_server")["Greeter"] == {"framework": "gRPC", "line": 3, "role": "server", "service": "Greeter"}
    assert _analyze(tmp_path, "src/plain.py", "import os\nprint(os.getcwd())\n") == {}


def test_generated_code_by_name_and_header(tmp_path: Path):
    python = "# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!\nclass GreeterStub(object):\n    pass\n"
    assert generated_by("gen/helloworld_pb2_grpc.py", python) == "grpcio-tools"
    assert generated_by("gen/helloworld_pb2.py", "") == "protoc"
    assert generated_by("api/greet.pb.go", "// Code generated by protoc-gen-go. DO NOT EDIT.") == "protoc-gen-go"
    assert generated_by("Greet.cs", "// <auto-generated>\n//     Generated by the protocol buffer compiler.  DO NOT EDIT!") \
        == "protocol buffer compiler"
    assert generated_by("gen/Calculator.py", "#\n# Autogenerated by Thrift Compiler (0.16.0)\n#") == "Thrift compiler"
    assert generated_by("GreeterGrpc.java", '@javax.annotation.Generated(value = "by gRPC proto compiler (version 1.58.0)")') \
        == "protoc-gen-grpc-java"
    # Names a hand-written file could have need the generator's mark.
    assert generated_by("src/db_connect.ts", "export function connect() {}") == ""
    assert generated_by("src/UserGrpc.java", "public class UserGrpc {}") == ""
    assert generated_services("type GreeterClient interface {\n}\ntype UnimplementedGreeterServer struct{}\n"
                              "type UnsafeGreeterServer interface {\n}\n", "protoc-gen-go-grpc") == ["Greeter"]
    assert generated_services("public protocol Helloworld_GreeterClientProtocol: GRPCClient {}", "grpc-swift") == ["Greeter"]
    assert generated_services("proto.helloworld.GreeterPromiseClient =\n    function(hostname, credentials, options) {",
                              "protoc-gen-grpc-web") == ["Greeter"]
    assert generated_services('export const ElizaService = {\n  typeName: "connectrpc.eliza.v1.ElizaService",',
                              "protoc-gen-connect-es") == ["ElizaService"]
    assert generated_services("module Helloworld\n  module Greeter\n    class Service\n", "grpc-tools") == ["Greeter"]
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "gen/helloworld_pb2_grpc.py", python)
    assert findings["Generated RPC code"].detail == ("Written by grpcio-tools, for service(s) Greeter. Generated code is "
                                                    "regenerated from its definition, not edited.")
    assert _facts(facts, "rpc_generated") == {"grpcio-tools": {"services": ["Greeter"]}}


def test_oversized_files(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(rpc, "MAX_RPC_BYTES", 10)
    assert _analyze(tmp_path, "api.proto", PROTO)["RPC definition scan budget reached"].confidence == "UNKNOWN"
    # Generated code past the budget is still known by its name; other code is left alone.
    assert "Generated RPC code" in _analyze(tmp_path, "gen/big.pb.go", "package gen\n" * 10)
    assert _analyze(tmp_path, "server.py", CODE["server.py"][0]) == {}


def test_the_parsers_are_linear_on_adversarial_input():
    for text in ("{" * 50_000, "message a {" * 20_000, "message " * 30_000, "rpc " * 30_000, "map<" * 30_000,
                 "service a { rpc b(" * 10_000, '"' * 50_000, "/*" * 30_000, "option (" * 30_000):
        started = time.perf_counter()
        parse_proto(text)
        assert time.perf_counter() - started < 5, text[:20]
    for extension in (".thrift", ".avdl"):
        for text in ("service a {" * 20_000, "protocol a {" * 20_000, "(" * 50_000, "service a { b(" * 20_000,
                     "protocol a { @x(" * 20_000, " " * 100_000 + "x("):
            started = time.perf_counter()
            idl_services(text, extension)
            assert time.perf_counter() - started < 5, text[:20]


def test_the_code_index_ties_services_to_generated_code_servers_and_clients(tmp_path: Path):
    project = tmp_path / "project"
    files = {
        "proto/helloworld.proto": ('syntax = "proto3";\npackage helloworld;\n'
                                   "service Greeter { rpc SayHello (HelloRequest) returns (HelloReply); }\n"
                                   "service Admin { rpc Reset (HelloRequest) returns (stream HelloReply); }\n"
                                   "message HelloRequest { string name = 1; }\nmessage HelloReply { string message = 1; }\n"),
        "server/app.py": ("import grpc\nfrom gen import helloworld_pb2_grpc\n\n\ndef serve(server):\n"
                          "    helloworld_pb2_grpc.add_GreeterServicer_to_server(object(), server)\n"),
        "client/main.go": ('package main\n\nimport "google.golang.org/grpc"\n\nfunc main() {\n'
                           '\tconn, _ := grpc.Dial("localhost:50051")\n\t_ = pb.NewGreeterClient(conn)\n'
                           "\t_ = billing.NewBillingClient(conn)\n}\n"),
        "gen/helloworld_pb2_grpc.py": ("# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!\nimport grpc\n\n\n"
                                       "class GreeterStub(object):\n    pass\n\n\nclass AdminStub(object):\n    pass\n"),
    }
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    value = report["metrics"]["code_index"]["rpc"]
    assert (value["service_total"], value["methods"]) == (2, 2)
    assert value["streaming"] == {"unary": 1, "server streaming": 1}
    assert value["schemas"] == {"files": 1, "messages": 2, "enums": 0}
    assert value["generated_files"] == {"grpcio-tools": 1}
    services = {item["name"]: item for item in value["services"]}
    greeter = services["helloworld.Greeter"]
    assert [item["file"] for item in greeter["servers"]] == ["server/app.py"]
    assert [item["file"] for item in greeter["clients"]] == ["client/main.go"]
    assert [item["generator"] for item in greeter["generated"]] == ["grpcio-tools"]
    assert value["unimplemented"] == ["helloworld.Admin"]
    assert value["undeclared"] == [{"role": "client", "service": "Billing", "file": "client/main.go", "line": 8,
                                    "framework": "gRPC"}]
    titles = {item["title"] for item in report["findings"] if item["analyzer"] == "code-index"}
    assert {"RPC services", "RPC services without a server",
            "RPC servers and clients for services no definition declares"} <= titles
