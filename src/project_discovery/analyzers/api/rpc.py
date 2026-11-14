"""RPC services, methods, messages, frameworks and generated code.

Protocol Buffers ``.proto`` files are read by a tokenizer and parser of its own (strings and
comments skipped, every character read once): the syntax or edition, package, imports and file
options; every message with its fields (label, type and number; maps and oneofs), nested
messages and enums; every service with its methods, their request and response types, the
streaming kind (unary, server streaming, client streaming, bidirectional) and the HTTP mapping a
``google.api.http`` option gives them (gRPC-Gateway and gRPC transcoding). Apache Thrift
services and Avro IDL protocols are read by a token scanner for their methods.

In code, the RPC frameworks a file serves or calls: gRPC servers and clients in Python, Go,
Java, Kotlin, C#, C++, Rust (tonic), Node.js, Swift, Dart, Ruby and PHP; Connect, Twirp,
gRPC-Web, Apache Thrift, Apache Dubbo, tRPC, Go ``net/rpc`` and Kitex. Forms that ordinary code
also uses (``XClient::new`` in Rust, ``NewXServer`` in Go) count only in files that import the
framework.

Generated code, the files protoc plugins and RPC compilers write (``*_pb2.py``,
``*_grpc.pb.go``, ``*Grpc.java``, ``*_grpc_web_pb.js`` and others), is recognized by its name
and its generator's header, with the services it generates clients and servers for. Nothing is
compiled, generated or called.
"""
from __future__ import annotations

import bisect
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import SourceBudgetExceeded, describe_error, read_text_bounded
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer

MAX_RPC_BYTES = 16 * 1024 * 1024
MAX_RPC_EVIDENCE = 100
MAX_RPC_FACTS = 1000
MAX_NESTING = 64
_GENERATED_HEAD = 8192


class _Lines:
    """Line numbers of offsets in a text, from its newline offsets (found on first use)."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._newlines: list[int] | None = None

    def line(self, offset: int) -> int:
        if self._newlines is None:
            self._newlines = [match.start() for match in re.finditer("\n", self.text)]
        return bisect.bisect_left(self._newlines, offset) + 1


# ------------------------------------------------------------------------- Protocol Buffers

_PROTO_TOKEN = re.compile(r'''//[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/|$)|"(?:[^"\\\n]|\\.)*+"?+|'(?:[^'\\\n]|\\.)*+'?+|'''
                          r'''\.?[A-Za-z_][\w.]*+|-?(?:0[xX][0-9A-Fa-f]++|\d[\d.eE+-]*+)|[{}()\[\]<>;=,:]''')
_LABELS = frozenset({"repeated", "optional", "required"})
_HTTP_BINDING = re.compile(r'\b(get|put|post|delete|patch)\s*+[:=]\s*+"([^"\n]{0,500}+)"')
_HTTP_CUSTOM = re.compile(r'\bcustom[ \t]*+:?+\s*+\{\s*+kind\s*+:\s*+"(\w{1,40}+)"[\s,;]*+path\s*+:\s*+"([^"\n]{0,500}+)"')
_STREAMING = {(False, False): "unary", (False, True): "server streaming", (True, False): "client streaming",
              (True, True): "bidirectional streaming"}
_FILE_OPTIONS = frozenset({"go_package", "java_package", "java_multiple_files", "csharp_namespace", "php_namespace",
                           "ruby_package", "swift_prefix", "objc_class_prefix", "optimize_for"})


@dataclass(slots=True)
class ProtoField:
    name: str
    type: str
    number: str
    label: str = ""
    oneof: str = ""


@dataclass(slots=True)
class ProtoMessage:
    name: str
    line: int
    kind: str = "message"  # or "enum"
    fields: list[ProtoField] = field(default_factory=list)


@dataclass(slots=True)
class ProtoMethod:
    name: str
    request: str
    response: str
    line: int
    client_streaming: bool = False
    server_streaming: bool = False
    http: list[tuple[str, str]] = field(default_factory=list)

    @property
    def streaming(self) -> str:
        return _STREAMING[(self.client_streaming, self.server_streaming)]


@dataclass(slots=True)
class ProtoService:
    name: str
    line: int
    methods: list[ProtoMethod] = field(default_factory=list)


@dataclass(slots=True)
class ProtoFile:
    syntax: str = ""
    edition: str = ""
    package: str = ""
    imports: list[str] = field(default_factory=list)
    options: dict[str, str] = field(default_factory=dict)
    messages: list[ProtoMessage] = field(default_factory=list)
    services: list[ProtoService] = field(default_factory=list)


class _ProtoParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = [(match.group(0), match.start()) for match in _PROTO_TOKEN.finditer(text)
                       if not match.group(0).startswith(("//", "/*"))]
        self.index = 0
        self.lines = _Lines(text)

    def peek(self, ahead: int = 0) -> str:
        index = self.index + ahead
        return self.tokens[index][0] if index < len(self.tokens) else ""

    def take(self) -> tuple[str, int]:
        token = self.tokens[self.index] if self.index < len(self.tokens) else ("", len(self.text))
        self.index += 1
        return token

    def done(self) -> bool:
        return self.index >= len(self.tokens)

    def skip_statement(self) -> None:
        """Skip to the end of a statement: its ``;``, or a balanced ``{...}`` block."""
        depth = 0
        while not self.done():
            token, _ = self.take()
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1
                if depth <= 0:
                    return
            elif token == ";" and depth == 0:
                return

    def group_text(self, opening: str, closing: str) -> str:
        """Skip a balanced group at the current token; return its source text."""
        if self.peek() != opening:
            return ""
        start = self.tokens[self.index][1]
        depth = 0
        while not self.done():
            token, offset = self.take()
            if token == opening:
                depth += 1
            elif token == closing:
                depth -= 1
                if depth == 0:
                    return self.text[start:offset + 1]
        return self.text[start:]

    @staticmethod
    def string(token: str) -> str:
        return token[1:-1] if len(token) >= 2 and token[0] in "\"'" and token[-1] == token[0] else token.strip("\"'")

    def to_semicolon(self) -> None:
        """The rest of a statement: options in brackets, a group's body, up to its ``;``."""
        while not self.done() and self.peek() not in {";", "}"}:
            if self.peek() == "[":
                self.group_text("[", "]")
            elif self.peek() == "{":
                self.group_text("{", "}")
                return
            else:
                self.take()
        if self.peek() == ";":
            self.take()

    def number(self) -> str:
        if self.peek() == "=":
            self.take()
            return self.take()[0]
        return ""

    def message(self, document: ProtoFile, prefix: str, kind: str, depth: int) -> None:
        name, offset = self.take()
        if not name or self.peek() != "{" or depth > MAX_NESTING:
            self.skip_statement()
            return
        qualified = f"{prefix}{name}"
        message = ProtoMessage(qualified, self.lines.line(offset), kind)
        document.messages.append(message)
        self.take()
        oneof = ""
        while not self.done() and (self.peek() != "}" or oneof):
            token, _ = self.take()
            if token == "}":  # the end of a oneof
                oneof = ""
            elif token in {"message", "enum"} and kind == "message" and not oneof:
                self.message(document, f"{qualified}.", token, depth + 1)
            elif token == "oneof" and kind == "message" and self.peek(1) == "{":
                oneof, _ = self.take()
                self.take()
            elif token in {"option", "reserved", "extensions", "extend"}:
                self.skip_statement()
            elif token == ";":
                continue
            elif kind == "enum":
                number = self.number()
                if number:
                    message.fields.append(ProtoField(token, "", number))
                self.to_semicolon()
            elif token == "map" and self.peek() == "<":
                types = self.group_text("<", ">")
                name, _ = self.take()
                number = self.number()
                if number:
                    message.fields.append(ProtoField(name, f"map{types}", number, "map", oneof))
                self.to_semicolon()
            else:
                label = token if token in _LABELS else ""
                field_type = self.take()[0] if label else token
                name, _ = self.take()
                number = self.number()
                if name and number:
                    message.fields.append(ProtoField(name, field_type, number, label, oneof))
                self.to_semicolon()
        if not self.done():
            self.take()

    def message_type(self) -> tuple[bool, str]:
        """A method's ``(stream Type)``: whether it streams, and the type."""
        if self.peek() != "(":
            return False, ""
        self.take()
        streaming = self.peek() == "stream" and self.peek(1) not in {")", ""}
        if streaming:
            self.take()
        name = self.take()[0] if self.peek() != ")" else ""
        while not self.done() and self.peek() != ")":
            self.take()
        self.take()
        return streaming, name

    def service(self, document: ProtoFile) -> None:
        name, offset = self.take()
        if not name or self.peek() != "{":
            self.skip_statement()
            return
        service = ProtoService(name, self.lines.line(offset))
        document.services.append(service)
        self.take()
        while not self.done() and self.peek() != "}":
            token, offset = self.take()
            if token == "option":
                self.skip_statement()
            if token != "rpc":
                continue
            method = ProtoMethod(self.take()[0], "", "", self.lines.line(offset))
            method.client_streaming, method.request = self.message_type()
            if self.peek() == "returns":
                self.take()
                method.server_streaming, method.response = self.message_type()
            if self.peek() == "{":
                body = self.group_text("{", "}")
                if "google.api.http" in body:
                    method.http = [(verb.upper(), path) for verb, path in _HTTP_BINDING.findall(body)]
                    method.http += [(kind.upper(), path) for kind, path in _HTTP_CUSTOM.findall(body)]
            elif self.peek() == ";":
                self.take()
            service.methods.append(method)
        if not self.done():
            self.take()

    def parse(self) -> ProtoFile:
        document = ProtoFile()
        while not self.done():
            token, _ = self.take()
            if token in {"syntax", "edition"} and self.peek() == "=":
                self.take()
                value = self.string(self.take()[0])
                if token == "syntax":
                    document.syntax = value
                else:
                    document.edition = value
                self.to_semicolon()
            elif token == "package":
                document.package = self.take()[0]
                self.to_semicolon()
            elif token == "import":
                if self.peek() in {"public", "weak", "option"}:
                    self.take()
                document.imports.append(self.string(self.take()[0]))
                self.to_semicolon()
            elif token == "option":
                name = self.take()[0]
                if name == "(":  # option (custom.name) = ...
                    name = f"({self.take()[0]})"
                    if self.peek() == ")":
                        self.take()
                if self.peek() == "=":
                    self.take()
                    if self.peek() == "{":
                        document.options[name] = self.group_text("{", "}")[:200]
                    else:
                        document.options[name] = self.string(self.take()[0])
                self.to_semicolon()
            elif token in {"message", "enum"}:
                self.message(document, "", token, 0)
            elif token == "service":
                self.service(document)
            elif token == "extend":
                self.take()
                self.skip_statement()
        return document


def parse_proto(text: str) -> ProtoFile:
    """The declarations of a Protocol Buffers file."""
    return _ProtoParser(text).parse()


# ----------------------------------------------------------- Apache Thrift and Avro IDL

# Comments and strings are matched so they can be skipped; annotations are kept.
_IDL_TOKEN = re.compile(r'''//[^\n]*+|#[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/|$)|"(?:[^"\\\n]|\\.)*+"?+|'''
                        r''''(?:[^'\\\n]|\\.)*+'?+|@[\w.-]*+|[A-Za-z_][\w.]*+|[(){};]''')
# Avro declarations and types with parentheses that are not messages: fixed MD5(16); decimal(9,2).
_AVRO_DECLARATIONS = frozenset({"fixed", "import"})
_AVRO_PARAMETRIC = frozenset({"decimal"})


def _skip_group(tokens: list[str], index: int, opening: str, closing: str) -> int:
    """The index after the balanced group opened at ``index``."""
    depth = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token == opening:
            depth += 1
        elif token == closing:
            depth -= 1
            if depth == 0:
                break
    return index


def _idl_methods(tokens: list[str], index: int, thrift: bool) -> tuple[list[str], int]:
    """The methods of the Thrift service or Avro protocol whose body starts at ``index``, and the
    index after the body. A method is the identifier before a parameter list; throws lists,
    annotations, record, error and enum bodies and union branches are skipped."""
    methods: list[str] = []
    first = last = ""  # the declaration's first and latest identifiers
    annotation = after = False  # after: the declaration's parameter list was read
    while index < len(tokens):
        token = tokens[index]
        if token == "}":
            return methods, index + 1
        if token == "{":
            index = _skip_group(tokens, index, "{", "}")
            first = last = ""
            after = False
            continue
        if token == "(":
            if not (annotation or after or not last or last == "throws" or first in _AVRO_DECLARATIONS
                    or last in _AVRO_PARAMETRIC):
                methods.append(last)
                after = True
            annotation = False
            index = _skip_group(tokens, index, "(", ")")
            continue
        index += 1
        if token == ";":
            first = last = ""
            annotation = after = False
        elif token.startswith("@"):
            annotation = True
        else:
            annotation = False
            if after and thrift and token != "throws":  # separators between Thrift functions are optional
                after = False
                first = ""
            first = first or token
            last = token
    return methods, index


def idl_services(text: str, extension: str) -> list[tuple[str, list[str], int]]:
    """(service, methods, line) of the services of a Thrift file or the protocols of an Avro IDL file."""
    thrift = extension == ".thrift"
    keyword = "service" if thrift else "protocol"
    tokens: list[str] = []
    offsets: list[int] = []
    for match in _IDL_TOKEN.finditer(text):
        token = match.group(0)
        if token[0] not in "/#\"'":
            tokens.append(token)
            offsets.append(match.start())
    lines = _Lines(text)
    found = []
    index = 0
    while index < len(tokens) and len(found) < MAX_RPC_FACTS:
        token = tokens[index]
        index += 1
        if token != keyword or index >= len(tokens) or not tokens[index].isidentifier():
            continue
        name, start = tokens[index], offsets[index - 1]
        index += 1
        if thrift and index < len(tokens) and tokens[index] == "extends":
            index += 2
        if index < len(tokens) and tokens[index] == "{":
            methods, index = _idl_methods(tokens, index + 1, thrift)
            found.append((name, methods, lines.line(start)))
    return found


# ------------------------------------------------------------------------------- code

_PY = frozenset({".py"})
_GO = frozenset({".go"})
_JVM = frozenset({".java", ".kt", ".kts", ".scala", ".groovy"})
_CS = frozenset({".cs"})
_CPP = frozenset({".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"})
_RUST = frozenset({".rs"})
_JS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
_SWIFT = frozenset({".swift"})
_DART = frozenset({".dart"})
_RUBY = frozenset({".rb"})
_PHP = frozenset({".php"})

# Imports a file must hold before forms that ordinary code also uses count.
_TONIC = re.compile(r"\btonic\b")
_SWIFT_GRPC = re.compile(r"\bimport[ \t]++GRPC")
_DART_GRPC = re.compile(r"package:grpc/")
_RUBY_GRPC = re.compile(r"(?i)grpc|_services_pb")
_CONNECT_ES = re.compile(r"@connectrpc/|@bufbuild/connect")
_GRPC_WEB = re.compile(r"grpc-web|_grpc_web_pb")
_TWIRP = re.compile(r"(?i)twirp")
_GO_THRIFT = re.compile(r"apache/thrift")
_NET_RPC = re.compile(r'"net/rpc(?:/jsonrpc)?+"')
_KITEX = re.compile(r"kitex_gen/|cloudwego/kitex")
_TRPC = re.compile(r"(?i)trpc")

# (framework, role, pattern with an optional "service" group, extensions, import the file must hold)
_RPC_CODE = (
    ("gRPC", "server", re.compile(r"\badd_(?P<service>\w{1,120}?)Servicer_to_server\b"), _PY, None),
    ("gRPC", "client", re.compile(r"_pb2_grpc\.(?P<service>\w{1,120}?)Stub\s*+\("), _PY, None),
    ("gRPC", "server", re.compile(r"\.Register(?P<service>\w{1,120}?)Server\s*+\("), _GO, None),
    ("gRPC", "client", re.compile(r"\.New(?P<service>\w{1,120}?)Client\s*+\(\s*+(?:\w{1,40}\.)?"
                                  r"(?:\w{0,30}[Cc]onn\w{0,20}|cc|[Cc]hannel|ch)\s*+\)"), _GO, None),
    ("gRPC", "server", re.compile(r"\b(?P<service>\w{1,120}?)(?:Grpc\.(?P=service)ImplBase|GrpcKt\.(?P=service)"
                                  r"CoroutineImplBase)\b"), _JVM, None),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120}?)(?:Grpc\.new(?:Blocking|Future)?+Stub|GrpcKt\.(?P=service)"
                                  r"CoroutineStub)\s*+\("), _JVM, None),
    ("gRPC", "server", re.compile(r":\s*+(?:\w{1,120}\.)?(?P<service>\w{1,120})\.(?P=service)Base\b"), _CS, None),
    ("gRPC", "client", re.compile(r"\bnew\s++(?:\w{1,120}\.)?(?P<service>\w{1,120})\.(?P=service)Client\s*+\("), _CS, None),
    ("gRPC", "client", re.compile(r"\bAddGrpcClient\s*+<\s*+(?:\w{1,120}\.)?(?P<service>\w{1,120})\.(?P=service)Client\s*+>"),
     _CS, None),
    ("gRPC", "server", re.compile(r"\bpublic\s++(?:[\w:]{1,200}::)?(?P<service>\w{1,120})::(?:Service|AsyncService|"
                                  r"CallbackService)\b"), _CPP, None),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120})::NewStub\s*+\("), _CPP, None),
    ("gRPC", "server", re.compile(r"\.add_service\s*+\(\s*+(?:\w{1,120}::){0,6}(?P<service>\w{1,120}?)Server::"
                                  r"(?:new|with_interceptor|from_arc)\s*+\("), _RUST, _TONIC),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120}?)Client::(?:connect|new|with_interceptor|with_origin)\s*+\("),
     _RUST, _TONIC),
    ("gRPC", "server", re.compile(r"\.addService\s*+\(\s*+(?:[\w$]{1,120}\.){0,6}(?P<service>[\w$]{1,120})\.service\b"),
     _JS, None),
    ("gRPC", "server", re.compile(r"\.addService\s*+\(\s*+(?:[\w$]{1,120}\.){0,6}(?P<service>[\w$]{1,120}?)Service\s*+,"),
     _JS, None),
    ("gRPC", "client", re.compile(r"\bnew\s++(?:[\w$]{1,120}\.){0,6}(?P<service>[\w$]{1,120}?)(?:Client)?\s*+\(\s*+"
                                  r"['\"`][^'\"`\n]{1,200}['\"`]\s*+,\s*+(?:grpc\.)?credentials\."), _JS, None),
    ("gRPC", "server", re.compile(r"\b(?:class|struct|actor)\s++\w{1,120}\s*+:\s*+(?:\w{1,120}\.)?"
                                  r"(?P<service>\w{1,120}?)(?:Async)?Provider\b"), _SWIFT, _SWIFT_GRPC),
    ("gRPC", "server", re.compile(r":\s*+(?P<service>\w{1,120})\.(?:Simple)?ServiceProtocol\b"), _SWIFT, _SWIFT_GRPC),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120}?)(?:NIO|Async)Client\s*+\("), _SWIFT, _SWIFT_GRPC),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120})\.Client\s*+\(\s*+wrapping\b"), _SWIFT, _SWIFT_GRPC),
    ("gRPC", "server", re.compile(r"\bextends\s++(?:\w{1,60}\.)?(?P<service>\w{1,120}?)ServiceBase\b"), _DART, _DART_GRPC),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120}?)Client\s*+\(\s*+\w{0,30}[Cc]hannel\b"), _DART, _DART_GRPC),
    ("gRPC", "server", re.compile(r"(?:\binclude\s++|<\s*+)(?:\w{1,120}::){0,8}(?P<service>\w{1,120})::Service\b"),
     _RUBY, _RUBY_GRPC),
    ("gRPC", "client", re.compile(r"\b(?P<service>\w{1,120})::Stub\.new\b"), _RUBY, _RUBY_GRPC),
    ("gRPC", "client", re.compile(r"\bnew\s++(?:\\?\w{1,120}\\){0,8}(?P<service>\w{1,120}?)Client\s*+\(\s*+"
                                  r"['\"][^'\"\n]{1,200}:\d"), _PHP, None),
    # Connect (connectrpc), Twirp and gRPC-Web.
    ("Connect", "server", re.compile(r"connect\.New(?P<service>\w{1,120})Handler\s*+\("), _GO, None),
    ("Connect", "client", re.compile(r"connect\.New(?P<service>\w{1,120})Client\s*+\("), _GO, None),
    ("Connect", "server", re.compile(r"\.service\s*+\(\s*+(?P<service>\w{1,120})\s*+,"), _JS, _CONNECT_ES),
    ("Connect", "client", re.compile(r"\bcreate(?:Promise)?Client\s*+\(\s*+(?P<service>\w{1,120})\s*+,"), _JS, _CONNECT_ES),
    ("Twirp", "server", re.compile(r"\.New(?P<service>\w{1,120}?)Server\s*+\("), _GO, _TWIRP),
    ("Twirp", "client", re.compile(r"\bNew(?P<service>\w{1,120}?)(?:Protobuf|JSON)Client\s*+\("), _GO, None),
    ("gRPC-Web", "client", re.compile(r"\bnew\s++(?:[\w$]{1,120}\.){0,6}(?P<service>[\w$]{1,120}?)(?:Promise)?Client\s*+\("),
     _JS, _GRPC_WEB),
    # Apache Thrift, Apache Dubbo, tRPC, Go net/rpc and Kitex.
    ("Apache Thrift", "server", re.compile(r"\b(?P<service>\w{1,120})\.Processor\s*+(?:<[^<>()\n]{0,200}+>\s*+)?\("),
     _PY | _JVM, None),
    ("Apache Thrift", "client", re.compile(r"\b(?P<service>\w{1,120})\.Client\s*+\(\s*+\w{0,40}(?:prot|Prot)"),
     _PY | _JVM, None),
    ("Apache Thrift", "server", re.compile(r"\bNew(?P<service>\w{1,120}?)Processor\s*+\("), _GO, _GO_THRIFT),
    ("Apache Thrift", "client", re.compile(r"\bNew(?P<service>\w{1,120}?)Client(?:Factory|Protocol)?\s*+\(\s*+"
                                           r"(?:thrift\.|\w{0,40}[Tt]rans|\w{0,40}[Pp]rot)"), _GO, _GO_THRIFT),
    ("Apache Dubbo", "server", re.compile(r"@DubboService\b"), _JVM, None),
    ("Apache Dubbo", "client", re.compile(r"@DubboReference\b"), _JVM, None),
    ("tRPC", "server", re.compile(r"\binitTRPC\b"), _JS, None),
    ("tRPC", "client", re.compile(r"\bcreateTRPC(?:Proxy)?Client\b|\bcreateTRPC(?:React|Next)\b"), _JS, None),
    ("Go net/rpc", "server", re.compile(r"\brpc\.Register(?:Name)?\s*+\("), _GO, _NET_RPC),
    ("Go net/rpc", "client", re.compile(r"\b(?:rpc|jsonrpc)\.Dial(?:HTTP)?\s*+\("), _GO, _NET_RPC),
    ("Kitex", "server", re.compile(r"\b(?P<service>\w{1,120})\.NewServer\s*+\("), _GO, _KITEX),
    ("Kitex", "client", re.compile(r"\b(?P<service>\w{1,120})\.(?:MustNewClient|NewClient)\s*+\(\s*+\""), _GO, _KITEX),
)
_NOT_SERVICES = frozenset({"server", "client", "kitex", "grpc", "rpc"})
# tRPC procedures: name: t.procedure / publicProcedure ... .query(...) / .mutation(...) / .subscription(...)
_TRPC_PROCEDURE = re.compile(r"(?<![\w$])(?P<name>[A-Za-z_$][\w$]{0,99})\s*+:\s*+(?:\w{1,60}\.)?\w{0,60}[Pp]rocedure\b"
                             r"(?P<chain>[^;]{0,2000}?)\.(?P<kind>query|mutation|subscription)\s*+\(")
_RPC_HINT = re.compile(r"(?i)grpc|_pb2|thrift|connect|twirp|dubbo|trpc|net/rpc|kitex|tonic")

# Generated code: (file name pattern, generator, what the head must hold when a hand-written file
# could have the name).
_GENERATED_NAMES = (
    (re.compile(r"_pb2_grpc\.py$"), "grpcio-tools", None),
    (re.compile(r"_pb2\.py$"), "protoc", None),
    (re.compile(r"_grpc\.pb\.go$"), "protoc-gen-go-grpc", None),
    (re.compile(r"\.pb\.gw\.go$"), "grpc-gateway", None),
    (re.compile(r"\.connect\.go$"), "protoc-gen-connect-go", None),
    (re.compile(r"\.twirp\.go$"), "protoc-gen-twirp", None),
    (re.compile(r"\.pb\.go$"), "protoc-gen-go", None),
    (re.compile(r"GrpcKt\.kt$"), "grpc-kotlin", re.compile(r"\bio\.grpc\.kotlin\b")),
    (re.compile(r"Grpc\.java$"), "protoc-gen-grpc-java", re.compile(r"by gRPC proto compiler|GrpcGenerated")),
    (re.compile(r"Grpc\.cs$"), "Grpc.Tools", re.compile(r"<auto-generated>")),
    (re.compile(r"_grpc_web_pb\.(?:js|d\.ts)$"), "protoc-gen-grpc-web", None),
    (re.compile(r"_grpc_pb\.(?:js|d\.ts)$"), "grpc-tools", None),
    (re.compile(r"_connect\.(?:ts|js)$"), "protoc-gen-connect-es", re.compile(r"protoc-gen-connect|@connectrpc/|@bufbuild/")),
    (re.compile(r"_pb\.(?:js|ts|d\.ts)$"), "protoc", None),
    (re.compile(r"\.grpc\.swift$"), "grpc-swift", None),
    (re.compile(r"\.pb\.swift$"), "swift-protobuf", None),
    (re.compile(r"\.pbgrpc\.dart$"), "protoc-gen-dart", None),
    (re.compile(r"\.pb(?:enum|json|server)?\.dart$"), "protoc-gen-dart", None),
    (re.compile(r"_services_pb\.rb$"), "grpc-tools", None),
    (re.compile(r"_pb\.rb$"), "protoc", None),
    (re.compile(r"\.grpc\.pb\.(?:h|cc)$"), "grpc_cpp_plugin", None),
    (re.compile(r"\.pb\.(?:h|cc)$"), "protoc", None),
)
_GENERATED_HEADER = re.compile(
    r"Code generated by (?P<go>protoc-gen-[\w-]{1,60}+|thriftgo|Kitex|[\w-]{0,40}twirp[\w-]{0,40})|"
    r"Generated by the (?P<compiler>protocol buffer compiler|gRPC [\w+#]{1,20} (?:protocol compiler )?plugin)|"
    r"@generated by (?P<es>protoc-gen-[\w-]{1,60}+)|(?P<java>by gRPC proto compiler)|Autogenerated by (?P<thrift>Thrift) Compiler"
)
# The services a generated file declares clients and servers for, by language.
_GENERATED_SERVICES = (
    re.compile(r"\btype[ \t]++(?P<service>\w{1,120}?)Client[ \t]++interface\b"),  # Go gRPC, Connect
    re.compile(r"\bfunc[ \t]++New(?P<service>\w{1,120}?)ProtobufClient\b"),  # Twirp
    re.compile(r"\bclass[ \t]++(?P<service>\w{1,120}?)Stub[ \t]*+\([ \t]*+object[ \t]*+\)"),  # Python
    re.compile(r"\bfinal[ \t]++class[ \t]++(?P<service>\w{1,120}?)Grpc\b"),  # Java
    re.compile(r"\bobject[ \t]++(?P<service>\w{1,120}?)GrpcKt\b"),  # Kotlin
    re.compile(r"\bpartial[ \t]++class[ \t]++(?P<service>\w{1,120}?)Client[ \t]*+:[ \t]*+grpc::ClientBase\b"),  # C#
    re.compile(r"\bprotocol[ \t]++(?P<service>\w{1,120}?)ClientProtocol\b"),  # Swift
    re.compile(r"\bclass[ \t]++(?P<service>\w{1,120}?)Client[ \t]++extends[ \t]++\$grpc\.Client\b"),  # Dart
    re.compile(r"\bexport[ \t]++class[ \t]++(?P<service>\w{1,120}?)Client[ \t]*+\{"),  # gRPC-Web typings
    re.compile(r"\.(?P<service>\w{1,120}?)Client[ \t]*+=\s*+function[ \t]*+\([ \t]*+hostname\b"),  # gRPC-Web
    re.compile(r"\bexports\.(?P<service>\w{1,120}?)Client[ \t]*+=[ \t]*+grpc\.makeGenericClientConstructor\b"),  # Node.js
    re.compile(r"\bexport[ \t]++const[ \t]++(?P<service>\w{1,120}+)[ \t]*+(?:=[ \t]*+\{\s*+typeName[ \t]*+:|:[ \t]*+"
               r"GenService\b)"),  # Connect-ES, Protobuf-ES
    re.compile(r"\bmodule[ \t]++(?P<service>\w{1,120}+)\s++class[ \t]++Service\b"),  # Ruby
    re.compile(r"\bservice_full_name\(\)\s*+\{\s*+return[ \t]*+\"(?:[\w.]{0,200}\.)?(?P<service>\w{1,120})\""),  # C++
)


def generated_by(relative: str, head: str) -> str:
    """The generator of a protoc plugin's or RPC compiler's output file, from its name or header; or ""."""
    name = PurePosixPath(relative.replace("\\", "/")).name
    header = _GENERATED_HEADER.search(head)
    for pattern, generator, marker in _GENERATED_NAMES:
        if pattern.search(name):
            if marker is None or header or marker.search(head):
                return generator
            break
    if header is None:
        return ""
    if header.group("java"):
        return "protoc-gen-grpc-java"
    if header.group("thrift"):
        return "Thrift compiler"
    return header.group("go") or header.group("es") or header.group("compiler")


def generated_services(text: str, generator: str) -> list[str]:
    """The services a generated file declares clients or servers for."""
    services = set()
    for pattern in _GENERATED_SERVICES:
        for match in pattern.finditer(text):
            service = match.group("service")
            if service.startswith(("Unimplemented", "Unsafe")):
                continue
            if generator in {"grpc-swift", "swift-protobuf"}:
                service = service.rsplit("_", 1)[-1]  # Helloworld_Greeter
            services.add(service.removesuffix("Promise"))
            if len(services) >= MAX_RPC_FACTS:
                return sorted(services)
    return sorted(services)


def code_rpc(text: str, extension: str) -> list[tuple[str, str, str, int]]:
    """(framework, role, service, line) of the RPC servers and clients a source file declares."""
    found = []
    lines = _Lines(text)
    imports: dict[int, bool] = {}
    for framework, role, pattern, extensions, marker in _RPC_CODE:
        if extension not in extensions:
            continue
        if marker is not None:
            if id(marker) not in imports:
                imports[id(marker)] = marker.search(text) is not None
            if not imports[id(marker)]:
                continue
        for match in pattern.finditer(text):
            service = match.groupdict().get("service") or ""
            if extension in _SWIFT:
                service = service.rsplit("_", 1)[-1]  # Helloworld_Greeter
            if service.lower() in _NOT_SERVICES:
                continue
            found.append((framework, role, service, lines.line(match.start())))
            if len(found) >= MAX_RPC_FACTS:
                return found
    if extension in _JS and _TRPC.search(text):
        for match in _TRPC_PROCEDURE.finditer(text):
            found.append(("tRPC", f"{match.group('kind')} procedure", match.group("name"), lines.line(match.start())))
            if len(found) >= MAX_RPC_FACTS:
                break
    return found


class RPCAnalyzer(Analyzer):
    """RPC services, methods, messages, frameworks and generated code, statically."""

    name = "api-rpc"
    limits = AnalyzerLimits(MAX_RPC_BYTES, "whole", {"evidence_lines": MAX_RPC_EVIDENCE},
                            outcome="UNKNOWN finding for an IDL file past the budget")
    domains = ("api_rpc",)
    languages = ("Protocol Buffers", "Thrift", "Avro IDL", "Python", "Go", "Java", "Kotlin", "Scala", "Groovy", "C#",
                 "C++", "C/C++ Header", "Rust", "JavaScript", "TypeScript", "Swift", "Dart", "Ruby", "PHP")
    _IDL = frozenset({".proto", ".thrift", ".avdl"})
    _CODE = _PY | _GO | _JVM | _CS | _CPP | _RUST | _JS | _SWIFT | _DART | _RUBY | _PHP

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and (record.extension in self._IDL or record.extension in self._CODE)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        idl = record.extension in self._IDL
        if over_limit(record.size_bytes, MAX_RPC_BYTES):
            if idl:
                return [Finding("api", f"RPC definition scan budget reached: {record.path}",
                                f"The file is larger than the {MAX_RPC_BYTES:,}-byte budget and was not read.",
                                confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
            # Generated code is often this large; its name says what wrote it without reading it.
            generator = generated_by(record.path, "")
            return self._generated(record, generator, []) if generator else []
        try:
            text = read_text_bounded(path, MAX_RPC_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, ValueError, SourceBudgetExceeded) as exc:
            if not idl:
                return []
            return [Finding("api", f"RPC definition unavailable: {record.path}", describe_error(exc),
                            confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
        if record.extension == ".proto":
            return self._proto(record, parse_proto(text))
        if idl:
            return self._idl(record, idl_services(text, record.extension))
        generator = generated_by(record.path, text[:_GENERATED_HEAD])
        if generator:
            return self._generated(record, generator, generated_services(text, generator))
        if not _RPC_HINT.search(text):
            return []
        return self._code(record, code_rpc(text, record.extension))

    def _proto(self, record: FileRecord, document: ProtoFile) -> list[Finding]:
        prefix = f"{document.package}." if document.package else ""
        messages = [message for message in document.messages if message.kind == "message"]
        enums = [message for message in document.messages if message.kind == "enum"]
        fields = sum(len(message.fields) for message in messages)
        version = f"edition {document.edition}" if document.edition else document.syntax or "proto2 (no syntax statement)"
        options = {name: value for name, value in document.options.items() if name in _FILE_OPTIONS}
        code_facts.emit_fact("rpc_schema", document.package or record.path, messages=len(messages), enums=len(enums),
                             services=len(document.services), syntax=version)
        findings = [Finding(
            "api", f"Protocol Buffers schema: {record.path}",
            f"{version}, package {document.package or '(none)'}: {len(messages)} message(s) with {fields} field(s), "
            f"{len(enums)} enum(s), {len(document.imports)} import(s)"
            + (", options " + ", ".join(f"{name}={value}" for name, value in sorted(options.items())) if options else "")
            + ".",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"{record.path}:{message.line} {message.kind} {message.name}"
                      + (f" ({len(message.fields)} {'value' if message.kind == 'enum' else 'field'}(s))" if message.fields else "")
                      for message in document.messages[:MAX_RPC_EVIDENCE]] or [record.path],
        )]
        if not document.services:
            return findings
        evidence = []
        emitted = 0
        for service in document.services:
            code_facts.emit_fact("rpc_service", f"{prefix}{service.name}", framework="gRPC", line=service.line,
                                 methods=[method.name for method in service.methods[:200]])
            for method in service.methods:
                if emitted < MAX_RPC_FACTS:
                    emitted += 1
                    code_facts.emit_fact("rpc_method", f"{prefix}{service.name}/{method.name}", request=method.request,
                                         response=method.response, streaming=method.streaming, line=method.line,
                                         http=[f"{verb} {route}" for verb, route in method.http])
                if len(evidence) < MAX_RPC_EVIDENCE:
                    evidence.append(
                        f"{record.path}:{method.line} {service.name}.{method.name}("
                        f"{'stream ' if method.client_streaming else ''}{method.request}) returns ("
                        f"{'stream ' if method.server_streaming else ''}{method.response})"
                        + "".join(f" {verb} {route}" for verb, route in method.http))
        kinds = Counter(method.streaming for service in document.services for method in service.methods)
        mapped = sum(1 for service in document.services for method in service.methods if method.http)
        findings.append(Finding(
            "api", f"gRPC services: {record.path}",
            f"{len(document.services)} service(s) ({', '.join(service.name for service in document.services[:12])}) "
            f"with {sum(kinds.values())} method(s)"
            + (": " + ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items(), key=lambda item: (-item[1], item[0])))
               if kinds else "")
            + (f"; {mapped} mapped to HTTP routes by google.api.http (gRPC-Gateway or transcoding)" if mapped else "")
            + ".",
            confidence="CONFIRMED", analyzer=self.name, evidence=evidence or [record.path],
        ))
        return findings

    def _idl(self, record: FileRecord, services: list[tuple[str, list[str], int]]) -> list[Finding]:
        if not services:
            return []
        thrift = record.extension == ".thrift"
        framework = "Apache Thrift" if thrift else "Avro IPC"
        for name, methods, line in services:
            code_facts.emit_fact("rpc_service", name, framework=framework, line=line, methods=methods[:200])
        count = sum(len(methods) for _, methods, _ in services)
        return [Finding(
            "api", f"{'Apache Thrift services' if thrift else 'Avro protocols'}: {record.path}",
            f"{len(services)} {'service' if thrift else 'protocol'}(s) with {count} "
            f"{'method' if thrift else 'message'}(s).",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"{record.path}:{line} {name}: {', '.join(methods[:20]) or '(none)'}"
                      for name, methods, line in services[:MAX_RPC_EVIDENCE]],
        )]

    def _generated(self, record: FileRecord, generator: str, services: list[str]) -> list[Finding]:
        code_facts.emit_fact("rpc_generated", generator, services=services[:200])
        return [Finding(
            "api", f"Generated RPC code: {record.path}",
            f"Written by {generator}" + (f", for service(s) {', '.join(services[:12])}" if services else "")
            + ". Generated code is regenerated from its definition, not edited.",
            confidence="CONFIRMED", analyzer=self.name, evidence=[record.path],
        )]

    def _code(self, record: FileRecord, found: list[tuple[str, str, str, int]]) -> list[Finding]:
        unique = sorted(set(found), key=lambda item: (item[3], item[0], item[1], item[2]))
        if not unique:
            return []
        for framework, role, service, line in unique:
            kind = "rpc_server" if role == "server" else "rpc_client" if role == "client" else "rpc_procedure"
            code_facts.emit_fact(kind, service or framework, framework=framework, line=line, role=role, service=service)
        frameworks = sorted({framework for framework, _, _, _ in unique})
        roles = Counter(role.rsplit(" ", 1)[-1] for _, role, _, _ in unique)
        return [Finding(
            "api", f"RPC servers and clients: {record.path}",
            f"{', '.join(frameworks)}: " + ", ".join(f"{count} {role}(s)" for role, count in sorted(roles.items())) + ".",
            confidence="INFERRED", analyzer=self.name,
            evidence=[f"{record.path}:{line} {framework} {role}{' ' + service if service else ''}"
                      for framework, role, service, line in unique[:MAX_RPC_EVIDENCE]],
        )]
