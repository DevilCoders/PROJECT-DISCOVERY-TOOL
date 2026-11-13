"""Network call sites in code: the sockets and servers a program opens (listen, bind, accept),
the connections it makes (connect, dial) and the sockets it creates, by language API.

This is what code does, as against what configuration declares: a port in a YAML file or a
``PORT = 8080`` constant is a declaration (the network-indicators analyzer's), a
``net.Listen("tcp", ":8080")`` call is a call site. Python call sites come from its syntax
tree with imports resolved, so ``from socket import create_server as serve`` is still found;
the other languages from the shared structural lexer (receiver and name of each call), so
they are INFERRED. Literal addresses and ports among the arguments are reported; an explicit
bind to every interface (0.0.0.0, ::) is a finding of its own.
"""
from __future__ import annotations

import ast
import ipaddress
import re
from pathlib import Path

from ...core.limits import AnalyzerLimits, limit_reached, over_limit
from ...core.source_utils import SourceBudgetExceeded, describe_error, read_text_bounded
from ...intelligence import facts as code_facts
from ...intelligence.model import MAX_MODEL_BYTES, FileModel, model_for, supports_language
from ...intelligence.model.lexical import LEXICAL_LANGUAGES
from ...models import FileRecord, Finding
from ..base import Analyzer, oversize_finding

_MAX_SITES = 1_000  # call sites kept per file
_MAX_EVIDENCE = 100
_ALL_INTERFACES = frozenset({"0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0"})
_ROLE_TITLES = {
    "listen": ("Network listeners opened in code", "open a listening socket or server"),
    "connect": ("Outbound network connections opened in code", "open a connection to another host"),
    "socket": ("Sockets created in code", "create a socket"),
}

# Python: resolved call targets (imports followed) -> role.
_PYTHON = {
    "socket.socket": "socket", "socket.socketpair": "socket", "socket.fromfd": "socket",
    "socket.create_server": "listen", "socket.create_connection": "connect",
    "asyncio.start_server": "listen", "asyncio.start_unix_server": "listen",
    "asyncio.open_connection": "connect", "asyncio.open_unix_connection": "connect",
    "socketserver.TCPServer": "listen", "socketserver.UDPServer": "listen",
    "socketserver.ThreadingTCPServer": "listen", "socketserver.ThreadingUDPServer": "listen",
    "socketserver.ForkingTCPServer": "listen", "socketserver.UnixStreamServer": "listen",
    "http.server.HTTPServer": "listen", "http.server.ThreadingHTTPServer": "listen",
    "wsgiref.simple_server.make_server": "listen", "xmlrpc.server.SimpleXMLRPCServer": "listen",
    "uvicorn.run": "listen", "aiohttp.web.run_app": "listen", "websockets.serve": "listen",
    "websockets.connect": "connect", "http.client.HTTPConnection": "connect",
    "http.client.HTTPSConnection": "connect", "ftplib.FTP": "connect", "smtplib.SMTP": "connect",
    "smtplib.SMTP_SSL": "connect", "telnetlib.Telnet": "connect", "poplib.POP3": "connect",
    "imaplib.IMAP4": "connect",
}
# Methods of objects these calls return.
_PYTHON_METHODS = {
    "socket": {"bind": "listen", "listen": "listen", "accept": "listen", "connect": "connect",
               "connect_ex": "connect"},
    "flask": {"run": "listen"},
}
_PYTHON_FACTORIES = {"socket.socket": "socket", "socket.create_server": "socket",
                     "socket.create_connection": "socket", "flask.Flask": "flask"}

# Lexical languages: (receiver, call name) -> role. A receiver of "" is a free function,
# "new" a constructor, "*" any receiver.
_GO = {("net", "Listen"): "listen", ("net", "ListenPacket"): "listen", ("net", "ListenTCP"): "listen",
       ("net", "ListenUDP"): "listen", ("net", "ListenUnix"): "listen", ("http", "ListenAndServe"): "listen",
       ("http", "ListenAndServeTLS"): "listen", ("tls", "Listen"): "listen", ("net", "Dial"): "connect",
       ("net", "DialTimeout"): "connect", ("net", "DialTCP"): "connect", ("net", "DialUDP"): "connect",
       ("tls", "Dial"): "connect", ("grpc", "Dial"): "connect", ("grpc", "DialContext"): "connect",
       ("grpc", "NewClient"): "connect"}
_JS_SERVER_MODULES = frozenset({"http", "https", "http2", "net", "tls", "express", "koa", "fastify", "@hapi",
                                "hapi", "restify", "connect", "socket.io", "ws", "@nestjs", "next"})
_JS = {("net", "createServer"): "listen", ("http", "createServer"): "listen", ("https", "createServer"): "listen",
       ("http2", "createServer"): "listen", ("http2", "createSecureServer"): "listen",
       ("tls", "createServer"): "listen", ("new", "WebSocketServer"): "listen", ("net", "connect"): "connect",
       ("net", "createConnection"): "connect", ("tls", "connect"): "connect", ("http2", "connect"): "connect",
       ("new", "WebSocket"): "connect", ("dgram", "createSocket"): "socket"}
_JVM = {("new", "ServerSocket"): "listen", ("ServerSocketChannel", "open"): "listen",
        ("AsynchronousServerSocketChannel", "open"): "listen", ("HttpServer", "create"): "listen",
        ("new", "Socket"): "connect", ("SocketChannel", "open"): "connect",
        ("AsynchronousSocketChannel", "open"): "connect", ("new", "DatagramSocket"): "socket",
        ("new", "MulticastSocket"): "socket"}
_KOTLIN = {**_JVM, **{("", name): role for (receiver, name), role in _JVM.items() if receiver == "new"}}
_CSHARP = {("new", "TcpListener"): "listen", ("new", "HttpListener"): "listen", ("new", "TcpClient"): "connect",
           ("new", "UdpClient"): "socket", ("new", "Socket"): "socket"}
_CSHARP_METHODS = {"Bind": "listen", "Listen": "listen", "Accept": "listen", "AcceptAsync": "listen",
                   "AcceptTcpClient": "listen", "AcceptSocket": "listen", "Connect": "connect",
                   "ConnectAsync": "connect"}
_C = {("", "socket"): "socket", ("", "bind"): "listen", ("", "listen"): "listen", ("", "accept"): "listen",
      ("", "accept4"): "listen", ("", "connect"): "connect", ("", "WSASocket"): "socket",
      ("", "WSASocketA"): "socket", ("", "WSASocketW"): "socket", ("", "WSAConnect"): "connect",
      ("", "WSAAccept"): "listen"}
_RUST = {("TcpListener", "bind"): "listen", ("UnixListener", "bind"): "listen", ("TcpStream", "connect"): "connect",
         ("UnixStream", "connect"): "connect", ("UdpSocket", "bind"): "socket", ("TcpSocket", "new_v4"): "socket",
         ("TcpSocket", "new_v6"): "socket"}
_PHP = {("", "socket_create"): "socket", ("", "socket_bind"): "listen", ("", "socket_listen"): "listen",
        ("", "socket_accept"): "listen", ("", "socket_connect"): "connect", ("", "stream_socket_server"): "listen",
        ("", "stream_socket_client"): "connect", ("", "fsockopen"): "connect", ("", "pfsockopen"): "connect"}
_SWIFT = {("", "NWListener"): "listen", ("", "NWConnection"): "connect"}
_DART = {("ServerSocket", "bind"): "listen", ("HttpServer", "bind"): "listen", ("Socket", "connect"): "connect",
         ("WebSocket", "connect"): "connect", ("RawDatagramSocket", "bind"): "socket"}
_FAMILIES = {"go": _GO, "js": _JS, "java": _JVM, "kotlin": _KOTLIN, "scala": _JVM, "groovy": _JVM,
             "csharp": _CSHARP, "c": _C, "cpp": _C, "rust": _RUST, "php": _PHP, "swift": _SWIFT, "dart": _DART}
# The socket headers a C or C++ file includes before its bind/connect are the socket calls
# (Qt's QObject::connect is not), and C# needs System.Net.Sockets for the socket methods.
_C_SOCKET_HEADERS = re.compile(r"^[ \t]*#[ \t]*include[ \t]*<(?:sys/socket|winsock2?|netinet/in|arpa/inet|ws2tcpip)\.h>",
                               re.MULTILINE)
_CSHARP_SOCKETS = re.compile(r"^[ \t]*using[ \t]+System\.Net(?:\.Sockets)?[ \t]*;", re.MULTILINE)
_PORT = re.compile(r"(?<![\w.])\d{1,5}(?![\w.])")
# Socket-level listen and accept take a backlog or nothing, never an address.
_NO_ADDRESS = frozenset({"listen", "accept", "accept4", "WSAAccept", "socket_listen", "socket_accept", "Listen",
                         "Accept", "AcceptAsync", "AcceptTcpClient", "AcceptSocket"})
# Server factories whose port the .listen(...) called on the server names (Node).
_FACTORY_LISTENERS = frozenset({"createServer", "createSecureServer"})
_HOST_PORT = re.compile(r"^(?:\[([0-9A-Fa-f:.]+)\]|([\w.-]*)):(\d{1,5})$")
# tcp://db:5432, wss://stream.example.com/feed: the host and the port, if the URL gives one.
_URL_ADDRESS = re.compile(r"(?i)(?:tcp|udp|tls|ssl|wss?|https?)://(?:\[([0-9a-f:.]{2,45})\]|([\w.-]{1,253}))"
                          r"(?::(\d{1,5}))?(?=[/?#]|$)")
_LABEL = re.compile(r"[\w-]{1,63}")
_SERVICE_NAME = re.compile(r"[A-Za-z][\w-]{0,62}")
# Network names Go and others pass before the address: never a host.
_NETWORK_WORDS = frozenset({"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix", "unixgram", "unixpacket",
                            "ip", "ip4", "ip6"})

# Ruby is no brace language: its socket classes are matched in the text.
_RUBY = re.compile(r"(?<![\w:])(TCPServer|TCPSocket|UDPSocket|UNIXServer|UNIXSocket)\.(?:new|open)\b|"
                   r"(?<![\w:])Socket\.(tcp_server_loop|tcp)\b")
_RUBY_ROLES = {"TCPServer": "listen", "UNIXServer": "listen", "tcp_server_loop": "listen", "TCPSocket": "connect",
               "UNIXSocket": "connect", "tcp": "connect", "UDPSocket": "socket"}


def _host_port(host: str, port: str | int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _plausible_host(value: str) -> bool:
    """An IP address, an every-interface address, localhost or a dotted host name."""
    if value in _ALL_INTERFACES or value == "localhost":
        return True
    if ":" in value:
        try:
            ipaddress.IPv6Address(value.strip("[]").split("%", 1)[0])
        except ValueError:
            return False
        return True
    labels = value.removesuffix(".").split(".")
    return len(labels) > 1 and len(value) <= 253 and all(_LABEL.fullmatch(label) for label in labels)


def _address(strings: list[str], numbers: list[int]) -> str | None:
    """A literal address among a call's arguments: "host:port", "host" or ":port". A URL
    (``tcp://db:5432``) gives its host and port; a single-label name next to a port
    (``("db", 5432)``) is a service name, as Compose and Kubernetes DNS resolve them."""
    for value in strings:
        match = _HOST_PORT.match(value.strip())
        if match and 0 < int(match.group(3)) < 65536:
            host = match.group(1) if match.group(1) is not None else match.group(2)
            return _host_port(host, match.group(3)) if host else f":{match.group(3)}"
        url = _URL_ADDRESS.match(value.strip())
        if url:
            host = url.group(1) or url.group(2)
            port = url.group(3)
            return _host_port(host, port) if port and 0 < int(port) < 65536 else host
    hosts = [value for value in strings if value and _plausible_host(value)]
    ports = [number for number in numbers if 0 < number < 65536]
    if ports and not hosts:
        hosts = [value for value in strings
                 if _SERVICE_NAME.fullmatch(value) and value.lower() not in _NETWORK_WORDS]
    if hosts and ports:
        return _host_port(hosts[0].strip("[]"), ports[0])
    if ports:
        return f":{ports[0]}"
    return hosts[0] if hosts else None


def _binds_all(address: str | None) -> bool:
    if not address:
        return False
    host = address.rsplit(":", 1)[0] if not address.startswith("[") else address[1:address.find("]")]
    return host in _ALL_INTERFACES


class _PythonSites(ast.NodeVisitor):
    """Python call sites: calls resolved through the file's imports, and methods of the objects
    the socket and Flask factories return (names they are assigned to in the file)."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.objects: dict[str, str] = {}  # name -> factory kind
        self.sites: list[tuple[int, str, str, str | None]] = []  # (line, role, api, address)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and not node.level:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def _resolve(self, node: ast.AST) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return ""
        head = self.aliases.get(node.id, node.id)
        return ".".join([head, *reversed(parts)])

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            kind = _PYTHON_FACTORIES.get(self._resolve(node.value.func))
            for target in node.targets:
                if kind and isinstance(target, ast.Name):
                    self.objects[target.id] = kind
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name):
                kind = _PYTHON_FACTORIES.get(self._resolve(item.context_expr.func))
                if kind:
                    self.objects[item.optional_vars.id] = kind
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Call(self, node: ast.Call) -> None:
        target = self._resolve(node.func)
        role = _PYTHON.get(target)
        api = target
        if role is None and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            kind = self.objects.get(node.func.value.id)
            role = _PYTHON_METHODS.get(kind or "", {}).get(node.func.attr)
            api = f"{node.func.value.id}.{node.func.attr}"
        if role is not None and len(self.sites) < _MAX_SITES:
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            self.sites.append((node.lineno, role, api, None if method in _NO_ADDRESS else _python_address(node)))
        self.generic_visit(node)


def _constants(node: ast.AST) -> tuple[list[str], list[int]]:
    strings, numbers = [], []
    for item in (node.elts if isinstance(node, ast.Tuple) else [node]):
        if isinstance(item, ast.Constant):
            if isinstance(item.value, str):
                strings.append(item.value)
            elif isinstance(item.value, int) and not isinstance(item.value, bool):
                numbers.append(item.value)
    return strings, numbers


def _python_address(node: ast.Call) -> str | None:
    strings, numbers = [], []
    for argument in node.args[:3]:
        found = _constants(argument)
        strings += found[0]
        numbers += found[1]
    for keyword in node.keywords:
        if keyword.arg in {"host", "port", "address", "addr", "server_address"}:
            found = _constants(keyword.value)
            strings += found[0]
            numbers += found[1]
    if strings == [""] and numbers:  # bind(("", port)): every interface, in Python's spelling
        return f"0.0.0.0:{numbers[0]}"
    return _address([value for value in strings if value], numbers)


def _lexical_sites(model: FileModel, family: str) -> list[tuple[int, str, str, str | None]]:
    apis = _FAMILIES.get(family)
    if apis is None:
        return []
    if family in {"c", "cpp"} and not _C_SOCKET_HEADERS.search(model.text):
        return []
    csharp_methods = family == "csharp" and _CSHARP_SOCKETS.search(model.text) is not None
    # app.listen(PORT) / server.listen(port): a server's listen when the file imports a server
    # module, or when a literal port is given.
    js_server = family == "js" and any(
        item.target.removeprefix("node:").split("/")[0] in _JS_SERVER_MODULES for item in model.imports)
    sites = []
    for call in model.calls:
        role = apis.get((call.receiver, call.callee))
        api = f"{call.receiver}.{call.callee}" if call.receiver not in ("", "new") else (
            f"new {call.callee}" if call.receiver == "new" else call.callee)
        if role is None and csharp_methods and call.receiver not in ("", "new"):
            role = _CSHARP_METHODS.get(call.callee)
        generic_listen = role is None and family == "js" and call.callee == "listen" and call.receiver not in ("", "new")
        if generic_listen:
            role = "listen"
        if role is None or len(sites) >= _MAX_SITES:
            continue
        address = None if call.callee in _NO_ADDRESS and family != "go" and not generic_listen else (
            _call_address(model, call.offset, call.callee))
        if generic_listen and not js_server and (address is None or not address.rsplit(":", 1)[-1].isdigit()):
            continue
        sites.append((call.line, role, api, address))
    return sites


def _call_address(model: FileModel, offset: int, name: str) -> str | None:
    """The literal address among a lexical call's arguments, from the text between its parentheses."""
    if offset < 0:
        return None
    opening = model.clean.find("(", offset + len(name))
    closing = model.parens.get(opening) if opening >= 0 else None
    if closing is None or closing - opening > 2000:
        return None
    strings = [model.string_value(span) for span in model.strings_between(opening, closing)]
    numbers = [int(value) for value in _PORT.findall(model.clean[opening + 1:closing])]
    return _address(strings, numbers)


def _ruby_sites(text: str) -> list[tuple[int, str, str, str | None]]:
    sites = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in _RUBY.finditer(line):
            name = match.group(1) or match.group(2)
            rest = line[match.end():match.end() + 200]
            strings = re.findall(r"""["']([^"']{0,253})["']""", rest)
            numbers = [int(value) for value in _PORT.findall(re.sub(r"""(["'])[^"']*\1""", "", rest))]
            sites.append((number, _RUBY_ROLES[name], match.group(0), _address(strings, numbers)))
            if len(sites) >= _MAX_SITES:
                return sites
    return sites


def _record_facts(sites: list[tuple[int, str, str, str | None]], language: str | None) -> None:
    """Facts for the network service map the code index builds: the port each listener uses
    ("?" when its call names none) and the address each connection goes to."""
    for line, role, api, address in sites:
        if role == "listen":
            method = api.rsplit(".", 1)[-1]
            if address is None and (method in _FACTORY_LISTENERS or (language != "Go" and method in _NO_ADDRESS)):
                continue  # listen(backlog), accept(), createServer(handler): another call names the address
            port = address.rsplit(":", 1)[-1] if address and ":" in address else ""
            code_facts.emit_fact("net_listen", port if port.isdigit() else "?", api=api, line=line,
                                 address=address or "")
        elif role == "connect" and address:
            code_facts.emit_fact("net_connect", address, api=api, line=line)


class SocketCallSiteAnalyzer(Analyzer):
    """The sockets, servers and connections code opens, with literal addresses."""

    name = "network-sockets"
    limits = AnalyzerLimits(MAX_MODEL_BYTES, "model", {"call_sites": _MAX_SITES, "evidence_lines": _MAX_EVIDENCE},
                            outcome="Files past the code model budget are not modelled (code-index reports them; an "
                                    "oversized Ruby file is an UNKNOWN finding); call sites past the per-file limit "
                                    "are an UNKNOWN finding")
    domains = ("networking",)
    languages = ("Python", "Go", "JavaScript", "TypeScript", "Java", "Kotlin", "Scala", "Groovy", "C#", "C", "C++",
                 "Rust", "PHP", "Swift", "Dart", "Ruby")

    def supports(self, record: FileRecord) -> bool:
        return (record.error is None and record.content_skipped_reason is None
                and (record.language == "Ruby" or supports_language(record.language)))

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.language == "Ruby":
            if over_limit(record.size_bytes, MAX_MODEL_BYTES):
                return [oversize_finding(self, record, "network", "Socket call site", MAX_MODEL_BYTES)]
            try:
                text = read_text_bounded(path, MAX_MODEL_BYTES, errors="replace",
                                         expected_identity=record.analysis_identity)
            except (OSError, SourceBudgetExceeded) as exc:
                return [Finding("network", f"Socket call sites unavailable: {record.path}", describe_error(exc),
                                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW")]
            sites, confidence = _ruby_sites(text), "INFERRED"
        else:
            model = model_for(path, record)
            if model is None:
                return []
            if model.language == "Python":
                if not isinstance(model.tree, ast.AST):
                    return []
                visitor = _PythonSites()
                visitor.visit(model.tree)
                sites, confidence = visitor.sites, "CONFIRMED"
            else:
                sites, confidence = _lexical_sites(model, LEXICAL_LANGUAGES.get(model.language, "")), "INFERRED"
        _record_facts(sites, record.language)
        findings = []
        for role, (title, verb) in _ROLE_TITLES.items():
            matched = [site for site in sites if site[1] == role]
            if not matched:
                continue
            findings.append(Finding(
                "network", f"{title}: {record.path}",
                f"{len(matched):,} call site(s) {verb} ({', '.join(sorted({site[2] for site in matched})[:10])}). "
                "These are call sites in code, not declarations: ports and hosts in configuration are reported "
                "as network indicators. Nothing was connected to.",
                confidence=confidence,
                evidence=[f"{record.path}:{line} ({api}{' ' + address if address else ''})"
                          for line, _, api, address in matched[:_MAX_EVIDENCE]],
                analyzer=self.name,
            ))
        exposed = [site for site in sites if site[1] == "listen" and _binds_all(site[3])]
        if exposed:
            findings.append(Finding(
                "security", f"Listeners bound to every network interface: {record.path}",
                f"{len(exposed):,} listener(s) bind 0.0.0.0 or :: explicitly, so they accept connections from "
                "every network the host is on, not only from localhost. Bind a specific interface unless the "
                "service is meant to be reachable from outside (in a container, the published port decides).",
                confidence=confidence,
                evidence=[f"{record.path}:{line} ({api} {address})" for line, _, api, address in exposed[:_MAX_EVIDENCE]],
                analyzer=self.name, severity="MEDIUM",
                recommendation="Bind 127.0.0.1 or a specific interface for services not meant for other hosts.",
            ))
        if len(sites) >= _MAX_SITES:
            limit_reached("call_sites", _MAX_SITES)
            findings.append(Finding(
                "network", f"Socket call site limit reached: {record.path}",
                f"The first {_MAX_SITES:,} network call sites were listed; later ones were not.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW",
            ))
        return findings
