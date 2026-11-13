"""Socket call sites in code: listeners, outbound connections and socket creation per language,
literal addresses, every-interface binds, and declarations that are not call sites."""
from __future__ import annotations

from pathlib import Path

import pytest

from project_discovery.analyzers.environment.sockets import SocketCallSiteAnalyzer
from project_discovery.models import FileRecord


def _sites(tmp_path: Path, name: str, language: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, path.suffix, language, file_type="text")
    analyzer = SocketCallSiteAnalyzer()
    assert analyzer.supports(record)
    return {finding.title.split(":", 1)[0]: finding for finding in analyzer.analyze(path, record)}


def test_python_sockets_servers_and_clients_are_resolved_through_imports(tmp_path: Path):
    findings = _sites(tmp_path, "server.py", "Python", (
        "import socket\n"
        "from socket import create_connection as dial\n"
        "import asyncio, uvicorn\n"
        "from flask import Flask\n"
        "from http.server import HTTPServer\n"
        "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "sock.bind(('0.0.0.0', 8080))\n"
        "sock.listen(5)\n"
        "conn, _ = sock.accept()\n"
        "dial(('db.internal', 5432))\n"
        "asyncio.start_server(handle, '127.0.0.1', 8888)\n"
        "uvicorn.run(app, host='0.0.0.0', port=8000)\n"
        "app = Flask(__name__)\n"
        "app.run(host='::', port=5000)\n"
        "HTTPServer(('', 9000), Handler)\n"
        "db.connect()\n"  # not a socket: no finding
    ))
    listeners = findings["Network listeners opened in code"]
    assert listeners.confidence == "CONFIRMED"
    assert listeners.evidence == [
        "server.py:7 (sock.bind 0.0.0.0:8080)", "server.py:8 (sock.listen)", "server.py:9 (sock.accept)",
        "server.py:11 (asyncio.start_server 127.0.0.1:8888)", "server.py:12 (uvicorn.run 0.0.0.0:8000)",
        "server.py:14 (app.run [::]:5000)", "server.py:15 (http.server.HTTPServer 0.0.0.0:9000)"]
    assert findings["Outbound network connections opened in code"].evidence == [
        "server.py:10 (socket.create_connection db.internal:5432)"]
    assert findings["Sockets created in code"].evidence == ["server.py:6 (socket.socket)"]
    exposed = findings["Listeners bound to every network interface"]
    assert exposed.severity == "MEDIUM" and len(exposed.evidence) == 4  # 0.0.0.0 twice, ::, ("", port)


@pytest.mark.parametrize(("name", "language", "source", "listen", "connect"), [
    ("main.go", "Go", 'package main\nimport ("net"; "net/http")\nfunc main() {\n'
     '  ln, _ := net.Listen("tcp", ":8080")\n  http.ListenAndServe("0.0.0.0:9090", nil)\n'
     '  c, _ := net.Dial("tcp", "api.example.com:443")\n}\n',
     ["main.go:4 (net.Listen :8080)", "main.go:5 (http.ListenAndServe 0.0.0.0:9090)"],
     ["main.go:6 (net.Dial api.example.com:443)"]),
    ("server.js", "JavaScript", 'const express = require("express");\nconst net = require("net");\n'
     'const app = express();\napp.listen(PORT);\nnet.createServer(handler).listen(4000, "0.0.0.0");\n'
     'const socket = new WebSocket("wss://stream.example.com/feed");\nemitter.on("x", () => {});\n',
     ["server.js:4 (app.listen)", "server.js:5 (net.createServer)", "server.js:5 (<expression>.listen 0.0.0.0:4000)"],
     ["server.js:6 (new WebSocket)"]),
    ("Server.java", "Java", 'import java.net.*;\nclass Server {\n  void run() throws Exception {\n'
     '    ServerSocket server = new ServerSocket(8443);\n    Socket client = new Socket("db.example.com", 5432);\n'
     '  }\n}\n',
     ["Server.java:4 (new ServerSocket :8443)"], ["Server.java:5 (new Socket db.example.com:5432)"]),
    ("net.c", "C", '#include <sys/socket.h>\n#include <netinet/in.h>\nint main(void) {\n'
     '  int fd = socket(AF_INET, SOCK_STREAM, 0);\n  bind(fd, (struct sockaddr *)&addr, sizeof(addr));\n'
     '  listen(fd, 16);\n  int c = accept(fd, 0, 0);\n  connect(fd, (struct sockaddr *)&peer, sizeof(peer));\n'
     '  return 0;\n}\n',
     ["net.c:5 (bind)", "net.c:6 (listen)", "net.c:7 (accept)"], ["net.c:8 (connect)"]),
    ("main.rs", "Rust", 'use std::net::{TcpListener, TcpStream};\nfn main() {\n'
     '    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();\n'
     '    let stream = TcpStream::connect("example.com:80").unwrap();\n}\n',
     ["main.rs:3 (TcpListener.bind 127.0.0.1:7878)"], ["main.rs:4 (TcpStream.connect example.com:80)"]),
    ("Server.cs", "C#", 'using System.Net;\nusing System.Net.Sockets;\nclass S {\n  void Run() {\n'
     '    var listener = new TcpListener(IPAddress.Any, 5000);\n    listener.Start();\n'
     '    var client = new TcpClient("mail.example.com", 25);\n    socket.Connect(endpoint);\n  }\n}\n',
     ["Server.cs:5 (new TcpListener :5000)"],
     ["Server.cs:7 (new TcpClient mail.example.com:25)", "Server.cs:8 (socket.Connect)"]),
    ("server.php", "PHP", '<?php\n$s = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);\nsocket_bind($s, "0.0.0.0", 1337);\n'
     '$c = stream_socket_client("tcp://example.com:80");\n',
     ["server.php:3 (socket_bind 0.0.0.0:1337)"], ["server.php:4 (stream_socket_client)"]),
    ("server.rb", "Ruby", 'require "socket"\nserver = TCPServer.new("0.0.0.0", 2000)\nclient = TCPSocket.new("example.com", 80)\n',
     ["server.rb:2 (TCPServer.new 0.0.0.0:2000)"], ["server.rb:3 (TCPSocket.new example.com:80)"]),
])
def test_call_sites_in_other_languages(tmp_path: Path, name, language, source, listen, connect):
    findings = _sites(tmp_path, name, language, source)
    assert findings["Network listeners opened in code"].evidence == listen
    assert findings["Network listeners opened in code"].confidence == "INFERRED"
    assert findings["Outbound network connections opened in code"].evidence == connect


def test_names_that_are_not_socket_calls_are_not_call_sites(tmp_path: Path):
    # Qt's connect without a socket header, a C# Connect without System.Net, and a JS listen
    # without a server module or a literal port.
    assert _sites(tmp_path, "window.cpp", "C++", "#include <QObject>\nvoid f() { connect(a, SIGNAL(x()), b, SLOT(y())); }\n") == {}
    assert _sites(tmp_path, "Db.cs", "C#", "class D { void F() { db.Connect(); } }\n") == {}
    assert _sites(tmp_path, "events.js", "JavaScript", "bus.listen(handler);\n") == {}


def test_declarations_in_configuration_are_not_call_sites(tmp_path: Path):
    findings = _sites(tmp_path, "settings.py", "Python", "PORT = 8080\nHOST = '0.0.0.0'\nBIND = ('0.0.0.0', 8080)\n")
    assert findings == {}  # the network-indicators analyzer reports these as declarations
