"""Network discovery is passive: a scan resolves no name, opens no connection, binds no port
and runs no network tool.

Two checks hold this in place. Statically, no module of the package imports a network client,
a resolver or the subprocess module, outside the few that need one for another job (named in
ALLOWED with the reason). At run time, an audit hook watches a whole scan of a project full of
URLs, host names, addresses, ports, deployment files, socket code, remote schema references
and external DTDs, and fails on any socket, name lookup, HTTP, FTP, mail or process event.
"""
import ast
import io
import json
import sys
import threading
import zipfile
from pathlib import Path

import project_discovery
from project_discovery.cli import run_scan

PACKAGE = Path(project_discovery.__file__).parent
NETWORK_MODULES = frozenset({
    "socket", "ssl", "socketserver", "http.client", "http.server", "urllib.request", "urllib3", "requests",
    "httpx", "aiohttp", "websocket", "websockets", "ftplib", "smtplib", "poplib", "imaplib", "nntplib",
    "telnetlib", "xmlrpc.client", "xmlrpc.server", "dns", "paramiko", "pycurl", "subprocess",
    "asyncio.subprocess",
})
RESOLVERS = frozenset({"getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo",
                       "create_connection", "urlopen"})
# Modules that may use these, by path prefix, with the names they may use and why.
ALLOWED = {
    "online/": (NETWORK_MODULES | RESOLVERS, "Online Mode: the fetch of a repository URL and the advisory lookups "
                                            "of --vuln-online, only when a scan asks for them"),
    "plugins/isolation.py": ({"subprocess"}, "starts the isolated plugin host process"),
    "plugins/sandbox.py": ({"socket", "subprocess", "create_connection"},
                           "starts sandboxed plugin hosts and checks the sandbox denies network access: a loopback "
                           "listener PDT holds and the unrouted RFC 5737 address 192.0.2.1"),
    "plugins/appcontainer.py": ({"socket", "subprocess"}, "the Windows AppContainer half of the same check"),
}

# Audit events of every way Python reaches the network or starts a process.
NETWORK_EVENTS = frozenset({
    "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo", "urllib.Request",
    "http.client.connect", "ftplib.connect", "smtplib.connect", "poplib.connect", "imaplib.open",
    "nntplib.connect", "telnetlib.Telnet.open", "subprocess.Popen", "os.system", "os.exec", "os.spawn",
    "os.posix_spawn", "os.startfile",
})
_recording = threading.Event()
_events: list[tuple[str, str]] = []
_hooked: list[bool] = []


def _audit(event: str, args: tuple) -> None:
    if _recording.is_set() and event in NETWORK_EVENTS:
        _events.append((event, repr(args)[:300]))


def _uses(tree: ast.AST):
    """(line, name) of each network module imported and each resolver named."""
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names = [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
        for name in names:
            for module in NETWORK_MODULES:
                if name == module or name.startswith(module + "."):
                    yield node.lineno, module
        if isinstance(node, ast.Attribute) and node.attr in RESOLVERS:
            yield node.lineno, node.attr
        elif isinstance(node, ast.Name) and node.id in RESOLVERS:
            yield node.lineno, node.id


def test_no_module_on_the_scan_path_imports_a_network_client():
    offending = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        allowed = next((names for prefix, (names, _) in ALLOWED.items() if relative.startswith(prefix)), frozenset())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        offending += [f"{relative}:{line} {name}" for line, name in _uses(tree) if name not in allowed]
    assert offending == [], "network access outside Online Mode and the plugin sandbox"


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")


def _zip(members: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return buffer.getvalue()


NETWORK_HEAVY = {
    "README.md": (
        "# Service\n\nDocs at https://docs.example.com/guide and http://user:secret@api.example.org:8443/v1?q=1.\n"
        "Mirror: ftp://files.example.net/pub, ws://stream.example.com/live, grpc://rpc.example.com:50051.\n"
        "Hosts: db.internal, cache.service.consul, 10.0.0.5, 192.168.1.20:22, fe80::1%eth0, [2001:db8::1]:443.\n"
        "Evasive: http://0x7f000001/, http://2130706433/, http://127.1/. IDN: bücher.de, xn--bcher-kva.de.\n"
    ),
    "config/app.yaml": (
        "database:\n  host: db.example.com\n  port: 5432\nredis_url: redis://cache:6379/0\n"
        "amqp: amqp://guest:guest@rabbit.example.com:5672/\nlisten: 0.0.0.0:8080\n"
    ),
    ".env": "API_URL=https://api.example.com\nSMTP_HOST=smtp.example.com\nSMTP_PORT=587\n",
    ".npmrc": "registry=https://registry.example.com/\n",
    "pip.conf": "[global]\nindex-url = https://pypi.example.com/simple\n",
    "requirements.txt": "requests==2.32.3\nhttpx>=0.27\n",
    "package.json": json.dumps({"name": "svc", "version": "1.0.0", "repository": "https://github.com/example/svc",
                                "dependencies": {"express": "^4.19.0"}}),
    "go.mod": "module github.com/example/svc\n\ngo 1.22\n\nrequire google.golang.org/grpc v1.64.0\n",
    "Dockerfile": "FROM golang:1.22\nEXPOSE 8080 9090/udp\n",
    "docker-compose.yml": "services:\n  api:\n    build: .\n    ports:\n      - \"8080:8080\"\n  db:\n    image: postgres\n",
    "k8s/service.yaml": ("apiVersion: v1\nkind: Service\nmetadata:\n  name: api\nspec:\n  type: LoadBalancer\n"
                         "  selector:\n    app: api\n  ports:\n    - port: 80\n      targetPort: 8080\n"),
    "infra/main.tf": ('resource "aws_security_group" "web" {\n  ingress {\n    from_port = 443\n    to_port = 443\n'
                      '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'),
    "main.go": ('package main\n\nimport (\n\t"net"\n\t"net/http"\n)\n\nfunc main() {\n'
                '\tnet.Listen("tcp", "0.0.0.0:8080")\n\tnet.Dial("tcp", "db.example.com:5432")\n'
                '\thttp.Get("https://api.example.com/health")\n}\n'),
    "client.py": ("import socket\nimport requests\n\n"
                  "def fetch():\n    socket.create_connection(('db.example.com', 5432))\n"
                  "    return requests.get('https://api.example.com/users')\n"),
    "server.js": 'const http = require("http");\nhttp.createServer(app).listen(3000, "0.0.0.0");\n'
                 'fetch("https://api.example.com/items");\n',
    "openapi.yaml": ("openapi: 3.0.3\ninfo:\n  title: svc\n  version: '1'\nservers:\n  - url: https://api.example.com\n"
                     "paths:\n  /users:\n    get:\n      responses:\n        '200':\n          description: ok\n"
                     "          content:\n            application/json:\n              schema:\n"
                     "                $ref: 'https://schemas.example.com/user.json'\n"),
    "schema.json": json.dumps({"$schema": "http://json-schema.org/draft-07/schema#",
                               "$ref": "https://schemas.example.com/base.json"}),
    "pom.xml": ('<?xml version="1.0"?>\n<!DOCTYPE project SYSTEM "http://dtd.example.com/project.dtd">\n'
                '<project xmlns="http://maven.apache.org/POM/4.0.0" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                'xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">'
                '<modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>svc</artifactId>'
                '<version>1</version><repositories><repository><id>r</id><url>https://repo.example.com/maven</url>'
                '</repository></repositories></project>\n'),
    "web/index.html": ('<!doctype html><html><head><script src="https://cdn.example.com/app.js"></script>'
                       '<link rel="stylesheet" href="//fonts.example.com/css"></head>'
                       '<body><a href="http://evil.example/">x</a><img src="https://img.example.com/a.png">'
                       '</body></html>\n'),
    "web/logo.svg": ('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
                     '<image xlink:href="https://img.example.com/logo.png"/></svg>\n'),
    "ssh_config": "Host bastion\n  HostName bastion.example.com\n  Port 2222\n",
    "bundle.zip": _zip({"inner/config.ini": "[server]\nurl = https://inner.example.com:9443/\n",
                        "inner/hosts": "10.1.2.3 db.inner.example\n"}),
}


def test_a_scan_resolves_no_name_and_opens_no_connection(tmp_path: Path):
    if not _hooked:  # audit hooks cannot be removed: one, recording only while a scan runs
        sys.addaudithook(_audit)
        _hooked.append(True)
    project = tmp_path / "project"
    _write(project, NETWORK_HEAVY)
    output = tmp_path / "out"
    _events.clear()
    _recording.set()
    try:
        assert run_scan(project, output, {"json", "markdown", "html"}, 1, quiet=True) == 0
    finally:
        _recording.clear()
    assert _events == []
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    titles = {finding["title"].split(":")[0] for finding in report["findings"]}
    # The scan did read the network content: indicators, call sites and the service map.
    assert {"Network listeners opened in code", "Outbound network connections opened in code",
            "Network service map"} <= titles
    assert any(finding["category"] == "network" and finding["analyzer"] == "network-indicators"
               for finding in report["findings"])
