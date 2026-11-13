# Network indicators

The `network-indicators` analyzer reads text, source and configuration files for static network references: addresses, networks, ports, URLs, host names and protocol markers. It is passive by construction: it resolves no name, opens no connection and sends nothing. A reference is evidence that a file names something, not that it is reachable or in use.

## What it reports

| Indicator | Detection | Evidence |
|---|---|---|
| IPv4 addresses | Dotted quads validated with `ipaddress`; four-part version numbers (`AssemblyVersion("1.0.0.0")`, `version = "1.2.3.4"`) are skipped | the address |
| IPv6 addresses | Full and compressed forms, IPv4-mapped (`::ffff:192.0.2.1`), bracketed literals, and zone-scoped link-local addresses (`fe80::1%eth0`; in a URL, the RFC 6874 form `[fe80::1%25eth0]`), which keep their zone. In source code only inside string literals, so `a::b` scopes are not addresses | the compressed address, with its zone |
| CIDR ranges | IPv4 and IPv6 networks, `::/0` included | the network |
| Ports | `port =`/`listen`/`EXPOSE` declarations, `host:port`, URL ports; common services are named (5432/PostgreSQL) | the port |
| URLs | `scheme://...`; evidence keeps the scheme, host and port only: user information, path, query, fragment and authority properties (JDBC `;user=...;password=...`, `\instance` names, replica lists) are removed | the redacted URL |
| Host and domain names | Dotted names whose last label is an IANA TLD (bundled snapshot), with Unicode labels; see below | the name |
| Protocols | REST/HTTP, WebSocket, gRPC, GraphQL, SOAP, MQTT, AMQP, Kafka, SSH and DNS markers | the line |

## Host names

A dotted name is a host name when its TLD is a real one (or a special-use name such as `.local`, `.internal`, `.test`), it is not a file name ending in a TLD-shaped extension (`setup.py`, `README.md`), not a reverse-DNS identifier (`com.example.app`) and not a configuration key, and it has three labels, a common TLD, or is a URL's host. Names are compared and reported lower-cased, without a trailing dot.

**Internationalized names.** Labels may be Unicode (`bücher.de`, `пример.рф`) or IDNA A-labels (`xn--bcher-kva.de`); both are reported as one Unicode name, and an *Internationalized domain names* finding gives each with the ASCII form DNS resolves. A label that mixes Latin letters with Cyrillic, Greek, Armenian or Cherokee ones, the look-alike scripts of IDN homograph names (`аpple.com`, its first letter Cyrillic), is a MEDIUM *Domain names that mix look-alike scripts* finding. Names that are entirely in another script are not flagged.

**Registrable domains and subdomains** follow the Public Suffix List: `example.co.uk` is a registrable domain, not a subdomain; `api.example.co.uk` is a subdomain of it; `user.github.io` is a registrable domain of its own (the list's private section applies, as in browsers). Wildcard (`*.ck`) and exception (`!www.ck`) rules apply as the list specifies, and a TLD the list does not name is its own suffix. The domain finding gives the names, the registrable domains they fall under and how many are subdomains.

**URL hosts** are read as browsers read them: a percent-encoded host is decoded, a backslash ends the authority (`http://evil.example\@good.example/` names `evil.example`), the last `@` ends the user information, and an empty or out-of-range port is no port. A host that spells an IPv4 address in a WHATWG number form, decimal (`2130706433`), hex (`0x7f000001`, `0x7f.1`), octal (`0177.0.0.1`), shortened (`127.1`) or percent-encoded, is reported as that address and in a MEDIUM *IP addresses written to evade URL filters* finding: browsers and curl resolve these forms while host filters often miss them, a server-side request forgery and filter-evasion technique.

## Call sites in code

A port in a YAML file or a `PORT = 8080` constant is a declaration; `net.Listen("tcp", ":8080")` is code that opens a listener. The `network-sockets` analyzer reports the second kind: the call sites that open a listening socket or server, connect to another host, or create a socket, by each language's API, with the literal address or port among their arguments. Declarations stay with `network-indicators`, so a report tells "declared" from "opened in code" by the finding.

| Language | Listen (bind, listen, accept, servers) | Connect | Socket |
|---|---|---|---|
| Python (syntax tree; imports resolved, so `from socket import create_connection as dial` counts) | `socket.create_server`, the `bind`/`listen`/`accept` of sockets the file creates, `asyncio.start_server`, `socketserver` and `http.server` servers, `wsgiref`, `xmlrpc`, `uvicorn.run`, `aiohttp.web.run_app`, `websockets.serve`, a Flask app's `run` | `socket.create_connection`, a socket's `connect`/`connect_ex`, `asyncio.open_connection`, `websockets.connect`, `http.client`, `ftplib`, `smtplib`, `telnetlib`, `poplib`, `imaplib` | `socket.socket`, `socketpair`, `fromfd` |
| Go | `net.Listen*`, `http.ListenAndServe(TLS)`, `tls.Listen` | `net.Dial*`, `tls.Dial`, `grpc.Dial`, `grpc.NewClient` | |
| JavaScript/TypeScript | `net`/`http`/`https`/`http2`/`tls` `createServer`, `new WebSocketServer`, a `.listen(...)` in a file importing a server module (or with a literal port) | `net.connect`, `createConnection`, `tls.connect`, `http2.connect`, `new WebSocket` | `dgram.createSocket` |
| Java, Kotlin, Scala, Groovy | `ServerSocket`, `ServerSocketChannel.open`, `HttpServer.create` | `Socket`, `SocketChannel.open` | `DatagramSocket`, `MulticastSocket` |
| C# (socket methods with `using System.Net.Sockets`) | `TcpListener`, `HttpListener`, `Bind`, `Listen`, `Accept*` | `TcpClient`, `Connect(Async)` | `UdpClient`, `Socket` |
| C, C++ (with a socket header included: Qt's `connect` is not a socket call) | `bind`, `listen`, `accept`, `accept4`, `WSAAccept` | `connect`, `WSAConnect` | `socket`, `WSASocket` |
| Rust | `TcpListener::bind`, `UnixListener::bind` | `TcpStream::connect`, `UnixStream::connect` | `UdpSocket::bind`, `TcpSocket::new_v4/6` |
| PHP | `socket_bind`, `socket_listen`, `socket_accept`, `stream_socket_server` | `socket_connect`, `stream_socket_client`, `fsockopen` | `socket_create` |
| Ruby (from the text) | `TCPServer`, `UNIXServer`, `Socket.tcp_server_loop` | `TCPSocket`, `UNIXSocket`, `Socket.tcp` | `UDPSocket` |
| Swift, Dart | `NWListener`; `ServerSocket.bind`, `HttpServer.bind` | `NWConnection`; `Socket.connect`, `WebSocket.connect` | `RawDatagramSocket.bind` |

Python call sites are CONFIRMED (the syntax tree, with imports followed); the others come from the shared structural lexer and are INFERRED. A listener that binds every interface explicitly (`0.0.0.0`, `::`, or Python's `''` in a bind tuple) is a MEDIUM "Listeners bound to every network interface" finding: it accepts connections from every network the host is on. An implicit all-interface bind (Go's `":8080"`, Node's `listen(port)`) is listed, not flagged. Socket-level `listen` and `accept` carry a backlog, not an address. At most 1,000 call sites are kept per file.

## The bundled Public Suffix List

`src/project_discovery/data/public_suffix_list.dat` is a copy of the [Public Suffix List](https://publicsuffix.org/list/), bundled unmodified and read at scan time; PDT never fetches it. The list is subject to the Mozilla Public License, v. 2.0 (its header says so). The current snapshot is the list as Debian's `publicsuffix` package 20260129.1928-1 ships it (SHA-256 `f3604fee29f4a2234547ca068da1e4c6a1c480418f1c418d4b4040633be501b4`). To refresh it, replace the file with a newer copy of `https://publicsuffix.org/list/public_suffix_list.dat`, unmodified, and run the network tests.

The IANA TLD list (`data/tlds.txt`) is a separate bundled snapshot used to tell real TLDs from other dotted words.

## Budgets

The analyzer reads at most 64 MiB of a file in bounded lines of up to 256 KiB, keeps at most 25,000 distinct indicators per file and 100 evidence lines per finding; reaching a limit is an `UNKNOWN` finding, and an overlong line is skipped with one ([Analyzer resource budgets](../architecture/ANALYZER_RESOURCE_BUDGETS.md)). Every pattern is checked for linear-time matching on adversarial input by the test suite.
