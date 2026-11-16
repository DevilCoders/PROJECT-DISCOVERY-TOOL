# Analyzer Domain Coverage

PDT is designed for polyglot repositories and heterogeneous project ecosystems. The analyzer roadmap is intentionally not limited to a short list of languages or security/configuration/API/database/test/build checks.

The machine-readable coverage catalog currently enumerates more than 50 domains spanning source structure, language semantics, dependency and supply-chain intelligence, security, APIs, databases, infrastructure, CI/CD, runtime architecture, ML/AI, datasets, robotics/ROS, embedded firmware, hardware description, GPU compute, graphics, game engines, mobile, accessibility, localization, and cross-project analysis.

Catalog status is explicit:
- `implemented`: the built-in analyzer currently provides the stated scope.
- `partial`: an initial analyzer exists but substantial planned coverage remains.
- `planned`: a domain is part of the coverage contract but has no substantive built-in analyzer yet.

A domain being catalogued is not evidence that its analyzer is complete. The roadmap is expanded as actual parsers, analyzers, tests, and evidence models are delivered.


## Code intelligence and the formerly planned domains

The symbol index, call graph, type systems, performance, concurrency, memory and resource management, data flow and taint, embedded, firmware, hardware description, graphics shader, frontend and multi-project domains now have built-in analyzers on a shared code model and a cross-file code index, and are catalogued as `partial`. Their methods, findings and limits are documented in [CODE_INTELLIGENCE.md](CODE_INTELLIGENCE.md).


## Implemented logging and observability slice

The built-in observability analyzer inventories static logging, metrics, tracing, health-check and telemetry configuration markers across recognized source languages. It records file and line evidence only and does not expose configuration values. Static presence is not proof of runtime initialization, active exporters, deployed collectors or operational telemetry.


## Implemented coverage artifact slice

The coverage analyzer reads LCOV, Cobertura, JaCoCo, Clover (the project's own `<metrics>`, which php-code-coverage writes after every class and file), OpenCover, Go cover profiles and Istanbul/coverage JSON. It extracts recorded line, statement, function and branch counters where the format provides them (LCOV `FNF`/`FNH` functions, JaCoCo `METHOD` and OpenCover method counters). A Go block that a `-coverpkg` run lists once per test binary counts once, as covered when any binary ran it. The report does not prove which source revision was tested, that all tests ran, or that coverage instrumentation was complete.


## Implemented accessibility markup slice

The built-in accessibility analyzer checks HTML and common component-template files for missing document language, image alternative-text attributes, iframe titles, form-control labels, button names and link names. In JSX, Vue, Svelte and Astro, PascalCase tags are components rather than native controls and `htmlFor` labels a control. Findings are inferred from static markup and do not replace browser accessibility-tree inspection, keyboard testing or assistive-technology testing.


## Implemented localization catalog slice

The localization analyzer inventories Gettext PO/POT, ARB, nested JSON, XLIFF, Android string XML, Apple strings, Fluent, RESX and Java properties catalogs. A JSON, YAML, XML or properties file is a catalog when it lives in a locale directory or its name is a language code (`en.json`, `pt-BR.yml`), so `app.json`, `pom.xml` and `ci.yml` are not. It counts keys and explicitly empty translations without copying translated values into findings. It does not yet perform cross-locale key parity, plural-rule validation, placeholder parity or runtime fallback resolution.


## Expanded non-relational and vector datastore inventory

The NoSQL analyzer now recognizes additional vector/search and multi-model datastore client ecosystems, including Chroma, Qdrant, Pinecone, Weaviate, Milvus, FAISS, LanceDB, Vespa, ArangoDB and SurrealDB. Python AST analysis also propagates imported client classes through simple constructor assignments so selected operations on local client variables can be associated with the imported datastore. These are static client/API references, not live connection or schema claims.


## Expanded source-language matrix for API, database and migration analyzers

The source-level API endpoint analyzer and NoSQL/vector datastore analyzer now use the central source-language extension catalog instead of a hard-coded short list. The datastore analyzer's static pattern checks run across every source family recognized by PDT; the endpoint analyzer reads each language with that language's adapters ([Endpoint adapters](../analyzers/API_ANALYZER.md#endpoint-adapters)), so a language without adapters reports no endpoint declarations. Language-specific semantic extraction remains explicitly bounded by implemented rules.

Migration discovery likewise accepts migration scripts written in any recognized source language and adds explicit framework identification for Goose, Atlas, Dbmate, Drizzle ORM, Diesel, SeaORM and SQLx. A recognized migration file is not evidence that it has been applied to a database.


## Implemented project architecture layout slice

PDT now builds a project-level architecture layout inventory from repository paths. It recognizes common presentation, application, domain, infrastructure, persistence, API, testing, documentation, robotics, game-engine, machine-learning and delivery directory conventions. Results are explicitly INFERRED from naming and do not claim dependency direction, runtime boundaries, deployment topology or architectural compliance.


## Expanded dependency ecosystem coverage

Dependency declarations are now extracted from Maven POMs, Gradle, .NET project XML, Swift Package Manager, Dart pubspec, Ruby Gemfiles, Elixir mix.exs, Julia Project.toml, R DESCRIPTION, CMake, Conan, Clojure deps.edn/Leiningen, Scala sbt, Perl cpanfile, Haskell Cabal, OCaml opam, Nimble, ROS package.xml, vcpkg, DUB, Haxelib and Fortran fpm manifests, in addition to the existing Python, Node, Rust, Go and Composer support. These findings confirm manifest declarations only, not installation, build resolution or runtime use.


## Initial filesystem, archive, network and platform intelligence

The filesystem inventory now uses separate records for regular files, directories and symbolic links. It inventories hidden state, permissions, selected file signatures, size buckets, directory aggregates and common development/cache directory markers. Symbolic links are classified lexically and never traversed. Special filesystem entries (FIFOs, sockets, devices and unknown types) get their own inventory records.

Oversized-file skipping is opt-in through the scan CLI flag. Initial Python AST analyzers and the Python import graph use an independent 16 MiB parser budget and report UNKNOWN when that budget is exceeded; this does not globally skip the file for streaming analyzers.

Archive intelligence reads the indexes of ZIP, TAR, ar (DEB packages, static libraries), Cabinet, RPM, ISO 9660, 7z and RAR archives and the headers of single gzip, bzip2, xz, LZMA and Zstandard files without extracting members, and names the language packages among them from their manifests. It records each archive and member, and path traversal, symlink, hardlink, permission, duplicate-name, encryption, compression-ratio, structure and install-time-code indicators. cpio, xar, WIM, UDF and other formats are identified by signature only ([Archive intelligence](../analyzers/ARCHIVE_ANALYZER.md)).

Network intelligence statically inventories IPv4/IPv6/CIDR (IPv4-mapped, bracketed and zone-scoped IPv6 included), common port declarations, URL/URI, host/domain/subdomain candidates and protocol markers. Host names may be internationalized (Unicode or IDNA labels, with a finding for labels that mix look-alike scripts), subdomains are classified by the bundled Public Suffix List, and URL hosts that spell an IPv4 address in a WHATWG number form or percent-encoded are reported as addresses written to evade filters ([Network indicators](../analyzers/NETWORK_ANALYZER.md)). A second analyzer, `network-sockets`, reports the listeners, outbound connections and sockets code opens, by each language's socket and server APIs, with literal addresses, so configuration declarations and code call sites are told apart; an explicit bind to every interface is a finding. The code index joins both with the ports Dockerfiles, Compose, Kubernetes and Terraform declare into a network service map ([Service map](../analyzers/NETWORK_ANALYZER.md#service-map)). URL evidence keeps only the scheme, host and port: userinfo, path, query, fragment and authority properties (JDBC `;user=...;password=...`, `\instance` names, replica lists) are removed. It does not probe or resolve hosts. API type classification adds initial REST, GraphQL, gRPC/protobuf, JSON-RPC, SOAP/WSDL, WebSocket and event markers. GraphQL is read in depth by `api-graphql`: schemas, operations, resolvers in eleven frameworks' forms, directives, Apollo Federation and subscriptions ([GraphQL](../analyzers/API_ANALYZER.md#graphql)). RPC is read in depth by `api-rpc`: Protocol Buffers messages and gRPC services with their streaming kinds and HTTP mappings, Thrift services and Avro protocols, RPC servers and clients in twelve languages and nine frameworks, and generated code ([RPC services](../analyzers/API_ANALYZER.md#rpc-services)). Other protocols are read by `api-protocols`: JSON-RPC, SOAP, WebSocket, Server-Sent Events, webhook, MQTT and message-driven endpoints in code, and AsyncAPI, OpenRPC and OpenAPI webhook documents recognized by content ([Protocol endpoints](../analyzers/API_ANALYZER.md#protocol-endpoints)). Generated OpenAPI clients are found by `api-clients` from twelve generators' marks, and the code index cross-references contract operations with routes, generated clients and HTTP calls ([Contracts, routes and generated clients](../analyzers/API_ANALYZER.md#contracts-routes-and-generated-clients)). Authentication and authorization, versioning, rate-limit and validation declarations are recorded by `api-policies` with their framework and scope ([Policy declarations](../analyzers/API_ANALYZER.md#policy-declarations)). The code index joins routes, handlers, contracts and policies into an endpoint catalog ([Endpoint catalog](../analyzers/API_ANALYZER.md#endpoint-catalog)).

Privacy intelligence inventories PII field-name categories and email-shaped values without retaining the matched values. A field name matches when it ends with the keyword (`user_email`, `DB_PASSWORD`, `GITHUB_TOKEN`, `token`), not when the keyword only begins a longer name (`email_verified`, `tokenizer`). Email values count only when the domain ends in a real IANA top-level domain and is not a reserved example name. Package specifiers such as `pkg@1.0.0`, asset names such as `logo@2x.png`, SCP remotes and URL user info are skipped. Prose documentation contributes email values but not field names. Field-name inventories are LOW severity because a name alone does not prove that data is present. Existing secret-pattern analysis remains responsible for high-signal credential formats. These are partial static indicators, not a full DLP engine.


Additional dependency manifests include Erlang rebar configuration, PlatformIO embedded firmware library declarations, Lua rockspec dependencies and Ruby gemspec runtime/development dependencies.


## Bounded archive member content inspection

The archive analyzer reads archive metadata without writing members to disk. For regular members (ZIP and TAR members, stored ar, ISO, 7z and RAR members, and the content of single compressed files), it reads bounded samples through in-memory streams with a per-member cap and a total per-archive byte budget. Initial sample rules identify credential-like assignments, private-key markers, cloud access-key identifiers and email-shaped values. Findings retain only archive/member paths, line numbers and redacted indicator types; matched values are discarded. TAR traversal continues past oversized members and exhausted sample budgets, so every header is examined, including later `../` paths, absolute paths, links and setuid entries. Plain archives seek past member data. Compressed TAR streams (gzip, bzip2, xz, LZMA, Zstandard) are decompressed through a budgeted reader capped at 4 GiB of output and 8 seconds of wall time, and reaching either limit is reported as `UNKNOWN`. Case- and Unicode-colliding member names are reported for every format with names. ZIP can continue metadata inventory independently of member sample limits. Cabinet, RPM and compressed 7z and RAR members are not decompressed, so their content is not sampled. This is partial static content inspection, not a complete malware scanner or DLP engine.
