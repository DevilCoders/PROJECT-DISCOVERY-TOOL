# Analyzer Domain Coverage

PDT is designed for polyglot repositories and heterogeneous project ecosystems. The analyzer roadmap is intentionally not limited to a short list of languages or security/configuration/API/database/test/build checks.

The machine-readable coverage catalog currently enumerates more than 50 domains spanning source structure, language semantics, dependency and supply-chain intelligence, security, APIs, databases, infrastructure, CI/CD, runtime architecture, ML/AI, datasets, robotics/ROS, embedded firmware, hardware description, GPU compute, graphics, game engines, mobile, accessibility, localization, and cross-project analysis.

Catalog status is explicit:
- `implemented`: the built-in analyzer currently provides the stated scope.
- `partial`: an initial analyzer exists but substantial planned coverage remains.
- `planned`: a domain is part of the coverage contract but has no substantive built-in analyzer yet.

A domain being catalogued is not evidence that its analyzer is complete. The roadmap is expanded as actual parsers, analyzers, tests, and evidence models are delivered.


## Implemented logging and observability slice

The built-in observability analyzer inventories static logging, metrics, tracing, health-check and telemetry configuration markers across recognized source languages. It records file and line evidence only and does not expose configuration values. Static presence is not proof of runtime initialization, active exporters, deployed collectors or operational telemetry.


## Implemented coverage artifact slice

The coverage analyzer reads LCOV, Cobertura, JaCoCo, Clover, OpenCover, Go cover profiles and Istanbul/coverage JSON. It extracts recorded line, statement, function and branch counters where the format provides them. The report does not prove which source revision was tested, that all tests ran, or that coverage instrumentation was complete.


## Implemented accessibility markup slice

The built-in accessibility analyzer checks HTML and common component-template files for missing document language, image alternative-text attributes, iframe titles, form-control labels, button names and link names. Findings are inferred from static markup and do not replace browser accessibility-tree inspection, keyboard testing or assistive-technology testing.


## Implemented localization catalog slice

The localization analyzer inventories Gettext PO/POT, ARB, nested JSON, XLIFF, Android string XML, Apple strings, Fluent, RESX and Java properties catalogs. It counts keys and explicitly empty translations without copying translated values into findings. It does not yet perform cross-locale key parity, plural-rule validation, placeholder parity or runtime fallback resolution.


## Expanded non-relational and vector datastore inventory

The NoSQL analyzer now recognizes additional vector/search and multi-model datastore client ecosystems, including Chroma, Qdrant, Pinecone, Weaviate, Milvus, FAISS, LanceDB, Vespa, ArangoDB and SurrealDB. Python AST analysis also propagates imported client classes through simple constructor assignments so selected operations on local client variables can be associated with the imported datastore. These are static client/API references, not live connection or schema claims.


## Expanded source-language matrix for API, database and migration analyzers

The source-level API endpoint analyzer and NoSQL/vector datastore analyzer now use the central source-language extension catalog instead of a hard-coded short list. Their static pattern checks therefore run across every source family recognized by PDT, while language-specific semantic extraction remains explicitly bounded by implemented rules.

Migration discovery likewise accepts migration scripts written in any recognized source language and adds explicit framework identification for Goose, Atlas, Dbmate, Drizzle ORM, Diesel, SeaORM and SQLx. A recognized migration file is not evidence that it has been applied to a database.


## Implemented project architecture layout slice

PDT now builds a project-level architecture layout inventory from repository paths. It recognizes common presentation, application, domain, infrastructure, persistence, API, testing, documentation, robotics, game-engine, machine-learning and delivery directory conventions. Results are explicitly INFERRED from naming and do not claim dependency direction, runtime boundaries, deployment topology or architectural compliance.


## Expanded dependency ecosystem coverage

Dependency declarations are now extracted from Maven POMs, Gradle, .NET project XML, Swift Package Manager, Dart pubspec, Ruby Gemfiles, Elixir mix.exs, Julia Project.toml, R DESCRIPTION, CMake, Conan, Clojure deps.edn/Leiningen, Scala sbt, Perl cpanfile, Haskell Cabal, OCaml opam, Nimble, ROS package.xml, vcpkg, DUB, Haxelib and Fortran fpm manifests, in addition to the existing Python, Node, Rust, Go and Composer support. These findings confirm manifest declarations only, not installation, build resolution or runtime use.


## Initial filesystem, archive, network and platform intelligence

The filesystem inventory now uses separate records for regular files, directories and symbolic links. It inventories hidden state, permissions, selected file signatures, size buckets, directory aggregates and common development/cache directory markers. Symbolic links are classified lexically and never traversed. Special filesystem entries are counted but still need per-entry records.

Oversized-file skipping is opt-in through the scan CLI flag. Initial Python AST analyzers and the Python import graph use an independent 16 MiB parser budget and report UNKNOWN when that budget is exceeded; this does not globally skip the file for streaming analyzers.

Initial archive intelligence reads ZIP/TAR metadata without extracting members. It records archive member counts and selected path traversal, symlink, hardlink, permission, duplicate-name, encrypted-entry and compression-ratio indicators. 7z/RAR/CAB/ISO and other formats may be identified by extension/signature but are not yet semantically indexed.

Network intelligence statically inventories IPv4/IPv6/CIDR, common port declarations, URL/URI, host/domain/subdomain candidates and protocol markers. URL evidence removes userinfo, path, query and fragment. It does not probe or resolve hosts. API type classification adds initial REST, GraphQL, gRPC/protobuf, JSON-RPC, SOAP/WSDL, WebSocket and event markers.

Privacy intelligence inventories PII field-name categories and email-shaped values without retaining the matched values. Existing secret-pattern analysis remains responsible for high-signal credential formats. These are partial static indicators, not a full DLP engine.


Additional dependency manifests include Erlang rebar configuration, PlatformIO embedded firmware library declarations, Lua rockspec dependencies and Ruby gemspec runtime/development dependencies.


## Bounded archive member content inspection

The ZIP/TAR archive analyzer reads archive metadata without writing members to disk. For regular members, it reads bounded samples through in-memory streams with a per-member cap and a total per-archive byte budget. Initial sample rules identify credential-like assignments, private-key markers, cloud access-key identifiers and email-shaped values. Findings retain only archive/member paths, line numbers and redacted indicator types; matched values are discarded. TAR streaming stops when an oversized member or scan budget is reached rather than decompressing the remainder solely to reach later entries. ZIP can continue metadata inventory independently of member sample limits. This is partial static content inspection, not a complete malware scanner or DLP engine. Unsupported 7z/RAR/CAB/ISO formats are detection-only in the current implementation.
