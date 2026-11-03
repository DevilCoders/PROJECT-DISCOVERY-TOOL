"""Coverage map for broad, polyglot project-intelligence domains.

The catalog is a roadmap contract, not a claim that every analyzer is implemented.
Only capabilities marked implemented are currently executed by built-in analyzers.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnalyzerDomain:
    identifier: str
    title: str
    scope: str
    status: str = "planned"


_DOMAINS = (
    AnalyzerDomain("source_structure", "Source Structure", "Files, declarations, scopes, namespaces and source organization.", "partial"),
    AnalyzerDomain("symbol_index", "Symbol Index", "Classes, functions, methods, types, fields, macros and symbol references."),
    AnalyzerDomain("imports", "Import and Module Graph", "Imports, exports, module resolution, dependency edges and cycles.", "partial"),
    AnalyzerDomain("call_graph", "Call Graph", "Static call sites, dispatch uncertainty, callers and callees."),
    AnalyzerDomain("type_systems", "Type Systems", "Declared types, generics, traits, interfaces, protocols and type references."),
    AnalyzerDomain("documentation", "Documentation Intelligence", "Markdown, HTML, PDF, office documents, references, stale claims and contradictions.", "partial"),
    AnalyzerDomain("dependency_manifests", "Dependency Manifests", "Declared packages, versions, optional groups, workspaces and lockfiles.", "partial"),
    AnalyzerDomain("dependency_resolution", "Dependency Resolution", "Resolved dependency trees, conflicts, version constraints and provenance."),
    AnalyzerDomain("licenses", "License Intelligence", "License declarations, notices, compatibility and attribution evidence."),
    AnalyzerDomain("secrets", "Secret Exposure", "Potential credentials, keys, tokens and sensitive material with redaction.", "partial"),
    AnalyzerDomain("vulnerabilities", "Vulnerability Intelligence", "Known vulnerable dependency versions and local advisory matching."),
    AnalyzerDomain("secure_code", "Secure Code Analysis", "Injection, unsafe APIs, trust boundaries, deserialization and insecure patterns."),
    AnalyzerDomain("authentication", "Authentication", "Identity providers, login flows, credential handling and session boundaries."),
    AnalyzerDomain("authorization", "Authorization", "Roles, permissions, access-control checks and policy consistency."),
    AnalyzerDomain("cryptography", "Cryptography", "Cryptographic primitives, key lifecycle, randomness and protocol usage."),
    AnalyzerDomain("configuration", "Configuration Intelligence", "Environment variables, config formats, defaults, overrides and drift.", "partial"),
    AnalyzerDomain("api_rest", "REST API Intelligence", "Routes, handlers, schemas, middleware, versioning and endpoint relationships.", "partial"),
    AnalyzerDomain("api_graphql", "GraphQL Intelligence", "Schemas, resolvers, directives, operations and federation boundaries.", "partial"),
    AnalyzerDomain("api_rpc", "RPC and Service Contracts", "gRPC, Thrift, message contracts, generated stubs and compatibility.", "partial"),
    AnalyzerDomain("databases_sql", "SQL Database Intelligence", "Schemas, queries, indexes, constraints, stored procedures and migrations.", "partial"),
    AnalyzerDomain("databases_nosql", "NoSQL Intelligence", "Document, key-value, graph and wide-column data models."),
    AnalyzerDomain("orm", "ORM and Data Mapping", "Models, relations, query builders, mappings and schema drift.", "partial"),
    AnalyzerDomain("migrations", "Data Migration Intelligence", "Migration ordering, reversibility, destructive operations and version state.", "partial"),
    AnalyzerDomain("messaging", "Messaging and Event Systems", "Queues, topics, event schemas, consumers, producers and delivery semantics."),
    AnalyzerDomain("tests", "Test Intelligence", "Test discovery, frameworks, fixtures, suites and test-to-code relationships.", "partial"),
    AnalyzerDomain("coverage", "Coverage Intelligence", "Coverage artifacts, untested code indicators and coverage trends."),
    AnalyzerDomain("build_systems", "Build Systems", "Build graphs, targets, toolchains, generated code and build dependencies.", "partial"),
    AnalyzerDomain("ci_cd", "CI/CD Intelligence", "Pipelines, jobs, conditions, artifacts, secrets exposure and release gates."),
    AnalyzerDomain("containers", "Container Intelligence", "Dockerfiles, image layers, compose files, base images and runtime settings."),
    AnalyzerDomain("orchestration", "Orchestration Intelligence", "Kubernetes, Helm, operators, manifests and workload relationships."),
    AnalyzerDomain("infrastructure_as_code", "Infrastructure as Code", "Terraform, Pulumi, CloudFormation, Ansible and infrastructure dependencies."),
    AnalyzerDomain("cloud_services", "Cloud Service Intelligence", "Cloud resources, service bindings, IAM references and deployment topology."),
    AnalyzerDomain("networking", "Network Architecture", "Ports, protocols, sockets, DNS, proxies, ingress and service communication."),
    AnalyzerDomain("performance", "Performance Hotspots", "Complexity indicators, expensive patterns, bottlenecks and profiling artifacts."),
    AnalyzerDomain("concurrency", "Concurrency and Parallelism", "Threads, tasks, locks, races, async flows and synchronization."),
    AnalyzerDomain("memory", "Memory and Resource Management", "Allocation, ownership, leaks, lifetimes, handles and resource cleanup."),
    AnalyzerDomain("dataflow", "Data Flow and Taint", "Sources, sinks, transformations, trust boundaries and propagation paths."),
    AnalyzerDomain("serialization", "Serialization Intelligence", "JSON, XML, protobuf, binary formats, schema evolution and unsafe decoding."),
    AnalyzerDomain("logging", "Logging Intelligence", "Loggers, levels, sensitive-data exposure and correlation identifiers."),
    AnalyzerDomain("observability", "Observability Intelligence", "Metrics, traces, health checks, alerts and telemetry configuration."),
    AnalyzerDomain("machine_learning", "Machine Learning Systems", "Framework imports, model/training/inference code markers and local model artifact inventory.", "partial"),
    AnalyzerDomain("datasets", "Dataset Intelligence", "Dataset container inventory and source-level input pipeline markers.", "partial"),
    AnalyzerDomain("model_artifacts", "Model Artifact Intelligence", "Checkpoint/model file inventory and selected model metadata extraction.", "partial"),
    AnalyzerDomain("robotics_ros", "Robotics and ROS", "Packages, nodes, topics, services, actions, launch files and message interfaces."),
    AnalyzerDomain("embedded", "Embedded Systems", "Cross-compilation, board support, RTOS, peripheral access and memory maps."),
    AnalyzerDomain("firmware", "Firmware and Binary Artifacts", "Firmware images, symbols, sections, boot chains and binary metadata."),
    AnalyzerDomain("hardware_description", "Hardware Description Languages", "Verilog, SystemVerilog, VHDL, modules and signal relationships."),
    AnalyzerDomain("gpu_compute", "GPU and Compute Kernels", "CUDA, OpenCL, shader compute, kernels and host-device boundaries.", "partial"),
    AnalyzerDomain("graphics_shaders", "Graphics and Shader Systems", "Shader stages, pipelines, bindings, materials and rendering assets."),
    AnalyzerDomain("game_engines", "Game Engine Intelligence", "Scenes, entities, components, assets, scripts and engine configuration."),
    AnalyzerDomain("frontend", "Frontend Application Intelligence", "Components, routes, state, rendering, bundlers and client dependencies."),
    AnalyzerDomain("mobile", "Mobile Application Intelligence", "Android, iOS, permissions, manifests, build variants and native bridges."),
    AnalyzerDomain("accessibility", "Accessibility", "Semantic structure, labels, keyboard navigation and accessibility metadata."),
    AnalyzerDomain("localization", "Localization", "Translation catalogs, locale fallback, missing keys and formatting."),
    AnalyzerDomain("assets", "Asset and Media Intelligence", "Images, audio, video, fonts, 3D assets and references."),
    AnalyzerDomain("architecture", "Architecture and Boundaries", "Layers, components, coupling, cohesion, patterns and boundary violations."),
    AnalyzerDomain("multi_project", "Multi-Project Intelligence", "Cross-repository comparison, shared capabilities, conflicts and integration maps."),
    AnalyzerDomain("supply_chain", "Software Supply Chain", "SBOM, provenance, signatures, attestations and build origin."),
    AnalyzerDomain("privacy", "Privacy and Data Governance", "PII indicators, retention configuration, data flows and privacy controls."),
)


def analyzer_domain_catalog() -> list[dict[str, str]]:
    return [
        {
            "id": item.identifier,
            "title": item.title,
            "scope": item.scope,
            "status": item.status,
        }
        for item in _DOMAINS
    ]


def analyzer_domain_count() -> int:
    return len(_DOMAINS)
