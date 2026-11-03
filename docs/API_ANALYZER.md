# API Contract Intelligence

The initial API contract analyzer statically inventories:
- OpenAPI/Swagger JSON and YAML files, including HTTP operations and component schemas.
- GraphQL schema definitions and named query/mutation/subscription operations.
- Protocol Buffers messages, enums, services and RPC declarations.
- Thrift services, structs, exceptions, enums and typedef declarations.

JSON OpenAPI parsing uses the Python standard library. YAML OpenAPI parsing uses PyYAML when installed; without it, a deliberately shallow line-based fallback inventories common paths, methods and operation IDs. The analyzer does not make network requests or claim that an API is deployed, reachable, authorized, or behaviorally correct. Runtime route discovery, framework-specific handlers, compatibility analysis and security testing remain future analyzer work.
