# Security Analysis

PDT uses complementary static security analyzers and deliberately reports evidence rather than exploitability claims.

## Current capabilities
- Secret-pattern inventory detects likely private keys, selected source-control tokens, AWS access-key IDs, credential URLs and secret-like assignments. Values are redacted and never copied into findings.
- Python AST checks inspect dangerous calls and selected argument semantics without importing or executing target modules.
- The cross-language secure-code pattern analyzer scans recognized source families (40+ language labels) for high-signal API patterns including dynamic code/process execution, unsafe deserialization, disabled TLS verification, unsafe C memory APIs, dynamic SQL construction, request-derived outbound HTTP destinations, request-derived filesystem paths, weak hashes, disabled JWT verification, non-cryptographic randomness used for secret-like identifiers, open redirects, permissive file permissions and unsafe XML external-entity settings.
- Configuration and deployment analyzers separately inspect declared risky settings such as debug mode, wildcard CORS, privileged containers, host networking and broad CI permissions.

## Evidence and limitations
- Pattern-based findings are INFERRED; a match is not proof of taint, exploitability, reachability or vulnerable runtime behavior.
- Python AST rules use syntax and call-argument evidence, but do not perform interprocedural dataflow analysis.
- Generic cross-language rules are lexical heuristics. They do not replace grammar-aware language-specific SAST, compiler analysis, framework-aware route resolution or taint tracking.
- Secret values are not included in reports. Findings contain file paths and line numbers only.
- PDT does not run target code, connect to target services, download advisories or upload project content.

A full SAST, vulnerability intelligence, compliance or penetration-test conclusion requires separate validated analysis. Human review is required for every finding.
