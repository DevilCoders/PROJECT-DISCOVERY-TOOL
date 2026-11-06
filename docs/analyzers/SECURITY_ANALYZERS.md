# Security Analysis

PDT uses complementary static security analyzers and deliberately reports evidence rather than exploitability claims.

## Current capabilities
- **Secret patterns** detect private keys, more than 30 provider credential formats, credential URLs and secret-like assignments. Values are redacted and never copied into findings (see [SECURITY_ANALYZER.md](SECURITY_ANALYZER.md)).
- **Python AST security** inspects dangerous calls and selected argument semantics, resolving import aliases, without importing or executing target modules.
- **Cross-language secure-code patterns** scan every recognized source family for high-signal API patterns: dynamic code and process execution, unsafe deserialization, disabled TLS verification, unsafe C memory APIs, dynamic SQL construction, request-derived outbound HTTP destinations and filesystem paths, weak hashes, disabled JWT verification, non-cryptographic randomness for secret-like identifiers, open redirects, permissive file permissions and unsafe XML external-entity settings.
- **Data flow and taint** (`dataflow`) follows untrusted input from web requests, sockets and stdin to SQL, command, code, deserialization, template, path, SSRF, XSS, redirect, format-string and buffer sinks. Python is analysed inter-procedurally (same-module helpers) and across modules; JavaScript/TypeScript, PHP, Java/Kotlin/Scala/Groovy, Go, C#, Rust and C/C++ follow input through the file's own functions (summaries of what each parameter reaches and what each function returns) and into functions of other files whose name only one file defines. Each finding names the source, the sink and their lines. See [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md#4-data-flow-and-taint-dataflow).
- **Configuration and deployment analyzers** separately inspect declared risky settings such as debug mode, wildcard CORS, privileged containers, host networking and broad CI permissions; the firmware analyzer flags development image features and empty root passwords in Yocto and Buildroot configurations.
- **Local vulnerability matching** compares lockfile-resolved package versions with an operator-imported OSV snapshot (`--vuln-db`).

## Evidence and limitations
- Pattern-based findings are `INFERRED`; a match is not proof of exploitability, reachability or vulnerable runtime behavior.
- Taint flows are also `INFERRED`: static analysis cannot see run-time validation, authorization or framework escaping. Outside Python, taint is not followed between functions, and no language has type inference.
- Generic cross-language rules are lexical heuristics. They do not replace compiler-grade SAST or framework-aware route resolution.
- Secret values are not included in reports. Findings contain file paths, line numbers and redacted excerpts only.
- PDT does not run target code or connect to target services. Vulnerability matching is offline by default and never uploads project content.

A full SAST, vulnerability intelligence, compliance or penetration-test conclusion requires separate validated analysis. Human review is required for every finding.
