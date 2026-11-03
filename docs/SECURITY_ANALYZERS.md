# Security Analysis

PDT has two complementary initial security analyzers:

- Secret-pattern inventory detects likely private keys, selected source-control tokens, AWS access-key IDs, credential URLs and secret-like assignments. Values are never copied into findings. Secret matches are INFERRED and assigned a severity for triage.
- Python AST security analysis detects selected dangerous APIs and patterns: eval/exec, shell=True subprocess calls, os.system, pickle deserialization, unsafe yaml.load, disabled TLS verification, tempfile.mktemp, weak hashes and dynamically formatted SQL execution. It parses but never imports or executes target code.

Severity is a triage signal, not an exploitability determination. Findings require human validation. The current rules are not a complete SAST engine, taint analyzer, dependency vulnerability scanner or compliance certification.
