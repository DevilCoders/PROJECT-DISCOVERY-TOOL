# Security Analyzer Coverage

The initial built-in security pass is a conservative secret-pattern scanner. It checks selected source/configuration files and common .env variants for private-key headers, token-like values, AWS access-key identifiers, credential-bearing URLs and sensitive-key assignments.

Safety properties:
- Matched values are never copied into findings or reports.
- Evidence contains only the target-relative path and line number.
- Findings are INFERRED and require manual validation; patterns can produce false positives.
- Placeholder and common environment-variable references are filtered.
- Oversized and unreadable files are skipped or marked UNKNOWN by the scan pipeline.

This is not a complete SAST engine, credential validator, or vulnerability scanner. It does not contact providers to test whether a credential is active. Further security domains remain in the analyzer coverage roadmap.
