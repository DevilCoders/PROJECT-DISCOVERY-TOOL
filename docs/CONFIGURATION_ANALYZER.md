# Configuration Intelligence

The initial configuration analyzer inventories key paths from selected JSON, TOML, INI, environment, YAML, HCL/Terraform, properties and container configuration files. It intentionally does not place configuration values in findings.

A conservative set of security-sensitive settings is flagged as INFERRED for manual review: debug mode, disabled TLS verification, wildcard CORS, privileged containers, privilege escalation, root-user allowances and host networking.

YAML/HCL/properties extraction is lexical and intentionally shallow in this first pass. It does not claim complete parsing or effective configuration resolution across includes, templates, environment overlays, Helm, Terraform modules or runtime defaults. Malformed structured formats produce UNKNOWN findings.

## Resource and evidence policy

Configuration files are read once with a hard per-file content budget of 16 MiB. Files whose inventoried size exceeds the budget, or which grow beyond it while being read, produce an explicit `UNKNOWN` result; the analyzer does not treat a budget stop as a clean configuration assessment. Parse-error details are redacted before they are included in findings. Risky-setting findings include a redacted source-line excerpt, line number, conditional impact statement and remediation guidance. Values from ordinary configuration inventory are not serialized.

TLS risk polarity is explicit: `verify=false`, `rejectUnauthorized=false` and equivalent false/off settings are flagged; `insecure_skip_verify=true` is flagged. The secure inverse settings are not reported as disabling verification.
