# Configuration Intelligence

The initial configuration analyzer inventories key paths from selected JSON, TOML, INI, environment, YAML, HCL/Terraform, properties and container configuration files. It intentionally does not place configuration values in findings.

A conservative set of security-sensitive settings is flagged as INFERRED for manual review: debug mode, disabled TLS verification, wildcard CORS, privileged containers, privilege escalation, root-user allowances and host networking.

YAML/HCL/properties extraction is lexical and intentionally shallow in this first pass. It does not claim complete parsing or effective configuration resolution across includes, templates, environment overlays, Helm, Terraform modules or runtime defaults. Malformed structured formats produce UNKNOWN findings.
