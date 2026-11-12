# Security Analyzer Coverage

The built-in secret scanner (`secret-patterns`) streams every textual source, configuration and documentation file, plus `.env` variants and key files (`.pem`, `.key`, `id_rsa`, …), in 8 MiB chunks up to 64 MiB per file. It reports:

- **Private-key blocks**: PEM, OpenSSH and PGP `PRIVATE KEY` markers.
- **Provider credential formats**: more than 30 high-confidence formats from one shared registry (`core/secret_patterns.py`), including GitHub, GitLab, AWS, Google, Slack, Stripe, OpenAI, Anthropic, Hugging Face, npm, PyPI, Docker, Azure storage and SAS keys, Vault, Doppler, age keys and JWTs. The same registry drives redaction, so every detected format is also removed from report excerpts.
- **Credential URLs**: URLs whose user-info part (before `@`) carries both a user name and a password.
- **Generic credential assignments**: a key containing `password`, `secret`, `token`, `api_key` and similar, assigned a value of at least 6 characters. Supported forms include `key = value`, `key: value`, `"key": value`, `'key' => value`, Go `:=` and typed defaults such as `secret: str = "…"`.
  - In programming languages, only string literals count, because an unquoted right-hand side is an expression.
  - In configuration, environment and shell files, unquoted values are literals and count too.
  - Separators never span a line break.
  - When a specific provider format matches on a line, it replaces the generic finding, so one secret yields one finding.

Filtering:
- Placeholders are ignored, including `changeme`, `your_api_key`, `<token>`, `${VAR}`, `{{ secrets.X }}`, `os.getenv(...)` and values made of one or two repeated characters. Plain URLs and filesystem paths (`token_url: https://…`, `secret_file: /run/secrets/db`) are also ignored.
- Findings in test, fixture, example, sample, mock and documentation locations are kept but lowered one severity level, and the detail says so.

Safety properties:
- Matched values are never copied into findings or reports. Excerpts pass through the redactor, which knows every key name and assignment form the scanner reports (typed defaults, `:=`, `=>`, quoted and subscripted keys), and again through the `CodeEvidence` model boundary for every analyzer, including third-party ones. On a line that names a credential field, every quoted literal is hidden, so positional values (an SQL `INSERT ... VALUES` row) are not shown either. PDT also redacts every text field of every plugin finding, in every isolation mode, and parse-error details name the error and its position, never the file's content.
- Every pattern is linear-time on adversarial input. `tests/test_regex_complexity.py` times each package regex against crafted inputs, because a scanned repository is untrusted.
- Findings are INFERRED and require manual validation; patterns can produce false positives.
- Read failures and budget stops are reported as `UNKNOWN` coverage findings, never as clean results.

This is not a complete SAST engine, credential validator, or vulnerability scanner. It does not contact providers to test whether a credential is active. Further security domains remain in the analyzer coverage roadmap.
