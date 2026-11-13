# Contributing

## Changelog

Every change that a user, a report consumer or a plugin author can notice gets an entry in [CHANGELOG.md](CHANGELOG.md) under **Unreleased**, in the pull request that makes it, in the section it belongs to (Added, Changed, Fixed, Performance):

- **Behavior:** new analyzers, findings, options and defaults, and changed limits.
- **Report schema:** an addition bumps the minor version of `REPORT_SCHEMA_VERSION` in `src/project_discovery/models.py` and is described as "Report schema X.Y"; a removal or rename needs a new major version. `compare` and the project catalog read any 1.x report.
- **Plugin API:** version 1 is defined in the [Plugin SDK](docs/guides/PLUGIN_SDK.md#compatibility-policy). Additions must be optional; any other change needs `Analyzer.api_version` 2 and a changelog entry that says what breaks.
- **Fixes:** name the defect register ID (`PDT-123`) when the defect is in the [audit](docs/project/AUDIT.md).

A pull request that changes `src/` or `native/` without changing `CHANGELOG.md` fails the `changelog` CI job. The `skip-changelog` label is for changes nobody can notice, such as refactoring, tests and CI.

## Documentation

- Documentation describes what the code does. Plans belong in the [roadmap](docs/project/ROADMAP.md), whose checkboxes are ticked only for work implemented end to end and tested.
- [CAPABILITY_MATRIX.md](docs/architecture/CAPABILITY_MATRIX.md) is generated: after changing languages, grammars, analyzers, domains or the files tests use, run `python tools/capability_matrix.py --write`.
- The per-analyzer limit table in [ANALYZER_RESOURCE_BUDGETS.md](docs/architecture/ANALYZER_RESOURCE_BUDGETS.md) is generated from each analyzer's `limits` declaration: after changing one, run `python tools/analyzer_limits.py --write`. A new analyzer declares its limits, and records a cap it reaches with `limit_reached` or `over_limit` (`core/limits.py`).
- `tests/test_documentation.py` checks the README figures, documented `pdt` options, links and anchors, the capability matrix, and plugin API version 1 against the code.

## Tests

- `python -m pytest` must pass on Linux and Windows; CI also runs macOS and CPython 3.11 to 3.14.
- `ruff check . --select E9,F,B,PLE` must pass.
- Every fix comes with a regression test, and every regular expression stays linear on adversarial input (`tests/test_regex_complexity.py`).
