# PDT documentation

## Architecture
- [Architecture](architecture/ARCHITECTURE.md): pipeline stages, components, trust boundaries and plugin execution.
- [Native execution backend](architecture/NATIVE_ENGINE.md): native extensions, bounded concurrent analysis, persistence and resume.
- [Code intelligence](architecture/CODE_INTELLIGENCE.md): the shared code model, code facts, the cross-file index and the domain analyzers built on them.
- [Polyglot parsing](architecture/POLYGLOT_PARSERS.md): the language catalog, capability levels and optional Tree-sitter grammars.
- [Capability matrix](architecture/CAPABILITY_MATRIX.md): every language and analyzer domain with its level, analyzers and test fixtures (generated).
- [Analyzer domain coverage](architecture/ANALYZER_COVERAGE.md): what each analyzer domain covers today.
- [Analyzer resource budgets](architecture/ANALYZER_RESOURCE_BUDGETS.md): per-analyzer byte, entry and time limits.
- [Fingerprint cache](architecture/CACHE.md): incremental hashing and how cached digests are validated.

## Analyzers
- [API contracts](analyzers/API_ANALYZER.md): contracts, source routes and API styles.
- [Archives](analyzers/ARCHIVE_ANALYZER.md): metadata-only archive inspection and its budgets.
- [Configuration](analyzers/CONFIGURATION_ANALYZER.md): configuration inventory and risky settings.
- [Documentation formats](analyzers/DOCUMENTATION_FORMATS.md): structural extraction from documentation files.
- [Licenses](analyzers/LICENSE_ANALYZER.md): SPDX headers and license declarations.
- [Lockfiles](analyzers/LOCKFILE_ANALYZER.md): resolved dependencies and local OSV matching.
- [Network indicators](analyzers/NETWORK_ANALYZER.md): addresses, URLs, host names, the Public Suffix List and protocol markers.
- [ORM and data mapping](analyzers/ORM_ANALYZER.md): Prisma schemas.
- [SQL and migrations](analyzers/SQL_ANALYZER.md): schema inventory and destructive statements.
- [ROS](analyzers/ROS_ANALYZER.md): ROS 1 and ROS 2 packages, nodes and interfaces.
- [AI/ML and robotics](analyzers/AI_ML_AND_ROBOTICS.md): ML frameworks, model artifacts and robotics.
- [Tests and builds](analyzers/TEST_BUILD_ANALYZERS.md): test discovery and build manifests.
- [Security analysis](analyzers/SECURITY_ANALYZERS.md): the security analyzers and how to read their findings.
- [Secret scanning](analyzers/SECURITY_ANALYZER.md): credential formats, redaction and budgets.

## Guides
- [CLI reference](guides/CLI_REFERENCE.md): every command and option, with examples.
- [Operations](guides/OPERATIONS.md): running large scans, exit codes, resume and performance data.
- [Plugin SDK](guides/PLUGIN_SDK.md): writing analyzer plugins and how PDT isolates them.
- [Benchmarks](guides/BENCHMARKS.md): the benchmark tool and measured results.
- [Multi-project intelligence](guides/MULTI_PROJECT_INTELLIGENCE.md): comparing reports and integration maps.
- [Local project catalog](guides/PROJECT_CATALOG.md): registering and comparing local reports.
- [Online mode](guides/ONLINE_MODE.md): scanning remote repositories with and without downloading, and online advisory sources.

## Project
- [Production roadmap](project/ROADMAP.md): the plan and the verified status of every capability.
- [Production-readiness audit](project/AUDIT.md): the audit and its defect register.
- [Changelog](../CHANGELOG.md) and [contribution rules](../CONTRIBUTING.md)
