# Analyzer Plugin SDK

PDT discovers third-party analyzers through the Python entry-point group:

```toml
[project.entry-points."pdt.analyzers"]
my-analyzer = "my_package.analyzer:MyAnalyzer"
```

A plugin subclasses `project_discovery.analyzers.base.Analyzer` and provides:
- A stable unique `name`.
- `api_version = 1`.
- `supports(FileRecord) -> bool`.
- `analyze(Path, FileRecord) -> list[Finding]`.
- Optional `version`, `description`, `domains` and `languages` metadata.

PDT validates plugin type, API version and unique names. Load failures are preserved as scan diagnostics rather than silently discarded. Plugin order is deterministic by entry-point name.

Plugins execute in the PDT process and inherit its filesystem/network permissions. Only install trusted plugins. The core contract expects plugins to be local-only and read-only with respect to analyzed projects; PDT does not sandbox plugin code or enforce network isolation at the operating-system level.
