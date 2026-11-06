import json

import pytest

from project_discovery.analyzers.dependencies.lockfile_parsers import (
    LockfileEntryBudgetExceeded,
    ResolvedPackage,
    parse_lockfile,
)


def _pairs(name: str, source: str) -> set[tuple[str, str]]:
    return {(item.name, item.version) for item in parse_lockfile(name, source)}


def test_yarn_v1_lockfile_headers_with_newlines_are_parsed():
    # Regression: headers keep their trailing newline when iterated, so
    # endswith(":") never matched and yarn projects produced zero packages.
    source = (
        "# yarn lockfile v1\n\n"
        '"@babel/core@^7.0.0":\n  version "7.21.0"\n  resolved "https://example.invalid/x"\n\n'
        "lodash@^4.17.0, lodash@^4.17.20:\n  version \"4.17.20\"\n"
    )
    assert _pairs("yarn.lock", source) == {("@babel/core", "7.21.0"), ("lodash", "4.17.20")}


def test_yarn_berry_lockfile_is_parsed():
    source = (
        "__metadata:\n  version: 6\n\n"
        '"lodash@npm:^4.17.21":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n'
    )
    assert _pairs("yarn.lock", source) == {("lodash", "4.17.21")}


@pytest.mark.parametrize(("key", "expected"), [
    ("  /lodash/4.17.20:", ("lodash", "4.17.20")),                       # pnpm v5
    ("  /@babel/core/7.21.0:", ("@babel/core", "7.21.0")),               # pnpm v5 scoped
    ("  /react-dom/18.2.0_react@18.2.0:", ("react-dom", "18.2.0")),      # v5 peer suffix
    ("  /lodash@4.17.21:", ("lodash", "4.17.21")),                       # pnpm v6
    ("  /@types/node@20.1.0:", ("@types/node", "20.1.0")),               # v6 scoped
    ("  lodash@4.17.21:", ("lodash", "4.17.21")),                        # pnpm v9
    ("  '@scope/pkg@1.0.0(react@18.0.0)':", ("@scope/pkg", "1.0.0")),   # v9 peers
])
def test_pnpm_lockfile_versions_5_6_and_9(key, expected):
    source = f"lockfileVersion: '6.0'\n\npackages:\n\n{key}\n    resolution: {{integrity: x}}\n"
    assert _pairs("pnpm-lock.yaml", source) == {expected}


def test_pnpm_importers_section_is_not_treated_as_packages():
    source = "importers:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4\n"
    assert parse_lockfile("pnpm-lock.yaml", source) == []


def test_go_sum_ignores_module_graph_only_lines_and_keeps_v_prefix():
    source = (
        "github.com/pkg/errors v0.8.0/go.mod h1:aaa=\n"
        "github.com/pkg/errors v0.9.1 h1:bbb=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:ccc=\n"
    )
    assert _pairs("go.sum", source) == {("github.com/pkg/errors", "v0.9.1")}


def test_nuget_lockfile_is_keyed_by_target_framework():
    source = json.dumps({"version": 1, "dependencies": {"net8.0": {
        "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
        "MyLib": {"type": "Project"},
    }}})
    assert _pairs("packages.lock.json", source) == {("Newtonsoft.Json", "13.0.1")}


def test_gemfile_lock_strips_platform_suffix():
    source = (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    nokogiri (1.15.4-x86_64-linux)\n      racc (~> 1.4)\n    racc (1.7.1)\n\n"
        "PLATFORMS\n  x86_64-linux\n"
    )
    assert _pairs("Gemfile.lock", source) == {("nokogiri", "1.15.4"), ("racc", "1.7.1")}


def test_toml_lockfiles_and_swift_and_pub():
    toml = '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    assert parse_lockfile("uv.lock", toml) == [ResolvedPackage("PyPI", "requests", "2.31.0")]
    swift = json.dumps({"pins": [{
        "identity": "swift-nio", "location": "https://github.com/apple/swift-nio.git",
        "state": {"version": "2.58.0"},
    }], "version": 2})
    assert _pairs("Package.resolved", swift) == {("github.com/apple/swift-nio", "2.58.0")}
    pub = 'packages:\n  http:\n    dependency: "direct main"\n    version: "1.1.0"\nsdks:\n  dart: ">=3.0.0"\n'
    assert _pairs("pubspec.lock", pub) == {("http", "1.1.0")}


def test_entry_budget_and_unsupported_formats_raise():
    source = '[[package]]\nname = "a"\nversion = "1"\n[[package]]\nname = "b"\nversion = "2"\n'
    with pytest.raises(LockfileEntryBudgetExceeded):
        parse_lockfile("Cargo.lock", source, max_entries=1)
    with pytest.raises(ValueError, match="unsupported"):
        parse_lockfile("requirements.txt", "requests==2.0\n")
