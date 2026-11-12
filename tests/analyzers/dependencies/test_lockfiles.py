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
    registry = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    source = f'[[package]]\nname = "a"\nversion = "1"\n{registry}[[package]]\nname = "b"\nversion = "2"\n{registry}'
    with pytest.raises(LockfileEntryBudgetExceeded):
        parse_lockfile("Cargo.lock", source, max_entries=1)
    with pytest.raises(ValueError, match="unsupported"):
        parse_lockfile("requirements.txt", "requests==2.0\n")


def test_npm_v1_source_specifiers_are_not_versions_and_never_leak(tmp_path):
    # Regression: npm v1 lockfiles write git and local dependencies as the version itself.
    # The token-bearing URL reached the report evidence and, with --vuln-online, OSV.dev.
    from project_discovery.analyzers.dependencies.lockfiles import LockfileAnalyzer
    from project_discovery.models import FileRecord

    secret = "ghp_" + "A" * 36
    lock = {
        "lockfileVersion": 1,
        "dependencies": {
            "private-lib": {"version": f"git+https://ci:{secret}@github.example/org/lib.git#0123abc"},
            "local-lib": {"version": "file:../local-lib"},
            "shorthand": {"version": "github:org/repo#main"},
            "aliased": {"version": "npm:real-package@2.4.1"},
            "left-pad": {"version": "1.3.0"},
        },
    }
    source = json.dumps(lock)
    parsed = parse_lockfile("package-lock.json", source)
    assert {(item.name, item.version) for item in parsed} == {("real-package", "2.4.1"), ("left-pad", "1.3.0")}
    assert parsed.non_registry == ["private-lib", "shorthand"] and parsed.local == ["local-lib"]
    path = tmp_path / "package-lock.json"
    path.write_text(source, encoding="utf-8")
    record = FileRecord("package-lock.json", path.stat().st_size, ".json", "JSON")
    findings = LockfileAnalyzer().analyze(path, record)
    text = json.dumps([finding.to_dict() for finding in findings])
    assert secret not in text and "github.example" not in text and "../local-lib" not in text
    gap = next(finding for finding in findings if finding.title.startswith("Dependencies outside"))
    assert gap.confidence == "UNKNOWN" and gap.evidence[1:] == ["private-lib", "shorthand"]


def test_project_workspace_and_path_packages_are_local_never_registry_lookups():
    # Regression: the project's own crate, uv editable and workspace members, Gemfile PATH
    # gems and pubspec path packages were sent to OSV.dev and matched against registry
    # advisories; git sources were treated as registry releases.
    cargo = (
        '[[package]]\nname = "my-app"\nversion = "0.1.0"\n\n'
        '[[package]]\nname = "helper"\nversion = "0.1.0"\nsource = "git+https://example.org/helper.git#abc"\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    parsed = parse_lockfile("Cargo.lock", cargo)
    assert [(item.name, item.version) for item in parsed] == [("serde", "1.0.200")]
    assert parsed.local == ["my-app"] and parsed.non_registry == ["helper"]
    uv = (
        '[[package]]\nname = "app"\nversion = "1.0.0"\nsource = { editable = "." }\n\n'
        '[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n'
    )
    parsed = parse_lockfile("uv.lock", uv)
    assert [item.name for item in parsed] == ["requests"] and parsed.local == ["app"]
    npm = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "root-app", "version": "1.0.0"},
        "packages/ui": {"name": "@acme/ui", "version": "2.0.0"},
        "node_modules/@acme/ui": {"resolved": "packages/ui", "link": True},
        "node_modules/react": {"version": "18.2.0"},
    }})
    parsed = parse_lockfile("package-lock.json", npm)
    assert [item.name for item in parsed] == ["react"]
    assert parsed.local == ["@acme/ui", "root-app"]
    gems = (
        "PATH\n  remote: engines/billing\n  specs:\n    billing (0.1.0)\n\n"
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.8)\n\n"
    )
    parsed = parse_lockfile("Gemfile.lock", gems)
    assert [item.name for item in parsed] == ["rack"] and parsed.local == ["billing"]
    pub = (
        "packages:\n  shared:\n    dependency: direct main\n    description:\n      path: ../shared\n"
        "    source: path\n    version: \"0.0.1\"\n  http:\n    dependency: direct main\n"
        "    source: hosted\n    version: \"1.1.0\"\n"
    )
    parsed = parse_lockfile("pubspec.lock", pub)
    assert [item.name for item in parsed] == ["http"] and parsed.local == ["shared"]


def test_aliased_dependencies_are_matched_under_the_real_package():
    # Regression: yarn npm: aliases, mix.lock keys and ssh:// Swift URLs gave names that
    # no advisory uses, so their vulnerabilities could never match.
    yarn = '"lodash4@npm:lodash@^4.17.15":\n  version "4.17.20"\n'
    assert _pairs("yarn.lock", yarn) == {("lodash", "4.17.20")}
    berry = '"my-app@workspace:.":\n  version: 0.0.0-use.local\n\n"left-pad@npm:^1.3.0":\n  version: 1.3.0\n'
    parsed = parse_lockfile("yarn.lock", berry)
    assert [(item.name, item.version) for item in parsed] == [("left-pad", "1.3.0")] and parsed.local == ["my-app"]
    mix = '%{\n  "my_jason": {:hex, :jason, "1.4.0", "e855", [:mix], [], "hexpm", "abc"},\n}\n'
    assert _pairs("mix.lock", mix) == {("jason", "1.4.0")}
    swift = json.dumps({"pins": [{"location": "ssh://git@github.com/apple/swift-log.git",
                                  "state": {"version": "1.5.3"}}], "version": 2})
    assert _pairs("Package.resolved", swift) == {("github.com/apple/swift-log", "1.5.3")}
