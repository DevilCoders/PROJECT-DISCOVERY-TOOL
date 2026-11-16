"""The dependency graphs lockfiles record: direct dependencies and each package's parent path,
and the path a vulnerability finding reports."""
from __future__ import annotations

import json
from pathlib import Path

from project_discovery.analyzers.dependencies import dependency_graph, lockfile_parsers
from project_discovery.analyzers.dependencies.lockfile_parsers import parse_lockfile
from project_discovery.cli import run_scan
from project_discovery.vulnerabilities.database import VulnerabilityDatabase


def _path(lockfile: str, source: str, name: str, version: str) -> str | None:
    graph = parse_lockfile(lockfile, source).graph
    path = graph.path(name, version)
    return None if path is None else " > ".join(f"{item}@{release}" for item, release in path)


def _direct(lockfile: str, source: str) -> set[str]:
    graph = parse_lockfile(lockfile, source).graph
    assert graph.direct_known
    return set(graph.direct)


NPM_V3 = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app", "dependencies": {"express": "^4.17.0", "lodash4": "npm:lodash@^4.17.0"},
         "devDependencies": {"jest": "^29.0.0"}},
    "node_modules/express": {"version": "4.17.1", "dependencies": {"body-parser": "1.19.0", "qs": "6.7.0"}},
    "node_modules/body-parser": {"version": "1.19.0", "dependencies": {"qs": "6.9.0"}},
    "node_modules/body-parser/node_modules/qs": {"version": "6.9.0"},  # nested: body-parser loads its own
    "node_modules/qs": {"version": "6.7.0"},
    "node_modules/lodash4": {"name": "lodash", "version": "4.17.21"},
    "node_modules/jest": {"version": "29.0.0"},
    "packages/member": {"name": "member", "dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/member": {"resolved": "packages/member", "link": True},
    "node_modules/left-pad": {"version": "1.3.0"}}})


def test_npm_lockfiles_resolve_as_node_does():
    assert _direct("package-lock.json", NPM_V3) == {"express", "lodash", "jest", "left-pad"}
    assert _path("package-lock.json", NPM_V3, "qs", "6.9.0") == "express@4.17.1 > body-parser@1.19.0 > qs@6.9.0"
    assert _path("package-lock.json", NPM_V3, "qs", "6.7.0") == "express@4.17.1 > qs@6.7.0"
    assert _path("package-lock.json", NPM_V3, "lodash", "4.17.21") == "lodash@4.17.21"  # an alias, direct
    v1 = json.dumps({"lockfileVersion": 1, "requires": True, "dependencies": {
        "express": {"version": "4.17.1", "requires": {"qs": "6.7.0", "debug": "2.6.9"}, "dependencies": {
            "debug": {"version": "2.6.9", "requires": {"ms": "2.0.0"}}}},
        "ms": {"version": "2.0.0"}, "qs": {"version": "6.7.0"}, "debug": {"version": "4.3.4"}}})
    # v1 names no direct dependencies: paths start at packages nothing depends on.
    assert _path("package-lock.json", v1, "ms", "2.0.0") == "express@4.17.1 > debug@2.6.9 > ms@2.0.0"
    assert _path("package-lock.json", v1, "debug", "4.3.4") == "debug@4.3.4"


def test_yarn_and_pnpm_lockfiles():
    yarn_v1 = ('express@^4.17.0:\n  version "4.17.1"\n  resolved "https://registry.yarnpkg.com/express/-/express-4.17.1.tgz"\n'
               '  dependencies:\n    qs "6.7.0"\n    "@types/node" "^20.0.0"\n\n'
               'qs@6.7.0:\n  version "6.7.0"\n\n"@types/node@^20.0.0":\n  version "20.1.0"\n')
    assert _path("yarn.lock", yarn_v1, "@types/node", "20.1.0") == "express@4.17.1 > @types/node@20.1.0"
    berry = ('__metadata:\n  version: 6\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n'
             '  dependencies:\n    express: "npm:^4.17.0"\n  languageName: unknown\n\n'
             '"express@npm:^4.17.0":\n  version: 4.17.1\n  resolution: "express@npm:4.17.1"\n  dependencies:\n'
             '    qs: "npm:6.7.0"\n  dependenciesMeta:\n    fsevents:\n      optional: true\n\n'
             '"qs@npm:6.7.0":\n  version: 6.7.0\n')
    assert _direct("yarn.lock", berry) == {"express"}
    assert _path("yarn.lock", berry, "qs", "6.7.0") == "express@4.17.1 > qs@6.7.0"
    pnpm_v9 = ("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      express:\n"
               "        specifier: ^4.17.0\n        version: 4.17.1\n    devDependencies:\n      '@types/node':\n"
               "        specifier: ^20\n        version: 20.1.0\n\npackages:\n\n  express@4.17.1:\n"
               "    resolution: {integrity: sha512-x}\n\n  qs@6.7.0:\n    resolution: {integrity: sha512-y}\n\n"
               "  '@types/node@20.1.0':\n    resolution: {integrity: sha512-z}\n\n"
               "  string-width@4.2.3:\n    resolution: {integrity: sha512-w}\n\nsnapshots:\n\n  express@4.17.1:\n"
               "    dependencies:\n      qs: 6.7.0\n      string-width-cjs: string-width@4.2.3\n\n  qs@6.7.0: {}\n\n"
               "  '@types/node@20.1.0': {}\n\n  string-width@4.2.3: {}\n")
    assert _direct("pnpm-lock.yaml", pnpm_v9) == {"express", "@types/node"}
    assert _path("pnpm-lock.yaml", pnpm_v9, "qs", "6.7.0") == "express@4.17.1 > qs@6.7.0"
    assert _path("pnpm-lock.yaml", pnpm_v9, "string-width", "4.2.3") == "express@4.17.1 > string-width@4.2.3"
    pnpm_v5 = ("lockfileVersion: 5.4\n\ndependencies:\n  express: 4.17.1\n\npackages:\n\n  /express/4.17.1:\n"
               "    dependencies:\n      qs: 6.7.0_react@18.0.0\n    dev: false\n\n  /qs/6.7.0_react@18.0.0:\n    dev: false\n")
    assert _path("pnpm-lock.yaml", pnpm_v5, "qs", "6.7.0") == "express@4.17.1 > qs@6.7.0"


def test_rust_python_php_and_ruby_lockfiles():
    cargo = ('version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["serde", "tokio 1.0.0"]\n\n'
             '[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
             '[[package]]\nname = "tokio"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
             'dependencies = ["mio 0.8.0 (registry+https://github.com/rust-lang/crates.io-index)"]\n\n'
             '[[package]]\nname = "mio"\nversion = "0.8.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
    assert _direct("Cargo.lock", cargo) == {"serde", "tokio"}
    assert _path("Cargo.lock", cargo, "mio", "0.8.0") == "tokio@1.0.0 > mio@0.8.0"
    uv = ('version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
          'dependencies = [{ name = "httpx" }]\n\n[[package]]\nname = "httpx"\nversion = "0.27.0"\n'
          'source = { registry = "https://pypi.org/simple" }\ndependencies = [{ name = "idna" }]\n\n'
          '[[package]]\nname = "idna"\nversion = "3.7"\nsource = { registry = "https://pypi.org/simple" }\n')
    assert _path("uv.lock", uv, "idna", "3.7") == "httpx@0.27.0 > idna@3.7"
    poetry = ('[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[package.dependencies]\nurllib3 = ">=1.21.1,<3"\n'
              'idna = ">=2.5,<4"\n\n[[package]]\nname = "urllib3"\nversion = "2.2.1"\n\n[[package]]\nname = "idna"\nversion = "3.7"\n')
    assert _path("poetry.lock", poetry, "urllib3", "2.2.1") == "requests@2.31.0 > urllib3@2.2.1"
    pdm = ('[[package]]\nname = "httpx"\nversion = "0.27.0"\ndependencies = ["idna>=2", "sniffio"]\n\n'
           '[[package]]\nname = "idna"\nversion = "3.7"\n\n[[package]]\nname = "sniffio"\nversion = "1.3.1"\n')
    assert _path("pdm.lock", pdm, "sniffio", "1.3.1") == "httpx@0.27.0 > sniffio@1.3.1"
    composer = json.dumps({"packages": [
        {"name": "laravel/framework", "version": "v10.0.0", "require": {"php": "^8.1", "ext-json": "*",
                                                                         "symfony/console": "^6.2"}},
        {"name": "symfony/console", "version": "v6.2.0"}]})
    assert _path("composer.lock", composer, "symfony/console", "v6.2.0") == "laravel/framework@v10.0.0 > symfony/console@v6.2.0"
    gemfile = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n"
               "    actionpack (7.0.4)\n      rack (~> 2.0)\n    rack (2.2.6)\n\nPLATFORMS\n  ruby\n\n"
               "DEPENDENCIES\n  rails (~> 7.0)\n\nBUNDLED WITH\n   2.4.0\n")
    assert _direct("Gemfile.lock", gemfile) == {"rails"}
    assert _path("Gemfile.lock", gemfile, "rack", "2.2.6") == "rails@7.0.4 > actionpack@7.0.4 > rack@2.2.6"


def test_dotnet_dart_cocoapods_erlang_and_others():
    nuget = json.dumps({"version": 1, "dependencies": {"net8.0": {
        "Serilog.AspNetCore": {"type": "Direct", "requested": "[8.0.0, )", "resolved": "8.0.0",
                               "dependencies": {"Serilog": "3.1.1"}},
        "Serilog": {"type": "Transitive", "resolved": "3.1.1"}}}})
    assert _direct("packages.lock.json", nuget) == {"Serilog.AspNetCore"}
    assert _path("packages.lock.json", nuget, "Serilog", "3.1.1") == "Serilog.AspNetCore@8.0.0 > Serilog@3.1.1"
    pubspec = ('packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n'
               '    source: hosted\n    version: "1.2.0"\n  meta:\n    dependency: transitive\n    description:\n'
               '      name: meta\n    source: hosted\n    version: "1.11.0"\n')
    graph = parse_lockfile("pubspec.lock", pubspec).graph
    assert graph.is_direct("http") and graph.is_direct("meta") is False and not graph.edges_known
    assert graph.describe("meta", "1.11.0") == ["dependency: transitive (the lockfile records no parents)"]
    podfile = ("PODS:\n  - Alamofire (5.8.0)\n  - Firebase/Core (10.0.0):\n    - Firebase/CoreOnly\n"
               "    - FirebaseAnalytics (= 10.0.0)\n  - FirebaseAnalytics (10.0.0)\n\nDEPENDENCIES:\n"
               "  - Alamofire (~> 5.8)\n  - Firebase/Core\n\nCOCOAPODS: 1.12.1\n")
    assert _direct("Podfile.lock", podfile) == {"Alamofire", "Firebase"}
    assert _path("Podfile.lock", podfile, "FirebaseAnalytics", "10.0.0") == "Firebase@10.0.0 > FirebaseAnalytics@10.0.0"
    rebar = ('{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.9.0">>},0},\n'
             ' {<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.11.0">>},1}]}.\n')
    graph = parse_lockfile("rebar.lock", rebar).graph
    assert (graph.is_direct("cowboy"), graph.is_direct("cowlib")) == (True, False)
    vcpkg = ("Package: zlib\nVersion: 1.3.1\nArchitecture: x64-windows\nStatus: install ok installed\n\n"
             "Package: curl\nVersion: 8.6.0\nDepends: zlib, openssl:x64-windows\nArchitecture: x64-windows\n"
             "Status: install ok installed\n\nPackage: openssl\nVersion: 3.2.1\nArchitecture: x64-windows\n"
             "Status: install ok installed\n")
    assert _path("vcpkg_installed/vcpkg/status", vcpkg, "zlib", "1.3.1") == "curl@8.6.0 > zlib@1.3.1"
    bun = '{"lockfileVersion": 1, "workspaces": {"": {"name": "app", "dependencies": {"express": "^4"}}}, "packages": {' \
          '"express": ["express@4.17.1", "", {"dependencies": {"qs": "6.7.0"}}, "sha512-x"],' \
          '"qs": ["qs@6.7.0", "", {}, "sha512-y"],}}'
    assert _path("bun.lock", bun, "qs", "6.7.0") == "express@4.17.1 > qs@6.7.0"
    deno = json.dumps({"version": "4", "specifiers": {"npm:express@^4": "4.17.1"}, "npm": {
        "express@4.17.1": {"integrity": "x", "dependencies": ["qs@6.7.0"]}, "qs@6.7.0": {"integrity": "y"}},
        "workspace": {"dependencies": ["npm:express@^4"]}})
    assert _direct("deno.lock", deno) == {"express"}
    assert _path("deno.lock", deno, "qs", "6.7.0") == "express@4.17.1 > qs@6.7.0"
    renv = json.dumps({"R": {"Version": "4.3.0", "Repositories": [{"Name": "CRAN", "URL": "https://cloud.r-project.org"}]},
                       "Packages": {"httr": {"Package": "httr", "Version": "1.4.7", "Source": "Repository",
                                             "Requirements": ["curl", "R6"]},
                                    "curl": {"Package": "curl", "Version": "5.2.0", "Source": "Repository"}}})
    assert _path("renv.lock", renv, "curl", "5.2.0") == "httr@1.4.7 > curl@5.2.0"
    julia = ('manifest_format = "2.0"\n\n[[deps.HTTP]]\nuuid = "cd3eb016-35fb-5094-929b-558a96fad6f3"\nversion = "1.10.0"\n'
             'deps = ["URIs"]\n\n[[deps.URIs]]\nuuid = "5c2747f8-b7ea-4ff2-ba2e-563bfd36b1d4"\nversion = "1.5.1"\n')
    assert _path("Manifest.toml", julia, "URIs", "1.5.1") == "HTTP@1.10.0 > URIs@1.5.1"
    # Formats that record neither: no graph.
    assert parse_lockfile("go.sum", "github.com/x/y v1.0.0 h1:abc=\n").graph is None


def test_cycles_unreached_packages_and_the_edge_limit(monkeypatch):
    cyclic = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"a": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
        "node_modules/orphan": {"version": "1.0.0"}}})
    graph = parse_lockfile("package-lock.json", cyclic).graph
    assert graph.path("b", "1.0.0") == [("a", "1.0.0"), ("b", "1.0.0")]
    assert graph.path("orphan", "1.0.0") is None
    assert graph.describe("orphan", "1.0.0") == [
        "dependency: transitive", "dependency_path: not reached from a direct dependency in the lockfile's graph"]
    monkeypatch.setattr(lockfile_parsers, "MAX_GRAPH_EDGES", 1)
    graph = parse_lockfile("package-lock.json", NPM_V3).graph
    assert graph.truncated and "(the graph was truncated)" in graph.describe("qs", "6.9.0")[-1]
    assert dependency_graph.MAX_PATH_LENGTH >= 100


def test_findings_say_how_a_vulnerable_package_entered_the_project(tmp_path: Path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "qs.json").write_text(json.dumps({"id": "GHSA-hrpp-h998-j3pp", "modified": "2023-01-01T00:00:00Z",
                                               "summary": "qs prototype pollution", "database_specific": {"severity": "HIGH"},
                                               "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                                                             "versions": ["6.9.0", "6.7.0"]}]}), encoding="utf-8")
    (feeds / "express.json").write_text(json.dumps({"id": "GHSA-rv95-896h-c2vc", "modified": "2023-01-01T00:00:00Z",
                                                    "summary": "express open redirect", "affected": [
                                                        {"package": {"ecosystem": "npm", "name": "express"},
                                                         "versions": ["4.17.1"]}]}), encoding="utf-8")
    database = tmp_path / "db.sqlite3"
    with VulnerabilityDatabase(database) as store:
        store.import_osv(feeds)
    project = tmp_path / "project"
    project.mkdir()
    (project / "package-lock.json").write_text(NPM_V3, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True, vulnerability_db=database) in {0, 1}
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    findings = [item for item in report["findings"] if item["category"] == "vulnerabilities"
                and item["confidence"] == "CONFIRMED"]
    qs = next(item for item in findings if "qs@6.9.0" in item["detail"])
    assert "dependency_path: express@4.17.1 > body-parser@1.19.0 > qs@6.9.0" in qs["evidence"]
    assert "dependency: transitive, 2 level(s) below express@4.17.1" in qs["evidence"]
    assert "brought in through express@4.17.1 > body-parser@1.19.0 > qs@6.9.0" in qs["detail"]
    assert "upgrading express may be the way to a patched qs" in qs["recommendation"]
    express = next(item for item in findings if "express@4.17.1 matched" in item["detail"])
    assert "dependency: direct" in express["evidence"]
    inventory = next(item for item in report["findings"] if item["title"].startswith("Resolved dependency inventory"))
    assert "Direct dependencies: 4; transitive: 3." in inventory["detail"]
