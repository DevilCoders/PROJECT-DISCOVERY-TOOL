"""The registry hosts lockfiles record for their packages: hosts only, never full URLs."""
from __future__ import annotations

import json

from project_discovery.analyzers.dependencies.lockfile_parsers import parse_lockfile, registry_host

SECRET = "npm-token" + "-0123456789"


def test_npm_yarn_and_pnpm_download_hosts():
    npm = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
        "node_modules/@acme/internal": {"version": "2.0.0",
                                        "resolved": f"https://ci:{SECRET}@npm.acme.example/@acme/internal/-/i-2.0.0.tgz"},
        "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
    }})
    parsed = parse_lockfile("package-lock.json", npm)
    assert parsed.registries == {"registry.npmjs.org": 2, "npm.acme.example": 1}
    assert SECRET not in repr(parsed.registries)
    yarn = ('lodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"\n'
            '  integrity sha512-x\n\n"@acme/x@^1", "@acme/x@^1.1":\n  version "1.1.0"\n'
            '  resolved "https://npm.acme.example/@acme/x/-/x-1.1.0.tgz"\n')
    assert parse_lockfile("yarn.lock", yarn).registries == {"npm.acme.example": 1, "registry.yarnpkg.com": 1}
    pnpm = ("lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n"
            "  '@acme/x@1.0.0':\n    resolution: {integrity: sha512-y, tarball: https://npm.acme.example/x-1.0.0.tgz}\n")
    assert parse_lockfile("pnpm-lock.yaml", pnpm).registries == {"npm.acme.example": 1}


def test_cargo_python_and_other_ecosystems():
    cargo = ('[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
             'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "log"\n'
             'version = "0.4.0"\nsource = "sparse+https://index.crates.io/"\n\n[[package]]\nname = "inner"\n'
             'version = "0.2.0"\nsource = "sparse+https://cargo.acme.example/index/"\n')
    assert parse_lockfile("Cargo.lock", cargo).registries == {"crates.io": 2, "cargo.acme.example": 1}
    uv = ('[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n\n'
          '[[package]]\nname = "inhouse"\nversion = "1.0.0"\nsource = { registry = "https://pypi.acme.example/simple" }\n')
    assert parse_lockfile("uv.lock", uv).registries == {"pypi.acme.example": 1, "pypi.org": 1}
    poetry = ('[[package]]\nname = "requests"\nversion = "2.31.0"\n\n[[package]]\nname = "inhouse"\nversion = "1.0.0"\n'
              '[package.source]\ntype = "legacy"\nurl = "https://pypi.acme.example/simple"\nreference = "acme"\n')
    assert parse_lockfile("poetry.lock", poetry).registries == {"pypi.acme.example": 1, "pypi.org": 1}
    pipfile = json.dumps({"_meta": {"sources": [{"name": "pypi", "url": "https://pypi.org/simple"},
                                                {"name": "acme", "url": "https://pypi.acme.example/simple"}]},
                          "default": {"requests": {"version": "==2.31.0"},
                                      "inhouse": {"version": "==1.0.0", "index": "acme"}}})
    assert parse_lockfile("Pipfile.lock", pipfile).registries == {"pypi.acme.example": 1, "pypi.org": 1}
    composer = json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.0.0",
                                         "dist": {"type": "zip", "url": "https://api.github.com/repos/x/zipball/1"}}]})
    assert parse_lockfile("composer.lock", composer).registries == {"api.github.com": 1}
    gemfile = ("GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n    rack (3.0.0)\n\n"
               "GEM\n  remote: https://gems.acme.example/\n  specs:\n    inhouse (1.0.0)\n")
    assert parse_lockfile("Gemfile.lock", gemfile).registries == {"rubygems.org": 2, "gems.acme.example": 1}
    mix = '%{\n  "plug": {:hex, :plug, "1.15.0", "abc", [:mix], [], "hexpm", "def"},\n}\n'
    assert parse_lockfile("mix.lock", mix).registries == {"repo.hex.pm": 1}
    pub = ('packages:\n  async:\n    dependency: transitive\n    description:\n      name: async\n'
           '      url: "https://pub.dev"\n    source: hosted\n    version: "2.11.0"\n')
    assert parse_lockfile("pubspec.lock", pub).registries == {"pub.dev": 1}
    swift = json.dumps({"pins": [{"identity": "x", "location": "https://github.com/apple/swift-nio.git",
                                  "state": {"version": "2.0.0"}}], "version": 2})
    assert parse_lockfile("Package.resolved", swift).registries == {"github.com": 1}
    # go.sum and NuGet lockfiles do not record where packages came from.
    assert parse_lockfile("go.sum", "golang.org/x/net v0.1.0 h1:abc=\n").registries == {}


def test_registry_hosts_never_keep_more_than_the_host():
    assert registry_host(f"https://user:{SECRET}@npm.example.com:8443/path?token=x") == "npm.example.com"
    for value in ("not a url", "", None, 3, "file:///home/user/pkg.tgz", "https://[::1"):
        assert registry_host(value) is None, value
