"""Lockfile formats beyond the original sixteen: CocoaPods, Gradle, Conan, vcpkg, Bun, Deno,
renv, Julia, Cabal, Stack, rebar3, Carton, Crystal shards, DUB, packages.config, PEP 751 and
Carthage."""
from __future__ import annotations

import json

import pytest

from project_discovery.analyzers.dependencies.lockfile_parsers import (
    OSV_ECOSYSTEMS,
    lockfile_key,
    parse_lockfile,
)


def _packages(parsed) -> set[tuple[str, str, str]]:
    return {(item.ecosystem, item.name, item.version) for item in parsed}


def test_lockfile_keys_name_formats_by_file_name_or_path():
    assert lockfile_key("ios/Podfile.lock") == "podfile.lock"
    assert lockfile_key("C:\\work\\app\\gradle.lockfile") == "gradle.lockfile"
    assert lockfile_key("pylock.toml") == lockfile_key("deps/pylock.dev.toml") == "pylock.toml"
    assert lockfile_key("pylock.a.b.toml") is None
    assert lockfile_key("build/vcpkg_installed/vcpkg/status") == "vcpkg-status"
    assert lockfile_key("vcpkg/installed/vcpkg/status") == "vcpkg-status"
    assert lockfile_key("etc/status") is None and lockfile_key("vcpkg-status") is None
    assert lockfile_key("src/main.py") is None


def test_cocoapods_podfile_lock():
    source = (
        "PODS:\n  - Alamofire (5.8.1)\n  - Firebase/Core (10.0.0):\n    - FirebaseAnalytics (= 10.0.0)\n"
        "  - Firebase/Messaging (10.0.0)\n  - InHouse (1.0.0)\n  - Local (0.1.0)\n  - \"Quoted+Pod (2.0)\"\n\n"
        "DEPENDENCIES:\n  - Alamofire (~> 5.8)\n\nSPEC REPOS:\n  trunk:\n    - Alamofire\n    - Firebase\n"
        "  \"https://github.com/acme/Specs.git\":\n    - Quoted+Pod\n\nEXTERNAL SOURCES:\n  InHouse:\n"
        "    :git: https://github.com/acme/inhouse.git\n  Local:\n    :path: \"../Local\"\n\n"
        "CHECKOUT OPTIONS:\n  InHouse:\n    :commit: abc\n    :git: https://github.com/acme/inhouse.git\n\n"
        "COCOAPODS: 1.14.3\n")
    parsed = parse_lockfile("Podfile.lock", source)
    assert _packages(parsed) == {("CocoaPods", "Alamofire", "5.8.1"), ("CocoaPods", "Firebase", "10.0.0"),
                                 ("CocoaPods", "Quoted+Pod", "2.0")}
    assert parsed.local == ["Local"] and parsed.non_registry == ["InHouse"]
    assert parsed.registries == {"cdn.cocoapods.org": 2, "github.com": 1}


def test_gradle_dependency_locking():
    source = ("# This is a Gradle generated file for dependency locking.\n"
              "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n"
              "org.slf4j:slf4j-api:2.0.9=runtimeClasspath\nempty=annotationProcessor\n")
    assert _packages(parse_lockfile("gradle.lockfile", source)) == {
        ("Maven", "com.google.guava:guava", "31.1-jre"), ("Maven", "org.slf4j:slf4j-api", "2.0.9")}
    assert len(parse_lockfile("buildscript-gradle.lockfile", source)) == 2


def test_conan_2_and_conan_1_lockfiles():
    conan2 = json.dumps({"version": "0.5", "requires": ["zlib/1.2.13#97d5730b529b4224045fe7090592d4c1%1692672717.68",
                                                         "openssl/3.1.2"],
                         "build_requires": ["cmake/3.27.0#abc"], "python_requires": []})
    assert _packages(parse_lockfile("conan.lock", conan2)) == {
        ("ConanCenter", "zlib", "1.2.13"), ("ConanCenter", "openssl", "3.1.2"), ("ConanCenter", "cmake", "3.27.0")}
    conan1 = json.dumps({"version": "0.4", "graph_lock": {"nodes": {
        "0": {"ref": "conanfile", "path": "conanfile.txt"},
        "1": {"ref": "fmt/9.1.0@acme/stable#rev", "requires": []},
        "2": {"pref": "spdlog/1.11.0#rev:package#prev"}}}})
    assert _packages(parse_lockfile("conan.lock", conan1)) == {("ConanCenter", "fmt", "9.1.0"),
                                                              ("ConanCenter", "spdlog", "1.11.0")}


def test_vcpkg_installed_ports():
    source = ("Package: zlib\nVersion: 1.3.1\nPort-Version: 0\nArchitecture: x64-windows\nMulti-Arch: same\n"
              "Description: A compression library\n  continued description\nStatus: install ok installed\n\n"
              "Package: zlib\nFeature: core\nArchitecture: x64-windows\nStatus: install ok installed\n\n"
              "Package: fmt\nVersion: 10.1.1\nPort-Version: 2\nArchitecture: x64-windows\n"
              "Status: install ok installed\n\nPackage: gone\nVersion: 1.0\nStatus: purge ok not-installed\n")
    assert _packages(parse_lockfile("vcpkg_installed/vcpkg/status", source)) == {
        ("vcpkg", "zlib", "1.3.1"), ("vcpkg", "fmt", "10.1.1#2")}


def test_bun_text_lockfile_with_trailing_commas():
    source = ('{\n  "lockfileVersion": 1,\n  "workspaces": {\n    "": { "name": "app", },\n  },\n'
              '  "packages": {\n    "lodash": ["lodash@4.17.21", "", {}, "sha512-x"],\n'
              '    "@types/node": ["@types/node@20.11.0", "", { "dependencies": {} }, "sha512-y",],\n'
              '    "inhouse": ["inhouse@1.0.0", "https://npm.acme.example/inhouse/-/inhouse-1.0.0.tgz", {}, "s"],\n'
              '    "member": ["member@workspace:packages/member"],\n'
              '    "fork": ["fork@github:acme/fork#abc", {}],\n    "text": ["text@1.0.0", "a \\"],\\" b", {}],\n  },\n}\n')
    parsed = parse_lockfile("bun.lock", source)
    assert _packages(parsed) == {("npm", "lodash", "4.17.21"), ("npm", "@types/node", "20.11.0"),
                                 ("npm", "inhouse", "1.0.0"), ("npm", "text", "1.0.0")}
    assert parsed.local == ["member"] and parsed.non_registry == ["fork"]
    assert parsed.registries == {"npm.acme.example": 1}


def test_deno_lockfiles_hold_npm_and_jsr_packages():
    v4 = json.dumps({"version": "4", "specifiers": {"npm:lodash@^4": "4.17.21"},
                     "jsr": {"@std/path@1.0.8": {"integrity": "x"}},
                     "npm": {"lodash@4.17.21": {"integrity": "y"}, "react-dom@18.2.0_react@18.2.0": {"integrity": "z"}},
                     "remote": {"https://user:token@deno.land/std@0.200.0/path/mod.ts?x=1": "hash"}})
    parsed = parse_lockfile("deno.lock", v4)
    assert _packages(parsed) == {("npm", "lodash", "4.17.21"), ("npm", "react-dom", "18.2.0"),
                                 ("JSR", "@std/path", "1.0.8")}
    assert parsed.non_registry == ["deno.land/std@0.200.0/path/mod.ts"]
    v3 = json.dumps({"version": "3", "packages": {"npm": {"chalk@5.3.0": {}}, "jsr": {}}})
    assert _packages(parse_lockfile("deno.lock", v3)) == {("npm", "chalk", "5.3.0")}


def test_renv_lockfile():
    source = json.dumps({
        "R": {"Version": "4.3.1", "Repositories": [{"Name": "CRAN", "URL": "https://cloud.r-project.org"}]},
        "Packages": {
            "dplyr": {"Package": "dplyr", "Version": "1.1.4", "Source": "Repository", "Repository": "CRAN"},
            "Biobase": {"Package": "Biobase", "Version": "2.62.0", "Source": "Bioconductor"},
            "fork": {"Package": "fork", "Version": "0.1", "Source": "GitHub", "RemoteUsername": "acme"},
            "mine": {"Package": "mine", "Version": "0.1", "Source": "Local"},
        }})
    parsed = parse_lockfile("renv.lock", source)
    assert _packages(parsed) == {("CRAN", "dplyr", "1.1.4"), ("Bioconductor", "Biobase", "2.62.0")}
    assert parsed.local == ["mine"] and parsed.non_registry == ["fork"]
    assert parsed.registries == {"cloud.r-project.org": 1}


def test_julia_manifests_in_both_formats():
    format2 = ('julia_version = "1.10.0"\nmanifest_format = "2.0"\n\n[[deps.JSON]]\ndeps = ["Dates"]\n'
               'uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"\nversion = "0.21.4"\n\n[[deps.Dates]]\n'
               'uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"\n\n[[deps.Mine]]\npath = "../Mine"\n'
               'uuid = "11111111-1111-1111-1111-111111111111"\nversion = "0.1.0"\n')
    parsed = parse_lockfile("Manifest.toml", format2)
    assert _packages(parsed) == {("Julia", "JSON", "0.21.4")} and parsed.local == ["Mine"]
    format1 = '[[Example]]\nuuid = "7876af07-990d-54b4-ab0e-23690620f79a"\nversion = "0.5.3"\n'
    assert _packages(parse_lockfile("JuliaManifest.toml", format1)) == {("Julia", "Example", "0.5.3")}


def test_haskell_cabal_freeze_and_stack_lock():
    freeze = ("active-repositories: hackage.haskell.org:merge\nconstraints: any.Cabal ==3.8.1.0,\n"
              "             any.aeson ==2.1.2.1,\n             aeson -ordered-keymap,\n"
              "             any.base installed,\n             any.text ==2.0.2\nindex-state: hackage.haskell.org 2023\n")
    assert _packages(parse_lockfile("cabal.project.freeze", freeze)) == {
        ("Hackage", "Cabal", "3.8.1.0"), ("Hackage", "aeson", "2.1.2.1"), ("Hackage", "text", "2.0.2")}
    stack = ("packages:\n- completed:\n    hackage: acme-missiles-0.3@sha256:2ba66a09,613\n    pantry-tree:\n"
             "      sha256: abc\n  original:\n    hackage: acme-missiles-0.3\n- completed:\n"
             "    git: https://github.com/acme/fork\n    commit: abc\n  original:\n    git: https://github.com/acme/fork\n")
    parsed = parse_lockfile("stack.yaml.lock", stack)
    assert _packages(parsed) == {("Hackage", "acme-missiles", "0.3")}
    assert parsed.non_registry == ["github.com/acme/fork"]


def test_erlang_perl_crystal_and_d_lockfiles():
    rebar = ('{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>},0},\n'
             ' {<<"cowlib">>,{pkg,<<"cowlib">>,<<"2.12.1">>},1},\n'
             ' {<<"mine">>,{git,"https://github.com/acme/mine.git",{ref,"abc"}},0}]}.\n')
    parsed = parse_lockfile("rebar.lock", rebar)
    assert _packages(parsed) == {("Hex", "cowboy", "2.10.0"), ("Hex", "cowlib", "2.12.1")}
    assert parsed.non_registry == ["mine"] and parsed.registries == {"repo.hex.pm": 2}
    carton = ("# carton snapshot format: version 1.0\nDISTRIBUTIONS\n  Moose-2.2200\n"
              "    pathname: E/ET/ETHER/Moose-2.2200.tar.gz\n    provides:\n      Moose 2.2200\n"
              "  libwww-perl-6.72\n    pathname: O/OA/OALDERS/libwww-perl-6.72.tar.gz\n")
    assert _packages(parse_lockfile("cpanfile.snapshot", carton)) == {("CPAN", "Moose", "2.2200"),
                                                                     ("CPAN", "libwww-perl", "6.72")}
    shard = ("version: 2.0\nshards:\n  kemal:\n    git: https://github.com/kemalcr/kemal.git\n    version: 1.4.0\n"
             "  radix:\n    github: luislavena/radix\n    version: 0.4.1\n  mine:\n    path: ../mine\n")
    parsed = parse_lockfile("shard.lock", shard)
    assert _packages(parsed) == {("Crystal", "kemal", "1.4.0"), ("Crystal", "radix", "0.4.1")}
    assert parsed.local == ["mine"] and parsed.registries == {"github.com": 2}
    dub = json.dumps({"fileVersion": 1, "versions": {"vibe-d": "0.9.7", "mine": {"path": "../mine"},
                                                      "fork": {"repository": "git+https://x/y", "version": "abc"}}})
    parsed = parse_lockfile("dub.selections.json", dub)
    assert _packages(parsed) == {("DUB", "vibe-d", "0.9.7")}
    assert parsed.local == ["mine"] and parsed.non_registry == ["fork"]


def test_nuget_packages_config_pylock_and_carthage():
    config = ('<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE packages [<!ENTITY x "boom">]>\n<packages>\n'
              '  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net48" />\n'
              '  <package version="4.5.0" id="System.Memory" />\n  <package id="NoVersion" />\n</packages>\n')
    assert _packages(parse_lockfile("packages.config", config)) == {("NuGet", "Newtonsoft.Json", "13.0.1"),
                                                                  ("NuGet", "System.Memory", "4.5.0")}
    pylock = ('lock-version = "1.0"\ncreated-by = "test"\n\n[[packages]]\nname = "attrs"\nversion = "25.1.0"\n'
              'index = "https://pypi.org/simple"\n\n[[packages]]\nname = "mine"\ndirectory = { path = "." }\n\n'
              '[[packages]]\nname = "fork"\nvcs = { type = "git", url = "https://github.com/a/b", commit-id = "c" }\n')
    parsed = parse_lockfile("pylock.dev.toml", pylock)
    assert _packages(parsed) == {("PyPI", "attrs", "25.1.0")}
    assert parsed.local == ["mine"] and parsed.non_registry == ["fork"] and parsed.registries == {"pypi.org": 1}
    carthage = ('github "Alamofire/Alamofire" "5.8.1"\ngit "https://user:pw@example.com/repo.git" "1.0"\n'
                'binary "https://example.com/spec.json?token=x" "2.0"\n')
    parsed = parse_lockfile("Cartfile.resolved", carthage)
    assert list(parsed) == []
    assert parsed.non_registry == ["Alamofire/Alamofire", "example.com/repo.git", "example.com/spec.json"]


@pytest.mark.parametrize("name", ["Podfile.lock", "gradle.lockfile", "conan.lock", "bun.lock", "deno.lock",
                                  "renv.lock", "Manifest.toml", "cabal.project.freeze", "stack.yaml.lock",
                                  "rebar.lock", "cpanfile.snapshot", "shard.lock", "dub.selections.json",
                                  "packages.config", "pylock.toml", "Cartfile.resolved"])
def test_empty_and_unrelated_content_gives_no_packages(name: str):
    for source in ("", "\n", "# nothing\n"):
        try:
            parsed = parse_lockfile(name, source)
        except ValueError:
            continue  # a JSON or TOML format refuses non-JSON text: an UNKNOWN finding, not packages
        assert list(parsed) == [], (name, source)


def test_only_ecosystems_osv_publishes_are_queried_online():
    assert {"Maven", "ConanCenter", "CRAN", "Bioconductor", "Hackage", "Hex", "NuGet", "PyPI", "npm"} <= OSV_ECOSYSTEMS
    assert not {"CocoaPods", "vcpkg", "JSR", "Julia", "CPAN", "Crystal", "DUB", "Carthage"} & OSV_ECOSYSTEMS
