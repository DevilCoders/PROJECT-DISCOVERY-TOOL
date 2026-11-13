"""Language packages inside archives: each ecosystem's manifest gives the package's name,
version and dependencies, and the code it runs when installed is a finding."""
from __future__ import annotations

import bz2
import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.content import archive_formats, packages
from test_archive_formats import _analyze, _titles, _zstd_frame


def _zip(path: Path, members: dict[str, bytes | str]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def _tar_bytes(members: dict[str, bytes | str], mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data in members.items():
            payload = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _package(path: Path, file_type: str):
    summaries, members, findings = _analyze(path, file_type)
    return summaries[path.name].get("package"), findings


_METADATA = ("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nSummary: A demo\nLicense: MIT\n"
             "Requires-Python: >=3.9\nRequires-Dist: requests (>=2)\nRequires-Dist: rich; extra == 'cli'\n\n"
             "Long description\nName: not-a-header\n")


def test_a_wheel_names_its_package_and_a_startup_hook_is_install_code(tmp_path: Path):
    path = _zip(tmp_path / "demo-1.0-py3-none-any.whl", {
        "demo/__init__.py": "", "demo-1.0.dist-info/METADATA": _METADATA,
        "demo-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\n", "demo.pth": "import os; os.system('id')\n",
        "plain.pth": "/opt/demo/lib\n",
    })
    package, findings = _package(path, "package/wheel")
    assert package == {
        "ecosystem": "pypi", "manifest": "demo-1.0.dist-info/METADATA", "name": "demo", "version": "1.0",
        "summary": "A demo", "license": "MIT", "requires_python": ">=3.9", "dependencies": ["requests (>=2)", "rich"],
        "dependency_count": 2, "install_code": ["demo.pth: import os; os.system('id')"],
    }
    inventory = next(item for item in findings if item.title.startswith("ZIP archive inventory"))
    assert inventory.evidence[0] == "package: demo 1.0 (pypi)"
    hook = next(item for item in findings if item.title.startswith("Package runs code when installed"))
    assert hook.severity == "MEDIUM" and hook.evidence == [f"{path.name}::demo.pth: import os; os.system('id')"]


def test_a_zip_package_is_named_even_when_the_wall_time_ends_its_sampling(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.content import archives

    # Already spent when the inspection starts (Windows' monotonic clock ticks every ~15 ms).
    monkeypatch.setattr(archives, "_MAX_ARCHIVE_WALL_SECONDS", -1.0)
    members = {f"demo/module{index}.py": "x = 1\n" * 100 for index in range(50)}
    members["demo-1.0.dist-info/METADATA"] = _METADATA  # last, as in a wheel
    path = _zip(tmp_path / "demo-1.0-py3-none-any.whl", members)
    summaries, _, _ = _analyze(path, "package/wheel")
    assert summaries[path.name]["state"] == "budget-stopped"
    assert (summaries[path.name]["package"]["name"], summaries[path.name]["package"]["version"]) == ("demo", "1.0")


def test_an_npm_tarball_names_its_install_scripts(tmp_path: Path):
    manifest = {"name": "demo", "version": "2.0.0", "license": "ISC", "dependencies": {"left-pad": "^1", "chalk": "5"},
                "scripts": {"postinstall": "node scripts/fetch.js", "test": "jest"}}
    path = tmp_path / "demo-2.0.0.tgz"
    path.write_bytes(_tar_bytes({"package/package.json": json.dumps(manifest), "package/index.js": "x"}, "w:gz"))
    package, findings = _package(path, "archive/gzip")
    assert (package["ecosystem"], package["name"], package["version"]) == ("npm", "demo", "2.0.0")
    assert package["dependencies"] == ["chalk", "left-pad"]
    assert package["install_scripts"] == {"postinstall": "node scripts/fetch.js"}
    assert "Package runs code when installed" in _titles(findings)


def test_a_gem_crate_and_sdist_name_their_packages(tmp_path: Path):
    gemspec = ("--- !ruby/object:Gem::Specification\nname: demo\nversion: !ruby/object:Gem::Version\n"
               "  version: 3.1.4\nplatform: ruby\ndependencies:\n- !ruby/object:Gem::Dependency\n  name: rake\n"
               "  type: :development\nextensions:\n- ext/demo/extconf.rb\nlicense: MIT\n")
    gem = tmp_path / "demo-3.1.4.gem"
    gem.write_bytes(_tar_bytes({"metadata.gz": gzip.compress(gemspec.encode()),
                                "data.tar.gz": _tar_bytes({"lib/demo.rb": "puts 1"}, "w:gz")}))
    package, _ = _package(gem, "archive/tar")
    assert {key: package[key] for key in ("ecosystem", "name", "version", "dependencies", "extensions")} == {
        "ecosystem": "rubygems", "name": "demo", "version": "3.1.4", "dependencies": ["rake"],
        "extensions": ["ext/demo/extconf.rb"]}
    crate = tmp_path / "demo-0.1.0.crate"
    crate.write_bytes(_tar_bytes({
        "demo-0.1.0/Cargo.toml": '[package]\nname = "demo"\nversion = "0.1.0"\n[dependencies]\nserde = "1"\n',
        "demo-0.1.0/build.rs": "fn main() {}", "demo-0.1.0/src/lib.rs": ""}, "w:gz"))
    package, _ = _package(crate, "archive/gzip")
    assert (package["ecosystem"], package["name"], package["dependencies"], package["build_script"]) == (
        "crates.io", "demo", ["serde"], True)
    sdist = tmp_path / "demo-1.0.tar.gz"
    sdist.write_bytes(_tar_bytes({"demo-1.0/PKG-INFO": _METADATA, "demo-1.0/setup.py": ""}, "w:gz"))
    package, _ = _package(sdist, "archive/gzip")
    assert (package["ecosystem"], package["manifest"], package["name"]) == ("pypi", "demo-1.0/PKG-INFO", "demo")


def test_nuget_jar_go_composer_and_vsix_packages(tmp_path: Path):
    nuspec = ('<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
              "<metadata><id>Demo.Lib</id><version>4.5.6</version><authors>Example</authors><dependencies>"
              '<group><dependency id="Newtonsoft.Json" version="13.0.1"/></group></dependencies></metadata></package>')
    package, findings = _package(_zip(tmp_path / "Demo.Lib.4.5.6.nupkg", {
        "Demo.Lib.nuspec": nuspec, "tools/install.ps1": "Write-Host hi", "lib/net8.0/Demo.dll": "MZ"}), "package/nupkg")
    assert (package["ecosystem"], package["name"], package["version"], package["dependencies"]) == (
        "nuget", "Demo.Lib", "4.5.6", ["Newtonsoft.Json"])
    assert package["install_code"] == ["tools/install.ps1: a PowerShell script run when the package is installed"]
    assert "Package runs code when installed" in _titles(findings)
    package, _ = _package(_zip(tmp_path / "demo.jar", {
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nMain-Class: com.example.Main\nImplementation-Version: 9\n",
        "META-INF/maven/com.example/demo/pom.properties": "#generated\ngroupId=com.example\nartifactId=demo\n"
                                                          "version=9.0\n"}), "archive/jar")
    assert (package["ecosystem"], package["name"], package["version"], package["main_class"]) == (
        "maven", "com.example:demo", "9.0", "com.example.Main")
    package, _ = _package(_zip(tmp_path / "v1.2.3.zip", {
        "example.com/demo@v1.2.3/go.mod": "module example.com/demo\n\nrequire (\n\tgolang.org/x/text v0.3.0\n)\n",
        "example.com/demo@v1.2.3/demo.go": "package demo"}), "archive/zip")
    assert (package["ecosystem"], package["name"], package["version"], package["dependencies"]) == (
        "go", "example.com/demo", "v1.2.3", ["golang.org/x/text"])
    package, _ = _package(_zip(tmp_path / "demo.zip", {
        "demo/composer.json": json.dumps({"name": "acme/demo", "require": {"php": ">=8"}})}), "archive/zip")
    assert (package["ecosystem"], package["name"]) == ("packagist", "acme/demo")
    manifest = ('<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">'
                '<Metadata><Identity Id="demo" Version="0.0.1" Publisher="acme"/></Metadata></PackageManifest>')
    package, _ = _package(_zip(tmp_path / "demo.vsix", {
        "extension.vsixmanifest": manifest, "extension/package.json": json.dumps({"name": "demo", "publisher": "acme",
                                                                                 "version": "0.0.1"})}), "archive/zip")
    assert (package["ecosystem"], package["name"], package["version"]) == ("vscode", "acme.demo", "0.0.1")


def test_conda_packages_read_their_index(tmp_path: Path):
    index = json.dumps({"name": "demo", "version": "1.0", "build": "py_0", "depends": ["python >=3.9"]})
    legacy = tmp_path / "demo-1.0-py_0.tar.bz2"
    legacy.write_bytes(bz2.compress(_tar_bytes({"info/index.json": index, "site-packages/demo.py": ""})))
    package, _ = _package(legacy, "archive/bzip2")
    assert (package["ecosystem"], package["name"], package["dependencies"]) == ("conda", "demo", ["python >=3.9"])
    modern = _zip(tmp_path / "demo-1.0-py_0.conda", {
        "metadata.json": json.dumps({"conda_pkg_format_version": 2}),
        "info-demo-1.0-py_0.tar.zst": _zstd_frame(_tar_bytes({"info/index.json": index})),
        "pkg-demo-1.0-py_0.tar.zst": _zstd_frame(_tar_bytes({"site-packages/demo.py": ""}))})
    package, _ = _package(modern, "archive/zip")
    if archive_formats.zstd_decompressor() is None:
        assert package is None  # the index is in the Zstandard info tarball
    else:
        assert (package["ecosystem"], package["name"], package["build"]) == ("conda", "demo", "py_0")


def test_manifests_are_parsed_safely(tmp_path: Path):
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
            "<package><metadata><id>&lol2;</id></metadata></package>")
    package, _ = _package(_zip(tmp_path / "bomb.nupkg", {"bomb.nuspec": bomb}), "package/nupkg")
    assert package is None  # a document type is refused, so no entity is expanded
    huge = _zip(tmp_path / "huge-1.0-py3-none-any.whl", {
        "huge-1.0.dist-info/METADATA": "Name: huge\n" + "X-Pad: " + "x" * (packages.MANIFEST_BYTES + 10) + "\n"})
    package, _ = _package(huge, "package/wheel")
    assert package is None  # larger than a manifest may be
    broken = tmp_path / "broken-1.0.tgz"
    broken.write_bytes(_tar_bytes({"package/package.json": "{not json"}, "w:gz"))
    package, _ = _package(broken, "archive/gzip")
    assert package is None


@pytest.mark.parametrize(("member", "archive", "kind"), [
    ("demo-1.0.dist-info/METADATA", "demo.whl", "wheel"), ("./package/package.json", "x.tgz", "npm"),
    ("demo.pth", "demo.whl", "pth"), ("demo.pth", "demo.zip", None), ("a/b/PKG-INFO", "x.tar.gz", None),
    ("metadata.gz", "demo.gem", "gem"), ("metadata.gz", "demo.tar", None), ("TOOLS/INSTALL.PS1", "x.nupkg", "nuget-script"),
    ("META-INF/maven/g/a/pom.properties", "x.jar", "maven"), ("mod@v1/go.mod", "x.zip", "go"),
])
def test_manifest_members_are_recognized_by_their_place(member, archive, kind):
    assert packages.manifest_kind(archive, member) == kind
