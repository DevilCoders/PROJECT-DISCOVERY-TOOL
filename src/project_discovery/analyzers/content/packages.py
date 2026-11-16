"""Language packages inside archives: the ecosystem, name, version and dependencies of a
wheel, egg or sdist, an npm tarball, a gem, a crate, a NuGet package, a Maven JAR, a conda
package, a Go module zip, a Composer package or a VS Code extension, read from the package's
own manifest members under a byte cap, and the code a package runs when it is installed.

Nothing here decompresses more than ``MANIFEST_BYTES`` of a member (a gem's ``metadata.gz``
expands to at most ``_EXPANDED_BYTES``), and no manifest is evaluated: JSON, TOML and
key-value texts are parsed, XML only without a document type (no entities to expand)."""
from __future__ import annotations

import email.parser
import gzip
import io
import json
import tomllib
import xml.etree.ElementTree as ElementTree
from typing import Any

MANIFEST_BYTES = 1 << 20  # a manifest member read for its fields
MANIFESTS_PER_ARCHIVE = 16
_EXPANDED_BYTES = 4 << 20  # what a compressed manifest (a gem's metadata.gz) may expand to
_FIELD = 512  # the longest field value kept
_DEPENDENCIES = 100  # dependency names kept per package

# member kind: ecosystem
_ECOSYSTEMS = {"wheel": "pypi", "egg": "pypi", "sdist": "pypi", "npm": "npm", "gem": "rubygems", "cargo": "crates.io",
               "nuspec": "nuget", "maven": "maven", "jar": "maven", "conda": "conda", "go": "go",
               "composer": "packagist", "vscode": "vscode", "vsix": "visualstudio"}
# The kinds that name the package, best first: a Maven pom.properties gives better
# coordinates than a JAR manifest.
_PRIMARY = ("wheel", "egg", "npm", "gem", "cargo", "nuspec", "maven", "conda", "go", "vscode", "vsix", "composer",
            "sdist", "jar")
_NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


def manifest_kind(archive: str, member: str) -> str | None:
    """The kind of package manifest an archive member is, or None."""
    name = member.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    parts = name.split("/")
    archive = archive.lower()
    if len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] == "METADATA":
        return "wheel"
    if len(parts) == 1 and name.endswith(".pth") and archive.endswith(".whl"):
        return "pth"  # processed at every interpreter start once installed
    if name == "EGG-INFO/PKG-INFO":
        return "egg"
    if len(parts) == 2 and parts[1] == "PKG-INFO":
        return "sdist"
    if name == "package/package.json":
        return "npm"
    if name == "metadata.gz" and archive.endswith(".gem"):
        return "gem"
    if len(parts) == 2 and archive.endswith(".crate") and parts[1] in ("Cargo.toml", "build.rs"):
        return "cargo" if parts[1] == "Cargo.toml" else "cargo-build"
    if len(parts) == 1 and name.lower().endswith(".nuspec"):
        return "nuspec"
    if name.lower() in ("tools/install.ps1", "tools/init.ps1"):
        return "nuget-script"  # run by Visual Studio's package manager console on install
    if name == "META-INF/MANIFEST.MF":
        return "jar"
    if len(parts) == 5 and parts[:2] == ["META-INF", "maven"] and parts[4] == "pom.properties":
        return "maven"
    if name == "info/index.json":
        return "conda"
    if len(parts) >= 2 and parts[-1] == "go.mod" and "@" in parts[-2]:
        return "go"  # a module zip: every file is under "module/path@version/"
    if name == "composer.json" or (len(parts) == 2 and parts[1] == "composer.json"):
        return "composer"
    if name == "extension.vsixmanifest":
        return "vsix"
    if name == "extension/package.json" and archive.endswith(".vsix"):
        return "vscode"
    return None


def _text(value: Any) -> str | None:
    return None if value is None else str(value).strip()[:_FIELD] or None


def _names(values) -> list[str]:
    return [str(value)[:_FIELD] for value in list(values)[:_DEPENDENCIES]]


def _email_fields(data: bytes) -> dict[str, Any]:
    """PKG-INFO and wheel METADATA: RFC 822 headers (the description after them is skipped)."""
    message = email.parser.HeaderParser().parsestr(data.decode("utf-8", "replace"))
    dependencies = [value.split(";", 1)[0].strip() for value in message.get_all("Requires-Dist") or ()]
    return {"name": _text(message.get("Name")), "version": _text(message.get("Version")),
            "summary": _text(message.get("Summary")), "license": _text(message.get("License")),
            "requires_python": _text(message.get("Requires-Python")),
            "dependencies": _names(dependencies), "dependency_count": len(dependencies)}


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _npm(data: bytes) -> dict[str, Any]:
    manifest = _json(data)
    dependencies = manifest.get("dependencies") if isinstance(manifest.get("dependencies"), dict) else {}
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    return {"name": _text(manifest.get("name")), "version": _text(manifest.get("version")),
            "license": _text(manifest.get("license")) if isinstance(manifest.get("license"), str) else None,
            "dependencies": _names(sorted(dependencies)), "dependency_count": len(dependencies),
            "install_scripts": {key: _text(scripts[key]) for key in _NPM_INSTALL_SCRIPTS if key in scripts}}


def _gem(data: bytes) -> dict[str, Any]:
    """A gem's metadata.gz: its gemspec as YAML with Ruby tags, read line by line."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            text = handle.read(_EXPANDED_BYTES).decode("utf-8", "replace")
    except (OSError, EOFError):
        return {}
    fields: dict[str, Any] = {"dependencies": [], "dependency_count": 0, "extensions": []}
    section = None
    dependency_names: list[str] = []
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("-"):
            key, _, value = line.partition(":")
            section = key
            if key in ("name", "platform", "license") and value.strip():
                fields[key] = _text(value.strip().strip("'\""))
            continue
        stripped = line.strip()
        if section == "version" and stripped.startswith("version:"):
            fields["version"] = _text(stripped.partition(":")[2].strip().strip("'\""))
            section = None
        elif section == "dependencies" and stripped.startswith("name:"):
            dependency_names.append(stripped.partition(":")[2].strip().strip("'\""))
        elif section == "extensions" and stripped.startswith("- "):
            fields["extensions"].append(_text(stripped[2:]))
    fields["dependencies"], fields["dependency_count"] = _names(dependency_names), len(dependency_names)
    return fields


def _cargo(data: bytes) -> dict[str, Any]:
    try:
        manifest = tomllib.loads(data.decode("utf-8", "replace"))
    except (tomllib.TOMLDecodeError, RecursionError):
        return {}
    package = manifest.get("package") if isinstance(manifest.get("package"), dict) else {}
    dependencies = manifest.get("dependencies") if isinstance(manifest.get("dependencies"), dict) else {}
    fields = {"name": _text(package.get("name")), "version": _text(package.get("version")),
              "license": _text(package.get("license")), "dependencies": _names(sorted(dependencies)),
              "dependency_count": len(dependencies)}
    if isinstance(package.get("build"), str) or package.get("build") is True:
        fields["build_script"] = True
    return fields


def _xml(data: bytes):
    """An XML document without a document type, so no entity is defined or expanded."""
    text = data.decode("utf-8", "replace")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return None
    try:
        return ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _nuspec(data: bytes) -> dict[str, Any]:
    root = _xml(data)
    if root is None:
        return {}
    fields: dict[str, Any] = {}
    dependencies = []
    for element in root.iter():
        tag = _local(element.tag)
        if tag in ("id", "version", "authors", "license") and tag not in fields:
            fields["name" if tag == "id" else tag] = _text(element.text)
        elif tag == "dependency" and element.get("id"):
            dependencies.append(element.get("id"))
    fields.update(dependencies=_names(dependencies), dependency_count=len(dependencies))
    return fields


def _properties(data: bytes) -> dict[str, str]:
    """Java properties and JAR manifest attributes (continuation lines start with a space)."""
    values: dict[str, str] = {}
    last = None
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith(" ") and last is not None:
            values[last] += line[1:]
            continue
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            last = None
            continue
        separator = min((index for index in (line.find("="), line.find(":")) if index >= 0), default=-1)
        if separator < 0:
            continue
        last = line[:separator].strip()
        values[last] = line[separator + 1:].strip()
    return values


def _jar(data: bytes) -> dict[str, Any]:
    values = _properties(data)
    return {"name": _text(values.get("Implementation-Title") or values.get("Bundle-SymbolicName")
                          or values.get("Automatic-Module-Name")),
            "version": _text(values.get("Implementation-Version") or values.get("Bundle-Version")),
            "main_class": _text(values.get("Main-Class"))}


def _maven(data: bytes) -> dict[str, Any]:
    values = _properties(data)
    group, artifact = values.get("groupId"), values.get("artifactId")
    return {"name": _text(f"{group}:{artifact}" if group and artifact else artifact),
            "version": _text(values.get("version"))}


def _conda(data: bytes) -> dict[str, Any]:
    index = _json(data)
    depends = index.get("depends") if isinstance(index.get("depends"), list) else []
    return {"name": _text(index.get("name")), "version": _text(index.get("version")), "build": _text(index.get("build")),
            "license": _text(index.get("license")), "dependencies": _names(depends), "dependency_count": len(depends)}


def _go(data: bytes, member: str) -> dict[str, Any]:
    """A go.mod's module path and requirements, line by line (a block or single requirements)."""
    module, requirements, in_block = None, [], False
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.split("//", 1)[0].strip()
        words = line.split()
        if not words:
            continue
        if words[0] == "module" and len(words) > 1 and module is None:
            module = words[1].strip('"')
        elif words[0] == "require":
            if words[1:2] == ["("]:
                in_block = True
            elif len(words) > 1:
                requirements.append(words[1])
        elif in_block:
            if words[0] == ")":
                in_block = False
            else:
                requirements.append(words[0])
    version = member.replace("\\", "/").split("/")[-2].rpartition("@")[2]
    return {"name": _text(module), "version": _text(version), "dependencies": _names(requirements),
            "dependency_count": len(requirements)}


def _composer(data: bytes) -> dict[str, Any]:
    manifest = _json(data)
    require = manifest.get("require") if isinstance(manifest.get("require"), dict) else {}
    return {"name": _text(manifest.get("name")), "version": _text(manifest.get("version")),
            "dependencies": _names(sorted(require)), "dependency_count": len(require)}


def _vscode(data: bytes) -> dict[str, Any]:
    manifest = _json(data)
    name = manifest.get("name")
    publisher = manifest.get("publisher")
    return {"name": _text(f"{publisher}.{name}" if publisher and name else name),
            "version": _text(manifest.get("version"))}


def _vsix(data: bytes) -> dict[str, Any]:
    root = _xml(data)
    if root is None:
        return {}
    identity = next((element for element in root.iter() if _local(element.tag) == "Identity"), None)
    if identity is None:
        return {}
    publisher, name = identity.get("Publisher"), identity.get("Id")
    return {"name": _text(f"{publisher}.{name}" if publisher and name else name),
            "version": _text(identity.get("Version"))}


_PARSERS = {"wheel": _email_fields, "egg": _email_fields, "sdist": _email_fields, "npm": _npm, "gem": _gem,
            "cargo": _cargo, "nuspec": _nuspec, "jar": _jar, "maven": _maven, "conda": _conda,
            "composer": _composer, "vscode": _vscode, "vsix": _vsix}


class Packages:
    """The package manifests found in one archive, and what they declare."""

    def __init__(self, archive: str) -> None:
        self.archive = archive
        self.read = 0
        self.found: dict[str, tuple[str, dict[str, Any]]] = {}  # kind: (member, fields)
        self.install_code: list[str] = []  # member: what runs at install time
        self.build_script = False

    def wants(self, member: str, size: int | None) -> str | None:
        """The manifest kind of a member worth reading (small, and the per-archive cap not reached)."""
        if self.read >= MANIFESTS_PER_ARCHIVE or size is None or size > MANIFEST_BYTES:
            return None
        kind = manifest_kind(self.archive, member)
        if kind is None or kind in self.found:
            return None
        return kind

    def add(self, kind: str, member: str, data: bytes) -> None:
        self.read += 1
        data = data[:MANIFEST_BYTES]
        if kind == "pth":
            hooks = [line.strip() for line in data.decode("utf-8", "replace").splitlines()
                     if line.startswith(("import ", "import\t"))]
            if hooks:
                self.install_code.append(f"{member}: {hooks[0][:200]}")
            return
        if kind == "nuget-script":
            self.install_code.append(f"{member}: a PowerShell script run when the package is installed")
            return
        if kind == "cargo-build":
            self.build_script = True
            return
        fields = _go(data, member) if kind == "go" else _PARSERS[kind](data)
        if not (fields.get("name") or fields.get("version")):
            return  # it did not parse, or names no package

        self.found[kind] = (member, fields)
        for script, command in (fields.get("install_scripts") or {}).items():
            self.install_code.append(f"{member}: {script}: {command}")

    def result(self) -> dict[str, Any] | None:
        """The package: its ecosystem, the manifest that named it, and its fields."""
        kind = next((name for name in _PRIMARY if name in self.found and self.found[name][1].get("name")), None)
        if kind is None:
            kind = next((name for name in _PRIMARY if name in self.found), None)
        if kind is None:
            return None
        member, fields = self.found[kind]
        package: dict[str, Any] = {"ecosystem": _ECOSYSTEMS[kind], "manifest": member}
        package.update({key: value for key, value in fields.items() if value not in (None, [], {})})
        if kind == "maven" and "jar" in self.found:  # the JAR manifest's main class, beside Maven coordinates
            main = self.found["jar"][1].get("main_class")
            if main:
                package["main_class"] = main
        if self.build_script or fields.get("build_script"):
            package["build_script"] = True
        if self.install_code:
            package["install_code"] = self.install_code[:20]
        return package
