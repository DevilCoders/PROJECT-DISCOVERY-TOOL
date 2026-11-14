"""Static reachability evidence for vulnerable packages (a code index pass).

For each package an advisory confirms (the ``vulnerable_package`` facts the local and online
matchers record), the pass looks for the scanned code's imports of it, and for calls to the
functions the advisory names (Go's vulndb, RustSec and GitHub record them). A package matched
by version alone says nothing about whether its vulnerable code runs. This evidence narrows
that down. An import shows that the code loads the package; a call to a named function
shows that the code uses the affected API. Neither proves exploitability, and the findings
never claim it.

Imports map to packages per ecosystem: npm, Pub and Go by name or module path, crates.io with
"-" read as "_", NuGet by dotted namespace, PyPI by module name (with the common
distribution-to-module renames), Maven by group, Packagist by vendor namespace, RubyGems by
require path and Hex by module. Other ecosystems are counted as unsupported.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from ..models import Finding

MAX_PACKAGES = 5_000
MAX_EVIDENCE = 10
ANALYZER = "dependency-reachability"
_JS = frozenset({"JavaScript", "TypeScript", "Vue", "Svelte"})
_JVM = frozenset({"Java", "Kotlin", "Scala", "Groovy"})
# PyPI distributions whose import name differs from the normalized distribution name.
_PYTHON_MODULES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "python-dateutil": "dateutil",
    "scikit-learn": "sklearn", "opencv-python": "cv2", "opencv-python-headless": "cv2",
    "opencv-contrib-python": "cv2", "pycryptodome": "Crypto", "pycryptodomex": "Cryptodome", "pyjwt": "jwt",
    "python-jose": "jose", "protobuf": "google.protobuf", "mysqlclient": "MySQLdb", "psycopg2-binary": "psycopg2",
    "python-multipart": "multipart", "attrs": "attr", "pyopenssl": "OpenSSL", "pymongo": "pymongo",
    "python-ldap": "ldap", "typing-extensions": "typing_extensions", "importlib-metadata": "importlib_metadata",
    "setuptools": "setuptools", "msgpack-python": "msgpack", "python-docx": "docx", "pyserial": "serial",
    "pygithub": "github", "python-magic": "magic", "dnspython": "dns", "faiss-cpu": "faiss",
}


def _python_modules(name: str) -> set[str]:
    normalized = name.strip().lower().replace("_", "-").replace(".", "-")
    modules = {normalized.replace("-", "_")}
    if normalized in _PYTHON_MODULES:
        modules.add(_PYTHON_MODULES[normalized])
    return modules


def _matcher(ecosystem: str, name: str) -> tuple[str, set[str]] | None:
    """The language family a package is imported from and the keys that name it there."""
    base = ecosystem.partition(":")[0]
    if base == "npm":
        return "js", {name}
    if base == "PyPI":
        return "python", _python_modules(name)
    if base == "Go":
        return "go", {name}
    if base == "crates.io":
        return "rust", {name.replace("-", "_")}
    if base == "NuGet":
        return "csharp", {name.lower()}
    if base == "Maven" and ":" in name:
        group = name.split(":", 1)[0]
        # Java packages usually start with the group, or with its first three parts
        # (com.fasterxml.jackson.core:jackson-databind is imported as com.fasterxml.jackson.databind).
        return "jvm", {group, ".".join(group.split(".")[:3])}
    if base == "Packagist" and "/" in name:
        return "php", {name.split("/", 1)[0].replace("-", "").lower()}
    if base == "RubyGems":
        return "ruby", {name, name.replace("-", "/")}
    if base == "Pub":
        return "dart", {name}
    if base == "Hex":
        return "elixir", {name.split("_", 1)[0].lower()}
    return None


def _import_keys(language: str, target: str) -> tuple[str, list[str]] | None:
    """The family of an import and the keys it could name a package by (most specific last)."""
    if language in _JS:
        if target.startswith((".", "/")) or not target:
            return None
        parts = target.split("/")
        return "js", ["/".join(parts[:2]) if target.startswith("@") else parts[0]]
    if language == "Python":
        parts = target.split(".")
        return "python", [".".join(parts[:end]) for end in range(1, min(len(parts), 3) + 1)]
    if language == "Go":
        return "go", [target]
    if language == "Rust":
        return "rust", [target.split("::", 1)[0]]
    if language == "C#":
        return "csharp", [target.lower()]
    if language in _JVM:
        return "jvm", [target]
    if language == "PHP":
        return "php", [target.replace("\\", "/").lstrip("/").split("/", 1)[0].lower()]
    if language == "Ruby":
        return "ruby", [target]
    if language == "Dart":
        return ("dart", [target[8:].split("/", 1)[0]]) if target.startswith("package:") else None
    if language == "Elixir":
        return "elixir", [target.split(".", 1)[0].lower()]
    return None


def _names_package(family: str, keys: list[str], wanted: set[str]) -> bool:
    if family in {"go", "csharp", "jvm", "ruby"}:
        # Module paths and dotted namespaces: the package or anything below it.
        separator = {"go": "/", "ruby": "/"}.get(family, ".")
        return any(key == item or key.startswith(item + separator) for key in keys for item in wanted)
    return any(key in wanted for key in keys)


def reachability(context: Any) -> tuple[dict, list[Finding]]:
    db = context.db
    packages: dict[tuple[str, str, str], dict[str, Any]] = {}
    for name, path, detail in db.execute("SELECT name, path, detail FROM code_facts WHERE kind = 'vulnerable_package'"):
        try:
            values = json.loads(detail)
        except ValueError:
            continue
        if not isinstance(values, dict):
            continue
        key = (str(values.get("ecosystem") or ""), name, str(values.get("version") or ""))
        entry = packages.setdefault(key, {"lockfiles": set(), "advisories": set(), "symbols": set(),
                                          "direct": None, "via": set()})
        entry["lockfiles"].add(path)
        entry["advisories"].update(map(str, values.get("advisories") or []))
        entry["symbols"].update(map(str, values.get("symbols") or []))
        if values.get("direct") is not None:
            entry["direct"] = bool(values["direct"]) or bool(entry["direct"])
        if values.get("via"):
            entry["via"].add(str(values["via"]))
        if len(packages) >= MAX_PACKAGES:
            break
    if not packages:
        return {"packages": 0}, []
    # What to look for: each package's import keys, and the direct dependencies that bring
    # transitive ones in.
    wanted: dict[str, dict[str, set[str]]] = defaultdict(dict)  # family -> package name -> keys
    unsupported = 0
    for (ecosystem, name, _), entry in packages.items():
        for candidate in [name, *entry["via"]]:
            found = _matcher(ecosystem, candidate)
            if found is not None:
                wanted[found[0]][candidate] = found[1]
        if _matcher(ecosystem, name) is None:
            unsupported += 1
    importers: dict[str, list[tuple[str, int]]] = defaultdict(list)  # package name -> (path, line)
    families: set[str] = set()  # the language families whose imports the scan holds
    for target, path, detail in db.execute("SELECT name, path, detail FROM code_facts WHERE kind = 'import'"):
        try:
            values = json.loads(detail)
        except ValueError:
            continue
        if values.get("level"):
            continue  # a relative import ("from . import x") is the project's own module
        keys = _import_keys(str(values.get("language") or ""), target)
        if keys is not None:
            families.add(keys[0])
        if keys is None or keys[0] not in wanted:
            continue
        for package_name, package_keys in wanted[keys[0]].items():
            if len(importers[package_name]) < 1_000 and _names_package(keys[0], keys[1], package_keys):
                importers[package_name].append((path, int(values.get("line") or 0)))
    findings: list[Finding] = []
    imported = not_imported = via_direct = calls_found = no_source = 0
    for (ecosystem, name, version), entry in sorted(packages.items()):
        matcher = _matcher(ecosystem, name)
        if matcher is None:
            continue
        if matcher[0] not in families:
            no_source += 1  # no scanned code in the package's language: nothing to say
            continue
        label = f"{name}@{version}"
        advisories = ", ".join(sorted(entry["advisories"])[:5])
        sites = sorted(set(importers.get(name, ())))
        evidence = [f"package: {label} ({ecosystem})", f"advisories: {advisories}",
                    *(f"lockfile: {path}" for path in sorted(entry["lockfiles"])[:3])]
        calls = []
        if sites and entry["symbols"]:
            # Calls, in the importing files, to the functions the advisory names.
            names = {symbol.replace("::", ".").rsplit(".", 1)[-1] for symbol in entry["symbols"]}
            files = sorted({path for path, _ in sites})[:200]
            for symbol in sorted(names)[:50]:
                for path, line, callee in db.execute(
                        f"SELECT path, line, callee FROM code_calls WHERE callee = ? AND path IN "
                        f"({','.join('?' * len(files))}) ORDER BY path, line LIMIT 20", [symbol, *files]):
                    calls.append((path, line, callee))
        if sites:
            imported += 1
            calls_found += bool(calls)
            detail = (f"{len({path for path, _ in sites}):,} file(s) of the scanned code import {name}, "
                      f"affected at {version} by {advisories}. ")
            if calls:
                detail += (f"{len(calls):,} call(s) name a function the advisory lists ("
                           + ", ".join(f"{callee} at {path}:{line}" for path, line, callee in calls[:5]) + "). ")
            elif entry["symbols"]:
                detail += ("The advisory names the affected functions (" + ", ".join(sorted(entry["symbols"])[:5])
                           + "); no call to them was found in the importing files. ")
            title = f"Vulnerable package imported by the code: {label}"
            evidence += [f"imported_by: {path}:{line}" for path, line in sites[:MAX_EVIDENCE]]
            evidence += [f"calls: {callee} at {path}:{line}" for path, line, callee in calls[:MAX_EVIDENCE]]
        else:
            through = [(parent, sorted(set(importers.get(parent, ())))) for parent in sorted(entry["via"])]
            through = [(parent, items) for parent, items in through if items]
            if through:
                via_direct += 1
                parent, items = through[0]
                title = f"Vulnerable package reached through an imported dependency: {label}"
                detail = (f"No scanned file imports {name} itself, but it comes in through {parent}, which "
                          f"{len({path for path, _ in items}):,} file(s) import. ")
                evidence += [f"via: {parent}", *(f"imported_by: {path}:{line}" for path, line in items[:MAX_EVIDENCE])]
            else:
                not_imported += 1
                title = f"Vulnerable package not imported by the scanned code: {label}"
                detail = (f"No scanned file imports {name}"
                          + (f" or the dependency that brings it in ({', '.join(sorted(entry['via']))})" if entry["via"] else "")
                          + ". It may still be loaded dynamically, by a framework or configuration, by a build "
                          "tool, or by code outside the scan, so this is not evidence that the vulnerability "
                          "cannot be reached. ")
        detail += ("This is static evidence from imports and call sites. It does not show that the vulnerable "
                   "code path runs, and it does not establish exploitability.")
        findings.append(Finding(
            "vulnerabilities", title, detail, confidence="INFERRED", evidence=evidence, analyzer=ANALYZER,
            severity="INFO",
        ))
    return {
        "packages": len(packages), "imported": imported, "reached_through_dependency": via_direct,
        "not_imported": not_imported, "with_calls_to_named_functions": calls_found,
        "no_code_in_language": no_source, "unsupported_ecosystems": unsupported,
    }, findings
