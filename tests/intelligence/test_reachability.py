"""Static reachability evidence for vulnerable packages: imports of them, calls to the functions
their advisories name, and the dependency that brings a transitive package in."""
from __future__ import annotations

import json
from pathlib import Path

from project_discovery.cli import run_scan
from project_discovery.intelligence.reachability import _import_keys, _matcher, _names_package
from project_discovery.vulnerabilities.database import VulnerabilityDatabase


def _advisory(identifier: str, ecosystem: str, name: str, version: str, **affected) -> dict:
    return {"id": identifier, "modified": "2024-01-01T00:00:00Z", "summary": f"{name} flaw",
            "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "versions": [version], **affected}]}


def _scan(tmp_path: Path, files: dict[str, str], advisories: list[dict]) -> tuple[list[dict], dict]:
    project = tmp_path / "project"
    for name, content in files.items():
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "advisories.json").write_text(json.dumps(advisories), encoding="utf-8")
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as store:
        store.import_osv(feeds)
    run_scan(project, tmp_path / "out", {"json"}, 1, quiet=True, vulnerability_db=tmp_path / "db.sqlite3")
    report = json.loads((tmp_path / "out" / "discovery-report.json").read_text(encoding="utf-8"))
    return ([item for item in report["findings"] if item["analyzer"] == "dependency-reachability"],
            report["metrics"]["code_index"]["reachability"])


def test_imports_map_to_packages_per_ecosystem():
    cases = [
        ("npm", "@babel/core", "TypeScript", "@babel/core/lib/parse", True),
        ("npm", "lodash", "JavaScript", "./lodash", False),
        ("PyPI", "PyYAML", "Python", "yaml", True),
        ("PyPI", "python-dateutil", "Python", "dateutil.parser", True),
        ("PyPI", "requests", "Python", "requests_toolbelt", False),
        ("Go", "golang.org/x/net", "Go", "golang.org/x/net/html", True),
        ("Go", "golang.org/x/net", "Go", "golang.org/x/network", False),
        ("crates.io", "serde-json", "Rust", "serde_json::Value", True),
        ("NuGet", "Newtonsoft.Json", "C#", "Newtonsoft.Json.Linq", True),
        ("Maven", "com.fasterxml.jackson.core:jackson-databind", "Java", "com.fasterxml.jackson.databind.ObjectMapper", True),
        ("Packagist", "guzzlehttp/guzzle", "PHP", "GuzzleHttp\\Client", True),
        ("Pub", "http", "Dart", "package:http/http.dart", True),
    ]
    for ecosystem, name, language, target, expected in cases:
        family, wanted = _matcher(ecosystem, name)
        keys = _import_keys(language, target)
        assert (keys is not None and keys[0] == family and _names_package(family, keys[1], wanted)) is expected, (
            ecosystem, name, target)
    assert _matcher("Debian:12", "openssl") is None and _matcher("CPE", "openssl:openssl") is None


def test_findings_say_what_imports_or_calls_a_vulnerable_package(tmp_path: Path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"express": "^4", "lodash": "^4", "unused": "^1"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0"}},
        "node_modules/qs": {"version": "6.7.0"}, "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/unused": {"version": "1.0.0"}}}
    findings, metrics = _scan(tmp_path, {
        "package-lock.json": json.dumps(lock),
        "src/app.js": 'const express = require("express");\nconst _ = require("lodash");\nconst page = _.template("x");\n',
    }, [_advisory("GHSA-aaaa", "npm", "lodash", "4.17.20",
                  ecosystem_specific={"vulnerable_functions": ["lodash.template"]}),
        _advisory("GHSA-bbbb", "npm", "qs", "6.7.0"), _advisory("GHSA-cccc", "npm", "unused", "1.0.0")])
    by_title = {item["title"]: item for item in findings}
    lodash = by_title["Vulnerable package imported by the code: lodash@4.17.20"]
    assert "imported_by: src/app.js:2" in lodash["evidence"] and "calls: template at src/app.js:3" in lodash["evidence"]
    assert lodash["confidence"] == "INFERRED" and lodash["severity"] == "INFO"
    assert "does not establish exploitability" in lodash["detail"]
    qs = by_title["Vulnerable package reached through an imported dependency: qs@6.7.0"]
    assert "via: express" in qs["evidence"] and "imported_by: src/app.js:1" in qs["evidence"]
    unused = by_title["Vulnerable package not imported by the scanned code: unused@1.0.0"]
    assert "not evidence that the vulnerability cannot be reached" in unused["detail"]
    assert metrics == {"packages": 3, "imported": 1, "reached_through_dependency": 1, "not_imported": 1,
                       "with_calls_to_named_functions": 1, "no_code_in_language": 0, "unsupported_ecosystems": 0}


def test_python_module_names_and_scans_without_code_in_the_language(tmp_path: Path):
    poetry = ('[[package]]\nname = "PyYAML"\nversion = "5.3"\n\n[[package]]\nname = "requests"\nversion = "2.0.0"\n')
    findings, metrics = _scan(tmp_path, {"poetry.lock": poetry, "app/load.py": "import yaml\n\nyaml.load('x')\n",
                                         "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
                                             "": {"name": "w"}, "node_modules/left-pad": {"version": "1.3.0"}}})},
                              [_advisory("PYSEC-1", "PyPI", "PyYAML", "5.3"), _advisory("PYSEC-2", "PyPI", "requests", "2.0.0"),
                               _advisory("GHSA-dddd", "npm", "left-pad", "1.3.0")])
    titles = sorted(item["title"] for item in findings)
    assert titles == ["Vulnerable package imported by the code: PyYAML@5.3",
                      "Vulnerable package not imported by the scanned code: requests@2.0.0"]
    # No JavaScript in the scan: nothing is said about left-pad.
    assert metrics["no_code_in_language"] == 1
