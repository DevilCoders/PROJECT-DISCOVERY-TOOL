"""Documentation claims checked against the code: figures, options, links, matrix, plugin API.

These tests keep the README, the guides and the generated capability matrix from drifting
away from the implementation (ROADMAP Phase 0).
"""
from __future__ import annotations

import dataclasses
import importlib.util
import inspect
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").rglob("*.md"))]
# Options PDT passes to VCS clients, as the Online Mode guide describes them.
CLIENT_OPTIONS = {
    "--depth", "--no-checkout", "--no-recurse-submodules", "--no-tags", "--non-interactive",
    "--noninteractive", "--single-branch",
}
# Plugin API version 1, as docs/guides/PLUGIN_SDK.md ("Compatibility policy") defines it.
# Within version 1 PDT only adds optional names; these must keep their names and types.
PLUGIN_API_V1 = {
    "Analyzer": {
        "api_version": "int", "name": "str", "version": "str", "description": "str",
        "domains": "tuple[str, ...]", "languages": "tuple[str, ...]",
    },
    "FileRecord": {
        "path": "str", "size_bytes": "int", "extension": "str", "language": "str", "sha256": "str | None",
        "analyzed": "bool", "error": "str | None", "file_type": "str", "size_bucket": "str",
        "is_hidden": "bool", "permissions": "int | None", "mtime_ns": "int | None",
        "content_skipped_reason": "str | None",
    },
    "Finding": {
        "category": "str", "title": "str", "detail": "str", "confidence": "Confidence", "evidence": "list[str]",
        "analyzer": "str", "severity": "Severity", "code_evidence": "list[CodeEvidence]", "impact": "str | None",
        "recommendation": "str | None",
    },
    "CodeEvidence": {"line_number": "int", "code": "str", "vulnerable": "bool"},
}


def _text(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_readme_figures_match_the_code():
    from project_discovery.analyzers.code.tree_sitter_syntax import GRAMMARS
    from project_discovery.catalog.languages import recognized_language_count, source_language_names
    from project_discovery.core.secret_patterns import TOKEN_FORMATS
    from project_discovery.models import REPORT_SCHEMA_VERSION

    readme = _text(ROOT / "README.md")
    figures = re.search(
        r"recognizes (\d+) languages and formats \((\d+) source languages\) and maps (\d+) optional Tree-sitter",
        readme,
    )
    assert figures, "README no longer states the language and grammar counts"
    assert tuple(map(int, figures.groups())) == (
        recognized_language_count(), len(source_language_names()), len(GRAMMARS),
    )
    assert re.search(r"\*\*JSON\*\* \(schema (\d+\.\d+)\)", readme).group(1) == REPORT_SCHEMA_VERSION
    assert len(TOKEN_FORMATS) >= int(re.search(r"Secrets in (\d+)\+ provider formats", readme).group(1))


def test_changelog_records_the_report_schema_version():
    from project_discovery.models import REPORT_SCHEMA_VERSION

    assert f"Report schema {REPORT_SCHEMA_VERSION}" in _text(ROOT / "CHANGELOG.md")


def test_documented_pdt_options_exist():
    # Options in `pdt ...` commands and bare `--option` references must be real; the
    # roadmap (plans) and the audit (history) are not checked.
    defined = set(re.findall(r'"(--[a-z][a-z0-9-]*)"', _text(ROOT / "src/project_discovery/cli.py")))
    option = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]+)")
    unknown: dict[str, set[str]] = {}
    for path in DOCUMENTS:
        if not path.exists() or path.name in {"ROADMAP.md", "AUDIT.md", "AUDIT_2026-11-12.md", "CHANGELOG.md"}:
            continue
        text = _text(path)
        pieces, in_block = [], False
        for line in text.splitlines():
            if line.startswith("```"):
                in_block = not in_block
            elif in_block and line.lstrip().startswith("pdt "):
                pieces.append(line)
        for span in re.findall(r"`([^`\n]+)`", text):
            stripped = span.strip()
            if stripped.startswith("pdt ") or re.fullmatch(r"--[a-z][a-z0-9-]+(?:[ =][^`]*)?", stripped):
                pieces.append(stripped)
        for piece in pieces:
            for name in option.findall(piece):
                if name not in defined and name not in CLIENT_OPTIONS:
                    unknown.setdefault(name, set()).add(path.relative_to(ROOT).as_posix())
    assert not unknown, f"documented options that pdt does not have: {unknown}"


def _anchors(text: str) -> set[str]:
    """GitHub heading anchors of a Markdown document (duplicates get -1, -2, ...)."""
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_block = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_block = not in_block
        if in_block or not line.startswith("#"):
            continue
        slug = re.sub(r"[^\w\- ]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        anchors.add(slug if count == 0 else f"{slug}-{count}")
        seen[slug] = count + 1
    return anchors


def test_relative_links_and_anchors_resolve():
    broken = []
    for path in DOCUMENTS:
        if not path.exists():
            continue
        text = _text(path)
        # Code is not prose: links inside code spans and blocks are not links.
        prose = re.sub(r"```.*?```", "", text, flags=re.S)
        prose = re.sub(r"`[^`\n]*`", "", prose)
        for target in re.findall(r"\]\(([^)\s]+)\)", prose):
            if re.match(r"[a-z][a-z0-9+.-]*:", target):
                continue  # http(s):, mailto:
            file_part, _, anchor = target.partition("#")
            resolved = (path.parent / file_part).resolve() if file_part else path
            if not resolved.exists():
                broken.append(f"{path.relative_to(ROOT)}: {target}")
            elif anchor and resolved.suffix == ".md" and anchor not in _anchors(_text(resolved)):
                broken.append(f"{path.relative_to(ROOT)}: {target} (no such heading)")
    assert not broken, "broken documentation links:\n" + "\n".join(broken)


def _matrix_tool():
    spec = importlib.util.spec_from_file_location("pdt_capability_matrix", ROOT / "tools" / "capability_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_capability_matrix_is_current():
    tool = _matrix_tool()
    assert _text(tool.DOCUMENT) == tool.render(ROOT / "tests"), (
        "docs/architecture/CAPABILITY_MATRIX.md is stale: run python tools/capability_matrix.py --write"
    )


def test_every_analyzer_language_is_a_catalog_name_or_a_declared_format():
    # The matrix lists analyzers by the catalog names they declare; a misspelt name would
    # silently drop an analyzer from its language's row.
    from project_discovery.analyzers import builtin_analyzers
    from project_discovery.catalog.languages import language_catalog

    names = {item["name"] for item in language_catalog()}
    for analyzer in builtin_analyzers():
        declared = set(analyzer.languages)
        if declared & names:
            near_misses = {
                language for language in declared - names
                if language.casefold() in {name.casefold() for name in names}
            }
            assert not near_misses, f"{analyzer.name} declares {near_misses} in a different case"


def test_plugin_api_version_1_is_kept():
    from project_discovery import models
    from project_discovery.analyzers.base import Analyzer

    assert Analyzer.api_version == 1
    for attribute, expected in PLUGIN_API_V1["Analyzer"].items():
        annotation = Analyzer.__annotations__.get(attribute)
        actual = str(annotation).replace("typing.", "") if annotation is not None else type(getattr(Analyzer, attribute)).__name__
        assert actual == expected, f"Analyzer.{attribute} is {actual}, plugin API 1 has {expected}"
    assert list(inspect.signature(Analyzer.supports).parameters) == ["self", "record"]
    assert list(inspect.signature(Analyzer.analyze).parameters) == ["self", "path", "record"]
    for name in ("FileRecord", "Finding", "CodeEvidence"):
        fields = {field.name: field for field in dataclasses.fields(getattr(models, name))}
        for field_name, expected in PLUGIN_API_V1[name].items():
            assert field_name in fields, f"{name}.{field_name} was removed: that needs plugin API version 2"
            assert str(fields[field_name].type) == expected, f"{name}.{field_name} changed type"
        if name != "FileRecord":  # plugins construct findings: new fields must be optional
            for field in fields.values():
                if field.name not in PLUGIN_API_V1[name]:
                    assert field.default is not dataclasses.MISSING or field.default_factory is not dataclasses.MISSING, (
                        f"{name}.{field.name} has no default: version-1 plugins could not construct a {name}"
                    )


def test_plugin_guide_lists_exactly_plugin_api_version_1():
    guide = _text(ROOT / "docs/guides/PLUGIN_SDK.md")

    def names(prefix: str) -> set[str]:
        line = next(line for line in guide.splitlines() if line.startswith(prefix))
        return set(re.findall(r"`([a-z_][a-z0-9_]*)`", line))

    assert names("- `project_discovery.analyzers.base.Analyzer`") - {"supports", "analyze"} >= set(
        PLUGIN_API_V1["Analyzer"]
    )
    assert names("- the `FileRecord` fields") == set(PLUGIN_API_V1["FileRecord"])
    listed = names("- `project_discovery.models.Finding`")
    assert listed == set(PLUGIN_API_V1["Finding"]) | set(PLUGIN_API_V1["CodeEvidence"])


@pytest.mark.parametrize("document", ["README.md", "CHANGELOG.md", "CONTRIBUTING.md"])
def test_root_documents_use_lf_line_endings(document):
    # The repository normalizes text to LF (.gitattributes); a CRLF copy breaks byte-exact tools.
    assert b"\r\n" not in (ROOT / document).read_bytes()
