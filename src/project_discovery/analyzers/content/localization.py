"""Static localization resource inventory across common ecosystems."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ...core.safe_parsers import safe_xml_fromstring, safe_yaml_load
from ...core.source_utils import describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_LOCALE_DIRS = {
    "locale", "locales", "lang", "langs", "language", "languages",
    "translation", "translations", "i18n", "l10n", "messages",
}
_STRONG_EXTENSIONS = {
    ".po", ".pot", ".arb", ".xlf", ".xliff", ".ftl", ".strings", ".resx",
}
_KNOWN_NAMES = {
    "localizable.strings", "messages.properties", "messages.po", "messages.pot",
    "translations.json", "translation.json", "messages.json", "i18n.json",
    "strings.xml",
}
_LOCALE_STEM = re.compile(
    r"(?i)^[a-z]{2,3}(?:[-_](?:[a-z]{2}|[a-z0-9]{4}))?$"
)
_PO_MSGID = re.compile(r'^msgid\s+"((?:\\.|[^"])*)"$')
_PO_MSGSTR = re.compile(r'^msgstr(?:\[\d+\])?\s+"((?:\\.|[^"])*)"$')


def _json_keys(data: Any) -> tuple[list[str], int]:
    keys: list[str] = []
    empty = 0

    def visit(value: Any, prefix: str = "") -> None:
        nonlocal empty
        if isinstance(value, dict):
            for key, child in value.items():
                name = str(key)
                if name.startswith("@") or name == "@@locale":
                    continue
                current = f"{prefix}.{name}" if prefix else name
                if isinstance(child, (dict, list)):
                    visit(child, current)
                elif isinstance(child, (str, int, float)) or child is None:
                    keys.append(current)
                    if child is None or isinstance(child, str) and not child.strip():
                        empty += 1
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{prefix}[{index}]")
    visit(data)
    return keys, empty


def _po_summary(source: str) -> tuple[int, int]:
    count = untranslated = 0
    for block in re.split(r"\n\s*\n", source):
        msgid = msgstr = None
        collecting = None
        for line in block.splitlines():
            if match := _PO_MSGID.match(line.strip()):
                msgid = match.group(1)
                collecting = "msgid"
            elif match := _PO_MSGSTR.match(line.strip()):
                if msgstr is None:
                    msgstr = match.group(1)
                collecting = "msgstr"
            elif line.strip().startswith('"') and collecting:
                fragment = line.strip()[1:-1]
                if collecting == "msgid" and msgid is not None:
                    msgid += fragment
                elif collecting == "msgstr" and msgstr is not None:
                    msgstr += fragment
            else:
                collecting = None
        if msgid:
            count += 1
            if not msgstr:
                untranslated += 1
    return count, untranslated


def _xml_summary(source: str, extension: str) -> tuple[list[str], int]:
    root = safe_xml_fromstring(source)
    keys: list[str] = []
    empty = 0
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        key = (
            element.attrib.get("name")
            or element.attrib.get("id")
            or element.attrib.get("resname")
        )
        if not key:
            continue
        if tag in {"string", "string-array", "plurals", "data", "trans-unit", "unit"}:
            keys.append(key)
            target = next(
                (child for child in element.iter()
                 if child.tag.rsplit("}", 1)[-1].lower() in {"target", "value"}),
                None,
            )
            if tag in {"trans-unit", "unit"} and (
                target is None or not "".join(target.itertext()).strip()
            ):
                empty += 1
            elif tag in {"string", "data"} and not "".join(element.itertext()).strip():
                empty += 1
    return keys, empty


class LocalizationAnalyzer(Analyzer):
    """Inventory translation catalogs without disclosing translated values."""

    name = "localization-intelligence"
    domains = ("localization",)
    languages = (
        "Gettext PO", "ARB", "XLIFF", "Apple Strings", "Fluent", "RESX",
        "JSON", "YAML", "XML",
    )

    def supports(self, record: FileRecord) -> bool:
        if record.error is not None:
            return False
        path = Path(record.path)
        name = path.name.lower()
        extension = path.suffix.lower()
        parents = [part.lower() for part in path.parts[:-1]]
        locale_context = any(
            part in _LOCALE_DIRS or part.startswith("values-")
            for part in parents
        )
        locale_filename = bool(_LOCALE_STEM.fullmatch(path.stem))
        if extension in _STRONG_EXTENSIONS:
            return True
        if name in _KNOWN_NAMES:
            return True
        return extension in {".json", ".yaml", ".yml", ".properties", ".xml"} and (
            locale_context or locale_filename
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
            extension = path.suffix.lower()
            untranslated = 0
            if extension in {".po", ".pot"}:
                count, untranslated = _po_summary(source)
                keys = [f"entry-{index}" for index in range(count)]
                format_name = "Gettext catalog"
            elif extension in {".json", ".arb"}:
                data = json.loads(source)
                keys, untranslated = _json_keys(data)
                format_name = "ARB" if extension == ".arb" else "JSON translation catalog"
            elif extension in {".xml", ".xlf", ".xliff", ".resx"}:
                keys, untranslated = _xml_summary(source, extension)
                format_name = "XML localization resource"
            elif extension == ".strings":
                pairs = re.findall(
                    r'(?m)^\s*"((?:\\.|[^"])*)"\s*=\s*"((?:\\.|[^"])*)"\s*;',
                    source,
                )
                keys = [key for key, _ in pairs]
                untranslated = sum(not value.strip() for _, value in pairs)
                format_name = "Apple strings catalog"
            elif extension == ".properties":
                keys = [
                    match.group(1).strip() for line in source.splitlines()
                    if (match := re.match(r"^\s*([^#!\s][^=:]*?)\s*[=:]", line))
                ]
                format_name = "Java properties catalog"
            elif extension == ".ftl":
                keys = [
                    match.group(1) for line in source.splitlines()
                    if (match := re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)\s*=", line))
                ]
                format_name = "Fluent catalog"
            elif extension in {".yaml", ".yml"}:
                try:
                    import yaml
                except ImportError:
                    keys = [
                        match.group(1) for line in source.splitlines()
                        if (match := re.match(r"^\s*([A-Za-z0-9_.-]+)\s*:", line))
                    ]
                else:
                    try:
                        keys, untranslated = _json_keys(safe_yaml_load(source))
                    except yaml.YAMLError as exc:
                        raise ValueError(f"YAML localization parse error: {exc}") from exc
                format_name = "YAML translation catalog"
            else:
                return []
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ET.ParseError, ValueError) as exc:
            return [Finding(
                "localization", f"Localization catalog parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN",
                evidence=[record.path], analyzer=self.name,
            )]

        if not keys:
            return [Finding(
                "localization", f"Empty or unrecognized localization catalog: {record.path}",
                "The file was recognized by path or format, but no translation keys "
                "could be extracted.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
            )]
        findings = [Finding(
            "localization", f"Localization catalog: {record.path}",
            f"Format: {format_name}; {len(keys)} key(s); "
            f"{untranslated} explicitly empty/untranslated value(s). "
            "Translated text is not copied into the report.",
            confidence="CONFIRMED",
            evidence=[record.path, f"keys: {len(keys)}", f"empty translations: {untranslated}"],
            analyzer=self.name,
        )]
        if untranslated:
            findings.append(Finding(
                "localization", f"Untranslated entries detected: {record.path}",
                f"{untranslated} catalog entry/entries have an explicitly empty translation.",
                confidence="CONFIRMED",
                evidence=[record.path, f"empty translations: {untranslated}"],
                analyzer=self.name,
            ))
        return findings
