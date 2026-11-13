"""Static localization resource inventory across common ecosystems."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ...core.limits import AnalyzerLimits
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
# An escape is a backslash and the next character; any other character but a quote or a
# backslash stands alone. "(?:\\.|[^"])*" let a backslash be either, which backtracks
# exponentially on a run of backslashes without a closing quote (46 bytes took seconds).
_PO_MSGID = re.compile(r'^msgid\s+"((?:\\.|[^"\\])*+)"$')
_PO_MSGSTR = re.compile(r'^msgstr(?:\[\d+\])?\s+"((?:\\.|[^"\\])*+)"$')
_STRINGS_PAIR = re.compile(r'(?m)^[ \t]*"((?:\\.|[^"\\])*+)"\s*=\s*"((?:\\.|[^"\\])*+)"\s*;')


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


# ISO 639-1 language codes. A bare two-letter stem must be one (en.json, fr.yml); three
# letters and anything else need a locale directory, so app.json, pom.xml, web.xml and
# ci.yml are not translation catalogs.
_LANGUAGE_CODES = frozenset("""
aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co cr cs cu cv cy da de dv dz
ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik
io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi mk ml
mn mr ms mt my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd
se sg si sk sl sm sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi
vo wa wo xh yi yo za zh zu
""".split())


def _locale_stem(stem: str) -> bool:
    """en, pt-BR, zh_Hant: a language code with an optional region or script subtag."""
    if not _LOCALE_STEM.fullmatch(stem):
        return False
    return stem.replace("_", "-").split("-", 1)[0].lower() in _LANGUAGE_CODES


_MAX_LOCALIZATION_BYTES = 16 * 1024 * 1024


class LocalizationAnalyzer(Analyzer):
    """Inventory translation catalogs without disclosing translated values."""

    name = "localization-intelligence"
    limits = AnalyzerLimits(
        _MAX_LOCALIZATION_BYTES,
        "whole",
        outcome="UNKNOWN finding on oversize, growth or read failure",
    )
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
        locale_filename = _locale_stem(path.stem)
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
                path, _MAX_LOCALIZATION_BYTES,
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
                pairs = _STRINGS_PAIR.findall(source)
                keys = [key for key, _ in pairs]
                untranslated = sum(not value.strip() for _, value in pairs)
                format_name = "Apple strings catalog"
            elif extension == ".properties":
                keys = [
                    match.group(1).strip() for line in source.splitlines()
                    if (match := re.match(r"^\s*+([^#!\s][^=:]*+)[=:]", line))
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
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
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
