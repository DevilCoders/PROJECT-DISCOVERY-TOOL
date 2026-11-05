"""Type-system usage: annotation coverage, escape hatches and type-checker settings.

Python annotation coverage comes from the syntax tree. Other languages count their
escape hatches in the structural lexer's cleaned text, where comments and strings are
blanked (TypeScript ``any`` and non-null assertions, Kotlin ``!!``, Swift ``as!``/``try!``,
C# ``dynamic``, Go ``interface{}``); suppression comments are read from the original
text. Type-checker configuration files (tsconfig/jsconfig, mypy, pyright, Flow, MSBuild
``<Nullable>``) are reported with the settings that loosen checking. Per-file counts
are recorded as facts and summed into the project-wide type summary.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path, PurePosixPath

from .. import code_facts
from ..code_model import FUNCTION_KINDS, model_for, supports_language
from ..models import FileRecord, Finding
from ..source_utils import SourceBudgetExceeded, read_text_bounded
from .base import Analyzer
from .code_findings import code_finding

_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_TS_ANY = re.compile(r"(?::|,|\bas|<|\|)[ \t]*+any(?![\w$])|(?<![\w$])any\[\]")
_TS_SUPPRESSION = re.compile(r"(?://|/\*)[ \t]*+@ts-(?:ignore|expect-error)\b")
_TS_NOCHECK = re.compile(r"(?m)^[ \t]*+(?://|/\*)[ \t]*+@ts-nocheck\b")
_TS_NON_NULL = re.compile(r"[\w$)\]]!(?=[.\[(])")
_PY_IGNORE = re.compile(r"#[ \t]*+type:[ \t]*+ignore\b")
_PY_FILE_IGNORE = re.compile(r"(?m)^[ \t]*+#[ \t]*+(?:mypy:[ \t]*+ignore-errors|type:[ \t]*+ignore)\b")
_KOTLIN_NOT_NULL = re.compile(r"!!")
_SWIFT_FORCED = re.compile(r"(?<![\w$])(?:as!|try!)")
_CSHARP_DYNAMIC = re.compile(r"(?<![\w$.])dynamic[ \t]++[A-Za-z_]")
_CSHARP_NULLABLE_OFF = re.compile(r"(?m)^[ \t]*+#nullable[ \t]++disable\b")
_JAVA_UNCHECKED = re.compile(r"@SuppressWarnings\([^)\n]{0,200}?\"(?:unchecked|rawtypes)\"")
_GO_EMPTY_INTERFACE = re.compile(r"(?<![\w$.])interface[ \t]*+\{[ \t]*+\}")
_JS_CHECKED = re.compile(r"(?m)^[ \t]*+(?://|/\*\*?)[ \t]*+@(?:ts-check|flow)\b")
_TS_FILES = (".ts", ".tsx", ".mts", ".cts")

_JSONC_TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*+"?|//[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/)?')
_TRAILING_COMMA = re.compile(r",(?=[ \t\r\n]*+[}\]])")
_SECTION = re.compile(r"(?m)^[ \t]*+\[\[?+([^\]\r\n]{1,120}+)\]\]?+[ \t]*+(?:[#;][^\r\n]*+)?\r?$")
_SETTING = re.compile(r"(?m)^[ \t]*+([A-Za-z_][\w-]{0,60}+)[ \t]*+[=:][ \t]*+([^\n#;]{0,200}+)")
_NULLABLE = re.compile(r"<Nullable>[ \t]*+(\w{1,20}+)[ \t]*+</Nullable>")

_TS_KEYS = ("extends", "strict", "noImplicitAny", "strictNullChecks", "checkJs", "allowJs",
            "noUncheckedIndexedAccess", "skipLibCheck")
_MYPY_KEYS = frozenset({
    "strict", "disallow_untyped_defs", "disallow_incomplete_defs", "disallow_any_generics",
    "check_untyped_defs", "ignore_missing_imports", "warn_return_any", "strict_optional",
    "ignore_errors", "follow_imports",
})
_PYRIGHT_KEYS = frozenset({"typeCheckingMode", "strict", "reportGeneralTypeIssues", "reportMissingImports",
                           "reportOptionalMemberAccess"})
_CONFIG_FILES = {
    "tsconfig.json": "TypeScript", "jsconfig.json": "JavaScript", "pyrightconfig.json": "Python (pyright)",
    "mypy.ini": "Python (mypy)", ".mypy.ini": "Python (mypy)", ".flowconfig": "Flow",
    "setup.cfg": "Python (mypy)", "pyproject.toml": "Python",
}


def _python_stats(tree: ast.Module, text: str) -> dict:
    functions = annotated = returns = parameters = typed_parameters = any_count = casts = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions += 1
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if arguments and arguments[0].arg in {"self", "cls"}:
                arguments = arguments[1:]
            arguments += [item for item in (node.args.vararg, node.args.kwarg) if item]
            typed = sum(1 for item in arguments if item.annotation is not None)
            parameters += len(arguments)
            typed_parameters += typed
            returns += node.returns is not None
            annotated += typed == len(arguments) and (node.returns is not None or node.name == "__init__")
        elif isinstance(node, ast.Name) and node.id == "Any" or isinstance(node, ast.Attribute) and node.attr == "Any":
            any_count += 1
        elif isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Name) and func.id == "cast") or (
                isinstance(func, ast.Attribute) and func.attr == "cast" and isinstance(func.value, ast.Name)
                and func.value.id in {"typing", "t"}
            ):
                casts += 1
    return {
        "functions": functions, "fully_annotated": annotated, "return_annotated": returns,
        "parameters": parameters, "typed_parameters": typed_parameters, "any": any_count,
        "suppressions": len(_PY_IGNORE.findall(text)), "casts": casts,
    }


def _python_file_ignored(tree: ast.Module, text: str) -> int | None:
    """Line of a module-level ``# type: ignore`` / ``# mypy: ignore-errors`` comment."""
    first = tree.body[0].lineno if tree.body else None
    for match in _PY_FILE_IGNORE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if "ignore-errors" in match.group(0) or first is None or line < first:
            return line
        break
    return None


def _lexical_stats(model) -> dict:
    clean, text, language = model.clean, model.text, model.language
    stats = {"functions": sum(1 for symbol in model.symbols if symbol.kind in FUNCTION_KINDS)}
    if language == "TypeScript" or model.path.endswith(_TS_FILES) or (
        language in {"Vue", "Svelte"} and re.search(r"<script[^>\n]{0,200}?lang=[\"']ts", text)
    ):
        stats.update(
            any=len(_TS_ANY.findall(clean)), suppressions=len(_TS_SUPPRESSION.findall(text)),
            non_null_assertions=len(_TS_NON_NULL.findall(clean)), nocheck=int(bool(_TS_NOCHECK.search(text))),
            type_declarations=sum(1 for s in model.symbols if s.kind in {"interface", "type", "enum"}),
            typescript=1,
        )
    elif language in {"JavaScript", "Vue", "Svelte"}:
        stats.update(checked=int(bool(_JS_CHECKED.search(text))), suppressions=len(_TS_SUPPRESSION.findall(text)),
                     nocheck=int(bool(_TS_NOCHECK.search(text))))
    elif language == "Kotlin":
        stats.update(not_null_assertions=len(_KOTLIN_NOT_NULL.findall(clean)))
    elif language == "Swift":
        stats.update(forced=len(_SWIFT_FORCED.findall(clean)))
    elif language == "C#":
        stats.update(dynamic=len(_CSHARP_DYNAMIC.findall(clean)),
                     nullable_disabled=len(_CSHARP_NULLABLE_OFF.findall(text)))
    elif language == "Java":
        stats.update(suppressions=len(_JAVA_UNCHECKED.findall(text)))
    elif language == "Go":
        stats.update(empty_interfaces=len(_GO_EMPTY_INTERFACE.findall(clean)))
    return stats


def _value(raw: str) -> str:
    return raw.strip().strip("\"'").strip()


def _jsonc(text: str):
    """Parse tsconfig-style JSON with comments and trailing commas."""
    cleaned = _JSONC_TOKEN.sub(lambda match: match.group(0) if match.group(0).startswith('"') else " ", text)
    return json.loads(_TRAILING_COMMA.sub("", cleaned))


def _json_settings(name: str, text: str) -> tuple[dict, list[str]] | None:
    try:
        data = _jsonc(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return {}, []
    settings: dict = {}
    relaxed: list[str] = []
    if name == "pyrightconfig.json":
        options = data
        keys: tuple[str, ...] | frozenset[str] = _PYRIGHT_KEYS
    else:
        options = data.get("compilerOptions") if isinstance(data.get("compilerOptions"), dict) else {}
        keys = _TS_KEYS
        if isinstance(data.get("extends"), (str, list)):
            settings["extends"] = data["extends"] if isinstance(data["extends"], str) else ", ".join(
                str(item) for item in data["extends"][:5])
    for key in keys:
        if key in options and key not in settings:
            value = options[key]
            settings[key] = value if isinstance(value, (bool, int, str)) else json.dumps(value)[:80]
    for key in ("strict", "noImplicitAny", "strictNullChecks"):
        if options.get(key) is False:
            relaxed.append(f"{key}: false")
    mode = str(options.get("typeCheckingMode", "")).lower()
    if mode in {"off", "basic"}:
        relaxed.append(f"typeCheckingMode: {mode}")
    if options.get("reportGeneralTypeIssues") in {False, "none"}:
        relaxed.append("reportGeneralTypeIssues: off")
    if name != "pyrightconfig.json" and "strict" not in options and "extends" not in settings:
        settings["strict"] = "not set (TypeScript defaults to non-strict)"
    return settings, relaxed


def _sections(text: str):
    headers = list(_SECTION.finditer(text))
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        yield header.group(1).strip(), text[header.end():end]


def _ini_settings(text: str, *, flow: bool = False) -> tuple[dict, list[str], str | None]:
    """(settings, relaxations, checker) from mypy/pyright sections of INI or TOML files."""
    settings: dict = {}
    relaxed: list[str] = []
    checker = None
    for section, body in _sections(text):
        lowered = section.lower()
        if lowered in {"mypy", "tool.mypy"}:
            checker = checker or "Python (mypy)"
            for key, raw in _SETTING.findall(body):
                if key in _MYPY_KEYS:
                    value = _value(raw)
                    settings[key] = value
                    if (key == "strict_optional" and value.lower() in {"false", "0"}) or (
                        key == "ignore_errors" and value.lower() in {"true", "1"}
                    ) or (key == "follow_imports" and value.lower() == "skip"):
                        relaxed.append(f"{key} = {value}")
        elif lowered.startswith(("mypy-", "tool.mypy.overrides")):
            checker = checker or "Python (mypy)"
            for key, raw in _SETTING.findall(body):
                if key == "ignore_errors" and _value(raw).lower() in {"true", "1"}:
                    module = section[5:] if lowered.startswith("mypy-") else next(
                        (_value(value) for name, value in _SETTING.findall(body) if name == "module"), "overrides")
                    relaxed.append(f"ignore_errors for {module[:80]}")
        elif lowered == "tool.pyright":
            checker = "Python (pyright)" if checker is None else checker + " and pyright"
            for key, raw in _SETTING.findall(body):
                if key in _PYRIGHT_KEYS:
                    value = _value(raw)
                    settings[f"pyright.{key}"] = value
                    if key == "typeCheckingMode" and value.lower() in {"off", "basic"}:
                        relaxed.append(f"typeCheckingMode = {value}")
        elif flow:
            entries = [line.strip() for line in body.splitlines() if line.strip() and not line.strip().startswith("#")]
            if lowered == "options":
                for key, raw in _SETTING.findall(body):
                    if key in {"all", "exact_by_default"}:
                        settings[key] = _value(raw)
            elif lowered == "strict":
                settings["strict_lints"] = len(entries)
            elif lowered in {"untyped", "declarations"} and entries:
                relaxed.append(f"{len(entries)} path pattern(s) in [{lowered}]")
    return settings, relaxed, checker


def _config_name(record: FileRecord) -> str | None:
    name = PurePosixPath(record.path.replace("\\", "/")).name.lower()
    if name in _CONFIG_FILES or (name.startswith(("tsconfig.", "jsconfig.")) and name.endswith(".json")):
        return name
    if name.endswith(".csproj") or name in {"directory.build.props"}:
        return name
    return None


class TypeSystemAnalyzer(Analyzer):
    name = "type-systems"
    version = "1.0.0"
    description = "Type annotation coverage, type escape hatches and type-checker strictness."
    domains = ("type_systems",)
    languages = ("Python", "TypeScript", "JavaScript", "Vue", "Svelte", "Kotlin", "Swift", "C#", "Java", "Go")

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.content_skipped_reason:
            return False
        return _config_name(record) is not None or (
            record.language in self.languages and supports_language(record.language)
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = _config_name(record)
        if name is not None:
            return self._config(path, record, name)
        model = model_for(path, record)
        if model is None:
            return []
        findings: list[Finding] = []
        if model.tree is not None:
            stats = _python_stats(model.tree, model.text)
            line = _python_file_ignored(model.tree, model.text)
            if line is not None:
                stats["file_ignored"] = 1
                findings.append(code_finding(
                    model, "type_systems", "Type checking disabled for the whole module",
                    "A module-level `# type: ignore` or `# mypy: ignore-errors` comment turns off type "
                    "checking for every line of this file.", [line], analyzer=self.name,
                    confidence="CONFIRMED",
                    recommendation="Remove the file-level suppression and silence individual lines instead.",
                ))
        else:
            stats = _lexical_stats(model)
            if stats.get("nocheck"):
                match = _TS_NOCHECK.search(model.text)
                findings.append(code_finding(
                    model, "type_systems", "Type checking disabled for the whole file",
                    "`// @ts-nocheck` turns off TypeScript checking for every line of this file.",
                    [model.line_of(match.start())] if match else [], analyzer=self.name, confidence="CONFIRMED",
                    recommendation="Remove `@ts-nocheck` and fix or individually suppress the reported errors.",
                ))
        if any(stats.values()):
            code_facts.emit_fact("type_stats", model.language, **stats)
        return findings

    def _config(self, path: Path, record: FileRecord, name: str) -> list[Finding]:
        if record.size_bytes > _MAX_CONFIG_BYTES:
            return []
        try:
            text = read_text_bounded(path, _MAX_CONFIG_BYTES, errors="replace",
                                     expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded):
            return []
        if name.endswith((".csproj", ".props")):
            return self._nullable(record, text)
        if name.endswith(".json"):
            parsed = _json_settings(name, text)
            if parsed is None:
                return [Finding(
                    "type_systems", f"Unparsed type checker configuration: {record.path}",
                    "The file is not valid JSON (with comments), so its type-checking settings are unknown.",
                    confidence="UNKNOWN", evidence=[record.path], analyzer=self.name,
                )]
            settings, relaxed = parsed
            kind = _CONFIG_FILES.get(name, "JavaScript" if name.startswith("jsconfig.") else "TypeScript")
        else:
            settings, relaxed, kind = _ini_settings(text, flow=name == ".flowconfig")
            if name == ".flowconfig":
                kind = "Flow"
            elif kind is None:
                if name in {"setup.cfg", "pyproject.toml"}:
                    return []  # no type-checker section
                kind = _CONFIG_FILES[name]
        detail = ", ".join(f"{key}={value}" for key, value in settings.items()) or "defaults"
        findings = [Finding(
            "type_systems", f"Type checker configuration: {record.path}",
            f"{kind} type checking is configured. Settings: {detail}.", confidence="CONFIRMED",
            evidence=[record.path], analyzer=self.name,
        )]
        if relaxed:
            findings.append(Finding(
                "type_systems", f"Relaxed type checking: {record.path}",
                f"{kind} checking is loosened ({'; '.join(relaxed[:10])}), so whole classes of type "
                "errors are not reported.", confidence="CONFIRMED", evidence=[record.path],
                analyzer=self.name, severity="LOW",
                recommendation="Enable strict checking and suppress individual cases instead of whole classes.",
            ))
        return findings

    def _nullable(self, record: FileRecord, text: str) -> list[Finding]:
        match = _NULLABLE.search(text)
        if not match:
            return []
        disabled = match.group(1).lower() == "disable"
        return [Finding(
            "type_systems", f"C# nullable reference types: {record.path}",
            f"<Nullable>{match.group(1)}</Nullable>: the compiler "
            + ("does not check null safety." if disabled else "checks null safety."),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            severity="LOW" if disabled else "INFO",
            recommendation="Enable nullable reference types so the compiler reports possible null dereferences."
            if disabled else None,
        )]
