"""Data flow and taint: untrusted input that reaches dangerous operations.

Python files are analysed semantically over the syntax tree (``taint_python``): flows
are followed through assignments, branches, loops and same-module helper functions, and
calls into other modules are recorded so the code index can join them with the callee
module's summary (cross-file flows). JavaScript/TypeScript, PHP, Java/Kotlin/Scala/Groovy,
Go, C#, Rust and C/C++ use the lexical engine (``taint_lexical``), which follows flows
through assignments and the file's own functions (summaries of what each parameter
reaches and what each function returns) and records calls into other files for the same
join, by function name within a language family. Every result names the source, the sink and their lines, and is
reported as INFERRED because static analysis cannot see run-time validation.
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

from ...intelligence import facts as code_facts
from ...intelligence.model import AMBIGUOUS_M, FileModel, model_for
from ...intelligence.model.lexical import LEXICAL_LANGUAGES
from ...models import FileRecord, Finding
from ..base import Analyzer
from ..code.findings import code_finding
from .taint_lexical import RULES, analyze_lexical
from .taint_python import _PROPAGATING_FUNCTIONS, _SANITIZERS, Flow, analyze_python_taint

MAX_FLOWS_DESCRIBED = 6
# Facts a file exports for the cross-module join; a file with more is reported as
# truncated (a "Data-flow analysis truncated" UNKNOWN), never cut silently.
MAX_EXPORTED_FACTS = 500
MAX_OUTGOING_FACTS = 500

# kind -> (title, severity, impact, recommendation)
KINDS: dict[str, tuple[str, str, str, str]] = {
    "sql": (
        "SQL injection", "HIGH",
        "Untrusted input is built into a SQL statement, so a crafted value can read or change any "
        "data the connection can reach.",
        "Pass input as bound query parameters (placeholders) instead of building the SQL text.",
    ),
    "command": (
        "Command injection", "HIGH",
        "Untrusted input reaches a shell or process command line, so a crafted value can run "
        "arbitrary commands.",
        "Run commands without a shell, pass arguments as a list, and allow-list values that select commands.",
    ),
    "code": (
        "Code injection", "HIGH",
        "Untrusted input is evaluated as code.",
        "Do not evaluate input; parse it with a data-only parser (JSON, ast.literal_eval) instead.",
    ),
    "deserialization": (
        "Unsafe deserialization of untrusted input", "HIGH",
        "Attacker-controlled data is deserialized with a format that can construct arbitrary objects, "
        "which allows code execution.",
        "Use a data-only format such as JSON or a safe loader, and authenticate serialized data.",
    ),
    "template": (
        "Server-side template injection", "HIGH",
        "Untrusted input is compiled as a template, which usually allows code execution in the template engine.",
        "Render fixed templates and pass input only as template variables.",
    ),
    "format_string": (
        "Format string vulnerability", "HIGH",
        "Untrusted input is used as a printf-style format string, which can read or write process memory.",
        "Use a constant format string such as \"%s\" and pass the input as an argument.",
    ),
    "path": (
        "Path traversal", "MEDIUM",
        "Untrusted input selects a file path, so `../` sequences or absolute paths can reach files "
        "outside the intended directory.",
        "Reduce input to a file name (basename, secure_filename) and check that the resolved path stays "
        "inside the base directory.",
    ),
    "ssrf": (
        "Server-side request forgery", "MEDIUM",
        "Untrusted input chooses the URL of a server-side request, so attackers can reach internal "
        "services or cloud metadata endpoints.",
        "Allow-list destination schemes and hosts before making the request.",
    ),
    "xss": (
        "Cross-site scripting", "MEDIUM",
        "Untrusted input is written into an HTML response or the DOM without escaping.",
        "Escape output for its HTML context, or render through a template engine with auto-escaping.",
    ),
    "buffer": (
        "Unbounded copy of untrusted input", "MEDIUM",
        "Untrusted input is copied into a buffer without a length bound, which can overflow it.",
        "Use bounded copies (snprintf, strlcpy) sized to the destination buffer.",
    ),
    "redirect": (
        "Open redirect", "LOW",
        "Untrusted input chooses a redirect target, which lets attackers send users to another site "
        "through a trusted link.",
        "Redirect only to relative paths or allow-listed hosts.",
    ),
}
# Imported names whose calls are not followed into other modules: the standard library
# and the frameworks whose behaviour the engine already models.
_EXTERNAL_PACKAGES = frozenset(sys.stdlib_module_names) | {
    "flask", "django", "fastapi", "starlette", "werkzeug", "requests", "httpx", "aiohttp",
    "sqlalchemy", "jinja2", "markupsafe", "pandas", "numpy", "yaml", "bleach", "tornado",
    "pyramid", "bottle", "quart", "sanic", "pydantic", "rest_framework", "dill", "jsonpickle",
    "mako", "psycopg2", "psycopg", "pymysql", "MySQLdb", "redis", "boto3", "celery", "click",
    "typer", "orjson", "ujson", "simplejson", "bson", "pymongo", "motor", "uvicorn", "gunicorn",
}


def describe(flow: Flow) -> str:
    text = f"`{flow.source}` (line {flow.source_line}) reaches `{flow.sink}`"
    if flow.via:
        text += f" (line {flow.sink_line}) through {flow.via} called at line {flow.call_line}"
    else:
        text += f" at line {flow.sink_line}"
    if flow.function and not flow.function.startswith("<"):
        text += f" in `{flow.function}`"
    return text


def flow_findings(model: FileModel, flows: list[Flow], analyzer: str) -> list[Finding]:
    by_kind: dict[str, list[Flow]] = defaultdict(list)
    for flow in flows:
        by_kind[flow.kind].append(flow)
    findings = []
    for kind, items in sorted(by_kind.items()):
        title, severity, impact, recommendation = KINDS[kind]
        described = "; ".join(describe(flow) for flow in items[:MAX_FLOWS_DESCRIBED])
        if len(items) > MAX_FLOWS_DESCRIBED:
            described += f"; and {len(items) - MAX_FLOWS_DESCRIBED} more"
        findings.append(code_finding(
            model, "security", title, f"{impact} {len(items)} flow(s): {described}.",
            sorted({flow.call_line for flow in items}), analyzer=analyzer, severity=severity,
            recommendation=recommendation,
        ))
    return findings


# Dependency trees: their functions are not summarized for other files unless they read
# untrusted input themselves, as calls into installed packages are not followed in Python.
_THIRD_PARTY_DIRS = frozenset({
    "node_modules", "bower_components", "jspm_packages", "vendor", "third_party", "third-party",
    "site-packages", "dist-packages", "Pods", "Carthage", ".venv", "venv",
})


def _third_party(path: str) -> bool:
    return any(part in _THIRD_PARTY_DIRS for part in path.replace("\\", "/").split("/")[:-1])


def _followed(target: str) -> bool:
    """Whether an outgoing call may land in scanned code (relative or first-party)."""
    if target.startswith("."):
        return True
    top = target.split(".", 1)[0]
    return bool(top) and top not in _EXTERNAL_PACKAGES and target not in _SANITIZERS \
        and target not in _PROPAGATING_FUNCTIONS


class DataFlowAnalyzer(Analyzer):
    name = "dataflow"
    version = "1.0.0"
    description = ("Taint tracking from untrusted input (web requests, sockets, stdin) to SQL, command, "
                   "code, deserialization, template, path, SSRF, XSS and redirect sinks.")
    domains = ("dataflow",)

    def supports(self, record: FileRecord) -> bool:
        if record.error or record.content_skipped_reason:
            return False
        # A .m file is modelled as Objective-C only when its content is (see AMBIGUOUS_M).
        language = "Objective-C" if record.language == AMBIGUOUS_M else record.language
        return language == "Python" or LEXICAL_LANGUAGES.get(language) in RULES

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        model = model_for(path, record)
        if model is None:
            return []
        if model.tree is not None:
            result = analyze_python_taint(model.tree, model.types)
            flows, sources = result.flows, result.sources
            cut = self._python_facts(result)
            if result.truncated or cut:
                code_facts.emit_fact("dataflow_truncated", model.language, functions=1)
        else:
            lexical = analyze_lexical(model, LEXICAL_LANGUAGES[model.language],
                                      export=not _third_party(record.path))
            flows, sources = lexical.flows, lexical.sources
            cut = self._lexical_facts(lexical)
            if lexical.truncated or cut:
                code_facts.emit_fact("dataflow_truncated", model.language, functions=1)
        if sources or flows:
            counts = Counter(flow.kind for flow in flows)
            code_facts.emit_fact("dataflow_stats", model.language, sources=sources, flows=len(flows),
                                 **dict(sorted(counts.items())))
        return flow_findings(model, flows, self.name) if flows else []

    @staticmethod
    def _lexical_facts(result) -> bool:
        """Export summaries and tainted calls; True when a cap left some out."""
        exported = [
            (name, index, summary.params[index] if index < len(summary.params) else "", entry)
            for name, summary in sorted(result.summaries.items())
            for index, entries in sorted(summary.sinks.items())
            for entry in sorted(entries)
        ]
        for name, index, parameter, (kind, sink, line, via) in exported[:MAX_EXPORTED_FACTS]:
            code_facts.emit_fact("taint_sink_param", name, param=index, parameter=parameter, sink_kind=kind,
                                 sink=sink, line=line, via=via)
        for call in result.outgoing[:MAX_OUTGOING_FACTS]:
            code_facts.emit_fact(
                "tainted_call", call.callee, arg=call.arg, keyword="", receiver=call.receiver,
                source=call.source, source_line=call.source_line, line=call.line,
            )
        return len(exported) > MAX_EXPORTED_FACTS or len(result.outgoing) > MAX_OUTGOING_FACTS

    @staticmethod
    def _python_facts(result) -> bool:
        """Export summaries and tainted calls; True when a cap left some out."""
        exported = [
            (key, index, summary.params[index] if index < len(summary.params) else "", entry)
            for key, summary in sorted(result.exported.items())
            for index, entries in sorted(summary.sinks.items())
            for entry in sorted(entries)
        ]
        for key, index, parameter, (kind, sink, line, via) in exported[:MAX_EXPORTED_FACTS]:
            code_facts.emit_fact("taint_sink_param", key, param=index, parameter=parameter, sink_kind=kind,
                                 sink=sink, line=line, via=via)
        outgoing = [call for call in result.outgoing if _followed(call.target)]
        for call in outgoing[:MAX_OUTGOING_FACTS]:
            code_facts.emit_fact(
                "tainted_call", call.target, arg=call.arg, keyword=call.keyword, source=call.source,
                source_line=call.source_line, line=call.line,
            )
        return len(exported) > MAX_EXPORTED_FACTS or len(outgoing) > MAX_OUTGOING_FACTS
