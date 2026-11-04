"""Python AST security heuristics; target code is parsed but never executed."""
from __future__ import annotations

from pathlib import Path

MAX_AST_FILE_BYTES = 16 * 1024 * 1024

_IMPACTS = {
    "dynamic_code_execution": (
        "If attacker-controlled input reaches eval() or exec(), an attacker may run arbitrary "
        "Python code with the privileges of the application process."
    ),
    "os_system_shell": (
        "If untrusted data influences the command string, an attacker may execute operating-"
        "system commands as the application account and access its files, secrets or services."
    ),
    "subprocess_shell_true": (
        "If attacker-controlled data reaches a shell=True command, an attacker may inject "
        "additional shell commands and execute them with the application's privileges."
    ),
    "unsafe_pickle_deserialization": (
        "If untrusted pickle data is loaded, deserialization can invoke attacker-controlled "
        "callables and result in arbitrary code execution in the application process."
    ),
    "unsafe_yaml_load": (
        "With an unsafe loader and attacker-controlled YAML, deserialization may construct "
        "dangerous Python objects or execute code, depending on the PyYAML version and loader."
    ),
    "tls_certificate_verification_disabled": (
        "A network attacker may impersonate the remote peer and intercept or modify traffic, "
        "including credentials, session tokens and application data."
    ),
    "tls_verification_disabled": (
        "A network attacker may impersonate the remote peer and intercept or modify traffic, "
        "including credentials, session tokens and application data."
    ),
    "insecure_temporary_file": (
        "A local attacker may exploit a predictable temporary path or race to read or replace "
        "files accessible to the application, depending on directory permissions."
    ),
    "weak_cryptographic_hash": (
        "If the hash protects signatures, integrity or password storage, collision or "
        "offline-guessing attacks may undermine that protection; risk depends on its purpose."
    ),
    "possible_sql_injection": (
        "If attacker-controlled data is interpolated into the SQL statement, an attacker may "
        "alter query logic to read, modify or delete records or bypass authorization."
    ),
}


from .base import Analyzer
from ..models import CodeEvidence, FileRecord, Finding
from ..source_utils import SourceBudgetExceeded, parse_python, read_python_source_bounded, redact_source_excerpt
from .secure_code_analyzer import python_security_matches

_RULE_DETAILS = {
    "dynamic_code_execution": ("{callee}() executes dynamically supplied code; validate the input source and use a constrained parser where possible.", "HIGH"),
    "os_system_shell": ("{callee}() invokes a command through a shell; avoid constructing commands from untrusted input.", "HIGH"),
    "subprocess_shell_true": ("subprocess is invoked with shell=True; untrusted arguments can create command-injection risk.", "HIGH"),
    "unsafe_pickle_deserialization": ("{callee} uses pickle-based deserialization, which can execute attacker-controlled code; never load untrusted data this way.", "CRITICAL"),
    "unsafe_yaml_load": ("yaml.load() is used without a recognized safe loader; use yaml.safe_load or SafeLoader.", "HIGH"),
    "tls_certificate_verification_disabled": ("TLS certificate or hostname validation is disabled ({callee}).", "HIGH"),
    "tls_verification_disabled": ("HTTP client call sets verify=False, disabling TLS certificate validation.", "HIGH"),
    "insecure_temporary_file": ("tempfile.mktemp() is race-prone; use NamedTemporaryFile or mkstemp.", "MEDIUM"),
    "weak_cryptographic_hash": ("{callee} is unsuitable for collision-resistant security uses; select a modern hash or keyed MAC.", "LOW"),
    "possible_sql_injection": ("SQL execution receives a dynamically formatted query string; prefer parameterized query arguments.", "HIGH"),
}


class PythonSecurityAnalyzer(Analyzer):
    """Per-line presentation of the shared Python AST security engine.

    The built-in registry runs SecureCodePatternAnalyzer, which aggregates the same
    matches per file; registering both would report every issue twice. This class
    remains available for plugins and integrations that want one finding per line.
    """

    name = "python-security"
    domains = ("secure_code", "application_security")
    languages = ("Python",)

    def supports(self, record: FileRecord) -> bool:
        return (
            record.extension in {".py", ".pyi"}
            and record.error is None
            and record.content_skipped_reason is None
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > MAX_AST_FILE_BYTES:
            return [Finding(
                "security",
                f"Python security AST resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds this analyzer's "
                f"{MAX_AST_FILE_BYTES:,}-byte AST budget. This is not a clean security result.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]
        try:
            source = read_python_source_bounded(
                path, MAX_AST_FILE_BYTES, expected_identity=record.analysis_identity,
            )
        except SourceBudgetExceeded as exc:
            return [Finding(
                "security",
                f"Python security AST resource limit: {record.path}",
                str(exc),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, SyntaxError, LookupError) as exc:
            return [Finding(
                "security",
                f"Python security analysis unavailable: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]
        try:
            tree = parse_python(source, filename=record.path)
        except (SyntaxError, RecursionError, MemoryError) as exc:
            return [Finding(
                "security",
                f"Python security parse resource limit: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
                severity="LOW",
            )]
        source_lines = source.splitlines()

        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        def report(rule: str, detail: str, line_number: int, severity: str) -> None:
            key = (rule, line_number)
            if key in seen:
                return
            seen.add(key)
            excerpt = (
                redact_source_excerpt(source_lines[line_number - 1])
                if 0 < line_number <= len(source_lines) else ""
            )
            findings.append(Finding(
                "security",
                f"Potential Python security issue: {rule}",
                detail,
                confidence="INFERRED",
                evidence=[f"{record.path}:{line_number}"],
                analyzer=self.name,
                severity=severity,
                code_evidence=(
                    [CodeEvidence(line_number=line_number, code=excerpt)]
                    if excerpt else []
                ),
                impact=_IMPACTS.get(
                    rule,
                    "If this operation is reachable with attacker-controlled data, it may "
                    "affect confidentiality, integrity or availability. Confirm the data flow."
                ),
                recommendation=detail,
            ))

        for rule, line_number, callee in python_security_matches(tree):
            detail, severity = _RULE_DETAILS[rule]
            report(rule, detail.format(callee=callee), line_number, severity)

        return findings
