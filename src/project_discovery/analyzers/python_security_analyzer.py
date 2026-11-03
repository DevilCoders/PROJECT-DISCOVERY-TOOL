"""Python AST security heuristics; target code is parsed but never executed."""
from __future__ import annotations

import ast
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


class PythonSecurityAnalyzer(Analyzer):
    """Detect selected high-signal dangerous Python API usage patterns."""

    name = "python-security"
    domains = ("secure_code", "application_security")
    languages = ("Python",)

    def supports(self, record: FileRecord) -> bool:
        return record.extension in {".py", ".pyi"} and record.error is None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=record.path)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            return [Finding(
                "security",
                f"Python security analysis unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        def report(rule: str, detail: str, node: ast.AST, severity: str) -> None:
            key = (rule, getattr(node, "lineno", 0))
            if key in seen:
                return
            seen.add(key)
            findings.append(Finding(
                "security",
                f"Potential Python security issue: {rule}",
                detail,
                confidence="INFERRED",
                evidence=[f"{record.path}:{getattr(node, 'lineno', 0)}"],
                analyzer=self.name,
                severity=severity,
            ))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else ""
            )
            dotted = ""
            if isinstance(func, ast.Attribute):
                base = func.value
                root = base.id if isinstance(base, ast.Name) else ""
                dotted = f"{root}.{func.attr}"

            if name in {"eval", "exec"}:
                report(
                    "dynamic_code_execution",
                    f"{name}() executes dynamically supplied code; validate the input source and use a constrained parser where possible.",
                    node, "HIGH",
                )
            elif dotted == "os.system":
                report(
                    "os_system_shell",
                    "os.system() invokes a command through a shell; avoid constructing commands from untrusted input.",
                    node, "HIGH",
                )
            elif name in {"run", "call", "Popen", "check_call", "check_output"} and dotted.startswith("subprocess."):
                shell_true = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                if shell_true:
                    report(
                        "subprocess_shell_true",
                        "subprocess is invoked with shell=True; untrusted arguments can create command-injection risk.",
                        node, "HIGH",
                    )
            elif dotted in {"pickle.load", "pickle.loads"}:
                report(
                    "unsafe_pickle_deserialization",
                    "pickle deserialization can execute attacker-controlled code; never load untrusted pickle data.",
                    node, "CRITICAL",
                )
            elif dotted == "yaml.load":
                safe_loader = any(
                    keyword.arg == "Loader"
                    and isinstance(keyword.value, ast.Attribute)
                    and keyword.value.attr in {"SafeLoader", "CSafeLoader"}
                    for keyword in node.keywords
                )
                if not safe_loader:
                    report(
                        "unsafe_yaml_load",
                        "yaml.load() is used without a recognized safe loader; use yaml.safe_load or SafeLoader.",
                        node, "HIGH",
                    )
            elif dotted == "ssl._create_unverified_context":
                report(
                    "tls_certificate_verification_disabled",
                    "An unverified TLS context disables certificate validation.",
                    node, "HIGH",
                )
            elif dotted == "tempfile.mktemp":
                report(
                    "insecure_temporary_file",
                    "tempfile.mktemp() is race-prone; use NamedTemporaryFile or mkstemp.",
                    node, "MEDIUM",
                )
            elif dotted in {"hashlib.md5", "hashlib.sha1"}:
                report(
                    "weak_cryptographic_hash",
                    f"{dotted} is unsuitable for collision-resistant security uses; select a modern hash or keyed MAC.",
                    node, "LOW",
                )
            elif name in {"execute", "executemany"} and isinstance(func, ast.Attribute) and node.args:
                query = node.args[0]
                interpolated = (
                    isinstance(query, (ast.JoinedStr, ast.BinOp))
                    or isinstance(query, ast.Call)
                    and isinstance(query.func, ast.Attribute)
                    and query.func.attr == "format"
                )
                if interpolated:
                    report(
                        "possible_sql_injection",
                        "SQL execution receives a dynamically formatted query string; prefer parameterized query arguments.",
                        node, "HIGH",
                    )
            elif dotted in {"requests.get", "requests.post", "requests.put", "requests.request"}:
                verify_false = any(
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                )
                if verify_false:
                    report(
                        "tls_verification_disabled",
                        "HTTP client call sets verify=False, disabling TLS certificate validation.",
                        node, "HIGH",
                    )

        return findings
