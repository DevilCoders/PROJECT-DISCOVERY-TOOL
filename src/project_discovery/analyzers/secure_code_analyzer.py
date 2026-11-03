"""Conservative static secure-code pattern analysis.

Findings are heuristic indicators, never proof of exploitability. Matched source
lines are not copied into reports, preventing accidental disclosure of secrets.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding


_SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".cs", ".fs", ".php", ".phtml", ".rb",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
    ".swift", ".sh", ".bash", ".zsh", ".ps1", ".pl", ".pm",
}
_PATTERNS = (
    (
        "dynamic_code_execution",
        re.compile(r"\b(?:eval|exec)\s*\(", re.I),
        "Dynamic code execution primitive",
        "Review whether the input can be influenced by untrusted data.",
    ),
    (
        "shell_command_execution",
        re.compile(
            r"\b(?:os\.system|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec|"
            r"child_process\.(?:exec|execSync)|Process\.Start)\s*\(",
            re.I,
        ),
        "Shell/process execution API",
        "Review argument construction and ensure untrusted input cannot control commands.",
    ),
    (
        "unsafe_deserialization",
        re.compile(
            r"\b(?:pickle\.(?:load|loads)|marshal\.loads|dill\.(?:load|loads)|"
            r"yaml\.load|ObjectInputStream|BinaryFormatter|unserialize)\s*\(",
            re.I,
        ),
        "Potential unsafe deserialization API",
        "Deserializing untrusted data may execute code or instantiate unsafe object graphs.",
    ),
    (
        "tls_verification_disabled",
        re.compile(
            r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
            r"InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|"
            r"--no-check-certificate)",
            re.I,
        ),
        "TLS certificate verification disabled",
        "Disabling certificate verification weakens peer authentication.",
    ),
    (
        "unsafe_c_memory_api",
        re.compile(r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(", re.I),
        "Potentially unsafe C memory/string API",
        "Review buffer bounds and prefer APIs that accept explicit destination sizes.",
    ),
)
_PYTHON_UNSAFE_LOADERS = {"UnsafeLoader", "Loader", "FullLoader"}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _dynamic_sql_argument(node: ast.AST) -> bool:
    if isinstance(node, (ast.BinOp, ast.JoinedStr)):
        return True
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Attribute) and node.func.attr == "format"
    return False


def _python_rules(tree: ast.AST) -> dict[str, set[int]]:
    matches: dict[str, set[int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        rule = None
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            rule = "dynamic_code_execution"
        elif name == "os.system":
            rule = "shell_command_execution"
        elif name.startswith("subprocess.") and any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True for keyword in node.keywords
        ):
            rule = "shell_command_execution"
        elif name in {
            "pickle.load", "pickle.loads", "marshal.loads", "dill.load", "dill.loads",
        }:
            rule = "unsafe_deserialization"
        elif name == "yaml.load":
            loader = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "Loader"),
                None,
            )
            safe = (
                isinstance(loader, ast.Name) and loader.id in {"SafeLoader", "CSafeLoader"}
            ) or (
                isinstance(loader, ast.Attribute)
                and loader.attr in {"SafeLoader", "CSafeLoader"}
            )
            if not safe:
                rule = "unsafe_deserialization"
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            rule = "weak_hash"
        elif name in {"ssl._create_unverified_context"}:
            rule = "tls_verification_disabled"
        elif name == "tempfile.mktemp":
            rule = "insecure_temporary_file"
        elif name.rsplit(".", 1)[-1] in {"execute", "executemany"} and node.args:
            if _dynamic_sql_argument(node.args[0]):
                rule = "dynamic_sql_query"
        if rule:
            matches.setdefault(rule, set()).add(node.lineno)

        if name in {"requests.get", "requests.post", "requests.put", "requests.delete",
                    "httpx.get", "httpx.post", "httpx.put", "httpx.delete"}:
            if any(
                keyword.arg == "verify" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False for keyword in node.keywords
            ):
                matches.setdefault("tls_verification_disabled", set()).add(node.lineno)
    return matches


class SecureCodePatternAnalyzer(Analyzer):
    """Find high-signal unsafe API patterns across common source languages."""

    name = "secure-code-patterns"
    domains = ("secure_code", "cryptography", "serialization")
    languages = tuple(sorted(_SOURCE_EXTENSIONS))

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.extension in _SOURCE_EXTENSIONS

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "security",
                f"Secure-code scan unavailable: {record.path}",
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        matches: dict[str, set[int]] = {}
        if record.extension in {".py", ".pyi"}:
            try:
                matches = _python_rules(ast.parse(source, filename=record.path))
            except SyntaxError as exc:
                return [Finding(
                    "security",
                    f"Secure-code parse error: {record.path}",
                    f"{type(exc).__name__}: {exc}",
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                )]
        else:
            for rule, pattern, _, _ in _PATTERNS:
                matches[rule] = {
                    number for number, line in enumerate(source.splitlines(), 1)
                    if pattern.search(line)
                }

        metadata = {rule: (title, detail) for rule, _, title, detail in _PATTERNS}
        metadata.update({
            "weak_hash": (
                "Potential weak cryptographic hash",
                "MD5 and SHA-1 are unsuitable for collision-resistant security uses; "
                "review whether the operation is security-sensitive.",
            ),
            "insecure_temporary_file": (
                "Insecure temporary-file API",
                "tempfile.mktemp does not reserve the file atomically and may permit races.",
            ),
            "dynamic_sql_query": (
                "Potential dynamically constructed SQL query",
                "A query execution call receives a formatted or concatenated expression. "
                "Use parameterized queries and validate the query construction path.",
            ),
        })
        findings = []
        for rule, lines in sorted(matches.items()):
            if not lines:
                continue
            title, detail = metadata[rule]
            findings.append(Finding(
                "security",
                f"{title}: {record.path}",
                detail,
                confidence="INFERRED",
                evidence=[f"{record.path}:{line}" for line in sorted(lines)[:100]],
                analyzer=self.name,
            ))
        return findings
