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
from ..language_catalog import is_source_path, source_language_names


_PATTERNS = (
    (
        "dynamic_code_execution",
        re.compile(r"""\b(?:eval|exec)\s*(?:\(|["'\x60$])""", re.I),
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
    (
        "dynamic_sql_query",
        re.compile(
            r"""(?i)\b(?:query|execute|execSQL|raw|createQuery)\s*\([^;\n]*(?:\+\s*[A-Za-z_$]|\.format\s*\(|\$\{)"""
        ),
        "Potential dynamically constructed SQL query",
        "A query API receives a concatenated, formatted, or interpolated expression. "
        "Review the data source and use parameterized query APIs.",
    ),
    (
        "ssrf_user_controlled_url",
        re.compile(
            r"""(?i)\b(?:requests?\.(?:get|post|put|delete)|httpx\.(?:get|post)|axios\.(?:get|post)|fetch|http\.Get|GetAsync|sendAsync)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params|body)|getParameter\s*\(|params\[|user_?input)"""
        ),
        "Potential user-controlled outbound request",
        "An outbound HTTP client call appears to receive request-derived input. "
        "Validate destination schemes, hosts, redirects, DNS results and network boundaries.",
    ),
    (
        "path_traversal_user_controlled_path",
        re.compile(
            r"""(?i)\b(?:readFile|writeFile|FileInputStream|Paths\.get|Path\.Combine|sendFile|open)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params|body)|getParameter\s*\(|params\[|user_?input|file_?name)"""
        ),
        "Potential user-controlled filesystem path",
        "A filesystem API appears to receive request or user-derived path material. "
        "Normalize paths and enforce an explicit allowed root after canonicalization.",
    ),
    (
        "weak_hash",
        re.compile(
            r"""(?i)(?:MessageDigest\.getInstance|createHash|HashAlgorithm\.Create)\s*\(\s*["'](?:MD5|SHA-?1|md5|sha1)["']|\b(?:md5|sha1)\s*\("""
        ),
        "Potential weak cryptographic hash",
        "MD5 and SHA-1 are unsuitable for collision-resistant security uses; "
        "review whether the operation is security-sensitive.",
    ),
    (
        "jwt_verification_disabled",
        re.compile(
            r"""(?i)(?:algorithms\s*[:=]\s*\[\s*["']none["']|ignoreExpiration\s*[:=]\s*true|verify\s*\(\s*[^,]+,\s*false\s*\))"""
        ),
        "JWT or token verification may be disabled",
        "A token verification configuration appears to accept an unsigned token or "
        "skip verification. Confirm library semantics and enforce algorithm allowlists.",
    ),
    (
        "insecure_random_for_secret",
        re.compile(
            r"""(?i)(?:token|secret|session|nonce|api[_-]?key)\w{0,30}.{0,100}(?:Math\.random\s*\(|new\s+Random\s*\(|\brand\s*\()"""
        ),
        "Potential non-cryptographic randomness for a secret",
        "A security-sensitive identifier appears to be derived from a non-cryptographic "
        "random generator. Use an operating-system-backed cryptographic random source.",
    ),
    (
        "open_redirect_user_controlled",
        re.compile(
            r"""(?i)\b(?:redirect|sendRedirect|Redirect)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params)|getParameter\s*\(|returnUrl|return_url|nextUrl|next_url)"""
        ),
        "Potential user-controlled redirect target",
        "A redirect API appears to consume request-derived destination data. "
        "Validate against an allowlist or use server-side destination identifiers.",
    ),
    (
        "insecure_file_permissions",
        re.compile(
            r"""(?i)(?:\bchmod\s*\([^;\n]*(?:0o?777|511)|\bchmod\s+0?777\b|\bsetWritable\s*\(\s*true\s*\))"""
        ),
        "Potentially permissive filesystem permissions",
        "A source declaration appears to grant broad write permissions. Review the "
        "effective mode, platform semantics and required access.",
    ),
    (
        "unsafe_xml_external_entities",
        re.compile(
            r"""(?i)(?:setFeature\s*\([^;\n]*(?:external-general-entities|external-parameter-entities)[^;\n]*true|resolveExternals\s*=\s*true|DtdProcessing\s*[:=]\s*(?:DtdProcessing\.)?Parse)"""
        ),
        "Potential unsafe XML external-entity configuration",
        "The XML parser appears to permit external entities or DTD processing. "
        "Disable external entity resolution and apply parser resource limits.",
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
    languages = source_language_names()

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and is_source_path(record.path)

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
                severity=(
                    "CRITICAL" if rule == "unsafe_deserialization" else
                    "HIGH" if rule in {
                        "dynamic_code_execution", "shell_command_execution",
                        "tls_verification_disabled", "unsafe_c_memory_api", "dynamic_sql_query"
                    } else "MEDIUM"
                ),
            ))
        return findings
