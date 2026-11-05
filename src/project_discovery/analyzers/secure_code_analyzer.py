"""Conservative static secure-code pattern analysis.

Findings are heuristic indicators, never proof of exploitability. Matched source
lines are not copied into reports, preventing accidental disclosure of secrets.
"""
from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from .base import Analyzer
from ..models import CodeEvidence, FileRecord, Finding
from ..source_utils import open_verified_binary, parse_python, redact_source_excerpt
from ..language_catalog import is_source_path, source_language_names


_PATTERNS = (
    (
        "dynamic_code_execution",
        # Case-sensitive and not a member call: RegExp.exec(), Go db.Exec() and
        # cursor.execute() are not dynamic code execution.
        re.compile(r"""(?<![.\w$])(?:eval|exec)\s*(?:\(|["'\x60$])"""),
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
        re.compile(r"(?<![.\w$])(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\("),
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
            r"""(?i)\b(?:readFile|writeFile|FileInputStream|Paths\.get|Path\.Combine|sendFile|open)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params|body)|getParameter\s*\(|params\[|user_?input)"""
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
            # One lazy window keeps the cost per keyword at 130 steps; the former
            # \w{0,30}.{0,100} pair overlapped and backtracked 31 x 101 times per keyword.
            r"""(?i)(?:token|secret|session|nonce|api[_-]?key).{0,130}?(?:Math\.random\s*\(|new\s+Random\s*\(|\brand\s*\()"""
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
# Rules that only make sense for particular language families.
_RULE_EXTENSIONS = {
    "unsafe_c_memory_api": frozenset({
        ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".ipp",
        ".inc", ".m", ".mm", ".cu", ".cuh", ".ino",
    }),
}
_MAX_SECURE_CODE_FILE_BYTES = 16 * 1024 * 1024
_MAX_RULE_LOCATIONS = 100
_MAX_CODE_EXCERPTS_PER_FINDING = 20


def _record_rule_line(matches: dict[str, set[int]], rule: str, line_number: int) -> None:
    locations = matches.setdefault(rule, set())
    if line_number not in locations and len(locations) < _MAX_RULE_LOCATIONS:
        locations.add(line_number)


_IMPACTS = {
    "dynamic_code_execution": (
        "If attacker-controlled input reaches this operation, an attacker may execute "
        "arbitrary code in the application process context, access its data and secrets, "
        "modify files, or pivot to resources available to that process."
    ),
    "shell_command_execution": (
        "If untrusted data influences the command or its arguments, an attacker may execute "
        "operating-system commands with the application's privileges, potentially exposing "
        "secrets, altering data or taking control of the service account."
    ),
    "unsafe_deserialization": (
        "If untrusted serialized data reaches an unsafe deserializer, an attacker may "
        "trigger code execution, unsafe object construction or resource exhaustion; the "
        "exact impact depends on the runtime and serializer."
    ),
    "tls_verification_disabled": (
        "A network attacker may impersonate the remote peer and intercept or alter traffic, "
        "including credentials, session tokens and application data."
    ),
    "unsafe_c_memory_api": (
        "An input that exceeds expected buffer bounds may corrupt memory or crash the process. "
        "Depending on platform and exploitability, memory corruption can sometimes enable code execution."
    ),
    "dynamic_sql_query": (
        "If attacker-controlled data is concatenated into the query, an attacker may alter SQL "
        "logic to read, modify or delete database records, bypass authorization or access other users' data."
    ),
    "ssrf_user_controlled_url": (
        "If the destination is attacker-controlled or insufficiently constrained, an attacker "
        "may make the server contact internal services, cloud metadata endpoints or systems "
        "not directly reachable from the attacker's network."
    ),
    "path_traversal_user_controlled_path": (
        "If path input is not constrained to an allowed directory, an attacker may read "
        "sensitive files or overwrite files writable by the application, potentially exposing "
        "credentials or changing application behavior."
    ),
    "weak_hash": (
        "If this hash protects signatures, integrity or password storage, collision or "
        "offline-guessing attacks may undermine that protection. Actual risk depends on purpose and key/salt use."
    ),
    "jwt_verification_disabled": (
        "If signature or algorithm verification is bypassed, an attacker may forge or alter "
        "tokens and impersonate users or services, potentially bypassing authentication and authorization."
    ),
    "insecure_random_for_secret": (
        "Predictable session identifiers, reset tokens or API secrets may be guessed or "
        "reproduced, allowing account/session takeover or unauthorized API access."
    ),
    "open_redirect_user_controlled": (
        "An attacker may direct users to a malicious destination using a trusted application "
        "URL, enabling phishing or, in some OAuth flows, leakage of authorization material."
    ),
    "insecure_file_permissions": (
        "Users or processes outside the intended trust boundary may read or modify files, "
        "including configuration, credentials or executable content, depending on effective permissions."
    ),
    "unsafe_xml_external_entities": (
        "If external entities are processed, an attacker may cause local file disclosure, "
        "server-side requests to internal services or resource exhaustion."
    ),
    "insecure_temporary_file": (
        "A predictable or non-atomically reserved temporary path may permit a local race, "
        "file overwrite or disclosure under the application's filesystem permissions."
    ),
}


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


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map names bound by absolute imports to the fully qualified names they refer to."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _resolve(name: str, aliases: dict[str, str]) -> str:
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + (f".{rest}" if rest else "")
    return name


def _keyword(node: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in node.keywords if item.arg == name), None)


def _is_constant(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader"}
_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options", "request", "stream"}
_PICKLE_LOADERS = {
    "pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads", "cPickle.load",
    "cPickle.loads", "marshal.load", "marshal.loads", "dill.load", "dill.loads",
    "cloudpickle.load", "cloudpickle.loads", "jsonpickle.decode", "shelve.open",
    "pandas.read_pickle", "joblib.load",
}


# Fine-grained Python rules (used by the per-line python-security presentation) mapped
# onto the secure-code rule catalog. Both presentations share this single engine.
PYTHON_RULE_CATEGORIES = {
    "dynamic_code_execution": "dynamic_code_execution",
    "os_system_shell": "shell_command_execution",
    "subprocess_shell_true": "shell_command_execution",
    "unsafe_pickle_deserialization": "unsafe_deserialization",
    "unsafe_yaml_load": "unsafe_deserialization",
    "weak_cryptographic_hash": "weak_hash",
    "tls_certificate_verification_disabled": "tls_verification_disabled",
    "tls_verification_disabled": "tls_verification_disabled",
    "insecure_temporary_file": "insecure_temporary_file",
    "possible_sql_injection": "dynamic_sql_query",
}


def _python_call_rule(node: ast.Call, name: str, aliases: dict[str, str]) -> str | None:
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return "dynamic_code_execution"
    if name in {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}:
        return "os_system_shell"
    if name.startswith("subprocess.") and _is_constant(_keyword(node, "shell"), True):
        return "subprocess_shell_true"
    if name in _PICKLE_LOADERS:
        return "unsafe_pickle_deserialization"
    if name == "torch.load" and not _is_constant(_keyword(node, "weights_only"), True):
        return "unsafe_pickle_deserialization"  # pickle-based unless weights_only=True
    if name == "numpy.load" and _is_constant(_keyword(node, "allow_pickle"), True):
        return "unsafe_pickle_deserialization"
    if name in {"yaml.load", "yaml.load_all"}:
        loader = _keyword(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
        loader_name = _resolve(_dotted(loader), aliases) if loader is not None else ""
        if loader_name.rsplit(".", 1)[-1] not in _SAFE_YAML_LOADERS:
            return "unsafe_yaml_load"
        return None
    if name in {"hashlib.md5", "hashlib.sha1"} or (
        name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant)
        and str(node.args[0].value).lower().replace("-", "") in {"md5", "sha1"}
    ):
        # usedforsecurity=False explicitly declares a non-security use (Python 3.9+).
        if _is_constant(_keyword(node, "usedforsecurity"), False):
            return None
        return "weak_cryptographic_hash"
    if name == "ssl._create_unverified_context":
        return "tls_certificate_verification_disabled"
    if name == "tempfile.mktemp":
        return "insecure_temporary_file"
    if name.rsplit(".", 1)[-1] in {"execute", "executemany"} and node.args:
        return "possible_sql_injection" if _dynamic_sql_argument(node.args[0]) else None
    if _is_constant(_keyword(node, "verify"), False) and (
        name.rsplit(".", 1)[-1] in _HTTP_VERBS
        or name.rsplit(".", 1)[-1] in {"Client", "AsyncClient", "Session"}
    ):
        return "tls_verification_disabled"
    return None


def python_security_matches(tree: ast.AST) -> list[tuple[str, int, str]]:
    """Return ordered (fine rule, line, resolved callee) Python AST security matches.

    Import aliases are resolved, so ``from pickle import loads as l; l(x)`` and
    ``import subprocess as sp; sp.run(cmd, shell=True)`` are recognized.
    """
    aliases = _import_aliases(tree)
    matches: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, line: int, name: str) -> None:
        if (rule, line) not in seen:
            seen.add((rule, line))
            matches.append((rule, line, name))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _resolve(_dotted(node.func), aliases)
            rule = _python_call_rule(node, name, aliases)
            if rule:
                add(rule, node.lineno, name)
        elif isinstance(node, ast.Assign):
            # ctx.verify_mode = ssl.CERT_NONE / ctx.check_hostname = False / s.verify = False
            for target in node.targets:
                if not isinstance(target, ast.Attribute):
                    continue
                value = _resolve(_dotted(node.value), aliases)
                if target.attr == "verify_mode" and value.endswith("CERT_NONE"):
                    add("tls_certificate_verification_disabled", node.lineno, value)
                elif target.attr == "check_hostname" and _is_constant(node.value, False):
                    add("tls_certificate_verification_disabled", node.lineno, target.attr)
                elif target.attr == "verify" and _is_constant(node.value, False):
                    add("tls_verification_disabled", node.lineno, target.attr)
    matches.sort(key=lambda item: (item[1], item[0]))
    return matches


def _python_rules(tree: ast.AST) -> dict[str, set[int]]:
    """Return secure-code rule -> line numbers for Python AST security indicators."""
    matches: dict[str, set[int]] = {}
    for rule, line, _ in python_security_matches(tree):
        _record_rule_line(matches, PYTHON_RULE_CATEGORIES[rule], line)
    return matches


class SecureCodePatternAnalyzer(Analyzer):
    """Find high-signal unsafe API patterns across common source languages."""

    name = "secure-code-patterns"
    domains = ("secure_code", "cryptography", "serialization")
    languages = source_language_names()

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and is_source_path(record.path)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if record.size_bytes > _MAX_SECURE_CODE_FILE_BYTES:
            return [Finding(
                "security",
                f"Secure-code analysis resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the secure-code analyzer's "
                f"{_MAX_SECURE_CODE_FILE_BYTES:,}-byte content budget. This is not a clean result.",
                confidence="UNKNOWN",
                evidence=[record.path, f"size: {record.size_bytes} bytes"],
                analyzer=self.name,
                severity="LOW",
            )]
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                raw_source = stream.read(_MAX_SECURE_CODE_FILE_BYTES + 1)
            if len(raw_source) > _MAX_SECURE_CODE_FILE_BYTES:
                return [Finding(
                    "security",
                    f"Secure-code analysis resource limit: {record.path}",
                    f"Content grew beyond the {_MAX_SECURE_CODE_FILE_BYTES:,}-byte analyzer budget "
                    "while being read. This is not a clean result.",
                    confidence="UNKNOWN",
                    evidence=[record.path, f"read_limit: {_MAX_SECURE_CODE_FILE_BYTES} bytes"],
                    analyzer=self.name,
                    severity="LOW",
                )]
            if record.extension in {".py", ".pyi"}:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_source).readline)
                source = raw_source.decode(encoding)
            else:
                source = raw_source.decode("utf-8")
        except (OSError, UnicodeDecodeError, SyntaxError, LookupError) as exc:
            return [Finding(
                "security",
                f"Secure-code scan unavailable: {record.path}",
                redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        matches: dict[str, set[int]] = {}
        if record.extension in {".py", ".pyi"}:
            try:
                matches = _python_rules(parse_python(source, filename=record.path))
            except (SyntaxError, RecursionError, MemoryError) as exc:
                return [Finding(
                    "security",
                    f"Secure-code parse error: {record.path}",
                    redact_source_excerpt(f"{type(exc).__name__}: {exc}"),
                    confidence="UNKNOWN",
                    evidence=[record.path],
                    analyzer=self.name,
                )]
        else:
            # Keep line iteration streaming. splitlines() can allocate millions of
            # strings for a newline-heavy 16 MiB source file.
            rules = [
                (rule, pattern) for rule, pattern, _, _ in _PATTERNS
                if record.extension in _RULE_EXTENSIONS.get(rule, (record.extension,))
            ]
            for line_number, line in enumerate(io.StringIO(source, newline=None), 1):
                for rule, pattern in rules:
                    if pattern.search(line):
                        _record_rule_line(matches, rule, line_number)

        requested_lines = {
            line_number
            for locations in matches.values()
            for line_number in sorted(locations)[:_MAX_CODE_EXCERPTS_PER_FINDING]
        }
        source_evidence: dict[int, str] = {}
        if requested_lines:
            for line_number, line in enumerate(io.StringIO(source, newline=None), 1):
                if line_number in requested_lines:
                    source_evidence[line_number] = redact_source_excerpt(line)
                    if len(source_evidence) >= len(requested_lines):
                        break

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
            selected_lines = sorted(lines)[:_MAX_RULE_LOCATIONS]
            findings.append(Finding(
                "security",
                f"{title}: {record.path}",
                detail,
                confidence="INFERRED",
                evidence=[f"{record.path}:{line}" for line in selected_lines],
                analyzer=self.name,
                severity=(
                    "CRITICAL" if rule == "unsafe_deserialization" else
                    "HIGH" if rule in {
                        "dynamic_code_execution", "shell_command_execution",
                        "tls_verification_disabled", "unsafe_c_memory_api", "dynamic_sql_query",
                        "ssrf_user_controlled_url", "path_traversal_user_controlled_path",
                        "jwt_verification_disabled", "unsafe_xml_external_entities",
                    } else "MEDIUM"
                ),
                code_evidence=[
                    CodeEvidence(
                        line_number=line,
                        code=source_evidence[line],
                    )
                    for line in selected_lines[:_MAX_CODE_EXCERPTS_PER_FINDING]
                    if line in source_evidence
                ],
                impact=_IMPACTS.get(
                    rule,
                    "If the risky behavior is reachable with attacker-controlled data, it may "
                    "weaken confidentiality, integrity or availability. Confirm data flow and "
                    "runtime configuration before asserting exploitability."
                ),
                recommendation=detail,
            ))
        return findings
