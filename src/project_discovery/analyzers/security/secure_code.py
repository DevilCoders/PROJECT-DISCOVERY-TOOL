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

from ...catalog.languages import is_source_path, source_language_names
from ...core.source_utils import describe_error, open_verified_binary, parse_python, redact_source_excerpt
from ...models import CodeEvidence, FileRecord, Finding
from ..base import Analyzer


def _statement_end(line: str, start: int) -> int:
    ends = [index for index in (line.find(";", start), line.find("\n", start)) if index != -1]
    return min(ends) if ends else len(line)


class _CallPattern:
    """``head [^;\\n]* part [^;\\n]* part ...`` within one statement, in linear time.

    One regex with these gaps rescans the rest of the statement from every head it finds,
    which is quadratic on a line such as ``redirect(a,`` repeated, and cubic with two
    gaps (the XXE rule took 2 s on 12,000 characters). Here each statement is scanned once
    per part: when the first head of a statement has no match, no later head of the same
    statement can have one, because its window is a suffix of the first one's.
    """

    def __init__(self, head: str, *parts: str, flags: int = 0) -> None:
        self.head = re.compile(head, flags)
        self.parts = tuple(re.compile(part, flags) for part in parts)

    def search(self, line: str) -> bool:
        position, length = 0, len(line)
        while position <= length:
            head = self.head.search(line, position)
            if head is None:
                return False
            stop = _statement_end(line, head.end())
            cursor = head.end()
            for part in self.parts:
                found = part.search(line, cursor, stop)
                if found is None:
                    break
                cursor = found.end()
            else:
                return True
            position = stop + 1
        return False


class _FirstArgumentThen:
    """``head [^,]+ tail``: the first comma after the call must start ``tail``, in linear time."""

    def __init__(self, head: str, tail: str, flags: int = 0) -> None:
        self.head = re.compile(head, flags)
        self.tail = re.compile(tail, flags)

    def search(self, line: str) -> bool:
        position = 0
        while (head := self.head.search(line, position)) is not None:
            comma = line.find(",", head.end())
            if comma == -1:
                return False
            if comma > head.end() and self.tail.match(line, comma):
                return True
            position = comma + 1  # every head before this comma shares it
        return False


class _NearBefore:
    """``keyword .{0,window}? call``, found from the (rare) calls backwards in linear time."""

    def __init__(self, keyword: str, call: str, window: int, longest_keyword: int, flags: int = 0) -> None:
        self.keyword = re.compile(keyword, flags)
        self.call = re.compile(call, flags)
        self.window = window
        self.longest = longest_keyword

    def search(self, line: str) -> bool:
        for call in self.call.finditer(line):
            low = max(0, call.start() - self.window - self.longest)
            for keyword in self.keyword.finditer(line, low, call.start()):
                if call.start() - keyword.end() <= self.window:
                    return True
        return False


class _AnyOf:
    def __init__(self, *patterns) -> None:
        self.patterns = patterns

    def search(self, line: str) -> bool:
        return any(pattern.search(line) for pattern in self.patterns)


_USER_INPUT = r"req(?:uest)?\.(?:query|params|body)|getParameter\s*\(|params\[|user_?input"

# Every rule runs once per source line, so each must stay linear in the line's length:
# minified bundles hold megabytes on one line.
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
            r"ObjectInputStream|BinaryFormatter|unserialize)\s*\(",
            re.I,
        ),
        "Potential unsafe deserialization API",
        "Deserializing untrusted data may execute code or instantiate unsafe object graphs.",
    ),
    (
        # js-yaml 4 and Psych 4 (Ruby 3.1) load safely by default; older versions construct
        # arbitrary objects. Python's yaml.load is judged from the syntax tree instead.
        "yaml_load_version_dependent",
        re.compile(r"\byaml\.load\s*\(", re.I),
        "YAML load whose safety depends on the library version",
        "js-yaml 4 and Psych 4 load safely by default; earlier versions construct arbitrary "
        "objects from tagged YAML. Confirm the version, or use safeLoad / YAML.safe_load.",
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
        _CallPattern(
            r"\b(?:query|execute|execSQL|raw|createQuery)\s*\(", r"\+\s*[A-Za-z_$]|\.format\s*\(|\$\{", flags=re.I,
        ),
        "Potential dynamically constructed SQL query",
        "A query API receives a concatenated, formatted, or interpolated expression. "
        "Review the data source and use parameterized query APIs.",
    ),
    (
        "ssrf_user_controlled_url",
        _CallPattern(
            r"\b(?:requests?\.(?:get|post|put|delete)|httpx\.(?:get|post)|axios\.(?:get|post)|fetch|http\.Get"
            r"|GetAsync|sendAsync)\s*\(",
            _USER_INPUT, flags=re.I,
        ),
        "Potential user-controlled outbound request",
        "An outbound HTTP client call appears to receive request-derived input. "
        "Validate destination schemes, hosts, redirects, DNS results and network boundaries.",
    ),
    (
        "path_traversal_user_controlled_path",
        _CallPattern(
            r"\b(?:readFile|writeFile|FileInputStream|Paths\.get|Path\.Combine|sendFile|open)\s*\(", _USER_INPUT,
            flags=re.I,
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
        _AnyOf(
            re.compile(r"""(?i)algorithms\s*[:=]\s*\[\s*["']none["']|ignoreExpiration\s*[:=]\s*true"""),
            _FirstArgumentThen(r"verify\s*\(", r",\s*false\s*\)", flags=re.I),
        ),
        "JWT or token verification may be disabled",
        "A token verification configuration appears to accept an unsigned token or "
        "skip verification. Confirm library semantics and enforce algorithm allowlists.",
    ),
    (
        "insecure_random_for_secret",
        # A keyword at most 130 characters before a non-cryptographic random call. Calls
        # are rare, so the search starts from them instead of from every keyword.
        _NearBefore(
            r"token|secret|session|nonce|api[_-]?key",
            r"Math\.random\s*\(|new\s+Random\s*\(|\brand\s*\(",
            window=130, longest_keyword=8, flags=re.I,
        ),
        "Potential non-cryptographic randomness for a secret",
        "A security-sensitive identifier appears to be derived from a non-cryptographic "
        "random generator. Use an operating-system-backed cryptographic random source.",
    ),
    (
        "open_redirect_user_controlled",
        _CallPattern(
            r"\b(?:redirect|sendRedirect|Redirect)\s*\(",
            r"req(?:uest)?\.(?:query|params)|getParameter\s*\(|returnUrl|return_url|nextUrl|next_url", flags=re.I,
        ),
        "Potential user-controlled redirect target",
        "A redirect API appears to consume request-derived destination data. "
        "Validate against an allowlist or use server-side destination identifiers.",
    ),
    (
        "insecure_file_permissions",
        # Java's setWritable(true) sets only the owner's bit; (true, false) grants everyone.
        _AnyOf(
            _CallPattern(r"\bchmod(?:Sync)?\s*\(", r"0o?777|511", flags=re.I),
            re.compile(
                r"""(?i)\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b"""
                r"""|\bset(?:Writable|Readable|Executable)\s*\(\s*true\s*,\s*false\s*\)"""
            ),
        ),
        "Potentially permissive filesystem permissions",
        "A source declaration appears to grant broad write permissions. Review the "
        "effective mode, platform semantics and required access.",
    ),
    (
        "unsafe_xml_external_entities",
        _AnyOf(
            _CallPattern(r"setFeature\s*\(", r"external-general-entities|external-parameter-entities", r"true", flags=re.I),
            re.compile(r"""(?i)resolveExternals\s*=\s*true|DtdProcessing\s*[:=]\s*(?:DtdProcessing\.)?Parse"""),
        ),
        "Potential unsafe XML external-entity configuration",
        "The XML parser appears to permit external entities or DTD processing. "
        "Disable external entity resolution and apply parser resource limits.",
    ),
)
_PYTHON_UNSAFE_LOADERS = {"UnsafeLoader", "Loader", "FullLoader"}
# In shell scripts ``exec "$@"`` replaces the shell with its arguments (the standard
# entrypoint idiom); only eval evaluates code.
_SHELL_EXTENSIONS = frozenset({".sh", ".bash", ".zsh", ".ksh", ".fish"})
_SHELL_EVAL = re.compile(r"""(?<![.\w$])eval\s*(?:\(|["'\x60$])""")
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


def _dynamic_sql_argument(
    node: ast.AST, structure: "_SqlStructure | None" = None, call: ast.AST | None = None,
) -> bool:
    """Whether a query argument is built at run time from values that could carry data.

    Interpolating only structure (a parameter-placeholder list, or constant table and
    column names) is not dynamic: ``f"... IN ({placeholders})"`` with the values passed
    as parameters is the standard safe idiom.
    """
    structure = structure or _SqlStructure()

    def safe(value: ast.AST) -> bool:
        return structure.safe(value, call)

    if isinstance(node, ast.JoinedStr):
        return not all(safe(part.value) for part in node.values if isinstance(part, ast.FormattedValue))
    if isinstance(node, ast.BinOp):
        return not (safe(node.left) and safe(node.right))
    if isinstance(node, ast.Call):
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "format"):
            return False
        arguments = [*node.args, *(item.value for item in node.keywords)]
        return not (arguments and all(safe(item) for item in arguments))
    return False


def _literal(node: ast.AST) -> bool:
    """A constant, or a tuple/list/set/dict built only of constants (dict values may vary)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _literal(key) for key in node.keys)
    return False


def _placeholder_join(node: ast.AST) -> bool:
    """``",".join("?" for _ in x)``, ``", ".join(["%s"] * n)`` and ``",".join("?" * n)``."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and isinstance(node.func.value, ast.Constant)
            and len(node.args) == 1 and not node.keywords):
        return False
    argument = node.args[0]
    if isinstance(argument, (ast.GeneratorExp, ast.ListComp)):
        return isinstance(argument.elt, ast.Constant)
    if isinstance(argument, ast.BinOp) and isinstance(argument.op, ast.Mult):
        return any(_literal(side) for side in (argument.left, argument.right))
    return False


class _SqlStructure:
    """Names whose every binding is SQL structure: constants and placeholder lists.

    Module level: names assigned only literals, and functions that only return a
    placeholder join. Per function: locals assigned only such values, and loop variables
    over constant collections. Flow-insensitive and conservative: one other binding of a
    name, or any parameter, makes it data.
    """

    def __init__(self, module: ast.AST | None = None) -> None:
        self.constants: set[str] = set()
        self.helpers: set[str] = set()
        # id(call) -> (structural local names, every name bound in the call's function)
        self.scopes: dict[int, tuple[set[str], set[str]]] = {}
        if module is None:
            return
        for statement in getattr(module, "body", []):
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                returns = [item for item in statement.body if not isinstance(item, ast.Expr)]
                if (len(returns) == 1 and isinstance(returns[0], ast.Return)
                        and returns[0].value is not None and _placeholder_join(returns[0].value)):
                    self.helpers.add(statement.name)
        # Any non-literal binding of a name anywhere in the module disqualifies it.
        rejected: set[str] = set()
        for name, value in _bindings(ast.walk(module), loops=True):
            (self.constants if value is not None and _literal(value) else rejected).add(name)
        self.constants -= rejected
        functions = [node for node in ast.walk(module) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for function in functions:   # breadth-first: an inner function's scope wins
            scope = self._function_scope(function)
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    self.scopes[id(node)] = scope

    def _function_scope(self, function: ast.AST) -> tuple[set[str], set[str]]:
        arguments = function.args
        bound = {item.arg for item in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)}
        bound |= {item.arg for item in (arguments.vararg, arguments.kwarg) if item is not None}
        candidates: dict[str, bool] = {}
        for name, value in _bindings(ast.walk(function), loops=True):
            # A local is structure when its value is: a literal, or concatenations and
            # f-strings of constants, placeholder lists and module constants (no locals,
            # so this stays one pass).
            ok = value is not None and (_literal(value) or self.safe(value))
            candidates[name] = candidates.get(name, True) and ok
        safe = {name for name, ok in candidates.items() if ok and name not in bound}
        return safe, bound | set(candidates)

    def _helper_call(self, node: ast.AST) -> bool:
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in self.helpers)

    def safe(self, node: ast.AST, call: ast.AST | None = None) -> bool:
        """Whether ``node``, as seen from ``call``'s function, is SQL structure only.

        Concatenations and nested f-strings are safe when every part is; an explicit stack
        keeps very long concatenation chains from exhausting the recursion limit.
        """
        safe, bound = self.scopes.get(id(call), (set(), set()))
        pending = [node]
        while pending:
            item = pending.pop()
            if isinstance(item, ast.BinOp):
                # Concatenation, or arithmetic such as ``LIMIT {MAX // 2}``: safe when both
                # sides are (``"%s" % value`` still carries ``value``).
                pending.extend((item.left, item.right))
            elif isinstance(item, ast.UnaryOp):
                pending.append(item.operand)
            elif isinstance(item, ast.IfExp):
                # The condition never reaches the string; both outcomes must be structure.
                pending.extend((item.body, item.orelse))
            elif isinstance(item, ast.JoinedStr):
                pending.extend(part.value for part in item.values if isinstance(part, ast.FormattedValue))
            elif isinstance(item, ast.Name):
                # A local binding (a parameter included) shadows a module constant.
                if not (item.id in safe if item.id in bound else item.id in self.constants):
                    return False
            elif not (isinstance(item, ast.Constant) or _placeholder_join(item) or self._helper_call(item)):
                return False
        return True


def _bindings(nodes, *, loops: bool = False):
    """(name, value) for each simple binding; value is None when it is not one expression.

    With ``loops``, a ``for`` target over a constant collection yields the collection's
    name (or literal) as its value, so iterating constant table names stays structural.
    """
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    yield target.id, node.value
                else:
                    for item in ast.walk(target):
                        if isinstance(item, ast.Name):
                            yield item.id, None
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
            yield node.target.id, node.value if isinstance(node, ast.AnnAssign) else None
        elif loops and isinstance(node, (ast.For, ast.AsyncFor)):
            if isinstance(node.target, ast.Name):
                yield node.target.id, node.iter if _literal(node.iter) or isinstance(node.iter, ast.Name) else None
            else:
                for item in ast.walk(node.target):
                    if isinstance(item, ast.Name):
                        yield item.id, None
        elif loops and isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for name in ast.walk(item.optional_vars):
                        if isinstance(name, ast.Name):
                            yield name.id, None
        elif loops and isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            yield node.target.id, node.value
        elif loops and isinstance(node, ast.comprehension):
            # [db.execute(f"... FROM {table}") for table in ("a", "b")], as a for loop.
            if isinstance(node.target, ast.Name):
                yield node.target.id, node.iter if _literal(node.iter) or isinstance(node.iter, ast.Name) else None
            else:
                for item in ast.walk(node.target):
                    if isinstance(item, ast.Name):
                        yield item.id, None


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


# BaseLoader builds only strings, lists and dicts.
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
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
    "jwt_verification_disabled": "jwt_verification_disabled",
    "insecure_file_permissions": "insecure_file_permissions",
    "unsafe_xml_external_entities": "unsafe_xml_external_entities",
    "insecure_random_for_secret": "insecure_random_for_secret",
    "open_redirect_user_controlled": "open_redirect_user_controlled",
}
# Non-cryptographic generators; secrets.* and random.SystemRandom are fine.
_RANDOM_FUNCTIONS = frozenset({
    "random.random", "random.randint", "random.randrange", "random.choice", "random.choices",
    "random.sample", "random.getrandbits", "random.uniform", "random.randbytes",
})
_SECRET_NAME = re.compile(r"(?i)token|secret|nonce|passw|api_?key|otp|salt|session_?id")
_REQUEST_VALUES = frozenset({"args", "values", "GET", "form", "query_params"})


def _python_family_rule(node: ast.Call, name: str) -> str | None:
    """The rule families the regex catalog covers for other languages, from the syntax tree."""
    parts = name.split(".")
    last = parts[-1]
    if last == "decode" and "jwt" in parts:
        algorithms = _keyword(node, "algorithms")
        options = _keyword(node, "options")
        if isinstance(algorithms, (ast.List, ast.Tuple, ast.Set)) and any(
            isinstance(item, ast.Constant) and str(item.value).lower() == "none" for item in algorithms.elts
        ):
            return "jwt_verification_disabled"
        if isinstance(options, ast.Dict) and any(
            isinstance(key, ast.Constant) and key.value == "verify_signature" and _is_constant(value, False)
            for key, value in zip(options.keys, options.values, strict=True)
        ):
            return "jwt_verification_disabled"
        if _is_constant(_keyword(node, "verify"), False):
            return "jwt_verification_disabled"
    if last in {"chmod", "fchmod", "lchmod"}:
        # os.chmod(path, mode); a pathlib method takes the mode first.
        index = 1 if parts[0] == "os" else 0
        mode = node.args[index] if len(node.args) > index else _keyword(node, "mode")
        if isinstance(mode, ast.Constant) and isinstance(mode.value, int) and mode.value & 0o002:
            return "insecure_file_permissions"
        if mode is not None and any(_dotted(item).endswith("S_IWOTH") for item in ast.walk(mode)):
            return "insecure_file_permissions"
    if last == "XMLParser" and _is_constant(_keyword(node, "resolve_entities"), True):
        return "unsafe_xml_external_entities"
    if last == "setFeature" and len(node.args) >= 2 and _is_constant(node.args[1], True) and (
        _dotted(node.args[0]).rsplit(".", 1)[-1] in {"feature_external_ges", "feature_external_pes"}
    ):
        return "unsafe_xml_external_entities"
    if last in {"redirect", "HttpResponseRedirect", "RedirectResponse"} and node.args and any(
        isinstance(item, ast.Attribute) and _dotted(item).split(".")[:2] in (
            ["request", value] for value in _REQUEST_VALUES
        )
        for item in ast.walk(node.args[0])
    ):
        return "open_redirect_user_controlled"
    return None


def _python_call_rule(
    node: ast.Call, name: str, aliases: dict[str, str], structure: "_SqlStructure | None" = None,
) -> str | None:
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
        dynamic = _dynamic_sql_argument(node.args[0], structure, node)
        return "possible_sql_injection" if dynamic else None
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
    structure = _SqlStructure(tree)
    matches: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, line: int, name: str) -> None:
        if (rule, line) not in seen:
            seen.add((rule, line))
            matches.append((rule, line, name))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _resolve(_dotted(node.func), aliases)
            rule = _python_call_rule(node, name, aliases, structure) or _python_family_rule(node, name)
            if rule:
                add(rule, node.lineno, name)
        elif isinstance(node, ast.Assign):
            # token = random.choice(...): a secret from a non-cryptographic generator.
            if any(_SECRET_NAME.search(_dotted(target) or "") for target in node.targets) and any(
                isinstance(item, ast.Call) and _resolve(_dotted(item.func), aliases) in _RANDOM_FUNCTIONS
                for item in ast.walk(node.value)
            ):
                add("insecure_random_for_secret", node.lineno, "random")
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
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
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
                    describe_error(exc),
                    confidence="UNKNOWN", severity="LOW",
                    evidence=[record.path],
                    analyzer=self.name,
                )]
        else:
            # Keep line iteration streaming. splitlines() can allocate millions of
            # strings for a newline-heavy 16 MiB source file.
            shell = record.extension in _SHELL_EXTENSIONS
            rules = [
                (rule, _SHELL_EVAL if shell and rule == "dynamic_code_execution" else pattern)
                for rule, pattern, _, _ in _PATTERNS
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
