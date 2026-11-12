"""Lexical taint tracking for brace languages, used by the data-flow analyzer.

Covers JavaScript/TypeScript (Express, Koa, Next.js, NestJS and DOM sources), PHP
(superglobals, Laravel, Symfony), Java/Kotlin/Scala/Groovy (Servlet, Spring, JAX-RS),
Go (net/http, gorilla/mux, Gin, Echo), C# (ASP.NET), Rust (actix-web, axum) and C/C++
(network, stdin and environment input).

The analysis reads the structural lexer's cleaned text, where comments and string
contents are blanked and offsets are kept. In each function body, and in the code
outside functions, assignments and sink calls are visited in source order. A variable
becomes tainted when the right-hand side of its assignment contains a source expression
or a tainted variable outside a sanitizer for the sink kind; re-assigning it from clean
input in the same block clears it. A sink is reported when the argument it is sensitive
to is tainted. String interpolation (template literals, PHP and Kotlin ``"$x"``, C#
``$"{x}"``) is read from the original text.

Functions of the file are summarized first: each parameter is followed to the sinks it
reaches and to the values the function returns, iterated so helpers that call helpers
are followed. A call to such a function then carries taint into the sinks inside it and
out through its return value. Calls passing untrusted input into functions this file
does not define are returned to the code index, which joins them with the summary of
the one file that defines the callee. Branches are not distinguished, so results are
INFERRED.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

from ...intelligence.model import FUNCTION_KINDS, FileModel
from .taint_python import Flow

MAX_LABELS = 6
MAX_EVENTS = 20_000          # assignments and sinks visited per region
MAX_ROUNDS = 3               # summary rounds: helpers calling helpers, up to three deep
MAX_SUMMARY_EVENTS = 200_000  # events visited while summarizing one file, across rounds
MAX_SUMMARY_SINKS = 16       # sink entries kept per parameter
MAX_OUTGOING = 200           # tainted calls into other files recorded per file
_MAX_CALL_DEPTH = 3          # nested helper calls followed inside one expression
_MAX_STATEMENT = 4000        # characters scanned for one right-hand side
_ALL = None                  # sanitizer kind set meaning "every sink kind"
# Label of a parameter while a function is summarized; never reported as a source.
_MARKER = "\x00parameter:"

_IDENTIFIER = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*+")
_PHP_VARIABLE = re.compile(r"\$[A-Za-z_]\w*+")
_ARGUMENT_DELIMITERS = re.compile(r"[()\[\]{},]")
_PARAMETER_DELIMITERS = re.compile(r"[()<>\[\]{},]")
_TERMINATORS = re.compile(r"[()\[\]{};\n]")
_CALL_ARGUMENTS = re.compile(r"\([^()]*+\)")
_PHP_CAST = re.compile(r"\((?:int|integer|float|double|bool|boolean)\)[ \t]*+$")
_SPACE = re.compile(r"\s++")
_CONTINUES = frozenset("+-*/%,=.?:&|([{<>!~^")
_LEADS = frozenset(".+-*/%?:&|,)]}=<>")
_NEWLINE_FAMILIES = frozenset({"js", "go", "kotlin", "scala", "swift", "groovy"})
_NOT_PARAMETERS = frozenset({"final", "const", "readonly", "in", "out", "ref", "params", "this", "mut", "val", "var"})
_DOM_SOURCES = ("location", "window.", "document.")
_RETURN = re.compile(r"(?<![\w$.])return(?![\w$])")
# Families whose parameters read ``name: Type`` or ``name Type`` (otherwise ``Type name``).
_NAME_FIRST_FAMILIES = frozenset({"js", "go", "kotlin", "scala", "rust"})
_SELF_NAMES = frozenset({"self", "this", "&self", "&mut self"})
# Receivers whose methods are library calls, not calls into another project file.
_LIBRARY_RECEIVERS = frozenset({
    "console", "res", "req", "response", "request", "window", "document", "Math", "JSON", "Object",
    "Array", "String", "Number", "Promise", "System", "os", "fmt", "log", "logger", "this", "self",
    "Self", "super", "std", "strings", "strconv", "http", "json", "path", "fs", "util", "Collections",
    "Arrays", "Integer", "Long", "Objects", "Optional", "Convert", "Console", "Task",
})


@dataclass(frozen=True, slots=True)
class Sink:
    pattern: re.Pattern
    kind: str
    arguments: tuple[int, ...] | None = (0,)   # None: every argument; -1: the last one
    style: str = "call"                         # call | assign | statement
    receiver: re.Pattern | None = None          # checked against the receiver before the match
    requires: re.Pattern | None = None          # checked against the call's original text


@dataclass(frozen=True, slots=True)
class Rules:
    hint: re.Pattern                       # searched in the original text; no hit, no analysis
    sources: re.Pattern
    assignment: re.Pattern                 # named groups: names (or destructure), op
    sinks: tuple[Sink, ...]
    sanitizers: tuple[tuple[re.Pattern, frozenset | None], ...] = ()
    postfix_sanitizer: re.Pattern | None = None   # matched right after a tainted identifier
    params: re.Pattern | None = None       # annotation marking a parameter as request input
    out_sources: tuple[tuple[re.Pattern, tuple[int, ...]], ...] = ()
    raw_sources: re.Pattern | None = None  # sources visible only in the original text
    raw_anchor: str = ""                   # cleaned text that must start at a raw source
    interpolation: re.Pattern | None = None
    interpolated: str = ""                 # "all", "double" (PHP) or "dollar" (C#)
    identifier: re.Pattern = _IDENTIFIER
    first_parameter_name: bool = False     # Kotlin/Scala: ``name: Type`` after an annotation
    # Calls that copy their other arguments into argument N (C ``sprintf(buf, ...)``).
    out_propagators: tuple[tuple[re.Pattern, int], ...] = ()
    # Method calls that add their arguments to the receiver (``sb.append(x)``).
    receiver_propagators: re.Pattern | None = None


@dataclass(slots=True)
class Summary:
    """What a function does with its parameters, for callers in this file and in others."""

    params: tuple[str, ...]
    # Parameter index -> (sink kind, sink as written, sink line, helper chain inside).
    sinks: dict[int, set[tuple[str, str, int, str]]] = field(default_factory=dict)
    # Parameter index -> sink kinds its value is sanitized for on the way to a return.
    returns: dict[int, frozenset] = field(default_factory=dict)
    # Untrusted input that the function reads itself and returns.
    sources: frozenset = frozenset()

    def key(self) -> tuple:
        return (
            tuple(sorted((index, tuple(sorted(entries))) for index, entries in self.sinks.items())),
            tuple(sorted(self.returns.items())), tuple(sorted(self.sources)),
        )

    def merge(self, other: "Summary") -> None:
        """Same-named functions (overloads, methods of different classes) are combined."""
        for index, entries in other.sinks.items():
            self.sinks.setdefault(index, set()).update(entries)
        for index, cleared in other.returns.items():
            self.returns[index] = self.returns.get(index, cleared) & cleared
        self.sources = frozenset(sorted(self.sources | other.sources)[:MAX_LABELS])


@dataclass(frozen=True, slots=True)
class OutgoingCall:
    """Untrusted input passed to a function this file does not define."""

    callee: str
    receiver: str
    arg: int
    source: str
    source_line: int
    line: int


@dataclass(slots=True)
class LexicalResult:
    flows: list[Flow]
    sources: int
    summaries: dict[str, Summary]
    outgoing: list[OutgoingCall]


def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern)


_RECEIVER_PROPAGATORS = re.compile(
    r"\.(?:append|Append|AppendFormat|AppendLine|push|unshift|add|Add|concat|insert|Insert|WriteString|"
    r"push_str|extend)[ \t]*+\("
)


# --------------------------------------------------------------------------- JavaScript

_JS_DATABASE = _c(r"(?i)(?:^|[._$])(?:db|database|conn|connection|pool|client|knex|sequelize|mysql|pg|sql|"
                  r"sqlite|prisma|tx|trx|repo|repository|manager|em|datasource|query)(?:$|[._])")
_JS = Rules(
    hint=_c(r"(?:req|request|ctx)\.|location\.|document\.|window\.name|router\.query|@(?:Query|Body|Param|Headers)\("),
    sources=_c(
        r"(?<![\w$.])(?:req|request|ctx\.request|ctx)\.(?:query|body|params|headers|cookies|files|file|originalUrl|url)\b"
        r"|(?<![\w$.])(?:window\.|document\.)?location\.(?:search|hash|href|pathname)\b"
        r"|(?<![\w$.])document\.(?:URL|documentURI|referrer|cookie)\b|(?<![\w$.])window\.name\b"
        r"|(?<![\w$.])router\.query\b"
    ),
    assignment=_c(
        r"(?<![\w$.])(?:const|let|var)[ \t]++(?P<names>[A-Za-z_$][\w$]*+)"
        r"(?:[ \t]*+:[ \t]*+[\w$<>\[\]|, .]{1,120}+)?[ \t]*+(?P<op>=)(?![=>])"
        r"|(?<![\w$.])(?:const|let|var)[ \t]++(?P<destructure>[{\[][^{}\[\]=;]{0,400}+[}\]])[ \t]*+=(?![=>])"
        r"|(?<![\w$.])(?P<plain>[A-Za-z_$][\w$]*+)[ \t]*+(?P<plain_op>\+?=)(?![=>])"
    ),
    sinks=(
        Sink(_c(r"(?<![\w$.])eval[ \t]*+\(|(?<![\w$])new[ \t]++Function[ \t]*+\(|(?<![\w$.])Function[ \t]*+\("
                r"|(?<![\w$])vm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)[ \t]*+\("), "code"),
        Sink(_c(r"(?<![\w$])(?:child_process|cp|childProcess|shell)\.(?:execSync|exec)[ \t]*+\("
                r"|(?<![\w$.])(?:execSync|exec)[ \t]*+\("), "command"),
        Sink(_c(r"\.(?:query|raw|execute|unsafe|\$queryRawUnsafe|\$executeRawUnsafe|queryRaw|whereRaw)[ \t]*+\("),
             "sql", receiver=_JS_DATABASE),
        Sink(_c(r"(?<![\w$])res\.(?:send|write|end)[ \t]*+\(|(?<![\w$])document\.write(?:ln)?[ \t]*+\("), "xss"),
        Sink(_c(r"\.(?:innerHTML|outerHTML)[ \t]*+\+?=(?!=)"), "xss", style="assign"),
        Sink(_c(r"\.insertAdjacentHTML[ \t]*+\("), "xss", arguments=(1,)),
        Sink(_c(r"dangerouslySetInnerHTML[ \t]*+=[ \t]*+\{\{[ \t]*+__html[ \t]*+:"), "xss", style="assign"),
        Sink(_c(r"(?<![\w$])(?:fs|fsp|fsPromises|fse)\.(?:readFile|readFileSync|createReadStream|createWriteStream|"
                r"writeFile|writeFileSync|appendFile|unlink|unlinkSync|readdir|readdirSync|open|openSync|rm|rmSync)"
                r"[ \t]*+\(|(?<![\w$])res\.(?:sendFile|download)[ \t]*+\("), "path"),
        Sink(_c(r"(?<![\w$.])fetch[ \t]*+\(|(?<![\w$])(?:axios|got|superagent|needle|ky)"
                r"(?:\.(?:get|post|put|patch|delete|head|request))?[ \t]*+\(|(?<![\w$])https?\.(?:get|request)[ \t]*+\("),
             "ssrf"),
        Sink(_c(r"(?<![\w$])res\.redirect[ \t]*+\("), "redirect", arguments=(-1,)),
        Sink(_c(r"(?<![\w$.])(?:window\.)?location(?:\.href)?[ \t]*+=(?!=)"), "redirect", style="assign"),
        Sink(_c(r"(?<![\w$.])(?:window\.)?location\.(?:assign|replace)[ \t]*+\("), "redirect"),
        Sink(_c(r"(?<![\w$.])unserialize[ \t]*+\(|(?<![\w$])serialize\.unserialize[ \t]*+\("), "deserialization"),
    ),
    sanitizers=(
        (_c(r"(?<![\w$.])(?:parseInt|parseFloat|Number|Boolean|isNaN)[ \t]*+\("
            r"|(?<![\w$])validator\.(?:toInt|toFloat|isInt|isUUID|isNumeric)[ \t]*+\("), _ALL),
        (_c(r"(?<![\w$.])(?:escape|escapeHtml|sanitize|sanitizeHtml|xss|encodeURIComponent|encodeURI)[ \t]*+\("
            r"|(?<![\w$])(?:DOMPurify\.sanitize|validator\.escape|he\.encode|_\.escape|lodash\.escape)[ \t]*+\("),
         frozenset({"xss", "redirect"})),
        (_c(r"(?<![\w$.])basename[ \t]*+\(|(?<![\w$])path\.basename[ \t]*+\("), frozenset({"path"})),
        (_c(r"(?<![\w$])(?:sqlstring|SqlString|mysql|connection|pool|db)\.escape(?:Id)?[ \t]*+\("), frozenset({"sql"})),
    ),
    params=_c(r"@(?:Query|Body|Param|Headers|Req)\([^()\n]{0,200}+\)[ \t]*+(?P<name>[A-Za-z_$][\w$]*+)"),
    interpolation=_c(r"\$\{([^{}\n]{1,200}+)\}"),
    interpolated="backtick",
    receiver_propagators=_RECEIVER_PROPAGATORS,
)

# --------------------------------------------------------------------------- PHP

_PHP = Rules(
    hint=_c(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|\$request->|Request::|Input::|getallheaders|php://input"),
    sources=_c(
        r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
        r"|\$request->(?:query|request|cookies|headers|files|attributes)->(?:get|all)\b"
        r"|\$request->(?:input|query|post|get|all|cookie|header|file|json|route)\b"
        r"|(?<![\w$>])(?:Request::(?:input|query|get|all|post)|Input::(?:get|all))\b"
        r"|(?<![\w$>])getallheaders[ \t]*+\("
    ),
    raw_sources=_c(
        r"\$_SERVER\[[ \t]*+['\"](?:HTTP_\w{1,40}+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO|REDIRECT_URL)['\"]"
        r"|file_get_contents[ \t]*+\([ \t]*+['\"]php://input['\"]"
    ),
    raw_anchor="$_SERVER|file_get_contents",
    assignment=_c(r"(?P<names>\$[A-Za-z_]\w*+)(?:\[[^\]\n]{0,100}+\])?[ \t]*+(?P<op>\.=|=)(?![=>])"),
    sinks=(
        Sink(_c(r"(?<![\w$>])(?:mysql_query|mysqli_query|mysqli_real_query|mysqli_multi_query|pg_query|"
                r"pg_send_query|sqlite_query|sqlsrv_query|odbc_exec|db2_exec|oci_parse)[ \t]*+\("), "sql", arguments=None),
        Sink(_c(r"->(?:query|exec|multi_query|real_query|prepare|unprepared|statement|raw|whereRaw|orWhereRaw|"
                r"havingRaw|orderByRaw|selectRaw|groupByRaw|fromRaw|get_results|get_row|get_var|get_col)[ \t]*+\("), "sql"),
        Sink(_c(r"(?<![\w$>])DB::(?:select|insert|update|delete|statement|unprepared|raw)[ \t]*+\("), "sql"),
        Sink(_c(r"(?<![\w$>:])(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)[ \t]*+\("), "command"),
        Sink(_c(r"(?<![\w$>:])(?:eval|assert|create_function)[ \t]*+\("), "code"),
        Sink(_c(r"(?<![\w$>:])(?:include|include_once|require|require_once)\b"), "path", style="statement"),
        Sink(_c(r"(?<![\w$>:])(?:fopen|file_get_contents|readfile|file|unlink|file_put_contents|fpassthru|opendir|"
                r"scandir|copy|rename|rmdir|mkdir|highlight_file|show_source|parse_ini_file|simplexml_load_file)"
                r"[ \t]*+\("), "path"),
        Sink(_c(r"(?<![\w$>:])(?:echo|print)\b"), "xss", style="statement"),
        Sink(_c(r"(?<![\w$>:])(?:printf|vprintf)[ \t]*+\("), "xss", arguments=None),
        Sink(_c(r"(?<![\w$>:])unserialize[ \t]*+\("), "deserialization"),
        Sink(_c(r"(?<![\w$>:])header[ \t]*+\("), "redirect", requires=_c(r"(?i)location[ \t]*+:")),
        Sink(_c(r"(?<![\w$>:])curl_init[ \t]*+\("), "ssrf"),
        Sink(_c(r"(?<![\w$>:])curl_setopt[ \t]*+\("), "ssrf", arguments=(2,), requires=_c(r"CURLOPT_URL")),
    ),
    sanitizers=(
        (_c(r"(?<![\w$>])(?:intval|floatval|boolval|abs|count|md5|sha1|hash|crc32|password_hash|is_numeric|"
            r"ctype_digit|ctype_alnum|ctype_alpha)[ \t]*+\("), _ALL),
        (_c(r"(?<![\w$>])(?:htmlspecialchars|htmlentities|strip_tags|esc_html|esc_attr|esc_url|e)[ \t]*+\("),
         frozenset({"xss"})),
        (_c(r"(?<![\w$>])(?:escapeshellarg|escapeshellcmd)[ \t]*+\("), frozenset({"command"})),
        (_c(r"(?<![\w$>])(?:mysqli_real_escape_string|mysql_real_escape_string|pg_escape_string|pg_escape_literal|"
            r"sqlite_escape_string)[ \t]*+\(|->(?:quote|prepare|real_escape_string|escape)[ \t]*+\("), frozenset({"sql"})),
        (_c(r"(?<![\w$>])basename[ \t]*+\("), frozenset({"path"})),
    ),
    interpolation=_c(r"(\$[A-Za-z_]\w*+)"),
    interpolated="double",
    identifier=_PHP_VARIABLE,
)

# --------------------------------------------------------------------------- JVM

_JVM_DATABASE = _c(r"(?i)(?:^|[._])(?:stmt|statement|st|conn|connection|entitymanager|em|session|"
                   r"db|dao|ps|pstmt|preparedstatement|handle|jdbi|dsl|query)(?:$|[._])|template$")
_JVM_SINKS = (
    Sink(_c(r"\.(?:executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|"
            r"createQuery|createNativeQuery|createSQLQuery|nativeQuery|queryForObject|queryForList|queryForMap|"
            r"queryForRowSet|query|update|batchUpdate)[ \t]*+\("), "sql", receiver=_JVM_DATABASE),
    Sink(_c(r"(?<![\w$])Runtime\.getRuntime\(\)\.exec[ \t]*+\(|(?<![\w$])ProcessBuilder[ \t]*+\("), "command",
         arguments=None),
    Sink(_c(r"(?<![\w$])(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|PrintWriter)"
            r"[ \t]*+\(|(?<![\w$])(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|readAllLines|readString|newInputStream|"
            r"newOutputStream|newBufferedReader|newBufferedWriter|lines|delete|deleteIfExists|write|writeString|copy|"
            r"move|list|walk))[ \t]*+\("), "path", arguments=None),
    Sink(_c(r"(?<![\w$])(?:URL|URI\.create)[ \t]*+\(|\.(?:getForObject|getForEntity|postForObject|postForEntity|"
            r"exchange)[ \t]*+\(|(?<![\w$])HttpRequest\.newBuilder[ \t]*+\("), "ssrf"),
    Sink(_c(r"(?<![\w$])(?:ObjectInputStream|XMLDecoder)[ \t]*+\(|\.fromXML[ \t]*+\("), "deserialization"),
    Sink(_c(r"\.getWriter\(\)\.(?:print|println|write|append|printf|format)[ \t]*+\("), "xss", arguments=None),
    Sink(_c(r"\.sendRedirect[ \t]*+\("), "redirect"),
    Sink(_c(r"\.eval[ \t]*+\("), "code", receiver=_c(r"(?i)engine$")),
    Sink(_c(r"\.parseExpression[ \t]*+\("), "code"),
)
_JVM_SANITIZERS = (
    (_c(r"(?<![\w$])(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Double\.(?:parseDouble|valueOf)|"
        r"Float\.parseFloat|Boolean\.parseBoolean|Short\.parseShort|UUID\.fromString)[ \t]*+\("), _ALL),
    (_c(r"(?<![\w$])(?:StringEscapeUtils\.escape(?:Html4|Html3|Xml10|Xml11|Xml|EcmaScript)|HtmlUtils\.htmlEscape|"
        r"Encode\.forHtml\w*+|HtmlEscapers\.htmlEscaper\(\)\.escape)[ \t]*+\("), frozenset({"xss"})),
    (_c(r"(?<![\w$])FilenameUtils\.getName[ \t]*+\("), frozenset({"path"})),
)
_JVM_PARAMS = _c(r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart|"
                 r"QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam|BeanParam)\b")
_JVM_HINT = _c(r"getParameter|getQueryString|getHeader|getCookies|getInputStream|getReader|getPathInfo|getRequestUR|"
               r"getPart|@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart|"
               r"QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam|BeanParam)")
_JVM_SOURCES = _c(r"(?<![\w$])[A-Za-z_]\w*+\.(?:getParameter|getParameterValues|getParameterMap|getParameterNames|"
                  r"getQueryString|getHeader|getHeaders|getCookies|getInputStream|getReader|getPathInfo|getRequestURI|"
                  r"getRequestURL|getPart|getParts)[ \t]*+\(")
_JAVA = Rules(
    hint=_JVM_HINT, sources=_JVM_SOURCES,
    assignment=_c(r"(?<![\w$.])(?P<names>[A-Za-z_]\w*+)[ \t]*+(?P<op>\+?=)(?![=])"),
    sinks=_JVM_SINKS, sanitizers=_JVM_SANITIZERS, params=_JVM_PARAMS,
    receiver_propagators=_RECEIVER_PROPAGATORS,
)
_KOTLIN = Rules(
    hint=_JVM_HINT, sources=_JVM_SOURCES,
    assignment=_c(r"(?<![\w$.])(?P<names>[A-Za-z_]\w*+)(?:[ \t]*+:[ \t]*+[\w<>?,. \[\]]{1,120}+)?[ \t]*+"
                  r"(?P<op>\+?=)(?![=>])"),
    sinks=_JVM_SINKS, sanitizers=_JVM_SANITIZERS, params=_JVM_PARAMS,
    postfix_sanitizer=_c(r"\.(?:toInt|toLong|toDouble|toFloat|toShort|toBoolean|toIntOrNull|toLongOrNull|"
                         r"toDoubleOrNull)\("),
    interpolation=_c(r"\$\{([^{}\n]{1,200}+)\}|\$([A-Za-z_]\w*+)"), interpolated="all",
    first_parameter_name=True,
    receiver_propagators=_RECEIVER_PROPAGATORS,
)

# --------------------------------------------------------------------------- Go

_GO_DATABASE = _c(r"(?i)(?:^|[._])(?:db|tx|conn|stmt|sqlx?|pool|gorm|database|session|repo|store)(?:$|[._])")
_GO = Rules(
    hint=_c(r"\.URL\.|FormValue|PostForm|\.Form\b|Header\.Get|\.Body\b|\.Cookie\(|mux\.Vars|\.Query\(|\.Param\(|"
            r"\.Bind|\.ShouldBind|NewDecoder|DefaultQuery|QueryParam"),
    sources=_c(
        r"(?<![\w$.])(?:r|req|request)\.(?:URL\.Query\(\)|URL\.RawQuery\b|URL\.Path\b|URL\.String\(\)|FormValue[ \t]*+\(|"
        r"PostFormValue[ \t]*+\(|Form\b|PostForm\b|MultipartForm\b|Header\.Get[ \t]*+\(|Body\b|Cookie[ \t]*+\()"
        r"|(?<![\w$.])mux\.Vars[ \t]*+\("
        r"|(?<![\w$.])(?:c|ctx)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|GetHeader|FormValue|"
        r"QueryParam|QueryParams|FormParams|GetQuery|GetPostForm)[ \t]*+\("
    ),
    out_sources=(
        (_c(r"(?<![\w$.])(?:c|ctx)\.(?:ShouldBind\w*+|Bind\w*+)[ \t]*+\("), (0,)),
        (_c(r"(?<![\w$])json\.NewDecoder\([ \t]*+(?:r|req|request)\.Body[ \t]*+\)\.Decode[ \t]*+\("), (0,)),
    ),
    assignment=_c(r"(?<![\w$.])(?:var[ \t]++)?(?P<names>[A-Za-z_]\w*+(?:[ \t]*+,[ \t]*+[A-Za-z_]\w*+){0,15}+)"
                  r"(?:[ \t]++[\w.*\[\]]{1,60}+)?[ \t]*+(?P<op>:=|\+=|=)(?!=)"),
    sinks=(
        Sink(_c(r"\.(?:Query|QueryRow|Exec|Raw|Prepare|MustExec|Queryx|QueryRowx|NamedExec|Where|Order|Group|"
                r"Having)[ \t]*+\("), "sql", receiver=_GO_DATABASE),
        Sink(_c(r"\.(?:QueryContext|QueryRowContext|ExecContext|PrepareContext|Get|Select)[ \t]*+\("), "sql",
             arguments=(1,), receiver=_GO_DATABASE),
        Sink(_c(r"(?<![\w$])exec\.Command(?:Context)?[ \t]*+\("), "command", arguments=None),
        Sink(_c(r"(?<![\w$])(?:os\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|WriteFile|ReadDir|Mkdir|MkdirAll)|"
                r"ioutil\.(?:ReadFile|WriteFile|ReadDir))[ \t]*+\("), "path"),
        Sink(_c(r"(?<![\w$])http\.ServeFile[ \t]*+\("), "path", arguments=(2,)),
        Sink(_c(r"\.(?:File|FileAttachment|Attachment|SendFile)[ \t]*+\("), "path", receiver=_c(r"^(?:c|ctx)$")),
        Sink(_c(r"(?<![\w$])http\.(?:Get|Head|Post|PostForm)[ \t]*+\("), "ssrf"),
        Sink(_c(r"(?<![\w$])http\.NewRequest[ \t]*+\("), "ssrf", arguments=(1,)),
        Sink(_c(r"(?<![\w$])http\.NewRequestWithContext[ \t]*+\("), "ssrf", arguments=(2,)),
        Sink(_c(r"(?<![\w$])template\.(?:HTML|JS|HTMLAttr|URL)[ \t]*+\("), "xss"),
        Sink(_c(r"(?<![\w$])fmt\.Fprint(?:f|ln)?[ \t]*+\((?=[ \t]*+(?:w|rw|writer|resp)[ \t]*+,)"), "xss",
             arguments=None),
        Sink(_c(r"(?<![\w$])(?:w|rw|writer)\.Write(?:String)?[ \t]*+\(|(?<![\w$])io\.WriteString[ \t]*+\("), "xss",
             arguments=None),
        Sink(_c(r"(?<![\w$])http\.Redirect[ \t]*+\("), "redirect", arguments=(2,)),
        Sink(_c(r"\.Redirect[ \t]*+\("), "redirect", arguments=(1,), receiver=_c(r"^(?:c|ctx)$")),
        Sink(_c(r"(?<![\w$])template\.New\([^()\n]{0,100}+\)\.Parse[ \t]*+\("), "template"),
    ),
    sanitizers=(
        (_c(r"(?<![\w$])(?:strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)|uuid\.(?:Parse|MustParse))"
            r"[ \t]*+\("), _ALL),
        (_c(r"(?<![\w$])(?:filepath\.Base|path\.Base)[ \t]*+\("), frozenset({"path"})),
        (_c(r"(?<![\w$])(?:html\.EscapeString|template\.HTMLEscapeString|template\.JSEscapeString|url\.QueryEscape|"
            r"url\.PathEscape)[ \t]*+\("), frozenset({"xss"})),
    ),
    receiver_propagators=_RECEIVER_PROPAGATORS,
)

# --------------------------------------------------------------------------- C#

_CSHARP = Rules(
    hint=_c(r"Request\.|\[From(?:Query|Body|Route|Form|Header)"),
    sources=_c(r"(?<![\w$.])(?:Request|HttpContext\.Request|context\.Request|ctx\.Request|req|request)\."
               r"(?:Query|Form|QueryString|Params|Headers|Cookies|Body|RouteValues|Path|PathBase|RawUrl|Url|"
               r"ServerVariables|Files|InputStream)\b"),
    params=_c(r"\[(?:FromQuery|FromBody|FromRoute|FromForm|FromHeader)\b[^\]\n]{0,100}+\]"),
    assignment=_c(r"(?<![\w$.])(?P<names>[A-Za-z_]\w*+)[ \t]*+(?P<op>\+?=)(?![=>])"),
    sinks=(
        Sink(_c(r"(?<![\w$])new[ \t]++(?:SqlCommand|SqliteCommand|SQLiteCommand|NpgsqlCommand|MySqlCommand|OracleCommand|"
                r"OleDbCommand|OdbcCommand|SqlDataAdapter)[ \t]*+\(|\.(?:ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw|"
                r"SqlQueryRaw|ExecuteSqlCommand|ExecuteSqlCommandAsync|FromSql)[ \t]*+\("), "sql"),
        Sink(_c(r"\.(?:Query|QueryAsync|QueryFirst|QueryFirstOrDefault|QueryFirstAsync|QueryFirstOrDefaultAsync|"
                r"QuerySingle|QuerySingleOrDefault|QuerySingleAsync|QueryMultiple|Execute|ExecuteAsync|ExecuteScalar|"
                r"ExecuteScalarAsync|ExecuteReader|ExecuteReaderAsync)[ \t]*+\("), "sql",
             receiver=_c(r"(?i)(?:^|[._])(?:conn|connection|db|cnn|sql|_db|_connection|database|dbconnection)$")),
        Sink(_c(r"\.CommandText[ \t]*+=(?!=)"), "sql", style="assign"),
        Sink(_c(r"(?<![\w$])Process\.Start[ \t]*+\(|(?<![\w$])new[ \t]++ProcessStartInfo[ \t]*+\("), "command",
             arguments=None),
        Sink(_c(r"\.(?:Arguments|FileName)[ \t]*+=(?!=)"), "command", style="assign"),
        Sink(_c(r"(?<![\w$])File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|OpenRead|OpenText|Open|OpenWrite|"
                r"WriteAllText|WriteAllBytes|AppendAllText|Delete|Copy|Move)[ \t]*+\(|(?<![\w$])new[ \t]++(?:FileStream|"
                r"StreamReader|StreamWriter|FileInfo|DirectoryInfo)[ \t]*+\(|(?<![\w$.])PhysicalFile[ \t]*+\("
                r"|(?<![\w$])Directory\.(?:GetFiles|Delete|EnumerateFiles|GetDirectories)[ \t]*+\("), "path"),
        Sink(_c(r"\.(?:GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|PutAsync|DeleteAsync|"
                r"DownloadString|DownloadData|DownloadFile)[ \t]*+\("), "ssrf", receiver=_c(r"(?i)client|http|web")),
        Sink(_c(r"(?<![\w$])WebRequest\.Create[ \t]*+\("), "ssrf"),
        Sink(_c(r"(?<![\w$])Html\.Raw[ \t]*+\(|(?<![\w$])new[ \t]++(?:HtmlString|MarkupString)[ \t]*+\("
                r"|(?<![\w$])Response\.Write[ \t]*+\("), "xss"),
        Sink(_c(r"(?<![\w$.])(?:Redirect|RedirectPermanent)[ \t]*+\(|(?<![\w$])Response\.Redirect[ \t]*+\("), "redirect"),
        Sink(_c(r"\.(?:Deserialize|UnsafeDeserialize|ReadObject)[ \t]*+\("), "deserialization",
             receiver=_c(r"(?i)formatter|binary|soap|los|netdatacontract|objectstate")),
        Sink(_c(r"(?<![\w$])CSharpScript\.(?:EvaluateAsync|RunAsync|Create)[ \t]*+\("), "code"),
    ),
    sanitizers=(
        (_c(r"(?<![\w$])(?:int|long|short|double|float|decimal|Guid|bool|DateTime|Int32|Int64)\.(?:Parse|TryParse)"
            r"[ \t]*+\(|(?<![\w$])Convert\.To(?:Int16|Int32|Int64|Double|Decimal|Boolean)[ \t]*+\("), _ALL),
        (_c(r"(?<![\w$])(?:HtmlEncoder\.Default\.Encode|HttpUtility\.HtmlEncode|WebUtility\.HtmlEncode|"
            r"AntiXssEncoder\.HtmlEncode|Encoder\.HtmlEncode)[ \t]*+\("), frozenset({"xss"})),
        (_c(r"(?<![\w$])Path\.GetFileName[ \t]*+\("), frozenset({"path"})),
    ),
    interpolation=_c(r"\{([^{}\n]{1,200}+)\}"), interpolated="dollar",
    receiver_propagators=_RECEIVER_PROPAGATORS,
)

# --------------------------------------------------------------------------- Rust

_RUST = Rules(
    hint=_c(r"Query|Path|Json|Form|query_string|match_info"),
    sources=_c(r"(?<![\w$.])(?:req|request)\.(?:query_string|uri|headers|match_info)[ \t]*+\("),
    params=_c(r"(?<![\w$])(?P<name>[A-Za-z_]\w*+)[ \t]*+:[ \t]*+(?:web::|axum::extract::|extract::)?(?:Query|Path|Json|Form)"
              r"[ \t]*+<|(?<![\w$])(?:web::)?(?:Query|Path|Json|Form)[ \t]*+\([ \t]*+(?:mut[ \t]++)?"
              r"(?P<inner>[A-Za-z_]\w*+)[ \t]*+\)[ \t]*+:"),
    assignment=_c(r"(?<![\w$.])(?:let[ \t]++(?:mut[ \t]++)?)?(?P<names>[A-Za-z_]\w*+)(?:[ \t]*+:[^=;\n]{1,120}+)?"
                  r"[ \t]*+(?P<op>\+?=)(?![=>])"),
    sinks=(
        Sink(_c(r"(?<![\w$])Command::new[ \t]*+\("), "command"),
        Sink(_c(r"\.args?[ \t]*+\("), "command", receiver=_c(r"(?i)command|cmd")),
        Sink(_c(r"(?<![\w$:])(?:sqlx::)?query(?:_as|_scalar)?[ \t]*+\(|(?<![\w$])(?:diesel::)?sql_query[ \t]*+\("), "sql"),
        Sink(_c(r"\.(?:execute|query|query_row|prepare|batch_execute|simple_query)[ \t]*+\("), "sql",
             receiver=_c(r"(?i)(?:^|[._])(?:conn|connection|client|tx|db|pool|transaction)$")),
        Sink(_c(r"(?<![\w$])(?:std::)?fs::(?:read|read_to_string|write|remove_file|remove_dir_all|create_dir_all|read_dir)"
                r"[ \t]*+\(|(?<![\w$])(?:File|NamedFile)::(?:open|create)[ \t]*+\("), "path"),
        Sink(_c(r"(?<![\w$])reqwest::(?:blocking::)?get[ \t]*+\("), "ssrf"),
        Sink(_c(r"\.(?:get|post|put|delete|patch)[ \t]*+\("), "ssrf", receiver=_c(r"(?i)client$")),
        Sink(_c(r"(?<![\w$])Html[ \t]*+\("), "xss"),
        Sink(_c(r"\.body[ \t]*+\("), "xss", receiver=_c(r"HttpResponse")),
        Sink(_c(r"(?<![\w$])Redirect::(?:to|temporary|permanent|see_other)[ \t]*+\("), "redirect"),
    ),
    sanitizers=(),
    receiver_propagators=_RECEIVER_PROPAGATORS,
    postfix_sanitizer=_c(r"\.parse::<[ \t]*+(?:u|i)(?:8|16|32|64|128|size)[ \t]*+>\(|\.parse::<[ \t]*+(?:f32|f64|bool|Uuid)"
                         r"[ \t]*+>\("),
)

# --------------------------------------------------------------------------- C / C++

_C = Rules(
    hint=_c(r"getenv|argv|recv|fgets|gets[ \t]*+\(|scanf"),
    sources=_c(r"(?<![\w$.>])getenv[ \t]*+\(|(?<![\w$.>])argv\b"),
    out_sources=(
        (_c(r"(?<![\w$.>])(?:recv|recvfrom)[ \t]*+\("), (1,)),
        (_c(r"(?<![\w$.>])(?:fgets|gets)[ \t]*+\("), (0,)),
        (_c(r"(?<![\w$.>])scanf[ \t]*+\("), (1, 2, 3, 4)),
        (_c(r"(?<![\w$.>])fscanf[ \t]*+\("), (2, 3, 4, 5)),
    ),
    assignment=_c(r"(?<![\w$.>])(?P<names>[A-Za-z_]\w*+)(?:\[[^\]\n]{0,60}+\])?[ \t]*+(?P<op>\+?=)(?!=)"),
    sinks=(
        Sink(_c(r"(?<![\w$.>])(?:system|popen)[ \t]*+\("), "command"),
        Sink(_c(r"(?<![\w$.>])(?:printf|vprintf)[ \t]*+\("), "format_string"),
        Sink(_c(r"(?<![\w$.>])(?:fprintf|sprintf|vsprintf|vfprintf|dprintf|syslog)[ \t]*+\("), "format_string",
             arguments=(1,)),
        Sink(_c(r"(?<![\w$.>])(?:snprintf|vsnprintf)[ \t]*+\("), "format_string", arguments=(2,)),
        Sink(_c(r"(?<![\w$.>])(?:mysql_query|mysql_real_query|sqlite3_exec|sqlite3_prepare(?:_v2|_v3)?|PQexec)"
                r"[ \t]*+\("), "sql", arguments=(1,)),
        Sink(_c(r"(?<![\w$.>])(?:fopen|unlink|remove|rename)[ \t]*+\("), "path"),
        Sink(_c(r"(?<![\w$.>])(?:strcpy|strcat|wcscpy|wcscat|stpcpy)[ \t]*+\("), "buffer", arguments=(1,)),
    ),
    sanitizers=(
        (_c(r"(?<![\w$.>])(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|strtod|atof)[ \t]*+\("), _ALL),
    ),
    out_propagators=(
        (_c(r"(?<![\w$.>])(?:sprintf|vsprintf|snprintf|vsnprintf|strcpy|strncpy|strcat|strncat|stpcpy|memcpy|memmove|"
            r"wcscpy|wcscat|strlcpy|strlcat)[ \t]*+\("), 0),
    ),
)

RULES: dict[str, Rules] = {
    "js": _JS, "php": _PHP, "java": _JAVA, "kotlin": _KOTLIN, "scala": _KOTLIN, "groovy": _KOTLIN,
    "go": _GO, "csharp": _CSHARP, "rust": _RUST, "c": _C, "cpp": _C,
}


# --------------------------------------------------------------------------- engine

def _statement_end(clean: str, start: int, limit: int, newline: bool) -> int:
    depth = 0
    stop = min(limit, start + _MAX_STATEMENT)
    for match in _TERMINATORS.finditer(clean, start, stop):
        char = match.group()
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return match.start()
            depth -= 1
        elif depth == 0 and (char == ";" or (newline and _ends_line(clean, start, match.start()))):
            return match.start()
    return stop


def _ends_line(clean: str, start: int, newline: int) -> bool:
    """Whether a newline ends the statement (no operator at the line end or next line start)."""
    back = newline - 1
    while back >= start and clean[back] in " \t\r":
        back -= 1
    if back < start or clean[back] in _CONTINUES:
        return False
    ahead, end = newline + 1, min(len(clean), newline + 200)
    while ahead < end and clean[ahead] in " \t\r\n":
        ahead += 1
    return ahead >= len(clean) or clean[ahead] not in _LEADS


def _split(clean: str, start: int, stop: int, delimiters: re.Pattern = _ARGUMENT_DELIMITERS) -> list[tuple[int, int]]:
    spans, depth, begin = [], 0, start
    for match in delimiters.finditer(clean, start, stop):
        char = match.group()
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= 1
            if depth < 0:
                spans.append((begin, match.start()))
                return spans
        elif depth == 0:
            spans.append((begin, match.start()))
            begin = match.end()
    spans.append((begin, stop))
    return spans


def _label(text: str) -> str:
    label = _SPACE.sub("", text)[:80]
    return label + ")" if label.count("(") > label.count(")") else label


class _FileTaint:
    def __init__(self, model: FileModel, rules: Rules, family: str) -> None:
        self.model = model
        self.rules = rules
        self.family = family
        self.clean = model.clean
        self.newline = family in _NEWLINE_FAMILIES
        # Keyed without the function: nested functions are visited with their parents.
        self.flows: dict[tuple, Flow] = {}
        self.source_sites: set[int] = set()
        self._closes: dict[int, int] | None = None
        self._opens: list[int] | None = None
        # Inter-procedural state: summaries of this file's functions, the summary being
        # built (None while reporting), and calls into functions defined elsewhere.
        self.summaries: dict[str, Summary] = {}
        self.call_pattern: re.Pattern | None = None
        self.collect: Summary | None = None
        self.local_names: set[str] = set()
        self.outgoing: dict[tuple, OutgoingCall] = {}
        self.summary_events = 0
        self._depth = 0
        self._claims: tuple[list[int], list[tuple[int, int]]] | None = None

    def set_summaries(self, summaries: dict[str, Summary]) -> None:
        self.summaries = summaries
        names = sorted((name for name, item in summaries.items() if item.sinks or item.returns or item.sources),
                       key=len, reverse=True)
        self.call_pattern = re.compile(
            r"(?<![\w$.>:])(?:(?:this|self)\s*+\.\s*+|\$this\s*+->\s*+|(?:self|static|Self)\s*+::\s*+)?"
            r"(?P<name>" + "|".join(re.escape(name) for name in names) + r")\s*+\("
        ) if names else None

    def signature_params(self, symbol) -> list[str]:
        """Positional parameter names, read from the first parentheses after the name."""
        clean, body = self.clean, symbol.body[0]
        start = self.model.line_start(symbol.line)
        name = re.compile(rf"(?<![\w$]){re.escape(symbol.name)}(?![\w$])").search(clean, start, body)
        opening = clean.find("(", name.end() if name else start, body)
        close = self.model.parens.get(opening) if opening >= 0 else None
        if close is None or close > body:
            return []
        names = []
        for part_start, part_end in _split(clean, opening + 1, close, _PARAMETER_DELIMITERS):
            text = clean[part_start:part_end].split("=", 1)[0].strip()
            if not text or text in _SELF_NAMES or text.startswith(("{", "[")):
                names.append("")  # destructured or receiver: keeps the positions aligned
                continue
            if self.family == "php":
                match = _PHP_VARIABLE.search(text)
                names.append(match.group() if match else "")
                continue
            words = [word for word in _IDENTIFIER.findall(text) if word not in _NOT_PARAMETERS]
            names.append((words[0] if self.family in _NAME_FIRST_FAMILIES else words[-1]) if words else "")
        if self.family == "rust" and names and names[0] == "":
            names = names[1:]  # ``self`` is the receiver, not a positional argument
        return names

    # -- structure helpers -------------------------------------------------------
    def closes(self) -> dict[int, int]:
        if self._closes is None:
            self._closes = {close: opening for opening, close in self.model.parens.items()}
        return self._closes

    def block_of(self, offset: int) -> int:
        """Offset of the innermost ``{`` enclosing ``offset`` (-1 at file level)."""
        if self._opens is None:
            self._opens = sorted(self.model.braces)
        index = bisect.bisect_left(self._opens, offset) - 1
        steps = 0
        while index >= 0 and steps < 256:
            opening = self._opens[index]
            if self.model.braces[opening] > offset:
                return opening
            index -= 1
            steps += 1
        return -1

    def receiver_before(self, offset: int) -> str:
        clean, position, floor = self.clean, offset, max(0, offset - 160)
        while position > floor:
            char = clean[position - 1]
            if char.isalnum() or char in "_$.:":
                position -= 1
            elif char == ")":
                opening = self.closes().get(position - 1)
                if opening is None or opening < floor:
                    break
                position = opening
            elif char == ">" and clean[position - 2:position] == "->":
                position -= 2
            else:
                break
        return _CALL_ARGUMENTS.sub("()", clean[position:offset]).strip(".:")

    def interpolates(self, span: tuple[int, int]) -> bool:
        mode, text = self.rules.interpolated, self.model.text
        if mode == "all":
            return True
        if mode == "backtick":
            return text.startswith("`", span[0])
        if mode == "double":
            return text.startswith('"', span[0]) or text.startswith("<<<", span[0])
        if mode == "dollar":
            return text.startswith(("$\"", "$@\"", "@$\""), span[0]) or text[max(0, span[0] - 2):span[0]].endswith(
                ("$", "$@", "@$"))
        return False

    # -- taint of an expression ----------------------------------------------------
    def sanitizer_spans(self, start: int, end: int) -> list[tuple[int, int, frozenset | None]]:
        spans = []
        for pattern, kinds in self.rules.sanitizers:
            for match in pattern.finditer(self.clean, start, end):
                close = self.model.parens.get(match.end() - 1)
                if close is not None:
                    spans.append((match.start(), close, kinds))
        return spans

    @staticmethod
    def cleared_at(offset: int, spans) -> frozenset | None:
        cleared = frozenset()
        for start, end, kinds in spans:
            if start <= offset < end:
                if kinds is None:
                    return None
                cleared |= kinds
        return cleared

    def origins(self, start: int, end: int, tainted: dict[str, frozenset]) -> frozenset:
        if end <= start:
            return frozenset()
        clean, rules, model = self.clean, self.rules, self.model
        spans = self.sanitizer_spans(start, end) if rules.sanitizers else []
        found: set[tuple[str, int, frozenset]] = set()
        for match in matches(rules.sources, clean, start, end):
            cleared = self.cleared_at(match.start(), spans)
            if cleared is not None:
                self.source_sites.add(match.start())
                found.add((_label(match.group()), model.line_of(match.start()), cleared))
        if rules.raw_sources is not None:
            for match in rules.raw_sources.finditer(model.text, start, end):
                if clean.startswith(tuple(rules.raw_anchor.split("|")), match.start()):
                    cleared = self.cleared_at(match.start(), spans)
                    if cleared is not None:
                        self.source_sites.add(match.start())
                        found.add((_label(match.group()), model.line_of(match.start()), cleared))
        if tainted:
            for match in rules.identifier.finditer(clean, start, end):
                labels = tainted.get(match.group())
                if not labels:
                    continue
                position = match.start()
                if rules.identifier is _IDENTIFIER and clean[position - 1:position] == ".":
                    continue  # a member named like the variable
                if rules.postfix_sanitizer is not None and rules.postfix_sanitizer.match(clean, match.end()):
                    continue
                if self.family == "php" and _PHP_CAST.search(clean, max(0, position - 24), position):
                    continue
                cleared = self.cleared_at(position, spans)
                if cleared is None:
                    continue
                found.update((source, line, previous | cleared) for source, line, previous in labels)
        if rules.interpolation is not None:
            for span in model.strings_between(start, end):
                if not self.interpolates(span):
                    continue
                cleared = self.cleared_at(span[0], spans)
                if cleared is None:
                    continue
                for match in rules.interpolation.finditer(model.text, span[0], span[1]):
                    expression = next((group for group in match.groups() if group), "")
                    source = rules.sources.search(expression)
                    if source:
                        found.add((_label(source.group()), model.line_of(span[0]), cleared))
                    for name in rules.identifier.findall(expression):
                        for label, line, previous in tainted.get(name, ()):
                            found.add((label, line, previous | cleared))
        if self.call_pattern is not None and self._depth < _MAX_CALL_DEPTH:
            self.returned_by_calls(start, end, tainted, spans, found)
        if len(found) > MAX_LABELS:
            return frozenset(sorted(found, key=lambda item: (len(item[2]), item[1], item[0]))[:MAX_LABELS])
        return frozenset(found)

    def returned_by_calls(self, start: int, end: int, tainted: dict, spans, found: set) -> None:
        """Taint returned by this file's functions called in ``[start, end)``."""
        for match in self.call_pattern.finditer(self.clean, start, end):
            summary = self.summaries.get(match.group("name"))
            if summary is None or not (summary.returns or summary.sources):
                continue
            cleared = self.cleared_at(match.start(), spans)
            close = self.model.parens.get(match.end() - 1)
            if cleared is None or close is None:
                continue
            arguments = _split(self.clean, match.end(), close)
            self._depth += 1
            try:
                for index, returned_cleared in summary.returns.items():
                    if index < len(arguments):
                        for source, line, previous in self.origins(*arguments[index], tainted):
                            found.add((source, line, previous | returned_cleared | cleared))
            finally:
                self._depth -= 1
            for source, line, previous in summary.sources:
                found.add((source, line, previous | cleared))

    # -- regions ---------------------------------------------------------------------
    def parameters(self, start: int, end: int) -> list[str]:
        """Parameter names marked as request input by annotations in ``[start, end)``."""
        pattern, clean, names = self.rules.params, self.clean, []
        if pattern is None:
            return names
        for match in pattern.finditer(clean, start, end):
            direct = match.groupdict().get("name") or match.groupdict().get("inner")
            if direct:
                names.append(direct)
                continue
            position = match.end()
            if clean.startswith("(", position):
                close = self.model.parens.get(position)
                if close is None:
                    continue
                position = close + 1
            stop = _split(clean, position, end, _PARAMETER_DELIMITERS)[0][1]
            words = [word for word in _IDENTIFIER.findall(clean, position, stop) if word not in _NOT_PARAMETERS]
            if words:
                names.append(words[0] if self.rules.first_parameter_name else words[-1])
        return names

    def analyze_region(self, start: int, end: int, skip: list[tuple[int, int]], function: str,
                       params: list[str], params_line: int, *, seed: dict | None = None,
                       nested: list[tuple[int, int]] = ()) -> None:
        """Follow taint through one region. With ``self.collect`` set, ``seed`` marks the
        function's parameters and the region is summarized instead of reported."""
        rules, clean = self.rules, self.clean
        if not params and not seed and not search(rules.sources, clean, start, end) and not any(
            pattern.search(clean, start, end) for pattern, _ in rules.out_sources
        ) and not (rules.raw_sources is not None and rules.raw_sources.search(self.model.text, start, end)):
            return
        tainted: dict[str, frozenset] = dict(seed or {})
        blocks: dict[str, int] = dict.fromkeys(tainted, -2)
        for name in params:
            tainted[name] = frozenset({(f"parameter `{name}`", params_line, frozenset())})
            blocks[name] = -2
        events: list[tuple[int, int, object, object]] = []
        if self.collect is not None:
            nested = list(nested)
            nested_starts = [interval[0] for interval in nested]
            for match in _RETURN.finditer(clean, start, end):
                if not self._inside(match.start(), nested, nested_starts):
                    events.append((match.start(), 2, "return", match))
        if self.call_pattern is not None:
            for match in self.call_pattern.finditer(clean, start, end):
                if self.summaries[match.group("name")].sinks:
                    events.append((match.start(), 2, "call", match))
        if self.collect is None:
            for call in self.model.calls:
                if start <= call.offset < end and call.callee not in self.local_names and (
                    not call.receiver or (call.receiver not in _LIBRARY_RECEIVERS and _IDENTIFIER.fullmatch(call.receiver))
                ):
                    events.append((call.offset, 2, "outgoing", call))
        for match in rules.assignment.finditer(clean, start, end):
            events.append((match.start(), 0, "assign", match))
        for pattern, positions in rules.out_sources:
            for match in pattern.finditer(clean, start, end):
                events.append((match.start(), 1, ("out", positions), match))
        for pattern, destination in rules.out_propagators:
            for match in pattern.finditer(clean, start, end):
                events.append((match.start(), 1, ("copy", destination), match))
        if rules.receiver_propagators is not None:
            for match in rules.receiver_propagators.finditer(clean, start, end):
                events.append((match.start(), 1, ("receiver", 0), match))
        for sink in rules.sinks:
            for match in matches(sink.pattern, clean, start, end):
                events.append((match.start(), 2, sink, match))
        if skip:
            starts = [interval[0] for interval in skip]
            events = [event for event in events if not self._inside(event[0], skip, starts)]
        events.sort(key=lambda event: (event[0], event[1]))
        events = events[:MAX_EVENTS]
        if self.collect is not None:
            self.summary_events += len(events)
        for _offset, _order, kind, match in events:
            if kind == "assign":
                self.assign(match, end, tainted, blocks)
            elif kind == "return":
                self.returned(match, end, tainted)
            elif kind == "call":
                self.call_sink(match, tainted, function)
            elif kind == "outgoing":
                self.outgoing_call(match, tainted)
            elif isinstance(kind, tuple):
                if kind[0] == "out":
                    self.out_source(match, kind[1], tainted, blocks)
                elif kind[0] == "copy":
                    self.copy_into(match, kind[1], tainted, blocks)
                else:
                    self.into_receiver(match, tainted, blocks)
            else:
                self.sink(kind, match, end, tainted, function)

    @staticmethod
    def _inside(offset: int, skip: list[tuple[int, int]], starts: list[int]) -> bool:
        index = bisect.bisect_right(starts, offset) - 1
        return index >= 0 and skip[index][0] <= offset < skip[index][1]

    def assign(self, match: re.Match, limit: int, tainted: dict, blocks: dict) -> None:
        rhs_end = _statement_end(self.clean, match.end(), limit, self.newline)
        labels = self.origins(match.end(), rhs_end, tainted)
        groups = match.groupdict()
        if groups.get("destructure"):
            names = _destructured(groups["destructure"])
        else:
            raw = groups.get("names") or groups.get("plain") or ""
            names = [name.strip() for name in raw.split(",") if name.strip()]
        op = groups.get("op") or groups.get("plain_op") or "="
        block = self.block_of(match.start())
        for name in names:
            if labels:
                tainted[name] = labels | tainted.get(name, frozenset()) if op != "=" and op != ":=" else labels
                blocks[name] = block
            elif name in tainted and op in {"=", ":="} and blocks.get(name) == block:
                del tainted[name]

    def out_source(self, match: re.Match, positions: tuple[int, ...], tainted: dict, blocks: dict) -> None:
        opening = match.end() - 1
        close = self.model.parens.get(opening)
        if close is None:
            return
        arguments = _split(self.clean, opening + 1, close)
        self.source_sites.add(match.start())
        label = (_label(match.group()), self.model.line_of(match.start()), frozenset())
        for position in positions:
            if position < len(arguments):
                for name in self.rules.identifier.findall(self.clean, *arguments[position]):
                    tainted[name] = frozenset({label})
                    blocks[name] = self.block_of(match.start())
                    break

    def copy_into(self, match: re.Match, destination: int, tainted: dict, blocks: dict) -> None:
        """``sprintf(buf, fmt, input)``: the destination holds tainted text afterwards."""
        opening = match.end() - 1
        close = self.model.parens.get(opening)
        if close is None or not tainted:
            return
        arguments = _split(self.clean, opening + 1, close)
        if destination >= len(arguments):
            return
        labels = frozenset()
        for index, (start, end) in enumerate(arguments):
            if index != destination:
                labels |= self.origins(start, end, tainted)
        if labels:
            names = self.rules.identifier.findall(self.clean, *arguments[destination])
            if names:
                tainted[names[0]] = labels | tainted.get(names[0], frozenset())
                blocks[names[0]] = self.block_of(match.start())

    def into_receiver(self, match: re.Match, tainted: dict, blocks: dict) -> None:
        """``builder.append(input)``: the receiver holds tainted text afterwards."""
        opening = match.end() - 1
        close = self.model.parens.get(opening)
        if close is None:
            return
        receiver = self.receiver_before(match.start())
        if not receiver or not self.rules.identifier.fullmatch(receiver):
            return
        labels = self.origins(opening + 1, close, tainted)
        if labels:
            tainted[receiver] = labels | tainted.get(receiver, frozenset())
            blocks.setdefault(receiver, self.block_of(match.start()))

    def sink(self, sink: Sink, match: re.Match, limit: int, tainted: dict, function: str) -> None:
        clean = self.clean
        display = " ".join(match.group().split()).rstrip("(=+ ").lstrip(".>-")
        if sink.receiver is not None:
            receiver = self.receiver_before(match.start())
            if not receiver or not sink.receiver.search(receiver):
                return
            display = f"{receiver}.{display}"
        if sink.style == "call":
            opening = match.end() - 1
            close = self.model.parens.get(opening)
            if close is None:
                return
            if sink.requires is not None and not sink.requires.search(self.model.text, opening, close):
                return
            arguments = _split(clean, opening + 1, close)
            if sink.arguments is None:
                spans = arguments
            else:
                spans = [arguments[index] for index in sink.arguments if -len(arguments) <= index < len(arguments)]
        else:
            spans = [(match.end(), _statement_end(clean, match.end(), limit, self.newline))]
        line = self.model.line_of(match.start())
        for start, end in spans:
            for source, source_line, cleared in self.origins(start, end, tainted):
                if sink.kind in cleared:
                    continue
                if source.startswith(_MARKER):
                    self.record_sink(source, (sink.kind, display, line, ""))
                    continue
                if self.collect is not None:
                    continue  # reported by the reporting pass
                if sink.kind == "ssrf" and source.startswith(_DOM_SOURCES):
                    continue  # a browser fetching a user-chosen URL is not server-side forgery
                key = (sink.kind, display, line, source, source_line)
                self.flows[key] = Flow(sink.kind, display, line, source, source_line, line, "", function)

    # -- inter-procedural ------------------------------------------------------------
    def record_sink(self, marker: str, entry: tuple[str, str, int, str]) -> None:
        if self.collect is None:
            return
        entries = self.collect.sinks.setdefault(int(marker[len(_MARKER):]), set())
        if len(entries) < MAX_SUMMARY_SINKS:
            entries.add(entry)

    def returned(self, match: re.Match, limit: int, tainted: dict) -> None:
        """``return expr`` while summarizing: which parameters and sources it carries."""
        end = _statement_end(self.clean, match.end(), limit, self.newline)
        summary, sources = self.collect, set()
        for source, line, cleared in self.origins(match.end(), end, tainted):
            if source.startswith(_MARKER):
                index = int(source[len(_MARKER):])
                summary.returns[index] = summary.returns.get(index, cleared) & cleared
            else:
                sources.add((source, line, cleared))
        if sources:
            summary.sources = frozenset(sorted(summary.sources | sources)[:MAX_LABELS])

    def call_sink(self, match: re.Match, tainted: dict, function: str) -> None:
        """A call to a function of this file whose parameter reaches a sink."""
        name = match.group("name")
        summary = self.summaries[name]
        close = self.model.parens.get(match.end() - 1)
        if close is None:
            return
        arguments = _split(self.clean, match.end(), close)
        call_line = self.model.line_of(match.start())
        for index, entries in summary.sinks.items():
            if index >= len(arguments):
                continue
            for source, source_line, cleared in self.origins(*arguments[index], tainted):
                for kind, display, sink_line, via in entries:
                    if kind in cleared:
                        continue
                    chain = f"{name}()" + (f" -> {via}" if via else "")
                    if source.startswith(_MARKER):
                        self.record_sink(source, (kind, display, sink_line, chain))
                    elif self.collect is None and not (kind == "ssrf" and source.startswith(_DOM_SOURCES)):
                        key = (kind, display, sink_line, source, source_line, call_line)
                        self.flows[key] = Flow(kind, display, sink_line, source, source_line, call_line, chain,
                                               function)

    def _claimed(self) -> tuple[list[int], list[tuple[int, int]]]:
        """Spans of calls the rules already understand: sources, sinks, sanitizers, propagators."""
        if self._claims is None:
            rules, spans = self.rules, []
            patterns = [rules.sources, *(sink.pattern for sink in rules.sinks),
                        *(pattern for pattern, _ in rules.sanitizers), *(pattern for pattern, _ in rules.out_sources),
                        *(pattern for pattern, _ in rules.out_propagators)]
            if rules.receiver_propagators is not None:
                patterns.append(rules.receiver_propagators)
            for pattern in patterns:
                spans.extend(match.span() for match in matches(pattern, self.clean))
            spans.sort()
            self._claims = ([span[0] for span in spans], spans)
        return self._claims

    def claimed_at(self, offset: int) -> bool:
        starts, spans = self._claimed()
        index = bisect.bisect_right(starts, offset) - 1
        while index >= 0 and spans[index][0] > offset - 200:
            if spans[index][0] <= offset < spans[index][1]:
                return True
            index -= 1
        return False

    def outgoing_call(self, call, tainted: dict) -> None:
        """Untrusted input passed to a function defined in another file (joined in the index)."""
        if len(self.outgoing) >= MAX_OUTGOING or not tainted and not self.rules.sources.search(
            self.clean, call.offset, call.offset + 400
        ):
            return
        if self.claimed_at(call.offset):
            return  # a source, sink or sanitizer call, analyzed where it is
        opening = self.clean.find("(", call.offset + len(call.callee), call.offset + len(call.callee) + 8)
        close = self.model.parens.get(opening) if opening >= 0 else None
        if close is None:
            return
        for index, span in enumerate(_split(self.clean, opening + 1, close)[:8]):
            if "{" in self.clean[span[0]:span[1]]:
                continue  # a callback or object literal, not a value handed over
            for source, source_line, cleared in self.origins(*span, tainted):
                if not cleared and not source.startswith(_MARKER):
                    key = (call.callee, index, source, source_line, call.line)
                    self.outgoing[key] = OutgoingCall(call.callee, call.receiver, index, source, source_line,
                                                      call.line)


def _destructured(pattern: str) -> list[str]:
    names = []
    for part in pattern.strip("{}[] \t\r\n").split(","):
        part = part.strip().lstrip(".")
        if not part:
            continue
        if ":" in part:
            part = part.split(":", 1)[1]
        part = part.split("=", 1)[0].strip()
        if _IDENTIFIER.fullmatch(part):
            names.append(part)
    return names


def _top_level_alternatives(pattern: str) -> list[str] | None:
    """Split a pattern at its top-level ``|``; None if it cannot be split safely."""
    parts, depth, start, index, in_class = [], 0, 0, 0, False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
            if pattern.startswith("[]", index) or pattern.startswith("[^]", index):
                index += 2 if pattern[index + 1] == "]" else 3
                continue
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append(pattern[start:index])
            start = index + 1
        index += 1
    parts.append(pattern[start:])
    return parts if depth == 0 and not in_class else None


_LEADING_LOOKBEHIND = re.compile(r"\(\?<!(?:\[(?:\\.|[^\]\\])*+\]|[^()\[\]])*+\)")
# A plain or escaped literal character that no quantifier follows.
_LITERAL_START = re.compile(r"(?:[A-Za-z0-9_@#%&'\"/<>=!~,:; -]|\\[.$()\[\]{}*+?|^\\/-])(?![*+?{])")
_FAST: dict[int, re.Pattern | None] = {}


def _group_end(fragment: str) -> int | None:
    """Index of the ``)`` closing the group that ``fragment`` starts with."""
    depth, index, in_class = 0, 0, False
    while index < len(fragment):
        char = fragment[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _starts_with_literal(fragment: str) -> bool:
    """Whether every match must begin with a fixed character (no class, no quantifier).

    Only then is it safe to drop the boundary lookbehind: each candidate costs constant
    work. A leading class run such as ``[A-Za-z_]\\w*+`` would be retried inside every
    word and turn a whole-file search quadratic.
    """
    if fragment.startswith("(?:"):
        close = _group_end(fragment)
        if close is None or fragment[close + 1:close + 2] in {"*", "+", "?", "{"}:
            return False
        inner = _top_level_alternatives(fragment[3:close])
        return bool(inner) and all(_starts_with_literal(part) for part in inner)
    return bool(_LITERAL_START.match(fragment))


def _fast_variant(pattern: re.Pattern) -> re.Pattern | None:
    """The pattern without the boundary lookbehind that leads each alternative.

    A leading lookbehind stops the regular-expression engine from searching for the
    literal that follows it, which makes a whole-file search tens of times slower. The
    variant finds candidates quickly and the original pattern confirms each of them.
    """
    key = id(pattern)
    if key not in _FAST:
        variant = None
        source = pattern.pattern
        global_flags = ""
        if source.startswith("(?") and source[2:3].isalpha() and ")" in source[:8]:
            close = source.index(")")
            global_flags, source = source[:close + 1], source[close + 1:]
        parts = _top_level_alternatives(source)
        if parts:
            stripped = []
            for part in parts:
                leading = _LEADING_LOOKBEHIND.match(part)
                rest = part[leading.end():] if leading else part
                stripped.append(rest if leading and _starts_with_literal(rest) else part)
            if stripped != parts and all(stripped):
                try:
                    variant = re.compile(global_flags + "|".join(stripped), pattern.flags & ~re.UNICODE)
                except re.error:
                    variant = None
        _FAST[key] = variant
    return _FAST[key]


def matches(pattern: re.Pattern, text: str, start: int = 0, end: int | None = None):
    """``pattern.finditer`` results, found through the pattern's fast variant when it has one."""
    end = len(text) if end is None else end
    fast = _fast_variant(pattern)
    if fast is None:
        yield from pattern.finditer(text, start, end)
        return
    # The variant matches wherever the pattern does, so its leftmost candidate is never
    # after the pattern's leftmost match; a rejected candidate resumes one place later.
    position = start
    while position <= end:
        candidate = fast.search(text, position, end)
        if candidate is None:
            return
        match = pattern.match(text, candidate.start(), end)
        if match:
            yield match
            position = max(match.end(), match.start() + 1)
        else:
            position = candidate.start() + 1


def search(pattern: re.Pattern, text: str, start: int = 0, end: int | None = None) -> bool:
    return next(matches(pattern, text, start, end), None) is not None


def sink_offsets(rules: Rules, clean: str) -> list[int]:
    """Start offsets of every sink match in the cleaned text."""
    return sorted(match.start() for sink in rules.sinks for match in matches(sink.pattern, clean))


def _worth_summarizing(engine: _FileTaint, functions: list, sinks: list[int]) -> tuple[list, bool]:
    """The functions whose summary can change a result, and whether any calls another.

    A summary matters when the body holds a sink, when it calls another function of the
    file (which may hold one), or when the function returns something to a caller in
    this file. Anything else would summarize to nothing.
    """
    clean, model, names = engine.clean, engine.model, engine.local_names
    local_calls = sorted(call.offset for call in model.calls if call.callee in names)
    called = {call.callee for call in model.calls if call.callee in names}

    def any_between(offsets: list[int], start: int, end: int) -> bool:
        index = bisect.bisect_left(offsets, start)
        return index < len(offsets) and offsets[index] < end

    selected, chained = [], False
    for symbol in functions:
        start, end = symbol.body
        calls_local = any_between(local_calls, start, end)
        chained = chained or calls_local
        if any_between(sinks, start, end) or calls_local or (
            symbol.name in called and _RETURN.search(clean, start, end)
        ):
            selected.append(symbol)
    return selected, chained


def _summarize(engine: _FileTaint, functions: list, sinks: list[int]) -> None:
    """Summaries of the file's functions, iterated so helpers that call helpers are followed."""
    functions, chained = _worth_summarizing(engine, functions, sinks)
    if not functions:
        return
    signatures = {id(symbol): engine.signature_params(symbol) for symbol in functions}
    nested = {
        id(symbol): [other.body for other in functions
                     if other is not symbol and symbol.body[0] < other.body[0] < symbol.body[1]]
        for symbol in functions
    }
    for _ in range(MAX_ROUNDS if chained else 1):
        summaries: dict[str, Summary] = {}
        for symbol in functions:
            if engine.summary_events > MAX_SUMMARY_EVENTS:
                break
            params = signatures[id(symbol)]
            summary = Summary(tuple(params))
            seed = {
                name: frozenset({(f"{_MARKER}{index}", symbol.line, frozenset())})
                for index, name in enumerate(params) if name
            }
            engine.collect = summary
            try:
                engine.analyze_region(*symbol.body, [], symbol.qualified, [], symbol.line,
                                      seed=seed, nested=nested[id(symbol)])
            finally:
                engine.collect = None
            if symbol.name in summaries:
                summaries[symbol.name].merge(summary)
            else:
                summaries[symbol.name] = summary
        changed = {name: item.key() for name, item in summaries.items()} != {
            name: item.key() for name, item in engine.summaries.items()
        }
        engine.set_summaries(summaries)
        if not changed or engine.summary_events > MAX_SUMMARY_EVENTS:
            return


def analyze_lexical(model: FileModel, family: str, *, export: bool = True) -> LexicalResult:
    """Flows, source sites, function summaries and outgoing tainted calls for one file.

    Functions are first summarized: each parameter is followed to the sinks it reaches and
    to the values the function returns. Calls to this file's functions then carry taint
    into and out of them. Calls into other files are returned for the code index, which
    joins them with the callee's summary. With ``export`` false (third-party code), a file
    without untrusted input is not summarized for other files.
    """
    rules = RULES.get(family)
    empty = LexicalResult([], 0, {}, [])
    if rules is None:
        return empty
    has_sources = search(rules.hint, model.text)
    if not has_sources and not export:
        return empty
    sinks = sink_offsets(rules, model.clean)
    if not has_sources and not sinks:
        return empty
    engine = _FileTaint(model, rules, family)
    functions = sorted(
        (symbol for symbol in model.symbols if symbol.kind in FUNCTION_KINDS and symbol.body),
        key=lambda symbol: symbol.body[0],
    )
    engine.local_names = {symbol.name for symbol in functions}
    if functions and sinks:
        _summarize(engine, functions, sinks)
    if has_sources:
        outermost: list[tuple[int, int]] = []
        for symbol in functions:
            start, end = symbol.body
            signature_start = model.line_start(symbol.line)
            params = engine.parameters(signature_start, start)
            engine.analyze_region(start, end, [], symbol.qualified, params, symbol.line)
            if not outermost or start >= outermost[-1][1]:
                outermost.append((start, end))
        engine.analyze_region(0, len(engine.clean), outermost, "<top level>", [], 0)
    flows = sorted(engine.flows.values(), key=lambda flow: (flow.sink_line, flow.kind, flow.source_line, flow.source))
    summaries = {name: item for name, item in engine.summaries.items() if item.sinks}
    return LexicalResult(flows, len(engine.source_sites), summaries, list(engine.outgoing.values()))


def analyze_lexical_taint(model: FileModel, family: str) -> tuple[list[Flow], int]:
    """(flows, distinct source sites) for one lexically modelled file."""
    result = analyze_lexical(model, family)
    return result.flows, result.sources


def _build_fast_variants() -> None:
    """Build every variant at import, so tests (including the regex-complexity check) see them."""
    for rules in RULES.values():
        patterns = [rules.hint, rules.sources, *(sink.pattern for sink in rules.sinks),
                    *(pattern for pattern, _ in rules.sanitizers), *(pattern for pattern, _ in rules.out_sources),
                    *(pattern for pattern, _ in rules.out_propagators)]
        if rules.receiver_propagators is not None:
            patterns.append(rules.receiver_propagators)
        for pattern in patterns:
            _fast_variant(pattern)


_build_fast_variants()
