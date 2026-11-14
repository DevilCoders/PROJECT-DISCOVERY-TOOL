"""GraphQL schemas, operations, resolvers, directives, federation and subscriptions.

GraphQL is read by a small tokenizer and parser (block strings, strings and comments skipped,
every character read once): SDL and documents in ``.graphql``, ``.gql`` and ``.graphqls``
files, and GraphQL embedded in code: ``gql`...``` and ``graphql`...``` template tags,
``/* GraphQL */`` templates, ``buildSchema(`...`)``, Python ``gql(...)`` and ``type_defs = ...``
with a triple-quoted string, C# ``AddDocumentFromString(@"...")``.

From a schema: the root operation types (``schema { query: ... }`` or the default names) and
their fields, so the queries, mutations and subscriptions a service serves, every type by kind,
directive definitions and uses, and Apollo Federation: entities (types with ``@key``), the
federation version a ``@link`` imports, and ``@external``/``@requires``/``@provides``/
``@shareable``/``@override`` uses. From documents: each operation's kind, name and root fields,
and fragments. Libraries that make a service a federation subgraph or gateway, and subscription
transports, are named from code.

Resolvers, the code behind each field, by framework: Apollo and graphql-tools resolver maps,
NestJS and TypeGraphQL decorators, Pothos and Nexus fields (JavaScript and TypeScript);
Strawberry, Graphene and Ariadne (Python, from the syntax tree); gqlgen (Go); Spring for
GraphQL and Netflix DGS (JVM); Hot Chocolate and GraphQL.NET (C#); graphql-ruby; async-graphql
and juniper (Rust); Absinthe (Elixir). Field names follow each framework's convention
(Strawberry's ``user_by_id`` is ``userById``, Hot Chocolate's ``GetBook`` is ``book``), so the
code index can match resolvers with schema fields. Nothing is executed or introspected.
"""
from __future__ import annotations

import bisect
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import SourceBudgetExceeded, describe_error, open_verified_text, read_text_bounded
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer
from .route_structure import DEPTH_TOKEN, DEPTH_TOKEN_CHARS

MAX_GRAPHQL_BYTES = 16 * 1024 * 1024
MAX_GRAPHQL_EVIDENCE = 100
_SDL_EXTENSIONS = frozenset({".graphql", ".gql", ".graphqls"})
_CODE_EXTENSIONS = frozenset({
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".py", ".cs", ".go", ".java",
    ".kt", ".kts", ".scala", ".groovy", ".rb", ".rs", ".ex", ".exs", ".php", ".dart", ".swift",
})
_ROOTS = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}
_FEDERATION_DIRECTIVES = frozenset({"key", "external", "requires", "provides", "shareable", "inaccessible",
                                    "override", "tag", "extends", "interfaceObject", "composeDirective"})

# One token: a block string, a string, a comment, a name, a number, a spread or a punctuator.
_TOKEN = re.compile(r'''"""(?:[^"\\]|\\[\s\S]|"(?!""))*+(?:"""|$)|"(?:[^"\\\n]|\\.)*+"?|\#[^\n]*|[_A-Za-z][_0-9A-Za-z]*|-?\d[\d.eE+-]*|\.\.\.|[!$&()\[\]{}:=@|]''')
# A file worth reading in full: it names GraphQL, or a GraphQL server library, somewhere.
_HINT = re.compile(r"(?i)graphql|\bgql\b|type_?defs|buildSchema|AddDocumentFromString|subgraph|ApolloGateway|"
                   r"strawberry|graphene|ariadne|absinthe|async_graphql|juniper|hotchocolate|ObjectGraphType|"
                   r"\bresolvers?\b|Resolver\b|QueryType|MutationType|SubscriptionType|Dgs(?:Query|Mutation|Subscription|Data)|"
                   r"(?:Query|Mutation|Subscription|Schema)Mapping|(?:query|mutation|subscription)Field")
# GraphQL embedded in code: where it starts, and what closes it.
_JS_TAG = re.compile(r"(?:\b(?:gql|graphql)\s*+(?:<[^<>`\n]{0,200}>)?\s*+\(?\s*+|/\*\s*+GraphQL\s*+\*/\s*+|\bbuildSchema\s*+\(\s*+)`")
_PY_TAG = re.compile(r"""(?:\bgql\s*\(\s*|\b(?:type_defs|typeDefs|sdl|schema_sdl)\s*=\s*)[rR]?("""+'"""'+r"""|''')""")
_CS_TAG = re.compile(r'\bAddDocumentFromString\s*\(\s*@"')
_INTERPOLATION = re.compile(r"\$\{[^{}]{0,300}\}")
# Code that makes a service a federation subgraph or gateway, or carries subscriptions.
_FEDERATION_CODE = {
    "subgraph": re.compile(r"@apollo/subgraph|\bbuildSubgraphSchema\b|\bbuildFederatedSchema\b|graphene_federation|"
                           r"strawberry\.federation|ariadne\.contrib\.federation|@DgsEntityFetcher|AddApolloFederation|"
                           r"federation\.Entity|\bfederation:\s*$", re.M),
    "gateway": re.compile(r"@apollo/gateway|\bApolloGateway\b|\bIntrospectAndCompose\b|\bsupergraphSdl\b|"
                          r"@graphql-mesh|\bstitchSchemas\b"),
}
_SUBSCRIPTION_TRANSPORTS = {
    "graphql-ws": re.compile(r"""['"]graphql-ws['"/]|\bgraphql_ws\b|GraphQLWSProtocol|graphql-transport-ws"""),
    "subscriptions-transport-ws": re.compile(r"""['"]subscriptions-transport-ws['"]|SubscriptionServer\.create"""),
    "graphql-sse": re.compile(r"""['"]graphql-sse['"]"""),
    "PubSub": re.compile(r"\bnew\s+PubSub\b|\bPubSub\(\)|\basyncIterator\s*\(|\basyncIterableIterator\s*\("),
}


@dataclass(slots=True)
class TypeDef:
    kind: str
    name: str
    line: int
    extend: bool = False
    fields: list[tuple[str, int]] = field(default_factory=list)  # (name, line)
    directives: list[tuple[str, str]] = field(default_factory=list)  # (name, arguments text)
    implements: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Operation:
    kind: str
    name: str
    line: int
    fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Document:
    roots: dict[str, str] = field(default_factory=dict)  # operation kind -> root type name
    types: list[TypeDef] = field(default_factory=list)
    directives: list[tuple[str, int, str]] = field(default_factory=list)  # (name, line, locations)
    directive_uses: Counter = field(default_factory=Counter)
    links: list[str] = field(default_factory=list)  # @link(url:) values
    operations: list[Operation] = field(default_factory=list)
    fragments: list[tuple[str, str, int]] = field(default_factory=list)  # (name, type, line)

    def merge(self, other: "Document") -> None:
        self.roots = {**other.roots, **self.roots}
        self.types += other.types
        self.directives += other.directives
        self.directive_uses.update(other.directive_uses)
        self.links += other.links
        self.operations += other.operations
        self.fragments += other.fragments


class _Parser:
    """A recursive-descent reader over GraphQL tokens: unknown constructs are skipped."""

    def __init__(self, text: str, base_line: int = 1) -> None:
        self.tokens: list[tuple[str, int]] = []  # (token, offset)
        for match in _TOKEN.finditer(text):
            token = match.group(0)
            if not token.startswith("#"):
                self.tokens.append((token, match.start()))
        self.text = text
        self.base_line = base_line
        self.index = 0
        self._newlines = [match.start() for match in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return self.base_line + bisect.bisect_left(self._newlines, offset)

    def peek(self, ahead: int = 0) -> str:
        index = self.index + ahead
        return self.tokens[index][0] if index < len(self.tokens) else ""

    def take(self) -> tuple[str, int]:
        token = self.tokens[self.index] if self.index < len(self.tokens) else ("", len(self.text))
        self.index += 1
        return token

    def is_name(self, token: str) -> bool:
        return bool(token) and (token[0].isalpha() or token[0] == "_")

    def skip_strings(self) -> None:
        while self.peek().startswith('"'):
            self.index += 1

    def skip_group(self, opening: str, closing: str) -> str:
        """Skip a balanced group starting at the current token; return its source text."""
        if self.peek() != opening:
            return ""
        start = self.tokens[self.index][1]
        depth = 0
        while self.index < len(self.tokens):
            token, offset = self.take()
            if token == opening:
                depth += 1
            elif token == closing:
                depth -= 1
                if depth == 0:
                    return self.text[start:offset + 1]
        return self.text[start:]

    def directives(self, document: Document) -> list[tuple[str, str]]:
        found = []
        while self.peek() == "@" and self.is_name(self.peek(1)):
            self.take()
            name, _ = self.take()
            arguments = self.skip_group("(", ")")
            found.append((name, arguments))
            document.directive_uses[name] += 1
            if name == "link":
                url = re.search(r'\burl\s*:\s*"([^"]*)"', arguments)
                if url:
                    document.links.append(url.group(1))
        return found

    def type_reference(self) -> None:
        """``Name``, ``Name!``, ``[Name!]!``: list brackets counted, never recursed into."""
        depth = 0
        while self.peek() == "[":
            self.take()
            depth += 1
        if self.is_name(self.peek()):
            self.take()
        if self.peek() == "!":
            self.take()
        while depth and self.peek() == "]":
            self.take()
            depth -= 1
            if self.peek() == "!":
                self.take()

    def fields(self, document: Document, definition: TypeDef) -> None:
        """A type's fields block: ``{ "description" name(args): Type @directive ... }``."""
        if self.peek() != "{":
            return
        self.take()
        while self.index < len(self.tokens) and self.peek() != "}":
            self.skip_strings()
            token, offset = self.take()
            if not self.is_name(token):
                continue
            definition.fields.append((token, self.line(offset)))
            self.skip_group("(", ")")
            if self.peek() == ":":
                self.take()
                self.type_reference()
            if self.peek() == "=":  # an input field's default value
                self.take()
                if self.peek() in {"[", "{"}:
                    self.skip_group(self.peek(), "]" if self.peek() == "[" else "}")
                else:
                    self.take()
            self.directives(document)
        self.take()

    def selection(self) -> list[str]:
        """The top-level fields of a selection set (``alias: field`` names the field)."""
        if self.peek() != "{":
            return []
        self.take()
        names = []
        while self.index < len(self.tokens) and self.peek() != "}":
            token, _ = self.take()
            if token == "...":
                # An inline fragment (... on Type { }) or a spread (...Name), with directives.
                if self.peek() == "on":
                    self.take()
                    self.take()
                elif self.is_name(self.peek()):
                    self.take()
                while self.peek() == "@":
                    self.take()
                    self.take()
                    self.skip_group("(", ")")
                if self.peek() == "{":
                    self.skip_group("{", "}")
                continue
            if not self.is_name(token):
                continue
            name = token
            if self.peek() == ":":
                self.take()
                name, _ = self.take()
            names.append(name)
            self.skip_group("(", ")")
            while self.peek() == "@":
                self.take()
                self.take()
                self.skip_group("(", ")")
            self.skip_group("{", "}")
        self.take()
        return names

    def parse(self) -> Document:
        document = Document()
        while self.index < len(self.tokens):
            token, offset = self.take()
            if token.startswith('"'):
                continue
            if token == "{":  # an anonymous query
                self.index -= 1
                document.operations.append(Operation("query", "", self.line(offset), self.selection()))
                continue
            if not self.is_name(token):
                continue
            extend = token == "extend"
            if extend:
                token, offset = self.take()
            if token == "schema":
                self.directives(document)
                if self.peek() == "{":
                    self.take()
                    while self.index < len(self.tokens) and self.peek() != "}":
                        kind, _ = self.take()
                        if kind in _ROOTS and self.peek() == ":":
                            self.take()
                            document.roots[kind], _ = self.take()
                    self.take()
            elif token in {"type", "interface", "input"} and self.is_name(self.peek()):
                name, _ = self.take()
                definition = TypeDef(token, name, self.line(offset), extend)
                if self.peek() == "implements":
                    self.take()
                    if self.peek() == "&":
                        self.take()
                    if self.is_name(self.peek()):
                        definition.implements.append(self.take()[0])
                    while self.peek() == "&" and self.is_name(self.peek(1)):
                        self.take()
                        definition.implements.append(self.take()[0])
                definition.directives = self.directives(document)
                self.fields(document, definition)
                document.types.append(definition)
            elif token == "enum" and self.is_name(self.peek()):
                name, _ = self.take()
                definition = TypeDef("enum", name, self.line(offset), extend, directives=self.directives(document))
                if self.peek() == "{":
                    self.take()
                    while self.index < len(self.tokens) and self.peek() != "}":
                        self.skip_strings()
                        value, value_offset = self.take()
                        if self.is_name(value):
                            definition.fields.append((value, self.line(value_offset)))
                            self.directives(document)
                    self.take()
                document.types.append(definition)
            elif token in {"union", "scalar"} and self.is_name(self.peek()):
                name, _ = self.take()
                definition = TypeDef(token, name, self.line(offset), extend, directives=self.directives(document))
                if token == "union" and self.peek() == "=":
                    # = A | B | C: members are separated by "|" (a leading "|" is allowed).
                    self.take()
                    if self.peek() == "|":
                        self.take()
                    while self.is_name(self.peek()):
                        member, member_offset = self.take()
                        definition.fields.append((member, self.line(member_offset)))
                        if self.peek() != "|":
                            break
                        self.take()
                document.types.append(definition)
            elif token == "directive" and self.peek() == "@":
                self.take()
                name, _ = self.take()
                self.skip_group("(", ")")
                if self.peek() == "repeatable":
                    self.take()
                locations = []
                if self.peek() == "on":
                    # on A | B | C: locations are separated by "|" (a leading "|" is allowed).
                    self.take()
                    if self.peek() == "|":
                        self.take()
                    while self.is_name(self.peek()):
                        locations.append(self.take()[0])
                        if self.peek() != "|":
                            break
                        self.take()
                document.directives.append((name, self.line(offset), "|".join(locations)))
            elif token in _ROOTS and not extend:
                name = ""
                if self.is_name(self.peek()):
                    name, _ = self.take()
                self.skip_group("(", ")")
                self.directives(document)
                document.operations.append(Operation(token, name, self.line(offset), self.selection()))
            elif token == "fragment" and self.is_name(self.peek()):
                name, _ = self.take()
                target = ""
                if self.peek() == "on":
                    self.take()
                    target, _ = self.take()
                self.directives(document)
                self.skip_group("{", "}")
                document.fragments.append((name, target, self.line(offset)))
        return document


def parse(text: str, base_line: int = 1) -> Document:
    """The definitions and operations of a GraphQL text."""
    return _Parser(text, base_line).parse()


def embedded(text: str, extension: str) -> list[tuple[str, int]]:
    """(GraphQL text, starting line) of each GraphQL literal in a source file."""
    found = []
    if extension == ".py":
        for match in _PY_TAG.finditer(text):
            quote = match.group(1)
            end = text.find(quote, match.end())
            if end >= 0:
                found.append((text[match.end():end], text.count("\n", 0, match.end()) + 1))
    elif extension == ".cs":
        for match in _CS_TAG.finditer(text):
            end = match.end()
            while True:
                end = text.find('"', end)
                if end < 0 or text[end + 1:end + 2] != '"':
                    break
                end += 2  # a doubled quote inside a verbatim string
            if end >= 0:
                found.append((text[match.end():end].replace('""', '"'), text.count("\n", 0, match.end()) + 1))
    else:
        for match in _JS_TAG.finditer(text):
            end = match.end()
            while True:
                end = text.find("`", end)
                if end < 0 or text[end - 1] != "\\":
                    break
                end += 1
            if end >= 0:
                body = _INTERPOLATION.sub(lambda item: " " * len(item.group(0)), text[match.end():end])
                found.append((body, text.count("\n", 0, match.end()) + 1))
    return found


def _root_fields(document: Document) -> dict[str, list[tuple[str, int]]]:
    """Operation kind -> the fields of its root type (extensions included)."""
    roots = {kind: document.roots.get(kind, default) for kind, default in _ROOTS.items()}
    fields: dict[str, list[tuple[str, int]]] = {kind: [] for kind in _ROOTS}
    for definition in document.types:
        for kind, name in roots.items():
            if definition.name == name and definition.kind == "type":
                fields[kind] += definition.fields
    return fields


def _federation_version(document: Document) -> str:
    for url in document.links:
        version = re.search(r"specs\.apollo\.dev/federation/v(\d+(?:\.\d+)?)", url)
        if version:
            return version.group(1)
    if any(name in document.directive_uses for name in ("key", "external", "requires", "provides", "extends")):
        return "1"
    return ""


class GraphQLAnalyzer(Analyzer):
    """GraphQL schemas, operations, directives, federation and subscriptions, statically."""

    name = "api-graphql"
    limits = AnalyzerLimits(MAX_GRAPHQL_BYTES, "whole", {"evidence_lines": MAX_GRAPHQL_EVIDENCE},
                            outcome="UNKNOWN finding for a GraphQL file past the budget")
    domains = ("api_graphql",)
    languages = ("GraphQL", "JavaScript", "TypeScript", "Python", "C#", "Go", "Java", "Kotlin", "Scala", "Groovy",
                 "Ruby", "Rust", "Elixir", "PHP", "Dart", "Swift")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and (record.extension in _SDL_EXTENSIONS or record.extension in _CODE_EXTENSIONS)

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        sdl = record.extension in _SDL_EXTENSIONS
        if over_limit(record.size_bytes, MAX_GRAPHQL_BYTES):
            if not sdl:
                # Code this large is generated or minified: reported only when it names GraphQL.
                try:
                    with open_verified_text(path, encoding="utf-8", errors="replace",
                                            expected_identity=record.analysis_identity) as stream:
                        head = stream.read(65536)
                except OSError:
                    head = ""
                if not _HINT.search(head):
                    return []
            return [Finding("api", f"GraphQL scan budget reached: {record.path}",
                            f"The file is larger than the {MAX_GRAPHQL_BYTES:,}-byte GraphQL budget and was not read.",
                            confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
        try:
            text = read_text_bounded(path, MAX_GRAPHQL_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, ValueError, SourceBudgetExceeded) as exc:
            return [Finding("api", f"GraphQL file unavailable: {record.path}", describe_error(exc),
                            confidence="UNKNOWN", severity="LOW", evidence=[record.path], analyzer=self.name)]
        if not sdl and not _HINT.search(text):
            return []
        document = Document()
        if sdl:
            document = parse(text)
        else:
            for body, line in embedded(text, record.extension):
                document.merge(parse(body, line))
        findings = self._schema(record, document, sdl) + self._operations(record, document)
        if not sdl:
            found = python_resolvers(text, record.path) if record.extension == ".py" else resolvers(text, record.extension)
            findings += self._resolvers(record, found) + self._code(record, text)
        return findings

    def _resolvers(self, record: FileRecord, found: list[tuple[str, str, str, int]]) -> list[Finding]:
        unique = sorted(set(found), key=lambda item: (item[3], item[0], item[1]))
        if not unique:
            return []
        for parent, name, framework, line in unique[:500]:
            code_facts.emit_fact("graphql_resolver", f"{parent}.{name}", framework=framework, line=line)
        frameworks = sorted({framework for _, _, framework, _ in unique})
        roots = Counter(parent for parent, _, _, _ in unique)
        return [Finding(
            "api", f"GraphQL resolvers: {record.path}",
            f"{len(unique)} resolver(s) ({', '.join(frameworks)}): "
            + ", ".join(f"{count} on {parent}" for parent, count in roots.most_common(8))
            + ". A resolver is the code that answers a field; the code index matches them with schema fields.",
            confidence="INFERRED", analyzer=self.name,
            evidence=[f"{record.path}:{line} {parent}.{name} ({framework})"
                      for parent, name, framework, line in unique[:MAX_GRAPHQL_EVIDENCE]],
        )]

    def _schema(self, record: FileRecord, document: Document, sdl: bool) -> list[Finding]:
        if not (document.types or document.directives or document.roots):
            return []
        roots = _root_fields(document)
        kinds = Counter(definition.kind for definition in document.types)
        for kind, fields in roots.items():
            for name, line in fields[:500]:
                code_facts.emit_fact("graphql_field", f"{_ROOTS[kind]}.{name}", kind=kind, line=line,
                                     root=document.roots.get(kind, _ROOTS[kind]))
        entities = [(definition, [arguments for name, arguments in definition.directives if name == "key"])
                    for definition in document.types if any(name == "key" for name, _ in definition.directives)]
        for definition, keys in entities[:500]:
            code_facts.emit_fact("graphql_entity", definition.name, line=definition.line,
                                 keys=[re.sub(r"\s+", " ", key)[:200] for key in keys])
        parts = [", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))]
        for kind, fields in roots.items():
            if fields:
                parts.append(f"{len(fields)} {kind} field(s) ({', '.join(name for name, _ in fields[:12])})")
        if document.directives:
            parts.append("directives defined: " + ", ".join(f"@{name}" for name, _, _ in document.directives[:12]))
        used = [f"@{name} ({count})" for name, count in document.directive_uses.most_common(12)]
        if used:
            parts.append("directives used: " + ", ".join(used))
        evidence = [f"{record.path}:{line} {_ROOTS[kind]}.{name}" for kind, fields in roots.items() for name, line in fields]
        evidence += [f"{record.path}:{line} directive @{name} on {locations}" for name, line, locations in document.directives]
        findings = [Finding(
            "api", f"GraphQL schema: {record.path}",
            "; ".join(part for part in parts if part) + ". " + ("" if sdl else "Read from GraphQL literals in code. ")
            + "The schema is read statically; resolvers and run-time schema changes are not.",
            confidence="CONFIRMED" if sdl else "INFERRED", analyzer=self.name,
            evidence=evidence[:MAX_GRAPHQL_EVIDENCE] or [record.path],
        )]
        if roots["subscription"]:
            findings.append(Finding(
                "api", f"GraphQL subscriptions: {record.path}",
                f"{len(roots['subscription'])} subscription field(s) on {document.roots.get('subscription', 'Subscription')}: "
                + ", ".join(name for name, _ in roots["subscription"][:20]) + ". Clients hold a long-lived connection "
                "(WebSocket or server-sent events) for each.",
                confidence="CONFIRMED" if sdl else "INFERRED", analyzer=self.name,
                evidence=[f"{record.path}:{line} Subscription.{name}" for name, line in roots["subscription"][:MAX_GRAPHQL_EVIDENCE]],
            ))
        version = _federation_version(document)
        if version:
            federation = {name: count for name, count in document.directive_uses.items() if name in _FEDERATION_DIRECTIVES}
            findings.append(Finding(
                "api", f"GraphQL federation: {record.path}",
                f"An Apollo Federation {version} subgraph schema with {len(entities)} entit(ies) "
                f"({', '.join(definition.name for definition, _ in entities[:12]) or 'none'}); directives: "
                + ", ".join(f"@{name} ({count})" for name, count in sorted(federation.items())) + ".",
                confidence="CONFIRMED" if sdl else "INFERRED", analyzer=self.name,
                evidence=[f"{record.path}:{definition.line} {'extend ' if definition.extend else ''}{definition.kind} "
                          f"{definition.name} @key{keys[0] if keys else ''}" for definition, keys in entities[:MAX_GRAPHQL_EVIDENCE]]
                + [f"@link(url: \"{url}\")" for url in document.links[:10]],
            ))
        return findings

    def _operations(self, record: FileRecord, document: Document) -> list[Finding]:
        if not document.operations and not document.fragments:
            return []
        for operation in document.operations[:500]:
            code_facts.emit_fact("graphql_operation", f"{operation.kind} {operation.name}".strip(),
                                 fields=operation.fields[:50], line=operation.line)
        kinds = Counter(operation.kind for operation in document.operations)
        return [Finding(
            "api", f"GraphQL operations: {record.path}",
            ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items())) + (
                f"; {len(document.fragments)} fragment(s)" if document.fragments else "")
            + ". These are operations a client sends; the fields they select are the root fields they call.",
            confidence="CONFIRMED", analyzer=self.name,
            evidence=[f"{record.path}:{operation.line} {operation.kind} {operation.name or '(anonymous)'} "
                      f"{{ {', '.join(operation.fields[:8])} }}" for operation in document.operations[:MAX_GRAPHQL_EVIDENCE]]
            + [f"{record.path}:{line} fragment {name} on {target}" for name, target, line in document.fragments[:20]],
        )]

    def _code(self, record: FileRecord, text: str) -> list[Finding]:
        roles = [role for role, pattern in _FEDERATION_CODE.items() if pattern.search(text)]
        transports = [name for name, pattern in _SUBSCRIPTION_TRANSPORTS.items() if pattern.search(text)]
        findings = []
        if roles:
            findings.append(Finding(
                "api", f"GraphQL federation in code: {record.path}",
                "The code builds an Apollo Federation " + " and ".join(
                    "subgraph (its schema joins a supergraph)" if role == "subgraph" else "gateway (it composes subgraphs)"
                    for role in roles) + ".",
                confidence="INFERRED", analyzer=self.name, evidence=[record.path],
            ))
        if transports:
            findings.append(Finding(
                "api", f"GraphQL subscription transport: {record.path}",
                f"Subscriptions are carried over {', '.join(transports)}.",
                confidence="INFERRED", analyzer=self.name, evidence=[record.path],
            ))
        return findings


# --------------------------------------------------------------------------------- resolvers

_ROOT_NAMES = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}


def _camel(name: str) -> str:
    """snake_case as GraphQL names it (Strawberry, Graphene, graphql-ruby, async-graphql, Absinthe)."""
    head, *rest = name.strip("_").split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _lower_first(name: str) -> str:
    return name[:1].lower() + name[1:]


def _root_of(name: str) -> str:
    """A resolver class's or impl's GraphQL type: QueryRoot, QueryType and Query are Query."""
    for root in ("Query", "Mutation", "Subscription"):
        if name == root or (name.startswith(root) and name[len(root):] in {"Root", "Type", "Resolver", "Resolvers"}) \
                or (name.endswith(root) and name[:-len(root)].isidentifier()):
            return root
    return name


def _block(text: str, opening: int, chars: bool = False) -> tuple[str, int]:
    """The text inside the brace at ``opening`` (strings and // comments skipped) and its end."""
    depth = 0
    for match in (DEPTH_TOKEN_CHARS if chars else DEPTH_TOKEN).finditer(text, opening):
        token = match.group(0)
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:match.start()], match.end()
    return text[opening + 1:], len(text)


def _paren_end(text: str, opening: int) -> int:
    """The offset after the parenthesis closing the one at ``opening`` (strings skipped)."""
    depth = 0
    for match in DEPTH_TOKEN.finditer(text, opening):
        token = match.group(0)
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
            if depth == 0:
                return match.end()
    return len(text)


def _top_level(body: str) -> str:
    """An object literal's body with every nested group blanked, offsets kept."""
    pieces, depth, last = [], 0, 0
    for match in DEPTH_TOKEN.finditer(body):
        token = match.group(0)
        if token in "([{":
            if depth == 0:
                pieces.append(body[last:match.end()])
                last = match.end()
            depth += 1
        elif token in ")]}":
            depth = max(0, depth - 1)
            if depth == 0:
                pieces.append(" " * (match.start() - last))
                last = match.start()
    pieces.append(body[last:] if depth == 0 else " " * (len(body) - last))
    return "".join(pieces)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _skip_space(text: str, position: int) -> int:
    return position + len(text[position:position + 4096]) - len(text[position:position + 4096].lstrip())


_JS_ROOT_MAP = re.compile(r"\b(Query|Mutation|Subscription)\s*:\s*\{")
# An object literal member at depth 0 (nested groups blanked): `user: ...`, or a method
# shorthand followed by its body (`async posts() {`), never a call on a continuation line.
_JS_MEMBER = re.compile(r"""(?:^|[,{\n])[ \t]*+(?:async[ \t]++)?\*?[ \t]*+['"]?(?P<name>[A-Za-z_$][\w$]{0,99})['"]?[ \t]*+"""
                        r"""(?::|\([ \t]*+\)[ \t\n]*+(?::[^{}\n]{0,200})?\{)""")
_JS_DECORATOR = re.compile(r"@(?P<kind>Query|Mutation|Subscription|ResolveField|FieldResolver)\s*\(")
_JS_BUILDER = re.compile(r"""(?<![\w$])(?:\w+\s*\.\s*)?(?P<kind>query|mutation|subscription)Field\s*\(\s*['"](?P<name>\w{1,100})['"]""")
_NAME_OPTION = re.compile(r"""\bname\s*:\s*['"](\w{1,100})['"]""")
# The method an annotation or decorator applies to, matched where the annotation ends: other
# annotations, modifiers and a return type, then the name before its parameter list.
_METHOD_AFTER = re.compile(r"(?:@\w{1,100}+(?:\([^()\n]{0,300}\))?\s*+){0,20}+(?:(?:public|private|protected|static|async|"
                           r"override|suspend|fun|open|final)\s++){0,8}+(?:[\w<>\[\],.?]{1,200}+\s++)?"
                           r"(?P<name>[A-Za-z_]\w{0,99}+)\s*+\(")
_GO_RESOLVER = re.compile(r"\bfunc\s*\(\s*\w{1,64}\s+\*?(?P<type>\w{1,64})Resolver\s*\)\s*(?P<name>[A-Z]\w{0,99})\s*\(")
_SPRING = re.compile(r"@(?P<kind>QueryMapping|MutationMapping|SubscriptionMapping|DgsQuery|DgsMutation|DgsSubscription)\b"
                     r"(?:\s*\(\s*(?:(?:name|field|value)\s*=\s*)?\"(?P<name>\w{1,100})\"\s*\))?")
_SPRING_SCHEMA = re.compile(r"@(?:SchemaMapping|DgsData|BatchMapping)\s*\((?P<arguments>[^()]{0,400})\)")
_SPRING_KINDS = {"QueryMapping": "Query", "MutationMapping": "Mutation", "SubscriptionMapping": "Subscription",
                 "DgsQuery": "Query", "DgsMutation": "Mutation", "DgsSubscription": "Subscription"}
_CS_CLASS = re.compile(r"(?P<attributes>(?:\[[^\[\]\n]{0,200}\]\s*){0,8})(?:public\s+|internal\s+)?(?:static\s+)?"
                       r"(?:partial\s+)?class\s+(?P<name>\w{1,100})(?P<bases>[^{;]{0,300})\{")  # the brace may be on its own line
_CS_METHOD = re.compile(r"\bpublic\s++(?:static\s++)?(?:async\s++)?(?:virtual\s++)?[\w<>\[\],.?]++\s++(?P<name>[A-Z]\w{0,99}+)\s*+\(")
_CS_FIELD = re.compile(r"""\bField\s*+(?:<[^()\n]{0,200}>)?\s*+\(\s*+"(?P<name>\w{1,100})\"""")
_RUBY_TYPE = re.compile(r"(?m)^(?P<indent>[ \t]*)class[ \t]+(?:\w+::)*(?P<name>\w*?(?:Query|Mutation|Subscription)Type)\b")
_RUBY_FIELD = re.compile(r"(?m)^[ \t]+field[ \t]+:(?P<name>\w{1,100})")
_RUST_IMPL = re.compile(r"#\[\s*(?P<kind>Object|Subscription|graphql_object|graphql_subscription)\b[^\]]{0,200}\]\s*"
                        r"impl(?:<[^<>{]{0,100}>)?\s+(?P<name>\w{1,100})")
_RUST_FN = re.compile(r"\b(?:pub(?:\([^()]{0,40}\))?\s+)?async\s+fn\s+(?P<name>\w{1,100})|\bfn\s+(?P<sync>\w{1,100})")
_ELIXIR_BLOCK = re.compile(r"(?m)^(?P<indent>[ \t]*)(?P<kind>query|mutation|subscription)[ \t]+do\b")
_ELIXIR_FIELD = re.compile(r"(?m)^[ \t]+field[ \t]+:(?P<name>\w{1,100})")


def resolvers(text: str, extension: str) -> list[tuple[str, str, str, int]]:
    """(GraphQL type, field, framework, line) of the resolvers a source file declares."""
    found: list[tuple[str, str, str, int]] = []
    if extension in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        for match in _JS_ROOT_MAP.finditer(text):  # Apollo and graphql-tools resolver maps
            body, _ = _block(text, match.end() - 1)
            for member in _JS_MEMBER.finditer(_top_level(body)):
                found.append((match.group(1), member.group("name"), "Apollo resolver map",
                              _line_at(text, match.end() + member.start("name"))))
        for match in _JS_DECORATOR.finditer(text):  # NestJS and TypeGraphQL
            close = _paren_end(text, match.end() - 1)
            named = _NAME_OPTION.search(text, match.end(), close)
            method = _METHOD_AFTER.match(text, _skip_space(text, close))
            name = named.group(1) if named else method.group("name") if method else ""
            if name:
                kind = match.group("kind")
                found.append((kind if kind in _ROOT_NAMES.values() else "(type field)", name, "NestJS/TypeGraphQL",
                              _line_at(text, match.start())))
        for match in _JS_BUILDER.finditer(text):  # Pothos and Nexus
            found.append((_ROOT_NAMES[match.group("kind")], match.group("name"), "Pothos/Nexus",
                          _line_at(text, match.start())))
    elif extension == ".go":
        for match in _GO_RESOLVER.finditer(text):  # gqlgen's generated resolver methods
            found.append((_root_of(match.group("type")[:1].upper() + match.group("type")[1:]),
                          _lower_first(match.group("name")), "gqlgen", _line_at(text, match.start())))
    elif extension in {".java", ".kt", ".kts", ".scala", ".groovy"}:
        for match in _SPRING.finditer(text):  # Spring for GraphQL and Netflix DGS
            method = _METHOD_AFTER.match(text, _skip_space(text, match.end()))
            name = match.group("name") or (method.group("name") if method else "")
            if name:
                framework = "Netflix DGS" if match.group("kind").startswith("Dgs") else "Spring for GraphQL"
                found.append((_SPRING_KINDS[match.group("kind")], name, framework, _line_at(text, match.start())))
        for match in _SPRING_SCHEMA.finditer(text):
            arguments = match.group("arguments")
            parent = re.search(r'\b(?:typeName|parentType)\s*=\s*"(\w+)"', arguments)
            named = re.search(r'\b(?:field|value)\s*=\s*"(\w+)"', arguments)
            method = _METHOD_AFTER.match(text, _skip_space(text, match.end()))
            name = named.group(1) if named else method.group("name") if method else ""
            if parent and name:
                framework = "Netflix DGS" if "DgsData" in match.group(0) else "Spring for GraphQL"
                found.append((parent.group(1), name, framework, _line_at(text, match.start())))
    elif extension == ".cs":
        for match in _CS_CLASS.finditer(text):  # Hot Chocolate and GraphQL.NET
            attributes, name, bases = match.group("attributes"), match.group("name"), match.group("bases")
            extended = re.search(r'ExtendObjectType\s*\(\s*(?:"(\w+)"|OperationTypeNames\.(\w+))', attributes)
            marked = re.search(r"\[(Query|Mutation|Subscription)Type\]", attributes)
            parent = (extended.group(1) or extended.group(2)) if extended else marked.group(1) if marked else _root_of(name)
            body, _ = _block(text, match.end() - 1, chars=True)
            if "ObjectGraphType" in bases:  # GraphQL.NET: Field<T>("name")
                for item in _CS_FIELD.finditer(body):
                    found.append((parent, item.group("name"), "GraphQL.NET", _line_at(text, match.end() + item.start())))
            elif parent in _ROOT_NAMES.values():
                for item in _CS_METHOD.finditer(body):
                    method = item.group("name")
                    if method == name:
                        continue  # a constructor
                    field_name = method[3:] if method.startswith("Get") and len(method) > 3 else method
                    field_name = field_name[:-5] if field_name.endswith("Async") else field_name
                    found.append((parent, _lower_first(field_name), "Hot Chocolate",
                                  _line_at(text, match.end() + item.start())))
    elif extension == ".rb":
        lines = text.split("\n")
        for match in _RUBY_TYPE.finditer(text):  # graphql-ruby
            parent = _root_of(match.group("name")[:-4])
            start = _line_at(text, match.start())
            indent = len(match.group("indent"))
            for number in range(start, len(lines)):
                line = lines[number]
                stripped = line.lstrip()
                if stripped and len(line) - len(stripped) <= indent and stripped.startswith("end"):
                    break
                field = _RUBY_FIELD.match(line)
                if field:
                    found.append((parent, _camel(field.group("name")), "graphql-ruby", number + 1))
    elif extension == ".rs":
        for match in _RUST_IMPL.finditer(text):  # async-graphql and juniper
            brace = text.find("{", match.end())
            if brace < 0:
                continue
            body, _ = _block(text, brace, chars=True)
            subscription = "ubscription" in match.group("kind")
            parent = "Subscription" if subscription else _root_of(match.group("name"))
            framework = "juniper" if match.group("kind").startswith("graphql_") else "async-graphql"
            for item in _RUST_FN.finditer(body):
                name = item.group("name") or item.group("sync")
                if name and not name.startswith("_"):
                    found.append((parent, _camel(name), framework, _line_at(text, brace + 1 + item.start())))
    elif extension in {".ex", ".exs"}:
        lines = text.split("\n")
        for match in _ELIXIR_BLOCK.finditer(text):  # Absinthe
            start = _line_at(text, match.start())
            indent = len(match.group("indent"))
            for number in range(start, len(lines)):
                line = lines[number]
                stripped = line.lstrip()
                if stripped and len(line) - len(stripped) <= indent:
                    break
                field = _ELIXIR_FIELD.match(line)
                if field and len(line) - len(stripped) == indent + 2:
                    found.append((_ROOT_NAMES[match.group("kind")], _camel(field.group("name")), "Absinthe", number + 1))
    return found


def python_resolvers(source: str, relative: str) -> list[tuple[str, str, str, int]]:
    """(GraphQL type, field, framework, line) of Strawberry, Graphene and Ariadne resolvers."""
    import ast

    try:
        tree = ast.parse(source, filename=relative)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    found: list[tuple[str, str, str, int]] = []

    def dotted(node: ast.AST) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    bindables: dict[str, str] = {}  # Ariadne: variable -> GraphQL type
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and isinstance(node.value, ast.Call):
            callee = dotted(node.value.func).rsplit(".", 1)[-1]
            if callee in {"QueryType", "MutationType", "SubscriptionType"}:
                bindables[node.targets[0].id] = callee[:-4]
            elif callee in {"ObjectType", "InterfaceType"} and node.value.args \
                    and isinstance(node.value.args[0], ast.Constant) and isinstance(node.value.args[0].value, str):
                bindables[node.targets[0].id] = node.value.args[0].value
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            decorators = [dotted(item.func if isinstance(item, ast.Call) else item) for item in node.decorator_list]
            bases = [dotted(base) for base in node.bases]
            if any(item.endswith(("strawberry.type", "federation.type")) or item == "type" for item in decorators):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                        marks = [dotted(mark.func if isinstance(mark, ast.Call) else mark) for mark in item.decorator_list]
                        if any(mark.rsplit(".", 1)[-1] in {"field", "mutation", "subscription"} for mark in marks):
                            found.append((node.name, _camel(item.name), "Strawberry", item.lineno))
                    elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) \
                            and isinstance(item.value, ast.Call) and dotted(item.value.func).endswith("field"):
                        found.append((node.name, _camel(item.target.id), "Strawberry", item.lineno))
            elif any(base.rsplit(".", 1)[-1] == "ObjectType" for base in bases):  # Graphene
                names: dict[str, int] = {}
                for item in node.body:
                    if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name) \
                            and isinstance(item.value, ast.Call) and not item.targets[0].id.startswith("_"):
                        names.setdefault(item.targets[0].id, item.lineno)
                    elif isinstance(item, ast.FunctionDef) and item.name.startswith("resolve_"):
                        names.setdefault(item.name[len("resolve_"):], item.lineno)
                for name, line in names.items():
                    found.append((node.name, _camel(name), "Graphene", line))
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for mark in node.decorator_list:
                if isinstance(mark, ast.Call) and isinstance(mark.func, ast.Attribute) \
                        and mark.func.attr in {"field", "source"} and isinstance(mark.func.value, ast.Name) \
                        and mark.func.value.id in bindables and mark.args \
                        and isinstance(mark.args[0], ast.Constant) and isinstance(mark.args[0].value, str):
                    found.append((bindables[mark.func.value.id], mark.args[0].value, "Ariadne", node.lineno))
    return [(_root_of(parent), name, framework, line) for parent, name, framework, line in found]
