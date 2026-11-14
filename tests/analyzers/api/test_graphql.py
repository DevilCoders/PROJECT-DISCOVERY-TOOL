"""GraphQL: schemas, operations, resolvers, directives, federation and subscriptions."""
import json
import time
from pathlib import Path

from project_discovery.analyzers.api import graphql
from project_discovery.analyzers.api.graphql import GraphQLAnalyzer, embedded, parse, python_resolvers, resolvers
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.models import FileRecord

SCHEMA = '''
extend schema @link(url: "https://specs.apollo.dev/federation/v2.3", import: ["@key", "@shareable"])
"""
The query root { braces in a description } # and a hash
"""
type Query {
  "one user"
  user(id: ID!): User
  users(first: Int = 10, filter: UserFilter): [User!]! @deprecated(reason: "use search { }")
  # a comment { with braces
}
type Mutation { createUser(input: CreateUserInput!): User! }
type Subscription { userCreated: User }
type User implements Node & Entity @key(fields: "id") { id: ID! name: String @shareable }
interface Node { id: ID! }
input CreateUserInput { name: String! tags: [[String!]!] = [] }
enum Role { ADMIN USER }
union SearchResult = | User | Post
scalar DateTime
directive @auth(requires: Role = ADMIN) on | OBJECT | FIELD_DEFINITION
type Post { id: ID! }
'''


def _analyze(tmp_path: Path, relative: str, source: str):
    path = tmp_path / "source"
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, Path(relative).suffix.lower(), "Source")
    analyzer = GraphQLAnalyzer()
    assert analyzer.supports(record)
    return {finding.title.split(":", 1)[0]: finding for finding in analyzer.analyze(path, record)}


def test_the_parser_reads_definitions_operations_and_skips_strings_and_comments():
    document = parse(SCHEMA + "query GetUser($id: ID!) { user(id: $id) { ...UserParts @include(if: true) name } "
                     "me: viewer { id } ... on Query { ping } }\nfragment UserParts on User { id }\n"
                     "subscription OnCreate { userCreated { id } }\n{ users { id } }\n")
    types = {definition.name: definition for definition in document.types}
    assert [name for name, _ in types["Query"].fields] == ["user", "users"]
    assert types["User"].implements == ["Node", "Entity"] and types["User"].directives == [("key", '(fields: "id")')]
    assert [name for name, _ in types["SearchResult"].fields] == ["User", "Post"]
    assert [name for name, _ in types["CreateUserInput"].fields] == ["name", "tags"]
    assert types["DateTime"].kind == "scalar" and "Post" in types
    assert document.directives == [("auth", 20, "OBJECT|FIELD_DEFINITION")]
    assert document.links == ["https://specs.apollo.dev/federation/v2.3"]
    # Directive uses describe the schema; @include and @skip inside operations are not counted.
    assert dict(document.directive_uses) == {"link": 1, "deprecated": 1, "key": 1, "shareable": 1}
    assert [(operation.kind, operation.name, operation.fields) for operation in document.operations] == [
        ("query", "GetUser", ["user", "viewer"]), ("subscription", "OnCreate", ["userCreated"]), ("query", "", ["users"])]
    assert document.fragments == [("UserParts", "User", 23)]


def test_schema_findings_with_subscriptions_and_federation(tmp_path: Path):
    with collecting_facts() as facts:
        findings = _analyze(tmp_path, "schema.graphql", SCHEMA)
    schema = findings["GraphQL schema"]
    assert schema.confidence == "CONFIRMED"
    assert "2 query field(s) (user, users)" in schema.detail and "1 mutation field(s) (createUser)" in schema.detail
    assert "directives defined: @auth" in schema.detail
    assert "schema.graphql:8 Query.user" in schema.evidence
    assert "userCreated" in findings["GraphQL subscriptions"].detail
    federation = findings["GraphQL federation"]
    assert "Apollo Federation 2.3 subgraph schema with 1 entit(ies) (User)" in federation.detail
    emitted = {(kind, name) for kind, name, _ in facts.facts}
    assert {("graphql_field", "Query.user"), ("graphql_field", "Subscription.userCreated"),
            ("graphql_entity", "User")} <= emitted


def test_federation_one_and_custom_root_names(tmp_path: Path):
    findings = _analyze(tmp_path, "products.graphqls", (
        "schema { query: RootQuery }\ntype RootQuery { topProducts: [Product] }\n"
        'extend type Product @key(fields: "upc") {\n  upc: String! @external\n  reviews: [Review]\n}\n'
    ))
    assert "1 query field(s) (topProducts)" in findings["GraphQL schema"].detail
    federation = findings["GraphQL federation"]
    assert "Apollo Federation 1 subgraph" in federation.detail
    assert federation.evidence == ['products.graphqls:3 extend type Product @key(fields: "upc")']


def test_operations_documents(tmp_path: Path):
    findings = _analyze(tmp_path, "queries.graphql", (
        "query GetUser($id: ID!) {\n  user(id: $id) { ...Parts }\n}\nmutation Save { save { ok } }\n"
        "fragment Parts on User { id name }\n"
    ))
    operations = findings["GraphQL operations"]
    assert "1 mutation, 1 query; 1 fragment(s)" in operations.detail
    assert operations.evidence[:2] == ["queries.graphql:1 query GetUser { user }", "queries.graphql:4 mutation Save { save }"]
    assert "GraphQL schema" not in findings


def test_graphql_embedded_in_code(tmp_path: Path):
    typescript = (
        'import { gql } from "@apollo/client";\n'
        "export const typeDefs = gql`\n  type Query { hello: String ${extra} }\n`;\n"
        "const QUERY = gql<Data>`query Hello { hello }`;\n"
        "const OTHER = /* GraphQL */ `mutation Do($x: Int) { do(x: $x) { ok } }`;\n"
    )
    assert [(body.strip()[:12], line) for body, line in embedded(typescript, ".ts")] == [
        ("type Query {", 2), ("query Hello ", 5), ("mutation Do(", 6)]
    findings = _analyze(tmp_path, "src/schema.ts", typescript)
    assert findings["GraphQL schema"].confidence == "INFERRED"
    assert "1 query field(s) (hello)" in findings["GraphQL schema"].detail
    assert "1 mutation, 1 query" in findings["GraphQL operations"].detail
    python = 'from ariadne import gql\ntype_defs = gql("""\n    type Query {\n        ping: String\n    }\n""")\n'
    assert "1 query field(s) (ping)" in _analyze(tmp_path, "schema.py", python)["GraphQL schema"].detail
    csharp = ('builder.Services.AddGraphQLServer()\n    .AddDocumentFromString(@"\n        type Query {\n'
              '            book: String @deprecated(reason: ""old"")\n        }")\n')
    assert "1 query field(s) (book)" in _analyze(tmp_path, "Program.cs", csharp)["GraphQL schema"].detail
    assert _analyze(tmp_path, "plain.ts", "export const x = 1;\n") == {}


def test_javascript_resolvers():
    source = (
        "const resolvers = {\n"
        "  Query: {\n"
        "    user: (_, { id }) => db.user(id),\n"
        "    'users': async () => {\n      return db.users();\n    },\n"
        "    async search(_, args) {\n      return find(args);\n    },\n"
        "    viewer: async (_parent, args) =>\n      getViewer(args),\n"
        "  },\n"
        "  Mutation: { createUser: (_, { input }) => create(input) },\n"
        "  Subscription: { userCreated: { subscribe: () => pubsub.asyncIterator(['USER_CREATED']) } },\n"
        "};\n"
        "@Resolver(() => User)\nexport class UserResolver {\n"
        "  @Query(() => User, { name: 'findUser' })\n  async user(@Args('id') id: string) {}\n"
        "  @Mutation(() => User)\n  createUser(@Args('input') input: CreateUserInput) {}\n"
        "  @ResolveField()\n  posts(@Parent() user: User) {}\n}\n"
        "builder.queryField('me', (t) => t.field({ type: User }));\n"
    )
    assert [(parent, name, framework) for parent, name, framework, _ in resolvers(source, ".ts")] == [
        ("Query", "user", "Apollo resolver map"), ("Query", "users", "Apollo resolver map"),
        ("Query", "search", "Apollo resolver map"), ("Query", "viewer", "Apollo resolver map"),
        ("Mutation", "createUser", "Apollo resolver map"), ("Subscription", "userCreated", "Apollo resolver map"),
        ("Query", "findUser", "NestJS/TypeGraphQL"), ("Mutation", "createUser", "NestJS/TypeGraphQL"),
        ("(type field)", "posts", "NestJS/TypeGraphQL"), ("Query", "me", "Pothos/Nexus"),
    ]


def test_resolvers_on_the_jvm_go_dotnet_ruby_rust_and_elixir():
    go = ("func (r *queryResolver) Todos(ctx context.Context) ([]*model.Todo, error) {}\n"
          "func (r *mutationResolver) CreateTodo(ctx context.Context, input model.NewTodo) (*model.Todo, error) {}\n"
          "func (r *todoResolver) User(ctx context.Context, obj *model.Todo) (*model.User, error) {}\n")
    assert [(parent, name) for parent, name, _, _ in resolvers(go, ".go")] == [
        ("Query", "todos"), ("Mutation", "createTodo"), ("Todo", "user")]
    java = (
        "@Controller\nclass BookController {\n"
        "  @QueryMapping\n  public Book bookById(@Argument String id) { return null; }\n"
        '  @MutationMapping(name = "addBook")\n  public Book create(@Argument BookInput input) { return null; }\n'
        "  @SubscriptionMapping\n  public Flux<Book> bookAdded() { return null; }\n"
        '  @SchemaMapping(typeName = "Book", field = "author")\n  public Author author(Book book) { return null; }\n'
        '  @DgsQuery(field = "shows")\n  public List<Show> allShows() { return null; }\n'
        '  @DgsData(parentType = "Show", field = "reviews")\n  public List<Review> reviews() { return null; }\n'
        "}\n"
    )
    assert [(parent, name, framework) for parent, name, framework, _ in resolvers(java, ".java")] == [
        ("Query", "bookById", "Spring for GraphQL"), ("Mutation", "addBook", "Spring for GraphQL"),
        ("Subscription", "bookAdded", "Spring for GraphQL"), ("Query", "shows", "Netflix DGS"),
        ("Book", "author", "Spring for GraphQL"), ("Show", "reviews", "Netflix DGS"),
    ]
    kotlin = "class Q {\n  @QueryMapping\n  fun greeting(@Argument name: String): String = name\n}\n"
    assert [(parent, name) for parent, name, _, _ in resolvers(kotlin, ".kt")] == [("Query", "greeting")]
    csharp = (
        "public class Query\n{\n    public Book GetBook(int id) => new();\n"
        "    public async Task<IEnumerable<Author>> GetAuthorsAsync() => null;\n}\n"
        '[ExtendObjectType(OperationTypeNames.Mutation)]\npublic class BookMutations\n{\n'
        "    public BookMutations() {}\n    public Book AddBook(BookInput input) => null;\n}\n"
        "public class StarWarsQuery : ObjectGraphType\n{\n"
        '    public StarWarsQuery() { Field<CharacterType>("hero").Resolve(ctx => null); }\n}\n'
    )
    assert [(parent, name, framework) for parent, name, framework, _ in resolvers(csharp, ".cs")] == [
        ("Query", "book", "Hot Chocolate"), ("Query", "authors", "Hot Chocolate"),
        ("Mutation", "addBook", "Hot Chocolate"), ("Query", "hero", "GraphQL.NET"),
    ]
    ruby = ("module Types\n  class QueryType < Types::BaseObject\n    field :user_by_id, UserType\n"
            "    field :users, [UserType]\n  end\nend\n")
    assert [(parent, name) for parent, name, _, _ in resolvers(ruby, ".rb")] == [("Query", "userById"), ("Query", "users")]
    rust = ("#[Object]\nimpl QueryRoot {\n    async fn user_by_id(&self, id: ID) -> User { todo!() }\n}\n"
            "#[Subscription]\nimpl SubscriptionRoot {\n    async fn ticks(&self) -> impl Stream<Item = i32> { todo!() }\n}\n"
            "#[graphql_object]\nimpl Mutation {\n    fn create_human(new_human: NewHuman) -> Human { todo!() }\n}\n")
    assert [(parent, name, framework) for parent, name, framework, _ in resolvers(rust, ".rs")] == [
        ("Query", "userById", "async-graphql"), ("Subscription", "ticks", "async-graphql"),
        ("Mutation", "createHuman", "juniper")]
    elixir = ("query do\n  field :posts, list_of(:post) do\n    resolve &Resolvers.list_posts/3\n  end\n"
              "  field :post_by_id, :post\nend\nsubscription do\n  field :post_added, :post\nend\n")
    assert [(parent, name) for parent, name, _, _ in resolvers(elixir, ".ex")] == [
        ("Query", "posts"), ("Query", "postById"), ("Subscription", "postAdded")]


def test_python_resolvers():
    source = (
        "import strawberry\nimport graphene\nfrom ariadne import ObjectType, QueryType\n\n"
        "@strawberry.type\nclass Query:\n    @strawberry.field\n    def user_by_id(self, id: int) -> User: ...\n"
        "    books: list[Book] = strawberry.field(resolver=get_books)\n\n"
        "@strawberry.type\nclass Mutation:\n    @strawberry.mutation\n    def add_book(self, title: str) -> Book: ...\n\n"
        "class GrapheneQuery(graphene.ObjectType):\n    hello = graphene.String()\n"
        "    def resolve_hello(root, info): ...\n    def resolve_goodbye(root, info): ...\n\n"
        "query = QueryType()\nuser = ObjectType(\"User\")\n\n@query.field(\"viewer\")\ndef resolve_viewer(*_): ...\n"
        "@user.field(\"fullName\")\ndef resolve_full_name(obj, *_): ...\n"
    )
    assert [(parent, name, framework) for parent, name, framework, _ in python_resolvers(source, "schema.py")] == [
        ("Query", "userById", "Strawberry"), ("Query", "books", "Strawberry"), ("Mutation", "addBook", "Strawberry"),
        ("Query", "hello", "Graphene"), ("Query", "goodbye", "Graphene"), ("Query", "viewer", "Ariadne"),
        ("User", "fullName", "Ariadne"),
    ]


def test_federation_and_subscription_transports_in_code(tmp_path: Path):
    gateway = ('import { ApolloGateway, IntrospectAndCompose } from "@apollo/gateway";\n'
               'import { useServer } from "graphql-ws/lib/use/ws";\nconst pubsub = new PubSub();\n')
    findings = _analyze(tmp_path, "gateway.ts", gateway)
    assert "gateway (it composes subgraphs)" in findings["GraphQL federation in code"].detail
    assert "graphql-ws, PubSub" in findings["GraphQL subscription transport"].detail


def test_oversized_files(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(graphql, "MAX_GRAPHQL_BYTES", 10)
    sdl = _analyze(tmp_path, "schema.graphql", "type Query { a: Int }\n")
    assert sdl["GraphQL scan budget reached"].confidence == "UNKNOWN"
    assert _analyze(tmp_path, "bundle.js", "var a = 1; var b = 2;\n") == {}
    assert "GraphQL scan budget reached" in _analyze(tmp_path, "bundle.js", "var q = gql`query { a }`;\n")


def test_the_parser_is_linear_on_adversarial_input():
    for text in ("[" * 50_000, "{" * 50_000, "type T { a: " + "[" * 50_000, '"""' * 20_000, "@a" * 30_000,
                 "query " * 20_000, "union U = " + "A | " * 30_000):
        started = time.perf_counter()
        parse(text)
        assert time.perf_counter() - started < 5


def test_the_code_index_matches_schema_fields_resolvers_and_operations(tmp_path: Path):
    project = tmp_path / "project"
    files = {
        "schema.graphql": "type Query { user(id: ID!): User users: [User] }\ntype Mutation { createUser: User }\n"
                          "type User { id: ID! }\n",
        "src/resolvers.ts": ("const resolvers = {\n  Query: {\n    user: () => null,\n    legacy: () => null,\n  },\n"
                             "  Mutation: { createUser: () => null },\n};\nexport default resolvers;\n"),
        "web/queries.graphql": "query GetUser { user(id: 1) { id } }\nquery Old { gone { id } }\n",
    }
    for name, text in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    value = report["metrics"]["code_index"]["graphql"]
    assert value["unresolved_fields"] == ["Query.users"]
    assert value["orphan_resolvers"] == ["Query.legacy"]
    assert [(item["name"], item["missing"]) for item in value["unknown_operation_fields"]] == [("Old", ["gone"])]
    titles = {item["title"] for item in report["findings"] if item["analyzer"] == "code-index"}
    assert {"GraphQL API", "GraphQL fields without a resolver", "GraphQL resolvers for fields no schema declares",
            "GraphQL operations calling fields no schema declares"} <= titles
