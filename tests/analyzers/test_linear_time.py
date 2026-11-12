"""Analyzers stay linear on adversarial file shapes, and the linear scanners that replaced
super-linear regexes find exactly what those regexes found.

Each shape below made an analyzer quadratic (or worse) before: per-match line counting
over the whole file, regexes that rescanned to the end of the file from every unclosed
construct, and secure-code rules that rescanned a statement from every call they found.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from project_discovery.analyzers.content.localization import LocalizationAnalyzer
from project_discovery.analyzers.databases.migrations import MigrationIntelligenceAnalyzer
from project_discovery.analyzers.databases.prisma import PrismaSchemaAnalyzer
from project_discovery.analyzers.databases.sql import SQLSchemaAnalyzer
from project_discovery.analyzers.delivery.deployment import DeploymentIntelligenceAnalyzer
from project_discovery.analyzers.environment.configuration import ConfigurationAnalyzer
from project_discovery.analyzers.security.secrets import SecretPatternAnalyzer
from project_discovery.analyzers.security.secure_code import SecureCodePatternAnalyzer
from project_discovery.models import FileRecord

SHAPES = [
    (SQLSchemaAnalyzer, "schema.sql", "CREATE INDEX i ON t (c);\n"),
    (SQLSchemaAnalyzer, "alter.sql", "ALTER TABLE t\n"),
    (SQLSchemaAnalyzer, "blank.sql", "\n"),
    (MigrationIntelligenceAnalyzer, "migrations/V1__x.sql", "CREATE TABLE t (a int);\n"),
    (MigrationIntelligenceAnalyzer, "db/changelog/changes.xml", "<changeSet a\n"),
    (PrismaSchemaAnalyzer, "schema.prisma", "enum E {\n  A\n}\n"),
    (PrismaSchemaAnalyzer, "open.prisma", "model A {\n"),
    (DeploymentIntelligenceAnalyzer, "main.tf", "cidr_blocks = [\n"),
    (DeploymentIntelligenceAnalyzer, "blocks.tf", 'resource "a" "b" {}\n'),
    (ConfigurationAnalyzer, "nginx.conf", "a" + " " * 200 + "#\n"),
    (LocalizationAnalyzer, "locale/en.po", 'msgid "' + "\\" * 60 + "\n"),
    (SecretPatternAnalyzer, "app.min.js", "token=Fk3x9q2;"),
    (SecureCodePatternAnalyzer, "app.js", "redirect(a,"),
    (SecureCodePatternAnalyzer, "Parser.java", "setFeature(external-general-entities,"),
    (SecureCodePatternAnalyzer, "verify.js", "verify(a"),
    (SecureCodePatternAnalyzer, "chmod.js", "chmod(a,"),
    (SecureCodePatternAnalyzer, "random.js", "token "),
]


def _elapsed(tmp_path: Path, analyzer_class, name: str, unit: str, size: int) -> float:
    path = tmp_path / f"{size}-{name.replace('/', '_')}"
    path.write_bytes((unit * (size // len(unit))).encode())
    record = FileRecord(name, path.stat().st_size, Path(name).suffix, "Text", file_type="text")
    analyzer = analyzer_class()
    assert analyzer.supports(record), name
    started = time.perf_counter()
    analyzer.analyze(path, record)
    return time.perf_counter() - started


@pytest.mark.parametrize(("analyzer_class", "name", "unit"), SHAPES, ids=[item[1] for item in SHAPES])
def test_analyzers_stay_linear_on_adversarial_shapes(tmp_path, analyzer_class, name, unit):
    small = _elapsed(tmp_path, analyzer_class, name, unit, 128 * 1024)
    large = _elapsed(tmp_path, analyzer_class, name, unit, 512 * 1024)
    if large > 0.25 and large > 10 * small:  # linear is about 4x; confirm once on a busy runner
        small = min(small, _elapsed(tmp_path, analyzer_class, name, unit, 128 * 1024))
        large = min(large, _elapsed(tmp_path, analyzer_class, name, unit, 512 * 1024))
    assert large < 2.0, f"{name}: {large:.2f}s for 512 KiB"
    assert large <= 0.25 or large <= 10 * small, f"{name}: x{large / small:.0f} from 128 KiB to 512 KiB"


# The patterns the linear secure-code rules replaced, for a differential check.
_REFERENCE = {
    "dynamic_sql_query": r"""(?i)\b(?:query|execute|execSQL|raw|createQuery)\s*\([^;\n]*(?:\+\s*[A-Za-z_$]|\.format\s*\(|\$\{)""",
    "ssrf_user_controlled_url": r"""(?i)\b(?:requests?\.(?:get|post|put|delete)|httpx\.(?:get|post)|axios\.(?:get|post)|fetch|http\.Get|GetAsync|sendAsync)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params|body)|getParameter\s*\(|params\[|user_?input)""",
    "path_traversal_user_controlled_path": r"""(?i)\b(?:readFile|writeFile|FileInputStream|Paths\.get|Path\.Combine|sendFile|open)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params|body)|getParameter\s*\(|params\[|user_?input)""",
    "jwt_verification_disabled": r"""(?i)(?:algorithms\s*[:=]\s*\[\s*["']none["']|ignoreExpiration\s*[:=]\s*true|verify\s*\(\s*[^,]+,\s*false\s*\))""",
    "insecure_random_for_secret": r"""(?i)(?:token|secret|session|nonce|api[_-]?key).{0,130}?(?:Math\.random\s*\(|new\s+Random\s*\(|\brand\s*\()""",
    "open_redirect_user_controlled": r"""(?i)\b(?:redirect|sendRedirect|Redirect)\s*\([^;\n]*(?:req(?:uest)?\.(?:query|params)|getParameter\s*\(|returnUrl|return_url|nextUrl|next_url)""",
    # setWritable(true) sets only the owner's bit; (true, false) grants every user.
    "insecure_file_permissions": r"""(?i)(?:\bchmod(?:Sync)?\s*\([^;\n]*(?:0o?777|511)|\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b|\bset(?:Writable|Readable|Executable)\s*\(\s*true\s*,\s*false\s*\))""",
    "unsafe_xml_external_entities": r"""(?i)(?:setFeature\s*\([^;\n]*(?:external-general-entities|external-parameter-entities)[^;\n]*true|resolveExternals\s*=\s*true|DtdProcessing\s*[:=]\s*(?:DtdProcessing\.)?Parse)""",
}
_LINES = [
    "db.query('SELECT * FROM t WHERE id=' + id)", "db.query(sql, [id]); x = a + b", "cursor.execute(q.format(x))",
    "execute(`SELECT ${x}`)", "query(a); b + c", "requests.get(url, params=req.query.x)", "fetch(user_input)",
    "fetch(a); req.query", "open(request.params['f'])", "readFile(path); params[0]", "jwt.verify(token, false)",
    "verify(a, b, false)", "verify(, false)", "verify(x , false )", 'algorithms: ["none"]', "ignoreExpiration: true",
    "token = Math.random()", "session" + "x" * 140 + "Math.random()", "nonce" + "x" * 120 + "rand()",
    "res.redirect(req.query.next)", "redirect(a); returnUrl", "Redirect(nextUrl)", "os.chmod(p, 0o777)",
    "chmod(p, 511)", "chmod 777 file", "f.setWritable(true)", "chmod(p); 0777", "f.setWritable(true, false)",
    "fs.chmodSync(p, 0o777)", "chmod -R 777 /srv", "f.setExecutable(true,false)",
    'f.setFeature("http://xml.org/sax/features/external-general-entities", true)',
    'f.setFeature("external-parameter-entities", false); true', "resolveExternals = true",
    "settings.DtdProcessing = DtdProcessing.Parse", "redirect(a,redirect(a,redirect(req.query.x)",
    "query(a + b; query(c + d)", "verify(a verify(, false)", "",
]


def test_linear_secure_code_rules_match_the_regexes_they_replaced():
    from project_discovery.analyzers.security.secure_code import _PATTERNS

    rules = {rule: pattern for rule, pattern, _, _ in _PATTERNS}
    for rule, source in _REFERENCE.items():
        reference = re.compile(source)
        for line in _LINES:
            assert bool(rules[rule].search(line)) == bool(reference.search(line)), (rule, line)


def test_line_index_matches_counting_newlines():
    from project_discovery.core.source_utils import LineIndex

    text = "a\nbb\n\nccc\n"
    index = LineIndex(text)
    assert [index.line(offset) for offset in range(len(text) + 1)] == [
        text.count("\n", 0, offset) + 1 for offset in range(len(text) + 1)
    ]


def test_prisma_blocks_report_their_own_lines(tmp_path):
    # The block regex started at the blank line above each block, so lines were off by one.
    path = tmp_path / "schema.prisma"
    path.write_bytes(b"datasource db {\n  provider = \"postgresql\"\n}\n\nmodel User {\n  id Int @id\n  posts Post[]\n}\n\n"
                     b"model Post {\n  id Int @id\n  author User\n}\n")
    record = FileRecord("schema.prisma", path.stat().st_size, ".prisma", "Prisma", file_type="text")
    finding = PrismaSchemaAnalyzer().analyze(path, record)[0]
    assert "schema.prisma:5 model User (2 fields)" in finding.evidence
    assert "schema.prisma:10 model Post (2 fields)" in finding.evidence


def test_linear_scanners_keep_the_former_matches():
    from project_discovery.analyzers.api.integration import _pom_identity_text
    from project_discovery.analyzers.databases.migrations import _changeset_id
    from project_discovery.analyzers.databases.sql import _drop_column_statements
    from project_discovery.analyzers.dependencies.manifests import _CLOSE_BRACE, _ROCKSPEC_DEPENDENCIES, _delimited
    from project_discovery.analyzers.environment.configuration import _directive_keys

    pom = "<parent><groupId>p</groupId></parent><!-- c --><groupId>g</groupId><dependencies><groupId>d</groupId>"
    assert _pom_identity_text(pom) == re.sub(r"(?s)<parent>.*?</parent>|<dependencies>.*|<!--.*?-->", "", pom)
    unclosed = "<parent><groupId>p</groupId><!-- x <groupId>g</groupId>"
    assert _pom_identity_text(unclosed) == re.sub(r"(?s)<parent>.*?</parent>|<dependencies>.*|<!--.*?-->", "", unclosed)
    sql = "ALTER TABLE a ADD COLUMN x int;\nALTER TABLE b\n  DROP COLUMN y;\nALTER TABLE c DROP COLUMN z"
    reference = re.compile(r"(?im)^\s*ALTER\s+TABLE\b[^;]*?\bDROP\s+COLUMN\b")
    assert [sql.count("\n", 0, start) for start in _drop_column_statements(sql)] == [
        sql.count("\n", 0, match.start()) for match in reference.finditer(sql)
    ] == [1, 3]
    assert _changeset_id('<changeSet author="a>b" id="x"><changeSet id="2" author="me">') == "2"
    assert _changeset_id("<databaseChangeLog/>") is None
    assert _delimited('dependencies = { "lua >= 5.1", "x" }', _ROCKSPEC_DEPENDENCIES, _CLOSE_BRACE) == ' "lua >= 5.1", "x" '
    assert _directive_keys("listen 80;\nserver_name a.example b;\nroot  ;\nkey = value\nbad a;b\n# c d\n") == [
        "listen", "server_name",
    ]
