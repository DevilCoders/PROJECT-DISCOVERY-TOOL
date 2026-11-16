"""Password and secret assignments in every syntax the scanner reads, with the value never kept:
JSON, TOML, INI, properties, XML elements and attributes, .NET key/value pairs, HCL attributes
and variable defaults, YAML block scalars, triple-quoted and multiline literals."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from project_discovery.analyzers.security.secrets import SecretPatternAnalyzer
from project_discovery.core.source_utils import redact_source_excerpt
from project_discovery.models import FileRecord

SECRET = "Kq8vT2mZp9wX"


def _findings(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, Path(filename).suffix or Path(filename).name, "Config")
    analyzer = SecretPatternAnalyzer()
    assert analyzer.supports(record)
    return [item for item in analyzer.analyze(path, record) if item.title.endswith("credential_assignment")]


@pytest.mark.parametrize(("filename", "content", "line"), [
    ("config.json", f'{{\n  "database": {{\n    "password": "{SECRET}"\n  }}\n}}\n', 3),
    ("config.toml", f'[database]\npassword = "{SECRET}"\n', 2),
    ("config.toml", f"[database]\npassword = '''{SECRET}'''\n", 2),
    ("app.ini", f"[db]\npassword = {SECRET}\n", 2),
    ("app.properties", f"db.password={SECRET}\n", 1),
    ("settings.xml", f"<servers>\n  <server>\n    <password>{SECRET}</password>\n  </server>\n</servers>\n", 3),
    ("context.xml", f'<Resource name="jdbc/app" username="app" password="{SECRET}"/>\n', 1),
    ("web.config", f'<appSettings>\n  <add key="DbPassword" value="{SECRET}" />\n</appSettings>\n', 2),
    ("main.tf", f'resource "aws_db_instance" "db" {{\n  password = "{SECRET}"\n}}\n', 2),
    ("variables.tf", f'variable "db_password" {{\n  type      = string\n  sensitive = true\n  default   = "{SECRET}"\n}}\n', 1),
    ("config.yaml", f"database:\n  password: |\n    {SECRET}\n", 2),
    ("config.yml", f"database:\n  password: >-\n    {SECRET}\n", 2),
    ("settings.py", f'PASSWORD = """{SECRET}"""\n', 1),
    (".env", f'DB_PASSWORD="{SECRET[:6]}\n{SECRET[6:]}"\n', 1),
])
def test_assignments_are_found_and_their_values_never_kept(tmp_path: Path, filename, content, line):
    findings = _findings(tmp_path, filename, content)
    assert [item.code_evidence[0].line_number for item in findings] == [line], findings
    # Nothing the report keeps holds the value: title, detail, evidence, excerpt, impact.
    assert SECRET not in repr(asdict(findings[0])) and SECRET[:6] not in findings[0].code_evidence[0].code


@pytest.mark.parametrize(("filename", "content"), [
    ("settings.xml", "<password>changeme</password>\n"),                       # a placeholder
    ("web.config", f'<add key="Title" value="{SECRET}" />\n'),                 # not a credential name
    ("variables.tf", f'variable "region" {{\n  default = "{SECRET}"\n}}\n'),
    ("config.yaml", f"docs:\n  description: |\n    {SECRET}\n"),
    ("config.yaml", "database:\n  password: |\n    ${DB_PASSWORD}\n"),        # a reference, not a value
])
def test_names_that_are_not_credentials_and_placeholders_are_not_reported(tmp_path: Path, filename, content):
    assert _findings(tmp_path, filename, content) == []


def test_the_excerpt_redactor_covers_each_syntax():
    for line in (f"<password>{SECRET}</password>", f'<add key="DbPassword" value="{SECRET}" />',
                 f'PASSWORD = """{SECRET}"""', f"secret = '''{SECRET}'''", f'token = """{SECRET} and more',
                 f'<param name="client_secret" value="{SECRET}"/>'):
        assert SECRET not in redact_source_excerpt(line), line
    assert redact_source_excerpt('<add key="Title" value="Hello world" />') == '<add key="Title" value="Hello world" />'
