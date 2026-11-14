import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from project_discovery.core.safe_parsers import (
    UnsafeDocumentError,
    safe_xml_fromstring,
    safe_yaml_load,
    safe_yaml_load_all,
)
from project_discovery.models import FileRecord

pytest.importorskip("yaml")

# 9 levels x 9 aliases: ~400 bytes that expand to 9**9 (387 million) leaves.
YAML_BOMB = "\n".join(
    ['a0: &a0 ["x","x","x","x","x","x","x","x","x"]']
    + [f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 9) + "]" for i in range(1, 9)]
) + "\n"
XML_BOMB = (
    '<?xml version="1.0"?>\n<!DOCTYPE lolz [\n <!ENTITY lol "lol">\n'
    + "".join(
        f' <!ENTITY lol{i} "' + f"&lol{i - 1 if i > 1 else ''};" * 10 + '">\n'
        for i in range(1, 10)
    )
    + "]>\n<manifest>&lol9;</manifest>\n"
)


def test_yaml_alias_bomb_is_rejected_without_expansion():
    started = time.monotonic()
    with pytest.raises(UnsafeDocumentError, match="expansion"):
        safe_yaml_load(YAML_BOMB)
    assert time.monotonic() - started < 2


def test_recursive_yaml_alias_is_rejected():
    with pytest.raises(UnsafeDocumentError, match="recursive"):
        safe_yaml_load("a: &a [*a]\n")


def test_ordinary_anchors_merge_keys_and_streams_still_load():
    compose = (
        "x-defaults: &defaults\n  restart: always\n  image: app\n"
        "services:\n  web:\n    <<: *defaults\n    ports: ['8080:80']\n"
    )
    data = safe_yaml_load(compose)
    assert data["services"]["web"] == {"restart": "always", "image": "app", "ports": ["8080:80"]}
    assert safe_yaml_load_all("a: 1\n---\nb: 2\n") == [{"a": 1}, {"b": 2}]
    assert safe_yaml_load("") is None


def test_unknown_tags_are_constructed_only_when_allowed():
    template = "Resources:\n  Bucket:\n    Properties:\n      Name: !Ref BucketName\n"
    assert safe_yaml_load(template, allow_unknown_tags=True)["Resources"]["Bucket"] == {
        "Properties": {"Name": "BucketName"}
    }
    with pytest.raises(ValueError, match="Invalid YAML"):
        safe_yaml_load(template)


def test_xml_entity_declarations_are_rejected_in_any_encoding():
    with pytest.raises(UnsafeDocumentError, match="entity"):
        safe_xml_fromstring(XML_BOMB)
    utf16 = XML_BOMB.replace('version="1.0"', 'version="1.0" encoding="UTF-16"').encode("utf-16")
    with pytest.raises(UnsafeDocumentError, match="entity"):
        safe_xml_fromstring(utf16)


def test_ordinary_and_malformed_xml():
    root = safe_xml_fromstring(b'<?xml version="1.0"?><project><name>x</name></project>')
    assert root.find("name").text == "x"
    with pytest.raises(ET.ParseError):
        safe_xml_fromstring("<unclosed>")


@pytest.mark.parametrize(("analyzer_path", "filename", "content"), [
    ("project_discovery.analyzers.environment.configuration:ConfigurationAnalyzer", "settings.yaml", YAML_BOMB),
    ("project_discovery.analyzers.content.localization:LocalizationAnalyzer", "locales/en.yaml", YAML_BOMB),
    ("project_discovery.analyzers.domains.mobile:MobileIntelligenceAnalyzer", "AndroidManifest.xml", XML_BOMB),
    ("project_discovery.analyzers.domains.ros:ROSIntelligenceAnalyzer", "package.xml",
     XML_BOMB.replace("manifest", "package")),
])
def test_analyzers_report_document_bombs_as_unknown_quickly(tmp_path: Path, analyzer_path, filename, content):
    import importlib

    module_name, class_name = analyzer_path.split(":")
    analyzer = getattr(importlib.import_module(module_name), class_name)()
    path = tmp_path / Path(filename).name
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix.lower(), "Data", file_type="text")
    assert analyzer.supports(record)
    started = time.monotonic()
    findings = analyzer.analyze(path, record)
    assert time.monotonic() - started < 5
    assert findings and all(item.confidence == "UNKNOWN" for item in findings)


def test_describe_error_quotes_no_yaml_or_configparser_content():
    import configparser

    from project_discovery.core.source_utils import describe_error

    yaml = pytest.importorskip("yaml")
    with pytest.raises(yaml.YAMLError) as caught:
        yaml.load("password: FakeYamlSecret1\n  bad: [\n", Loader=yaml.SafeLoader)
    text = describe_error(caught.value)
    assert "FakeYamlSecret1" not in text and "line" in text
    with pytest.raises(configparser.Error) as caught:
        configparser.ConfigParser().read_string("db_pass: FakeHunter2Value\n")
    text = describe_error(caught.value)
    assert "FakeHunter2Value" not in text and text.startswith("MissingSectionHeaderError")
    with pytest.raises(ValueError) as caught:
        try:
            yaml.load("a: FakeYamlSecret2\n b: [\n", Loader=yaml.SafeLoader)
        except yaml.YAMLError as inner:
            raise ValueError(f"wrapped: {inner}") from inner
    assert "FakeYamlSecret2" not in describe_error(caught.value)


def test_analyzer_error_details_go_through_describe_error():
    # Every analyzer names a failure without quoting the file: a raw f"{exc}" detail
    # copied YAML snippets and configparser lines (passwords included) into reports.
    import project_discovery

    analyzers = Path(project_discovery.__file__).parent / "analyzers"
    offenders = [
        path.relative_to(analyzers).as_posix()
        for path in analyzers.rglob("*.py")
        if path.parent != analyzers and 'f"{type(exc).__name__}: {exc}"' in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_python_modules_beyond_the_syntax_tree_budget_are_not_parsed():
    # Regression: a 5.6 MB generated module took 1.2 GB of memory to parse.
    from project_discovery.core import source_utils

    source = "x = 1\n" * (source_utils.MAX_PYTHON_SYNTAX_TREE_LINES + 1)
    with pytest.raises(source_utils.PythonSourceTooLarge, match="syntax-tree budget"):
        source_utils.parse_python(source, "generated.py")
    with pytest.raises(MemoryError):  # memoized, and still a MemoryError for callers
        source_utils.parse_python(source, "generated.py")
    assert source_utils.parse_python("y = 2\n", "small.py").body
