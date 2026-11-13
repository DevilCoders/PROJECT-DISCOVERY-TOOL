from pathlib import Path

from project_discovery.analyzers.content.localization import LocalizationAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, relative: str, content: str):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Localization")
    analyzer = LocalizationAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_gettext_catalog_counts_untranslated_entries_without_values(tmp_path: Path):
    private_translation = "private-translated-content"
    findings = _scan(
        tmp_path, "locale/fr/LC_MESSAGES/app.po",
        'msgid "Hello"\nmsgstr "Bonjour"\n\n'
        'msgid "Save"\nmsgstr ""\n',
    )
    assert "2 key(s)" in findings[0].detail
    assert "1 explicitly empty" in findings[0].detail
    assert len(findings) == 2
    assert private_translation not in str([item.to_dict() for item in findings])


def test_arb_and_nested_json_catalogs(tmp_path: Path):
    arb = _scan(
        tmp_path, "lib/l10n/app_en.arb",
        '{"@@locale":"en","title":"Welcome","empty":"","@title":{"description":"Title"}}',
    )
    json_catalog = _scan(
        tmp_path, "public/locales/de/common.json",
        '{"menu":{"home":"Start","settings":"Einstellungen"},"empty":""}',
    )
    assert "2 key(s)" in arb[0].detail
    assert "1 explicitly empty" in arb[0].detail
    assert "3 key(s)" in json_catalog[0].detail


def test_apple_strings_and_fluent_catalogs(tmp_path: Path):
    apple = _scan(
        tmp_path, "Resources/en.lproj/Localizable.strings",
        '"welcome" = "Welcome";\n"missing" = "";\n',
    )
    fluent = _scan(
        tmp_path, "locales/en/app.ftl",
        "welcome-message = Welcome\nsave-button = Save\n",
    )
    assert "2 key(s)" in apple[0].detail
    assert "1 explicitly empty" in apple[0].detail
    assert "2 key(s)" in fluent[0].detail


def test_android_xml_and_xliff_catalogs(tmp_path: Path):
    android = _scan(
        tmp_path, "app/src/main/res/values-fr/strings.xml",
        '<resources><string name="hello">Bonjour</string>'
        '<string name="missing"></string></resources>',
    )
    xliff = _scan(
        tmp_path, "i18n/fr/messages.xlf",
        '<xliff><file><body><trans-unit id="hello"><source>Hello</source>'
        '<target>Bonjour</target></trans-unit><trans-unit id="save">'
        '<source>Save</source></trans-unit></body></file></xliff>',
    )
    assert "2 key(s)" in android[0].detail
    assert "1 explicitly empty" in android[0].detail
    assert "2 key(s)" in xliff[0].detail
    assert "1 explicitly empty" in xliff[0].detail


def test_unrelated_json_is_not_misclassified(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text('{"name":"app"}', encoding="utf-8")
    record = FileRecord("package.json", path.stat().st_size, ".json", "JSON")
    assert not LocalizationAnalyzer().supports(record)


def test_malformed_catalog_is_unknown(tmp_path: Path):
    findings = _scan(tmp_path, "locales/en.json", "{broken")
    assert findings[0].confidence == "UNKNOWN"
    assert "parse error" in findings[0].title.lower()


def test_yaml_catalog_and_invalid_yaml_are_handled(tmp_path: Path):
    valid = _scan(
        tmp_path, "locales/es/common.yaml",
        "navigation:\n  home: Inicio\n  empty: ''\n",
    )
    invalid = _scan(tmp_path, "locales/it/broken.yaml", "items: [unterminated\n")
    assert "2 key(s)" in valid[0].detail
    assert "1 explicitly empty" in valid[0].detail
    assert invalid[0].confidence == "UNKNOWN"
    assert "parse error" in invalid[0].title.lower()


def test_resx_and_properties_catalogs_are_supported(tmp_path: Path):
    resx = _scan(
        tmp_path, "Resources/App.fr.resx",
        '<root><data name="Welcome"><value>Bonjour</value></data>'
        '<data name="Missing"><value></value></data></root>',
    )
    properties = _scan(
        tmp_path, "locales/fr/messages.properties",
        "welcome=Bonjour\nmissing=\n",
    )
    assert "2 key(s)" in resx[0].detail
    assert "1 explicitly empty" in resx[0].detail
    assert "2 key(s)" in properties[0].detail


def test_short_config_file_names_are_not_translation_catalogs():
    # Regression: any 2-3 letter stem (app.json, pom.xml, web.xml, ci.yml) was a catalog.
    analyzer = LocalizationAnalyzer()

    def supported(relative):
        return analyzer.supports(FileRecord(relative, 10, "." + relative.rsplit(".", 1)[1], "Data"))

    for relative in ("app.json", "pom.xml", "web.xml", ".github/ci.yml", "src/api.json", "db.yaml"):
        assert not supported(relative), relative
    for relative in ("en.json", "fr-FR.json", "zh_Hant.yml", "locales/app.json", "i18n/xyz.json"):
        assert supported(relative), relative
