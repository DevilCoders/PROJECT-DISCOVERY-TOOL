from pathlib import Path

from project_discovery.analyzers.content.accessibility import AccessibilityAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, path.suffix.lower(), "Markup")
    analyzer = AccessibilityAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_html_missing_names_labels_and_document_language(tmp_path: Path):
    findings = _scan(
        tmp_path, "index.html",
        '<html><body><img src="hero.png"><iframe src="embed"></iframe>'
        '<input id="email"><button></button><a href="/next"></a></body></html>',
    )
    titles = [item.title for item in findings]
    assert any("Document language" in title for title in titles)
    assert any("Image has no alt" in title for title in titles)
    assert any("Iframe has no accessible title" in title for title in titles)
    assert any("Form control has no static accessible label" in title for title in titles)
    assert any("Button has no static accessible name" in title for title in titles)
    assert any("Link has no static accessible name" in title for title in titles)
    assert all(item.confidence == "INFERRED" for item in findings)


def test_explicit_labels_and_decorative_images_are_not_flagged(tmp_path: Path):
    findings = _scan(
        tmp_path, "form.html",
        '<html lang="en"><body><label for="email">Email</label>'
        '<input id="email"><img src="ornament.svg" alt="">'
        '<button aria-label="Save"></button><a href="/home">Home</a></body></html>',
    )
    assert findings == []


def test_component_markup_is_supported_and_non_markup_is_skipped(tmp_path: Path):
    findings = _scan(
        tmp_path, "components/Panel.vue",
        '<template><img :src="image"><button></button></template>',
    )
    assert any("Image has no alt" in item.title for item in findings)
    record = FileRecord("src/app.ts", 20, ".ts", "TypeScript")
    assert not AccessibilityAnalyzer().supports(record)
