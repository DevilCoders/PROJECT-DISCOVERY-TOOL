from pathlib import Path
from project_discovery.analyzers.document_analyzer import DocumentAnalyzer
from project_discovery.models import FileRecord


def _analyze(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Document")
    analyzer = DocumentAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_html_extracts_title_headings_links_and_visible_text(tmp_path: Path):
    findings = _analyze(
        tmp_path, "guide.html",
        "<html><head><title>Architecture</title><script>secret()</script></head>"
        "<body><h1>System Design</h1><a href='/api'>API</a><p>Local service</p></body></html>",
    )
    assert len(findings) == 1
    assert findings[0].title == "Document: Architecture"
    assert "headings: 1" in findings[0].detail
    assert "links: 1" in findings[0].detail
    assert "secret" not in findings[0].detail


def test_rst_and_plain_text_documents(tmp_path: Path):
    rst = _analyze(tmp_path, "guide.rst", "Architecture\n============\n\nService modules.")
    assert "Document: Architecture" == rst[0].title
    assert "headings: 1" in rst[0].detail

    txt = _analyze(tmp_path, "notes.txt", "First line\nSecond line")
    assert "lines: 2" in txt[0].detail


def test_pdf_optional_dependency_is_reported_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.document_analyzer as module

    path = tmp_path / "scan.pdf"
    path.write_bytes(b"%PDF-placeholder")
    record = FileRecord("scan.pdf", path.stat().st_size, ".pdf", "PDF")
    monkeypatch.setattr(module.importlib, "import_module", lambda _: (_ for _ in ()).throw(ImportError()))
    findings = module.DocumentAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "pypdf" in findings[0].detail

def test_text_document_growth_after_inventory_returns_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.document_analyzer as module

    path = tmp_path / "large.txt"
    path.write_text("x" * 100, encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_TEXT_DOCUMENT_BYTES", 8)
    record = FileRecord(path.name, 1, ".txt", "Document")
    findings = DocumentAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_pdf_binary_input_growth_after_inventory_returns_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.document_analyzer as module

    path = tmp_path / "large.pdf"
    path.write_bytes(b"%PDF-" + b"x" * 100)
    monkeypatch.setattr(module, "_MAX_BINARY_DOCUMENT_BYTES", 8)
    record = FileRecord(path.name, 1, ".pdf", "PDF")
    findings = DocumentAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_docx_uncompressed_package_budget_returns_unknown(tmp_path: Path, monkeypatch):
    import zipfile
    import project_discovery.analyzers.document_analyzer as module

    path = tmp_path / "expanded.docx"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", b"x" * 1024)
    monkeypatch.setattr(module, "_MAX_DOCX_UNCOMPRESSED_BYTES", 64)
    record = FileRecord(path.name, path.stat().st_size, ".docx", "DOCX")
    findings = DocumentAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "uncompressed bytes" in findings[0].detail
