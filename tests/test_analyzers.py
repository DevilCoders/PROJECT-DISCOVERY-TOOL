from pathlib import Path
from project_discovery.models import FileRecord
from project_discovery.analyzers.python_analyzer import PythonAnalyzer
from project_discovery.analyzers.docs_analyzer import MarkdownAnalyzer

def test_python_analyzer_extracts_symbols_without_execution(tmp_path: Path):
    source = tmp_path/"sample.py"
    source.write_text("import os\nclass Widget:\n    def run(self): pass\ndef helper(): pass\n",encoding="utf-8")
    rec = FileRecord("sample.py",source.stat().st_size,".py","Python")
    findings = PythonAnalyzer().analyze(source,rec)
    titles = [f.title for f in findings]
    assert "Class: Widget" in titles
    assert "Function: helper" in titles
    assert "Python import: os" in titles

def test_markdown_analyzer_counts_headings(tmp_path: Path):
    source = tmp_path/"README.md"
    source.write_text("# Intro\n\n## Setup\n[docs](guide.md)\n",encoding="utf-8")
    rec = FileRecord("README.md",source.stat().st_size,".md","Markdown")
    finding = MarkdownAnalyzer().analyze(source,rec)[0]
    assert "2 headings" in finding.detail
    assert "1 links" in finding.detail

def test_python_analyzer_honors_pep263_source_encoding_cookie(tmp_path: Path):
    source = tmp_path / "latin_source.py"
    source.write_bytes(b"# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n")
    record = FileRecord("latin_source.py", source.stat().st_size, ".py", "Python")
    findings = PythonAnalyzer().analyze(source, record)
    assert any(item.title == "Python module: latin_source.py" for item in findings)
    assert not any("parse error" in item.title.lower() for item in findings)

def test_python_analyzer_detects_growth_after_inventory(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import python_analyzer

    source = tmp_path / "growing.py"
    source.write_text("import os\\n", encoding="utf-8")
    monkeypatch.setattr(python_analyzer, "MAX_AST_FILE_BYTES", 8)
    record = FileRecord("growing.py", 1, ".py", "Python")
    findings = PythonAnalyzer().analyze(source, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail
