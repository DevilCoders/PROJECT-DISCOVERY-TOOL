from pathlib import Path
from project_discovery.scanner import discover_files

def test_discovers_files_and_prunes_generated_dirs(tmp_path: Path):
    (tmp_path/"main.py").write_text("print('hello')",encoding="utf-8")
    (tmp_path/"node_modules").mkdir()
    (tmp_path/"node_modules"/"hidden.js").write_text("x",encoding="utf-8")
    records,stats = discover_files(tmp_path,max_file_bytes=1024)
    assert [r.path for r in records] == ["main.py"]
    assert stats["total_bytes"] > 0

def test_oversized_file_is_inventoried_but_marked(tmp_path: Path):
    (tmp_path/"large.bin").write_bytes(b"x"*20)
    records,_ = discover_files(tmp_path,max_file_bytes=10)
    assert len(records) == 1
    assert records[0].error is not None
