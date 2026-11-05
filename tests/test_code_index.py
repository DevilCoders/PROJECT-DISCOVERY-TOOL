"""Cross-file code index: symbol index, call graph, dead code, test links, module graph, query CLI."""
import json
import sys
from pathlib import Path

import pytest

from project_discovery.cli import main, run_scan
from project_discovery.code_index import query_code_index


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _scan(tmp_path: Path, files: dict[str, str]) -> tuple[dict, Path]:
    project = _write(tmp_path / "project", files)
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    return json.loads((output / "discovery-report.json").read_text(encoding="utf-8")), output


PROJECT = {
    "pkg/__init__.py": "",
    "pkg/core.py": (
        "from .util import helper\n"
        "def walk(node):\n    return [walk(child) for child in node]\n"
        "def ping(n):\n    return pong(n - 1)\n"
        "def pong(n):\n    return ping(n)\n"
        "def run():\n    return helper()\n"
        "def _unused_helper():\n    return 1\n"
    ),
    "pkg/util.py": "def helper():\n    return 42\n",
    "tests/test_core.py": "from pkg.core import run\n\ndef test_run():\n    assert run()\n",
    "web/a.ts": "import { b } from './b';\nexport const a = () => b();\n",
    "web/b.ts": "import { a } from './a';\nexport function b() { return a; }\n",
    "native/lib.c": "#include <stdio.h>\n#include \"lib.h\"\nstatic int never_called(void) { return 0; }\nint api(void) { return 1; }\n",
    "native/lib.h": "int api(void);\n",
}


def test_scan_builds_call_graph_dead_code_and_module_graph(tmp_path: Path):
    report, _ = _scan(tmp_path, PROJECT)
    index = report["metrics"]["code_index"]
    assert index["symbols"]["symbol_count"] >= 9
    titles = {finding["title"] for finding in report["findings"] if finding["analyzer"] == "code-index"}
    assert {"Symbol index", "Call graph", "Module graph"} <= titles
    cycles = next(item for item in report["findings"] if item["title"] == "Recursive call cycles")
    evidence = " ".join(cycles["evidence"])
    assert "walk -> itself" in evidence and "ping" in evidence and "pong" in evidence
    unreferenced = next(item for item in report["findings"] if item["title"] == "Unreferenced private functions")
    assert any("_unused_helper" in item for item in unreferenced["evidence"])
    assert any("never_called" in item for item in unreferenced["evidence"])
    module_cycles = next(item for item in report["findings"] if item["title"] == "Module dependency cycles")
    assert any("web/a.ts" in item and "web/b.ts" in item for item in module_cycles["evidence"])
    assert index["test_links"]["referenced_from_tests"] >= 1


def test_query_finds_symbols_callers_callees_and_references(tmp_path: Path):
    _, output = _scan(tmp_path, PROJECT)
    inventory = output / ".pdt-cache" / "inventory.sqlite3"
    symbols = query_code_index(inventory, "symbol", "helper")
    assert [item["path"] for item in symbols] == ["pkg/util.py"]
    callers = query_code_index(inventory, "callers", "helper")
    assert any(item["path"] == "pkg/core.py" and item["caller"] == "run" for item in callers)
    callees = query_code_index(inventory, "callees", "run")
    assert any(item["callee"] == "helper" for item in callees)
    references = query_code_index(inventory, "references", "run")
    assert "tests/test_core.py" in {item["path"] for item in references}
    with pytest.raises(ValueError):
        query_code_index(inventory, "everything", "x")


def test_query_cli_prints_json(tmp_path: Path, monkeypatch, capsys):
    _, output = _scan(tmp_path, PROJECT)
    monkeypatch.setattr(sys, "argv", ["pdt", "query", str(output), "--callers", "ping", "--json"])
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 0
    rows = json.loads(capsys.readouterr().out)
    assert any(row["caller"] == "pong" for row in rows)


def test_inventory_only_scan_skips_the_code_index(tmp_path: Path):
    project = _write(tmp_path / "project", {"a.py": "def f():\n    return 1\n"})
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True, inventory_only=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    assert report["metrics"]["code_index"] == {"skipped": "inventory-only scan"}
