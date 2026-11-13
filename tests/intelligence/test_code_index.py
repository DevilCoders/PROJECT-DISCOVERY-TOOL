"""Cross-file code index: symbol index, call graph, dead code, test links, module graph, query CLI."""
import json
import sys
from pathlib import Path

import pytest

from project_discovery.cli import main, run_scan
from project_discovery.intelligence.index import query_code_index


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


def test_objective_c_m_files_reach_the_code_index(tmp_path: Path):
    _, output = _scan(tmp_path, {
        "Sources/Widget.m": "#import <Foundation/Foundation.h>\n\nint widget_scale(int value) {\n    return value * 2;\n}\n",
        "scripts/analysis.m": "function y = analysis(x)\n% MATLAB, not Objective-C\ny = 2 * x;\nend\n",
    })
    inventory = output / ".pdt-cache" / "inventory.sqlite3"
    assert [item["path"] for item in query_code_index(inventory, "symbol", "widget_scale")] == ["Sources/Widget.m"]
    assert query_code_index(inventory, "symbol", "analysis") == []


def test_qualified_callers_include_same_file_and_module_qualified_names(tmp_path: Path):
    # Regression: same-file calls are stored as "@Engine.run", and the condition meant for
    # them bound the same pattern as another, so `--callers Engine.run` missed them; the
    # module-qualified name the call graph prints found nothing at all.
    _, output = _scan(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/engine.py": (
            "class Engine:\n"
            "    def run(self):\n        return 1\n"
            "    def start(self):\n        return self.run()\n"
            "def boot(engine: Engine):\n    return engine.run()\n"
        ),
        "pkg/other.py": "class Other:\n    def run(self):\n        return 2\n    def go(self):\n        return self.run()\n",
    })
    inventory = output / ".pdt-cache" / "inventory.sqlite3"
    for name in ("Engine.run", "pkg.engine.Engine.run"):
        callers = {item["caller"] for item in query_code_index(inventory, "callers", name)}
        assert "Engine.start" in callers and "Other.go" not in callers, name
    assert [item["path"] for item in query_code_index(inventory, "symbol", "pkg.engine.Engine.run")] == ["pkg/engine.py"]
    assert query_code_index(inventory, "symbol", "pkg.other.Engine.run") == []


def test_go_standard_library_imports_never_match_local_directories(tmp_path: Path):
    # Regression: every directory suffix was registered and every import suffix tried, so
    # "log", "net/http" and "github.com/pkg/errors" resolved to local log/, http/ and
    # errors/ directories, inventing internal edges and a module cycle.
    report, _ = _scan(tmp_path, {
        "go.mod": "module example.com/shop\n\ngo 1.22\n",
        "main.go": 'package main\n\nimport (\n\t"log"\n\t"net/http"\n\t"example.com/shop/internal/http"\n)\n\nfunc main() {}\n',
        "internal/http/server.go": 'package http\n\nimport (\n\t"github.com/pkg/errors"\n\t"log"\n)\n\nfunc Serve() {}\n',
        "internal/log/log.go": 'package log\n\nimport "net/http"\n\nfunc Write() {}\n',
        "errors/errors.go": 'package errors\n\nimport "log"\n\nfunc New() {}\n',
    })
    graph = report["metrics"]["code_index"]["module_graph"]
    assert graph["resolved_imports"] == 1  # only example.com/shop/internal/http
    assert graph["cycles"] == 0
    assert [item["module"] for item in graph["most_imported"]] == ["internal/http/"]


def test_delegation_through_another_receiver_is_not_recursion(tmp_path: Path):
    # Regression: a lexical call resolved to any same-named function in its file, so
    # size() { return items.size(); } and PathBuf::new() were listed as recursive.
    report, _ = _scan(tmp_path, {
        "src/Box.java": (
            "class Box {\n"
            "    private java.util.List<String> items;\n"
            "    int size() {\n        return items.size();\n    }\n"
            "    int depth(int n) {\n        return n <= 0 ? 0 : 1 + depth(n - 1);\n    }\n"
            "}\n"
        ),
        "src/lib.rs": (
            "struct Wrapper;\n"
            "impl Wrapper {\n"
            "    fn new() -> std::path::PathBuf {\n        PathBuf::new()\n    }\n"
            "}\n"
        ),
    })
    cycles = next((item for item in report["findings"] if item["title"] == "Recursive call cycles"), None)
    evidence = " ".join(cycles["evidence"]) if cycles else ""
    assert "Box.depth" in evidence
    assert "Box.size" not in evidence and "Wrapper.new" not in evidence


def test_a_reference_cap_is_reported_and_called_functions_are_not_dead_code(tmp_path: Path):
    # Regression: the lexer stopped at exactly 10,000 references without marking the cut,
    # so no "Code index truncated" finding appeared, and a function called after the cut
    # was listed as an unreferenced dead-code candidate.
    names = "\n".join(f"int value_{index} = {index};" for index in range(10_050))
    source = names + "\nstatic int helper(void) {\n    return 1;\n}\nint main(void) {\n    return helper();\n}\n"
    report, _ = _scan(tmp_path, {"gen.c": source})
    titles = {item["title"] for item in report["findings"]}
    assert "Code index truncated" in titles
    unreferenced = next((item for item in report["findings"] if item["title"] == "Unreferenced private functions"), None)
    assert unreferenced is None or not any("helper" in item for item in unreferenced["evidence"])
    assert report["metrics"]["code_index"]["truncated"]["kinds"] == {"references": 1}


def test_calls_through_a_namespace_package_resolve(tmp_path: Path):
    # Regression: modules are named by their package chain ("pkg.mod" for
    # src/ns/pkg/mod.py), so a call through the namespace name "ns.pkg.mod.run" never
    # resolved to its definition.
    report, _ = _scan(tmp_path, {
        "src/ns/pkg/__init__.py": "",
        "src/ns/pkg/mod.py": "def run():\n    return 1\n",
        "app.py": "import ns.pkg.mod\n\ndef main():\n    return ns.pkg.mod.run()\n",
    })
    graph = report["metrics"]["code_index"]["call_graph"]
    assert graph["python"]["resolved"] == 1
    assert {"calls": 1, "target": "pkg.mod.run"} in graph["top_fan_in"]


def test_class_constructors_rust_use_paths_and_php_imports(tmp_path: Path):
    # Regressions: a Java class with an explicit constructor was two symbols named Foo, so
    # new Foo() from another file was "ambiguous"; Rust ``use crate::...`` never resolved;
    # PHP ``use function`` and trait ``use`` were external packages "function"/"HasFactory".
    report, _ = _scan(tmp_path, {
        "java/Foo.java": "class Foo {\n    Foo(int size) {\n        init();\n    }\n    void init() {}\n}\n",
        "java/Main.java": "class Main {\n    void run() {\n        Foo foo = new Foo(1);\n    }\n}\n",
        "src/lib.rs": "mod net;\nmod util;\n",
        "src/util.rs": "pub fn helper() {}\n",
        "src/net.rs": "use crate::util::helper;\npub fn send() { helper(); }\n",
        "app/User.php": "<?php\nuse function App\\Support\\format_name;\nclass User {\n    use HasFactory, Notifiable;\n}\n",
    })
    index = report["metrics"]["code_index"]
    assert index["call_graph"]["lexical"].get("ambiguous", 0) == 0
    graph = index["module_graph"]
    packages = {item["package"] for item in graph["external_packages"]}
    assert not packages & {"function", "HasFactory", "Notifiable"}
    assert "src/util.rs" in {item["module"] for item in graph["most_imported"]}


def test_calls_on_a_call_result_are_not_recursion(tmp_path: Path):
    # Regression: getItems().size(), Runtime.getRuntime().exec() and this.getEngine().stop()
    # had the receiver "<expression>", which resolved like a receiverless call to the
    # caller itself: "Wrapper.size -> itself".
    report, _ = _scan(tmp_path, {
        "src/Wrapper.java": (
            "class Wrapper {\n"
            "    java.util.List<String> getItems() { return null; }\n"
            "    int size() { return getItems().size(); }\n"
            "    Process exec(String c) throws Exception { return Runtime.getRuntime().exec(c); }\n"
            "    String build() { return new StringBuilder().build(); }\n"
            "    int depth(int n) { return n <= 0 ? 0 : depth(n - 1); }\n"
            "}\n"
        ),
        "src/engine.ts": (
            "class Facade {\n"
            "    getEngine(): any { return null; }\n"
            "    stop(): void { this.getEngine().stop(); }\n"
            "}\n"
        ),
        "src/Service.cs": (
            "class Service {\n"
            "    Client GetClient() { return null; }\n"
            "    void Send() { GetClient().Send(); }\n"
            "}\n"
        ),
        "src/Box.kt": (
            "class Box {\n"
            "    fun items(): List<Int> = listOf()\n"
            "    fun count(): Int { return items().count() }\n"
            "}\n"
        ),
        "src/lib.rs": (
            "struct Pool;\n"
            "impl Pool {\n"
            "    fn items(&self) -> Vec<u8> { Vec::new() }\n"
            "    fn len(&self) -> usize { self.items().len() }\n"
            "}\n"
        ),
    })
    cycles = next((item for item in report["findings"] if item["title"] == "Recursive call cycles"), None)
    evidence = " ".join(cycles["evidence"]) if cycles else ""
    assert "Wrapper.depth" in evidence
    for name in ("Wrapper.size", "Wrapper.exec", "Wrapper.build", "Facade.stop", "Service.Send", "Box.count", "Pool.len"):
        assert name not in evidence, name


def test_calls_on_returned_values_and_inherited_methods_resolve_across_modules(tmp_path: Path):
    # The defining file is what knows the class a factory returns and the methods a class
    # inherits: make_store().run() and self.save() (defined in a base class of another
    # module) were unresolved.
    report, _ = _scan(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/base.py": "class Base:\n    def save(self):\n        return 1\n",
        "pkg/store.py": (
            "from .base import Base\n"
            "class Store(Base):\n"
            "    def run(self):\n        return self.save()\n"
            "    def configure(self):\n        return self\n"
            "def make_store():\n    return Store()\n"
        ),
        "pkg/app.py": (
            "from .store import make_store\n"
            "def main():\n"
            "    make_store().run()\n"
            "    return make_store().configure().save()\n"
        ),
    })
    fan_in = {item["target"]: item["calls"] for item in report["metrics"]["code_index"]["call_graph"]["top_fan_in"]}
    assert fan_in["pkg.store.Store.run"] == 1
    assert fan_in["pkg.base.Base.save"] == 2  # self.save() in Store.run, and through configure()
    assert fan_in["pkg.store.make_store"] == 2
