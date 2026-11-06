"""Shared code model: Python syntax-tree backend and the structural lexer."""
import time
from pathlib import Path

from project_discovery.catalog.languages import detect_language
from project_discovery.intelligence.model import model_for, supports_language
from project_discovery.intelligence.model.lexical import build_lexical_model, clean_source
from project_discovery.intelligence.model.python_model import build_python_model
from project_discovery.models import FileRecord


def _symbols(model):
    return {(symbol.kind, symbol.qualified) for symbol in model.symbols}


def test_python_model_resolves_calls_through_imports_and_self():
    model = build_python_model("pkg/service.py", (
        "import os.path\nfrom .db import query as q\nfrom . import util\n"
        "class Service:\n    def __init__(self):\n        self.ready = True\n"
        "    def run(self):\n        self.helper()\n        q('x')\n        util.go()\n        os.path.join('a')\n"
        "    def helper(self):\n        return local()\n"
        "def local():\n    return len([])\n"
    ))
    assert {("class", "Service"), ("constructor", "Service.__init__"), ("method", "Service.run"),
            ("function", "local")} <= _symbols(model)
    targets = {(call.caller, call.callee): call.target for call in model.calls}
    assert targets[("Service.run", "helper")] == "@Service.helper"
    assert targets[("Service.run", "q")] == ".db.query"
    assert targets[("Service.run", "go")] == ".util.go"
    assert targets[("Service.run", "join")] == "os.path.join"
    assert targets[("Service.helper", "local")] == "@local"
    assert targets[("local", "len")] == "builtins.len"


def test_clean_source_blanks_comments_and_strings_but_keeps_offsets():
    text = 'int f() { /* } */ char *s = "}{"; // }\n return 1; }\n'
    clean, strings = clean_source(text, "c")
    assert len(clean) == len(text)
    assert clean.count("{") == 1 and clean.count("}") == 1
    assert [text[start:end] for start, end in strings] == ['"}{"']


def test_lexical_model_finds_definitions_across_families():
    cpp = build_lexical_model("a.cpp", "C++", "namespace n {\nclass Box {\n public:\n  Box() {}\n  int size() const { return 1; }\n};\n}\n"
                                               "int Box::area() { return size(); }\n")
    assert {("namespace", "n"), ("class", "n.Box"), ("constructor", "n.Box.Box"), ("method", "n.Box.size"),
            ("method", "Box.area")} <= _symbols(cpp)
    go = build_lexical_model("a.go", "Go", "package a\ntype Store struct{}\nfunc (s *Store) Get(k string) string { return k }\n"
                                         "func New() *Store { return &Store{} }\n")
    assert {("struct", "Store"), ("function", "New")} <= _symbols(go)
    assert any(symbol.name == "Get" for symbol in go.symbols)
    rust = build_lexical_model("a.rs", "Rust", "pub struct P;\nimpl P {\n    pub fn new() -> Self { P }\n}\nfn main() { P::new(); }\n")
    assert ("function", "main") in _symbols(rust)
    assert any(symbol.name == "new" for symbol in rust.symbols)


def test_javascript_expression_is_not_mistaken_for_an_arrow_function():
    model = build_lexical_model("a.ts", "TypeScript", (
        "export function f(a: any) {\n  const x = (a as any).y;\n  const g = (p: number): Promise<void> => go(p);\n"
        "  const h = async (q) => { return q };\n  const n = (1 + 2) * 3;\n  return x;\n}\n"
    ))
    names = {symbol.qualified for symbol in model.symbols}
    assert {"f", "f.g", "f.h"} <= names
    assert "f.x" not in names and "f.n" not in names


def test_lexer_stays_linear_on_hostile_input():
    hostile = {
        "c": "'\\'" * 40_000 + "/*" * 20_000 + '"' * 20_000,
        "js": "`${" * 30_000 + "/'" * 30_000,
        "cpp": 'R"x(' * 30_000 + "{" * 30_000,
        "go": "func (" * 20_000 + "`" * 10_001,
    }
    languages = {"c": "C", "js": "JavaScript", "cpp": "C++", "go": "Go"}
    for family, text in hostile.items():
        started = time.perf_counter()
        build_lexical_model(f"x.{family}", languages[family], text)
        assert time.perf_counter() - started < 5, family


def test_model_for_is_memoized_per_file_identity(tmp_path: Path):
    path = tmp_path / "m.py"
    path.write_text("def a():\n    return 1\n", encoding="utf-8")
    record = FileRecord("m.py", path.stat().st_size, ".py", "Python", mtime_ns=path.stat().st_mtime_ns)
    first = model_for(path, record)
    assert first is model_for(path, record)
    path.write_text("def b():\n    return 2\n", encoding="utf-8")
    changed = FileRecord("m.py", path.stat().st_size, ".py", "Python", mtime_ns=path.stat().st_mtime_ns + 1)
    assert {symbol.name for symbol in model_for(path, changed).symbols} == {"b"}


def test_supported_languages_include_shaders_and_arduino():
    for name in ("shader.comp", "kernel.cu", "sketch.ino", "app.vue", "Main.kt", "lib.rs"):
        assert supports_language(detect_language(name)), name
    assert not supports_language(detect_language("notes.md"))
