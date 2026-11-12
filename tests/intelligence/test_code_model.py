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


def test_javascript_regular_expressions_do_not_hide_the_code_after_them():
    # Regression: a regex literal holding "//" was read as a line comment, which blanked
    # the rest of the line (the rest of the file in a minified bundle), losing its code.
    source = 'var strip=p=>p.replace(/\\//g,"").replace(/[/*]/,"");function after(){return run()}\n'
    model = build_lexical_model("a.js", "JavaScript", source)
    assert "after" in {symbol.name for symbol in model.symbols}
    assert ("after", "run") in {(call.caller, call.callee) for call in model.calls}
    assert clean_source("a=/\\//g;b()", "js")[0] == "a=/  / ;b()"
    # Divisions stay code, and JSX closing tags are not regular expressions.
    assert clean_source("x = a / b / c; y()", "js")[0] == "x = a / b / c; y()"
    assert clean_source("t = <p>a</p>; f()", "js")[0] == "t = <p>a</p>; f()"


def test_keyword_prefixed_identifiers_are_not_definitions():
    # Regression: `function_exists`, `funcs` and similar names matched a keyword followed
    # by a name with nothing between them, inventing definitions that swallowed calls.
    php = build_lexical_model("a.php", "PHP", (
        "<?php\nif (function_exists('x')) { definitions(); }\nfunction real() { return 1; }\n"
    ))
    assert {symbol.name for symbol in php.symbols} == {"real"}
    go = build_lexical_model("a.go", "Go", "package a\nfunc main() {\n  funcs := 1\n  funds(funcs)\n}\n")
    assert {symbol.name for symbol in go.symbols} == {"main"}
    assert ("main", "funds") in {(call.caller, call.callee) for call in go.calls}


def test_calls_in_conditions_are_not_c_style_definitions():
    # Regression: in `if (ready() && work(x)) {` the call before `) {` was taken for a
    # typed definition, which removed the call, or (C#) nested a phantom method.
    model = build_lexical_model("a.c", "C", (
        "int main(void) {\n  if (ready() && work(x)) {\n    run();\n  }\n  return 0;\n}\n"
    ))
    assert {symbol.name for symbol in model.symbols} == {"main"}
    assert {("main", "ready"), ("main", "work"), ("main", "run")} <= {
        (call.caller, call.callee) for call in model.calls
    }
    csharp = build_lexical_model("A.cs", "C#", (
        "class A {\n  void M() {\n    if (Ok() && Go(1)) {\n      Run();\n    }\n  }\n}\n"
    ))
    assert {symbol.qualified for symbol in csharp.symbols} == {"A", "A.M"}
    assert ("A.M", "Run") in {(call.caller, call.callee) for call in csharp.calls}
    # Member-initializer lists keep balanced parentheses, so constructors still count.
    cpp = build_lexical_model("a.cpp", "C++", "class Box {\n public:\n  Box(int w) : w_(w) {}\n  int w_;\n};\n")
    assert ("constructor", "Box.Box") in {(symbol.kind, symbol.qualified) for symbol in cpp.symbols}


def test_lexer_stays_linear_on_hostile_input():
    hostile = {
        "c": "'\\'" * 40_000 + "/*" * 20_000 + '"' * 20_000,
        "js": "`${" * 30_000 + "/'" * 30_000,
        "cpp": 'R"x(' * 30_000 + "{" * 30_000,
        "go": "func (" * 20_000 + "`" * 10_001,
        "js-regex": "=/[" * 100_000 + "a/" * 100_000 + "return /x" * 30_000,
    }
    languages = {"c": "C", "js": "JavaScript", "cpp": "C++", "go": "Go", "js-regex": "JavaScript"}
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


def test_python_calls_on_objects_resolve_to_the_class_the_code_states():
    import textwrap

    source = textwrap.dedent('''
        from typing import Optional
        from .db import Store

        class Repo:
            def find(self, name): ...
            def clone(self) -> "Repo": ...

        class Service:
            store: Store

            def __init__(self, repo: Repo, cache: Optional[Repo] = None):
                self.repo = repo
                self.cache = cache or Repo()
                self.flaky = Repo()
                self.flaky = Store()

            def run(self):
                self.repo.find(1)
                self.cache.find(2)
                self.store.save(3)
                self.flaky.find(4)

        SHARED = Repo()

        def main(other):
            repo = Repo()
            repo.find(5)
            SHARED.find(6)
            Repo().clone().find(7)
            with Repo() as managed:
                managed.find(8)
            other.find(9)
            changing = Repo()
            changing = make()
            changing.find(10)

        def shadow(SHARED):
            SHARED.find(11)
    ''')
    model = build_python_model("app.py", source)
    targets = {(call.caller, call.line, call.callee): call.target for call in model.calls
               if call.callee in {"find", "save", "clone"}}
    resolved = {(caller, callee): target for (caller, _line, callee), target in targets.items() if target}
    assert resolved == {
        ("Service.run", "find"): "@Repo.find",
        ("Service.run", "save"): ".db.Store.save",
        ("main", "find"): "@Repo.find",
        ("main", "clone"): "@Repo.clone",
    }
    by_line = {line: target for (_caller, line, callee), target in targets.items() if callee == "find"}
    # Typed: self.repo, self.cache (``cache or Repo()``), a local, a module instance, a call
    # result and a context manager. Untyped: self.flaky (two classes), an unannotated
    # parameter, a name reassigned from an unknown call, and a parameter shadowing SHARED.
    assert sorted(line for line, target in by_line.items() if target) == [19, 20, 28, 29, 30, 32]
    assert sorted(line for line, target in by_line.items() if not target) == [22, 33, 36, 39]


def test_m_files_are_modelled_as_objective_c_only_when_their_content_is(tmp_path):
    # Regression: ".m" is always "Objective-C / MATLAB (ambiguous)" in the inventory, and only
    # the exact name "Objective-C" had a model, so no Objective-C file was ever modelled while
    # the language catalog listed Objective-C under the structural lexer.
    from project_discovery.intelligence.model import AMBIGUOUS_M, model_for
    from project_discovery.models import FileRecord

    objc = tmp_path / "Widget.m"
    objc.write_text(
        "// Widget\n#import <Foundation/Foundation.h>\n\n"
        "static int clamp(int value) {\n    return value < 0 ? 0 : value;\n}\n\n"
        "@implementation Widget\n@end\n",
        encoding="utf-8",
    )
    matlab = tmp_path / "analysis.m"
    matlab.write_text("function y = analysis(x)\n% Scale the input.\ny = 2 * x;\nend\n", encoding="utf-8")
    for path, expected in ((objc, "Objective-C"), (matlab, None)):
        record = FileRecord(path.name, path.stat().st_size, ".m", AMBIGUOUS_M, mtime_ns=path.stat().st_mtime_ns)
        model = model_for(path, record)
        assert (model.language if model else None) == expected, path.name
    model = model_for(objc, FileRecord("Widget.m", objc.stat().st_size, ".m", AMBIGUOUS_M, mtime_ns=1))
    assert "clamp" in {symbol.name for symbol in model.symbols}


def test_interval_containment_is_exact_and_logarithmic():
    import time

    from project_discovery.analyzers.code.findings import Intervals

    intervals = Intervals([(0, 10), (2, 5), (10, 20), (30, 40), (35, 50)])
    expected = {0: False, 1: True, 3: True, 10: False, 11: True, 20: False, 25: False, 36: True, 45: True, 50: False}
    assert {offset: intervals.contains(offset) for offset in expected} == expected
    # Regression: each query walked back through every earlier sibling interval, O(loops)
    # per call, so 20,000 calls after 20,000 sibling loops took minutes.
    siblings = Intervals([(index * 10, index * 10 + 5) for index in range(20_000)])
    started = time.perf_counter()
    assert not any(siblings.contains(index * 10 + 7) for index in range(20_000))
    assert time.perf_counter() - started < 2.0


def test_loop_analyzers_stay_fast_on_large_generated_sources(tmp_path):
    # 30,000 sibling loops in about 3 MB: the old per-call walk over earlier loops needed
    # about half a minute here; containment by binary search keeps it to seconds.
    import time

    from project_discovery.analyzers.code.performance import PerformanceHotspotAnalyzer
    from project_discovery.models import FileRecord

    path = tmp_path / "generated.js"
    path.write_text("".join(
        f"function f{index}(items) {{\n  for (const item of items) {{ total += item; }}\n  emit{index}(items);\n}}\n"
        for index in range(30_000)
    ), encoding="utf-8")
    info = path.stat()
    record = FileRecord("generated.js", info.st_size, ".js", "JavaScript", mtime_ns=info.st_mtime_ns)
    started = time.perf_counter()
    PerformanceHotspotAnalyzer().analyze(path, record)
    assert time.perf_counter() - started < 20.0


def _symbols(model):
    return {(symbol.kind, symbol.qualified) for symbol in model.symbols}


def _callers(model):
    return {(call.caller, call.callee) for call in model.calls}


def test_bodies_after_multi_line_headers():
    # Regression: the same-line brace rule dropped the body of a Kotlin class whose primary
    # constructor spans lines (ktlint's layout) and of a Rust function with a where clause
    # (rustfmt's layout), so methods became top-level and calls went to <module>.
    from project_discovery.intelligence.model.lexical import build_lexical_model

    kotlin = build_lexical_model("a.kt", "Kotlin", (
        "class OrderService(\n    private val repo: Repo,\n) {\n"
        "    fun place(order: Order) {\n        repo.save(order)\n    }\n}\n"
    ))
    assert ("method", "OrderService.place") in _symbols(kotlin)
    rust = build_lexical_model("a.rs", "Rust", (
        "fn largest<T>(list: &[T]) -> &T\nwhere\n    T: PartialOrd,\n{\n    pick(list)\n}\n"
    ))
    assert next(symbol for symbol in rust.symbols if symbol.name == "largest").body is not None
    assert ("largest", "pick") in _callers(rust)


def test_definitions_that_were_missed_or_invented():
    from project_discovery.intelligence.model.lexical import build_lexical_model

    go = build_lexical_model("a.go", "Go", (
        "package a\n\ntype (\n\tUser struct {\n\t\tName string\n\t}\n\tRepo interface {\n\t\tFind() User\n\t}\n)\n\n"
        "func main() {\n\tsort.Slice(xs, func(i, j int) bool {\n\t\treturn less(xs, i, j)\n\t})\n"
        "\tdefer func() error {\n\t\treturn nil\n\t}()\n}\n"
    ))
    assert {("struct", "User"), ("interface", "Repo")} <= _symbols(go)
    assert not {symbol.name for symbol in go.symbols} & {"bool", "error", "type"}
    assert "type" not in {call.callee for call in go.calls}
    assert ("main", "less") in _callers(go)  # the closure's call belongs to main

    swift = build_lexical_model("p.swift", "Swift", (
        "struct Point {\n    var x: Int\n    init(x: Int) {\n        self.x = clamp(x)\n    }\n"
        "    deinit {\n        release()\n    }\n}\n"
    ))
    assert ("constructor", "Point.init") in _symbols(swift)
    assert {("Point.init", "clamp"), ("Point.deinit", "release")} <= _callers(swift)

    cpp = build_lexical_model("w.cpp", "C++", (
        "Widget::Widget(int size) : size_(size), name_{\"w\"} {\n    init();\n}\n"
        "Widget::~Widget() {\n    release();\n}\n"
    ))
    symbols = _symbols(cpp)
    assert ("constructor", "Widget.Widget") in symbols
    assert any(qualified == "Widget.~Widget" for _, qualified in symbols)
    assert ("function", "Widget") not in symbols
    assert {("Widget.Widget", "init"), ("Widget.~Widget", "release")} <= _callers(cpp)

    csharp = build_lexical_model("s.cs", "C#", (
        "class Service {\n    bool IsValid(int x) => Check(x) && x > 0;\n    void Run() { IsValid(1); }\n}\n"
    ))
    assert ("method", "Service.IsValid") in _symbols(csharp)
    assert ("Service.IsValid", "Check") in _callers(csharp)
    assert ("<module>", "IsValid") not in _callers(csharp)
