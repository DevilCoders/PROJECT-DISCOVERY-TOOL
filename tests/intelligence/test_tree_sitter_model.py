"""Tree-sitter refinement of the lexical code model.

Tests that parse need real grammars, which CI's optional-integrations job provisions; they
skip elsewhere. The no-download guarantee is tested everywhere.
"""
import time
from pathlib import Path

import pytest

from project_discovery.intelligence.model import tree_sitter_model as tsm
from project_discovery.intelligence.model.lexical import build_lexical_model
from project_discovery.models import FileRecord

_GRAMMARS = ("c", "cpp", "csharp", "go", "java", "javascript", "kotlin", "php", "rust",
             "scala", "solidity", "swift", "typescript", "tsx")


def _provisioned() -> bool:
    try:
        import tree_sitter_language_pack as pack
    except ImportError:
        return False
    return set(_GRAMMARS) <= set(pack.downloaded_languages())


needs_grammars = pytest.mark.skipif(not _provisioned(), reason="Tree-sitter grammars are not provisioned")


def _refine(language: str, path: str, text: str):
    return tsm.refine(build_lexical_model(path, language, text), tsm.model_grammar(language, path))


def _symbols(model) -> set[tuple[str, str]]:
    return {(symbol.kind, symbol.qualified) for symbol in model.symbols}


def _calls(model) -> set[tuple[str, str]]:
    return {(call.caller, call.callee) for call in model.calls}


def test_unprovisioned_grammars_are_never_parsed_or_downloaded(monkeypatch):
    # tree-sitter-language-pack 1.23+ downloads a missing grammar inside get_parser() and
    # get_language(), so nothing of the pack but downloaded_languages() may be called.
    import sys
    import types

    calls = []
    fake = types.ModuleType("tree_sitter_language_pack")
    fake.downloaded_languages = lambda: []
    fake.get_parser = lambda name: calls.append(("parser", name))
    fake.get_language = lambda name: calls.append(("language", name))
    fake.get_tags_query = lambda name: calls.append(("tags", name))
    monkeypatch.setitem(sys.modules, "tree_sitter_language_pack", fake)
    monkeypatch.setattr(tsm, "_downloaded", None)
    model = build_lexical_model("a.js", "JavaScript", "function f() { g(); }\n")
    assert tsm.refine(model, "javascript") is model
    assert not tsm.available("javascript")
    assert calls == []


def test_the_lexical_model_can_be_forced(monkeypatch):
    monkeypatch.setenv("PDT_CODE_MODEL", "lexical")
    assert tsm.model_grammar("JavaScript", "a.js") is None
    monkeypatch.delenv("PDT_CODE_MODEL")
    assert tsm.model_grammar("TypeScript", "App.tsx") == "tsx"
    assert tsm.model_grammar("Python", "a.py") is None


@needs_grammars
def test_containers_and_definitions_the_lexer_misses():
    csharp = _refine("C#", "A.cs", (
        "namespace App.Core {\n  public interface IRepo { string Find(string key); }\n"
        "  public class Service {\n    public Service(IRepo repo) { }\n"
        "    private int Compute() => 3;\n    public void Run() { Compute(); }\n  }\n}\n"
    ))
    assert csharp.backend == "tree-sitter"
    assert {("namespace", "App.Core"), ("method", "App.Core.IRepo.Find"),
            ("constructor", "App.Core.Service.Service"), ("method", "App.Core.Service.Compute")} <= _symbols(csharp)
    assert ("App.Core.Service.Run", "Compute") in _calls(csharp)
    swift = _refine("Swift", "A.swift", (
        "class Service {\n  init(r: Int) { }\n}\n"
        "extension Service {\n  func describe() -> String { return String(describing: self) }\n}\n"
    ))
    assert {("constructor", "Service.init"), ("method", "Service.describe")} <= _symbols(swift)
    solidity = _refine("Solidity", "A.sol", (
        "library SafeMath { function add(uint a, uint b) internal pure returns (uint) { return a + b; } }\n"
        "interface IToken { function transfer(address to, uint amount) external returns (bool); }\n"
        "contract Vault { constructor() { } function f() external { SafeMath.add(1, 2); } }\n"
    ))
    assert {("method", "SafeMath.add"), ("method", "IToken.transfer"),
            ("constructor", "Vault.constructor")} <= _symbols(solidity)
    kotlin = _refine("Kotlin", "A.kt", (
        "class Service {\n  fun run(items: List<Int>) = items.map { it * 2 }\n"
        "  fun start() { scope.launch { run(listOf(1)) } }\n}\n"
    ))
    assert {("Service.run", "map"), ("Service.start", "launch")} <= _calls(kotlin)


@needs_grammars
def test_prototypes_declarations_and_initializers_are_not_calls_or_definitions():
    c = _refine("C", "a.c", (
        "static int helper(int value);\nint helper(int value) { return value; }\n"
        "int main(void) { struct point p = {1, 2}; return helper(p.x); }\n"
    ))
    assert _symbols(c) == {("function", "helper"), ("function", "main")}
    assert ("<module>", "helper") not in _calls(c)
    cpp = _refine("C++", "a.cpp", "class Box {\n public:\n  Box() : w_(0) {}\n private:\n  int w_;\n};\n")
    assert ("Box.Box", "w_") not in _calls(cpp) and ("<module>", "w_") not in _calls(cpp)


@needs_grammars
def test_javascript_object_and_export_definitions():
    model = _refine("JavaScript", "a.js", (
        "const api = { list() { return []; }, create: function (item) { return save(item); } };\n"
        "exports.other = (b) => b * 2;\n"
        "class Store {\n  #secret() { return this.db.key(); }\n}\n"
    ))
    names = _symbols(model)
    assert {("function", "list"), ("function", "create"), ("function", "other"),
            ("method", "Store.#secret")} <= names
    assert ("create", "save") in _calls(model)
    assert all(symbol.exported for symbol in model.symbols if symbol.name in {"list", "create", "other"})


@needs_grammars
def test_lines_and_bodies_are_right_after_multibyte_text():
    text = "// été € \U0001f600\nfunction échelle() {\n  run();\n}\nfunction after() { stop(); }\n"
    model = _refine("JavaScript", "a.js", text)
    assert model.backend == "tree-sitter"
    by_name = {symbol.name: symbol for symbol in model.symbols}
    assert (by_name["after"].line, by_name["after"].end_line) == (5, 5)
    start, end = by_name["after"].body
    assert text[start] == "{" and text[end] == "}"
    assert {("échelle", "run"), ("after", "stop")} <= _calls(model)


@needs_grammars
def test_regions_the_tree_does_not_structure_keep_the_lexers_results():
    rust = _refine("Rust", "a.rs", (
        "macro_rules! make { () => { fn generated() { inner(); } } }\n"
        "fn main() { make!(); real(); }\n"
    ))
    assert ("function", "main") in _symbols(rust)
    assert ("main", "real") in _calls(rust)
    assert ("<module>", "make") not in _calls(rust)


@needs_grammars
def test_hostile_or_broken_input_keeps_the_lexical_model_quickly():
    # Tree-sitter's query cursor is quadratic below depth 32,767: 300 KB of nested calls
    # took minutes before the depth guard.
    for language, path, text in (
        ("JavaScript", "deep.js", "f(" * 100_000 + ")" * 100_000),
        ("C", "deep.c", "int f() {" + "{" * 100_000 + "}" * 100_000 + "}"),
        ("Go", "broken.go", "func (" * 20_000 + "`" * 10_001),
    ):
        started = time.perf_counter()
        model = _refine(language, path, text)
        assert time.perf_counter() - started < 10, path
        assert model.backend == "lexical", path


@needs_grammars
def test_model_for_uses_the_grammar_and_reports_the_backend(tmp_path: Path):
    from project_discovery.intelligence.model import model_for

    path = tmp_path / "app.ts"
    path.write_bytes(b"export interface Repo { find(key: string): string; }\nexport type Mode = 'a';\n")
    record = FileRecord("app.ts", path.stat().st_size, ".ts", "TypeScript", mtime_ns=path.stat().st_mtime_ns)
    model = model_for(path, record)
    assert model.backend == "tree-sitter"
    assert {("method", "Repo.find"), ("type", "Mode")} <= _symbols(model)
