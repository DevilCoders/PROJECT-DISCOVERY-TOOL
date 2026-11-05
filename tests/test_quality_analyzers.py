"""Performance, concurrency, resource-management and type-system analyzers."""
import json
from pathlib import Path

from project_discovery.analyzers.concurrency_analyzer import ConcurrencyAnalyzer
from project_discovery.analyzers.performance_analyzer import PerformanceHotspotAnalyzer
from project_discovery.analyzers.resource_analyzer import ResourceManagementAnalyzer
from project_discovery.analyzers.type_system_analyzer import TypeSystemAnalyzer
from project_discovery.code_facts import collecting_facts
from project_discovery.language_catalog import detect_language
from project_discovery.models import FileRecord


def run(analyzer, tmp_path: Path, name: str, text: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))  # bytes: keep line endings exactly as written
    record = FileRecord(name, path.stat().st_size, path.suffix, detect_language(name))
    assert analyzer.supports(record), name
    with collecting_facts() as facts:
        findings = analyzer.analyze(path, record)
    issues = {
        finding.title.split(": ")[0]: (finding.severity, sorted(int(item.rsplit(":", 1)[1])
                                                               for item in finding.evidence if ":" in item))
        for finding in findings
    }
    return issues, [(kind, name, json.loads(detail)) for kind, name, detail in facts.facts]


def test_performance_hotspots_in_python_loops(tmp_path: Path):
    issues, facts = run(PerformanceHotspotAnalyzer(), tmp_path, "orders.py", (
        "import time, copy, requests\n"
        "def sync(orders, cursor):\n"
        "    out = ''\n"
        "    for order in orders:\n"
        "        cursor.execute('SELECT * FROM items WHERE order_id = %s', (order.id,))\n"
        "        requests.get(f'https://api/x/{order.id}')\n"
        "        out += 'x'\n"
        "        time.sleep(1)\n"
        "        for line in order.lines:\n"
        "            for tag in line.tags:\n"
        "                pass\n"
        "    return out\n"
        "def schema(db):\n"
        "    for statement in ('CREATE TABLE a (x)', 'CREATE TABLE b (y)'):\n"
        "        db.execute(statement)\n"
        "    names = {row[0] for row in db.execute('PRAGMA table_info(a)')}\n"
        "    for row in rows:\n"
        "        db.execute('COMMIT')\n"
        "    return names\n"
    ))
    assert issues["Database query inside a loop"] == ("LOW", [5])
    assert issues["HTTP request inside a loop"][1] == [6]
    assert issues["String built with += in a loop"][1] == [7]
    assert issues["Sleep inside a loop"][1] == [8]
    assert issues["Deeply nested loops"][1] == [10]
    assert facts[0][0] == "complexity_stats" and facts[0][2]["functions"] == 2


def test_lexical_performance_and_profiling_artifacts(tmp_path: Path):
    issues, _ = run(PerformanceHotspotAnalyzer(), tmp_path, "load.ts", (
        "export async function load(ids: number[]) {\n  for (const id of ids) {\n"
        "    await db.query('SELECT 1 WHERE id = $1', [id]);\n    await fetch(`/api/items/${id}`);\n  }\n}\n"
    ))
    assert issues["Database query inside a loop"][1] == [3]
    assert issues["HTTP request inside a loop"][1] == [4]
    artifacts, _ = run(PerformanceHotspotAnalyzer(), tmp_path, "dump.hprof", "x")
    assert artifacts["Profiling artifact"][0] == "LOW"


def test_python_concurrency_defects(tmp_path: Path):
    issues, facts = run(ConcurrencyAnalyzer(), tmp_path, "svc.py", (
        "import asyncio, threading, time, requests\n"
        "counter = 0\nlock = threading.Lock()\n"
        "async def fetch():\n    time.sleep(1)\n    requests.get('http://x')\n    await asyncio.sleep(0)\n"
        "async def main():\n    fetch()\n    asyncio.sleep(1)\n    await fetch()\n"
        "def work():\n    global counter\n    counter += 1\n"
        "def guarded():\n    lock.acquire()\n    do()\n    lock.release()\n"
        "def safe():\n    with lock:\n        do()\n"
        "def finally_safe():\n    lock.acquire()\n    try:\n        do()\n    finally:\n        lock.release()\n"
        "threading.Thread(target=work).start()\n"
        "class Guard:\n    def __enter__(self):\n        lock.acquire()\n    def __exit__(self, *exc):\n        lock.release()\n"
    ))
    assert issues["Blocking call inside async code"] == ("MEDIUM", [5, 6])
    assert issues["Coroutine or promise not awaited"][1] == [9, 10]
    assert issues["Lock acquired without a guaranteed release"][1] == [16]
    assert issues["Thread target modifies global state without a lock"][1] == [12]
    assert facts == [("concurrency", "Python", {"async_functions": 2, "locks": 1, "threads": 1})]


def test_lexical_concurrency_defects(tmp_path: Path):
    go, _ = run(ConcurrencyAnalyzer(), tmp_path, "store.go", (
        "package store\nfunc (s *Store) Put(k string) { s.mu.Lock(); s.m[k] = 1 }\n"
        "func (s *Store) Get(k string) int { s.mu.RLock(); defer s.mu.RUnlock(); return s.m[k] }\n"
        "func run(wg *sync.WaitGroup) { go func() { wg.Add(1); work() }() }\n"
    ))
    assert go["Lock acquired without a guaranteed release"][1] == [2]
    assert go["WaitGroup.Add inside the goroutine"][1] == [4]
    java, _ = run(ConcurrencyAnalyzer(), tmp_path, "Single.java", (
        "class Single {\n  private static Single instance;\n  private static volatile Single safe;\n"
        "  static Single get() { if (instance == null) { synchronized (Single.class) { instance = new Single(); } } return instance; }\n"
        "  static Single getSafe() { if (safe == null) { synchronized (Single.class) { safe = new Single(); } } return safe; }\n}\n"
    ))
    assert java["Double-checked locking without volatile"][1] == [4]
    csharp, _ = run(ConcurrencyAnalyzer(), tmp_path, "Svc.cs", (
        "class Svc {\n  async void Fire() { await Task.Delay(1); }\n"
        "  async void OnClick(object sender, EventArgs e) { await Task.Delay(1); }\n}\n"
    ))
    assert csharp["async void method"][1] == [2]
    rust, _ = run(ConcurrencyAnalyzer(), tmp_path, "lib.rs", "struct Raw(*mut u8);\nunsafe impl Send for Raw {}\n")
    assert rust["Manual Send/Sync implementation"] == ("MEDIUM", [2])


def test_resource_leaks_and_ownership(tmp_path: Path):
    python, _ = run(ResourceManagementAnalyzer(), tmp_path, "io.py", (
        "import json, sqlite3, subprocess, tempfile\n"
        "def leak(path):\n    f = open(path)\n    return json.load(f)\n"
        "def ok(path):\n    with open(path) as f:\n        return f.read()\n"
        "def returned(path):\n    f = open(path)\n    return f\n"
        "def conn():\n    c = sqlite3.connect('x.db')\n    c.execute('select 1')\n"
        "def tmp():\n    return tempfile.mktemp()\n"
    ))
    assert python["File opened without a guaranteed close"] == ("LOW", [3])
    assert python["Database connection opened without a guaranteed close"][1] == [12]
    assert python["Insecure temporary file name"] == ("MEDIUM", [15])
    native, facts = run(ResourceManagementAnalyzer(), tmp_path, "buf.c", (
        "#include <stdlib.h>\n"
        "int leak(size_t n) { char *p = malloc(n); memcpy(p, src, n); return 0; }\n"
        "char *give(size_t n) { char *p = malloc(n); return p; }\n"
        "void ok(size_t n) { char *p = malloc(n); use(p); free(p); }\n"
        "void grow(char *buf, size_t n) { buf = realloc(buf, n); }\n"
    ))
    assert native["Allocation without a matching free"][1] == [2]
    assert native["realloc result overwrites its input pointer"] == ("MEDIUM", [5])
    assert facts[0][0] == "memory_stats"
    cpp, _ = run(ResourceManagementAnalyzer(), tmp_path, "arr.cpp",
                 "void f() { int *a = new int[10]; delete a; }\nvoid g() { int *b = new int[4]; delete[] b; }\n")
    assert cpp["delete on memory from new[]"][1] == [1]


def test_type_annotation_coverage_and_escape_hatches(tmp_path: Path):
    issues, facts = run(TypeSystemAnalyzer(), tmp_path, "typed.py", (
        "from typing import Any, cast\n"
        "def a(x: int, y: str) -> int:\n    return x\n"
        "def b(x, y: Any):\n    return cast(int, y)  # type: ignore[return-value]\n"
    ))
    assert issues == {}
    assert facts[0][2] == {"any": 1, "casts": 1, "fully_annotated": 1, "functions": 2, "parameters": 4,
                           "return_annotated": 1, "suppressions": 1, "typed_parameters": 3}
    ignored, _ = run(TypeSystemAnalyzer(), tmp_path, "ignored.py", "# type: ignore\nimport os\n")
    assert ignored["Type checking disabled for the whole module"][0] == "LOW"
    ts, ts_facts = run(TypeSystemAnalyzer(), tmp_path, "app.ts", (
        "// @ts-nocheck\nexport function f(a: any, b: Map<string, any>): any[] {\n  // @ts-ignore\n"
        "  return [(a as any).y!.z];\n}\nconst s = 'any: any';\n"
    ))
    assert "Type checking disabled for the whole file" in ts
    assert ts_facts[0][2]["any"] == 4 and ts_facts[0][2]["suppressions"] == 1


def test_type_checker_configuration(tmp_path: Path):
    tsconfig, _ = run(TypeSystemAnalyzer(), tmp_path, "tsconfig.json",
                      '{\n  // comment\n  "compilerOptions": {\n    "strict": false, /* inline */\n  },\n}\n')
    assert tsconfig["Relaxed type checking"][0] == "LOW"
    mypy, _ = run(TypeSystemAnalyzer(), tmp_path, "mypy.ini",
                  "[mypy]\r\nstrict_optional = False\r\n[mypy-vendor.*]\r\nignore_errors = True\r\n")
    assert "Relaxed type checking" in mypy
    pyproject, _ = run(TypeSystemAnalyzer(), tmp_path, "pyproject.toml",
                       '[project]\nname = "x"\n[tool.ruff]\nstrict = false\n')
    assert pyproject == {}
    nullable, _ = run(TypeSystemAnalyzer(), tmp_path, "App.csproj",
                      "<Project><PropertyGroup><Nullable>disable</Nullable></PropertyGroup></Project>")
    assert nullable["C# nullable reference types"][0] == "LOW"
