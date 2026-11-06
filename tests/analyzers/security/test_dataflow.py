"""Data-flow / taint analysis: Python engine, lexical engine and cross-module flows."""
import ast
import json
import textwrap
from pathlib import Path

from project_discovery.analyzers.security.dataflow import DataFlowAnalyzer
from project_discovery.analyzers.security.taint_lexical import analyze_lexical_taint
from project_discovery.analyzers.security.taint_python import analyze_python_taint
from project_discovery.cli import run_scan
from project_discovery.intelligence.facts import collecting_facts
from project_discovery.intelligence.model.lexical import LEXICAL_LANGUAGES, build_lexical_model
from project_discovery.models import FileRecord


def python_flows(source: str) -> set[tuple[str, int]]:
    result = analyze_python_taint(ast.parse(textwrap.dedent(source)))
    return {(flow.kind, flow.call_line) for flow in result.flows}


def lexical_flows(name: str, language: str, source: str) -> set[tuple[str, int]]:
    model = build_lexical_model(name, language, textwrap.dedent(source))
    flows, _ = analyze_lexical_taint(model, LEXICAL_LANGUAGES[language])
    return {(flow.kind, flow.sink_line) for flow in flows}


def test_python_request_data_reaches_sinks_through_helpers():
    flows = python_flows('''
        import os, subprocess, sqlite3
        from flask import request, redirect
        def build(term):
            return "SELECT * FROM t WHERE name = '%s'" % term
        def run(conn, sql):
            conn.cursor().execute(sql)
        def search():
            term = request.args.get("q", "")
            run(sqlite3.connect("x"), build(term))
            cursor.execute("SELECT * FROM t WHERE id = ?", (term,))
            subprocess.run("ls " + term, shell=True)
            subprocess.run(["ls", term])
            return redirect(term)
    ''')
    assert flows == {("sql", 10), ("command", 12), ("redirect", 14)}


def test_python_sanitizers_and_validated_route_parameters():
    flows = python_flows('''
        import os, shlex, pickle
        from flask import Flask, request, send_file
        from werkzeug.utils import secure_filename
        app = Flask(__name__)
        @app.route("/files/<int:fid>/<path:name>")
        def download(fid, name):
            open(os.path.join("/data", str(fid)))
            send_file(os.path.join("/data", secure_filename(name)))
            os.system("echo " + shlex.quote(name))
            n = int(request.args["n"])
            os.system("echo %d" % n)
            return send_file(os.path.join("/data", name))
        @app.get("/items/{item_id}")
        def item(item_id: str, limit: int = 10):
            return pickle.loads(item_id.encode())
    ''')
    assert flows == {("path", 13), ("deserialization", 16)}


def test_python_flows_through_loops_branches_and_methods():
    flows = python_flows('''
        import os
        from flask import request
        def loop():
            acc = ""
            for part in request.args.getlist("p"):
                acc += part
            eval(acc)
        def branch():
            if request.args:
                target = request.args["t"]
            else:
                target = "/"
            os.popen(target)
        def cleared():
            value = request.args["v"]
            value = "constant"
            os.system(value)
        class View:
            def get(self):
                self.helper(self.request.GET["v"])
            def helper(self, v):
                os.popen(v)
    ''')
    assert flows == {("code", 8), ("command", 14), ("command", 21)}


def test_lexical_engine_follows_flows_in_eight_language_families():
    assert lexical_flows("app.js", "JavaScript", '''
        app.get('/run', (req, res) => {
          const cmd = req.query.cmd;
          exec('ls ' + cmd);
          const id = parseInt(req.query.id, 10);
          db.query('SELECT * FROM t WHERE id = ' + id);
          db.query(`SELECT * FROM t WHERE name = '${req.query.name}'`);
          db.query('SELECT * FROM t WHERE name = ?', [req.query.name]);
          res.redirect(req.query.next);
        });
    ''') == {("command", 4), ("sql", 7), ("redirect", 9)}
    assert lexical_flows("index.php", "PHP", '''<?php
        $id = $_GET['id'];
        mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
        echo "Hello " . htmlspecialchars($_GET['name']);
        include $_SERVER['DOCUMENT_ROOT'] . '/header.php';
        system('ping ' . escapeshellarg($_GET['host']));
        $body = file_get_contents('php://input');
        eval($body);
    ''') == {("sql", 3), ("code", 8)}
    assert lexical_flows("Ctl.java", "Java", '''
        class Ctl {
          String user(@RequestParam("name") String name, HttpServletRequest request) throws Exception {
            StringBuilder sql = new StringBuilder("SELECT * FROM u WHERE name = '");
            sql.append(name);
            stmt.executeQuery(sql.toString());
            int n = Integer.parseInt(request.getParameter("n"));
            stmt.executeQuery("SELECT " + n);
            return "ok";
          }
        }
    ''') == {("sql", 6)}
    assert lexical_flows("main.go", "Go", '''
        package main
        func handler(w http.ResponseWriter, r *http.Request) {
            name := r.URL.Query().Get("name")
            db.Query("SELECT * FROM t WHERE name = '" + name + "'")
            db.Query("SELECT * FROM t WHERE name = $1", name)
            n, _ := strconv.Atoi(r.FormValue("n"))
            os.Open(fmt.Sprintf("/data/%d", n))
            os.Open(filepath.Join("/data", r.FormValue("f")))
        }
    ''') == {("sql", 5), ("path", 9)}
    assert lexical_flows("Home.cs", "C#", '''
        public class HomeController : Controller {
          public IActionResult Find([FromQuery] string q) {
            var cmd = new SqlCommand("SELECT * FROM t WHERE n = '" + q + "'", conn);
            var name = Request.Query["name"];
            var html = $"<b>{name}</b>";
            return Content(Html.Raw(html).ToString());
          }
        }
    ''') == {("sql", 4), ("xss", 7)}
    assert lexical_flows("srv.c", "C", '''
        void serve(int sock) {
          char buf[256], cmd[300];
          recv(sock, buf, sizeof buf, 0);
          printf(buf);
          sprintf(cmd, "echo %s", buf);
          system(cmd);
          printf("%d", atoi(buf));
        }
    ''') == {("format_string", 5), ("command", 7)}
    assert lexical_flows("Api.kt", "Kotlin", '''
        class Api {
          fun k(@RequestParam name: String): String {
            jdbcTemplate.queryForList("SELECT * FROM t WHERE n = '$name'")
            val count = name.toInt()
            jdbcTemplate.queryForList("SELECT * FROM t LIMIT $count")
            return name
          }
        }
    ''') == {("sql", 4)}
    assert lexical_flows("main.rs", "Rust", '''
        async fn search(Query(params): Query<Params>) -> impl Responder {
            let out = Command::new(params.cmd).output();
            HttpResponse::Ok().body(params.name)
        }
    ''') == {("command", 3), ("xss", 4)}


def test_analyzer_reports_flows_with_source_and_sink(tmp_path: Path):
    path = tmp_path / "views.py"
    path.write_text("import os\nfrom flask import request\n\ndef run():\n    os.system(request.args['c'])\n",
                    encoding="utf-8")
    record = FileRecord("views.py", path.stat().st_size, ".py", "Python")
    with collecting_facts() as facts:
        findings = DataFlowAnalyzer().analyze(path, record)
    assert [(item.title, item.severity, item.confidence) for item in findings] == [
        ("Command injection: views.py", "HIGH", "INFERRED")]
    assert "`request.args` (line 5) reaches `os.system`" in findings[0].detail
    stats = next(json.loads(detail) for kind, _, detail in facts.facts if kind == "dataflow_stats")
    assert stats == {"command": 1, "flows": 1, "sources": 1}


def test_scan_joins_flows_across_python_modules(tmp_path: Path):
    project = tmp_path / "project"
    (project / "shop").mkdir(parents=True)
    (project / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (project / "shop" / "db.py").write_text(
        "import sqlite3\n"
        "def run_query(sql):\n    return sqlite3.connect('x').execute(sql).fetchall()\n"
        "def find(name):\n    return run_query(\"SELECT * FROM p WHERE name = '\" + name + \"'\")\n"
        "def safe(pid):\n    return run_query('SELECT * FROM p WHERE id = %d' % int(pid))\n",
        encoding="utf-8",
    )
    (project / "shop" / "views.py").write_text(
        "from flask import request\nfrom .db import find, safe\n"
        "def search():\n    return find(request.args['q'])\n"
        "def item():\n    return safe(request.args['id'])\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    cross = next(item for item in report["findings"] if item["title"] == "SQL injection across modules")
    assert cross["severity"] == "HIGH"
    assert len(cross["evidence"]) == 1
    assert cross["evidence"][0].startswith("shop/views.py:4 `request.args` (line 4) -> shop.db.find() -> run_query() -> ")
    assert cross["evidence"][0].endswith("at shop/db.py:3")
    assert all("safe" not in item for item in cross["evidence"])
    assert report["metrics"]["code_index"]["dataflow"]["cross_module_flows"] == 1


def test_files_without_sources_or_sinks_cost_one_walk():
    from project_discovery.analyzers.security.taint_python import PythonTaintEngine

    engine = PythonTaintEngine(ast.parse("def a(x):\n    return x + 1\n\ndef b():\n    return a(2)\n"))
    assert engine.relevant == [] and not engine.has_sources
    assert analyze_python_taint(ast.parse("def a(x):\n    return x\n")).flows == []


def lexical_paths(name: str, language: str, source: str) -> set[tuple[str, int, int, str]]:
    model = build_lexical_model(name, language, textwrap.dedent(source))
    flows, _ = analyze_lexical_taint(model, LEXICAL_LANGUAGES[language])
    return {(flow.kind, flow.sink_line, flow.call_line, flow.via) for flow in flows}


def test_lexical_engine_follows_the_files_own_functions():
    # A parameter reaching a sink, a returned parameter, a returned source and a chain.
    assert lexical_paths("app.js", "JavaScript", '''
        function runQuery(sql) {
          return pool.query(sql);
        }
        function wrap(x) {
          return "SELECT * FROM t WHERE n = '" + x + "'";
        }
        function name(req) {
          return req.query.name;
        }
        function outer(a) { inner(a); }
        function inner(b) { exec(b); }
        app.get('/x', (req, res) => {
          runQuery("SELECT * FROM t WHERE id = " + req.query.id);
          pool.query(wrap(req.query.q));
          exec("ls " + name(req));
          outer(req.query.c);
          runQuery("SELECT 1 WHERE id = " + parseInt(req.query.n, 10));
        });
    ''') == {
        ("sql", 3, 14, "runQuery()"), ("sql", 15, 15, ""), ("command", 16, 16, ""),
        ("command", 12, 17, "outer() -> inner()"),
    }
    assert lexical_paths("index.php", "PHP", '''<?php
        function run($q) {
            mysqli_query($GLOBALS['conn'], $q);
        }
        run("SELECT * FROM t WHERE id = " . $_GET['id']);
        run("SELECT * FROM t WHERE id = " . intval($_GET['id']));
    ''') == {("sql", 3, 5, "run()")}
    assert lexical_paths("main.go", "Go", '''
        package main
        func find(db *sql.DB, name string) {
            db.Query("SELECT * FROM t WHERE n = '" + name + "'")
        }
        func handler(w http.ResponseWriter, r *http.Request) {
            find(db, r.FormValue("n"))
            find(r.FormValue("db"), "fixed")
        }
    ''') == {("sql", 4, 7, "find()")}
    assert lexical_paths("Ctl.java", "Java", '''
        class Ctl {
          private void run(String sql) throws Exception {
            stmt.executeQuery(sql);
          }
          String user(HttpServletRequest request) throws Exception {
            run("SELECT " + request.getParameter("n"));
            return "ok";
          }
        }
    ''') == {("sql", 4, 7, "run()")}
    assert lexical_paths("srv.c", "C", '''
        void run(const char *c) {
          system(c);
        }
        void serve(int sock) {
          char buf[256];
          recv(sock, buf, sizeof buf, 0);
          run(buf);
        }
    ''') == {("command", 3, 8, "run()")}


def test_lexical_flows_are_joined_across_files_by_an_unambiguous_name(tmp_path: Path):
    project = tmp_path / "project"
    (project / "lib").mkdir(parents=True)
    (project / "lib" / "db.js").write_text(
        "function runQuery(sql) {\n  return pool.query(sql);\n}\n"
        "function save(row) {\n  return pool.query('INSERT ' + row);\n}\n"
        "module.exports = { runQuery, save };\n",
        encoding="utf-8",
    )
    # A second file also defines save(), so calls to save() are ambiguous and not joined.
    (project / "lib" / "cache.js").write_text("function save(item) {\n  store.set(item);\n}\n", encoding="utf-8")
    (project / "app.js").write_text(
        "const { runQuery, save } = require('./lib/db');\n"
        "app.get('/find', (req, res) => {\n"
        "  runQuery(\"SELECT * FROM t WHERE id = \" + req.query.id);\n"
        "  save(req.query.row);\n"
        "});\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    cross = next(item for item in report["findings"] if item["title"] == "SQL injection across modules")
    assert cross["evidence"] == [
        "app.js:3 `req.query` (line 3) -> runQuery() -> `pool.query` at lib/db.js:2",
    ]
    assert report["metrics"]["code_index"]["dataflow"]["cross_module_flows"] == 1


def test_python_flows_follow_methods_of_objects_with_a_known_class():
    assert python_flows('''
        from flask import request

        class Repo:
            def find(self, name):
                cursor.execute("SELECT * FROM t WHERE n = '" + name + "'")

        class Service:
            def __init__(self, repo: Repo):
                self.repo = repo

            def search(self):
                self.repo.find(request.args["q"])

        def view(other):
            repo = Repo()
            repo.find(request.args["a"])
            other.find(request.args["b"])
            repo.find(int(request.args["c"]))
    ''') == {("sql", 13), ("sql", 17)}


def test_scan_joins_flows_into_methods_of_imported_classes(tmp_path: Path):
    project = tmp_path / "project"
    (project / "shop").mkdir(parents=True)
    (project / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (project / "shop" / "store.py").write_text(
        "import sqlite3\n"
        "class Store:\n"
        "    def run(self, sql):\n"
        "        return sqlite3.connect('x').execute(sql).fetchall()\n",
        encoding="utf-8",
    )
    (project / "shop" / "views.py").write_text(
        "from flask import request\nfrom .store import Store\n"
        "def search():\n"
        "    store = Store()\n"
        "    return store.run(\"SELECT * FROM p WHERE name = '\" + request.args['q'] + \"'\")\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    cross = next(item for item in report["findings"] if item["title"] == "SQL injection across modules")
    assert cross["evidence"] == [
        "shop/views.py:5 `request.args` (line 5) -> shop.store.Store.run() -> `(...).execute` at shop/store.py:4",
    ]
