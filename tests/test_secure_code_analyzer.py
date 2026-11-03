from pathlib import Path

from project_discovery.analyzers.secure_code_analyzer import SecureCodePatternAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix.lower(), "Source")
    analyzer = SecureCodePatternAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_python_shell_execution_and_unsafe_deserialization():
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        findings = _scan(
            Path(directory), "unsafe.py",
            "import subprocess\nimport pickle\n"
            "subprocess.run(user_input, shell=True)\npickle.loads(payload)\n"
            "yaml.load(payload, Loader=yaml.SafeLoader)\n",
        )
    titles = [item.title for item in findings]
    assert any("Shell/process execution" in title for title in titles)
    assert any("unsafe deserialization" in title for title in titles)
    assert all(item.confidence == "INFERRED" for item in findings)


def test_python_tls_sql_weak_hash_and_tempfile_patterns(tmp_path: Path):
    findings = _scan(
        tmp_path, "app.py",
        "import requests, hashlib, tempfile\n"
        "requests.get(url, verify=False)\n"
        "hashlib.md5(value)\ntempfile.mktemp()\n"
        "cursor.execute('SELECT * FROM users WHERE id=' + user_id)\n",
    )
    titles = [item.title for item in findings]
    assert any("TLS certificate" in title for title in titles)
    assert any("weak cryptographic hash" in title for title in titles)
    assert any("temporary-file" in title for title in titles)
    assert any("dynamically constructed SQL" in title for title in titles)


def test_safe_yaml_loader_is_not_flagged(tmp_path: Path):
    findings = _scan(
        tmp_path, "safe.py",
        "import yaml\ndata = yaml.safe_load(payload)\n"
        "other = yaml.load(payload, Loader=yaml.SafeLoader)\n",
    )
    assert findings == []


def test_polyglot_shell_and_c_unsafe_api_patterns(tmp_path: Path):
    shell = _scan(tmp_path, "deploy.sh", "eval \"$USER_INPUT\"\ncurl --no-check-certificate https://x\n")
    c_source = _scan(tmp_path, "legacy.c", "void f(char *a, char *b) { strcpy(a, b); }\n")
    assert any("Dynamic code execution" in item.title for item in shell)
    assert any("TLS certificate" in item.title for item in shell)
    assert any("unsafe C memory" in item.title for item in c_source)


def test_non_source_files_are_not_supported():
    record = FileRecord("model.bin", 10, ".bin", "Other")
    assert SecureCodePatternAnalyzer().supports(record) is False


def test_syntax_error_is_unknown_not_crash(tmp_path: Path):
    findings = _scan(tmp_path, "broken.py", "def broken(:\n")
    assert findings[0].confidence == "UNKNOWN"



def test_secure_code_rules_cover_the_full_recognized_source_catalog(tmp_path: Path):
    from project_discovery.language_catalog import source_language_names

    analyzer = SecureCodePatternAnalyzer()
    assert len(source_language_names()) >= 40
    for filename in (
        "agent.jl", "service.ex", "contract.sol", "kernel.cu",
        "shader.wgsl", "module.vhd", "controller.nim", "firmware.cob",
    ):
        record = FileRecord(filename, 10, Path(filename).suffix.lower(), "Other")
        assert analyzer.supports(record), filename

    findings = _scan(tmp_path, "agent.jl", "result = eval(user_input)\n")
    assert any("Dynamic code execution" in item.title for item in findings)


def test_polyglot_security_rules_detect_web_dataflow_and_token_misuse(tmp_path: Path):
    javascript = _scan(
        tmp_path,
        "routes.js",
        'db.query("SELECT * FROM users WHERE id = " + req.query.id);\n'
        'fetch(req.query.url);\n'
        'res.redirect(req.query.next);\n'
        'const token = Math.random();\n',
    )
    titles = [item.title for item in javascript]
    assert any("dynamically constructed SQL" in title for title in titles)
    assert any("user-controlled outbound request" in title for title in titles)
    assert any("user-controlled redirect" in title for title in titles)
    assert any("non-cryptographic randomness" in title for title in titles)

    java = _scan(
        tmp_path,
        "Controller.java",
        'String path = request.getParameter("file");\n'
        'new FileInputStream(path);\n'
        'MessageDigest.getInstance("MD5");\n'
        'response.sendRedirect(request.getParameter("next"));\n',
    )
    java_titles = [item.title for item in java]
    assert any("user-controlled filesystem path" in title for title in java_titles)
    assert any("weak cryptographic hash" in title for title in java_titles)
    assert any("user-controlled redirect" in title for title in java_titles)


def test_polyglot_security_rules_cover_dotnet_and_xml_parser_misconfiguration(tmp_path: Path):
    source = _scan(
        tmp_path,
        "Service.cs",
        'var client = new HttpClient();\n'
        'client.GetAsync(request.Query["url"]);\n'
        'settings.DtdProcessing = DtdProcessing.Parse;\n',
    )
    titles = [item.title for item in source]
    assert any("user-controlled outbound request" in title for title in titles)
    assert any("external-entity" in title for title in titles)


def test_polyglot_security_rule_catalog_is_deterministic():
    from project_discovery.analyzers.secure_code_analyzer import _PATTERNS

    names = [item[0] for item in _PATTERNS]
    assert len(names) == len(set(names))
    assert {
        "dynamic_sql_query",
        "ssrf_user_controlled_url",
        "path_traversal_user_controlled_path",
        "jwt_verification_disabled",
        "open_redirect_user_controlled",
        "unsafe_xml_external_entities",
    } <= set(names)
