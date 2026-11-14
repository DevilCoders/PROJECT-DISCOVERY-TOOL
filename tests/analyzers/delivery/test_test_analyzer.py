from pathlib import Path

from project_discovery.analyzers.delivery.testing import TestDiscoveryAnalyzer
from project_discovery.models import FileRecord


def _record(path: Path, relative: str) -> FileRecord:
    return FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Source")


def test_python_and_javascript_test_declarations(tmp_path: Path):
    python = tmp_path / "test_service.py"
    python.write_text("def test_login():\n    assert True\n", encoding="utf-8")
    js = tmp_path / "service.test.ts"
    js.write_text("test('loads service', () => {});\nit('handles error', () => {});", encoding="utf-8")
    analyzer = TestDiscoveryAnalyzer()
    assert "Detected 1 test declarations" in analyzer.analyze(
        python, _record(python, "tests/test_service.py")
    )[0].detail
    assert "Detected 2 test declarations" in analyzer.analyze(
        js, _record(js, "src/service.test.ts")
    )[0].detail


def test_rust_go_and_csharp_test_naming(tmp_path: Path):
    analyzer = TestDiscoveryAnalyzer()
    rust = tmp_path / "service_test.rs"
    rust.write_text("#[test]\nfn works() {}\n", encoding="utf-8")
    go = tmp_path / "service_test.go"
    go.write_text("func TestService(t *testing.T) {}\n", encoding="utf-8")
    csharp = tmp_path / "ServiceTests.cs"
    csharp.write_text("[Fact]\npublic void Works() {}\n", encoding="utf-8")
    assert analyzer.supports(_record(rust, "service_test.rs"))
    assert analyzer.supports(_record(go, "service_test.go"))
    assert analyzer.supports(_record(csharp, "ServiceTests.cs"))
    assert analyzer.analyze(rust, _record(rust, "service_test.rs"))[0].confidence == "CONFIRMED"


def test_many_polyglot_test_paths_are_recognized(tmp_path: Path):
    analyzer = TestDiscoveryAnalyzer()
    cases = [
        ("test_widget.dart", ".dart"),
        ("widget_test.exs", ".exs"),
        ("test_parser.R", ".r"),
        ("runtests.jl", ".jl"),
        ("TokenSpec.scala", ".scala"),
        ("string_test.clj", ".clj"),
        ("router_spec.lua", ".lua"),
        ("network.bats", ".bats"),
        ("CryptoTests.ps1", ".ps1"),
        ("Token.t.sol", ".sol"),
        ("tb_cpu.sv", ".sv"),
    ]
    for filename, extension in cases:
        path = tmp_path / filename
        path.write_text("", encoding="utf-8")
        record = FileRecord(filename, 0, extension, "Source")
        assert analyzer.supports(record), filename


def test_test_directory_discovers_unusual_source_names(tmp_path: Path):
    path = tmp_path / "integration" / "helpers.go"
    path.parent.mkdir()
    path.write_text("package integration\n", encoding="utf-8")
    record = _record(path, "tests/integration/helpers.go")
    assert TestDiscoveryAnalyzer().supports(record)


def test_non_test_source_is_not_supported(tmp_path: Path):
    path = tmp_path / "main.py"
    path.write_text("print('hello')", encoding="utf-8")
    assert TestDiscoveryAnalyzer().supports(_record(path, "src/main.py")) is False



def test_test_discovery_uses_catalog_for_uncommon_polyglot_languages(tmp_path: Path):
    analyzer = TestDiscoveryAnalyzer()
    for relative in (
        "tests/test_scheduler.odin",
        "tests/integration/firmware_test.cob",
        "tests/gpu/test_kernel.cu",
        "specs/test_contract.move",
    ):
        path = tmp_path / Path(relative).name
        path.write_text("", encoding="utf-8")
        record = FileRecord(relative, 0, path.suffix.lower(), "Other")
        assert analyzer.supports(record), relative


def test_root_test_filename_convention_is_language_agnostic(tmp_path: Path):
    analyzer = TestDiscoveryAnalyzer()
    path = tmp_path / "test_runtime.odin"
    path.write_text('proc testRuntime() = discard\n', encoding="utf-8")
    record = FileRecord(path.name, path.stat().st_size, path.suffix.lower(), "Odin")
    assert analyzer.supports(record)


def test_test_declarations_across_framework_conventions(tmp_path: Path):
    # Regressions: unittest testCamelCase methods, Rust tokio/test_case/rstest attributes,
    # PHPUnit attributes, @test docblocks and Pest calls were not counted; Groovy counted
    # every def; annotation patterns produced empty sample names.
    analyzer = TestDiscoveryAnalyzer()

    def scan(relative, source):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return analyzer.analyze(path, _record(path, relative))[0]

    python = scan("tests/test_login.py", "class LoginTest(TestCase):\n    def testLogin(self):\n        pass\n")
    assert "Detected 1 test declarations" in python.detail
    rust = scan(
        "tests/api.rs",
        "#[tokio::test(flavor = \"multi_thread\")]\nasync fn a() {}\n#[cfg(test)]\nmod m {}\n"
        "#[test_case(1, 2 ; \"small\")]\nfn b() {}\n#[rstest]\nfn c() {}\n#[sqlx::test]\nasync fn d() {}\n",
    )
    assert "Detected 4 test declarations" in rust.detail
    assert "Sample names: ," not in rust.detail
    php = scan(
        "tests/MathTest.php",
        "<?php\nclass MathTest extends TestCase {\n"
        "    #[Test]\n    public function testAdds(): void {}\n"
        "    /**\n     * @test\n     */\n    public function subtracts(): void {}\n"
        "    public function testPlain(): void {}\n"
        "    public function helper(): void { $mail = 'someone@test.example'; }\n}\n"
        "it('multiplies numbers', function () {});\n",
    )
    assert "Detected 4 test declarations" in php.detail
    assert "testAdds, subtracts, testPlain, multiplies numbers" in php.detail
    groovy = scan(
        "src/test/groovy/MathSpec.groovy",
        "class MathSpec extends Specification {\n    def \"adds numbers\"() { expect: true }\n"
        "    def helper() { 1 }\n    @Test\n    void checksTotals() {}\n}\n",
    )
    assert "Detected 2 test declarations" in groovy.detail
    assert "adds numbers, checksTotals" in groovy.detail
