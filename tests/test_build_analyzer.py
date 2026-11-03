from pathlib import Path

from project_discovery.analyzers.build_analyzer import BuildManifestAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Build")
    analyzer = BuildManifestAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_makefile_targets_are_inventoried(tmp_path: Path):
    findings = _scan(tmp_path, "Makefile", ".PHONY: all test\nall: build\ntest: unit\n")
    assert "2 build targets/jobs" in findings[0].detail
    assert "all" in findings[0].evidence
    assert "test" in findings[0].evidence


def test_package_json_scripts_are_inventoried(tmp_path: Path):
    findings = _scan(
        tmp_path, "package.json",
        '{"name":"frontend","scripts":{"build":"vite build","test":"vitest"}}',
    )
    assert "2 build targets/jobs" in findings[0].detail
    assert "script: build" in findings[0].evidence


def test_dockerfile_instructions_are_inventoried(tmp_path: Path):
    findings = _scan(tmp_path, "Dockerfile", "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCMD [\"python\",\"app.py\"]\n")
    assert "4 build targets/jobs" in findings[0].detail



def test_bazel_targets_are_inventoried(tmp_path: Path):
    findings = _scan(
        tmp_path, "BUILD.bazel",
        'cc_binary(name = "agent")\npy_test(name = "agent_tests")\n',
    )
    assert "2 build targets/jobs" in findings[0].detail
    assert "cc_binary: agent" in findings[0].evidence
    assert "py_test: agent_tests" in findings[0].evidence


def test_swift_package_targets_are_inventoried(tmp_path: Path):
    findings = _scan(
        tmp_path, "Package.swift",
        'let package = Package(name: "Core", targets: ['
        '.executableTarget(name: "App"), .testTarget(name: "AppTests")])',
    )
    assert "2 build targets/jobs" in findings[0].detail
    assert "target: App" in findings[0].evidence
    assert "target: AppTests" in findings[0].evidence


def test_dotnet_project_references_and_framework_are_inventoried(tmp_path: Path):
    findings = _scan(
        tmp_path, "Core.csproj",
        '<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
        '</PropertyGroup><ItemGroup><ProjectReference Include="../Shared/Shared.csproj" />'
        '<PackageReference Include="Serilog" Version="3.0" /></ItemGroup></Project>',
    )
    assert ".NET project manifest" in findings[0].detail
    assert "TargetFramework: net8.0" in findings[0].detail
    assert "ProjectReference: ../Shared/Shared.csproj" in findings[0].evidence
    assert "PackageReference: Serilog" in findings[0].evidence


def test_ant_and_ninja_build_targets_are_inventoried(tmp_path: Path):
    ant = _scan(
        tmp_path, "build.xml",
        '<project name="sample"><target name="compile"/><target name="test"/></project>',
    )
    ninja = _scan(
        tmp_path, "build.ninja",
        'rule cc\n  command = cc $in -o $out\nbuild app: cc main.c\n',
    )
    assert "target: compile" in ant[0].evidence
    assert "target: test" in ant[0].evidence
    assert "target: app" in ninja[0].evidence


def test_github_actions_workflow_extracts_nested_jobs(tmp_path: Path):
    path = tmp_path / "ci.yml"
    path.write_text(
        "name: CI\non: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n"
        "  tests:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    record = FileRecord(".github/workflows/ci.yml", path.stat().st_size, ".yml", "YAML")
    analyzer = BuildManifestAnalyzer()
    assert analyzer.supports(record)
    findings = analyzer.analyze(path, record)
    assert "job: lint" in findings[0].evidence
    assert "job: tests" in findings[0].evidence


def test_build_supports_more_ecosystem_manifests(tmp_path: Path):
    analyzer = BuildManifestAnalyzer()
    for filename in (
        "SConstruct", "MODULE.bazel", "BUCK", "azure-pipelines.yml",
        "Jenkinsfile", "build.zig", "conanfile.py", "Package.swift",
        "Core.fsproj", "Makefile.am", "Taskfile.yaml",
    ):
        record = FileRecord(filename, 1, Path(filename).suffix.lower(), "Build")
        assert analyzer.supports(record), filename
