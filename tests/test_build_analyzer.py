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



def test_scons_visual_studio_qmake_and_jenkins_targets(tmp_path: Path):
    scons = _scan(tmp_path, "SConstruct", "Program('agent', ['main.c'])\n")
    solution = _scan(
        tmp_path, "Core.sln",
        'Project("{GUID}") = "Core", "Core.csproj", "{PROJECT}"\nEndProject\n',
    )
    qmake = _scan(tmp_path, "widget.pro", "TEMPLATE = app\nTARGET = widget\n")
    jenkins = _scan(
        tmp_path, "Jenkinsfile",
        "pipeline { stages { stage('Build') {} stage('Test') {} } }\n",
    )
    assert "target: agent" in scons[0].evidence
    assert "project: Core" in solution[0].evidence
    assert "target: widget" in qmake[0].evidence
    assert "stage: Build" in jenkins[0].evidence
    assert "stage: Test" in jenkins[0].evidence


def test_ci_taskfile_autotools_and_gradle_targets(tmp_path: Path):
    azure = _scan(
        tmp_path, "azure-pipelines.yml",
        "trigger:\n- main\njobs:\n- job: Build\n- job: Test\n",
    )
    taskfile = _scan(
        tmp_path, "Taskfile.yaml",
        "version: '3'\ntasks:\n  build:\n    cmds: []\n  test:\n    cmds: []\n",
    )
    autotools = _scan(
        tmp_path, "Makefile.am",
        "AM_INIT_AUTOMAKE([foreign])\nAC_CONFIG_FILES([Makefile])\n",
    )
    gradle = _scan(
        tmp_path, "build.gradle.kts",
        "tasks.register(\"compileKotlin\") {}\ntask(\"test\") {}\n",
    )
    assert "job: Build" in azure[0].evidence
    assert "job: Test" in azure[0].evidence
    assert "task: build" in taskfile[0].evidence
    assert "task: test" in taskfile[0].evidence
    assert "build macro: AM_INIT_AUTOMAKE" in autotools[0].evidence
    assert "task: compileKotlin" in gradle[0].evidence
    assert "task: test" in gradle[0].evidence


def test_generic_build_manifests_and_mix_dependencies(tmp_path: Path):
    setup = _scan(tmp_path, "setup.py", "from setuptools import setup\nsetup(name='sample')\n")
    mix = _scan(
        tmp_path, "mix.exs",
        'defp deps do\n  [{:phoenix, "~> 1.7"}]\nend\n',
    )
    assert "recognized build ecosystem manifest: setup.py" in setup[0].detail
    assert "Elixir task: phoenix" in mix[0].evidence

def test_build_manifest_reports_oversized_and_growing_source_as_unknown(tmp_path: Path, monkeypatch):
    import project_discovery.analyzers.build_analyzer as module

    path = tmp_path / "Makefile"
    path.write_text("all: build\nbuild: test\n", encoding="utf-8")
    monkeypatch.setattr(module, "_MAX_BUILD_MANIFEST_BYTES", 8)
    record = FileRecord(path.name, 1, "", "Build")
    findings = BuildManifestAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_build_manifest_reports_growth_as_unknown_and_redacts_parse_errors(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers import build_analyzer

    path = tmp_path / "package.json"
    path.write_text('{"name":"sample","scripts":{"build":"webpack"}}', encoding="utf-8")
    record = FileRecord(path.name, 1, ".json", "JSON")
    monkeypatch.setattr(build_analyzer, "_MAX_BUILD_MANIFEST_BYTES", 8)
    budget = BuildManifestAnalyzer().analyze(path, record)
    assert len(budget) == 1 and budget[0].confidence == "UNKNOWN"
    assert "resource limit" in budget[0].title.lower()

    monkeypatch.setattr(build_analyzer, "_MAX_BUILD_MANIFEST_BYTES", 1024)
    monkeypatch.setattr(
        build_analyzer.json, "loads",
        lambda _: (_ for _ in ()).throw(ValueError('token="build-parser-secret"')),
    )
    error = BuildManifestAnalyzer().analyze(path, record)
    assert error[0].confidence == "UNKNOWN"
    assert "build-parser-secret" not in error[0].detail
