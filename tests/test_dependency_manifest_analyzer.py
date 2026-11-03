import json
from pathlib import Path

from project_discovery.analyzers.dependency_manifest_analyzer import (
    DependencyManifestAnalyzer,
)
from project_discovery.models import FileRecord


def _analyze(tmp_path: Path, name: str, content: str):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, path.suffix, "Configuration")
    analyzer = DependencyManifestAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_pyproject_extracts_runtime_and_optional_dependencies(tmp_path: Path):
    findings = _analyze(
        tmp_path,
        "pyproject.toml",
        '[project]\ndependencies = ["rich>=13", "httpx[http2]>=0.27"]\n'
        '[project.optional-dependencies]\ntest = ["pytest>=8"]\n',
    )
    names = {item.title for item in findings}
    assert names == {
        "Declared dependency: rich",
        "Declared dependency: httpx",
        "Declared dependency: pytest",
    }
    assert all(item.confidence == "CONFIRMED" for item in findings)
    assert all("not installation or runtime use" in item.detail for item in findings)


def test_package_json_reads_dependency_groups(tmp_path: Path):
    payload = {
        "dependencies": {"react": "^18.0.0"},
        "devDependencies": {"vite": "^5.0.0"},
    }
    findings = _analyze(tmp_path, "package.json", json.dumps(payload))
    assert {item.title for item in findings} == {
        "Declared dependency: react",
        "Declared dependency: vite",
    }


def test_requirements_and_go_mod_are_supported(tmp_path: Path):
    requirements = _analyze(
        tmp_path, "requirements-dev.txt", "pytest>=8\n# comment\n-r base.txt\n"
    )
    assert [item.title for item in requirements] == ["Declared dependency: pytest"]

    go = _analyze(
        tmp_path, "go.mod",
        "module example.com/app\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n",
    )
    assert [item.title for item in go] == [
        "Declared dependency: github.com/pkg/errors"
    ]


def test_malformed_manifest_is_unknown_not_a_crash(tmp_path: Path):
    findings = _analyze(tmp_path, "package.json", "{invalid")
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert findings[0].title == "Dependency manifest parse error"


def test_maven_and_dotnet_xml_manifests_are_supported(tmp_path: Path):
    maven = _analyze(
        tmp_path, "pom.xml",
        '<project><dependencies><dependency><groupId>org.slf4j</groupId>'
        '<artifactId>slf4j-api</artifactId><version>2.0.12</version>'
        '<scope>runtime</scope></dependency></dependencies></project>',
    )
    dotnet = _analyze(
        tmp_path, "App.csproj",
        '<Project><ItemGroup><PackageReference Include="Serilog" Version="3.1.1" />'
        '</ItemGroup></Project>',
    )
    assert any("org.slf4j:slf4j-api" in item.title for item in maven)
    assert any("Serilog" in item.title for item in dotnet)


def test_gradle_and_swift_package_manifests_are_supported(tmp_path: Path):
    gradle = _analyze(
        tmp_path, "build.gradle.kts",
        'dependencies {\n implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.0")\n'
        ' testImplementation("junit:junit:4.13.2")\n}\n',
    )
    swift = _analyze(
        tmp_path, "Package.swift",
        '.package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),\n',
    )
    assert any("org.jetbrains.kotlin:kotlin-stdlib" in item.title for item in gradle)
    assert any("junit:junit" in item.title for item in gradle)
    assert any("swift-collections" in item.title for item in swift)


def test_dart_ruby_and_elixir_manifests_are_supported(tmp_path: Path):
    dart = _analyze(
        tmp_path, "pubspec.yaml",
        "name: sample\ndependencies:\n  http: ^1.2.0\ndev_dependencies:\n  test: ^1.25.0\n",
    )
    ruby = _analyze(
        tmp_path, "Gemfile",
        'source "https://rubygems.org"\ngem "rails", "~> 7.1"\ngem "puma"\n',
    )
    elixir = _analyze(
        tmp_path, "mix.exs",
        'defp deps do\n  [{:phoenix, "~> 1.7"}, {:plug, "~> 1.15"}]\nend\n',
    )
    assert any("http" in item.title for item in dart)
    assert any("test" in item.title for item in dart)
    assert any("rails" in item.title for item in ruby)
    assert any("phoenix" in item.title for item in elixir)


def test_julia_r_and_cmake_manifests_are_supported(tmp_path: Path):
    julia = _analyze(
        tmp_path, "Project.toml",
        '[deps]\nDataFrames = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"\n'
        '[compat]\nDataFrames = "1.6"\n',
    )
    r = _analyze(
        tmp_path, "DESCRIPTION",
        "Package: sample\nImports:\n  dplyr, ggplot2 (>= 3.5)\nSuggests: testthat\n",
    )
    cmake = _analyze(
        tmp_path, "CMakeLists.txt",
        "find_package(Qt6 6.5 REQUIRED COMPONENTS Core)\n"
        "FetchContent_Declare(fmt URL https://example.invalid/fmt.tar.gz)\n",
    )
    assert any("DataFrames" in item.title for item in julia)
    assert any("dplyr" in item.title for item in r)
    assert any("Qt6" in item.title for item in cmake)
    assert any("fmt" in item.title for item in cmake)


def test_clojure_scala_and_conan_manifests_are_supported(tmp_path: Path):
    clojure = _analyze(
        tmp_path, "deps.edn",
        '{:deps {org.clojure/clojure {:mvn/version "1.11.1"}}}',
    )
    scala = _analyze(
        tmp_path, "build.sbt",
        'libraryDependencies += "org.scala-lang" %% "scala3-library" % "3.3.3"\n',
    )
    conan = _analyze(
        tmp_path, "conanfile.txt",
        "[requires]\nfmt/10.2.1\n",
    )
    assert any("org.clojure/clojure" in item.title for item in clojure)
    assert any("org.scala-lang:scala3-library" in item.title for item in scala)
    assert any("fmt" in item.title for item in conan)


def test_ros_manifest_and_malformed_xml_are_supported(tmp_path: Path):
    ros = _analyze(
        tmp_path, "package.xml",
        '<package><name>robot</name><depend>rclcpp</depend>'
        '<exec_depend>sensor_msgs</exec_depend></package>',
    )
    malformed = _analyze(tmp_path, "pom.xml", "<project><dependencies>")
    assert any("rclcpp" in item.title for item in ros)
    assert any("sensor_msgs" in item.title for item in ros)
    assert malformed[0].confidence == "UNKNOWN"


def test_rebar_platformio_and_lua_rockspec_manifests_are_supported(tmp_path: Path):
    rebar = _analyze(
        tmp_path, "rebar.config",
        '{deps, [{cowboy, "2.10.0"}, {jsx, "3.1.0"}]}.\n',
    )
    platformio = _analyze(
        tmp_path, "platformio.ini",
        "[env:native]\nlib_deps =\n  knolleary/PubSubClient@^2.8\n"
        "  bblanchon/ArduinoJson@^6.21\n",
    )
    rockspec = _analyze(
        tmp_path, "sample-1.0-1.rockspec",
        'dependencies = { "lua >= 5.1", "luasocket >= 3.0" }\n',
    )
    assert any("cowboy" in item.title for item in rebar)
    assert any("PubSubClient" in item.title for item in platformio)
    assert any("ArduinoJson" in item.title for item in platformio)
    assert any("luasocket" in item.title for item in rockspec)


def test_ruby_gemspec_dependencies_are_extracted(tmp_path: Path):
    findings = _analyze(
        tmp_path, "sample.gemspec",
        'spec.add_dependency "rack", ">= 3.0"\n'
        'spec.add_development_dependency "rspec", "~> 3.13"\n',
    )
    assert any("rack" in item.title for item in findings)
    assert any("rspec" in item.title for item in findings)
