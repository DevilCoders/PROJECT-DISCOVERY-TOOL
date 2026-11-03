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
