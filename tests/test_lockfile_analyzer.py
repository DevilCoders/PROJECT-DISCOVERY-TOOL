import json
from pathlib import Path

from project_discovery.analyzers.lockfile_analyzer import LockfileAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, content: str):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    record = FileRecord(filename, path.stat().st_size, path.suffix, "Lockfile")
    analyzer = LockfileAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_package_lock_extracts_resolved_versions(tmp_path: Path):
    findings = _scan(
        tmp_path, "package-lock.json",
        json.dumps({
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/react": {"name": "react", "version": "18.2.0"},
                "node_modules/vite": {"name": "vite", "version": "5.0.0"},
            }
        }),
    )
    assert "2 package/version entries" in findings[0].detail
    assert "react==18.2.0" in findings[0].evidence


def test_cargo_lock_extracts_packages(tmp_path: Path):
    findings = _scan(
        tmp_path, "Cargo.lock",
        'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.0"\n',
    )
    assert "serde==1.0.0" in findings[0].evidence


def test_go_sum_extracts_module_versions(tmp_path: Path):
    findings = _scan(
        tmp_path, "go.sum",
        "github.com/pkg/errors v0.9.1 h1:hash\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:hash\n",
    )
    assert "github.com/pkg/errors==v0.9.1" in findings[0].evidence


def test_malformed_lockfile_is_unknown(tmp_path: Path):
    findings = _scan(tmp_path, "package-lock.json", "{")
    assert findings[0].confidence == "UNKNOWN"
