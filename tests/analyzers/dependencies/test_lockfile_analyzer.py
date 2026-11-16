import json
from pathlib import Path

from project_discovery.analyzers.dependencies.lockfiles import LockfileAnalyzer
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
        'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
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


def test_scoped_yarn_dependency_name_is_preserved(tmp_path: Path):
    findings = _scan(
        tmp_path, "yarn.lock",
        '"@babel/core@^7.0.0":\n  version "7.26.0"\n',
    )
    assert "@babel/core==7.26.0" in findings[0].evidence


def test_pnpm_lock_extracts_package_entries(tmp_path: Path):
    findings = _scan(
        tmp_path, "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  react@18.2.0:\n    resolution: {}\n",
    )
    assert "react==18.2.0" in findings[0].evidence


def test_mix_lock_extracts_hex_package_version(tmp_path: Path):
    findings = _scan(
        tmp_path, "mix.lock",
        '"decimal": {:hex, :decimal, "2.1.1", "checksum", [:mix], [], "hexpm", "checksum"},\n',
    )
    assert "decimal==2.1.1" in findings[0].evidence

def test_lockfile_analyzer_detects_growth_after_inventory(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.dependencies import lockfiles as lockfile_analyzer

    path = tmp_path / "growing-lock.json"
    path.write_text('{"dependencies":{"express":"^4.0.0"}}', encoding="utf-8")
    monkeypatch.setattr(lockfile_analyzer, "_MAX_LOCKFILE_INVENTORY_BYTES", 8)
    record = FileRecord(path.name, 1, ".json", "Lockfile")
    findings = LockfileAnalyzer().analyze(path, record)
    assert findings[0].confidence == "UNKNOWN"
    assert "grew beyond" in findings[0].detail


def test_lockfile_inventory_reports_package_entry_cap_as_unknown(tmp_path: Path, monkeypatch):
    from project_discovery.analyzers.dependencies import lockfiles as lockfile_analyzer

    monkeypatch.setattr(lockfile_analyzer, "_MAX_LOCKFILE_PACKAGE_ENTRIES", 1)
    findings = _scan(
        tmp_path,
        "package-lock.json",
        json.dumps({
            "packages": {
                "node_modules/alpha": {"version": "1.0.0"},
                "node_modules/beta": {"version": "2.0.0"},
            }
        }),
    )
    assert len(findings) == 1
    assert findings[0].confidence == "UNKNOWN"
    assert "package entry budget" in findings[0].detail
