"""Development-tree markers: the catalog, evidence and confidence, and --exclude-profile."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_discovery.inventory.markers import (
    CATEGORIES,
    PROFILES,
    SPECS,
    detect_marker,
    normalize_profiles,
    profile_match,
)


def _entries(*names: str):
    present = set(names)
    return lambda entry: entry in present


# (directory name, entries inside, entries beside, key, category, ecosystem, confidence)
CASES = [
    ("node_modules", (".package-lock.json",), (), "node_modules", "dependencies", "npm/pnpm/Yarn/Bun", "confirmed"),
    ("node_modules", (".modules.yaml",), (), "node_modules", "dependencies", "npm/pnpm/Yarn/Bun", "confirmed"),
    ("node_modules", (), (), "node_modules", "dependencies", "npm/pnpm/Yarn/Bun", "name"),
    (".yarn", ("cache",), (), ".yarn", "cache", "Yarn", "confirmed"),
    (".pnpm-store", (), (), ".pnpm-store", "cache", "pnpm", "name"),
    (".bun", ("install",), (), ".bun", "cache", "Bun", "confirmed"),
    (".venv", ("pyvenv.cfg",), (), ".venv", "dependencies", "Python virtual environment", "confirmed"),
    ("env", ("conda-meta",), (), "env", "dependencies", "conda environment", "confirmed"),
    ("pypoetry", ("virtualenvs",), (), "pypoetry", "cache", "Poetry", "confirmed"),
    ("pkgs", ("urls.txt",), (), "pkgs", "cache", "conda package cache", "confirmed"),
    ("target", (), ("pom.xml",), "target", "build", "Maven", "confirmed"),
    ("target", ("CACHEDIR.TAG",), (), "target", "build", "Cargo", "confirmed"),
    ("target", (), ("Cargo.toml",), "target", "build", "Cargo", "confirmed"),
    (".m2", ("repository",), (), ".m2", "cache", "Maven local repository", "confirmed"),
    (".gradle", (), ("settings.gradle.kts",), ".gradle", "cache", "Gradle", "confirmed"),
    ("build", (), ("build.gradle",), "build", "build", "Gradle", "confirmed"),
    (".cargo", ("registry",), (), ".cargo", "cache", "Cargo", "confirmed"),
    ("vendor", ("modules.txt",), (), "vendor", "dependencies", "Go modules", "confirmed"),
    ("pkg", ("mod/cache",), (), "pkg", "cache", "Go module cache", "confirmed"),
    ("packages", ("repositories.config",), (), "packages", "dependencies", "NuGet", "confirmed"),
    (".nuget", ("packages",), (), ".nuget", "cache", "NuGet", "confirmed"),
    ("vendor", ("autoload.php",), (), "vendor", "dependencies", "Composer", "confirmed"),
    ("vendor", ("bundle",), ("Gemfile",), "vendor", "dependencies", "Bundler", "confirmed"),
    (".build", (), ("Package.swift",), ".build", "build", "SwiftPM", "confirmed"),
    ("Pods", ("Manifest.lock",), (), "pods", "dependencies", "CocoaPods", "confirmed"),
    (".dart_tool", (), ("pubspec.yaml",), ".dart_tool", "cache", "Dart", "confirmed"),
    ("build", (), ("pubspec.yaml",), "build", "build", "Flutter", "confirmed"),
    ("obj", ("project.assets.json",), (), "obj", "build", ".NET/MSBuild", "confirmed"),
    ("bin", ("Release",), (), "bin", "build", ".NET/MSBuild", "confirmed"),
    ("bazel-out", (), (), "bazel-out", "build", "Bazel", "name"),
    ("buck-out", (), (), "buck-out", "build", "Buck", "name"),
    (".pants.d", (), (), ".pants.d", "build", "Pants", "name"),
    (".sconf_temp", (), (), ".sconf_temp", "build", "SCons", "name"),
    ("build", ("CMakeCache.txt",), (), "build", "build", "CMake", "confirmed"),
    ("cmake-build-debug", (), (), "cmake-build-*", "build", "CLion (CMake)", "name"),
    ("CMakeFiles", (), (), "cmakefiles", "build", "CMake", "name"),
    ("_deps", (), (), "_deps", "dependencies", "CMake FetchContent", "name"),
    (".idea", (), (), ".idea", "ide", "JetBrains IDEs", "name"),
    (".vs", (), (), ".vs", "ide", "Visual Studio", "name"),
    (".ccache", (), (), ".ccache", "cache", "ccache", "name"),
    ("__pycache__", (), (), "__pycache__", "cache", "Python bytecode", "name"),
    ("corpus", (), (), "corpus", "fuzzing", "fuzzing corpus", "possible"),
    ("queue", (), ("fuzzer_stats",), "queue", "fuzzing", "AFL", "confirmed"),
    ("fuzz", ("fuzz_targets",), (), "fuzz", "fuzzing", "cargo-fuzz", "confirmed"),
    ("huggingface", ("hub",), (), "huggingface", "models", "Hugging Face cache", "confirmed"),
    (".ollama", (), (), ".ollama", "models", "Ollama", "name"),
    ("mlruns", (), (), "mlruns", "models", "MLflow", "name"),
    (".clangd", (), (), ".clangd", "cache", "clangd (language server)", "name"),
    (".metals", (), (), ".metals", "cache", "Metals (Scala language server)", "name"),
    (".git", ("HEAD",), (), ".git", "vcs", "Git", "confirmed"),
    ("foo.egg-info", (), (), "*.egg-info", "build", "setuptools metadata", "name"),
]


@pytest.mark.parametrize(("name", "inside", "beside", "key", "category", "ecosystem", "confidence"), CASES,
                         ids=[f"{case[0]}-{case[-1]}" for case in CASES])
def test_markers_are_identified_with_their_ecosystem_and_confidence(name, inside, beside, key, category, ecosystem,
                                                                    confidence):
    marker = detect_marker(name, _entries(*inside), _entries(*beside))
    assert (marker.key, marker.category, marker.ecosystem, marker.confidence) == (key, category, ecosystem, confidence)
    if confidence == "confirmed":
        assert marker.evidence in {*inside, *(f"../{entry}" for entry in beside)}


def test_common_names_are_possible_until_something_confirms_them():
    for name in ("build", "dist", "out", "target", "vendor", "coverage", "tmp", "generated", "third_party"):
        marker = detect_marker(name, _entries(), _entries())
        assert marker.confidence == "possible" and not marker.actionable, name
    # The ecosystem of a common name with several possible owners is unknown until confirmed.
    assert detect_marker("vendor", _entries(), _entries()).ecosystem is None
    assert detect_marker("build", _entries(), _entries()).ecosystem is None
    # Names that are mostly project source are not marked at all without evidence.
    for name in ("packages", "bin", "env", "deps", "go", "pkg", "gradle", "site", "library", "torch", "queue"):
        assert detect_marker(name, _entries(), _entries()) is None, name
    assert detect_marker("deps", _entries(), _entries("mix.exs")).ecosystem == "Mix (Elixir)"
    assert detect_marker("src", _entries(), _entries()) is None


def test_the_catalog_names_every_category_and_casefolded_keys():
    assert {spec.category for spec in SPECS} == set(CATEGORIES)
    assert all(spec.key == spec.key.casefold() for spec in SPECS)
    assert all(spec.strength in {"name", "possible", "evidence"} for spec in SPECS)
    # Evidence-only specs must have evidence to look for.
    assert all(spec.inside or spec.beside for spec in SPECS if spec.strength == "evidence")
    assert set(PROFILES["all"]) == set(CATEGORIES)


def test_profiles_prune_confirmed_and_named_trees_only():
    confirmed = detect_marker("node_modules", _entries(".package-lock.json"), _entries())
    named = detect_marker("__pycache__")
    possible = detect_marker("vendor")
    key, reason = profile_match(confirmed, frozenset({"dependencies"}))
    assert key == "exclusion_used:profile:dependencies"
    assert reason == ("--exclude-profile dependencies: node_modules: dependencies (npm/pnpm/Yarn/Bun), "
                      "confirmed by .package-lock.json")
    assert profile_match(named, frozenset({"caches"}))[1].endswith("__pycache__: cache (Python bytecode), by its name")
    assert profile_match(possible, frozenset({"dependencies", "all"})) is None
    assert profile_match(confirmed, frozenset({"caches"})) is None
    assert profile_match(None, frozenset({"all"})) is None
    assert normalize_profiles(["dependencies,Caches", " build "]) == {"dependencies", "caches", "build"}
    with pytest.raises(ValueError, match="unknown profile; choose from vcs, dependencies"):
        normalize_profiles(["deps"])


def _tree(root: Path) -> Path:
    root.mkdir()
    for directory in ("node_modules/left-pad", "vendor/lib", "build", "target", "src/.venv", "src/__pycache__",
                      ".git/objects", "tools/env"):
        (root / directory).mkdir(parents=True)
    (root / "node_modules" / ".package-lock.json").write_text("{}", encoding="utf-8")
    (root / "node_modules" / "left-pad" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (root / "Cargo.toml").write_text("[package]\nname = 'x'\n", encoding="utf-8")
    (root / "src" / ".venv" / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (root / "vendor" / "lib" / "code.go").write_text("package lib\n", encoding="utf-8")
    (root / "build" / "notes.txt").write_text("a project directory named build\n", encoding="utf-8")
    return root


def _walkers(monkeypatch):
    from project_discovery.inventory import scanner

    yield "native"
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    yield "python"


def test_both_walkers_record_marker_categories_confidence_and_evidence(tmp_path: Path, monkeypatch):
    from project_discovery.inventory.scanner import discover_inventory

    project = _tree(tmp_path / "project")
    for walker in _walkers(monkeypatch):
        _, directories, *_, stats = discover_inventory(project)
        marked = {
            item.path: (item.development_marker, item.marker_category, item.marker_confidence, item.marker_evidence)
            for item in directories if item.development_marker
        }
        assert marked == {
            "node_modules": ("node_modules", "dependencies", "confirmed", ".package-lock.json"),
            "target": ("target", "build", "confirmed", "../Cargo.toml"),
            "vendor": ("vendor", "dependencies", "confirmed", "../Cargo.toml"),
            "build": ("build", "build", "possible", None),
            "src/.venv": (".venv", "dependencies", "confirmed", "pyvenv.cfg"),
            "src/__pycache__": ("__pycache__", "cache", "name", None),
            ".git": (".git", "vcs", "confirmed", "HEAD"),
        }, walker
        assert stats["development_confidence:confirmed"] == 5 and stats["development_confidence:possible"] == 1
        assert stats["development_category:dependencies"] == 3


def test_exclude_profiles_prune_presets_and_keep_possible_trees(tmp_path: Path, monkeypatch):
    from project_discovery.inventory.scanner import discover_inventory

    project = _tree(tmp_path / "project")
    for walker in _walkers(monkeypatch):
        files, directories, *_, stats = discover_inventory(project, exclude_profiles=frozenset({"dependencies", "vcs"}))
        pruned = {item.path: item.prune_reason for item in directories if item.pruned}
        assert set(pruned) == {"node_modules", "vendor", "src/.venv", ".git"}, walker
        assert pruned["node_modules"].startswith("--exclude-profile dependencies: node_modules: dependencies")
        assert pruned[".git"] == "--exclude-profile vcs: .git: vcs (Git), confirmed by HEAD"
        paths = {item.path for item in files}
        assert "node_modules/left-pad/index.js" not in paths and "vendor/lib/code.go" not in paths
        # A possible marker (a project directory named build) is never pruned by a preset.
        assert "build/notes.txt" in paths
        assert stats["exclusion_used:profile:dependencies"] == 3 and stats["exclusion_used:profile:vcs"] == 1


def test_exclude_profile_reaches_reports_resume_options_and_usage_errors(tmp_path: Path, capsys):
    from project_discovery.cli import main, run_scan

    project = _tree(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown"}, 128, quiet=True, exclude_profiles={"dependencies"}) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    metrics = report["metrics"]
    assert metrics["pruned_by_profile"] == {"dependencies": 3}
    assert metrics["development_confidence"] == {"confirmed": 5, "name": 1, "possible": 1}
    assert metrics["development_categories"]["build"] == 2
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- Development/cache trees: 7 (5 confirmed, 1 by name, 1 possible)" in markdown
    assert "- Pruned by --exclude-profile: dependencies 3" in markdown
    assert "node_modules — " in markdown and "[node_modules: dependencies, confirmed by .package-lock.json] [pruned]" in markdown
    # --resume continues only an inventory made with the same presets.
    import sys

    argv = sys.argv
    try:
        sys.argv = ["pdt", "scan", str(project), "--output", str(output), "--resume", "--quiet",
                    "--exclude-profile", "caches"]
        with pytest.raises(SystemExit) as exit_info:
            main()
        assert exit_info.value.code == 2
        assert "--exclude-profile: stored dependencies, now caches" in " ".join(capsys.readouterr().err.split())
        sys.argv = ["pdt", "scan", str(project), "--output", str(tmp_path / "other"), "--quiet",
                    "--exclude-profile", "node"]
        with pytest.raises(SystemExit) as exit_info:
            main()
        assert exit_info.value.code == 2
        assert "--exclude-profile node: unknown profile" in " ".join(capsys.readouterr().err.split())
    finally:
        sys.argv = argv
