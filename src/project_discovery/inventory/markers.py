"""Development, dependency, build and cache trees: a catalog of directory markers.

A directory is marked by its name, and each marker says how sure that is:

- ``confirmed``: an entry that only that kind of tree has was found inside the directory or
  next to it (``pyvenv.cfg`` in a virtual environment, ``CACHEDIR.TAG`` in a Cargo ``target``,
  a ``Cargo.toml`` beside it);
- ``name``: the name is distinctive on its own (``node_modules``, ``__pycache__``, ``.gradle``);
- ``possible``: a common name (``build``, ``vendor``, ``dist``) without that evidence, so the
  directory may well be project source.

Some names are marked only with evidence (``packages``, ``bin``, ``env``, ``deps``): as
project source they are too common to flag at all. Profiles (``--exclude-profile``) and
development-tree modes act on ``confirmed`` and ``name`` markers only, never on ``possible``
ones, so a project's own ``build/`` or ``vendor/`` source is never pruned by a preset.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# A stored inventory marked with another catalog version is not resumed.
CATALOG_VERSION = 1
CONFIDENCES = ("confirmed", "name", "possible")
# Markers that presets and development-tree modes act on.
ACTIONABLE = frozenset({"confirmed", "name"})
CATEGORIES = (
    "vcs", "dependencies", "build", "generated", "cache", "ide", "test-output", "fuzzing", "models",
)
# --development-trees: what happens inside the confirmed and distinctively named trees that
# no option pruned. deep: inventoried and analyzed like any other directory; inventory: every
# entry is recorded but no file content is read; directory-only: only directories are
# recorded, and their files, links and special entries are counted in the directory totals.
TREE_MODES = ("deep", "inventory", "directory-only")
# --exclude-profile presets: the marker categories each one prunes.
PROFILES: dict[str, frozenset[str]] = {
    "vcs": frozenset({"vcs"}),
    "dependencies": frozenset({"dependencies"}),
    "build": frozenset({"build", "generated"}),
    "caches": frozenset({"cache"}),
    "ide": frozenset({"ide"}),
    "test-output": frozenset({"test-output"}),
    "fuzzing": frozenset({"fuzzing"}),
    "models": frozenset({"models"}),
    "all": frozenset(CATEGORIES),
}


@dataclass(frozen=True, slots=True)
class Marker:
    """What a directory is, and how sure that is."""

    key: str  # the catalog entry: the casefolded name, or a pattern such as "cmake-build-*"
    category: str
    ecosystem: str | None  # None for a possible marker whose ecosystem nothing confirmed
    confidence: str  # confirmed, name or possible
    evidence: str | None = None  # the entry that confirmed it: "pyvenv.cfg", "../Cargo.toml"

    @property
    def actionable(self) -> bool:
        return self.confidence in ACTIONABLE


@dataclass(frozen=True, slots=True)
class _Spec:
    key: str
    category: str
    ecosystem: str
    inside: tuple[str, ...] = ()
    beside: tuple[str, ...] = ()
    # "name": distinctive; "possible": common, marked unconfirmed; "evidence": marked only with evidence
    strength: str = "name"


def _s(key: str, category: str, ecosystem: str, *, inside: tuple[str, ...] = (), beside: tuple[str, ...] = (),
       strength: str = "name") -> _Spec:
    return _Spec(key, category, ecosystem, inside, beside, strength)


_GRADLE_BUILD = ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")

# Specs are tried in order: the first whose evidence is found confirms the directory.
SPECS: tuple[_Spec, ...] = (
    # Version control
    _s(".git", "vcs", "Git", inside=("HEAD", "objects")),
    _s(".hg", "vcs", "Mercurial", inside=("store", "requires")),
    _s(".svn", "vcs", "Subversion", inside=("wc.db", "entries")),
    _s(".bzr", "vcs", "Bazaar", inside=("branch-format",)),
    _s("_darcs", "vcs", "Darcs", inside=("format",)),
    _s("cvs", "vcs", "CVS", inside=("Root", "Entries"), strength="possible"),
    # Installed dependencies and environments
    _s("node_modules", "dependencies", "npm/pnpm/Yarn/Bun",
       inside=(".package-lock.json", ".modules.yaml", ".yarn-state.yml", ".pnpm"), beside=("package.json",)),
    _s("bower_components", "dependencies", "Bower", beside=("bower.json",)),
    _s("jspm_packages", "dependencies", "jspm"),
    _s(".venv", "dependencies", "Python virtual environment", inside=("pyvenv.cfg",)),
    _s("venv", "dependencies", "Python virtual environment", inside=("pyvenv.cfg",)),
    _s("env", "dependencies", "Python virtual environment", inside=("pyvenv.cfg",), strength="evidence"),
    _s("env", "dependencies", "conda environment", inside=("conda-meta",), strength="evidence"),
    _s(".conda", "dependencies", "conda environments"),
    _s("site-packages", "dependencies", "Python packages"),
    _s("dist-packages", "dependencies", "Python packages"),
    _s("__pypackages__", "dependencies", "PDM (PEP 582)"),
    _s(".tox", "dependencies", "tox environments", beside=("tox.ini",)),
    _s(".nox", "dependencies", "nox sessions", beside=("noxfile.py",)),
    _s(".eggs", "dependencies", "setuptools"),
    _s("vendor", "dependencies", "Go modules", inside=("modules.txt",), beside=("go.mod",), strength="possible"),
    _s("vendor", "dependencies", "Composer", inside=("autoload.php", "composer"), beside=("composer.json",),
       strength="possible"),
    _s("vendor", "dependencies", "Bundler", inside=("bundle",), beside=("Gemfile",), strength="possible"),
    _s("vendor", "dependencies", "Cargo vendor", beside=("Cargo.toml",), strength="possible"),
    _s(".bundle", "dependencies", "Bundler", inside=("ruby",), strength="possible"),
    _s("pods", "dependencies", "CocoaPods", inside=("Manifest.lock",), beside=("Podfile",)),
    _s("carthage", "dependencies", "Carthage", inside=("Checkouts", "Build"), beside=("Cartfile",)),
    _s("packages", "dependencies", "NuGet", inside=("repositories.config",), beside=("packages.config",),
       strength="evidence"),
    _s("deps", "dependencies", "Mix (Elixir)", beside=("mix.exs", "mix.lock"), strength="evidence"),
    _s("_deps", "dependencies", "CMake FetchContent"),
    _s("elm-stuff", "dependencies", "Elm"),
    _s("_opam", "dependencies", "opam"),
    _s(".terraform", "dependencies", "Terraform providers and modules", inside=("providers", "modules")),
    _s("third_party", "dependencies", "vendored third-party code", strength="possible"),
    _s("third-party", "dependencies", "vendored third-party code", strength="possible"),
    # Build output
    _s("build", "build", "CMake", inside=("CMakeCache.txt",), beside=("CMakeLists.txt",), strength="possible"),
    _s("build", "build", "Meson/Ninja", inside=("build.ninja", "meson-info"), beside=("meson.build",),
       strength="possible"),
    _s("build", "build", "Gradle", beside=_GRADLE_BUILD, strength="possible"),
    _s("build", "build", "Flutter", beside=("pubspec.yaml",), strength="possible"),
    _s("build", "build", "setuptools", beside=("setup.py",), strength="possible"),
    _s("dist", "build", "Python distributions", beside=("setup.py", "pyproject.toml"), strength="possible"),
    _s("dist", "build", "JavaScript bundles", beside=("package.json",), strength="possible"),
    _s("out", "build", "IntelliJ IDEA", inside=("production",), strength="possible"),
    _s("target", "build", "Cargo", inside=("CACHEDIR.TAG", ".rustc_info.json"), beside=("Cargo.toml",),
       strength="possible"),
    _s("target", "build", "Maven", inside=("maven-status", "maven-archiver"), beside=("pom.xml",),
       strength="possible"),
    _s("target", "build", "sbt", inside=("streams",), beside=("build.sbt",), strength="possible"),
    _s("target", "build", "Leiningen", beside=("project.clj",), strength="possible"),
    _s("obj", "build", ".NET/MSBuild", inside=("project.assets.json",), strength="possible"),
    _s("bin", "build", ".NET/MSBuild", inside=("Debug", "Release"), strength="evidence"),
    _s("_build", "build", "Mix (Elixir)", beside=("mix.exs",), strength="possible"),
    _s("_build", "build", "dune (OCaml)", beside=("dune-project",), strength="possible"),
    _s("_build", "build", "Sphinx", inside=("doctrees",), strength="possible"),
    _s("_site", "build", "Jekyll", beside=("_config.yml",), strength="possible"),
    _s("site", "build", "MkDocs", beside=("mkdocs.yml",), strength="evidence"),
    _s("artifacts", "build", "build artifacts", strength="possible"),
    _s("maven", "build", "Maven", strength="possible"),
    _s("cmakefiles", "build", "CMake"),
    _s("cmake-build-*", "build", "CLion (CMake)"),
    _s("bazel-out", "build", "Bazel"),
    _s("bazel-bin", "build", "Bazel"),
    _s("bazel-testlogs", "build", "Bazel"),
    _s("bazel-genfiles", "build", "Bazel"),
    _s("buck-out", "build", "Buck"),
    _s(".pants.d", "build", "Pants"),
    _s(".sconf_temp", "build", "SCons"),
    _s("deriveddata", "build", "Xcode"),
    _s(".build", "build", "SwiftPM", inside=("checkouts", "repositories", "workspace-state.json"),
       beside=("Package.swift",)),
    _s(".next", "build", "Next.js"),
    _s(".nuxt", "build", "Nuxt"),
    _s(".output", "build", "Nuxt/Nitro"),
    _s(".svelte-kit", "build", "SvelteKit"),
    _s(".docusaurus", "build", "Docusaurus"),
    _s(".vercel", "build", "Vercel"),
    _s(".netlify", "build", "Netlify"),
    _s("storybook-static", "build", "Storybook"),
    _s(".serverless", "build", "Serverless Framework"),
    _s(".aws-sam", "build", "AWS SAM"),
    _s(".cxx", "build", "Android NDK"),
    _s(".externalnativebuild", "build", "Android NDK"),
    _s(".stack-work", "build", "Stack (Haskell)"),
    _s("dist-newstyle", "build", "Cabal (Haskell)"),
    _s("zig-out", "build", "Zig"),
    _s("*.egg-info", "build", "setuptools metadata"),
    # Generated code
    _s("generated", "generated", "generated code", strength="possible"),
    _s("generated_code", "generated", "generated code", strength="possible"),
    _s("__generated__", "generated", "Relay/GraphQL code generation"),
    # Caches
    _s(".cache", "cache", "tool caches"),
    _s("cache", "cache", "cache", strength="possible"),
    _s("caches", "cache", "cache", strength="possible"),
    _s("tmp", "cache", "temporary files", strength="possible"),
    _s("temp", "cache", "temporary files", strength="possible"),
    _s(".npm", "cache", "npm", inside=("_cacache",)),
    _s(".yarn", "cache", "Yarn", inside=("cache", "unplugged", "install-state.gz", "releases")),
    _s(".pnpm-store", "cache", "pnpm"),
    _s(".bun", "cache", "Bun", inside=("install",)),
    _s("pypoetry", "cache", "Poetry", inside=("virtualenvs", "cache"), strength="possible"),
    _s("pkgs", "cache", "conda package cache", inside=("urls.txt",), strength="evidence"),
    _s(".m2", "cache", "Maven local repository", inside=("repository",)),
    _s(".ivy2", "cache", "Ivy"),
    _s(".coursier", "cache", "Coursier"),
    _s(".sbt", "cache", "sbt"),
    _s(".gradle", "cache", "Gradle", beside=_GRADLE_BUILD),
    _s("gradle", "cache", "Gradle user home", inside=("caches",), strength="evidence"),
    _s(".cargo", "cache", "Cargo", inside=("registry", "git")),
    _s(".rustup", "cache", "rustup toolchains"),
    _s("go", "cache", "Go (GOPATH)", inside=("pkg/mod",), strength="evidence"),
    _s("pkg", "cache", "Go module cache", inside=("mod/cache",), strength="evidence"),
    _s(".nuget", "cache", "NuGet", inside=("packages",)),
    _s(".pub-cache", "cache", "Dart pub"),
    _s(".dart_tool", "cache", "Dart", beside=("pubspec.yaml",)),
    _s(".composer", "cache", "Composer"),
    _s(".gem", "cache", "RubyGems"),
    _s("__pycache__", "cache", "Python bytecode"),
    _s(".pytest_cache", "cache", "pytest"),
    _s(".mypy_cache", "cache", "mypy"),
    _s(".ruff_cache", "cache", "Ruff"),
    _s(".hypothesis", "cache", "Hypothesis"),
    _s(".ipynb_checkpoints", "cache", "Jupyter"),
    _s(".pyre", "cache", "Pyre"),
    _s(".pytype", "cache", "pytype"),
    _s(".ccache", "cache", "ccache"),
    _s(".sccache", "cache", "sccache"),
    _s("zig-cache", "cache", "Zig"),
    _s(".zig-cache", "cache", "Zig"),
    _s(".parcel-cache", "cache", "Parcel"),
    _s(".turbo", "cache", "Turborepo"),
    _s(".vite", "cache", "Vite"),
    _s(".webpack", "cache", "webpack"),
    _s(".angular", "cache", "Angular CLI"),
    _s(".nx", "cache", "Nx"),
    _s(".sass-cache", "cache", "Sass"),
    _s(".expo", "cache", "Expo"),
    _s(".kotlin", "cache", "Kotlin"),
    _s(".terragrunt-cache", "cache", "Terragrunt"),
    _s(".cpcache", "cache", "Clojure CLI"),
    _s(".shadow-cljs", "cache", "shadow-cljs"),
    _s(".clangd", "cache", "clangd (language server)"),
    _s(".ccls-cache", "cache", "ccls (language server)"),
    _s(".metals", "cache", "Metals (Scala language server)"),
    _s(".bloop", "cache", "Bloop (Scala build server)"),
    _s(".bsp", "cache", "Build Server Protocol"),
    _s(".lsp", "cache", "clojure-lsp (language server)"),
    _s(".elixir_ls", "cache", "ElixirLS (language server)"),
    _s(".sourcekit-lsp", "cache", "SourceKit-LSP (language server)"),
    _s(".ionide", "cache", "Ionide (F# language server)"),
    _s(".godot", "cache", "Godot"),
    _s(".import", "cache", "Godot 3"),
    _s("library", "cache", "Unity", beside=("ProjectSettings",), strength="evidence"),
    _s("deriveddatacache", "cache", "Unreal Engine"),
    # IDE and editor state
    _s(".idea", "ide", "JetBrains IDEs"),
    _s(".vscode", "ide", "VS Code"),
    _s(".vs", "ide", "Visual Studio"),
    _s(".fleet", "ide", "Fleet"),
    _s(".history", "ide", "editor local history"),
    _s(".swiftpm", "ide", "SwiftPM workspace"),
    _s("xcuserdata", "ide", "Xcode user data"),
    _s(".settings", "ide", "Eclipse", beside=(".project",), strength="evidence"),
    _s(".metadata", "ide", "Eclipse workspace", inside=(".plugins",), strength="evidence"),
    # Test output
    _s("coverage", "test-output", "coverage reports", strength="possible"),
    _s("htmlcov", "test-output", "coverage.py"),
    _s(".nyc_output", "test-output", "nyc/Istanbul"),
    _s("test-results", "test-output", "test results", strength="possible"),
    _s("allure-results", "test-output", "Allure"),
    _s("playwright-report", "test-output", "Playwright"),
    _s(".vscode-test", "test-output", "VS Code extension tests"),
    # Fuzzing
    _s(".fuff", "fuzzing", "fuzzing"),
    _s(".fuzz", "fuzzing", "fuzzing"),
    _s(".fuzzing", "fuzzing", "fuzzing"),
    _s("fuzz", "fuzzing", "cargo-fuzz", inside=("fuzz_targets",), strength="possible"),
    _s("corpus", "fuzzing", "fuzzing corpus", strength="possible"),
    _s("corpora", "fuzzing", "fuzzing corpora", strength="possible"),
    _s("crashers", "fuzzing", "go-fuzz", strength="possible"),
    _s("seeds", "fuzzing", "fuzzing seeds", strength="possible"),
    _s("crashes", "fuzzing", "AFL", beside=("fuzzer_stats",), strength="evidence"),
    _s("hangs", "fuzzing", "AFL", beside=("fuzzer_stats",), strength="evidence"),
    _s("queue", "fuzzing", "AFL", beside=("fuzzer_stats",), strength="evidence"),
    # Machine-learning models, datasets and experiment tracking
    _s("huggingface", "models", "Hugging Face cache", inside=("hub", "datasets", "modules"), strength="possible"),
    _s(".ollama", "models", "Ollama", inside=("models",)),
    _s(".keras", "models", "Keras", inside=("models", "datasets")),
    _s("torch", "models", "PyTorch hub", inside=("hub",), strength="evidence"),
    _s("tensorflow_datasets", "models", "TensorFlow Datasets"),
    _s("lightning_logs", "models", "PyTorch Lightning"),
    _s("mlruns", "models", "MLflow"),
    _s("mlartifacts", "models", "MLflow"),
    _s("wandb", "models", "Weights & Biases", inside=("latest-run",)),
    _s(".dvc", "models", "DVC data cache", inside=("cache", "config")),
    _s("catboost_info", "models", "CatBoost"),
    _s(".neptune", "models", "Neptune"),
)

_EXACT: dict[str, list[_Spec]] = {}
_PREFIXES: list[tuple[str, _Spec]] = []
_SUFFIXES: list[tuple[str, _Spec]] = []
for _spec in SPECS:
    if _spec.key.endswith("*"):
        _PREFIXES.append((_spec.key[:-1], _spec))
    elif _spec.key.startswith("*"):
        _SUFFIXES.append((_spec.key[1:], _spec))
    else:
        _EXACT.setdefault(_spec.key, []).append(_spec)
del _spec


def _specs(name: str) -> list[_Spec]:
    folded = name.casefold()
    specs = _EXACT.get(folded)
    if specs:
        return specs
    return [spec for prefix, spec in _PREFIXES if folded.startswith(prefix) and len(folded) > len(prefix)] or [
        spec for suffix, spec in _SUFFIXES if folded.endswith(suffix) and len(folded) > len(suffix)
    ]


def detect_marker(
    name: str,
    inside: Callable[[str], bool] | None = None,
    beside: Callable[[str], bool] | None = None,
) -> Marker | None:
    """The marker of a directory named ``name``, or None.

    ``inside(entry)`` and ``beside(entry)`` say whether the directory, or its parent,
    contains that entry (a link counts and is never followed). Without them nothing can be
    confirmed, and names that need evidence are never marked.
    """
    specs = _specs(name)
    if not specs:
        return None
    for spec in specs:
        if inside is not None:
            for entry in spec.inside:
                if inside(entry):
                    return Marker(spec.key, spec.category, spec.ecosystem, "confirmed", entry)
        if beside is not None:
            for entry in spec.beside:
                if beside(entry):
                    return Marker(spec.key, spec.category, spec.ecosystem, "confirmed", f"../{entry}")
    distinctive = next((spec for spec in specs if spec.strength == "name"), None)
    if distinctive is not None:
        return Marker(distinctive.key, distinctive.category, distinctive.ecosystem, "name")
    common = [spec for spec in specs if spec.strength == "possible"]
    if not common:
        return None
    # Which ecosystem a common name belongs to is exactly what nothing confirmed.
    ecosystem = common[0].ecosystem if len({spec.ecosystem for spec in common}) == 1 else None
    return Marker(common[0].key, common[0].category, ecosystem, "possible")


def apply_marker(record, marker: Marker | None) -> None:
    """Store a marker in a DirectoryRecord."""
    record.development_marker = None if marker is None else marker.key
    record.marker_category = None if marker is None else marker.category
    record.marker_ecosystem = None if marker is None else marker.ecosystem
    record.marker_confidence = None if marker is None else marker.confidence
    record.marker_evidence = None if marker is None else marker.evidence


def count_marker(stats, marker: Marker | None) -> None:
    """Count a marked directory by marker, category and confidence."""
    if marker is None:
        return
    stats["development_directory_count"] += 1
    stats[f"development_dir:{marker.key}"] += 1
    stats[f"development_category:{marker.category}"] += 1
    stats[f"development_confidence:{marker.confidence}"] += 1


def describe(marker: Marker) -> str:
    """"node_modules: dependencies (npm/pnpm/Yarn/Bun), confirmed by .package-lock.json"."""
    ecosystem = f" ({marker.ecosystem})" if marker.ecosystem else ""
    if marker.confidence == "confirmed":
        how = f"confirmed by {marker.evidence}"
    elif marker.confidence == "name":
        how = "by its name"
    else:
        how = "possible: a common name, not confirmed"
    return f"{marker.key}: {marker.category}{ecosystem}, {how}"


def profile_match(marker: Marker | None, profiles: frozenset[str] | set[str]) -> tuple[str, str] | None:
    """The --exclude-profile that prunes a marked directory, as (stats key, prune reason).

    Only confirmed and distinctive-name markers are pruned: a possible marker (a project's
    own build/ or vendor/ directory) never is.
    """
    if marker is None or not marker.actionable:
        return None
    for profile in sorted(profiles):
        if marker.category in PROFILES[profile]:
            return f"exclusion_used:profile:{profile}", f"--exclude-profile {profile}: {describe(marker)}"
    return None


@dataclass(frozen=True, slots=True)
class TreeScope:
    """The --development-trees mode of a directory inside a development tree, and why."""

    mode: str  # inventory or directory-only
    root: str  # the tree's top directory
    marker: Marker

    @property
    def reason(self) -> str:
        return (f"--development-trees {self.mode}: inside the {self.marker.category} tree {self.root} "
                f"({self.marker.key}, {self.marker.confidence})")


def tree_scope(mode: str, inherited: TreeScope | None, marker: Marker | None, path: str) -> TreeScope | None:
    """The scope of a directory: its parent's, or a new tree when its own marker is actionable."""
    if inherited is not None:
        return inherited
    if mode == "deep" or marker is None or not marker.actionable:
        return None
    return TreeScope(mode, path, marker)


def validate_tree_mode(mode: str) -> str:
    if mode not in TREE_MODES:
        raise ValueError(f"--development-trees {mode}: choose from {', '.join(TREE_MODES)}")
    return mode


def describe_profiles() -> str:
    """The presets and the categories they prune, for --help."""
    return ", ".join(
        name if PROFILES[name] == {name} else f"{name} ({', '.join(sorted(PROFILES[name]))})"
        for name in PROFILES if name != "all"
    ) + ", all (every category)"


def normalize_profiles(values) -> frozenset[str]:
    """--exclude-profile values, validated (ValueError names an unknown one)."""
    profiles = set()
    for raw in values or ():
        for value in str(raw).split(","):
            name = value.strip().casefold()
            if not name:
                continue
            if name not in PROFILES:
                raise ValueError(
                    f"--exclude-profile {value.strip()}: unknown profile; choose from {', '.join(PROFILES)}"
                )
            profiles.add(name)
    return frozenset(profiles)
