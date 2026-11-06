# Test and Build Intelligence

## Test discovery

The test analyzer identifies test files by naming convention (for example `test_*.py`, `*_test.go`, `*.spec.ts`, `*_spec.rb`, `tests/` directories) and extracts test declaration candidates in about 35 languages: Python, JavaScript/TypeScript, Rust, Go, Java, Kotlin, Scala, Groovy, C#, F#, Visual Basic, C, C++ (GoogleTest, Catch2), Objective-C, Swift, Dart, PHP, Ruby, Elixir (ExUnit), R, Julia, Clojure, Haskell, Lua, Perl, PowerShell (Pester), Bats, Solidity, Nim, Zig, Fortran, and Verilog/SystemVerilog/VHDL testbenches. It never imports or executes test code. For a test file without a language-specific declaration pattern, it emits an `INFERRED` candidate rather than inventing a test count.

The code index links public functions to the test files that reference them (`metrics.code_index.test_links`; see [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md)).

## Build manifests

The build analyzer inventories more than 60 build, packaging and CI manifest types, including Make, CMake (and presets), Meson, Autotools, Ninja, Bazel, Buck, Pants, SCons, Maven, Gradle (with wrappers), Ant, sbt, Cargo, Go modules, Python packaging (`pyproject.toml`, `setup.py`, `setup.cfg`, `tox.ini`, Pipfile, requirements files), npm `package.json`, Swift Package Manager, Zig, Rake, Mix, Composer, vcpkg, Conan, MSBuild projects and solutions, Xcode projects, Dockerfile/Containerfile, Earthly, Tilt, Just, Task, Procfile, Brewfile, CocoaPods, Carthage, fastlane, and CI definitions for GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, Bitbucket Pipelines, Travis CI and AppVeyor. It extracts a limited set of targets, scripts, jobs, metadata and Docker instructions; each manifest is read with a 16 MiB budget.

These are static inventories, not build execution or proof that a target succeeds. Toolchain resolution, build dependency graphs, generated-code provenance, CI expression evaluation and release artifact verification remain future work.
