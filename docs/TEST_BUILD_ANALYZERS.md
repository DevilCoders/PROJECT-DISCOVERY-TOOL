# Test and Build Intelligence

## Test discovery
The initial test analyzer identifies common test-file naming conventions and extracts test declaration candidates from Python, JavaScript/TypeScript, Rust, Go, Java/Kotlin, C#, C++, PHP, Ruby and Swift. It never imports or executes test code. For recognized test file naming conventions without a language-specific declaration pattern, it emits an INFERRED candidate rather than inventing a test count.

## Build manifests
The initial build analyzer inventories common Make, CMake, package.json, pyproject, Cargo, Maven, Gradle/SBT, Dockerfile and CI workflow manifests. It extracts a limited set of targets, scripts, jobs, metadata and Docker instructions.

These are static inventories, not build execution or proof that a target succeeds. Toolchain resolution, dependency graphs, generated-code provenance, CI expression evaluation and release artifact verification remain future work.
