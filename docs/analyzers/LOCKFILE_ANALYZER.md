# Dependency Resolution and Lockfiles

The offline lockfile analyzer extracts resolved package/version entries from 16 lockfile formats:

| Ecosystem | Lockfiles |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5, v6, v9) |
| PyPI | `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock` |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` |
| Go | `go.sum` (lines that only pin a `go.mod` are not treated as resolved versions) |
| Hex | `mix.lock` |
| NuGet | `packages.lock.json` |
| Swift Package Manager | `Package.resolved` |
| Pub | `pubspec.lock` |

The same parsers feed local vulnerability matching: with `--vuln-db`, resolved versions are matched against an operator-imported OSV snapshot (see the README's "Local vulnerability intelligence" section). Each lockfile is read with a 128 MiB budget and at most 250,000 resolved entries; crossing either limit produces an `UNKNOWN` finding, not a partial clean result.

Lockfile entries are evidence of a recorded dependency resolution, not proof that the packages are installed or that the lockfile matches the current manifest. Full resolver semantics, workspace and monorepo constraints, lockfile-to-manifest consistency and transitive license checks remain future work. Lockfile analysis contacts no package registry.
