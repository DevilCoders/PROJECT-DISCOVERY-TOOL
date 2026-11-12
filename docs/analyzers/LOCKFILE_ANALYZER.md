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

Entries are classified by source:

- **Registry releases** are inventoried as `name==version` and matched against advisories.
- **The project's own packages** (the root project, workspace members, path and linked packages: a `Cargo.lock` crate without `source`, uv `editable`/`virtual`/`path` entries, Yarn `workspace:` and `link:` entries, npm keys outside `node_modules/`, Gemfile `PATH` gems, pubspec `path`/`sdk` packages, Composer path repositories, NuGet project references) are listed in a "Local and workspace packages" finding. They are never sent to OSV.dev nor matched against registry advisories.
- **Third-party code from outside a registry** (git and URL dependencies, including npm v1 `git+https://` versions) is listed by name only, because a specifier can carry credentials, in an `UNKNOWN` "Dependencies outside a package registry" finding: those dependencies were not checked.

Aliases resolve to the real package: yarn `alias@npm:real@range`, npm `npm:real@version`, `mix.lock` keys that differ from the hex package, and `ssh://user@host/...` Swift URLs.

Lockfile entries are evidence of a recorded dependency resolution, not proof that the packages are installed or that the lockfile matches the current manifest. Full resolver semantics, workspace and monorepo constraints, lockfile-to-manifest consistency and transitive license checks remain future work. Lockfile analysis contacts no package registry.
