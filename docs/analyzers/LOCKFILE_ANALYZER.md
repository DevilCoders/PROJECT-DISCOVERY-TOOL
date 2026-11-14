# Dependency Resolution and Lockfiles

The offline lockfile analyzer extracts resolved package/version entries from 33 lockfile formats, and from the [installed-package databases and SBOMs](#installed-os-packages-and-sboms) below:

| Ecosystem | Lockfiles |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5, v6, v9), `bun.lock` (Bun's text lockfile, with its trailing commas), `deno.lock` (its npm packages; v3 to v5) |
| JSR | `deno.lock` (its JSR packages) |
| PyPI | `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock`, `pylock.toml` and `pylock.<name>.toml` (PEP 751) |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` |
| Go | `go.sum` (lines that only pin a `go.mod` are not treated as resolved versions) |
| Hex | `mix.lock`, `rebar.lock` (rebar3) |
| NuGet | `packages.lock.json`, `packages.config` (read with patterns, never an XML parser) |
| Swift Package Manager | `Package.resolved` |
| Pub | `pubspec.lock` |
| Maven | `gradle.lockfile`, `buildscript-gradle.lockfile`, `settings-gradle.lockfile` (Gradle dependency locking; `group:artifact` names) |
| ConanCenter | `conan.lock` (Conan 2 requires, build and python requires; Conan 1 graph locks) |
| CRAN, Bioconductor | `renv.lock` |
| Hackage | `cabal.project.freeze`, `stack.yaml.lock` |
| CocoaPods | `Podfile.lock` (subspecs count as their pod) |
| vcpkg | `vcpkg_installed/vcpkg/status` and `installed/vcpkg/status`: the ports vcpkg installed (vcpkg has no lockfile; a port version is written `1.3.1#2`) |
| Julia | `Manifest.toml`, `JuliaManifest.toml` (formats 1 and 2; standard libraries have no version and are skipped) |
| CPAN | `cpanfile.snapshot` (Carton) |
| Crystal | `shard.lock` |
| DUB | `dub.selections.json` |
| Carthage | `Cartfile.resolved` (every dependency is a git repository or a binary URL, so every one is listed as outside a registry) |

OSV.dev publishes advisories for npm, PyPI, crates.io, Packagist, RubyGems, Go, Hex, SwiftURL, NuGet, Pub, Maven, ConanCenter, CRAN, Bioconductor and Hackage. CocoaPods, vcpkg, JSR, Julia, CPAN, Crystal, DUB and Carthage packages are inventoried but cannot be checked: a local snapshot holds no advisories for them, which an `UNKNOWN` "not covered" finding says per ecosystem (one lockfile can hold several), and `--vuln-online` never sends them and counts them in a coverage finding.

Not parsed: Gradle 5's per-configuration `gradle/dependency-locks/*.lockfile` files and conda environments (`conda-lock.yml`, `pixi.lock`). Maven `pom.xml`, sbt, Clojure (`deps.edn`, `project.clj`), Haxe, Fortran fpm, PlatformIO and CMake projects have no lockfile format; their manifests are read by the dependency-manifest analyzer.

The same parsers feed local vulnerability matching: with `--vuln-db`, resolved versions are matched against an operator-imported advisory snapshot (see [`pdt vuln-db import`](../guides/CLI_REFERENCE.md#pdt-vuln-db-import) for the formats it reads). Each lockfile is read with a 128 MiB budget and at most 250,000 resolved entries; crossing either limit produces an `UNKNOWN` finding, not a partial clean result.

Entries are classified by source:

- **Registry releases** are inventoried as `name==version` and matched against advisories.
- **The project's own packages** (the root project, workspace members, path and linked packages: a `Cargo.lock` crate without `source`, uv `editable`/`virtual`/`path` entries, Yarn `workspace:` and `link:` entries, npm keys outside `node_modules/`, Gemfile `PATH` gems, pubspec `path`/`sdk` packages, Composer path repositories, NuGet project references) are listed in a "Local and workspace packages" finding. They are never sent to OSV.dev nor matched against registry advisories.
- **Third-party code from outside a registry** (git and URL dependencies, including npm v1 `git+https://` versions) is listed by name only, because a specifier can carry credentials, in an `UNKNOWN` "Dependencies outside a package registry" finding: those dependencies were not checked.

Aliases resolve to the real package: yarn `alias@npm:real@range`, npm `npm:real@version`, `mix.lock` keys that differ from the hex package, and `ssh://user@host/...` Swift URLs.

**Registries.** Where a format records where its packages came from, the inventory finding names the registry hosts with their package counts ("Resolved from: registry.npmjs.org (812), npm.example.com (4)"), and the code index's [provenance graph](VCS_ANALYZER.md#provenance-graph) links them to the project. Only the host is kept, never the URL, which can carry credentials and private paths. The hosts come from npm `resolved` URLs, Yarn v1 `resolved` lines, pnpm `tarball` URLs (pnpm does not record the default registry), Bun registry URLs, Cargo `registry+`/`sparse+` sources (crates.io's index, wherever it is served, is `crates.io`), uv `registry` sources, Poetry `[package.source]` URLs (a package without one comes from PyPI), Pipfile.lock `_meta.sources` and each package's `index`, PEP 751 `index` values, Composer `dist` and `source` URLs, Gemfile.lock `GEM` remotes, Hex for `mix.lock` and `rebar.lock`, SwiftPM package locations, pub `description.url`, CocoaPods `SPEC REPOS` (trunk is the CocoaPods CDN), renv repositories, Hackage for Cabal and Stack, CPAN for Carton, the git hosts of Crystal shards and the DUB registry. Yarn Berry, pdm, Go, NuGet, Gradle, Conan, vcpkg, Deno and Julia lockfiles do not record it.

## Installed OS packages and SBOMs

A scanned tree that holds a root file system (an unpacked container image, an appliance image, a chroot) names its installed packages in the package manager's database. These databases and SBOM files are read like lockfiles:

| Source | Path | Recorded as |
|---|---|---|
| dpkg (Debian, Ubuntu) | `var/lib/dpkg/status` | each installed package by its source package and source version, because Debian and Ubuntu advisories name source packages (`libssl3` is recorded as `openssl`) |
| apk (Alpine, Wolfi) | `lib/apk/db/installed` | each package by its origin package (`o:`) |
| rpm (Red Hat, AlmaLinux, Rocky Linux, Fedora, SUSE) | `var/lib/rpm/rpmdb.sqlite`, `usr/lib/sysimage/rpm/rpmdb.sqlite` | each package by name and `epoch:version-release`. rpm also stores GPG keys as packages; these are left out. The database is opened from memory, read-only, with a 50 million-step query budget, and refused when its `Packages` table is not a plain table. The older Berkeley DB and NDB rpm databases are not read. |
| CycloneDX and SPDX JSON SBOMs | `bom.json`, `sbom.json`, `*.cdx.json`, `*.cyclonedx.json`, `*.spdx.json` | each component that has a package URL, in that purl's ecosystem. Components without one are not packages PDT can match. |

An installed package's ecosystem is the distribution release named in the root's `etc/os-release` (or `usr/lib/os-release`), using the names OSV and the advisory importer use: `Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`, `AlmaLinux:9`, `Rocky Linux:9`, `Red Hat`, `Wolfi`.

Without an os-release, a package keeps only the distribution's name (`Debian`), which no advisory uses. Such packages are inventoried and reported as not checked.

A package URL gives the same information through its qualifiers. Its `distro` qualifier names the release (`distro=debian-12`, `distro=bookworm`, `distro=alpine-3.19.1`). Its `upstream` qualifier names the source package (`upstream=openssl`, or `upstream=zlib@1:1.2.13.dfsg-1` as Syft writes it).

Versions are compared in each distribution's own order:

- **dpkg:** epochs, and `~` sorts before everything.
- **apk:** the `_alpha` to `_p` suffixes, then `-r` revisions.
- **rpm:** `rpmvercmp`, including `~` and `^`.

`--vuln-online` asks OSV.dev about Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux and Wolfi packages, as long as they carry their release. Red Hat, Fedora and SUSE packages are checked only against a local snapshot; for Red Hat, import its CSAF advisories.

Lockfile entries are evidence of a recorded dependency resolution, not proof that the packages are installed or that the lockfile matches the current manifest. Full resolver semantics, workspace and monorepo constraints, lockfile-to-manifest consistency and transitive license checks remain future work. Lockfile analysis contacts no package registry.
