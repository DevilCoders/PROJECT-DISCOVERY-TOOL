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

## Dependency graphs

Where a lockfile records them, PDT reads each package's dependencies (by exact version where the format resolves one, by name otherwise) and the project's direct dependencies:

| Records | Formats |
|---|---|
| Edges and direct dependencies | `package-lock.json` and `npm-shrinkwrap.json` v2/v3 (the root's and workspace members' dependencies, resolved as Node resolves them, nested `node_modules` first), Yarn Berry (workspace entries), `pnpm-lock.yaml` (importers; v5's top-level dependencies), `Cargo.lock` (the project's own crates), `uv.lock` (the virtual or editable root), `Gemfile.lock` (`DEPENDENCIES` and PATH gems), `packages.lock.json` (`Direct` and `Transitive`), `Podfile.lock` (`DEPENDENCIES`), `bun.lock` (workspaces), `deno.lock` (workspace dependencies or specifiers) |
| Edges only | `package-lock.json` v1, Yarn v1, `poetry.lock`, `pdm.lock`, `composer.lock`, vcpkg's status database, `renv.lock` (`Requirements`), Julia manifests |
| Direct dependencies only | `pubspec.lock` (`direct` or `transitive`), `rebar.lock` (level 0) |
| Neither | the other formats, installed OS package databases and SBOMs |

The graph gives each package the shortest path from a direct dependency. When the lockfile names no direct dependencies, the path starts from a package that nothing else depends on.

A vulnerability finding says whether the package is a direct dependency. If it is transitive, the finding also names the path that brings it in, for example `dependency_path: express@4.17.1 > body-parser@1.19.0 > qs@6.9.0`. It then suggests upgrading the direct dependency, or pinning the package with an override. A package that the graph does not reach is reported as such, and so is a graph cut at its 2,000,000-edge limit.

The inventory finding counts direct and transitive dependencies, and how many packages the graph reaches. The graph says what the lockfile resolved, not what is loaded at runtime.

## Reachability evidence

A version match says nothing about whether the vulnerable code runs. For each package an advisory confirms, locally or through `--vuln-online`, the code index's reachability pass looks for static evidence in the scanned code. It reports one `INFERRED`, `INFO` finding per package, under the `dependency-reachability` analyzer:

- **Imported by the code.** Files import the package (each `imported_by: path:line`). When the advisory names its affected functions, calls to them in those files are listed too (`calls: template at src/app.js:3`). Go's vulndb, RustSec and GitHub's `vulnerable_functions` name them.
- **Reached through an imported dependency.** No file imports the package itself, but the direct dependency that brings it in (from the [dependency graph](#dependency-graphs)) is imported.
- **Not imported by the scanned code.** Neither the package nor the dependency that brings it in is imported. The package may still be loaded dynamically, by a framework, by configuration or by code outside the scan, so this is not evidence that the vulnerability cannot be reached.

Imports name packages as each ecosystem writes them:

| Ecosystem | How an import names the package |
|---|---|
| npm, Pub | by name (`require("lodash")`, `@babel/core/...`, `package:http/...`) |
| Go | by module path, packages below it included |
| crates.io | by crate name with `-` read as `_` |
| NuGet | by dotted namespace |
| PyPI | by module name, including the common renames (`PyYAML` is `yaml`, `beautifulsoup4` is `bs4`) |
| Maven | by group (`com.fasterxml.jackson`), which cannot tell a group's artifacts apart |
| Packagist | by vendor namespace |
| RubyGems | by `require` path |
| Hex | by module |

Packages of other ecosystems, and packages in a language with no code in the scan, get no reachability finding. `metrics.code_index.reachability` counts every outcome. This evidence never establishes exploitability.

## Installed OS packages and SBOMs

A scanned tree that holds a root file system (an unpacked container image, an appliance image, a chroot) names its installed packages in the package manager's database. These databases and SBOM files are read like lockfiles:

| Source | Path | Recorded as |
|---|---|---|
| dpkg (Debian, Ubuntu) | `var/lib/dpkg/status` | each installed package by its source package and source version, because Debian and Ubuntu advisories name source packages (`libssl3` is recorded as `openssl`) |
| apk (Alpine, Wolfi) | `lib/apk/db/installed` | each package by its origin package (`o:`) |
| rpm (Red Hat, AlmaLinux, Rocky Linux, Fedora, SUSE) | `var/lib/rpm/rpmdb.sqlite`, `usr/lib/sysimage/rpm/rpmdb.sqlite` | each package by name and `epoch:version-release`. rpm also stores GPG keys as packages; these are left out. The database is opened from memory, read-only, with a 50 million-step query budget, and refused when its `Packages` table is not a plain table. The older Berkeley DB and NDB rpm databases are not read. |
| CycloneDX and SPDX JSON SBOMs | `bom.json`, `sbom.json`, `*.cdx.json`, `*.cyclonedx.json`, `*.spdx.json` | each component that has a package URL, in that purl's ecosystem. A component without one but with a CPE (CycloneDX `cpe`, SPDX `cpe23Type`), such as firmware, an appliance or a vendored C library, is recorded as `vendor:product` in the CPE ecosystem. NVD records name products that way. Components with neither are not packages PDT can match. |

An installed package's ecosystem is the distribution release named in the root's `etc/os-release` (or `usr/lib/os-release`), using the names OSV and the advisory importer use: `Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`, `AlmaLinux:9`, `Rocky Linux:9`, `Red Hat`, `Wolfi`.

Without an os-release, a package keeps only the distribution's name (`Debian`), which no advisory uses. Such packages are inventoried and reported as not checked.

A package URL gives the same information through its qualifiers. Its `distro` qualifier names the release (`distro=debian-12`, `distro=bookworm`, `distro=alpine-3.19.1`). Its `upstream` qualifier names the source package (`upstream=openssl`, or `upstream=zlib@1:1.2.13.dfsg-1` as Syft writes it).

Versions are compared in each distribution's own order (see [Version ordering](#version-ordering)).

`--vuln-online` asks OSV.dev about Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux and Wolfi packages, as long as they carry their release. Red Hat, Fedora and SUSE packages are checked only against a local snapshot; for Red Hat, import its CSAF advisories.

## Version ordering

An advisory's `ECOSYSTEM` range is evaluated in the ordering of the package's own ecosystem, and a `SEMVER` range in SemVer 2.0 precedence:

| Ecosystem | Ordering |
|---|---|
| PyPI | PEP 440 |
| npm, crates.io, Hex, SwiftURL | SemVer 2.0; build metadata is ignored |
| Go | `golang.org/x/mod/semver`. A pseudo-version is a prerelease of the release after the tag it follows (`v1.2.4-0.20191109021931-daa7c04131f5` sorts after `v1.2.3` and before `v1.2.4-alpha`), as the go command orders it. A finding for one names its commit and time, and says that a fix tagged in the next release counts as missing even if the commit already contains it. |
| NuGet | SemVer 2.0 with four numeric parts, labels compared without case |
| RubyGems | `Gem::Version`: string segments mark prereleases |
| Packagist | Composer: `dev` < `alpha` < `beta` < `RC` < stable < `patch` (`2.4.6-p3` follows `2.4.6`) |
| Pub | `pub_semver`: as SemVer, except that a build follows its release (`1.0.0` < `1.0.0+1` < `1.0.0+2`) |
| Maven | the [version order specification](https://maven.apache.org/pom.html#version-order-specification), as Maven's `ComparableVersion` implements it and checked against its test vectors: `1-alpha-1` < `1-beta` < `1-rc` < `1-SNAPSHOT` < `1` = `1.0` = `1-ga` < `1-sp` < `1-jre` < `1-1` < `1.1` |
| Hackage | the Haskell PVP: lists of numbers, so `1.0` < `1.0.0` |
| CRAN, Bioconductor | R's `package_version`: numbers separated by `.` or `-` (`1.2-3` is `1.2.3`) |
| ConanCenter | Conan 2's `Version`: trailing zeros ignored, a prerelease after the last `-`, a build after the last `+` |
| Debian, Ubuntu | dpkg: epochs, and `~` sorts before everything |
| Alpine, Wolfi, Chainguard | apk-tools: `_alpha` to `_rc` sort before the release. After the release come `-r` revisions, then `_cvs` to `_p`, then a letter (`1.2.3-r10` < `1.2.3_p1` < `1.2.3a`). |
| Red Hat, AlmaLinux, Rocky Linux, Fedora, openSUSE, SUSE, Mageia, openEuler, Photon OS | rpm's `rpmvercmp`, including `~` and `^`. A version without a release matches every release. |
| NVD CPE bounds | NVD defines no order for vendor product versions, so PDT uses its own. Versions are runs of digits and letters, with separators ignored. `dev`, `alpha`, `beta`, `milestone`, `pre`/`preview` and `rc` sort before their release. Any other word or letter sorts after the release but before the next number (`1.0.2` < `1.0.2k` < `1.0.3`, `15.2(4)M3` < `15.2(4)M10`). NVD's exclusive start bounds are evaluated as written. |

A version that the ordering cannot read leaves the match `UNKNOWN`. So does a range in a scheme PDT has no ordering for (`GIT`, or an ecosystem such as GitHub Actions). Neither is reported as clean.

## CPE matching, exploitation and VEX

- **CPE-named components** match an NVD criterion when the vendor and product are the same and the version is within the criterion's bounds. The bounds are compared in the vendor order, and an exclusive start is evaluated as written. The other attributes (part, update, edition, language, target software and hardware) must also agree wherever both CPEs state one. A lodash CPE built for Python therefore does not match a criterion for Node.js.
- **Withdrawn and superseded advisories.** A withdrawn advisory, including an NVD record marked Rejected, gives no finding. On re-import the copy modified later is kept, so an older snapshot cannot bring back an advisory that was withdrawn or corrected.
- **Known exploited.** Import CISA's Known Exploited Vulnerabilities catalog with `pdt vuln-db import`. A confirmed finding of a CVE it lists names the entry (date added, known ransomware use, remediation due date) and is raised to at least HIGH. Findings from `--vuln-online` do not consult the catalog.
- **Exploit maturity.** When an advisory's CVSS vector states one (the `E` metric of CVSS 2, 3.x and 4.0), the finding names the highest. NVD's vectors hold base metrics only.
- **VEX.** `pdt scan --vex FILE` applies the operator's OpenVEX, CycloneDX VEX or CSAF VEX statements to local and online findings, matched by advisory ID or alias. A `not_affected` or `fixed` statement turns a finding into an INFO finding that keeps its evidence. The finding is titled "Not affected per VEX" or "Fixed per VEX" and carries the statement's justification. An `affected` or `under_investigation` statement is added to the finding. The most specific statement decides: a package at its version first, then the package, then the whole product. See [CLI_REFERENCE.md](../guides/CLI_REFERENCE.md#vulnerability-intelligence).

Lockfile entries are evidence of a recorded dependency resolution, not proof that the packages are installed or that the lockfile matches the current manifest. Full resolver semantics, workspace and monorepo constraints, lockfile-to-manifest consistency and transitive license checks remain future work. Lockfile analysis contacts no package registry.
