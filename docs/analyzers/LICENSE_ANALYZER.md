# License Intelligence

The offline license analyzer inventories SPDX headers in supported source and configuration files, package-level license declarations in package.json, pyproject.toml (`[project]` and Poetry's `[tool.poetry]`), Cargo.toml (`[package]`, `[workspace.package]`, and `license.workspace = true`, reported as inherited from the workspace) and composer.json, and common license text patterns in license files: LICENSE, LICENCE, COPYING, NOTICE and UNLICENSE, with any suffix (`LICENSE-MIT`, `LICENSE-APACHE`, `COPYING.LESSER`, `LICENSE.rst`).

SPDX tags count only in a comment (`#`, `//`, `/*`, `*`, `--`, `;`, `<!--`, `%`, `'`), as REUSE places them, never inside a string literal. Only the first 64 KiB of a source file is read, decoded leniently, so files in any encoding and of any size are checked within that header window.

Explicit manifest declarations and SPDX headers are CONFIRMED as declarations. License-text pattern matches are INFERRED. This is not legal advice, a complete SPDX expression parser, dependency-license resolution, or a license compatibility assessment. It performs no network lookup.
