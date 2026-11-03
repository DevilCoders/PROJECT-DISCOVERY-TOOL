# Analyzer Domain Coverage

PDT is designed for polyglot repositories and heterogeneous project ecosystems. The analyzer roadmap is intentionally not limited to a short list of languages or security/configuration/API/database/test/build checks.

The machine-readable coverage catalog currently enumerates more than 50 domains spanning source structure, language semantics, dependency and supply-chain intelligence, security, APIs, databases, infrastructure, CI/CD, runtime architecture, ML/AI, datasets, robotics/ROS, embedded firmware, hardware description, GPU compute, graphics, game engines, mobile, accessibility, localization, and cross-project analysis.

Catalog status is explicit:
- `implemented`: a built-in analyzer currently emits findings for this domain.
- `planned`: a domain is part of the coverage contract but is not yet implemented.

A domain being catalogued is not evidence that its analyzer is complete. The roadmap is expanded as actual parsers, analyzers, tests, and evidence models are delivered.


## Implemented logging and observability slice

The built-in observability analyzer inventories static logging, metrics, tracing, health-check and telemetry configuration markers across recognized source languages. It records file and line evidence only and does not expose configuration values. Static presence is not proof of runtime initialization, active exporters, deployed collectors or operational telemetry.


## Implemented coverage artifact slice

The coverage analyzer reads LCOV, Cobertura, JaCoCo, Clover, OpenCover, Go cover profiles and Istanbul/coverage JSON. It extracts recorded line, statement, function and branch counters where the format provides them. The report does not prove which source revision was tested, that all tests ran, or that coverage instrumentation was complete.


## Implemented accessibility markup slice

The built-in accessibility analyzer checks HTML and common component-template files for missing document language, image alternative-text attributes, iframe titles, form-control labels, button names and link names. Findings are inferred from static markup and do not replace browser accessibility-tree inspection, keyboard testing or assistive-technology testing.
