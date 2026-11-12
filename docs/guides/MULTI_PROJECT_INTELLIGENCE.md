# Multi-Project Intelligence

`pdt compare` compares two or more independent JSON scan reports:

```bash
pdt compare project-a-report/discovery-report.json project-b-report/discovery-report.json project-c-report/discovery-report.json \
  --output comparison-report
```

The comparison reports, for all projects together and for every pair: language overlap, declared dependency overlap, resolved dependency version conflicts, Python module-name overlap, matching API evidence strings and SHA-256-identical file content. It also builds an **integration map** (`integration_map`) of links between the projects:

| Link | Evidence | Confidence |
|---|---|---|
| `package_dependency` | One project declares a dependency on another project's package name | CONFIRMED |
| `http_api` | One project calls a path that another serves, exactly or below a gateway or mount prefix | INFERRED |
| `messaging` | One project publishes a topic or queue that another consumes (declaring a queue is not publishing) | INFERRED |
| `shared_channel` | Both projects use a topic or queue, and neither publishes what the other consumes, for example two competing consumers. The edge has no direction | INFERRED |
| `grpc` | One project uses a client stub for a gRPC service that another defines or serves | INFERRED |

The map is built from each scan's integration summary (`metrics.code_index.integration`); reports from older scans fall back to the endpoint evidence in their API findings. Manifests, sources and protocol files below dependency and vendor directories (`node_modules`, `vendor`, `site-packages`, `.venv`, `target`, `third_party` and similar) describe other projects and are not part of the summary. Django `path()` routes, which declare no method, match calls of any method.

Resolved dependency versions come from `metrics.code_index.dependencies`, which lists every resolved package of every lockfile (up to 4,000 per lockfile and 50,000 per scan; the excess is counted). Older reports fall back to the first 200 packages per lockfile in finding evidence.

**Labels.** Every input is a separate project, labelled by its root. A remote scan's label adds its ref or revision (`URL#v1.4.0`), and inputs that still share a label, such as a before/after pair of one local project, are told apart by position (`/app [report 2]`), with a warning. All per-project keys and edge ends use these labels.

**Coverage.** `coverage` lists, per project, the evidence its report cannot provide: an `--inventory-only` scan (no dependencies, hashes or integration points), a skipped or failed code index or integration pass, lists cut at their caps, files without content hashes (older reports) and resolved-dependency lists that were cut. The same gaps are in `warnings` and in the Markdown Coverage section. A section that is empty because of a gap is unknown, not absent: an empty integration map then says that the evidence is incomplete instead of reporting no links. Methods and limits are described in [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md#6-integration-points-and-the-integration-map-integration-points).

Every project remains a separate identity. Similar names, dependencies or matching paths are not treated as proof of compatible architecture or a recommendation to merge, and an inferred link still needs confirmation of deployment and configuration. The comparison writes JSON and Markdown artifacts outside the target projects and does not modify any of them. The local project catalog (`pdt catalog-compare`, see [PROJECT_CATALOG.md](PROJECT_CATALOG.md)) runs the same comparison over every registered report.

Cross-project symbol matching, interface compatibility between contract versions, data-model mapping and integration planning remain future work.
