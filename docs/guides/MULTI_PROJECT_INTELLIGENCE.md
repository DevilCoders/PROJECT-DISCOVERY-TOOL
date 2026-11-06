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
| `messaging` | One project publishes a topic or queue that another consumes | INFERRED |
| `grpc` | One project uses a client stub for a gRPC service that another defines or serves | INFERRED |

The map is built from each scan's integration summary (`metrics.code_index.integration`); reports from older scans fall back to the endpoint evidence in their API findings. Methods and limits are described in [CODE_INTELLIGENCE.md](../architecture/CODE_INTELLIGENCE.md#6-integration-points-and-the-integration-map-integration-points).

Every project remains a separate identity. Similar names, dependencies or matching paths are not treated as proof of compatible architecture or a recommendation to merge, and an inferred link still needs confirmation of deployment and configuration. The comparison writes JSON and Markdown artifacts outside the target projects and does not modify any of them. The local project catalog (`pdt catalog-compare`, see [PROJECT_CATALOG.md](PROJECT_CATALOG.md)) runs the same comparison over every registered report.

Cross-project symbol matching, interface compatibility between contract versions, data-model mapping and integration planning remain future work.
