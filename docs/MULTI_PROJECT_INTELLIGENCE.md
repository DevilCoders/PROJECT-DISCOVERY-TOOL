# Multi-Project Intelligence

PDT can compare two independent JSON scan reports using:

```bash
pdt compare project-a-report/discovery-report.json project-b-report/discovery-report.json \
  --output comparison-report
```

The comparison reports language overlap, declared dependency overlap, Python module-name overlap, matching API evidence strings and SHA-256-identical file content. Every project remains a separate identity. Similar names or dependencies are not treated as proof of compatible architecture or a recommendation to merge.

The comparison CLI writes JSON and Markdown artifacts outside the target projects. It does not mutate either project. The first comparison engine is intentionally evidence-bounded. Cross-project semantic symbol matching, interface compatibility, version conflict analysis, data-model mapping, shared subsystem discovery and integration planning remain future milestones.
