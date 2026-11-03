"""Project-level architecture layout inference from path conventions only."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import PurePosixPath
from typing import Any

from .models import FileRecord, Finding


_LAYER_ALIASES = {
    "presentation": {
        "presentation", "ui", "views", "view", "frontend", "web", "client",
        "pages", "screens", "components", "widgets",
    },
    "application": {
        "application", "usecases", "use_cases", "services", "service",
        "commands", "queries", "handlers", "workers", "jobs",
    },
    "domain": {
        "domain", "entities", "entity", "aggregates", "value_objects", "business",
    },
    "infrastructure": {
        "infrastructure", "infra", "adapters", "adapter", "drivers",
        "providers", "integrations",
    },
    "persistence": {
        "persistence", "repositories", "repository", "dao", "database",
        "db", "migrations", "storage",
    },
    "api": {
        "api", "routes", "controllers", "controller", "endpoints",
        "http", "grpc", "rpc", "graphql", "proto", "schemas", "schema",
    },
    "testing": {"tests", "test", "spec", "specs", "__tests__"},
    "documentation": {"docs", "doc", "documentation"},
    "robotics": {"launch", "urdf", "msg", "srv", "action", "robot", "robots", "firmware"},
    "game_engine": {"assets", "scenes", "levels", "prefabs", "materials", "shaders", "resources"},
    "machine_learning": {
        "datasets", "training", "train", "inference", "tokenizers",
        "checkpoints", "weights", "embeddings", "experiments",
    },
    "delivery": {"deploy", "deployment", "ci", "pipelines", "scripts", "tools"},
}


def analyze_project_architecture(
    records: list[FileRecord],
) -> tuple[dict[str, Any], list[Finding]]:
    """Infer likely architectural layers from repository paths without reading source."""
    top_level: Counter[str] = Counter()
    layer_counts: Counter[str] = Counter()
    layer_examples: dict[str, list[str]] = defaultdict(list)
    file_count = 0

    for record in records:
        if record.error:
            continue
        parts = PurePosixPath(record.path.replace("\\", "/")).parts
        if not parts:
            continue
        file_count += 1
        if len(parts) > 1 and not parts[0].startswith("."):
            top_level[parts[0]] += 1

        matched: set[str] = set()
        for part in parts[:-1]:
            normalized = part.lower().replace("-", "_").replace(" ", "_")
            for layer, aliases in _LAYER_ALIASES.items():
                if normalized in aliases and layer not in matched:
                    matched.add(layer)
                    layer_counts[layer] += 1
                    if len(layer_examples[layer]) < 8:
                        layer_examples[layer].append(record.path)

    layers = [
        {
            "name": name,
            "file_count": layer_counts[name],
            "evidence_paths": sorted(layer_examples[name]),
            "confidence": "INFERRED",
        }
        for name in sorted(layer_counts)
    ]
    components = [
        {"name": name, "file_count": count}
        for name, count in sorted(top_level.items(), key=lambda item: (-item[1], item[0]))
    ]
    metrics = {
        "file_count": file_count,
        "top_level_components": components,
        "layers": layers,
        "classification_basis": "directory naming conventions only",
    }
    if not layers and not components:
        return metrics, []

    evidence = [
        f"top-level component: {item['name']} ({item['file_count']} files)"
        for item in components[:30]
    ]
    evidence.extend(
        f"layer: {item['name']} ({item['file_count']} files)"
        for item in layers
    )
    for item in layers:
        evidence.extend(item["evidence_paths"][:5])
    finding = Finding(
        "architecture",
        "Project architecture layout inventory",
        f"Inventoried {file_count} readable path(s), {len(components)} top-level "
        f"component(s), and {len(layers)} directory-convention layer(s). Layer labels "
        "are INFERRED from names only; this does not establish dependency direction, "
        "runtime boundaries, deployment topology or architectural compliance.",
        confidence="INFERRED",
        evidence=evidence[:150],
        analyzer="architecture-layout",
        severity="INFO",
    )
    return metrics, [finding]
