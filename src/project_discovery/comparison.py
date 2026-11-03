"""Evidence-bounded comparison of independent PDT project reports."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_report(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0":
        raise ValueError(f"Unsupported PDT report schema in {path}")
    required = {"root", "files", "findings", "metrics"}
    missing = required - set(data)
    if missing:
        raise ValueError(f"Invalid PDT report {path}: missing {', '.join(sorted(missing))}")
    return data


def _declared_dependencies(report: dict[str, Any]) -> set[str]:
    prefix = "Declared dependency: "
    return {
        item["title"][len(prefix):]
        for item in report.get("findings", [])
        if item.get("title", "").startswith(prefix)
    }


def _python_modules(report: dict[str, Any]) -> set[str]:
    graph = report.get("metrics", {}).get("python_dependency_graph", {})
    return {
        item["name"] for item in graph.get("modules", [])
        if isinstance(item, dict) and item.get("name")
    }


def _file_hashes(report: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for item in report.get("files", []):
        digest = item.get("sha256")
        if digest:
            result[digest].append(item.get("path", ""))
    return dict(result)


def compare_reports(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    """Compare two independent project reports without merging their identities."""
    left_languages = set(left.get("metrics", {}).get("languages", {}))
    right_languages = set(right.get("metrics", {}).get("languages", {}))
    left_dependencies = _declared_dependencies(left)
    right_dependencies = _declared_dependencies(right)
    left_modules = _python_modules(left)
    right_modules = _python_modules(right)

    left_hashes = _file_hashes(left)
    right_hashes = _file_hashes(right)
    shared_hashes = sorted(set(left_hashes) & set(right_hashes))
    duplicate_content = [
        {
            "sha256": digest,
            "left_paths": sorted(left_hashes[digest]),
            "right_paths": sorted(right_hashes[digest]),
            "confidence": "CONFIRMED",
        }
        for digest in shared_hashes
    ]

    left_api = {
        evidence
        for item in left.get("findings", []) if item.get("category") == "api"
        for evidence in item.get("evidence", [])
    }
    right_api = {
        evidence
        for item in right.get("findings", []) if item.get("category") == "api"
        for evidence in item.get("evidence", [])
    }

    shared_dependencies = sorted(left_dependencies & right_dependencies)
    shared_modules = sorted(left_modules & right_modules)
    shared_api_evidence = sorted(left_api & right_api)
    return {
        "schema_version": "1.0",
        "comparison_type": "independent_project_reports",
        "projects": [
            {"root": left.get("root"), "file_count": len(left.get("files", []))},
            {"root": right.get("root"), "file_count": len(right.get("files", []))},
        ],
        "language_overlap": {
            "shared": sorted(left_languages & right_languages),
            "left_only": sorted(left_languages - right_languages),
            "right_only": sorted(right_languages - left_languages),
        },
        "dependency_overlap": {
            "shared_declared_dependencies": shared_dependencies,
            "left_only": sorted(left_dependencies - right_dependencies),
            "right_only": sorted(right_dependencies - left_dependencies),
        },
        "python_module_overlap": {
            "shared_module_names": shared_modules,
            "left_only": sorted(left_modules - right_modules),
            "right_only": sorted(right_modules - left_modules),
        },
        "shared_api_evidence": shared_api_evidence,
        "duplicate_file_content": duplicate_content,
        "interpretation": {
            "shared_dependencies": "CONFIRMED declarations; not proof of compatible versions or runtime use.",
            "shared_module_names": "INFERRED naming overlap; not proof of equivalent implementation.",
            "shared_api_evidence": "CONFIRMED matching evidence strings; not proof of API compatibility.",
            "duplicate_file_content": "CONFIRMED byte-identical content based on SHA-256 report fingerprints.",
            "integration_recommendation": "Not generated. Similarity is evidence for human review, not authorization to merge projects.",
        },
    }


def write_comparison(
    comparison: dict[str, Any], output: Path, formats: set[str]
) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        path = output / "project-comparison.json"
        path.write_text(
            json.dumps(comparison, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    if "markdown" in formats:
        path = output / "project-comparison.md"
        left, right = comparison["projects"]
        lines = [
            "# Independent Project Comparison",
            "",
            f"- Project A: {left['root']}",
            f"- Project B: {right['root']}",
            "",
            "## Shared languages",
            "",
            *[f"- {item}" for item in comparison["language_overlap"]["shared"]],
            "",
            "## Shared declared dependencies",
            "",
            *[f"- {item}" for item in comparison["dependency_overlap"]["shared_declared_dependencies"]],
            "",
            "## Shared Python module names",
            "",
            *[f"- {item}" for item in comparison["python_module_overlap"]["shared_module_names"]],
            "",
            "## Byte-identical files",
            "",
            *[
                f"- {item['sha256']}: A={', '.join(item['left_paths'])}; "
                f"B={', '.join(item['right_paths'])}"
                for item in comparison["duplicate_file_content"]
            ],
            "",
            "> Similarity is evidence for review, not a recommendation to merge independent projects.",
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(path)
    return written
