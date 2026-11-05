"""Evidence-bounded comparison of independent PDT project reports."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .analyzers.integration_analyzer import EndpointIndex, normalize_route


SUPPORTED_REPORT_SCHEMA_MAJOR = "1"


def load_report(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid PDT report {path}: top-level value is not an object")
    # Minor schema revisions are additive, so any 1.x scan report is comparable.
    version = str(data.get("schema_version", ""))
    if version.split(".", 1)[0] != SUPPORTED_REPORT_SCHEMA_MAJOR:
        raise ValueError(f"Unsupported PDT report schema {version!r} in {path}")
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



def _resolved_dependency_versions(report: dict[str, Any]) -> dict[str, set[str]]:
    resolved: dict[str, set[str]] = defaultdict(set)
    for finding in report.get("findings", []):
        if not finding.get("title", "").startswith("Resolved dependency inventory:"):
            continue
        for evidence in finding.get("evidence", []):
            if "==" in evidence:
                package, version = evidence.rsplit("==", 1)
                if package and version:
                    resolved[package].add(version)
    return dict(resolved)


MAX_EDGE_EVIDENCE = 25


def _integration_summary(report: dict[str, Any]) -> dict[str, Any]:
    """The scan's integration points; endpoints fall back to API findings for older reports."""
    summary = report.get("metrics", {}).get("code_index", {}).get("integration") or {}
    endpoints = list(summary.get("endpoints") or [])
    if not endpoints:
        for item in report.get("findings", []):
            if not str(item.get("title", "")).startswith("API route declarations:"):
                continue
            for evidence in item.get("evidence", []):
                location, _, rest = str(evidence).partition(" ")
                method, _, route = rest.partition(" ")
                if route:
                    endpoints.append({"method": method.upper(), "path": normalize_route(route),
                                      "file": location.rsplit(":", 1)[0]})
    return {
        "packages": list(summary.get("packages") or []), "endpoints": endpoints,
        "http_calls": list(summary.get("http_calls") or []), "topics": list(summary.get("topics") or []),
        "grpc": dict(summary.get("grpc") or {}),
    }


def _package_key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def integration_map(reports: list[dict[str, Any]], projects: list[dict[str, Any]]) -> dict[str, Any]:
    """Edges between projects: package dependencies, HTTP calls to served endpoints, topics
    one project publishes and another consumes, and gRPC services one serves and another calls."""
    summaries = [_integration_summary(report) for report in reports]
    declared = [{_package_key(name) for name in _declared_dependencies(report)} for report in reports]
    labels = [str(project["root"]) for project in projects]
    edges: list[dict[str, Any]] = []
    for provider_index, provider in enumerate(summaries):
        index = EndpointIndex([(item.get("method", ""), item.get("path", "")) for item in provider["endpoints"]])
        services = {name.rsplit(".", 1)[-1] for name in provider["grpc"].get("service", [])} | set(
            provider["grpc"].get("server", []))
        produced = {(item["name"], item.get("system", "")) for item in provider["topics"]
                    if item.get("role") in {"produce", "declare"}}
        for consumer_index, consumer in enumerate(summaries):
            if provider_index == consumer_index:
                continue
            provider_label, consumer_label = labels[provider_index], labels[consumer_index]
            packages = sorted({item["name"] for item in provider["packages"]
                               if _package_key(item["name"]) in declared[consumer_index]})
            if packages:
                edges.append({"from": consumer_label, "to": provider_label, "kind": "package_dependency",
                              "count": len(packages), "evidence": packages[:MAX_EDGE_EVIDENCE],
                              "confidence": "CONFIRMED"})
            calls = []
            for call in consumer["http_calls"]:
                hit = index.match(call.get("method", ""), call.get("path", ""))
                if hit:
                    calls.append(f"{call.get('method')} {call.get('path')}"
                                 + (f" on {call['host']}" if call.get("host") else "")
                                 + f" ({call.get('file')}) -> {hit[0]} {hit[1]} [{hit[2]}]")
            if calls:
                edges.append({"from": consumer_label, "to": provider_label, "kind": "http_api", "count": len(calls),
                              "evidence": calls[:MAX_EDGE_EVIDENCE], "confidence": "INFERRED"})
            topics = sorted({
                f"{item['name']} ({item.get('system') or system})" for item in consumer["topics"]
                if item.get("role") in {"consume", "declare"}
                for name, system in produced
                if item["name"] == name and (not item.get("system") or not system or item.get("system") == system
                                             or "pub/sub" in {item.get("system"), system})
            })
            if topics:
                edges.append({"from": provider_label, "to": consumer_label, "kind": "messaging", "count": len(topics),
                              "evidence": topics[:MAX_EDGE_EVIDENCE], "confidence": "INFERRED"})
            grpc = sorted(services & set(consumer["grpc"].get("client", [])))
            if grpc:
                edges.append({"from": consumer_label, "to": provider_label, "kind": "grpc", "count": len(grpc),
                              "evidence": grpc[:MAX_EDGE_EVIDENCE], "confidence": "INFERRED"})
    return {
        "edges": edges,
        "projects": [
            {"root": labels[index], "packages": [item["name"] for item in summary["packages"]][:20],
             "endpoints": len(summary["endpoints"]), "http_calls": len(summary["http_calls"]),
             "topics": len(summary["topics"]), "grpc_services": len(summary["grpc"].get("service", []))}
            for index, summary in enumerate(summaries)
        ],
        "interpretation": (
            "`from` depends on or calls `to`; for messaging, `from` publishes what `to` consumes. Package edges are "
            "CONFIRMED declarations; HTTP, messaging and gRPC edges are INFERRED from literal paths, topic and "
            "service names and need confirmation of deployment and configuration."
        ),
    }


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
    left_resolved = _resolved_dependency_versions(left)
    right_resolved = _resolved_dependency_versions(right)

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
    resolved_overlap = [
        {
            "name": package,
            "left_versions": sorted(left_resolved[package]),
            "right_versions": sorted(right_resolved[package]),
            "version_conflict": left_resolved[package] != right_resolved[package],
        }
        for package in sorted(set(left_resolved) & set(right_resolved))
    ]
    return {
        "schema_version": "1.1",
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
        "resolved_dependency_overlap": resolved_overlap,
        "duplicate_file_content": duplicate_content,
        "integration_map": integration_map(
            [left, right], [{"root": left.get("root")}, {"root": right.get("root")}],
        ),
        "interpretation": {
            "shared_dependencies": "CONFIRMED declarations; not proof of compatible versions or runtime use.",
            "shared_module_names": "INFERRED naming overlap; not proof of equivalent implementation.",
            "shared_api_evidence": "CONFIRMED matching evidence strings; not proof of API compatibility.",
            "dependency_version_conflicts": "CONFIRMED lockfile version differences; dependency compatibility still requires semantic analysis.",
            "duplicate_file_content": "CONFIRMED byte-identical content based on SHA-256 report fingerprints.",
            "integration_recommendation": "Not generated. Similarity is evidence for human review, not authorization to merge projects.",
        },
    }




def compare_many_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare two or more independent project reports pairwise and collectively."""
    if len(reports) < 2:
        raise ValueError("At least two project reports are required.")
    projects = [
        {"root": report.get("root"), "file_count": len(report.get("files", []))}
        for report in reports
    ]
    language_sets = [
        set(report.get("metrics", {}).get("languages", {})) for report in reports
    ]
    dependency_sets = [_declared_dependencies(report) for report in reports]
    module_sets = [_python_modules(report) for report in reports]
    resolved_sets = [_resolved_dependency_versions(report) for report in reports]
    api_sets = [
        {
            evidence
            for item in report.get("findings", []) if item.get("category") == "api"
            for evidence in item.get("evidence", [])
        }
        for report in reports
    ]
    shared_hashes: dict[str, dict[int, list[str]]] = defaultdict(dict)
    for index, report in enumerate(reports):
        for digest, paths in _file_hashes(report).items():
            shared_hashes[digest][index] = paths

    common_languages = set.intersection(*language_sets) if language_sets else set()
    common_dependencies = set.intersection(*dependency_sets) if dependency_sets else set()
    common_modules = set.intersection(*module_sets) if module_sets else set()
    common_resolved = set.intersection(*(set(item) for item in resolved_sets)) if resolved_sets else set()
    common_api = set.intersection(*api_sets) if api_sets else set()
    resolved_across_all = [
        {
            "name": package,
            "versions_by_project": {
                str(projects[index]["root"]): sorted(item[package])
                for index, item in enumerate(resolved_sets)
            },
            "version_conflict": len({
                version for item in resolved_sets for version in item[package]
            }) > 1,
        }
        for package in sorted(common_resolved)
    ]
    duplicates = []
    for digest, locations in sorted(shared_hashes.items()):
        if len(locations) >= 2:
            duplicates.append({
                "sha256": digest,
                "projects": {
                    str(projects[index]["root"]): sorted(paths)
                    for index, paths in sorted(locations.items())
                },
                "confidence": "CONFIRMED",
            })

    pairwise = []
    for left_index in range(len(reports)):
        for right_index in range(left_index + 1, len(reports)):
            result = compare_reports(reports[left_index], reports[right_index])
            pairwise.append({
                "left_project": projects[left_index]["root"],
                "right_project": projects[right_index]["root"],
                "shared_languages": result["language_overlap"]["shared"],
                "shared_declared_dependencies": result["dependency_overlap"]["shared_declared_dependencies"],
                "shared_python_module_names": result["python_module_overlap"]["shared_module_names"],
                "duplicate_file_count": len(result["duplicate_file_content"]),
                "dependency_version_conflict_count": sum(
                    1 for item in result["resolved_dependency_overlap"] if item["version_conflict"]
                ),
            })

    return {
        "schema_version": "1.1",
        "comparison_type": "independent_project_reports",
        "projects": projects,
        "all_projects_shared": {
            "languages": sorted(common_languages),
            "declared_dependencies": sorted(common_dependencies),
            "python_module_names": sorted(common_modules),
            "resolved_dependencies": resolved_across_all,
            "api_evidence": sorted(common_api),
        },
        "pairwise_comparisons": pairwise,
        "duplicate_file_content": duplicates,
        "integration_map": integration_map(reports, projects),
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
        if "all_projects_shared" in comparison:
            shared = comparison["all_projects_shared"]
            lines = [
                "# Independent Project Comparison",
                "",
                "## Projects",
                "",
            ]
            lines.extend(
                f"- {project['root']} ({project['file_count']} files)"
                for project in comparison["projects"]
            )
            lines.extend(["", "## Shared across all projects", "", "### Languages"])
            lines.extend(f"- {item}" for item in shared["languages"])
            lines.extend(["", "### Declared dependencies"])
            lines.extend(f"- {item}" for item in shared["declared_dependencies"])
            lines.extend(["", "### Resolved dependency versions"])
            for item in shared["resolved_dependencies"]:
                versions = "; ".join(
                    "{}={}".format(project, ", ".join(values))
                    for project, values in item["versions_by_project"].items()
                )
                suffix = " (version conflict)" if item["version_conflict"] else ""
                lines.append(f"- {item['name']}: {versions}{suffix}")
            lines.extend(["", "### Python module names"])
            lines.extend(f"- {item}" for item in shared["python_module_names"])
            lines.extend(["", "## Pairwise overlap", ""])
            for item in comparison["pairwise_comparisons"]:
                lines.append(
                    f"- {item['left_project']} ↔ {item['right_project']}: "
                    f"{len(item['shared_languages'])} languages, "
                    f"{len(item['shared_declared_dependencies'])} dependencies, "
                    f"{item['duplicate_file_count']} duplicate files, "
                    f"{item['dependency_version_conflict_count']} version conflicts"
                )
            lines.extend(["", "## Byte-identical content", ""])
            for item in comparison["duplicate_file_content"]:
                locations = "; ".join(
                    "{}: {}".format(project, ", ".join(paths))
                    for project, paths in item["projects"].items()
                )
                lines.append(f"- {item['sha256']}: {locations}")
        else:
            left, right = comparison["projects"]
            lines = [
                "# Independent Project Comparison",
                "",
                f"- Project A: {left['root']}",
                f"- Project B: {right['root']}",
                "",
                "## Shared languages",
                "",
            ]
            lines.extend(f"- {item}" for item in comparison["language_overlap"]["shared"])
            lines.extend(["", "## Shared declared dependencies", ""])
            lines.extend(
                f"- {item}"
                for item in comparison["dependency_overlap"]["shared_declared_dependencies"]
            )
            lines.extend(["", "## Resolved dependency versions", ""])
            for item in comparison["resolved_dependency_overlap"]:
                left_versions = ", ".join(item["left_versions"])
                right_versions = ", ".join(item["right_versions"])
                suffix = " (version conflict)" if item["version_conflict"] else ""
                lines.append(
                    f"- {item['name']}: A={left_versions}; B={right_versions}{suffix}"
                )
            lines.extend(["", "## Shared Python module names", ""])
            lines.extend(
                f"- {item}"
                for item in comparison["python_module_overlap"]["shared_module_names"]
            )
            lines.extend(["", "## Byte-identical files", ""])
            for item in comparison["duplicate_file_content"]:
                lines.append(
                    f"- {item['sha256']}: A={', '.join(item['left_paths'])}; "
                    f"B={', '.join(item['right_paths'])}"
                )
        mapping = comparison.get("integration_map") or {}
        lines.extend(["", "## Integration map", ""])
        if mapping.get("edges"):
            for edge in mapping["edges"]:
                lines.append(f"- {edge['from']} → {edge['to']}: {edge['kind']} ({edge['count']}, {edge['confidence']})")
                lines.extend(f"  - {item}" for item in edge["evidence"][:10])
        else:
            lines.append("- No package, HTTP, messaging or gRPC links were found between the projects.")
        if mapping.get("interpretation"):
            lines.extend(["", f"> {mapping['interpretation']}"])
        lines.extend([
            "",
            "> Similarity is evidence for review, not a recommendation to merge independent projects.",
        ])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(path)
    return written
