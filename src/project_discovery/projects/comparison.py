"""Evidence-bounded comparison of independent PDT project reports."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ..analyzers.api.integration import EndpointIndex, normalize_route
from ..reporting.writers import md_inline

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
    return _normalized(data)


def _object(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _normalized(data: dict[str, Any]) -> dict[str, Any]:
    """Read the sections comparison uses as empty when they have the wrong type.

    A report from another producer, or edited by hand, may hold null or another type
    where PDT writes an object or a list (for example ``python_dependency_graph: null``).
    Such a section compares as empty instead of failing with a traceback.
    """
    data["files"] = _objects(data.get("files"))
    findings = _objects(data.get("findings"))
    for item in findings:
        item["title"] = str(item.get("title") or "")
        evidence = item.get("evidence")
        item["evidence"] = [str(value) for value in evidence] if isinstance(evidence, list) else []
    data["findings"] = findings
    metrics = _object(data.get("metrics"))
    graph = _object(metrics.get("python_dependency_graph"))
    graph["modules"] = _objects(graph.get("modules"))
    metrics["python_dependency_graph"] = graph
    metrics["languages"] = _object(metrics.get("languages"))
    if "code_index" in metrics:
        # Absence stays absence: the coverage block reports a missing section as unknown.
        code_index = _object(metrics["code_index"])
        if "integration" in code_index:
            integration = _object(code_index["integration"])
            for key in ("packages", "topics"):
                integration[key] = [item for item in _objects(integration.get(key))
                                    if isinstance(item.get("name"), str)]
            for key in ("endpoints", "http_calls"):
                integration[key] = _objects(integration.get(key))
            integration["grpc"] = {
                key: [str(value) for value in values]
                for key, values in _object(integration.get("grpc")).items() if isinstance(values, list)
            }
            code_index["integration"] = integration
        metrics["code_index"] = code_index
    data["metrics"] = metrics
    return data


def _section(report: dict[str, Any], *keys: str) -> dict:
    """``report[keys[0]][keys[1]]...`` as a dict; {} where a level is missing or not a dict."""
    value: Any = report
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return value if isinstance(value, dict) else {}


def project_labels(reports: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """A distinct label per input report, and a warning for each root several inputs share.

    A remote scan's label carries its ref or revision, so two refs of one repository stay
    apart. Inputs that still share a label (before/after scans of one project) are told
    apart by position; before, the second silently replaced the first in every result.
    """
    bases = []
    for report in reports:
        root = str(report.get("root") or "?")
        remote = _section(report, "scan", "remote") or _section(report, "metrics", "source", "remote")
        ref = remote.get("ref") or remote.get("revision")
        bases.append(f"{root}#{ref}" if ref and "#" not in root else root)
    counts = Counter(bases)
    labels = [f"{base} [report {index + 1}]" if counts[base] > 1 else base for index, base in enumerate(bases)]
    warnings = [
        f"{count} input reports have the project label {base}; they are told apart as [report N] by their "
        "position on the command line."
        for base, count in counts.items() if count > 1
    ]
    return labels, warnings


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
        # Empty files are identical everywhere (every package's __init__.py): not a signal.
        if digest and item.get("size_bytes") != 0:
            result[digest].append(item.get("path", ""))
    return dict(result)



_EVIDENCE_OMITTED = re.compile(r"Evidence lists the first [\d,]++; [\d,]++ more are omitted")


_LOCKFILE_ECOSYSTEM = re.compile(r"from an? ([\w.+-]{1,40}+) lockfile")


def _resolved_dependency_versions(report: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    """Resolved versions by (ecosystem, package): every package of every lockfile from the
    code index; for older reports, the first 200 per lockfile that finding evidence lists.
    The ecosystem is part of the key: PyPI redis and npm redis are different packages."""
    resolved: dict[tuple[str, str], set[str]] = defaultdict(set)
    lockfiles = _section(report, "metrics", "code_index", "dependencies").get("lockfiles")
    if isinstance(lockfiles, dict):
        for entry in lockfiles.values():
            entry = entry if isinstance(entry, dict) else {}
            ecosystem = str(entry.get("ecosystem") or "")
            for name, versions in _section(entry, "packages").items():
                if isinstance(versions, list):
                    resolved[(ecosystem, str(name))].update(str(version) for version in versions if version)
        return dict(resolved)
    for finding in report.get("findings", []):
        if not finding.get("title", "").startswith("Resolved dependency inventory:"):
            continue
        match = _LOCKFILE_ECOSYSTEM.search(str(finding.get("detail", "")))
        ecosystem = match.group(1) if match else ""
        for evidence in finding.get("evidence", []):
            if "==" in evidence:
                package, version = evidence.rsplit("==", 1)
                if package and version:
                    resolved[(ecosystem, package)].add(version)
    return dict(resolved)


# Language buckets that name no language: they are never "shared".
_NOT_LANGUAGES = frozenset({"Other", "Objective-C / MATLAB (ambiguous)", "V / Verilog (ambiguous)"})
MAX_DUPLICATES_LISTED = 1000


def _languages(report: dict[str, Any]) -> set[str]:
    return set(_section(report, "metrics", "languages")) - _NOT_LANGUAGES


def _dependency_gaps(report: dict[str, Any]) -> list[str]:
    dependencies = _section(report, "metrics", "code_index", "dependencies")
    lockfiles = dependencies.get("lockfiles")
    if isinstance(lockfiles, dict):
        gaps = [
            f"{path}: {int(entry.get('omitted') or 0):,} resolved package(s) beyond the per-lockfile limit are "
            "not compared"
            for path, entry in sorted(lockfiles.items()) if isinstance(entry, dict) and entry.get("omitted")
        ]
        if dependencies.get("truncated"):
            gaps.append(f"{int(dependencies['truncated']):,} resolved package(s) beyond the scan's limit are not compared")
        return gaps
    partial = [
        str(item.get("title", "")).split(": ", 1)[-1] for item in report.get("findings", [])
        if str(item.get("title", "")).startswith("Resolved dependency inventory:")
        and _EVIDENCE_OMITTED.search(str(item.get("detail", "")))
    ]
    if partial:
        return [
            f"resolved versions come from finding evidence (an older report), which lists only the first 200 "
            f"packages of {len(partial):,} lockfile(s): " + ", ".join(partial[:5])
        ]
    return []


def project_coverage(report: dict[str, Any], label: str) -> dict[str, Any]:
    """What a report cannot tell the comparison, so a missing section never reads as absence."""
    metrics = _section(report, "metrics")
    gaps: list[str] = []
    if _section(report, "metrics", "execution").get("analysis_mode") == "inventory-only":
        gaps.append("inventory-only scan: no file contents were analyzed, so dependencies, file hashes and "
                    "integration points are unknown, not absent")
        return {"project": label, "complete": False, "gaps": gaps}
    code_index = metrics.get("code_index")
    if not isinstance(code_index, dict):
        gaps.append("no code index (an older report): only API findings give integration points")
    elif "skipped" in code_index or "error" in code_index:
        state = "skipped" if "skipped" in code_index else "failed"
        gaps.append(f"code index {state} ({code_index.get('skipped') or code_index.get('error')}): integration "
                    "points and resolved dependencies are unknown")
    else:
        integration = code_index.get("integration")
        if not isinstance(integration, dict):
            gaps.append("no integration summary (an older report): packages, HTTP calls, topics and gRPC services "
                        "are unknown; endpoints come from API findings")
        elif "error" in integration:
            gaps.append(f"integration pass failed ({integration['error']}): integration points are unknown")
        elif isinstance(integration.get("truncated"), dict) and integration["truncated"]:
            gaps.append("integration lists cut at their caps: " + ", ".join(
                f"{name} ({count:,} left out)" for name, count in sorted(integration["truncated"].items())
                if isinstance(count, int)
            ))
    unhashed = sum(
        1 for item in report.get("files", [])
        if isinstance(item, dict) and not item.get("sha256") and not item.get("content_skipped_reason")
        and not item.get("error")
    )
    if unhashed:
        gaps.append(f"{unhashed:,} file(s) have no content hash (an older report, or files not analyzed), so "
                    "byte-identical content is not compared for them")
    gaps.extend(_dependency_gaps(report))
    return {"project": label, "complete": not gaps, "gaps": gaps}


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
    truncated = summary.get("truncated")
    return {
        "packages": list(summary.get("packages") or []), "endpoints": endpoints,
        "http_calls": list(summary.get("http_calls") or []), "topics": list(summary.get("topics") or []),
        "grpc": dict(summary.get("grpc") or {}),
        "truncated": dict(truncated) if isinstance(truncated, dict) else {},
    }


def _package_key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _same_system(left: str, right: str) -> bool:
    return not left or not right or left == right or "pub/sub" in {left, right}


def _shared_channels(left: dict[str, Any], right: dict[str, Any], linked: set[str]) -> list[str]:
    """Topics both projects use without one publishing what the other consumes."""
    shared = set()
    for item in left["topics"]:
        for other in right["topics"]:
            if (item["name"] == other["name"] and item["name"] not in linked
                    and _same_system(item.get("system", ""), other.get("system", ""))):
                shared.add(f"{item['name']} ({item.get('system') or other.get('system') or 'unknown system'}; "
                           f"{item.get('role') or '?'} / {other.get('role') or '?'})")
    return sorted(shared)


def integration_map(reports: list[dict[str, Any]], projects: list[dict[str, Any]]) -> dict[str, Any]:
    """Edges between projects: package dependencies, HTTP calls to served endpoints, topics
    one project publishes and another consumes, and gRPC services one serves and another calls."""
    summaries = [_integration_summary(report) for report in reports]
    declared = [{_package_key(name) for name in _declared_dependencies(report)} for report in reports]
    labels = [str(project.get("label") or project["root"]) for project in projects]
    edges: list[dict[str, Any]] = []
    # Topic names linked by publishing, per unordered project pair.
    linked: dict[tuple[int, int], set[str]] = defaultdict(set)
    for provider_index, provider in enumerate(summaries):
        index = EndpointIndex([(item.get("method", ""), item.get("path", "")) for item in provider["endpoints"]])
        services = {name.rsplit(".", 1)[-1] for name in provider["grpc"].get("service", [])} | set(
            provider["grpc"].get("server", []))
        # Only publishing counts: declaring a queue (queue_declare, assertQueue) is what
        # competing consumers do too, so it made two consumers "publish" to each other.
        produced = {(item["name"], item.get("system", "")) for item in provider["topics"]
                    if item.get("role") == "produce"}
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
            matched = [
                (item["name"], item.get("system") or system) for item in consumer["topics"]
                if item.get("role") == "consume"
                for name, system in produced
                if item["name"] == name and _same_system(item.get("system", ""), system)
            ]
            topics = sorted({f"{name} ({system})" for name, system in matched})
            if topics:
                linked[tuple(sorted((provider_index, consumer_index)))].update(name for name, _ in matched)
                edges.append({"from": provider_label, "to": consumer_label, "kind": "messaging", "count": len(topics),
                              "evidence": topics[:MAX_EDGE_EVIDENCE], "confidence": "INFERRED"})
            grpc = sorted(services & set(consumer["grpc"].get("client", [])))
            if grpc:
                edges.append({"from": consumer_label, "to": provider_label, "kind": "grpc", "count": len(grpc),
                              "evidence": grpc[:MAX_EDGE_EVIDENCE], "confidence": "INFERRED"})
    for left_index in range(len(summaries)):
        for right_index in range(left_index + 1, len(summaries)):
            shared = _shared_channels(summaries[left_index], summaries[right_index],
                                      linked[(left_index, right_index)])
            if shared:
                edges.append({"from": labels[left_index], "to": labels[right_index], "kind": "shared_channel",
                              "count": len(shared), "evidence": shared[:MAX_EDGE_EVIDENCE],
                              "confidence": "INFERRED"})
    return {
        "edges": edges,
        "projects": [
            {"root": labels[index], "packages": [item["name"] for item in summary["packages"]][:20],
             "endpoints": len(summary["endpoints"]), "http_calls": len(summary["http_calls"]),
             "topics": len(summary["topics"]), "grpc_services": len(summary["grpc"].get("service", [])),
             # Lists cut at the scan's caps; links through what was left out are missing.
             "truncated": summary["truncated"]}
            for index, summary in enumerate(summaries)
        ],
        "interpretation": (
            "`from` depends on or calls `to`; for messaging, `from` publishes what `to` consumes. A shared_channel "
            "edge has no direction: both projects use the topic or queue (for example as competing consumers) "
            "and neither publishes what the other consumes. Package edges are CONFIRMED declarations; HTTP, "
            "messaging, shared-channel and gRPC edges are INFERRED from literal paths, topic and service names "
            "and need confirmation of deployment and configuration."
        ),
    }


def compare_reports(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, Any]:
    """Compare two independent project reports without merging their identities."""
    left_languages = _languages(left)
    right_languages = _languages(right)
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
            "name": package[1],
            "ecosystem": package[0],
            "left_versions": sorted(left_resolved[package]),
            "right_versions": sorted(right_resolved[package]),
            # The same rule as all_projects_shared: the projects' version sets differ.
            "version_conflict": left_resolved[package] != right_resolved[package],
        }
        for package in sorted(set(left_resolved) & set(right_resolved))
    ]
    labels, warnings = project_labels([left, right])
    coverage = [project_coverage(report, label) for report, label in zip((left, right), labels, strict=True)]
    return {
        "schema_version": "1.2",
        "comparison_type": "independent_project_reports",
        "projects": [
            {"root": left.get("root"), "label": labels[0], "file_count": len(left.get("files", []))},
            {"root": right.get("root"), "label": labels[1], "file_count": len(right.get("files", []))},
        ],
        # What each report cannot show; a section that is empty because of a gap is unknown.
        "coverage": coverage,
        "warnings": warnings + [f"{item['project']}: {gap}" for item in coverage for gap in item["gaps"]],
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
            [left, right], [{"root": left.get("root"), "label": label} for label in labels],
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
    labels, warnings = project_labels(reports)
    projects = [
        {"root": report.get("root"), "label": label, "file_count": len(report.get("files", []))}
        for report, label in zip(reports, labels, strict=True)
    ]
    coverage = [project_coverage(report, label) for report, label in zip(reports, labels, strict=True)]
    language_sets = [_languages(report) for report in reports]
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
            "name": package[1],
            "ecosystem": package[0],
            "versions_by_project": {
                labels[index]: sorted(item[package]) for index, item in enumerate(resolved_sets)
            },
            # Version sets that differ between projects, as in the pairwise results (a
            # project resolving two versions itself is not a conflict with an identical one).
            "version_conflict": len({frozenset(item[package]) for item in resolved_sets}) > 1,
        }
        for package in sorted(common_resolved)
    ]
    duplicates = []
    duplicate_total = 0
    for digest, locations in sorted(shared_hashes.items()):
        if len(locations) >= 2:
            duplicate_total += 1
            if len(duplicates) >= MAX_DUPLICATES_LISTED:
                continue
            duplicates.append({
                "sha256": digest,
                "projects": {
                    labels[index]: sorted(paths) for index, paths in sorted(locations.items())
                },
                "confidence": "CONFIRMED",
            })

    pairwise = []
    for left_index in range(len(reports)):
        for right_index in range(left_index + 1, len(reports)):
            result = compare_reports(reports[left_index], reports[right_index])
            pairwise.append({
                "left_project": labels[left_index],
                "right_project": labels[right_index],
                "shared_languages": result["language_overlap"]["shared"],
                "shared_declared_dependencies": result["dependency_overlap"]["shared_declared_dependencies"],
                "shared_python_module_names": result["python_module_overlap"]["shared_module_names"],
                "duplicate_file_count": len(result["duplicate_file_content"]),
                "dependency_version_conflict_count": sum(
                    1 for item in result["resolved_dependency_overlap"] if item["version_conflict"]
                ),
            })

    return {
        "schema_version": "1.2",
        "comparison_type": "independent_project_reports",
        "projects": projects,
        "coverage": coverage,
        "warnings": warnings + [f"{item['project']}: {gap}" for item in coverage for gap in item["gaps"]],
        "all_projects_shared": {
            "languages": sorted(common_languages),
            "declared_dependencies": sorted(common_dependencies),
            "python_module_names": sorted(common_modules),
            "resolved_dependencies": resolved_across_all,
            "api_evidence": sorted(common_api),
        },
        "pairwise_comparisons": pairwise,
        "duplicate_file_content": duplicates,
        # Shared digests in all; the list above holds the first MAX_DUPLICATES_LISTED.
        "duplicate_file_total": duplicate_total,
        "integration_map": integration_map(reports, projects),
        "interpretation": {
            "shared_dependencies": "CONFIRMED declarations; not proof of compatible versions or runtime use.",
            "shared_module_names": "INFERRED naming overlap; not proof of equivalent implementation.",
            "shared_api_evidence": "CONFIRMED matching evidence strings; not proof of API compatibility.",
            "duplicate_file_content": "CONFIRMED byte-identical content based on SHA-256 report fingerprints.",
            "integration_recommendation": "Not generated. Similarity is evidence for human review, not authorization to merge projects.",
        },
    }


def _coverage_lines(comparison: dict[str, Any]) -> list[str]:
    """The Markdown coverage section: what the inputs cannot show."""
    m = md_inline
    warnings = [item for item in comparison.get("warnings") or [] if isinstance(item, str)]
    if not warnings:
        return []
    return ["", "## Coverage", "", "Sections that depend on missing evidence are partial: an empty result there "
            "is unknown, not absent.", "", *(f"- {m(item)}" for item in warnings)]


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
        # Every value comes from scanned projects: neutralize HTML, links and new blocks.
        m = md_inline
        if "all_projects_shared" in comparison:
            shared = comparison["all_projects_shared"]
            lines = [
                "# Independent Project Comparison",
                "",
                "## Projects",
                "",
            ]
            lines.extend(
                f"- {m(project.get('label') or project['root'])} ({project['file_count']} files)"
                for project in comparison["projects"]
            )
            lines.extend(_coverage_lines(comparison))
            lines.extend(["", "## Shared across all projects", "", "### Languages"])
            lines.extend(f"- {m(item)}" for item in shared["languages"])
            lines.extend(["", "### Declared dependencies"])
            lines.extend(f"- {m(item)}" for item in shared["declared_dependencies"])
            lines.extend(["", "### Resolved dependency versions"])
            for item in shared["resolved_dependencies"]:
                versions = "; ".join(
                    "{}={}".format(m(project), ", ".join(m(value) for value in values))
                    for project, values in item["versions_by_project"].items()
                )
                suffix = " (version conflict)" if item["version_conflict"] else ""
                lines.append(f"- {m(item['name'])}: {versions}{suffix}")
            lines.extend(["", "### Python module names"])
            lines.extend(f"- {m(item)}" for item in shared["python_module_names"])
            lines.extend(["", "### API evidence"])
            lines.extend(f"- {m(item)}" for item in shared.get("api_evidence", []))
            lines.extend(["", "## Pairwise overlap", ""])
            for item in comparison["pairwise_comparisons"]:
                lines.append(
                    f"- {m(item['left_project'])} ↔ {m(item['right_project'])}: "
                    f"{len(item['shared_languages'])} languages, "
                    f"{len(item['shared_declared_dependencies'])} dependencies, "
                    f"{item['duplicate_file_count']} duplicate files, "
                    f"{item['dependency_version_conflict_count']} version conflicts"
                    + (f"; module names: {', '.join(m(name) for name in item['shared_python_module_names'][:20])}"
                       if item.get("shared_python_module_names") else "")
                )
            lines.extend(["", "## Byte-identical content", ""])
            if comparison.get("duplicate_file_total", 0) > len(comparison["duplicate_file_content"]):
                lines.append(f"- {comparison['duplicate_file_total']:,} shared digests; the first "
                             f"{len(comparison['duplicate_file_content']):,} are listed (empty files are not counted).")
            for item in comparison["duplicate_file_content"]:
                locations = "; ".join(
                    "{}: {}".format(m(project), ", ".join(m(path) for path in paths))
                    for project, paths in item["projects"].items()
                )
                lines.append(f"- {m(item['sha256'])}: {locations}")
        else:
            left, right = comparison["projects"]
            lines = [
                "# Independent Project Comparison",
                "",
                f"- Project A: {m(left.get('label') or left['root'])}",
                f"- Project B: {m(right.get('label') or right['root'])}",
                *_coverage_lines(comparison),
                "",
                "## Shared languages",
                "",
            ]
            lines.extend(f"- {m(item)}" for item in comparison["language_overlap"]["shared"])
            lines.extend(["", "## Shared declared dependencies", ""])
            lines.extend(
                f"- {m(item)}"
                for item in comparison["dependency_overlap"]["shared_declared_dependencies"]
            )
            lines.extend(["", "## Resolved dependency versions", ""])
            for item in comparison["resolved_dependency_overlap"]:
                left_versions = ", ".join(m(value) for value in item["left_versions"])
                right_versions = ", ".join(m(value) for value in item["right_versions"])
                suffix = " (version conflict)" if item["version_conflict"] else ""
                lines.append(
                    f"- {m(item['name'])}: A={left_versions}; B={right_versions}{suffix}"
                )
            lines.extend(["", "## Shared Python module names", ""])
            lines.extend(
                f"- {m(item)}"
                for item in comparison["python_module_overlap"]["shared_module_names"]
            )
            lines.extend(["", "## Byte-identical files", ""])
            for item in comparison["duplicate_file_content"]:
                lines.append(
                    f"- {m(item['sha256'])}: A={', '.join(m(path) for path in item['left_paths'])}; "
                    f"B={', '.join(m(path) for path in item['right_paths'])}"
                )
        mapping = comparison.get("integration_map") or {}
        lines.extend(["", "## Integration map", ""])
        if mapping.get("edges"):
            for edge in mapping["edges"]:
                lines.append(
                    f"- {m(edge['from'])} → {m(edge['to'])}: {m(edge['kind'])} "
                    f"({edge['count']}, {m(edge['confidence'])})"
                )
                lines.extend(f"  - {m(item)}" for item in edge["evidence"][:10])
        elif any(not item.get("complete", True) for item in comparison.get("coverage") or []):
            lines.append("- No links were found, but the evidence is incomplete (see Coverage): this is not "
                         "evidence that the projects are unrelated.")
        else:
            lines.append("- No package, HTTP, messaging or gRPC links were found between the projects.")
        if mapping.get("interpretation"):
            lines.extend(["", f"> {m(mapping['interpretation'])}"])
        lines.extend([
            "",
            "> Similarity is evidence for review, not a recommendation to merge independent projects.",
        ])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(path)
    return written
