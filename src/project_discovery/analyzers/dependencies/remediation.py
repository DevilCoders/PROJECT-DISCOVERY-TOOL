"""Fixed-version suggestions and remediation plans for vulnerable packages.

The suggestion for a package is the lowest release that none of its known advisories
affects, as far as their ranges record fixes. Start at the resolved version, move to the
next fixed version of each advisory that still affects the candidate, and repeat until no
advisory does. An advisory with no recorded fix for the candidate is named, not guessed at.
A lockfile's plan groups the upgrades. Transitive packages are grouped under the direct
dependency that brings them in.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ...models import Finding
from ...vulnerabilities.versions import comparator_for

ANALYZER = "vulnerability-remediation"
MAX_ROUNDS = 50
MAX_PLAN_LINES = 200
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def next_fixed(version: str, affected: dict[str, Any], ecosystem: str) -> str | None:
    """The lowest fixed version above ``version`` that an advisory entry's ranges record."""
    from .vulnerabilities import _normalise_version

    current = _normalise_version(version)
    best: str | None = None
    for item in affected.get("ranges") or [] if isinstance(affected.get("ranges"), list) else []:
        compare = comparator_for(ecosystem, str(item.get("type") or "")) if isinstance(item, dict) else None
        if compare is None:
            continue
        for event in item.get("events") or [] if isinstance(item.get("events"), list) else []:
            fixed = event.get("fixed") if isinstance(event, dict) else None
            if not fixed:
                continue
            fixed = _normalise_version(str(fixed))
            above = compare(current, fixed)
            if above is not None and above < 0 and (best is None or (compare(fixed, best) or 0) < 0):
                best = fixed
    return best


def suggest_upgrade(version: str, advisories: Sequence[dict[str, Any]], ecosystem: str) -> tuple[str | None, list[str]]:
    """(the lowest release none of ``advisories`` affects, or None when the data names none; the
    advisories that record no fix for the versions on the way)."""
    from .vulnerabilities import _affected_version

    candidate = version
    unfixed: set[str] = set()
    for _ in range(MAX_ROUNDS):
        moved = False
        for advisory in advisories:
            if advisory.get("withdrawn"):
                continue
            entry_ecosystem = advisory.get("ecosystem") or ecosystem
            affected, _ = _affected_version(candidate, advisory["affected"], entry_ecosystem)
            if affected is not True:
                continue
            fix = next_fixed(candidate, advisory["affected"], entry_ecosystem)
            if fix is None:
                unfixed.add(str(advisory["id"]))
            else:
                candidate, moved = fix, True
        if not moved:
            break
    return (None if candidate == version else candidate), sorted(unfixed)


def remediation_plan(lockfile: str, items: Sequence[dict[str, Any]], graph: Any, *, analyzer: str = ANALYZER) -> Finding | None:
    """One finding per lockfile with two or more vulnerable packages, grouping their upgrades
    (one package's suggestion is in its own findings). Each item holds a package, its confirmed
    advisories, their highest severity, the suggestion and the advisories without a fix."""
    if len(items) < 2:
        return None
    direct_lines: list[str] = []
    through: dict[str, list[str]] = {}
    unfixed_lines: list[str] = []
    fixes = 0
    for item in sorted(items, key=lambda entry: (_SEVERITY_ORDER.get(entry["severity"], 5), entry["package"].name)):
        package = item["package"]
        ids = ", ".join(item["advisories"][:6]) + (" and more" if len(item["advisories"]) > 6 else "")
        if item["suggestion"]:
            fixes += 1
            line = (f"{package.name} {package.version} -> {item['suggestion']} "
                    f"(fixes {ids}; {item['severity']})")
            path = graph.path(package.name, package.version) if graph is not None and graph.edges_known else None
            if path is not None and len(path) > 1 and not graph.is_direct(package.name):
                through.setdefault(f"{path[0][0]}@{path[0][1]}", []).append(line)
            else:
                direct_lines.append(line)
        if item["unfixed"]:
            unfixed_lines.append(f"{package.name} {package.version}: no recorded fix for {', '.join(item['unfixed'][:6])}")
    evidence = [lockfile, *(f"upgrade: {line}" for line in direct_lines)]
    for parent, lines in sorted(through.items()):
        evidence += [f"upgrade through {parent}: {line}" for line in lines]
    evidence += [f"no fix: {line}" for line in unfixed_lines]
    detail = (f"{fixes:,} upgrade(s) would fix the confirmed advisories of {len(items):,} vulnerable package(s) in "
              f"{lockfile}. Each upgrade is the lowest recorded release that none of the package's known advisories "
              "affects. ")
    if through:
        detail += (f"{sum(map(len, through.values())):,} of them are transitive: upgrade the direct dependency that "
                   f"brings them in ({', '.join(sorted(through)[:5])}) to a release that resolves the fixed version, "
                   "or pin it with an override. ")
    if unfixed_lines:
        detail += (f"{len(unfixed_lines):,} package(s) have advisories that record no fixed version: replace or "
                   "mitigate them, or record the accepted risk in a triage file. ")
    detail += "Versions come from the advisories' ranges; check release notes and run the tests after upgrading."
    return Finding(
        "vulnerabilities", f"Remediation plan: {lockfile}", detail, confidence="INFERRED",
        evidence=evidence[:MAX_PLAN_LINES], analyzer=analyzer, severity="INFO",
    )
