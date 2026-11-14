"""VEX documents: the operator's own statements of whether a vulnerability affects their product.

``pdt scan --vex FILE`` reads OpenVEX, CycloneDX VEX and CSAF VEX documents. A statement that
the product is not affected by a vulnerability, or that it is fixed, turns the findings that
match it into INFO findings. Those findings say so and keep their evidence, so the decision
stays reviewable. A statement that the product is affected, or that the vulnerability is
under investigation, is added to the finding. Nothing is fetched.

A statement names its packages through package URLs: OpenVEX subcomponents, the components
a CycloneDX vulnerability affects, and the CSAF products that carry a purl. A statement that
names no package is about the product as a whole, which is what is being scanned. An OpenVEX
statement's ``products`` without subcomponents are such a product. It then applies to every
finding of its vulnerability.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adapters import _csaf_products, purl_package
from .database import normalize_package_name
from .versions import compare_versions

MAX_VEX_BYTES = 64 * 1024 * 1024
MAX_VEX_STATEMENTS = 1_000_000
_MAX_TEXT = 500
STATUSES = frozenset({"not_affected", "fixed", "affected", "under_investigation"})
# The statuses that clear a finding: the product is not exposed.
CLEARING = frozenset({"not_affected", "fixed"})
_CYCLONEDX_STATES = {
    "not_affected": "not_affected", "false_positive": "not_affected", "resolved": "fixed",
    "resolved_with_pedigree": "fixed", "exploitable": "affected", "in_triage": "under_investigation",
}
_CSAF_STATUSES = {
    "known_not_affected": "not_affected", "fixed": "fixed", "first_fixed": "fixed", "known_affected": "affected",
    "first_affected": "affected", "last_affected": "affected", "under_investigation": "under_investigation",
}


@dataclass(frozen=True, slots=True)
class VexStatement:
    """One vulnerability's status for the product, or for one package of it (``ecosystem``
    and ``name``; ``version`` narrows it to one version)."""

    vulnerability: str
    status: str
    ecosystem: str = ""
    name: str = ""
    version: str = ""
    justification: str = ""
    detail: str = ""
    source: str = ""


@dataclass(frozen=True, slots=True)
class VexDocuments:
    statements: tuple[VexStatement, ...]
    names: tuple[str, ...]
    sha256: str  # of the documents' bytes, in order: --resume compares it

    def describe(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for statement in self.statements:
            counts[statement.status] = counts.get(statement.status, 0) + 1
        return {"documents": list(self.names), "statements": len(self.statements),
                "statuses": dict(sorted(counts.items())), "sha256": self.sha256}


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    """Operator text for a report: one line, bounded, without control characters."""
    if not isinstance(value, str):
        return ""
    return " ".join("".join(char if char.isprintable() else " " for char in value).split())[:_MAX_TEXT]


def _package_statements(names: Iterable[str], status: str, purls: Iterable[str], justification: str,
                        detail: str, source: str) -> list[VexStatement]:
    """One statement per vulnerability name and package URL that names a package; per name
    alone when none does (the whole product)."""
    packages = []
    for purl in purls:
        parsed = purl_package(purl) if isinstance(purl, str) else None
        if parsed is not None:
            packages.append(parsed)
    statements = []
    for name in dict.fromkeys(item.strip().upper() for item in names if isinstance(item, str) and item.strip()):
        if not packages:
            statements.append(VexStatement(name, status, justification=justification, detail=detail, source=source))
        for ecosystem, package, version in packages:
            statements.append(VexStatement(name, status, ecosystem, package, version, justification, detail, source))
    return statements


def _purls_of(value: Any) -> list[str]:
    """The package URLs an OpenVEX product or subcomponent names (as a string, its @id, or its
    identifiers' purl)."""
    if isinstance(value, str):
        return [value]
    item = _mapping(value)
    return [purl for purl in (item.get("@id"), _mapping(item.get("identifiers")).get("purl"))
            if isinstance(purl, str) and purl.startswith("pkg:")]


def _openvex(document: dict, source: str) -> list[VexStatement]:
    statements: list[VexStatement] = []
    for statement in map(_mapping, _items(document.get("statements"))):
        vulnerability = statement.get("vulnerability")
        if isinstance(vulnerability, str):
            names = [vulnerability]
        else:
            vulnerability = _mapping(vulnerability)
            names = [vulnerability.get("name"), vulnerability.get("@id"), *_items(vulnerability.get("aliases"))]
        status = str(statement.get("status") or "").strip().lower()
        if status not in STATUSES:
            continue
        # Subcomponents name the packages; products without them are the product itself.
        subcomponents = [purl for item in _items(statement.get("subcomponents")) for purl in _purls_of(item)]
        for product in _items(statement.get("products")):
            subcomponents += [purl for item in _items(_mapping(product).get("subcomponents")) for purl in _purls_of(item)]
        statements += _package_statements(
            [name for name in names if isinstance(name, str) and not name.startswith("http")], status, subcomponents,
            _text(statement.get("justification")),
            _text(statement.get("impact_statement") or statement.get("action_statement") or statement.get("status_notes")),
            source)
    return statements


def _cyclonedx(document: dict, source: str) -> list[VexStatement]:
    purls = {str(_mapping(component).get("bom-ref")): _mapping(component).get("purl")
             for component in _items(document.get("components")) if _mapping(component).get("bom-ref")}
    statements: list[VexStatement] = []
    for vulnerability in map(_mapping, _items(document.get("vulnerabilities"))):
        analysis = _mapping(vulnerability.get("analysis"))
        status = _CYCLONEDX_STATES.get(str(analysis.get("state") or ""))
        if status is None:
            continue
        refs = []
        for target in map(_mapping, _items(vulnerability.get("affects"))):
            reference = str(target.get("ref") or "")
            # A BOM-Link (urn:cdx:serial/version#bom-ref) names a component of another BOM.
            local = reference.rsplit("#", 1)[-1] if reference.startswith("urn:cdx:") else reference
            purl = purls.get(local) or (local if local.startswith("pkg:") else None)
            if isinstance(purl, str):
                refs.append(purl)
        names = [vulnerability.get("id"), *(_mapping(item).get("id") for item in _items(vulnerability.get("references")))]
        statements += _package_statements(
            [name for name in names if isinstance(name, str)], status, refs, _text(analysis.get("justification")),
            _text(analysis.get("detail") or ", ".join(str(item) for item in _items(analysis.get("response")))), source)
    return statements


def _csaf(document: dict, source: str) -> list[VexStatement]:
    purls = _csaf_products(_mapping(document.get("product_tree")))
    statements: list[VexStatement] = []
    for vulnerability in map(_mapping, _items(document.get("vulnerabilities"))):
        names = [vulnerability.get("cve"), *(_mapping(item).get("text") for item in _items(vulnerability.get("ids")))]
        names = [name for name in names if isinstance(name, str)]
        justifications = {str(product): _text(_mapping(flag).get("label"))
                          for flag in _items(vulnerability.get("flags"))
                          for product in _items(_mapping(flag).get("product_ids"))}
        details = {str(product): _text(_mapping(threat).get("details"))
                   for threat in _items(vulnerability.get("threats")) if _mapping(threat).get("category") == "impact"
                   for product in _items(_mapping(threat).get("product_ids"))}
        for state, status in _CSAF_STATUSES.items():
            for product in map(str, _items(_mapping(vulnerability.get("product_status")).get(state))):
                statements += _package_statements(names, status, [purls.get(product, "")],
                                                  justifications.get(product, ""), details.get(product, ""), source)
    return statements


def parse_vex(document: Any, source: str) -> list[VexStatement] | None:
    """The statements of a parsed VEX document, or None when it is no VEX document."""
    if not isinstance(document, dict):
        return None
    if isinstance(document.get("statements"), list) and "openvex" in str(document.get("@context", "")):
        return _openvex(document, source)
    if document.get("bomFormat") == "CycloneDX" and isinstance(document.get("vulnerabilities"), list):
        return _cyclonedx(document, source)
    meta = _mapping(document.get("document"))
    if "csaf_version" in meta and isinstance(document.get("vulnerabilities"), list):
        return _csaf(document, source)
    return None


def load_vex(paths: Iterable[Path]) -> VexDocuments:
    """Read VEX documents; ValueError names a file that is unreadable or not VEX."""
    statements: list[VexStatement] = []
    names: list[str] = []
    digest = hashlib.sha256()
    for path in paths:
        path = Path(path).expanduser()
        try:
            if path.stat().st_size > MAX_VEX_BYTES:
                raise ValueError(f"--vex {path}: larger than {MAX_VEX_BYTES // (1024 * 1024)} MiB")
            data = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"--vex {path}: {exc.strerror or exc}") from exc
        digest.update(hashlib.sha256(data).digest())
        try:
            document = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError(f"--vex {path}: not JSON ({type(exc).__name__})") from exc
        parsed = parse_vex(document, path.name)
        if parsed is None:
            raise ValueError(f"--vex {path}: not an OpenVEX, CycloneDX VEX or CSAF VEX document")
        statements += parsed
        names.append(path.name)
        if len(statements) > MAX_VEX_STATEMENTS:
            raise ValueError(f"--vex: more than {MAX_VEX_STATEMENTS:,} statements")
    return VexDocuments(tuple(statements), tuple(names), digest.hexdigest())


def vex_statement(statements: Iterable[VexStatement], identifiers: Iterable[str], ecosystem: str, name: str,
                  version: str) -> VexStatement | None:
    """The statement that decides a finding: about one of its advisory IDs or aliases, and
    about its package at its version, its package, or the whole product (most specific
    first; a later statement replaces an earlier equally specific one)."""
    wanted = {identifier.upper() for identifier in identifiers}
    base = ecosystem.partition(":")[0].casefold()
    best: tuple[int, VexStatement] | None = None
    for statement in statements:
        if statement.vulnerability not in wanted:
            continue
        rank = 1
        if statement.name:
            if statement.ecosystem.partition(":")[0].casefold() != base or normalize_package_name(
                    ecosystem, statement.name) != normalize_package_name(ecosystem, name):
                continue
            rank = 2
            if statement.version:
                if statement.version != version and compare_versions(statement.version, version, ecosystem) != 0:
                    continue
                rank = 3
        if best is None or rank >= best[0]:
            best = (rank, statement)
    return best[1] if best else None
