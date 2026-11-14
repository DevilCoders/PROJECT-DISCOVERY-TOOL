"""Advisory formats other than OSV, converted to OSV records for the local store.

``pdt vuln-db import`` accepts, besides OSV records, files in these formats; each is turned
into OSV-shaped records so one matcher and one finding builder serve every source. Nothing
is fetched: the operator downloads the files.

- NVD CVE JSON: API 2.0 responses and 2.0 yearly feeds (``vulnerabilities[].cve``) and the
  retired 1.1 feeds (``CVE_Items``). A CVE names products by CPE, not by package, so its
  affected entries use the ``CPE`` ecosystem (``vendor:product``) with the CPE criteria kept;
  its CVSS metrics also give a severity to the OSV advisories that alias it.
- GitHub Security Advisories as the REST API exports them (``ghsa_id``, ``vulnerabilities``).
  The github/advisory-database repository is OSV already.
- The Debian security tracker's JSON (``package -> CVE -> releases``), per release
  (``Debian:12``); Ubuntu publishes OSV records, which import as they are.
- Alpine secdb (``secfixes`` per branch: ``Alpine:v3.19``).
- CSAF 2.0 documents: Red Hat's and other vendors' security advisories and VEX files; the
  products that name a purl become affected packages (fixed products give the fixed version).
- CycloneDX vulnerabilities (an SBOM's VDR or a VEX BOM): the affected components' purls.
"""
from __future__ import annotations

import re
from typing import Any, Iterator
from urllib.parse import unquote

# GitHub's REST ecosystem names, as OSV names them.
_GHSA_ECOSYSTEMS = {
    "npm": "npm", "pip": "PyPI", "maven": "Maven", "nuget": "NuGet", "composer": "Packagist",
    "rubygems": "RubyGems", "go": "Go", "rust": "crates.io", "erlang": "Hex", "pub": "Pub",
    "swift": "SwiftURL", "actions": "GitHub Actions",
}
# Debian release code names and their OSV ecosystem suffix.
_DEBIAN_RELEASES = {
    "jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13",
    "forky": "14", "duke": "15",
}
# Ubuntu code names a purl's distro qualifier may give instead of the version.
_UBUNTU_RELEASES = {
    "trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04",
    "lunar": "23.04", "mantic": "23.10", "noble": "24.04", "oracular": "24.10", "plucky": "25.04",
    "questing": "25.10", "resolute": "26.04",
}
_UBUNTU_VERSION = re.compile(r"[0-9]{2}\.[0-9]{2}")
_DEBIAN_URGENCY = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "unimportant": "LOW"}
_CVSS_TYPES = (("cvssMetricV40", "CVSS_V4"), ("cvssMetricV31", "CVSS_V3"), ("cvssMetricV30", "CVSS_V3"),
               ("cvssMetricV2", "CVSS_V2"))
# CycloneDX rating methods: the OSV severity type and the prefix a bare vector needs.
_CYCLONEDX_CVSS = {"CVSSv2": ("CVSS_V2", ""), "CVSSv3": ("CVSS_V3", "CVSS:3.0/"),
                   "CVSSv31": ("CVSS_V3", "CVSS:3.1/"), "CVSSv4": ("CVSS_V4", "CVSS:4.0/")}
_ADVISORY_ID = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{2,99}")
_MAX_TEXT = 100_000


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _items(value: Any) -> list:
    return value if isinstance(value, list) else []


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------------------------
# Package URLs


def ubuntu_ecosystem(version: str) -> str:
    """OSV's name for an Ubuntu release: ``Ubuntu:22.04:LTS`` (every even year's April release
    is a long-term one), ``Ubuntu:23.10``; ``Ubuntu`` alone, which no advisory names, without one."""
    number = _UBUNTU_RELEASES.get(version.lower(), version)[:5]
    if not _UBUNTU_VERSION.fullmatch(number):
        return "Ubuntu"
    return f"Ubuntu:{number}" + (":LTS" if number.endswith(".04") and int(number[:2]) % 2 == 0 else "")


def _distribution_ecosystem(kind: str, vendor: str, release: str) -> str | None:
    """The OSV ecosystem of a distribution package URL, from its vendor and the release its
    distro qualifier names (``debian-12``, ``bookworm``, ``ubuntu-22.04``, ``alpine-3.19.1``,
    ``rhel-9.3``)."""
    major = release.split(".")[0]
    if kind == "deb" and vendor == "debian":
        major = _DEBIAN_RELEASES.get(release, major)
        return f"Debian:{major}" if major.isdigit() else "Debian"
    if kind == "deb" and vendor == "ubuntu":
        return ubuntu_ecosystem(release)
    if kind == "apk" and vendor == "alpine":
        numbers = release.lstrip("v").split(".")
        if len(numbers) >= 2 and numbers[0].isdigit() and numbers[1].isdigit():
            return f"Alpine:v{numbers[0]}.{numbers[1]}"
        return "Alpine"
    if kind == "rpm":
        label = {"redhat": "Red Hat", "almalinux": "AlmaLinux", "rocky": "Rocky Linux", "fedora": "Fedora",
                 "opensuse": "openSUSE", "suse": "SUSE"}.get(vendor)
        if label in {"AlmaLinux", "Rocky Linux"} and major.isdigit():
            return f"{label}:{major}"
        return label
    return None


def purl_package(purl: str) -> tuple[str, str, str] | None:
    """(OSV ecosystem, package name, version) of a package URL, or None for a purl no OSV
    ecosystem names. Distribution packages keep their release in the ecosystem
    (``pkg:deb/debian/openssl@3.0.11-1?distro=debian-12`` is ``Debian:12``). Debian, Ubuntu
    and Alpine advisories name source packages: a binary package's ``upstream`` qualifier
    (``upstream=openssl`` or ``upstream=zlib@1:1.2.13.dfsg-1``, as Syft writes it) gives the
    source package and its version."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0]
    body, _, query = body.partition("?")
    path, _, version = body.partition("@")
    parts = [unquote(part) for part in path.split("/") if part]
    if len(parts) < 2:
        return None
    kind, namespace, name = parts[0].lower(), parts[1:-1], parts[-1]
    qualifiers = dict(item.partition("=")[::2] for item in query.split("&") if "=" in item)
    version = unquote(version)
    simple = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "gem": "RubyGems", "nuget": "NuGet",
              "composer": "Packagist", "hex": "Hex", "pub": "Pub", "cran": "CRAN", "hackage": "Hackage",
              "conan": "ConanCenter", "swift": "SwiftURL", "cocoapods": "CocoaPods"}
    if kind in simple:
        prefix = "/".join(namespace)
        if kind == "npm" and prefix:
            return "npm", f"{prefix}/{name}", version
        if kind == "composer" and prefix:
            return "Packagist", f"{prefix}/{name}", version
        if kind == "swift" and prefix:
            return "SwiftURL", f"{prefix}/{name}", version
        return simple[kind], name, version
    if kind == "maven" and namespace:
        return "Maven", f"{'.'.join(namespace) if len(namespace) > 1 else namespace[0]}:{name}", version
    if kind == "golang":
        return "Go", "/".join([*namespace, name]), version
    if kind in {"deb", "apk", "rpm"} and namespace:
        release = unquote(qualifiers.get("distro", "")).rsplit("-", 1)[-1].lower()
        ecosystem = _distribution_ecosystem(kind, namespace[0].lower(), release)
        if ecosystem is None:
            return None
        if kind == "rpm":
            # Red Hat's advisories name binary packages; the epoch is a qualifier.
            epoch = unquote(qualifiers.get("epoch", ""))
            return ecosystem, name, (f"{epoch}:{version}" if epoch and epoch != "0" else version)
        source, _, source_version = unquote(qualifiers.get("upstream", "")).partition("@")
        return ecosystem, source.strip() or name, source_version.strip() or version
    return None


# ---------------------------------------------------------------------------------------------
# NVD


def _nvd_severity(metrics: dict) -> list[dict]:
    severity = []
    for key, kind in _CVSS_TYPES:
        for item in _items(metrics.get(key))[:1]:
            vector = _mapping(_mapping(item).get("cvssData")).get("vectorString")
            if isinstance(vector, str) and vector:
                severity.append({"type": kind, "score": vector})
    return severity


def _cpe_affected(match: dict) -> dict | None:
    """An OSV affected entry for one vulnerable CPE match: ``vendor:product`` in the CPE
    ecosystem, the version or bounds as written, and the criteria kept for CPE matching."""
    criteria = match.get("criteria") or match.get("cpe23Uri")
    if not match.get("vulnerable") or not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    fields = criteria.split(":")
    if len(fields) < 6:
        return None
    vendor, product, version = fields[3], fields[4], fields[5]
    bounds = {key: match[key] for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                                          "versionEndExcluding") if isinstance(match.get(key), str)}
    entry: dict[str, Any] = {"package": {"ecosystem": "CPE", "name": f"{vendor}:{product}"},
                             "database_specific": {"cpe": criteria, **bounds}}
    if bounds:
        # OSV events cannot say "excluding" for a start: the CPE matcher reads the bounds kept above.
        events = [{"introduced": bounds.get("versionStartIncluding") or bounds.get("versionStartExcluding") or "0"}]
        if "versionEndExcluding" in bounds:
            events.append({"fixed": bounds["versionEndExcluding"]})
        elif "versionEndIncluding" in bounds:
            events.append({"last_affected": bounds["versionEndIncluding"]})
        entry["ranges"] = [{"type": "CPE", "events": events}]
    elif version not in {"*", "-", ""}:
        entry["versions"] = [version]
    else:
        entry["ranges"] = [{"type": "CPE", "events": [{"introduced": "0"}]}]
    return entry


def _cpe_matches(nodes: Any) -> Iterator[dict]:
    for node in _items(nodes):
        node = _mapping(node)
        if node.get("negate"):
            continue
        yield from (_mapping(match) for match in _items(node.get("cpeMatch") or node.get("cpe_match")))
        yield from _cpe_matches(node.get("children"))


def _nvd_record(cve: dict, *, published: Any, modified: Any, description: str, references: list[str],
                severity: list[dict], matches: Iterator[dict], rejected: bool, weaknesses: list[str]) -> dict | None:
    identifier = cve.get("id") or _mapping(cve.get("CVE_data_meta")).get("ID")
    if not isinstance(identifier, str) or not identifier.startswith("CVE-"):
        return None
    affected, seen = [], set()
    for match in matches:
        entry = _cpe_affected(match)
        if entry is not None and entry["database_specific"]["cpe"] not in seen and len(affected) < 2_000:
            seen.add(entry["database_specific"]["cpe"])
            affected.append(entry)
    return {
        "id": identifier, "aliases": [], "summary": description.split(". ", 1)[0][:300] or identifier,
        "details": description, "published": published, "modified": modified,
        "withdrawn": modified if rejected else None, "severity": severity, "affected": affected,
        "references": [{"type": "WEB", "url": url} for url in references[:200]],
        "database_specific": {"source": "NVD", "cwe": weaknesses[:20]},
    }


def _nvd_2(document: dict) -> Iterator[dict]:
    for item in _items(document.get("vulnerabilities")):
        cve = _mapping(_mapping(item).get("cve"))
        descriptions = [_text(entry.get("value")) for entry in map(_mapping, _items(cve.get("descriptions")))
                        if entry.get("lang") == "en"]
        weaknesses = [str(description.get("value")) for weakness in map(_mapping, _items(cve.get("weaknesses")))
                      for description in map(_mapping, _items(weakness.get("description")))
                      if str(description.get("value", "")).startswith("CWE-")]
        record = _nvd_record(
            cve, published=cve.get("published"), modified=cve.get("lastModified"),
            description=descriptions[0] if descriptions else "",
            references=[str(ref.get("url")) for ref in map(_mapping, _items(cve.get("references"))) if ref.get("url")],
            severity=_nvd_severity(_mapping(cve.get("metrics"))),
            matches=(match for configuration in map(_mapping, _items(cve.get("configurations")))
                     for match in _cpe_matches(configuration.get("nodes"))),
            rejected=str(cve.get("vulnStatus", "")).lower() == "rejected", weaknesses=weaknesses)
        if record:
            yield record


def _nvd_1(document: dict) -> Iterator[dict]:
    for item in map(_mapping, _items(document.get("CVE_Items"))):
        cve = _mapping(item.get("cve"))
        descriptions = [_text(entry.get("value")) for entry in
                        map(_mapping, _items(_mapping(cve.get("description")).get("description_data")))
                        if entry.get("lang") == "en"]
        impact = _mapping(item.get("impact"))
        severity = []
        for key, inner, kind in (("baseMetricV3", "cvssV3", "CVSS_V3"), ("baseMetricV2", "cvssV2", "CVSS_V2")):
            vector = _mapping(_mapping(impact.get(key)).get(inner)).get("vectorString")
            if isinstance(vector, str) and vector:
                severity.append({"type": kind, "score": vector})
        record = _nvd_record(
            cve, published=item.get("publishedDate"), modified=item.get("lastModifiedDate"),
            description=descriptions[0] if descriptions else "",
            references=[str(ref.get("url")) for ref in
                        map(_mapping, _items(_mapping(cve.get("references")).get("reference_data"))) if ref.get("url")],
            severity=severity, matches=_cpe_matches(_mapping(item.get("configurations")).get("nodes")),
            rejected=descriptions[0].startswith("** REJECT **") if descriptions else False, weaknesses=[])
        if record:
            yield record


# ---------------------------------------------------------------------------------------------
# GitHub Security Advisories (REST)


def ghsa_ranges(expression: str) -> list[dict] | None:
    """OSV range events of a GitHub vulnerable_version_range (">= 1.0, < 1.2.3", "<= 2.0",
    "= 1.0.0"); None when it cannot be written as events (an exclusive lower bound)."""
    introduced, upper = "0", None
    exact = None
    for clause in (part.strip() for part in expression.split(",") if part.strip()):
        operator = next((op for op in (">=", "<=", ">", "<", "=") if clause.startswith(op)), None)
        if operator is None:
            return None
        value = clause[len(operator):].strip()
        if not value:
            return None
        if operator == ">=":
            introduced = value
        elif operator == ">":
            return None  # "greater than" has no OSV event; the range is kept as unsupported
        elif operator == "<":
            upper = {"fixed": value}
        elif operator == "<=":
            upper = {"last_affected": value}
        else:
            exact = value
    if exact is not None:
        return [{"exact": exact}]
    return [{"introduced": introduced}, *([upper] if upper else [])]


def _ghsa(document: list) -> Iterator[dict]:
    for item in map(_mapping, document):
        identifier = item.get("ghsa_id")
        if not isinstance(identifier, str) or not identifier.startswith("GHSA-"):
            continue
        aliases = sorted({value for value in [item.get("cve_id"), *(
            _mapping(entry).get("value") for entry in _items(item.get("identifiers")))]
            if isinstance(value, str) and value and value != identifier})
        severity = []
        for kind, key in (("CVSS_V4", "cvss_v4"), ("CVSS_V3", "cvss_v3")):
            vector = _mapping(_mapping(item.get("cvss_severities")).get(key)).get("vector_string")
            if isinstance(vector, str) and vector:
                severity.append({"type": kind, "score": vector})
        vector = _mapping(item.get("cvss")).get("vector_string")
        if not severity and isinstance(vector, str) and vector:
            severity.append({"type": "CVSS_V4" if vector.startswith("CVSS:4") else "CVSS_V3", "score": vector})
        affected = []
        for vulnerability in map(_mapping, _items(item.get("vulnerabilities"))):
            package = _mapping(vulnerability.get("package"))
            ecosystem = _GHSA_ECOSYSTEMS.get(str(package.get("ecosystem", "")).lower())
            name = package.get("name")
            if not ecosystem or not isinstance(name, str) or not name:
                continue
            expression = str(vulnerability.get("vulnerable_version_range") or "")
            events = ghsa_ranges(expression) if expression else None
            patched = vulnerability.get("first_patched_version")
            patched = patched.get("identifier") if isinstance(patched, dict) else patched
            entry: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name},
                                     "database_specific": {"vulnerable_version_range": expression[:200]}}
            if events and "exact" in events[0]:
                entry["versions"] = [events[0]["exact"]]
            elif events:
                if len(events) == 1 and isinstance(patched, str) and patched:
                    events.append({"fixed": patched})
                entry["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
            else:
                # Unreadable bounds: matching reports the package's status as unknown.
                entry["ranges"] = [{"type": "GHSA_RANGE", "events": [{"introduced": "0"}]}]
            affected.append(entry)
        yield {
            "id": identifier, "aliases": aliases, "summary": _text(item.get("summary"), 300) or identifier,
            "details": _text(item.get("description")), "published": item.get("published_at"),
            "modified": item.get("updated_at"), "withdrawn": item.get("withdrawn_at"), "severity": severity,
            "affected": affected,
            "references": [{"type": "WEB", "url": str(url)} for url in _items(item.get("references"))[:200]
                           if isinstance(url, str)],
            "database_specific": {"severity": str(item.get("severity") or "").upper(), "source": "GHSA"},
        }


# ---------------------------------------------------------------------------------------------
# Debian, Alpine


def _debian(document: dict) -> Iterator[dict]:
    """The Debian security tracker's JSON: one OSV record per issue, with an affected entry per
    package and release. A fixed version of "0" means the release was never affected."""
    issues: dict[str, dict] = {}
    for package, entries in document.items():
        for issue, data in _mapping(entries).items():
            data = _mapping(data)
            if not isinstance(issue, str) or not data.get("releases"):
                continue
            record = issues.setdefault(issue, {
                "id": f"DEBIAN-{issue}", "aliases": [issue] if issue.startswith("CVE-") else [],
                "summary": _text(data.get("description"), 300) or issue, "details": _text(data.get("description")),
                "affected": [], "references": [{"type": "WEB",
                                                "url": f"https://security-tracker.debian.org/tracker/{issue}"}],
                "database_specific": {"source": "Debian security tracker", "severity": ""},
            })
            for release, status in _mapping(data.get("releases")).items():
                status = _mapping(status)
                number = _DEBIAN_RELEASES.get(str(release))
                state, fixed = status.get("status"), status.get("fixed_version")
                if not number or state not in {"resolved", "open"} or fixed == "0":
                    continue  # sid has no OSV release; "undetermined" says nothing either way
                if state == "resolved" and not (isinstance(fixed, str) and fixed.strip()):
                    continue  # resolved without a version gives a match nothing to compare
                urgency = _DEBIAN_URGENCY.get(str(status.get("urgency", "")).split("*")[0].strip())
                if urgency and not record["database_specific"]["severity"]:
                    record["database_specific"]["severity"] = urgency
                events = [{"introduced": "0"}] + ([{"fixed": fixed.strip()}] if state == "resolved" else [])
                record["affected"].append({"package": {"ecosystem": f"Debian:{number}", "name": str(package)},
                                           "ranges": [{"type": "ECOSYSTEM", "events": events}]})
    yield from (record for record in issues.values() if record["affected"])


def _alpine(document: dict) -> Iterator[dict]:
    """Alpine secdb: each package's secfixes, a fixed version and the issues it fixes. The
    "0" key lists issues that never affected the branch."""
    version = str(document.get("distroversion") or "")
    branch = "v" + ".".join(version.lstrip("v").split(".")[:2]) if version else ""
    if not branch:
        return
    issues: dict[str, dict] = {}
    for item in map(_mapping, _items(document.get("packages"))):
        package = _mapping(item.get("pkg"))
        name = package.get("name")
        for fixed, identifiers in _mapping(package.get("secfixes")).items():
            if fixed == "0" or not isinstance(name, str):
                continue
            for value in _items(identifiers):
                for issue in str(value).split():
                    if not _ADVISORY_ID.fullmatch(issue):
                        continue
                    record = issues.setdefault(issue, {
                        "id": f"ALPINE-{issue}", "aliases": [issue] if issue.startswith("CVE-") else [],
                        "summary": f"{issue} fixed in Alpine {branch}", "details": "", "affected": [],
                        "references": [], "database_specific": {"source": "Alpine secdb"},
                    })
                    record["affected"].append({
                        "package": {"ecosystem": f"Alpine:{branch}", "name": name},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": str(fixed)}]}]})
    yield from issues.values()


# ---------------------------------------------------------------------------------------------
# CSAF and CycloneDX


def _csaf_products(tree: dict) -> dict[str, str]:
    """Product IDs of a CSAF product tree mapped to the purl that identifies them; a
    relationship's combined product takes its component's purl."""
    purls: dict[str, str] = {}

    def visit(branch: dict, depth: int = 0) -> None:
        if depth > 30:
            return
        product = _mapping(branch.get("product"))
        purl = _mapping(product.get("product_identification_helper")).get("purl")
        if isinstance(purl, str) and product.get("product_id"):
            purls[str(product["product_id"])] = purl
        for child in map(_mapping, _items(branch.get("branches"))):
            visit(child, depth + 1)

    visit(tree)
    for product in map(_mapping, _items(tree.get("full_product_names"))):
        purl = _mapping(product.get("product_identification_helper")).get("purl")
        if isinstance(purl, str) and product.get("product_id"):
            purls[str(product["product_id"])] = purl
    for relationship in map(_mapping, _items(tree.get("relationships"))):
        combined = _mapping(relationship.get("full_product_name")).get("product_id")
        component = purls.get(str(relationship.get("product_reference")))
        if combined and component:
            purls.setdefault(str(combined), component)
    return purls


def _csaf(document: dict) -> Iterator[dict]:
    meta = _mapping(document.get("document"))
    tracking = _mapping(meta.get("tracking"))
    identifier = str(tracking.get("id") or "")
    if not identifier:
        return
    purls = _csaf_products(_mapping(document.get("product_tree")))
    for vulnerability in map(_mapping, _items(document.get("vulnerabilities"))):
        cve = vulnerability.get("cve")
        status = _mapping(vulnerability.get("product_status"))
        affected, seen = [], set()
        for state in ("fixed", "known_affected"):
            for product in _items(status.get(state)):
                parsed = purl_package(purls.get(str(product), ""))
                if parsed is None:
                    continue
                ecosystem, name, version = parsed
                key = (ecosystem, name, state, version)
                if key in seen or not version:
                    continue
                seen.add(key)
                if state == "fixed":
                    affected.append({"package": {"ecosystem": ecosystem, "name": name},
                                     "ranges": [{"type": "ECOSYSTEM",
                                                 "events": [{"introduced": "0"}, {"fixed": version}]}]})
                else:
                    affected.append({"package": {"ecosystem": ecosystem, "name": name}, "versions": [version]})
        if not affected:
            continue
        scores = [_mapping(score.get("cvss_v3")).get("vectorString") for score in map(_mapping,
                                                                                         _items(vulnerability.get("scores")))]
        notes = [_text(note.get("text")) for note in map(_mapping, _items(vulnerability.get("notes")))
                 if note.get("category") == "description"]
        record_id = identifier if len(_items(document.get("vulnerabilities"))) == 1 or not cve else f"{identifier}/{cve}"
        yield {
            "id": record_id, "aliases": [cve] if isinstance(cve, str) and cve else [],
            "summary": _text(vulnerability.get("title") or meta.get("title"), 300) or record_id,
            "details": notes[0] if notes else "", "published": tracking.get("initial_release_date"),
            "modified": tracking.get("current_release_date"), "affected": affected,
            "severity": [{"type": "CVSS_V3", "score": vector} for vector in scores[:1] if isinstance(vector, str)],
            "references": [{"type": "WEB", "url": str(ref.get("url"))} for ref in map(_mapping, _items(meta.get("references")))
                           if ref.get("url")][:200],
            "database_specific": {"source": "CSAF", "publisher": _text(_mapping(meta.get("publisher")).get("name"), 200)},
        }


def _cyclonedx(document: dict) -> Iterator[dict]:
    """A CycloneDX BOM's vulnerabilities: the components they affect, by purl and version.
    A VEX analysis of not_affected, false_positive or resolved leaves the component out."""
    purls = {str(_mapping(component).get("bom-ref")): _mapping(component).get("purl")
             for component in _items(document.get("components")) if _mapping(component).get("bom-ref")}
    for vulnerability in map(_mapping, _items(document.get("vulnerabilities"))):
        identifier = vulnerability.get("id")
        if not isinstance(identifier, str) or not _ADVISORY_ID.fullmatch(identifier):
            continue
        if str(_mapping(vulnerability.get("analysis")).get("state", "")) in {"not_affected", "false_positive",
                                                                              "resolved"}:
            continue
        affected = []
        for target in map(_mapping, _items(vulnerability.get("affects"))):
            reference = str(target.get("ref") or "")
            parsed = purl_package(purls.get(reference) or reference)
            if parsed is None:
                continue
            ecosystem, name, version = parsed
            versions = [str(item.get("version")) for item in map(_mapping, _items(target.get("versions")))
                        if item.get("version") and item.get("status", "affected") == "affected"] or (
                [version] if version else [])
            if versions:
                affected.append({"package": {"ecosystem": ecosystem, "name": name}, "versions": versions[:200]})
        if not affected:
            continue
        ratings = [_mapping(item) for item in _items(vulnerability.get("ratings"))]
        severity = []
        for item in ratings:
            kind, prefix = _CYCLONEDX_CVSS.get(str(item.get("method")), (None, ""))
            vector = item.get("vector")
            if kind and isinstance(vector, str) and vector.strip():
                vector = vector.strip()
                # CycloneDX allows a v3 or v4 vector without its "CVSS:3.1/" prefix; scoring needs it.
                severity.append({"type": kind, "score": vector if vector.startswith("CVSS:") or not prefix
                                 else prefix + vector})
        label = next((str(item.get("severity")).upper() for item in ratings if item.get("severity")), "")
        yield {
            "id": identifier, "aliases": [], "summary": _text(vulnerability.get("description"), 300) or identifier,
            "details": _text(vulnerability.get("detail") or vulnerability.get("description")),
            "published": vulnerability.get("published"), "modified": vulnerability.get("updated"),
            "severity": severity[:10], "affected": affected, "references": [],
            "database_specific": {"source": "CycloneDX", "severity": label},
        }


# ---------------------------------------------------------------------------------------------


def detect_format(document: Any) -> str:
    """The advisory format of a parsed JSON document."""
    if isinstance(document, list):
        if document and all(isinstance(item, dict) and "ghsa_id" in item for item in document[:5]):
            return "ghsa"
        if document and all(isinstance(item, dict) and item.get("id") and "affected" in item for item in document[:5]):
            return "osv-list"
        return "unknown"
    if not isinstance(document, dict):
        return "unknown"
    if document.get("id") and isinstance(document.get("affected"), list):
        return "osv"
    if isinstance(document.get("vulnerabilities"), list) and (
            document.get("format") == "NVD_CVE" or any(isinstance(_mapping(item).get("cve"), dict)
                                                       for item in document["vulnerabilities"][:3])):
        return "nvd"
    if isinstance(document.get("CVE_Items"), list):
        return "nvd-1.1"
    if isinstance(document.get("document"), dict) and "csaf_version" in document["document"]:
        return "csaf"
    if document.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if isinstance(document.get("packages"), list) and "distroversion" in document:
        return "alpine"
    sample = next(iter(document.values()), None) if document else None
    if isinstance(sample, dict) and any(isinstance(key, str) and key[:4] in {"CVE-", "TEMP"} for key in list(sample)[:5]):
        return "debian"
    return "unknown"


def convert(document: Any) -> tuple[str, Iterator[dict]]:
    """(format, OSV records) of a parsed advisory document; format "unknown" yields none."""
    kind = detect_format(document)
    if kind == "osv":
        return kind, iter([document])
    if kind == "osv-list":
        return kind, iter(document)
    converters = {"nvd": _nvd_2, "nvd-1.1": _nvd_1, "ghsa": _ghsa, "debian": _debian, "alpine": _alpine,
                  "csaf": _csaf, "cyclonedx": _cyclonedx}
    return kind, (converters[kind](document) if kind in converters else iter(()))
