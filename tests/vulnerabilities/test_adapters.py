"""Advisory adapters (NVD, GitHub exports, Debian, Alpine, CSAF, CycloneDX), the distribution
package inventories they are matched against (dpkg, apk, rpm, SBOMs) and an end-to-end scan."""
from __future__ import annotations

import gzip
import json
import sqlite3
import struct
import zipfile
from pathlib import Path

import pytest

from project_discovery.analyzers.dependencies import os_packages
from project_discovery.analyzers.dependencies.lockfile_parsers import lockfile_key, osv_covers, parse_lockfile
from project_discovery.cli import run_scan
from project_discovery.vulnerabilities.adapters import convert, detect_format, ghsa_ranges, purl_package
from project_discovery.vulnerabilities.database import VulnerabilityDatabase, advisory_severity

NVD_2 = {"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [{"cve": {
    "id": "CVE-2024-1111", "published": "2024-01-01T00:00:00", "lastModified": "2024-02-01T00:00:00",
    "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "A flaw in libdemo. It is bad."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:demo:libdemo:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "1.0", "versionEndExcluding": "1.4.2"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:demo:tool:2.0:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}],
    "references": [{"url": "https://example.com/advisory"}]}}]}
NVD_1 = {"CVE_data_type": "CVE", "CVE_Items": [{
    "cve": {"CVE_data_meta": {"ID": "CVE-2019-2222"}, "description": {"description_data": [
        {"lang": "en", "value": "Old flaw."}]}, "references": {"reference_data": [{"url": "https://example.com/x"}]}},
    "configurations": {"nodes": [{"operator": "OR", "cpe_match": [
        {"vulnerable": True, "cpe23Uri": "cpe:2.3:a:demo:old:*:*:*:*:*:*:*:*", "versionEndIncluding": "3.0"}]}]},
    "impact": {"baseMetricV2": {"cvssV2": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}},
    "publishedDate": "2019-01-01T00:00Z", "lastModifiedDate": "2019-02-01T00:00Z"}]}
GHSA = [{
    "ghsa_id": "GHSA-35jh-r3h4-6jhm", "cve_id": "CVE-2021-23337", "summary": "Command injection in lodash",
    "description": "lodash before 4.17.21", "severity": "high", "published_at": "2021-02-15T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z", "withdrawn_at": None, "references": ["https://github.com/lodash/lodash"],
    "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
    "vulnerabilities": [
        {"package": {"ecosystem": "npm", "name": "lodash"}, "vulnerable_version_range": "< 4.17.21",
         "first_patched_version": "4.17.21"},
        {"package": {"ecosystem": "pip", "name": "demo"}, "vulnerable_version_range": "> 1.0, < 2.0"},
        {"package": {"ecosystem": "rubygems", "name": "exact"}, "vulnerable_version_range": "= 2.0.0"}]}]
DEBIAN = {
    "openssl": {"CVE-2024-0001": {"description": "openssl flaw", "scope": "remote", "releases": {
        "bookworm": {"status": "resolved", "fixed_version": "3.0.13-1~deb12u1", "urgency": "medium"},
        "bullseye": {"status": "resolved", "fixed_version": "0", "urgency": "not yet assigned"},
        "sid": {"status": "resolved", "fixed_version": "3.1.5-1", "urgency": "medium"}}}},
    "zlib": {"CVE-2024-0002": {"description": "zlib flaw", "releases": {
        "bookworm": {"status": "open", "urgency": "low"}}}},
}
ALPINE = {"distroversion": "v3.19", "reponame": "main", "packages": [
    {"pkg": {"name": "openssl", "secfixes": {"3.1.4-r1": ["CVE-2023-5678", "CVE-2023-5363 XSA-1"],
                                             "0": ["CVE-2022-0000"]}}}]}
CSAF = {"document": {"csaf_version": "2.0", "category": "csaf_security_advisory", "title": "openssl update",
                     "publisher": {"name": "Red Hat Product Security"},
                     "tracking": {"id": "RHSA-2024:1234", "initial_release_date": "2024-03-01T00:00:00Z",
                                  "current_release_date": "2024-03-02T00:00:00Z"}},
        "product_tree": {"branches": [{"category": "vendor", "name": "Red Hat", "branches": [
            {"category": "product_version", "name": "openssl-1:3.0.7-27.el9.x86_64", "product": {
                "product_id": "openssl-1:3.0.7-27.el9.x86_64", "name": "openssl",
                "product_identification_helper": {
                    "purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9?arch=x86_64&epoch=1"}}}]}],
            "relationships": [{"category": "default_component_of", "product_reference": "openssl-1:3.0.7-27.el9.x86_64",
                               "relates_to_product_reference": "AppStream-9.3.0.Z",
                               "full_product_name": {"product_id": "AppStream-9.3.0.Z:openssl-1:3.0.7-27.el9.x86_64",
                                                     "name": "openssl on RHEL 9"}}]},
        "vulnerabilities": [{"cve": "CVE-2023-5678", "title": "openssl: DH check",
                             "product_status": {"fixed": ["AppStream-9.3.0.Z:openssl-1:3.0.7-27.el9.x86_64"]},
                             "notes": [{"category": "description", "text": "Generating excessively long X9.42 keys."}],
                             "scores": [{"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}}]}]}
CYCLONEDX = {"bomFormat": "CycloneDX", "specVersion": "1.5",
             "components": [{"bom-ref": "pkg:npm/minimist@1.2.5", "purl": "pkg:npm/minimist@1.2.5"},
                            {"bom-ref": "c2", "purl": "pkg:pypi/requests@2.0.0"}],
             "vulnerabilities": [{"id": "CVE-2021-44906", "description": "minimist prototype pollution",
                                  "ratings": [{"severity": "critical", "method": "CVSSv31",
                                               "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                                  "affects": [{"ref": "pkg:npm/minimist@1.2.5"}]},
                                 {"id": "CVE-2000-0001", "analysis": {"state": "not_affected"},
                                  "affects": [{"ref": "c2"}]}]}


def _records(document) -> list[dict]:
    return list(convert(document)[1])


def test_formats_are_detected():
    assert [detect_format(item) for item in (NVD_2, NVD_1, GHSA, DEBIAN, ALPINE, CSAF, CYCLONEDX,
                                             {"id": "X", "affected": []}, {"hello": 1}, [1, 2])] == [
        "nvd", "nvd-1.1", "ghsa", "debian", "alpine", "csaf", "cyclonedx", "osv", "unknown", "unknown"]


def test_nvd_records_name_products_by_cpe():
    record, = _records(NVD_2)
    assert (record["id"], record["summary"], record["severity"][0]["type"]) == (
        "CVE-2024-1111", "A flaw in libdemo", "CVSS_V3")
    ranged, exact = record["affected"]  # the not-vulnerable platform is left out
    assert ranged["package"] == {"ecosystem": "CPE", "name": "demo:libdemo"}
    assert ranged["ranges"][0]["events"] == [{"introduced": "1.0"}, {"fixed": "1.4.2"}]
    assert ranged["database_specific"]["versionEndExcluding"] == "1.4.2"
    assert exact["versions"] == ["2.0"] and record["database_specific"]["cwe"] == ["CWE-787"]
    old, = _records(NVD_1)
    assert old["affected"][0]["ranges"][0]["events"] == [{"introduced": "0"}, {"last_affected": "3.0"}]
    assert old["severity"] == [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}]


def test_github_exports_become_osv_ranges():
    record, = _records(GHSA)
    assert record["aliases"] == ["CVE-2021-23337"]
    npm, pip, gem = record["affected"]
    assert npm["ranges"] == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
    assert pip["package"]["ecosystem"] == "PyPI" and pip["ranges"][0]["type"] == "GHSA_RANGE"  # "> 1.0": unsupported
    assert gem["versions"] == ["2.0.0"]
    assert ghsa_ranges(">= 1.0, <= 2.0") == [{"introduced": "1.0"}, {"last_affected": "2.0"}]
    assert ghsa_ranges("~> 1.0") is None


def test_distribution_trackers_and_bulletins():
    debian = {item["id"]: item for item in _records(DEBIAN)}
    openssl = debian["DEBIAN-CVE-2024-0001"]
    assert openssl["affected"] == [{"package": {"ecosystem": "Debian:12", "name": "openssl"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.13-1~deb12u1"}]}]}]
    assert debian["DEBIAN-CVE-2024-0002"]["affected"][0]["ranges"][0]["events"] == [{"introduced": "0"}]
    alpine = {item["id"]: item for item in _records(ALPINE)}
    assert set(alpine) == {"ALPINE-CVE-2023-5678", "ALPINE-CVE-2023-5363", "ALPINE-XSA-1"}
    assert alpine["ALPINE-CVE-2023-5678"]["affected"][0]["package"] == {"ecosystem": "Alpine:v3.19", "name": "openssl"}
    csaf, = _records(CSAF)
    assert (csaf["id"], csaf["aliases"]) == ("RHSA-2024:1234", ["CVE-2023-5678"])
    assert csaf["affected"] == [{"package": {"ecosystem": "Red Hat", "name": "openssl"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.7-27.el9"}]}]}]
    sbom, = _records(CYCLONEDX)  # the not_affected one is left out
    assert sbom["affected"] == [{"package": {"ecosystem": "npm", "name": "minimist"}, "versions": ["1.2.5"]}]


def test_package_urls():
    assert purl_package("pkg:npm/%40scope/name@1.0.0") == ("npm", "@scope/name", "1.0.0")
    assert purl_package("pkg:maven/org.apache.commons/commons-text@1.9") == ("Maven", "org.apache.commons:commons-text", "1.9")
    assert purl_package("pkg:golang/github.com/gin-gonic/gin@v1.9.0") == ("Go", "github.com/gin-gonic/gin", "v1.9.0")
    assert purl_package("pkg:deb/debian/openssl@3.0.11-1?distro=debian-12") == ("Debian:12", "openssl", "3.0.11-1")
    assert purl_package("pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=bookworm") == ("Debian:12", "curl", "7.88.1-10")
    assert purl_package("pkg:deb/debian/curl@7.88.1-10")[0] == "Debian"  # no release: matches nothing
    # A binary package names its source package (and the source's version) as Syft writes it.
    assert purl_package("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?upstream=openssl&distro=debian-12") == (
        "Debian:12", "openssl", "3.0.11-1~deb12u2")
    assert purl_package("pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?upstream=zlib%401%3A1.2.13.dfsg-1&distro=debian-12.5") == (
        "Debian:12", "zlib", "1:1.2.13.dfsg-1")
    assert [purl_package(f"pkg:deb/ubuntu/x@1?distro={distro}")[0] for distro in (
        "ubuntu-22.04", "jammy", "ubuntu-23.10", "ubuntu")] == ["Ubuntu:22.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:23.10", "Ubuntu"]
    assert purl_package("pkg:apk/alpine/libcrypto3@3.1.4-r0?upstream=openssl&distro=alpine-3.19.1") == (
        "Alpine:v3.19", "openssl", "3.1.4-r0")
    assert purl_package("pkg:apk/alpine/musl@1.2.4-r2?distro=alpine")[0] == "Alpine"
    assert purl_package("pkg:rpm/redhat/bash@5.1.8-6.el9?epoch=0") == ("Red Hat", "bash", "5.1.8-6.el9")
    assert purl_package("pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?epoch=1&upstream=openssl-3.0.7-24.el9.src.rpm") == (
        "Red Hat", "openssl-libs", "1:3.0.7-24.el9")  # Red Hat names binary packages
    assert purl_package("pkg:rpm/almalinux/bash@5.1.8-6.el9?distro=almalinux-9.3")[0] == "AlmaLinux:9"
    assert purl_package("pkg:rpm/unknown/bash@1") is None
    assert purl_package("pkg:generic/thing@1") is None and purl_package("not a purl") is None


def test_import_reads_every_format_and_gzip_and_aliases_give_severities(tmp_path: Path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "nvdcve-2.0-2024.json.gz").write_bytes(gzip.compress(json.dumps(NVD_2).encode()))
    for name, document in (("ghsa.json", GHSA), ("debian.json", DEBIAN), ("alpine.json", ALPINE),
                           ("rhsa.json", CSAF), ("bom.json", CYCLONEDX), ("noise.json", {"hello": "world"})):
        (feeds / name).write_text(json.dumps(document), encoding="utf-8")
    # An OSV record without CVSS that aliases the NVD record takes its severity.
    (feeds / "osv.json").write_text(json.dumps({"id": "OSV-1", "aliases": ["CVE-2024-1111"], "affected": [
        {"package": {"ecosystem": "npm", "name": "libdemo"}, "versions": ["1.0.0"]}]}), encoding="utf-8")
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as database:
        result = database.import_osv(feeds)
        assert result["formats"] == {"alpine": 3, "csaf": 1, "cyclonedx": 1, "debian": 2, "ghsa": 1, "nvd": 1, "osv": 1}
        assert result["skipped_records"] == 1 and "noise.json: not a supported advisory record" in result["errors"][0]
        status = database.status()
        assert {"CPE", "Debian:12", "Alpine:v3.19", "Red Hat", "npm", "PyPI", "RubyGems"} <= set(status["ecosystems"])
        osv, = database.query("npm", "libdemo")
        assert (osv["severity"], osv["severity_source"]) == ("CRITICAL", "CVE-2024-1111")


def _rpm_blob(name: str, version: str, release: str, epoch: int | None = None) -> bytes:
    tags = {1000: (6, name.encode() + b"\0"), 1001: (6, version.encode() + b"\0"), 1002: (6, release.encode() + b"\0")}
    if epoch is not None:
        tags[1003] = (4, struct.pack(">L", epoch))
    entries, data = b"", b""
    for tag, (kind, payload) in sorted(tags.items()):
        if kind == 4:
            data += b"\0" * (-len(data) % 4)
        entries += struct.pack(">4L", tag, kind, len(data), 1)
        data += payload
    return struct.pack(">LL", len(tags), len(data)) + entries + data


def _rpmdb(path: Path, packages: list[tuple], *, schema: str = "CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY "
           "AUTOINCREMENT, blob BLOB NOT NULL)") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute(schema)
    for package in packages:
        db.execute("INSERT INTO Packages (blob) VALUES (?)", (_rpm_blob(*package),))
    db.execute("CREATE TABLE padding (x TEXT)")
    db.execute("INSERT INTO padding VALUES (?)", ("x" * 600,))
    db.commit()
    db.close()
    return path


def test_os_package_databases(tmp_path: Path):
    status = ("Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n"
              "Description: SSL\n continued\n\nPackage: zlib1g\nStatus: install ok installed\n"
              "Source: zlib (1:1.2.13.dfsg-1)\nVersion: 1:1.2.13.dfsg-1\n\n"
              "Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n")
    debian = parse_lockfile("var/lib/dpkg/status", status, context={"os_release": 'ID=debian\nVERSION_ID="12"\n'})
    assert {(item.ecosystem, item.name, item.version) for item in debian} == {
        ("Debian:12", "openssl", "3.0.11-1~deb12u2"), ("Debian:12", "zlib", "1:1.2.13.dfsg-1")}
    installed = "P:libcrypto3\nV:3.1.4-r0\no:openssl\n\nP:musl\nV:1.2.4-r2\n"
    alpine = parse_lockfile("lib/apk/db/installed", installed, context={"os_release": "ID=alpine\nVERSION_ID=3.19.1\n"})
    assert {(item.ecosystem, item.name, item.version) for item in alpine} == {
        ("Alpine:v3.19", "openssl", "3.1.4-r0"), ("Alpine:v3.19", "musl", "1.2.4-r2")}
    database = _rpmdb(tmp_path / "var/lib/rpm/rpmdb.sqlite", [("openssl", "3.0.7", "24.el9", 1),
                                                               ("bash", "5.1.8", "6.el9", None),
                                                               ("gpg-pubkey", "fd431d51", "4ae0493b", None)])
    rpm = parse_lockfile("var/lib/rpm/rpmdb.sqlite", database.read_bytes(), context={"os_release": "ID=rhel\n"})
    assert {(item.ecosystem, item.name, item.version) for item in rpm} == {
        ("Red Hat", "openssl", "1:3.0.7-24.el9"), ("Red Hat", "bash", "5.1.8-6.el9")}
    # A release-less distribution matches nothing: OSV is not asked.
    assert not osv_covers("Debian") and osv_covers("Debian:12") and osv_covers("npm") and not osv_covers("Red Hat")
    hostile = _rpmdb(tmp_path / "x/var/lib/rpm/rpmdb.sqlite", [],
                     schema="CREATE VIRTUAL TABLE Packages USING rtree(hnum, a, b)") if _has_rtree() else None
    if hostile is not None:
        with pytest.raises(ValueError, match="computes its values"):
            parse_lockfile("var/lib/rpm/rpmdb.sqlite", hostile.read_bytes())
    assert lockfile_key("rootfs/usr/lib/sysimage/rpm/rpmdb.sqlite") == "rpmdb-sqlite"
    assert os_packages.os_ecosystem('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n',
                                    "Debian") == "Ubuntu:22.04:LTS"


def _has_rtree() -> bool:
    try:
        sqlite3.connect(":memory:").execute("CREATE VIRTUAL TABLE t USING rtree(i, a, b)")
        return True
    except sqlite3.OperationalError:
        return False


def test_sboms_name_their_components_by_purl():
    spdx = json.dumps({"spdxVersion": "SPDX-2.3", "packages": [
        {"name": "lodash", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
        {"name": "internal", "externalRefs": []}]})
    assert {(item.ecosystem, item.name, item.version) for item in parse_lockfile("app.spdx.json", spdx)} == {
        ("npm", "lodash", "4.17.20")}
    cyclonedx = json.dumps({"bomFormat": "CycloneDX", "components": [
        {"purl": "pkg:pypi/requests@2.31.0", "components": [{"purl": "pkg:cargo/serde@1.0.0"}]}]})
    assert {(item.ecosystem, item.name) for item in parse_lockfile("bom.json", cyclonedx)} == {
        ("PyPI", "requests"), ("crates.io", "serde")}


def test_a_scan_matches_installed_packages_and_sboms_against_imported_advisories(tmp_path: Path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    # Ubuntu publishes OSV records; they import as they are.
    ubuntu = {"id": "UBUNTU-CVE-2024-0003", "modified": "2024-05-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.15"}]}]}]}
    for name, document in (("debian.json", DEBIAN), ("alpine.json", ALPINE), ("ghsa.json", GHSA), ("rhsa.json", CSAF),
                           ("ubuntu.json", ubuntu)):
        (feeds / name).write_text(json.dumps(document), encoding="utf-8")
    database = tmp_path / "db.sqlite3"
    with VulnerabilityDatabase(database) as store:
        store.import_osv(feeds)
    project = tmp_path / "images"
    _rpmdb(project / "rhel-root/usr/lib/sysimage/rpm/rpmdb.sqlite", [("openssl", "3.0.7", "24.el9", 1)])
    files = {
        "debian-root/var/lib/dpkg/status": ("Package: libssl3\nStatus: install ok installed\nSource: openssl\n"
                                            "Version: 3.0.11-1~deb12u2\n\nPackage: zlib1g\nStatus: install ok installed\n"
                                            "Source: zlib (1:1.2.13.dfsg-1)\nVersion: 1:1.2.13.dfsg-1\n"),
        "debian-root/usr/lib/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
        "alpine-root/lib/apk/db/installed": "P:libcrypto3\nV:3.1.4-r0\no:openssl\n\nP:musl\nV:1.2.4-r2\no:musl\n",
        "alpine-root/etc/os-release": "ID=alpine\nVERSION_ID=3.19.1\n",
        "rhel-root/etc/os-release": 'ID="rhel"\nVERSION_ID="9.3"\n',
        "ubuntu-root/var/lib/dpkg/status": ("Package: libssl3\nStatus: install ok installed\nSource: openssl\n"
                                            "Version: 3.0.2-0ubuntu1.10\n"),
        "ubuntu-root/etc/os-release": 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n',
        "app/bom.cdx.json": json.dumps({"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/lodash@4.17.20"}]}),
    }
    for name, content in files.items():
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 1, quiet=True, vulnerability_db=database) in {0, 1}
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    titles = [item["title"] for item in report["findings"]
              if item["category"] == "vulnerabilities" and item["confidence"] == "CONFIRMED"]
    for advisory in ("DEBIAN-CVE-2024-0001", "DEBIAN-CVE-2024-0002", "ALPINE-CVE-2023-5678", "GHSA-35jh-r3h4-6jhm",
                     "RHSA-2024:1234", "UBUNTU-CVE-2024-0003"):
        assert any(title.startswith(advisory) for title in titles), (advisory, titles)
    # secdb lists under "0" the issues a package never had: they match nothing.
    assert not any(title.startswith("ALPINE-CVE-2022-0000") for title in titles)


def test_corrupt_compressed_files_fail_alone(tmp_path: Path):
    good = gzip.compress(json.dumps(ALPINE).encode())
    broken = bytearray(good)
    broken[len(broken) // 2] ^= 0xFF  # a broken deflate stream or a failed CRC
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "good.json.gz").write_bytes(good)
    (feeds / "broken.json.gz").write_bytes(bytes(broken))
    (feeds / "truncated.json.gz").write_bytes(good[: len(good) // 2])
    plain = json.dumps(ALPINE).encode()
    bundle = tmp_path / "all.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("good.json.gz", good)
        archive.writestr("broken.json.gz", bytes(broken))
        archive.writestr("crc.json", plain)
    data = bytearray(bundle.read_bytes())
    data[data.index(plain) + 10] ^= 0x01  # the stored member no longer matches its CRC-32
    bundle.write_bytes(bytes(data))
    with VulnerabilityDatabase(tmp_path / "db.sqlite3") as database:
        result = database.import_osv(feeds)
        assert result["formats"] == {"alpine": 3}
        assert result["skipped_records"] == 2
        assert sorted(error.split(":", 1)[0] for error in result["errors"]) == ["broken.json.gz", "truncated.json.gz"]
        result = database.import_osv(bundle)
        assert result["formats"] == {"alpine": 3}
        assert sorted(error.split(":", 1)[0] for error in result["errors"]) == ["broken.json.gz", "crc.json"]


def test_unusable_tracker_entries_and_cyclonedx_ratings():
    # A resolved issue without a fixed version gives a match nothing to compare.
    assert _records({"curl": {"CVE-2024-0009": {"releases": {"bookworm": {"status": "resolved", "urgency": "low"}}}}}) == []
    bom = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "a", "purl": "pkg:npm/a@1.0.0"}],
           "vulnerabilities": [{"id": "CVE-2020-0001", "affects": [{"ref": "a"}], "ratings": [
               {"method": "CVSSv2", "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
               {"method": "CVSSv31", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
               {"method": "OWASP", "vector": "SL:1/M:1"}, {"severity": "medium"}]}]}
    record, = _records(bom)
    assert record["severity"] == [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                                  {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert advisory_severity(record) == "CRITICAL"  # the highest score, not the first rating's
