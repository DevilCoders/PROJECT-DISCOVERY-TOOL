"""Installed operating-system packages and SBOM components, as resolved packages.

A scanned tree that holds a root file system (a container image's, an appliance's) names its
installed packages in the package manager's database: dpkg's ``var/lib/dpkg/status``,
apk's ``lib/apk/db/installed`` and rpm's ``rpmdb.sqlite``. Their packages are matched against
distribution advisories like lockfile packages are matched against registry advisories, in
the ecosystem of the distribution release the root's ``os-release`` names (``Debian:12``,
``Ubuntu:22.04:LTS``, ``Alpine:v3.19``, ``Red Hat``). Debian and Ubuntu advisories name source
packages, so a dpkg package is recorded by its source package and version; an apk package by
its origin. CycloneDX and SPDX SBOMs name their components by package URL.
"""
from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import Any

from ...core.safe_sqlite import plain_tables, untrusted_database
from ...core.source_utils import read_bytes_bounded, read_text_bounded
from ...vulnerabilities.adapters import purl_package, ubuntu_ecosystem

# The databases' paths below a root file system, by lockfile key.
OS_DATABASES = {
    "dpkg-status": ("var/lib/dpkg/status",),
    "apk-installed": ("lib/apk/db/installed",),
    "rpmdb-sqlite": ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
}
_MAX_OS_RELEASE_BYTES = 64 * 1024
_MAX_RPM_HEADER_BYTES = 64 * 1024 * 1024
# NAME, VERSION, RELEASE, EPOCH, ARCH
_RPM_TAGS = frozenset({1000, 1001, 1002, 1003, 1022})


def database_root(path: Path, key: str) -> Path | None:
    """The root file system an OS package database belongs to."""
    normalized = str(path).replace("\\", "/").casefold()
    parts = Path(path).parts
    for suffix in OS_DATABASES.get(key, ()):
        depth = len(suffix.split("/"))
        if normalized.endswith(suffix):
            return Path(*parts[:-depth]) if len(parts) > depth else Path(".")
    return None


def os_release_text(path: Path, key: str) -> str:
    """The os-release of the root file system an OS package database belongs to, or "".
    /etc/os-release is usually a link to /usr/lib/os-release; links are not followed, so
    the link's target is read from its own path."""
    root = database_root(path, key)
    if root is None:
        return ""
    for candidate in ("etc/os-release", "usr/lib/os-release"):
        try:
            return read_text_bounded(root / candidate, _MAX_OS_RELEASE_BYTES, errors="replace")
        except (OSError, ValueError):
            continue
    return ""


def os_ecosystem(os_release: str, default: str) -> str:
    """The OSV ecosystem of a distribution release, from its os-release; ``default`` (the
    distribution alone, which no advisory names) when the release is unknown."""
    fields: dict[str, str] = {}
    for line in os_release.splitlines()[:500]:
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip().strip("\"'")
    distro, version = fields.get("ID", "").lower(), fields.get("VERSION_ID", "")
    major = version.split(".")[0]
    if distro == "debian":
        return f"Debian:{major}" if major.isdigit() else "Debian"
    if distro == "ubuntu":
        return ubuntu_ecosystem(version)
    if distro == "alpine":
        parts = version.split(".")
        return f"Alpine:v{parts[0]}.{parts[1]}" if len(parts) >= 2 else "Alpine"
    if distro == "rhel":
        return "Red Hat"
    if distro in {"almalinux", "rocky"}:
        label = "AlmaLinux" if distro == "almalinux" else "Rocky Linux"
        return f"{label}:{major}" if major.isdigit() else label
    if distro in {"opensuse-leap", "opensuse-tumbleweed", "opensuse"}:
        return "openSUSE"
    if distro in {"sles", "sled", "sles_sap"}:
        return "SUSE"
    if distro in {"wolfi", "fedora", "mageia", "openeuler"}:
        return {"wolfi": "Wolfi", "fedora": "Fedora", "mageia": "Mageia", "openeuler": "openEuler"}[distro]
    return default


def read_lockfile(path: Path, key: str, max_bytes: int, expected_identity=None) -> tuple[str | bytes, dict | None]:
    """A lockfile's content (bytes for the RPM database) and the context its parser needs
    (the root's os-release for an OS package database)."""
    if key == "rpmdb-sqlite":
        content: str | bytes = read_bytes_bounded(path, max_bytes, expected_identity=expected_identity)
    else:
        content = read_text_bounded(path, max_bytes, expected_identity=expected_identity)
    context = {"os_release": os_release_text(path, key)} if key in OS_DATABASES else None
    return content, context


def _paragraphs(source: str):
    """Key: value paragraphs separated by blank lines (dpkg status, apk installed)."""
    fields: dict[str, str] = {}
    for raw_line in io.StringIO(source, newline=None):
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            if fields:
                yield fields
            fields = {}
        elif not line[0].isspace():
            key, separator, value = line.partition(":")
            if separator and key not in fields:
                fields[key] = value.strip()
    if fields:
        yield fields


def dpkg_status(source: str, out, ecosystem: str) -> None:
    """dpkg's installed packages, by source package and source version."""
    for fields in _paragraphs(source):
        status = fields.get("Status", "").split()
        if not fields.get("Package") or not fields.get("Version") or not status or status[-1] != "installed":
            continue
        name, version = fields["Package"], fields["Version"]
        origin = fields.get("Source", "")
        if origin:
            origin_name, _, rest = origin.partition(" ")
            name = origin_name or name
            if rest.startswith("(") and rest.endswith(")"):
                version = rest[1:-1]
        out.add(name, version, None, ecosystem)


def apk_installed(source: str, out, ecosystem: str) -> None:
    """apk's installed packages (P:, V:, o: lines), by origin package."""
    for fields in _paragraphs(source):
        if fields.get("P") and fields.get("V"):
            out.add(fields.get("o") or fields["P"], fields["V"], None, ecosystem)


def read_rpmdb(data: bytes, max_packages: int = 100_000) -> list[tuple[str, str, str, str]]:
    """(name, epoch, version, release) of each package in an rpm SQLite database (its headers,
    read from memory through core.safe_sqlite); GPG public keys rpm stores as packages are left out."""
    from ..content.archive_formats import ArchiveFormatError, ArchiveLimitError, _rpm_header

    packages = []
    with untrusted_database(data, label="RPM database") as db:
        plain_tables(db, ("PACKAGES",), label="RPM database")
        for (blob,) in db.execute("SELECT blob FROM Packages LIMIT ?", (max_packages,)):
            if not isinstance(blob, bytes) or len(blob) < 8:
                continue
            # The database keeps headers without their 8-byte magic: the parser expects it.
            header = b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + blob
            try:
                values, _, _ = _rpm_header(io.BytesIO(header), 0, len(header), _MAX_RPM_HEADER_BYTES, _RPM_TAGS, 1)
            except (ArchiveFormatError, ArchiveLimitError, struct.error):
                continue
            name = values.get(1000)
            if not isinstance(name, str) or not name or name == "gpg-pubkey":
                continue
            epoch = values.get(1003)
            packages.append((name, str(epoch[0]) if isinstance(epoch, list) and epoch else "",
                             str(values.get(1001) or ""), str(values.get(1002) or "")))
    return packages


def rpmdb(data: bytes, out, ecosystem: str) -> None:
    """rpm's installed packages, by name and epoch:version-release."""
    for name, epoch, version, release in read_rpmdb(data, out.max_entries):
        if version:
            full = f"{version}-{release}" if release else version
            out.add(name, f"{epoch}:{full}" if epoch and epoch != "0" else full, None, ecosystem)


def sbom(document: Any, out) -> None:
    """A CycloneDX or SPDX JSON SBOM's components, by their package URLs (each in its own
    ecosystem); components without one are not packages PDT can match."""
    if not isinstance(document, dict):
        return
    purls: list[str] = []
    if document.get("bomFormat") == "CycloneDX":
        stack = [item for item in document.get("components") or [] if isinstance(item, dict)]
        while stack and len(purls) < out.max_entries:
            component = stack.pop()
            stack.extend(item for item in component.get("components") or [] if isinstance(item, dict))
            if isinstance(component.get("purl"), str):
                purls.append(component["purl"])
    elif document.get("spdxVersion"):
        for package in document.get("packages") or []:
            for reference in package.get("externalRefs") or [] if isinstance(package, dict) else ():
                if isinstance(reference, dict) and str(reference.get("referenceType", "")).lower() == "purl":
                    purls.append(str(reference.get("referenceLocator", "")))
    for purl in purls:
        parsed = purl_package(purl)
        if parsed is not None and parsed[2]:
            out.add(parsed[1], parsed[2], None, parsed[0])
