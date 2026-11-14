"""Ecosystem-aware version ordering for offline advisory matching.

OSV ``SEMVER`` ranges use SemVer 2.0 precedence; ``ECOSYSTEM`` ranges use the ordering of
the package ecosystem itself. Comparators return ``None`` when a version cannot be ordered
reliably, so callers can report UNKNOWN instead of guessing.
"""
from __future__ import annotations

import re
from collections.abc import Callable

Comparator = Callable[[str, str], "int | None"]

_SEMVER = re.compile(
    r"^[vV=]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:-?([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]*)?$"
)
_NATURAL_PART = re.compile(r"\d+|[A-Za-z]+")


def _cmp(left, right) -> int:
    return (left > right) - (left < right)


def _natural_parts(identifier: str) -> list[int | str]:
    return [int(part) if part.isdigit() else part for part in _NATURAL_PART.findall(identifier)]


def _compare_identifiers(left: str, right: str, *, natural: bool, casefold: bool) -> int:
    if casefold:
        left, right = left.casefold(), right.casefold()
    if left.isdigit() and right.isdigit():
        return _cmp(int(left), int(right))
    if left.isdigit():
        return -1  # numeric identifiers have lower precedence than alphanumeric ones
    if right.isdigit():
        return 1
    if natural:
        for a, b in zip(_natural_parts(left), _natural_parts(right), strict=False):
            if a == b:
                continue
            if isinstance(a, int) and isinstance(b, int):
                return _cmp(a, b)
            if isinstance(a, int):
                return 1
            if isinstance(b, int):
                return -1
            return _cmp(a, b)
        return _cmp(len(_natural_parts(left)), len(_natural_parts(right)))
    return _cmp(left, right)


def _parse_semver(value: str):
    match = _SEMVER.match(value.strip())
    if not match:
        return None
    release = tuple(int(part) if part else 0 for part in match.group(1, 2, 3, 4))
    prerelease = match.group(5)
    return release, prerelease.split(".") if prerelease else []


def _semver_comparator(*, natural: bool = False, casefold: bool = False) -> Comparator:
    def compare(left: str, right: str) -> int | None:
        a, b = _parse_semver(left), _parse_semver(right)
        if a is None or b is None:
            return None
        if a[0] != b[0]:
            return _cmp(a[0], b[0])
        left_pre, right_pre = a[1], b[1]
        if not left_pre or not right_pre:
            # A release without a prerelease has higher precedence.
            return _cmp(not left_pre, not right_pre)
        for x, y in zip(left_pre, right_pre, strict=False):
            result = _compare_identifiers(x, y, natural=natural, casefold=casefold)
            if result:
                return result
        return _cmp(len(left_pre), len(right_pre))
    return compare


compare_semver = _semver_comparator()
# NuGet compares numeric labels numerically and the others ordinally, ignoring case
# (beta10 < beta9), as SemVer 2.0 does.
_compare_nuget = _semver_comparator(natural=False, casefold=True)

# Composer's VersionParser: up to four numeric parts, then one stability suffix with an
# optional number. Stabilities order dev < alpha < beta < RC < stable < patch, so the
# Magento patch release 2.4.6-p3 sorts after 2.4.6.
_COMPOSER = re.compile(
    r"^[vV]?(\d{1,18})(?:\.(\d{1,18}))?(?:\.(\d{1,18}))?(?:\.(\d{1,18}))?"
    r"(?:[-_.]?(stable|beta|b|rc|alpha|a|patch|pl|p|dev)[-_.]?(\d{0,18}))?$",
    re.IGNORECASE,
)
_COMPOSER_RANK = {
    "dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "stable": 4, "patch": 5, "pl": 5, "p": 5,
}


def _strip_composer(value: str) -> str:
    value = value.strip()
    # Composer stability flags (1.2.3@dev) and inline aliases (1.x-dev as 1.2.3) are not ordered.
    return value.split("@", 1)[0].split(" as ", 1)[-1]


def _parse_composer(value: str):
    match = _COMPOSER.match(value.strip())
    if not match:
        return None  # branch versions (dev-main) and other forms are not ordered
    release = tuple(int(part) if part else 0 for part in match.group(1, 2, 3, 4))
    stability = (match.group(5) or "stable").lower()
    return release, _COMPOSER_RANK[stability], int(match.group(6)) if match.group(6) else 0


def compare_composer(left: str, right: str) -> int | None:
    a, b = _parse_composer(_strip_composer(left)), _parse_composer(_strip_composer(right))
    if a is None or b is None:
        return None
    return _cmp(a, b)


def _gem_segments(value: str) -> list[int | str] | None:
    value = value.strip()
    if not value or not re.fullmatch(r"[0-9]+(?:[.\-]?[0-9A-Za-z]+)*", value):
        return None
    segments: list[int | str] = []
    for part in re.split(r"[.\-]", value):
        segments.extend(_natural_parts(part))
    # Gem::Version canonicalizes trailing zero segments of the release part.
    first_string = next((i for i, s in enumerate(segments) if isinstance(s, str)), len(segments))
    release, suffix = segments[:first_string], segments[first_string:]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    return release + suffix


def compare_rubygems(left: str, right: str) -> int | None:
    """Gem::Version ordering: string segments mark prereleases and sort below numbers."""
    a, b = _gem_segments(left), _gem_segments(right)
    if a is None or b is None:
        return None
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else 0
        y = b[index] if index < len(b) else 0
        if x == y:
            continue
        if isinstance(x, str) and isinstance(y, int):
            return -1
        if isinstance(x, int) and isinstance(y, str):
            return 1
        return _cmp(x, y)
    return 0


_PEP440_FALLBACK = re.compile(
    r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
    r"(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9.]+)?$",
    re.I,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def _pep440_key(value: str):
    match = _PEP440_FALLBACK.match(value.strip())
    if not match:
        return None
    epoch, release, pre_label, pre_number, post_label, post_number, dev_label, dev_number = (
        match.groups()
    )
    numbers = [int(part) for part in release.split(".")]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    # Ordering: dev < pre < release < post, mirroring PEP 440 for common versions.
    if pre_label:
        pre = (0, _PRE_RANK[pre_label.lower()], int(pre_number or 0))
    elif dev_label and not post_label:
        pre = (-1, 0, 0)
    else:
        pre = (1, 0, 0)
    post = (1, int(post_number or 0)) if post_label else (0, 0)
    dev = (0, int(dev_number or 0)) if dev_label else (1, 0)
    return int(epoch or 0), tuple(numbers), pre, post, dev


def compare_pep440(left: str, right: str) -> int | None:
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:  # pragma: no cover - packaging is a declared dependency
        a, b = _pep440_key(left), _pep440_key(right)
        return None if a is None or b is None else _cmp(a, b)
    try:
        return _cmp(Version(left.strip()), Version(right.strip()))
    except InvalidVersion:
        return None


# ---------------------------------------------------------------------------------------------
# Distribution package versions


def _dpkg_order(char: str) -> int:
    """dpkg's character order: "~" before the end of a part, the end before letters, letters
    before other characters (digits are compared as numbers elsewhere)."""
    if not char:
        return 0
    if char == "~":
        return -1
    if char.isascii() and char.isalpha():
        return ord(char)
    return ord(char) + 256


def _dpkg_part(left: str, right: str) -> int:
    """dpkg's verrevcmp: alternate non-digit runs (by _dpkg_order) and digit runs (as numbers)."""
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            a = _dpkg_order(left[i] if i < len(left) else "")
            b = _dpkg_order(right[j] if j < len(right) else "")
            if a != b:
                return _cmp(a, b)
            i, j = i + 1, j + 1
        start_i, start_j = i, j
        while i < len(left) and left[i].isdigit():
            i += 1
        while j < len(right) and right[j].isdigit():
            j += 1
        a, b = int(left[start_i:i] or 0), int(right[start_j:j] or 0)
        if a != b:
            return _cmp(a, b)
    return 0


def _dpkg_split(value: str) -> tuple[int, str, str] | None:
    epoch, colon, rest = value.strip().partition(":")
    if not colon:
        epoch, rest = "0", value.strip()
    if not epoch.isdigit() or not rest:
        return None
    upstream, dash, revision = rest.rpartition("-")
    if not dash:
        upstream, revision = rest, ""
    if not upstream or not upstream[0].isdigit():
        return None
    return int(epoch), upstream, revision


def compare_dpkg(left: str, right: str) -> int | None:
    """Debian (and Ubuntu) package versions: [epoch:]upstream[-revision], as dpkg orders them."""
    a, b = _dpkg_split(left), _dpkg_split(right)
    if a is None or b is None:
        return None
    return _cmp(a[0], b[0]) or _dpkg_part(a[1], b[1]) or _dpkg_part(a[2], b[2])


_APK_SUFFIXES = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_APK_VERSION = re.compile(r"(\d{1,30}(?:\.\d{1,30}){0,30})([a-z]?)((?:_[a-z]{1,8}\d{0,30}){0,20})(?:-r(\d{1,30}))?")


def _apk_key(value: str):
    match = _APK_VERSION.fullmatch(value.strip())
    if not match:
        return None
    numbers, letter, suffixes, revision = match.groups()
    parsed = []
    for suffix in suffixes.split("_")[1:]:
        name = suffix.rstrip("0123456789")
        if name not in _APK_SUFFIXES:
            return None
        parsed.append((_APK_SUFFIXES[name], int(suffix[len(name):] or 0)))
    # No suffix ranks between the pre-release and the post-release suffixes.
    return (tuple(int(part) for part in numbers.split(".")), letter, tuple(parsed) + ((0, 0),), int(revision or 0))


def compare_apk(left: str, right: str) -> int | None:
    """Alpine package versions: numbers, a letter, _alpha/_beta/_pre/_rc (before the release) and
    _cvs/_svn/_git/_hg/_p (after it) suffixes, and the -rN package revision."""
    a, b = _apk_key(left), _apk_key(right)
    if a is None or b is None:
        return None
    return _cmp(a, b)


def _rpm_segments(left: str, right: str) -> int:
    """rpmvercmp: alphanumeric segments, numbers above letters, "~" below everything and "^"
    below everything but the end."""
    i = j = 0
    while i < len(left) or j < len(right):
        while i < len(left) and not left[i].isalnum() and left[i] not in "~^":
            i += 1
        while j < len(right) and not right[j].isalnum() and right[j] not in "~^":
            j += 1
        a = left[i] if i < len(left) else ""
        b = right[j] if j < len(right) else ""
        if a == "~" or b == "~":
            if a != "~":
                return 1
            if b != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if a == "^" or b == "^":
            if not a:
                return -1
            if not b:
                return 1
            if a != "^":
                return 1
            if b != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not a or not b:
            break
        numeric = a.isdigit()
        start_i, start_j = i, j
        test = str.isdigit if numeric else (lambda char: char.isascii() and char.isalpha())
        while i < len(left) and test(left[i]):
            i += 1
        while j < len(right) and test(right[j]):
            j += 1
        first, second = left[start_i:i], right[start_j:j]
        if not second:  # a number against letters: the number is newer
            return 1 if numeric else -1
        if numeric:
            first, second = first.lstrip("0"), second.lstrip("0")
            if len(first) != len(second):
                return _cmp(len(first), len(second))
        if first != second:
            return _cmp(first, second)
    a = i < len(left)
    b = j < len(right)
    return 0 if a == b else (1 if a else -1)


def _rpm_split(value: str) -> tuple[int, str, str] | None:
    epoch, colon, rest = value.strip().partition(":")
    if not colon:
        epoch, rest = "0", value.strip()
    if not epoch.isdigit() or not rest:
        return None
    version, _, release = rest.partition("-")
    return int(epoch), version, release


def compare_rpm(left: str, right: str) -> int | None:
    """RPM versions: [epoch:]version[-release], as rpm orders them (a missing release matches any)."""
    a, b = _rpm_split(left), _rpm_split(right)
    if a is None or b is None:
        return None
    result = _cmp(a[0], b[0]) or _rpm_segments(a[1], b[1])
    if result or not a[2] or not b[2]:
        return result
    return _rpm_segments(a[2], b[2])


_ECOSYSTEM_COMPARATORS: dict[str, Comparator] = {
    "pypi": compare_pep440,
    "rubygems": compare_rubygems,
    "packagist": compare_composer,
    "nuget": _compare_nuget,
    "npm": compare_semver,
    "crates.io": compare_semver,
    "go": compare_semver,
    "hex": compare_semver,
    "swifturl": compare_semver,
    "pub": compare_semver,
    # Distributions: OSV names them "Debian:12", "Alpine:v3.19" and so on.
    "debian": compare_dpkg,
    "ubuntu": compare_dpkg,
    "alpine": compare_apk,
    "wolfi": compare_apk,
    "chainguard": compare_apk,
    "red hat": compare_rpm,
    "almalinux": compare_rpm,
    "rocky linux": compare_rpm,
    "fedora": compare_rpm,
    "opensuse": compare_rpm,
    "suse": compare_rpm,
    "mageia": compare_rpm,
    "openeuler": compare_rpm,
    "photon os": compare_rpm,
}


def comparator_for(ecosystem: str | None, range_type: str = "ECOSYSTEM") -> Comparator | None:
    """Return the version comparator for an OSV range, or None when unsupported."""
    kind = range_type.upper()
    if kind == "SEMVER":
        return compare_semver
    if kind != "ECOSYSTEM" or not ecosystem:
        return None
    return _ECOSYSTEM_COMPARATORS.get(ecosystem.split(":", 1)[0].casefold())


def compare_versions(left: str, right: str, ecosystem: str | None = None) -> int | None:
    """Compare two versions with the ecosystem's ordering, defaulting to SemVer."""
    comparator = comparator_for(ecosystem) if ecosystem else compare_semver
    return None if comparator is None else comparator(left, right)
