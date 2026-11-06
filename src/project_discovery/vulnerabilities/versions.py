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
# NuGet labels are case-insensitive; Composer stabilities such as beta10 sort naturally.
_compare_nuget = _semver_comparator(natural=True, casefold=True)
_compare_composer = _semver_comparator(natural=True, casefold=True)


def _strip_composer(value: str) -> str:
    value = value.strip()
    # Composer stability flags (1.2.3@dev) and inline aliases (1.x-dev as 1.2.3) are not ordered.
    return value.split("@", 1)[0].split(" as ", 1)[-1]


def compare_composer(left: str, right: str) -> int | None:
    return _compare_composer(_strip_composer(left), _strip_composer(right))


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
