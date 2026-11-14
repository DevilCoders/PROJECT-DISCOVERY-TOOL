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


_ASCII_DIGITS = frozenset("0123456789")
_IDENTIFIER_CHARACTERS = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-")
_MAX_VERSION_CHARACTERS = 256


def _bounded_ascii(value: str) -> str | None:
    """A version string, stripped, or None when empty, overlong, non-ASCII or holding spaces
    or control characters."""
    text = value.strip()
    if not text or len(text) > _MAX_VERSION_CHARACTERS or not text.isascii() or not text.isprintable() or " " in text:
        return None
    return text


# ---------------------------------------------------------------------------------------------
# Maven: the version order specification (https://maven.apache.org/pom.html), as Maven's
# ComparableVersion implements it.

_MAVEN_QUALIFIERS = {"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6}
_MAVEN_ALIASES = {"cr": "rc", "final": "", "ga": "", "release": ""}
_MAVEN_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}


def _maven_tokens(value: str) -> list[tuple[str, int | str]] | None:
    """A Maven version as (separator, token) pairs. It is split on ".", "-" and each change
    between digits and other characters (which counts as "-"); an empty token is 0; qualifiers
    are lower-cased and aliased ("cr" is "rc"; "final", "ga" and "release" are the release, "";
    "a", "b" and "m" right before a number are alpha, beta and milestone) and always follow a
    "-" (2.0.a is 2-a); then the null tokens, 0 and "", are trimmed from the end and from
    before every remaining "-"."""
    text = _bounded_ascii(value)
    if text is None:
        return None
    text = text.lower()
    raw: list[tuple[str, str, bool]] = []  # (separator, text, right before a number)
    separator, start = ".", 0
    for index, char in enumerate(text):
        if char in ".-":
            raw.append((separator, text[start:index], False))
            separator, start = char, index + 1
        elif index > start and (char in _ASCII_DIGITS) != (text[index - 1] in _ASCII_DIGITS):
            raw.append((separator, text[start:index], char in _ASCII_DIGITS))
            separator, start = "-", index
    raw.append((separator, text[start:], False))
    tokens: list[tuple[str, int | str]] = []
    for separator, part, before_number in raw:
        if not part or part[0] in _ASCII_DIGITS:
            tokens.append((separator, int(part) if part else 0))
        else:
            qualifier = _MAVEN_SHORT.get(part, part) if before_number else part
            tokens.append(("-", _MAVEN_ALIASES.get(qualifier, qualifier)))
    trimmed: list[tuple[str, int | str]] = []
    trimming = True
    for separator, token in reversed(tokens):
        if trimming and token in (0, ""):
            continue
        trimmed.append((separator, token))
        trimming = separator == "-"
    return trimmed[::-1]


def _maven_rank(qualifier: str) -> tuple[int, str]:
    """Known qualifiers in their order, then any other alphabetically."""
    known = _MAVEN_QUALIFIERS.get(qualifier)
    return (known, "") if known is not None else (len(_MAVEN_QUALIFIERS), qualifier)


def _maven_order(left: tuple[str, int | str], right: tuple[str, int | str]) -> int:
    (left_separator, a), (right_separator, b) = left, right
    if isinstance(a, int) and isinstance(b, int):
        if left_separator == right_separator:
            return _cmp(a, b)
        return 1 if left_separator == "." else -1  # "-number" < ".number"
    if isinstance(a, str) and isinstance(b, str):
        return _cmp(_maven_rank(a), _maven_rank(b))
    return 1 if isinstance(a, int) else -1  # a qualifier sorts before a number


def compare_maven(left: str, right: str) -> int | None:
    """Maven versions in the specification's order: 1-alpha-1 < 1-beta < 1-rc < 1-SNAPSHOT
    < 1 = 1.0 = 1-ga < 1-sp < 1-foo < 1-1 < 1.1."""
    a, b = _maven_tokens(left), _maven_tokens(right)
    if a is None or b is None:
        return None
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else None
        y = b[index] if index < len(b) else None
        # The shorter version is padded with nulls: 0 against a number, the release against
        # a qualifier (so 1 > 1-alpha but 1 < 1-sp and 1 < 1-1).
        if x is None and y is not None:
            x = (y[0], 0 if isinstance(y[1], int) else "")
        elif y is None and x is not None:
            y = (x[0], 0 if isinstance(x[1], int) else "")
        if x is None or y is None:
            break
        result = _maven_order(x, y)
        if result:
            return result
    return 0


# ---------------------------------------------------------------------------------------------
# Go: golang.org/x/mod/semver, and the pseudo-versions the go command writes for commits.


def _go_identifiers(text: str, *, numeric_rule: bool) -> list[str] | None:
    parts = text.split(".")
    for part in parts:
        if not part or not set(part) <= _IDENTIFIER_CHARACTERS:
            return None
        if numeric_rule and part.isdigit() and len(part) > 1 and part[0] == "0":
            return None  # numeric identifiers have no leading zeros
    return parts


def _go_version(value: str) -> tuple[tuple[int, int, int], list[str]] | None:
    """vMAJOR[.MINOR[.PATCH[-PRERELEASE][+BUILD]]] as golang.org/x/mod/semver reads it, the "v"
    optional (OSV writes Go versions without it); build metadata takes no part in ordering."""
    text = _bounded_ascii(value)
    if text is None:
        return None
    text = text[1:] if text[0] == "v" else text
    text, plus, build = text.partition("+")
    if plus and _go_identifiers(build, numeric_rule=False) is None:
        return None
    text, dash, prerelease = text.partition("-")
    numbers = text.split(".")
    if len(numbers) > 3 or ((dash or plus) and len(numbers) != 3):
        return None  # v1 and v1.2 are shorthands only without a prerelease or build
    if any(not part.isdigit() or (len(part) > 1 and part[0] == "0") for part in numbers):
        return None
    identifiers = _go_identifiers(prerelease, numeric_rule=True) if dash else []
    if identifiers is None:
        return None
    release = tuple(int(part) for part in numbers) + (0,) * (3 - len(numbers))
    return (release[0], release[1], release[2]), identifiers


def compare_go(left: str, right: str) -> int | None:
    """Go module versions as the go command orders them. A pseudo-version is a prerelease of
    the version after the tag it follows (v1.2.4-0.20191109021931-daa7c04131f5 sorts after
    v1.2.3 and before v1.2.4-alpha); see go_pseudo_version."""
    a, b = _go_version(left), _go_version(right)
    if a is None or b is None:
        return None
    if a[0] != b[0]:
        return _cmp(a[0], b[0])
    if not a[1] or not b[1]:
        return _cmp(not a[1], not b[1])
    for x, y in zip(a[1], b[1], strict=False):
        result = _compare_identifiers(x, y, natural=False, casefold=False)
        if result:
            return result
    return _cmp(len(a[1]), len(b[1]))


def go_pseudo_version(version: str) -> tuple[str, str, str] | None:
    """(the tag it follows, "" for none; commit time as yyyymmddhhmmss; revision) of a Go
    pseudo-version, or None for any other version. The three forms:
    vX.0.0-yyyymmddhhmmss-abcdefabcdef (no earlier tag), vX.Y.(Z+1)-0.yyyymmddhhmmss-abcdefabcdef
    (after vX.Y.Z) and vX.Y.Z-pre.0.yyyymmddhhmmss-abcdefabcdef (after vX.Y.Z-pre)."""
    parsed = _go_version(version)
    if parsed is None or not parsed[1]:
        return None
    (major, minor, patch), identifiers = parsed
    timestamp, dash, revision = identifiers[-1].partition("-")
    if not dash or len(timestamp) != 14 or not timestamp.isdigit() or not 7 <= len(revision) <= 40 \
            or not revision.isalnum():
        return None
    if len(identifiers) == 1:
        return ("", timestamp, revision) if (minor, patch) == (0, 0) else None
    if identifiers[-2] != "0":
        return None
    if len(identifiers) == 2:
        return (f"v{major}.{minor}.{patch - 1}", timestamp, revision) if patch else None
    return f"v{major}.{minor}.{patch}-" + ".".join(identifiers[:-2]), timestamp, revision


# ---------------------------------------------------------------------------------------------
# Pub: pub_semver, where a build (1.0.0+1) sorts after its release.


def _pub_parts(text: str) -> list[int | str] | None:
    items = text.split(".")
    if any(not item or not set(item) <= _IDENTIFIER_CHARACTERS for item in items):
        return None
    return [int(item) if item.isdigit() else item for item in items]


def _pub_lists(a: list[int | str], b: list[int | str]) -> int:
    """pub_semver's part order: a missing part first, numbers before strings."""
    for index in range(max(len(a), len(b))):
        if index >= len(a):
            return -1
        if index >= len(b):
            return 1
        x, y = a[index], b[index]
        if x == y:
            continue
        if isinstance(x, int) != isinstance(y, int):
            return -1 if isinstance(x, int) else 1
        return _cmp(x, y)
    return 0


def compare_pub(left: str, right: str) -> int | None:
    """Dart and Flutter package versions: SemVer precedence, then build metadata, which pub
    orders (1.0.0 < 1.0.0+1 < 1.0.0+2) where SemVer ignores it."""
    parsed = []
    for value in (left, right):
        text = _bounded_ascii(value)
        if text is None:
            return None
        text, plus, build = text.partition("+")
        text, dash, prerelease = text.partition("-")
        numbers = text.split(".")
        if len(numbers) != 3 or not all(part.isdigit() for part in numbers):
            return None
        pre = _pub_parts(prerelease) if dash else []
        built = _pub_parts(build) if plus else []
        if pre is None or built is None:
            return None
        parsed.append((tuple(int(part) for part in numbers), pre, built))
    (a_release, a_pre, a_build), (b_release, b_pre, b_build) = parsed
    if a_release != b_release:
        return _cmp(a_release, b_release)
    if bool(a_pre) != bool(b_pre):
        return 1 if not a_pre else -1  # a prerelease comes before its release
    result = _pub_lists(a_pre, b_pre)
    if result or bool(a_build) == bool(b_build):
        return result or _pub_lists(a_build, b_build)
    return 1 if a_build else -1  # a build comes after the version without one


# ---------------------------------------------------------------------------------------------
# Hackage (the Haskell PVP), CRAN and Bioconductor: lists of numbers.


def _number_list(value: str) -> tuple[int, ...] | None:
    text = _bounded_ascii(value)
    if text is None:
        return None
    parts = text.split(".")
    if any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def compare_hackage(left: str, right: str) -> int | None:
    """Haskell package versions: dotted numbers compared as lists, so 1.0 < 1.0.0 < 1.0.1."""
    a, b = _number_list(left), _number_list(right)
    return None if a is None or b is None else _cmp(a, b)


def compare_r(left: str, right: str) -> int | None:
    """R package versions (CRAN, Bioconductor): numbers separated by "." or "-" (1.2-3 is
    1.2.3), compared as lists, as package_version does."""
    a, b = _number_list(left.replace("-", ".")), _number_list(right.replace("-", "."))
    return None if a is None or b is None else _cmp(a, b)


# ---------------------------------------------------------------------------------------------
# ConanCenter: Conan 2's Version.


def _conan_items(text: str) -> tuple[int | str, ...] | None:
    items = text.split(".")
    if any(not item for item in items):
        return None
    values = [int(item) if item.isdigit() else item for item in items]
    while values and values[-1] == 0:
        values.pop()  # 1.2 == 1.2.0
    return tuple(values)


def _conan_cmp(a: tuple[int | str, ...], b: tuple[int | str, ...]) -> int:
    """Conan's item order: numbers as numbers, anything else (a number against a word too)
    as text."""
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        return _cmp(x, y) if type(x) is type(y) else _cmp(str(x), str(y))
    return _cmp(len(a), len(b))


def compare_conan(left: str, right: str) -> int | None:
    """Conan package versions: dotted items, a prerelease after the last "-" (before its
    release) and a build after the last "+" (after the version without one)."""
    parsed = []
    for value in (left, right):
        text = _bounded_ascii(value)
        if text is None:
            return None
        main, plus, build = text.rpartition("+") if "+" in text else (text, "", "")
        main, dash, pre = main.rpartition("-") if "-" in main else (main, "", "")
        items = _conan_items(main)
        pre_items = _conan_items(pre) if dash else None
        build_items = _conan_items(build) if plus else None
        if items is None or (dash and pre_items is None) or (plus and build_items is None):
            return None
        parsed.append((items, pre_items, build_items))
    (a_items, a_pre, a_build), (b_items, b_pre, b_build) = parsed
    if (a_pre is None) != (b_pre is None):
        if a_items == b_items:
            return -1 if a_pre is not None else 1
        return _conan_cmp(a_items, b_items)
    result = _conan_cmp(a_items, b_items)
    if not result and a_pre is not None and b_pre is not None:
        result = _conan_cmp(a_pre, b_pre)
    if result:
        return result
    if (a_build is None) != (b_build is None):
        return -1 if a_build is None else 1
    return _conan_cmp(a_build, b_build) if a_build is not None and b_build is not None else 0


# ---------------------------------------------------------------------------------------------
# Vendor product versions: the NVD's CPE bounds (2.4.58, 1.1.1w, 15.2(4)M3, 18.4R2-S3,
# 10.2.4-h3) follow no shared scheme and NVD defines no order for them. This one is PDT's.

_VENDOR_PRERELEASES = {"dev": 0, "snapshot": 0, "alpha": 1, "beta": 2, "milestone": 3, "pre": 4, "preview": 4,
                       "rc": 5, "cr": 5}
_VENDOR_SEPARATORS = frozenset("._-+~:()")
_VENDOR_END = (1, 0, "")


def _vendor_tokens(value: str) -> list[tuple[int, int, str]] | None:
    text = _bounded_ascii(value)
    if text is None:
        return None
    runs: list[str] = []
    current = ""
    for char in text.lower():
        if char in _VENDOR_SEPARATORS:
            if current:
                runs.append(current)
            current = ""
        elif not char.isalnum():
            return None
        else:
            if current and (char in _ASCII_DIGITS) != (current[-1] in _ASCII_DIGITS):
                runs.append(current)
                current = ""
            current += char
    if current:
        runs.append(current)
    keys: list[tuple[int, int, str]] = []
    for run in runs:
        if run[0] in _ASCII_DIGITS:
            keys.append((3, int(run), ""))
            continue
        # Zeros before a word say nothing (1.0rc1 is 1rc1, 1.0.0a is 1a).
        while keys and keys[-1] == (3, 0, ""):
            keys.pop()
        rank = _VENDOR_PRERELEASES.get(run)
        keys.append((0, rank, "") if rank is not None else (2, 0, run))
    while keys and keys[-1] == (3, 0, ""):
        keys.pop()  # 2.4 == 2.4.0
    return keys


def compare_vendor(left: str, right: str) -> int | None:
    """Vendor product versions as runs of digits and of letters, separators ignored: numbers
    numerically; dev, alpha, beta, milestone, pre/preview and rc before the release they
    follow; any other word or letter (1.1.1w, 6.0-sp2, 10.2.4-h3) after it but before the
    next number (1.0.2k < 1.0.3)."""
    a, b = _vendor_tokens(left), _vendor_tokens(right)
    if a is None or b is None:
        return None
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else _VENDOR_END
        y = b[index] if index < len(b) else _VENDOR_END
        if x != y:
            return _cmp(x, y)
    return 0


_ECOSYSTEM_COMPARATORS: dict[str, Comparator] = {
    "pypi": compare_pep440,
    "rubygems": compare_rubygems,
    "packagist": compare_composer,
    "nuget": _compare_nuget,
    "npm": compare_semver,
    "crates.io": compare_semver,
    "go": compare_go,
    "hex": compare_semver,
    "swifturl": compare_semver,
    "pub": compare_pub,
    "maven": compare_maven,
    "hackage": compare_hackage,
    "cran": compare_r,
    "bioconductor": compare_r,
    "conancenter": compare_conan,
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
    if kind == "CPE":
        return compare_vendor  # NVD bounds of vendor products (see vulnerabilities.adapters)
    if kind != "ECOSYSTEM" or not ecosystem:
        return None
    return _ECOSYSTEM_COMPARATORS.get(ecosystem.split(":", 1)[0].casefold())


def compare_versions(left: str, right: str, ecosystem: str | None = None) -> int | None:
    """Compare two versions with the ecosystem's ordering, defaulting to SemVer."""
    comparator = comparator_for(ecosystem) if ecosystem else compare_semver
    return None if comparator is None else comparator(left, right)
