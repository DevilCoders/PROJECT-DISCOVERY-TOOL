"""Host names: their public suffix and registrable domain from the bundled Public Suffix List,
internationalized (IDNA) labels, and the WHATWG forms of IPv4 addresses in URLs.

The list (data/public_suffix_list.dat, MPL-2.0, from https://publicsuffix.org/list/) is a
snapshot bundled unmodified: nothing is fetched. Its rules are applied as the list's own
algorithm says: the longest matching rule prevails, an exception rule (``!www.ck``) over
a wildcard (``*.ck``), and an unlisted TLD is its own suffix. ICANN and private rules
both apply, as in browsers: ``user.github.io`` is a registrable domain of its own.
"""
from __future__ import annotations

import unicodedata
from functools import lru_cache
from importlib.resources import files as resource_files


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(rules, wildcard parents, exception rules), lower-cased Unicode."""
    text = resource_files("project_discovery").joinpath("data/public_suffix_list.dat").read_text(encoding="utf-8")
    rules, wildcards, exceptions = set(), set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcards.add(rule[2:])
        else:
            rules.add(rule)
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


def to_unicode(label: str) -> str:
    """A label's Unicode form (an ``xn--`` A-label decoded), lower-cased."""
    label = label.lower()  # the idna codec recognizes only a lower-case "xn--" prefix
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna").lower()
        except UnicodeError:
            return label
    return label


def to_ascii(domain: str) -> str | None:
    """A domain's ASCII (A-label) form, or None when a label is not a valid IDNA label."""
    labels = []
    for label in domain.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            return None
    return ".".join(labels)


def normalize(domain: str) -> str:
    """A domain as compared and reported: lower-cased Unicode labels, no trailing dot."""
    return ".".join(to_unicode(label) for label in domain.strip(".").split("."))


def public_suffix(domain: str) -> str:
    """The public suffix of a normalized domain (its last label when no rule matches)."""
    rules, wildcards, exceptions = _rules()
    labels = domain.split(".")
    for start in range(len(labels)):  # the longest candidate first
        candidate = ".".join(labels[start:])
        if candidate in exceptions:
            return ".".join(labels[start + 1:])
        if candidate in rules:
            return candidate
        if start + 1 < len(labels) and ".".join(labels[start + 1:]) in wildcards:
            return candidate
    return labels[-1]


def registrable_domain(domain: str) -> str | None:
    """The public suffix and one more label, or None when the domain is a public suffix."""
    suffix = public_suffix(domain)
    labels, suffix_labels = domain.split("."), suffix.count(".") + 1
    if len(labels) <= suffix_labels:
        return None
    return ".".join(labels[-(suffix_labels + 1):])


def is_subdomain(domain: str) -> bool:
    """Whether a normalized domain has labels beyond its registrable domain."""
    registrable = registrable_domain(domain)
    return registrable is not None and registrable != domain


_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"})


def mixed_script_labels(domain: str) -> list[str]:
    """Labels that mix Latin letters with Cyrillic, Greek, Armenian or Cherokee ones, the
    look-alike scripts of IDN homograph names (``аpple``, its first letter Cyrillic)."""
    found = []
    for label in domain.split("."):
        if label.isascii():
            continue
        scripts = set()
        for char in label:
            if char.isalpha():
                name = unicodedata.name(char, "")
                scripts.add(name.split(" ", 1)[0])
        if "LATIN" in scripts and len(scripts & _CONFUSABLE_SCRIPTS) > 1:
            found.append(label)
    return found


def whatwg_ipv4(host: str) -> str | None:
    """The IPv4 address a URL host means in browsers and curl when it is written in the
    WHATWG number forms (``2130706433``, ``0x7f.1``, ``0177.0.0.1``, ``127.1``), else None."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts.pop()  # a trailing dot
    if not 1 <= len(parts) <= 4:
        return None
    numbers = []
    for part in parts:
        if not part:
            return None
        try:
            if part[:2].lower() == "0x":
                value = int(part[2:] or "0", 16)
            elif len(part) > 1 and part[0] == "0":
                value = int(part[1:], 8)
            else:
                value = int(part, 10) if part.isdigit() else None
        except ValueError:
            return None
        if value is None:
            return None
        numbers.append(value)
    if any(value > 255 for value in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    address = numbers[-1]
    for index, value in enumerate(numbers[:-1]):
        address += value << (8 * (3 - index))
    return ".".join(str((address >> shift) & 0xFF) for shift in (24, 16, 8, 0))
