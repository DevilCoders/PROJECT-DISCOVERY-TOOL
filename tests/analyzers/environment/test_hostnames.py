"""Host names: public suffixes and registrable domains from the bundled Public Suffix List,
IDNA labels, look-alike scripts and WHATWG IPv4 forms; and the network analyzer's use of them."""
from __future__ import annotations

from pathlib import Path

import pytest

from project_discovery.analyzers.environment import hostnames
from project_discovery.analyzers.environment.network import NetworkIndicatorAnalyzer
from project_discovery.models import FileRecord


@pytest.mark.parametrize(("domain", "suffix", "registrable", "subdomain"), [
    ("example.com", "com", "example.com", False),
    ("api.example.com", "com", "example.com", True),
    ("example.co.uk", "co.uk", "example.co.uk", False),  # not a subdomain by label count
    ("api.example.co.uk", "co.uk", "example.co.uk", True),
    ("co.uk", "co.uk", None, False),  # a public suffix itself
    ("user.github.io", "github.io", "user.github.io", False),  # the private section
    ("docs.user.github.io", "github.io", "user.github.io", True),
    ("foo.ck", "foo.ck", None, False),  # the wildcard rule *.ck
    ("bar.foo.ck", "foo.ck", "bar.foo.ck", False),
    ("www.ck", "ck", "www.ck", False),  # the exception rule !www.ck
    ("a.www.ck", "ck", "www.ck", True),
    ("example.unknowntld", "unknowntld", "example.unknowntld", False),  # the default rule *
    ("пример.рф", "рф", "пример.рф", False),
    ("shop.bücher.de", "de", "bücher.de", True),
])
def test_public_suffixes_and_registrable_domains_follow_the_list(domain, suffix, registrable, subdomain):
    assert hostnames.public_suffix(domain) == suffix
    assert hostnames.registrable_domain(domain) == registrable
    assert hostnames.is_subdomain(domain) is subdomain


def test_idna_labels_are_normalized_both_ways():
    assert hostnames.normalize("XN--BCHER-KVA.DE.") == "bücher.de"
    assert hostnames.normalize("Bücher.De") == "bücher.de"
    assert hostnames.to_ascii("bücher.de") == "xn--bcher-kva.de"
    assert hostnames.to_ascii("пример.рф") == "xn--e1afmkfd.xn--p1ai"
    assert hostnames.to_ascii("example.com") == "example.com"


@pytest.mark.parametrize(("domain", "labels"), [
    ("аpple.com", ["аpple"]),  # the first letter is Cyrillic
    ("pаypаl.com", ["pаypаl"]),
    ("пример.рф", []),  # all Cyrillic: no mix
    ("bücher.de", []),  # Latin with diacritics
    ("example.com", []),
])
def test_labels_that_mix_look_alike_scripts_are_found(domain, labels):
    assert hostnames.mixed_script_labels(domain) == labels


@pytest.mark.parametrize(("host", "address"), [
    ("2130706433", "127.0.0.1"), ("0x7f000001", "127.0.0.1"), ("0x7f.1", "127.0.0.1"),
    ("0177.0.0.1", "127.0.0.1"), ("127.1", "127.0.0.1"), ("10.1.1", "10.1.0.1"), ("169.254.169.254", "169.254.169.254"),
    ("1.2.3.4.", "1.2.3.4"), ("256.1.1.1", None), ("4294967296", None), ("08.0.0.1", None), ("1.2.3.4.5", None),
    ("example.com", None), ("0x", "0.0.0.0"),
])
def test_whatwg_ipv4_forms_are_read_as_browsers_read_them(host, address):
    assert hostnames.whatwg_ipv4(host) == address


def _scan(tmp_path: Path, text: str, name: str = "settings.conf"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    record = FileRecord(name, path.stat().st_size, path.suffix, "Configuration", file_type="text")
    findings = NetworkIndicatorAnalyzer().analyze(path, record)
    return {finding.title.split(":", 1)[0]: finding for finding in findings}


def test_zone_scoped_ipv6_addresses_keep_their_zone(tmp_path: Path):
    findings = _scan(tmp_path, "peer = fe80::1%eth0\nurl = http://[fe80::abcd%25wlan0]:8080/status\n")
    evidence = findings["IPv6 address indicators"].evidence
    assert "settings.conf:1 (fe80::1%eth0)" in evidence
    assert "settings.conf:2 (fe80::abcd%wlan0)" in evidence


def test_ip_addresses_written_to_evade_filters_are_found(tmp_path: Path):
    findings = _scan(tmp_path, "a = http://2130706433/admin\nb = http://0x7f.1:8080/\nc = http://%31%32%37.0.0.1/\n"
                               "d = http://169.254.169.254/latest/meta-data\n")
    addresses = findings["IPv4 address indicators"].evidence
    assert {"settings.conf:1 (127.0.0.1)", "settings.conf:2 (127.0.0.1)", "settings.conf:3 (127.0.0.1)",
            "settings.conf:4 (169.254.169.254)"} <= set(addresses)
    hidden = findings["IP addresses written to evade URL filters"]
    assert hidden.severity == "MEDIUM" and set(hidden.evidence) == {
        "settings.conf:1 (2130706433 = 127.0.0.1)", "settings.conf:2 (0x7f.1 = 127.0.0.1)",
        "settings.conf:3 (%31%32%37.0.0.1 = 127.0.0.1)"}  # the plain dotted quad is no evasion


def test_subdomains_are_counted_by_the_public_suffix_list(tmp_path: Path):
    findings = _scan(tmp_path, "a = https://example.co.uk/\nb = https://api.example.co.uk/\n"
                               "c = https://user.github.io/\nd = https://www.example.com/\n")
    detail = findings["Hostname and domain indicators"].detail
    assert "4 distinct FQDN/domain candidate(s) under 3 registrable domain(s), 2 of them subdomain(s)" in detail


def test_internationalized_and_look_alike_domains_are_reported(tmp_path: Path):
    findings = _scan(tmp_path, "shop = https://bücher.de/kasse\nsame = xn--bcher-kva.de\nru = https://пример.рф/\n"
                               "fake = https://аpple.com/login\n")
    domains = findings["Hostname and domain indicators"].evidence
    assert "settings.conf:1 (bücher.de)" in domains and "settings.conf:2 (bücher.de)" in domains
    international = findings["Internationalized domain names"].evidence
    assert "settings.conf:1 (bücher.de = xn--bcher-kva.de)" in international
    assert "settings.conf:3 (пример.рф = xn--e1afmkfd.xn--p1ai)" in international
    homograph = findings["Domain names that mix look-alike scripts"]
    assert homograph.severity == "MEDIUM"
    assert homograph.evidence == ["settings.conf:4 (аpple.com = xn--pple-43d.com; mixed: аpple)"]


def test_url_host_edge_cases(tmp_path: Path):
    findings = _scan(tmp_path, "a = HTTP://API.Example.COM./v1\nb = http://evil.example.net\\@good.example.org/\n"
                               "c = http://user:p@ss@db.example.com:5432/\nd = http://example.com:/x\n")
    domains = {line.split("(", 1)[1].rstrip(")") for line in findings["Hostname and domain indicators"].evidence}
    # Upper case and a trailing dot are one name; a backslash ends the authority as browsers read it;
    # the last "@" ends the user information.
    assert {"api.example.com", "evil.example.net", "db.example.com", "example.com"} <= domains
    assert "good.example.org" not in domains
    assert all("p@ss" not in line for line in findings["URL/URI indicators"].evidence)
