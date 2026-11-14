import pytest

from project_discovery.vulnerabilities.cvss import (
    base_score,
    cvss2_base_score,
    cvss3_base_score,
    qualitative_severity,
)
from project_discovery.vulnerabilities.versions import (
    comparator_for,
    compare_apk,
    compare_composer,
    compare_conan,
    compare_dpkg,
    compare_go,
    compare_hackage,
    compare_maven,
    compare_pep440,
    compare_pub,
    compare_r,
    compare_rpm,
    compare_rubygems,
    compare_semver,
    compare_vendor,
    go_pseudo_version,
)


def _ascending(compare, versions: list[str]) -> list[tuple[str, str, int | None]]:
    """The pairs of an ascending list that the comparator does not order (every pair, both ways)."""
    wrong = []
    for index, lower in enumerate(versions):
        for higher in versions[index + 1:]:
            if compare(lower, higher) != -1 or compare(higher, lower) != 1:
                wrong.append((lower, higher, compare(lower, higher)))
    return wrong


@pytest.mark.parametrize(("left", "right", "expected"), [
    # SemVer 2.0 precedence examples from the specification.
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-alpha.beta", "1.0.0-beta", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("v1.2.3", "1.2.3+build.7", 0),
    # Go pseudo-versions and +incompatible build metadata.
    ("v0.0.0-20210101000000-abcdef123456", "v0.0.0-20220101000000-abcdef123456", -1),
    ("2.0.0+incompatible", "2.0.1", -1),
    ("not-a-version", "1.0.0", None),
])
def test_semver_precedence(left, right, expected):
    assert compare_semver(left, right) == expected


@pytest.mark.parametrize(("left", "right", "expected"), [
    ("1.0.a", "1.0", -1),
    ("1.0", "1.0.0", 0),
    ("1.2.10", "1.2.9", 1),
    ("2.0.0.beta.2", "2.0.0.beta.10", -1),
    ("6.1.7.3", "6.1.7.10", -1),
])
def test_rubygems_ordering(left, right, expected):
    assert compare_rubygems(left, right) == expected


@pytest.mark.parametrize(("left", "right", "expected"), [
    ("1.0rc1", "1.0", -1),
    ("1.0.post1", "1.0", 1),
    ("1.0.dev1", "1.0a1", -1),
    ("2.0", "2.0.0", 0),
])
def test_pep440_ordering(left, right, expected):
    assert compare_pep440(left, right) == expected


def test_composer_ordering_is_natural_and_case_insensitive():
    assert compare_composer("1.0.0-beta10", "1.0.0-beta9") == 1
    assert compare_composer("v2.1.0", "2.1.0") == 0
    assert compare_composer("1.0.0-RC1", "1.0.0-beta2") == 1


def test_composer_orders_stabilities_and_patch_releases_like_composer():
    # Regression: Magento patch releases (2.4.6-p3) were ordered as prereleases, so the
    # range [2.4.6, 2.4.6-p6) missed every vulnerable patch release.
    assert compare_composer("2.4.6-p3", "2.4.6") == 1
    assert compare_composer("2.4.6-p3", "2.4.6-p6") == -1
    assert compare_composer("2.4.6-patch1", "2.4.6-p1") == 0
    assert compare_composer("1.0.0-dev", "1.0.0-alpha1") == -1
    assert compare_composer("1.0.0-alpha1", "1.0.0-beta1") == -1
    assert compare_composer("1.0.0-rc1", "1.0.0") == -1
    assert compare_composer("1.0", "1.0.0.0") == 0
    assert compare_composer("dev-main", "1.0.0") is None


def test_nuget_compares_alphanumeric_labels_ordinally():
    nuget = comparator_for("NuGet", "ECOSYSTEM")
    assert nuget("1.0.0-beta10", "1.0.0-beta9") == -1
    assert nuget("1.0.0-BETA.2", "1.0.0-beta.10") == -1
    assert nuget("1.0.0-beta", "1.0.0") == -1


def test_git_ranges_do_not_make_decidable_versions_unknown():
    # Regression: PyPA records carry a GIT commit range next to the ECOSYSTEM range, and
    # the uncomparable GIT range turned every patched version into an UNKNOWN match.
    from project_discovery.analyzers.dependencies.vulnerabilities import _affected_version

    affected = {
        "ranges": [
            {"type": "GIT", "repo": "https://github.com/psf/requests", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]},
        ],
        "versions": ["2.19.0", "2.19.1"],
    }
    assert _affected_version("2.31.0", affected, "PyPI")[0] is False
    assert _affected_version("2.19.1", affected, "PyPI")[0] is True
    git_only = {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]}
    assert _affected_version("2.31.0", git_only, "PyPI")[0] is None


def test_osv_range_types_select_the_right_comparator():
    assert comparator_for("PyPI", "SEMVER") is compare_semver
    assert comparator_for("PyPI", "ECOSYSTEM") is compare_pep440
    assert comparator_for("RubyGems", "ECOSYSTEM") is compare_rubygems
    assert comparator_for("npm", "GIT") is None
    assert comparator_for("Maven", "ECOSYSTEM") is compare_maven
    assert comparator_for("Go", "ECOSYSTEM") is compare_go
    assert comparator_for("Debian:12", "ECOSYSTEM") is compare_dpkg
    assert comparator_for("Bioconductor", "ECOSYSTEM") is compare_r
    assert comparator_for("CPE", "CPE") is compare_vendor
    assert comparator_for("GitHub Actions", "ECOSYSTEM") is None


# Maven's own ComparableVersionTest vectors, ascending.
MAVEN_QUALIFIERS = ["1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc",
                    "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1",
                    "1-1-snapshot", "1-1", "1-2", "1-123"]
MAVEN_NUMBERS = ["2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2",
                 "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m"]


def test_maven_follows_the_version_order_specification():
    assert _ascending(compare_maven, MAVEN_QUALIFIERS) == []
    assert _ascending(compare_maven, MAVEN_NUMBERS) == []
    equal = [("1", "1.0.0"), ("1.0", "1.0-0"), ("1a", "1.0.0-a"), ("1.0.0x", "1-x"), ("1ga", "1"), ("1RELeaSE", "1"),
             ("1Final", "1"), ("1cr", "1rc"), ("1a1", "1-alpha-1"), ("1b2", "1-beta-2"), ("1m3", "1MILESTONE3"),
             ("2-a", "2.0.0.a"), ("5.3.18.RELEASE", "5.3.18")]
    assert [pair for pair in equal if compare_maven(*pair) != 0] == []
    ordered = [("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"), ("1.0.0", "1.0-1"), ("2.0-1", "2.0.1"), ("2.0.1", "2.0.1-xyz"),
               ("2.0.1-xyz", "2.0.1-123"), ("6.1.0rc3", "6.1.0"), ("6.1.0", "6.1H.5-beta"), ("1-0.alpha", "1"),
               ("1.0.0.abc1", "1.0.0-abc2"), ("20190126.230843", "1234567890.12345"), ("2.0.0.M1", "2.0.0"),
               ("2.13.4", "2.13.4.2"), ("31.1-android", "31.1-jre"), ("31.1", "31.1-jre"), ("1.0-SNAPSHOT", "1.0")]
    assert [pair for pair in ordered if compare_maven(*pair) != -1] == []
    assert compare_maven("", "1") is None and compare_maven("1 0", "1") is None

    # Maven ECOSYSTEM ranges (Gradle lockfiles) were UNKNOWN before; they decide now.
    from project_discovery.analyzers.dependencies.vulnerabilities import _affected_version

    jackson = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.13.4.2"}]}]}
    assert [_affected_version(version, jackson, "Maven")[0] for version in (
        "2.12.7", "2.13.0", "2.13.4", "2.13.4.1", "2.13.4.2", "2.14.0-rc1")] == [False, True, True, True, False, False]


def test_go_orders_releases_prereleases_and_pseudo_versions_as_go_does():
    assert _ascending(compare_go, [
        "v0.0.0-20190101000000-abcdefabcdef", "v0.0.0-20200101000000-abcdefabcdef", "v0.1.0", "v1.2.3",
        "v1.2.4-0.20191109021931-daa7c04131f5",  # a commit after v1.2.3
        "v1.2.4-alpha", "v1.2.4-alpha.0.20200101000000-abcdefabcdef", "v1.2.4-beta", "v1.2.4", "v2.0.0+incompatible",
        "v2.0.1"]) == []
    assert (compare_go("v1.2", "v1.2.0"), compare_go("1.2.3", "v1.2.3"), compare_go("v2.0.0+incompatible", "v2.0.0")) == (
        0, 0, 0)
    # What golang.org/x/mod/semver rejects: shorthand with a prerelease, leading zeros, four parts.
    assert [compare_go(bad, "v1.0.0") for bad in ("v1.2-pre", "v01.2.3", "1.2.3.4", "v1.2.3-01")] == [None] * 4
    assert go_pseudo_version("v0.0.0-20210101000000-abcdef123456") == ("", "20210101000000", "abcdef123456")
    assert go_pseudo_version("v1.2.4-0.20191109021931-daa7c04131f5") == ("v1.2.3", "20191109021931", "daa7c04131f5")
    assert go_pseudo_version("v1.2.3-pre.0.20191109021931-daa7c04131f5")[0] == "v1.2.3-pre"
    assert [go_pseudo_version(value) for value in ("v1.2.3", "v1.2.3-beta", "v1.2.0-0.20191109021931-daa7c04131f5")] == [
        None, None, None]


def test_a_go_pseudo_version_finding_says_what_it_is():
    from project_discovery.analyzers.dependencies.lockfile_parsers import ResolvedPackage
    from project_discovery.analyzers.dependencies.vulnerabilities import advisory_findings, match_advisories

    advisory = {"id": "GO-2020-0001", "aliases": [], "severity": "HIGH", "summary": "x", "details": "",
                "modified": "2020-01-01T00:00:00Z", "withdrawn": None, "ecosystem": "Go",
                "affected": {"package": {"ecosystem": "Go", "name": "m"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}}
    package = ResolvedPackage("Go", "example.com/m", "v1.2.4-0.20191109021931-daa7c04131f5")
    finding, = advisory_findings("go.sum", package, match_advisories(package, [advisory]))
    assert finding.confidence == "CONFIRMED"
    assert "Go pseudo-version: commit daa7c04131f5 of 2019-11-09 02:19:31 UTC, after v1.2.3" in finding.detail


def test_pub_hackage_r_and_conan_orderings():
    assert _ascending(compare_pub, ["1.0.0-beta", "1.0.0", "1.0.0+1", "1.0.0+2", "1.0.0+10", "1.0.1-dev", "1.0.1"]) == []
    assert compare_pub("1.0", "1.0.0") is None
    assert _ascending(compare_hackage, ["1.0", "1.0.0", "1.0.1", "1.2", "1.10"]) == []
    assert compare_hackage("1.0a", "1.0") is None
    assert _ascending(compare_r, ["0.9", "0.10", "1.2-3", "1.2-9", "1.2-10"]) == []
    assert compare_r("1.2-3", "1.2.3") == 0 and compare_r("1.2-x", "1.2") is None
    assert _ascending(compare_conan, ["1.2.0-pre", "1.2", "1.2+b1", "1.2+b2", "1.3"]) == []
    assert compare_conan("1.2", "1.2.0") == 0 and compare_conan("cci.20210101", "cci.20220101") == -1


def test_distribution_orderings():
    assert _ascending(compare_dpkg, ["1.0~rc1", "1.0", "1.0-1~deb12u1", "1.0-1", "1.0-1+deb12u1", "1.0a", "1.0+", "2.0",
                                     "1:0.9"]) == []
    assert _ascending(compare_dpkg, ["2.36-9+deb12u4", "2.36-9+deb12u10"]) == []
    assert _ascending(compare_apk, ["1.2.3_alpha1", "1.2.3_beta1", "1.2.3_pre1", "1.2.3_rc1", "1.2.3", "1.2.3-r1",
                                    "1.2.3-r10", "1.2.3_p1", "1.2.3a", "1.2.4"]) == []
    assert compare_apk("1.2.3_rc1-r5", "1.2.3") == -1 and compare_apk("1.2.3_git20230101", "1.2.3") == 1
    assert _ascending(compare_rpm, ["1.0~rc1", "1.0", "1.0^post1", "1.0a", "1.0.1", "2.0", "1:1.0"]) == []
    assert _ascending(compare_rpm, ["5.1.8-6.el9", "5.1.8-6.el9_1", "5.1.8-7.el9"]) == []
    assert compare_rpm("2.0", "2.0-1") == 0  # a version without a release matches every release


def test_vendor_product_versions_and_nvd_cpe_bounds():
    assert _ascending(compare_vendor, ["1.0rc1", "1.0", "1.0a", "1.0.2", "1.0.2k", "1.0.3"]) == []
    assert _ascending(compare_vendor, ["15.2(4)M3", "15.2(4)M10", "15.3(1)T"]) == []
    assert _ascending(compare_vendor, ["18.4R1", "18.4R2", "18.4R2-S3", "18.4R3"]) == []
    assert _ascending(compare_vendor, ["10.2.4", "10.2.4-h3", "10.2.5"]) == []
    assert _ascending(compare_vendor, ["3.0.0-alpha1", "3.0.0-beta", "3.0.0-rc2", "3.0.0", "3.0.0-sp1"]) == []
    assert compare_vendor("2.4.58", "2.4.58.0") == 0 and compare_vendor("1.0/2", "1") is None

    from project_discovery.analyzers.dependencies.vulnerabilities import _affected_version
    from project_discovery.vulnerabilities.adapters import convert

    _, records = convert({"vulnerabilities": [{"cve": {"id": "CVE-2024-9999", "configurations": [{"nodes": [
        {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                       "versionStartExcluding": "2.4.0", "versionEndIncluding": "2.4.58"}]}]}]}}]})
    affected = next(records)["affected"][0]
    # NVD's exclusive start, which OSV events cannot say, is kept and evaluated.
    assert [_affected_version(version, affected, "CPE")[0] for version in ("2.4.0", "2.4.1", "2.4.58", "2.4.59")] == [
        False, True, True, False]


@pytest.mark.parametrize(("vector", "score"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_scores_match_published_values(vector, score):
    assert cvss3_base_score(vector) == score


@pytest.mark.parametrize(("vector", "score"), [
    ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
    ("AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
    ("AV:L/AC:L/Au:N/C:C/I:C/A:C", 7.2),
])
def test_cvss2_base_scores_match_published_values(vector, score):
    assert cvss2_base_score(vector) == score


def test_cvss_entries_and_bands():
    assert base_score("CVSS_V3", "7.5") == 7.5
    assert base_score("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L") is None
    assert [qualitative_severity(v) for v in (9.0, 7.0, 4.0, 0.1, 0.0)] == [
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    ]
