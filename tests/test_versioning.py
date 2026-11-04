import pytest

from project_discovery.cvss import base_score, cvss2_base_score, cvss3_base_score, qualitative_severity
from project_discovery.versioning import (
    comparator_for,
    compare_composer,
    compare_pep440,
    compare_rubygems,
    compare_semver,
)


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


def test_osv_range_types_select_the_right_comparator():
    assert comparator_for("PyPI", "SEMVER") is compare_semver
    assert comparator_for("PyPI", "ECOSYSTEM") is compare_pep440
    assert comparator_for("RubyGems", "ECOSYSTEM") is compare_rubygems
    assert comparator_for("npm", "GIT") is None
    assert comparator_for("Maven", "ECOSYSTEM") is None


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
