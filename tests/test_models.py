from project_discovery.models import Finding


def test_security_categories_receive_triage_severity_by_default():
    assert Finding("security", "risk", "detail").severity == "MEDIUM"
    assert Finding("supply_chain", "risk", "detail").severity == "MEDIUM"
    assert Finding("migration", "risk", "detail").severity == "MEDIUM"
    assert Finding("code", "info", "detail").severity == "INFO"


def test_explicit_severity_overrides_category_default():
    assert Finding("security", "critical", "detail", severity="CRITICAL").severity == "CRITICAL"
