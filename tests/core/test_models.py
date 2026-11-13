from project_discovery.models import (
    DirectoryRecord,
    FileRecord,
    Finding,
    ScanResult,
    SpecialEntryRecord,
    SymlinkRecord,
)


def test_inventory_models_serialize_additive_metadata():
    file = FileRecord(
        "src/main.rs", 42, ".rs", "Rust",
        file_type="text", size_bucket="4-64KiB", is_hidden=False,
    )
    directory = DirectoryRecord("src", 1, direct_child_count=1, file_count=1, total_bytes=42)
    directory.pruned = True
    directory.prune_reason = "explicit --exclude-dir name: node_modules"
    link = SymlinkRecord("current", "releases/v1", "internal")
    result = ScanResult(
        root="/work/project",
        started_at="start",
        finished_at="finish",
        files=[file],
        directories=[directory],
        symlinks=[link],
        special_entries=[SpecialEntryRecord("events.pipe", "fifo", permissions=0o600)],
    )
    payload = result.to_dict()
    assert payload["schema_version"] == "1.17"
    # Schema 1.8: ownership, platform attributes and the opt-in security block on every record.
    for kind in ("files", "directories", "symlinks", "special_entries"):
        assert {key: payload[kind][0][key] for key in ("uid", "gid", "attributes", "security", "reparse_tag")} == {
            "uid": None, "gid": None, "attributes": [], "security": None, "reparse_tag": None,
        }
    # Schema 1.9: modification times on every record, device numbers on special entries.
    assert all("mtime_ns" in payload[kind][0] for kind in ("files", "directories", "symlinks", "special_entries"))
    assert (payload["special_entries"][0]["device_major"], payload["special_entries"][0]["device_minor"]) == (None, None)
    assert payload["files"][0]["file_type"] == "text"
    assert payload["directories"][0]["total_bytes"] == 42
    assert payload["symlinks"][0]["target_scope"] == "internal"
    assert payload["special_entries"][0]["entry_type"] == "fifo"
    assert payload["directories"][0]["prune_reason"].startswith("explicit")


def test_security_categories_receive_triage_severity_by_default():
    assert Finding("security", "risk", "detail").severity == "MEDIUM"
    assert Finding("supply_chain", "risk", "detail").severity == "MEDIUM"
    assert Finding("migration", "risk", "detail").severity == "MEDIUM"
    assert Finding("privacy", "risk", "detail").severity == "MEDIUM"
    assert Finding("code", "info", "detail").severity == "INFO"


def test_explicit_severity_overrides_category_default():
    assert Finding("security", "critical", "detail", severity="CRITICAL").severity == "CRITICAL"
