from project_discovery.architecture_analyzer import analyze_project_architecture
from project_discovery.models import FileRecord


def _record(path: str, error=None):
    return FileRecord(path, 100, "." + path.rsplit(".", 1)[-1], "Source", error=error)


def test_project_layout_infers_multiple_layers_with_path_evidence():
    records = [
        _record("src/domain/entities/user.py"),
        _record("src/application/services/user_service.py"),
        _record("src/infrastructure/adapters/email.py"),
        _record("src/presentation/api/routes.py"),
        _record("src/persistence/repositories/user.py"),
        _record("tests/test_user.py"),
        _record("docs/architecture.md"),
    ]
    metrics, findings = analyze_project_architecture(records)
    assert metrics["file_count"] == 7
    assert {item["name"] for item in metrics["layers"]} >= {
        "domain", "application", "infrastructure", "presentation",
        "api", "persistence", "testing", "documentation",
    }
    assert len(findings) == 1
    assert findings[0].confidence == "INFERRED"
    assert "does not establish dependency direction" in findings[0].detail


def test_project_layout_ignores_unreadable_records_and_handles_flat_repositories():
    metrics, findings = analyze_project_architecture([
        _record("main.rs"),
        _record("broken.py", error="permission denied"),
    ])
    assert metrics["file_count"] == 1
    assert metrics["layers"] == []
    assert metrics["top_level_components"] == []
    assert findings == []


def test_project_layout_recognizes_ml_robotics_game_and_delivery_layers():
    metrics, findings = analyze_project_architecture([
        _record("training/experiments/run.py"),
        _record("robot/launch/start.launch.py"),
        _record("game/assets/player.tres"),
        _record("deploy/production/compose.yml"),
    ])
    assert {item["name"] for item in metrics["layers"]} >= {
        "machine_learning", "robotics", "game_engine", "delivery",
    }
    assert findings[0].confidence == "INFERRED"
