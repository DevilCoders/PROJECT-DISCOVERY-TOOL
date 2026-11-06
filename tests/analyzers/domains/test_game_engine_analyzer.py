from pathlib import Path

from project_discovery.analyzers.domains.game_engines import GameEngineIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _scan(tmp_path: Path, filename: str, relative: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    record = FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Source")
    analyzer = GameEngineIntelligenceAnalyzer()
    assert analyzer.supports(record)
    return analyzer.analyze(path, record)


def test_godot_project_and_scene_inventory(tmp_path: Path):
    project = _scan(
        tmp_path, "project.godot", "game/project.godot",
        'config/features=["4.3"]\nrun/main_scene="res://main.tscn"\n',
    )
    assert any("Godot project" in item.title for item in project)
    scene = _scan(
        tmp_path, "main.tscn", "game/scenes/main.tscn",
        '[gd_scene load_steps=2 format=3]\n'
        '[node name="Root" type="Node2D"]\n'
        '[node name="Player" type="CharacterBody2D" parent="."]\n'
        '[ext_resource type="Script" path="res://player.gd" id="1"]\n',
    )
    assert "2 scene node declaration" in scene[0].detail


def test_unreal_project_and_cpp_reflection_markers(tmp_path: Path):
    project = _scan(
        tmp_path, "Game.uproject", "Game/Game.uproject",
        '{"EngineAssociation":"5.4","Modules":[{"Name":"Game"}],"Plugins":[]}',
    )
    assert any("Unreal Engine project" in item.title for item in project)
    source = _scan(
        tmp_path, "Player.h", "Source/Game/Player.h",
        "UCLASS()\nclass APlayer : public AActor {\nGENERATED_BODY()\nUPROPERTY()\n};\n",
    )
    assert any("Unreal Engine source markers" in item.title for item in source)


def test_unity_version_and_script_markers(tmp_path: Path):
    version = _scan(
        tmp_path, "ProjectVersion.txt", "ProjectSettings/ProjectVersion.txt",
        "m_EditorVersion: 2022.3.18f1\n",
    )
    assert "2022.3.18f1" in version[0].detail
    script = _scan(
        tmp_path, "Player.cs", "Assets/Scripts/Player.cs",
        "public class Player : MonoBehaviour {\n[SerializeField] int speed;\n}\n",
    )
    assert any("MonoBehaviour" in item.detail for item in script)


def test_gamemaker_and_renpy_script_markers(tmp_path: Path):
    gml = _scan(
        tmp_path, "player.gml", "objects/obj_player/player.gml",
        "function move_player() {\n    room_goto(rm_next);\n}\n",
    )
    assert any("GameMaker script markers" in item.title for item in gml)
    rpy = _scan(
        tmp_path, "script.rpy", "game/script.rpy",
        "label start:\n    define hero = Character('Hero')\n",
    )
    assert any("Ren'Py script markers" in item.title for item in rpy)


def test_bevy_manifest_and_binary_asset_inventory(tmp_path: Path):
    cargo = _scan(
        tmp_path, "Cargo.toml", "game/Cargo.toml",
        '[dependencies]\nbevy = "0.14"\n',
    )
    assert any("Bevy project dependency" in item.title for item in cargo)

    path = tmp_path / "level.umap"
    path.write_bytes(b"binary-map-data")
    record = FileRecord("Content/Maps/level.umap", path.stat().st_size, ".umap", "Other")
    findings = GameEngineIntelligenceAnalyzer().analyze(path, record)
    assert findings[0].category == "assets"
    assert "not decoded" in findings[0].detail


def test_unrelated_python_file_is_not_a_game_file(tmp_path: Path):
    path = tmp_path / "logic.py"
    path.write_text("print('ordinary utility')", encoding="utf-8")
    record = FileRecord("src/logic.py", path.stat().st_size, ".py", "Python")
    assert GameEngineIntelligenceAnalyzer().supports(record) is False
