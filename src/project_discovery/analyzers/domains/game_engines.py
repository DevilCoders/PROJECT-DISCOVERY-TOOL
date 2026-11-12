"""Static game-engine project, script and asset discovery."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ...core.safe_parsers import safe_xml_fromstring
from ...core.source_utils import describe_error, read_bytes_bounded, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_GAME_SCRIPT_EXTENSIONS = {".gd", ".gml", ".rpy", ".lua", ".cs", ".cpp", ".cc", ".h", ".hpp", ".rs"}
_BINARY_GAME_ASSETS = {".uasset", ".umap"}
_UNITY_MARKERS = (
    (r":\s*MonoBehaviour\b", "MonoBehaviour component"),
    (r":\s*ScriptableObject\b", "ScriptableObject type"),
    (r"\[SerializeField\]", "serialized field"),
    (r"\[CreateAssetMenu", "asset creation menu"),
)
_UNREAL_MARKERS = (
    (r"\bUCLASS\s*\(", "UCLASS"),
    (r"\bUSTRUCT\s*\(", "USTRUCT"),
    (r"\bUFUNCTION\s*\(", "UFUNCTION"),
    (r"\bUPROPERTY\s*\(", "UPROPERTY"),
    (r"\bGENERATED_BODY\s*\(", "GENERATED_BODY"),
    (r"\b(?:AActor|UActorComponent|UObject)\b", "Unreal object type"),
)
_GODOT_MARKERS = (
    (r"(?m)^[ \t]*extends\s+", "base class"),
    (r"(?m)^[ \t]*class_name\s+", "global class"),
    (r"(?m)^[ \t]*signal\s+", "signal"),
    (r"@export\b", "exported property"),
    (r"@onready\b", "onready property"),
    (r"(?m)^[ \t]*func\s+_(?:ready|process|physics_process)\s*\(", "engine lifecycle callback"),
)
_GAMEMAKER_MARKERS = (
    (r"\bfunction\s+[A-Za-z_]\w*\s*\(", "function declaration"),
    (r"\b(?:instance_create_layer|instance_create_depth|room_goto|event_perform)\s*\(", "runtime API"),
)
_RENPY_MARKERS = (
    (r"(?m)^[ \t]*label\s+[A-Za-z_]\w*\s*:", "label"),
    (r"(?m)^[ \t]*screen\s+[A-Za-z_]\w*", "screen"),
    (r"(?m)^[ \t]*define\s+[A-Za-z_]\w*\s*=", "define"),
)


class GameEngineIntelligenceAnalyzer(Analyzer):
    """Recognize major game engines and extract safe, static project evidence."""

    name = "game-engine-intelligence"
    domains = ("game_engines", "graphics_shaders", "assets")
    languages = (
        "Unity", "Unreal Engine", "Godot", "GameMaker", "Defold",
        "Bevy", "Ren'Py", "Roblox", "LÖVE", "Phaser", "Three.js", "Cocos",
    )

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        name = Path(record.path).name.lower()
        parts = {part.lower() for part in Path(record.path).parts}
        return (
            name in {
                "project.godot", "projectversion.txt", "game.project", "conf.lua",
                "packages.config",
            }
            or record.extension in _BINARY_GAME_ASSETS
            or record.extension in {
                ".gd", ".tscn", ".tres", ".gdshader", ".unity", ".prefab", ".asset",
                ".uproject", ".uplugin", ".uasset", ".umap", ".yyp", ".yy", ".gml",
                ".collection", ".script", ".rpy", ".rbxlx", ".rbxmx",
            }
            or record.extension == ".go" and bool(parts & {"game", "defold"})
            or record.extension in _GAME_SCRIPT_EXTENSIONS and bool(
                parts & {"assets", "source", "scripts", "scenes", "rooms", "objects",
                         "serverstorage", "serverscriptservice", "starterplayerscripts",
                         "replicatedstorage", "game"}
            )
            or name.endswith(".build.cs") or name.endswith(".target.cs")
            or name == "manifest.json" and "packages" in parts
            or name == "package.json"
            or name == "cargo.toml"
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        ext = record.extension
        if ext in _BINARY_GAME_ASSETS:
            return [Finding(
                "assets",
                f"Game-engine binary asset: {record.path}",
                f"Recognized binary asset container ({ext}); payload was not decoded.",
                confidence="CONFIRMED",
                evidence=[record.path, f"{record.size_bytes} bytes"],
                analyzer=self.name,
            )]
        if name == "project.godot":
            return self._godot_project(path, record)
        if name == "projectversion.txt":
            return self._unity_version(path, record)
        if name == "game.project":
            return [Finding(
                "game_engine",
                f"Defold project manifest: {record.path}",
                "Defold project configuration is present. Build settings and resource graph "
                "are not evaluated.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if name == "conf.lua":
            return [Finding(
                "game_engine",
                f"LÖVE project configuration: {record.path}",
                "LÖVE configuration script is present; it is not executed.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if name == "manifest.json" and "packages" in {p.lower() for p in Path(record.path).parts}:
            return self._unity_packages(path, record)
        if ext in {".uproject", ".uplugin", ".yyp", ".yy", ".json"}:
            return self._json_project(path, record)
        if ext == ".tscn":
            return self._godot_scene(path, record)
        if ext in {".gd", ".gdshader"}:
            return self._script_markers(path, record, "Godot", _GODOT_MARKERS)
        if ext in {".unity", ".prefab", ".asset"}:
            return [Finding(
                "assets", f"Unity serialized asset: {record.path}",
                "A Unity scene, prefab or asset text container is present. Object references "
                "and serialized component graphs are not yet resolved.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if name.endswith((".build.cs", ".target.cs")) or ext in {".cpp", ".cc", ".h", ".hpp"}:
            return self._unreal_source(path, record)
        if ext == ".cs":
            return self._unity_source(path, record)
        if ext == ".gml":
            return self._script_markers(path, record, "GameMaker", _GAMEMAKER_MARKERS)
        if ext == ".rpy":
            return self._script_markers(path, record, "Ren'Py", _RENPY_MARKERS)
        if ext in {".collection", ".go", ".script"}:
            return [Finding(
                "game_engine", f"Defold resource: {record.path}",
                "A Defold collection, game object or script resource is present.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        if ext in {".rbxlx", ".rbxmx"}:
            return self._roblox_xml(path, record)
        if name == "package.json":
            return self._web_game_manifest(path, record)
        if name == "cargo.toml":
            return self._bevy_manifest(path, record)
        return []

    def _read_text(self, path: Path, record: FileRecord):
        try:
            return read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            ), None
        except (OSError, UnicodeDecodeError) as exc:
            return None, Finding(
                "game_engine", f"Game project file read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )

    def _godot_project(self, path: Path, record: FileRecord) -> list[Finding]:
        source, error = self._read_text(path, record)
        if error:
            return [error]
        main_scene = re.search(r'(?m)^run/main_scene\s*=\s*"([^"]+)"', source)
        features = re.search(r"(?m)^config/features\s*=\s*\[([^\]]*)\]", source)
        return [Finding(
            "game_engine", f"Godot project: {record.path}",
            "Detected Godot project configuration; main scene: "
            + (main_scene.group(1) if main_scene else "not statically declared")
            + "; engine feature declaration: " + ("present" if features else "not found"),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _godot_scene(self, path: Path, record: FileRecord) -> list[Finding]:
        source, error = self._read_text(path, record)
        if error:
            return [error]
        nodes = re.findall(r'(?m)^\[node\s+name="([^"]+)"\s+type="([^"]+)"', source)
        resources = re.findall(r'(?m)^\[ext_resource\s+type="([^"]+)"\s+path="([^"]+)"', source)
        evidence = [f"node: {kind} {name}" for name, kind in nodes[:100]]
        evidence.extend(f"external resource: {kind}" for kind, _ in resources[:100])
        return [Finding(
            "game_engine", f"Godot scene: {record.path}",
            f"Detected {len(nodes)} scene node declaration(s) and {len(resources)} "
            "external resource reference(s).",
            confidence="CONFIRMED", evidence=evidence or [record.path], analyzer=self.name,
        )]

    def _unity_version(self, path: Path, record: FileRecord) -> list[Finding]:
        source, error = self._read_text(path, record)
        if error:
            return [error]
        match = re.search(r"(?m)^m_EditorVersion:\s*(\S+)", source)
        return [Finding(
            "game_engine", f"Unity editor version: {record.path}",
            "Unity editor version: " + (match.group(1) if match else "not resolved"),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _unity_packages(self, path: Path, record: FileRecord) -> list[Finding]:
        return self._json_project(path, record, forced_engine="Unity package manifest")

    def _json_project(self, path: Path, record: FileRecord, forced_engine: str | None = None) -> list[Finding]:
        try:
            data = json.loads(read_text_bounded(
                    path, 16 * 1024 * 1024,
                    expected_identity=record.analysis_identity,
                ))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [Finding(
                "game_engine", f"Game project JSON parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if not isinstance(data, dict):
            return []
        ext = record.extension
        engine = forced_engine or {
            ".uproject": "Unreal Engine project",
            ".uplugin": "Unreal Engine plugin",
            ".yyp": "GameMaker project",
            ".yy": "GameMaker resource",
        }.get(ext)
        if not engine:
            return []
        if ext in {".uproject", ".uplugin"}:
            modules = data.get("Modules", [])
            plugins = data.get("Plugins", [])
            detail = f"Engine association: {data.get('EngineAssociation', 'unspecified')}; "
            detail += f"{len(modules) if isinstance(modules, list) else 0} module(s), "
            detail += f"{len(plugins) if isinstance(plugins, list) else 0} plugin declaration(s)."
        elif ext == ".yyp":
            resources = data.get("resources", [])
            detail = f"GameMaker project; {len(resources) if isinstance(resources, list) else 0} resource reference(s)."
        elif ext == ".yy":
            detail = "GameMaker resource metadata is present."
        else:
            dependencies = data.get("dependencies", {})
            detail = f"Detected {len(dependencies) if isinstance(dependencies, dict) else 0} package declarations."
        return [Finding(
            "game_engine", f"{engine}: {record.path}", detail,
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _unity_source(self, path: Path, record: FileRecord) -> list[Finding]:
        source, error = self._read_text(path, record)
        if error:
            return [error]
        matches = [
            (label, number)
            for pattern, label in _UNITY_MARKERS
            for number, line in enumerate(source.splitlines(), 1)
            if re.search(pattern, line)
        ]
        if not matches:
            return []
        return [Finding(
            "game_engine", f"Unity script markers: {record.path}",
            "Detected: " + ", ".join(sorted({label for label, _ in matches})),
            confidence="CONFIRMED",
            evidence=[f"{record.path}:{line} ({label})" for label, line in matches[:100]],
            analyzer=self.name,
        )]

    def _unreal_source(self, path: Path, record: FileRecord) -> list[Finding]:
        source, error = self._read_text(path, record)
        if error:
            return [error]
        matches = [
            (label, number)
            for pattern, label in _UNREAL_MARKERS
            for number, line in enumerate(source.splitlines(), 1)
            if re.search(pattern, line)
        ]
        if not matches and not record.path.lower().endswith((".build.cs", ".target.cs")):
            return []
        return [Finding(
            "game_engine", f"Unreal Engine source markers: {record.path}",
            "Detected Unreal reflection/runtime markers: "
            + (", ".join(sorted({label for label, _ in matches})) or "build/target rule file"),
            confidence="CONFIRMED",
            evidence=[f"{record.path}:{line} ({label})" for label, line in matches[:100]]
            or [record.path],
            analyzer=self.name,
        )]

    def _script_markers(self, path: Path, record: FileRecord, engine: str, markers):
        source, error = self._read_text(path, record)
        if error:
            return [error]
        matches = [
            (label, number)
            for pattern, label in markers
            for number, line in enumerate(source.splitlines(), 1)
            if re.search(pattern, line)
        ]
        if not matches:
            return []
        return [Finding(
            "game_engine", f"{engine} script markers: {record.path}",
            "Detected: " + ", ".join(sorted({label for label, _ in matches})),
            confidence="CONFIRMED",
            evidence=[f"{record.path}:{line} ({label})" for label, line in matches[:100]],
            analyzer=self.name,
        )]

    def _roblox_xml(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            root = safe_xml_fromstring(read_bytes_bounded(
                path, 64 * 1024 * 1024, expected_identity=record.analysis_identity,
            ))
        except (OSError, ValueError, ET.ParseError) as exc:
            return [Finding(
                "game_engine", f"Roblox model parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        classes = {}
        for item in root.iter("Item"):
            kind = item.attrib.get("class", "Unknown")
            classes[kind] = classes.get(kind, 0) + 1
        return [Finding(
            "game_engine", f"Roblox project/model: {record.path}",
            "Detected instance classes: "
            + ", ".join(f"{kind}={count}" for kind, count in sorted(classes.items())[:30]),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _web_game_manifest(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            data = json.loads(read_text_bounded(
                    path, 16 * 1024 * 1024,
                    expected_identity=record.analysis_identity,
                ))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []
        deps = {}
        for group in ("dependencies", "devDependencies"):
            if isinstance(data.get(group), dict):
                deps.update(data[group])
        engines = [
            label for package, label in (
                ("phaser", "Phaser"), ("three", "Three.js"), ("babylonjs", "Babylon.js"),
                ("@babylonjs/core", "Babylon.js"), ("pixi.js", "PixiJS"),
                ("playcanvas", "PlayCanvas"), ("cocos-creator", "Cocos Creator"),
            ) if package in deps
        ]
        if not engines:
            return []
        return [Finding(
            "game_engine", f"Web game frameworks: {record.path}",
            "Detected: " + ", ".join(sorted(set(engines))),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _bevy_manifest(self, path: Path, record: FileRecord) -> list[Finding]:
        source, error = self._read_text(path, record)
        if error:
            return [error]
        if not re.search(r"(?m)^[ \t]*bevy\s*=", source):
            return []
        return [Finding(
            "game_engine", f"Bevy project dependency: {record.path}",
            "The Cargo manifest declares Bevy. Rust ECS component/system semantics are "
            "not inferred from this dependency declaration.",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]
