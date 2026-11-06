"""Graphics and compute shaders: stages, entry points, resource bindings and binaries.

Source shaders are read with comments blanked: GLSL (``#version``, extensions,
``layout(set, binding, location)``, push constants, compute workgroup sizes), HLSL
(``register(t0, space1)``, cbuffers, ``[numthreads]``, DXR ``[shader(...)]``, Unity and
Unreal ``#pragma`` entry points), WGSL (``@group/@binding``, ``@vertex/@fragment/
@compute``), Metal (``kernel/vertex/fragment`` functions, ``[[buffer(n)]]``), Godot
shaders and Unity ShaderLab (properties, sub-shaders, passes, render pipeline tags).
Compiled shaders are parsed from their headers: SPIR-V (version, generator, entry
points with execution models, descriptor bindings), DXBC/DXIL containers (shader kind
and model) and Metal libraries.

Findings: binding conflicts within a file, GLSL without ``#version``, GLSL ES fragment
shaders without a default float precision and compute workgroups beyond 1024
invocations. Per-file facts feed the project shader inventory.
"""
from __future__ import annotations

import re
import struct
from collections import defaultdict
from pathlib import Path, PurePosixPath

from ...core.source_utils import SourceBudgetExceeded, open_verified_binary, read_text_bounded
from ...intelligence import facts as code_facts
from ...models import FileRecord, Finding
from ..base import Analyzer

MAX_SHADER_BYTES = 4 * 1024 * 1024
MAX_SPIRV_WORDS = 2_000_000
_NON_NEWLINE = re.compile(r"[^\n]")
_C_NOISE = re.compile(r"//[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/)?")
_GLSL_STAGES = {
    ".vert": "vertex", ".frag": "fragment", ".geom": "geometry", ".tesc": "tessellation control",
    ".tese": "tessellation evaluation", ".comp": "compute", ".mesh": "mesh", ".task": "task", ".rgen": "ray generation",
    ".rint": "intersection", ".rahit": "any-hit", ".rchit": "closest-hit", ".rmiss": "miss", ".rcall": "callable",
}
_SOURCE_LANGUAGES = frozenset({"GLSL", "HLSL", "WGSL", "Metal Shading Language", "Godot Shader", "ShaderLab"})
_BINARY_SUFFIXES = (".spv", ".cso", ".dxbc", ".dxil", ".metallib")
_GLSL_VERSION = re.compile(r"(?m)^[ \t]*+#[ \t]*+version[ \t]++(\d{2,3}+)(?:[ \t]++(core|compatibility|es))?")
_GLSL_EXTENSION = re.compile(r"(?m)^[ \t]*+#[ \t]*+extension[ \t]++(\w{1,80}+)[ \t]*+:[ \t]*+(\w{1,20}+)")
_GLSL_STAGE_PRAGMA = re.compile(r"#pragma[ \t]++shader_stage[ \t]*+\([ \t]*+(\w{1,30}+)")
_GLSL_LAYOUT = re.compile(r"(?<![\w$])layout[ \t]*+\(([^()]{0,400}+)\)[ \t\r\n]*+((?:(?:readonly|writeonly|restrict|coherent|"
                          r"volatile|highp|mediump|lowp|flat|smooth|noperspective|centroid|patch)[ \t\r\n]++)*+)"
                          r"(uniform|buffer|in|out|shared|rayPayloadEXT|rayPayloadInEXT|hitAttributeEXT|"
                          r"callableDataEXT)\b")
_GLSL_PRECISION = re.compile(r"(?<![\w$])precision[ \t]++(?:lowp|mediump|highp)[ \t]++float[ \t]*+;")
_GLSL_MAIN = re.compile(r"(?<![\w$])void[ \t]++main[ \t]*+\(")
_HLSL_REGISTER = re.compile(
    r"(?<![\w$])(\w{1,60}+)(?:<[^<>;\n]{0,80}+>)?[ \t]++(\w{1,80}+)(?:\[[^\]\n]{0,20}+\])?[ \t]*+:[ \t]*+register[ \t]*+\("
    r"[ \t]*+([tbsu])(\d{1,4}+)[ \t]*+(?:,[ \t]*+space(\d{1,3}+))?[ \t]*+\)"
)
_HLSL_NUMTHREADS = re.compile(r"\[numthreads[ \t]*+\([ \t]*+(\d{1,5}+)[ \t]*+,[ \t]*+(\d{1,5}+)[ \t]*+,[ \t]*+(\d{1,5}+)[ \t]*+\)[ \t]*+\]"
                              r"[ \t\r\n]*+(?:\[[^\]\n]{0,100}+\][ \t\r\n]*+)*+\w{1,40}+[ \t]++(\w{1,80}+)[ \t]*+\(")
_HLSL_DXR = re.compile(r"\[shader[ \t]*+\([ \t]*+\"(\w{1,30}+)\"[ \t]*+\)[ \t]*+\][ \t\r\n]*+\w{1,40}+[ \t]++(\w{1,80}+)")
_HLSL_PRAGMA = re.compile(r"(?m)^[ \t]*+#pragma[ \t]++(vertex|fragment|geometry|hull|domain|surface|kernel)[ \t]++(\w{1,80}+)")
_HLSL_SEMANTIC_ENTRY = re.compile(r"(?<![\w$])\w{1,40}+[ \t]++(\w{1,80}+)[ \t]*+\([^()]{0,400}+\)[ \t\r\n]*+:[ \t]*+(SV_Target\d?|SV_Position|COLOR\d?)")
_WGSL_BINDING = re.compile(
    r"@(group|binding)[ \t]*+\([ \t]*+(\d{1,4}+)[ \t]*+\)[ \t\r\n]*+@(group|binding)[ \t]*+\([ \t]*+(\d{1,4}+)[ \t]*+\)"
    r"[ \t\r\n]*+var(?:[ \t]*+<[^<>;\n]{0,80}+>)?[ \t]++(\w{1,80}+)"
)
_WGSL_ENTRY = re.compile(r"@(vertex|fragment|compute)\b(?:[ \t\r\n]*+@\w{1,40}+(?:[ \t]*+\([^()\n]{0,80}+\))?)*+[ \t\r\n]*+fn[ \t]++(\w{1,80}+)")
_WGSL_WORKGROUP = re.compile(r"@workgroup_size[ \t]*+\(([^()\n]{1,80}+)\)")
_METAL_ENTRY = re.compile(r"(?<![\w$])(kernel|vertex|fragment)[ \t]++[\w<>:, ]{1,120}?[ \t]++(\w{1,80}+)[ \t]*+\(")
_METAL_BINDING = re.compile(r"(\w{1,80}+)[ \t]*+\[\[[ \t]*+(buffer|texture|sampler)[ \t]*+\([ \t]*+(\d{1,4}+)[ \t]*+\)")
_GODOT_TYPE = re.compile(r"(?<![\w$])shader_type[ \t]++(\w{1,30}+)")
_GODOT_FUNCTION = re.compile(r"(?<![\w$])void[ \t]++(vertex|fragment|light|start|process|sky|fog)[ \t]*+\(")
_SHADERLAB_NAME = re.compile(r"(?<![\w$])Shader[ \t]++\"([^\"\n]{1,200}+)\"")
_SHADERLAB_PROPERTY = re.compile(r"(?m)^[ \t]*+(?:\[[^\]\n]{0,80}+\][ \t]*+)*+(_\w{1,80}+)[ \t]*+\(")
_SHADERLAB_PIPELINE = re.compile(r"\"RenderPipeline\"[ \t]*+=[ \t]*+\"(\w{1,60}+)\"")
_UNIFORM = re.compile(r"(?<![\w$])uniform\b")
_INCLUDE = re.compile(r"(?m)^[ \t]*+#[ \t]*+include[ \t]++[\"<]([^\">\n]{1,200}+)[\">]")
_SPIRV_MODELS = {0: "vertex", 1: "tessellation control", 2: "tessellation evaluation", 3: "geometry", 4: "fragment",
                 5: "compute", 6: "kernel", 5267: "task (NV)", 5268: "mesh (NV)", 5313: "ray generation",
                 5314: "intersection", 5315: "any-hit", 5316: "closest-hit", 5317: "miss", 5318: "callable",
                 5364: "task", 5365: "mesh"}
_DXIL_KINDS = {0: "pixel", 1: "vertex", 2: "geometry", 3: "hull", 4: "domain", 5: "compute", 6: "library",
               7: "ray generation", 8: "intersection", 9: "any-hit", 10: "closest-hit", 11: "miss", 12: "callable",
               13: "mesh", 14: "amplification"}


def _blank(text: str) -> str:
    return _C_NOISE.sub(lambda match: _NON_NEWLINE.sub(" ", match.group()), text)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _declared_name(clean: str, start: int) -> str:
    """Name declared after a layout qualifier: the block name before ``{`` or the last
    identifier before ``;`` (``uniform writeonly image2D dst;`` -> ``dst``)."""
    window = clean[start:start + 400]
    stops = [index for index in (window.find(";"), window.find("{")) if index != -1]
    declaration = window[:min(stops)] if stops else window
    words = re.findall(r"[A-Za-z_]\w{0,80}+", re.sub(r"\[[^\]]{0,40}+\]", " ", declaration))
    if not words:
        return "?"
    return words[0] if stops and min(stops) == window.find("{") else words[-1]


def _layout_fields(text: str) -> dict[str, str]:
    fields = {}
    for part in text.split(","):
        key, _, value = part.partition("=")
        if key.strip():
            fields[key.strip()] = value.strip()
    return fields


def _shader_kind(record: FileRecord) -> str | None:
    lower = PurePosixPath(record.path.replace("\\", "/")).name.lower()
    if record.language in _SOURCE_LANGUAGES:
        return "source"
    if lower.endswith(".compute"):
        return "source"
    if lower.endswith(_BINARY_SUFFIXES):
        return "binary"
    if lower.endswith((".shadergraph", ".shadersubgraph")):
        return "graph"
    return None


class ShaderAnalyzer(Analyzer):
    name = "shaders"
    version = "1.0.0"
    description = ("Shader stages, entry points and resource bindings (GLSL, HLSL, WGSL, Metal, Godot, ShaderLab) and "
                   "compiled shaders (SPIR-V, DXBC/DXIL, metallib).")
    domains = ("graphics_shaders",)

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and _shader_kind(record) is not None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        kind = _shader_kind(record)
        try:
            if kind == "binary":
                return self._binary(path, record)
            if record.size_bytes > MAX_SHADER_BYTES:
                return []
            text = read_text_bounded(path, MAX_SHADER_BYTES, errors="replace", expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded, struct.error):
            return []
        if kind == "graph":
            nodes = text.count("\"UnityEditor.ShaderGraph.")
            code_facts.emit_fact("shader", "Unity Shader Graph", stage="graph", entries=0, bindings=0)
            return [self._finding(record, "Unity Shader Graph", f"Shader graph with about {nodes:,} serialized node(s).")]
        return self._source(record, text)

    def _finding(self, record, title, detail, *, lines=(), severity="INFO", confidence="CONFIRMED",
                 recommendation=None) -> Finding:
        evidence = [f"{record.path}:{line}" for line in sorted(set(lines))[:25]] or [record.path]
        return Finding("graphics_shaders", f"{title}: {record.path}", detail, confidence=confidence,
                       evidence=evidence, analyzer=self.name, severity=severity, recommendation=recommendation)

    # -- sources ------------------------------------------------------------------------
    def _source(self, record: FileRecord, text: str) -> list[Finding]:
        clean = _blank(text)
        lower = record.path.lower()
        language = "HLSL" if lower.endswith(".compute") else record.language
        stages: list[str] = []
        entries: list[str] = []
        # (namespace, slot) -> {resource names}; namespace distinguishes register classes/sets.
        bindings: dict[tuple, set[str]] = defaultdict(set)
        binding_lines: dict[tuple, int] = {}
        details: list[str] = []
        issues: list[Finding] = []

        def bind(key: tuple, name: str, offset: int) -> None:
            bindings[key].add(name)
            binding_lines.setdefault(key, _line(clean, offset))

        if language == "GLSL":
            version = _GLSL_VERSION.search(text)
            stage = _GLSL_STAGES.get(PurePosixPath(lower).suffix) or (
                (_GLSL_STAGE_PRAGMA.search(clean) or [None, ""])[1] or "")
            if stage:
                stages.append(stage)
            if _GLSL_MAIN.search(clean):
                entries.append("main")
            extensions = [name for name, _ in _GLSL_EXTENSION.findall(text)]
            workgroup = None
            for layout in _GLSL_LAYOUT.finditer(clean):
                fields, storage = _layout_fields(layout.group(1)), layout.group(3)
                if "binding" in fields:
                    bind(("set", fields.get("set", "0"), fields["binding"]), _declared_name(clean, layout.end()),
                         layout.start())
                if storage == "in" and any(key.startswith("local_size") for key in fields):
                    sizes = [int(fields.get(axis, "1")) if fields.get(axis, "1").isdigit() else 1
                             for axis in ("local_size_x", "local_size_y", "local_size_z")]
                    workgroup = sizes
            if version:
                details.append(f"#version {version.group(1)}{' ' + version.group(2) if version.group(2) else ''}")
            if extensions:
                details.append("extensions " + ", ".join(extensions[:8]))
            if workgroup:
                details.append("workgroup " + "x".join(map(str, workgroup)))
            is_include = not entries and lower.endswith(".glsl")
            if not version and not is_include and entries:
                issues.append(self._finding(
                    record, "GLSL shader without #version",
                    "Without a #version directive drivers compile the shader as GLSL 1.10, which rejects most modern "
                    "syntax or behaves differently between vendors.", severity="LOW",
                    recommendation="Start every GLSL shader with an explicit #version directive.",
                ))
            if version and version.group(2) == "es" and stage == "fragment" and not _GLSL_PRECISION.search(clean):
                issues.append(self._finding(
                    record, "GLSL ES fragment shader without default float precision",
                    "GLSL ES fragment shaders have no default float precision; declarations without a precision "
                    "qualifier fail to compile.", lines=[_line(text, version.start())], severity="LOW",
                    recommendation="Add `precision mediump float;` (or highp) after #version.",
                ))
            if workgroup and workgroup[0] * workgroup[1] * workgroup[2] > 1024:
                issues.append(self._finding(
                    record, "Compute workgroup exceeds common limits",
                    f"local_size {'x'.join(map(str, workgroup))} = {workgroup[0] * workgroup[1] * workgroup[2]:,} "
                    "invocations; many GPUs support at most 1,024 per workgroup.", severity="LOW",
                ))
        elif language == "HLSL":
            for match in _HLSL_REGISTER.finditer(clean):
                kind, name, register, index, space = match.groups()
                bind(("register", register, index, space or "0"), name, match.start())
            for match in _HLSL_NUMTHREADS.finditer(clean):
                x, y, z, name = match.groups()
                stages.append("compute")
                entries.append(name)
                if int(x) * int(y) * int(z) > 1024:
                    issues.append(self._finding(
                        record, "Compute thread group exceeds limits",
                        f"[numthreads({x},{y},{z})] = {int(x) * int(y) * int(z):,} threads; Direct3D allows at most 1,024.",
                        lines=[_line(clean, match.start())], severity="LOW",
                    ))
            for match in _HLSL_DXR.finditer(clean):
                stages.append(match.group(1))
                entries.append(match.group(2))
            for match in _HLSL_PRAGMA.finditer(clean):
                stages.append({"kernel": "compute"}.get(match.group(1), match.group(1)))
                entries.append(match.group(2))
            for match in _HLSL_SEMANTIC_ENTRY.finditer(clean):
                if match.group(1) not in entries:
                    entries.append(match.group(1))
                    stages.append("pixel" if match.group(2).startswith(("SV_Target", "COLOR")) else "vertex")
            cbuffers = len(re.findall(r"(?<![\w$])cbuffer[ \t]++\w", clean))
            if cbuffers:
                details.append(f"{cbuffers} constant buffer(s)")
        elif language == "WGSL":
            for match in _WGSL_BINDING.finditer(clean):
                first, first_value, second, second_value, name = match.groups()
                values = {first: first_value, second: second_value}
                bind(("group", values.get("group", "0"), values.get("binding", "0")), name, match.start())
            for match in _WGSL_ENTRY.finditer(clean):
                stages.append(match.group(1))
                entries.append(match.group(2))
            for match in _WGSL_WORKGROUP.finditer(clean):
                details.append(f"workgroup_size({match.group(1).strip()})")
        elif language == "Metal Shading Language":
            entry_spans = []
            for match in _METAL_ENTRY.finditer(clean):
                stages.append(match.group(1))
                entries.append(match.group(2))
                entry_spans.append((match.start(), match.group(2)))
            for match in _METAL_BINDING.finditer(clean):
                owner = next((name for start, name in reversed(entry_spans) if start < match.start()), "")
                bind((owner, match.group(2), match.group(3)), match.group(1), match.start())
        elif language == "Godot Shader":
            shader_type = _GODOT_TYPE.search(clean)
            stages.extend(_GODOT_FUNCTION.findall(clean))
            entries.extend(stages)
            details.append(f"shader_type {shader_type.group(1) if shader_type else 'unknown'}")
            details.append(f"{len(_UNIFORM.findall(clean))} uniform(s)")
        elif language == "ShaderLab":
            name = _SHADERLAB_NAME.search(text)
            properties_block = re.search(r"(?<![\w$])Properties[ \t\r\n]*+\{", clean)
            properties = 0
            if properties_block:
                end = clean.find("\n}", properties_block.end())
                end = clean.find("}", properties_block.end()) if end == -1 else end
                properties = len(_SHADERLAB_PROPERTY.findall(clean, properties_block.end(), end if end != -1 else len(clean)))
            pipeline = _SHADERLAB_PIPELINE.search(text)
            sub_shaders = len(re.findall(r"(?<![\w$])SubShader\b", clean))
            passes = len(re.findall(r"(?<![\w$])Pass[ \t\r\n]*+\{", clean))
            for match in _HLSL_PRAGMA.finditer(clean):
                stages.append({"kernel": "compute"}.get(match.group(1), match.group(1)))
                entries.append(match.group(2))
            details.append(f"Unity shader \"{name.group(1) if name else '?'}\"")
            details.append(f"{properties} propert{'y' if properties == 1 else 'ies'}, {sub_shaders} sub-shader(s), {passes} pass(es)")
            details.append(f"render pipeline {pipeline.group(1) if pipeline else 'built-in'}")
        includes = _INCLUDE.findall(text)
        if includes:
            details.append(f"{len(includes)} include(s)")
        conflicts = {key: names for key, names in bindings.items() if len(names) > 1}
        stage_names = sorted(set(stages))
        code_facts.emit_fact("shader", language, stage=",".join(stage_names) or "library", entries=len(entries),
                             bindings=len(bindings))
        summary = [f"{language} shader"]
        if stage_names:
            summary.append("stages " + ", ".join(stage_names))
        if entries:
            summary.append("entry points " + ", ".join(list(dict.fromkeys(entries))[:10]))
        if bindings:
            summary.append(f"{len(bindings)} resource binding(s)")
        findings = [self._finding(record, "Shader", "; ".join(summary + details) + ".")]
        if conflicts:
            described = "; ".join(f"{'/'.join(str(part) for part in key if part)}: {', '.join(sorted(names))}"
                                  for key, names in list(conflicts.items())[:10])
            findings.append(self._finding(
                record, "Conflicting resource bindings",
                f"Different resources share a binding slot ({described}). Unless they are never used together, one "
                "overwrites the other in the descriptor set or register.",
                lines=[binding_lines[key] for key in conflicts], severity="LOW", confidence="INFERRED",
                recommendation="Give every resource used by a pipeline its own binding.",
            ))
        return findings + issues

    # -- binaries -----------------------------------------------------------------------
    def _binary(self, path: Path, record: FileRecord) -> list[Finding]:
        with open_verified_binary(path, record.analysis_identity) as stream:
            head = stream.read(64)
            if len(head) >= 20 and head[:4] in (b"\x03\x02\x23\x07", b"\x07\x23\x02\x03"):
                stream.seek(0)
                data = stream.read(min(record.size_bytes, MAX_SPIRV_WORDS * 4))
                return self._spirv(record, data)
            if head[:4] == b"DXBC":
                stream.seek(0)
                return self._dxbc(record, stream.read(min(record.size_bytes, MAX_SHADER_BYTES)))
            if head[:4] == b"MTLB":
                code_facts.emit_fact("shader", "Metal library", stage="library", entries=0, bindings=0)
                return [self._finding(record, "Compiled Metal library", f"metallib, {record.size_bytes:,} bytes.")]
        return []

    def _spirv(self, record: FileRecord, data: bytes) -> list[Finding]:
        endian = "<" if data[:4] == b"\x03\x02\x23\x07" else ">"
        words = len(data) // 4
        _, version, generator, bound, _ = struct.unpack_from(endian + "IIIII", data)
        major, minor = (version >> 16) & 0xFF, (version >> 8) & 0xFF
        entries, bindings, sets = [], 0, set()
        position = 5
        while position < words and position < MAX_SPIRV_WORDS:
            word = struct.unpack_from(endian + "I", data, position * 4)[0]
            count, opcode = word >> 16, word & 0xFFFF
            if count == 0:
                break
            if opcode == 15 and count >= 4:  # OpEntryPoint
                model = struct.unpack_from(endian + "I", data, (position + 1) * 4)[0]
                raw = data[(position + 3) * 4:(position + count) * 4]
                name = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
                entries.append(f"{name} ({_SPIRV_MODELS.get(model, model)})")
            elif opcode == 71 and count >= 4:  # OpDecorate
                decoration, value = struct.unpack_from(endian + "II", data, (position + 2) * 4)
                if decoration == 33:
                    bindings += 1
                elif decoration == 34:
                    sets.add(value)
            elif opcode in (54, 5):  # OpFunction / OpName: past the declarations that matter
                if opcode == 54:
                    break
            position += count
        code_facts.emit_fact("shader", "SPIR-V", stage=",".join(sorted({entry.rsplit("(", 1)[-1].rstrip(")")
                                                                       for entry in entries})) or "unknown",
                             entries=len(entries), bindings=bindings)
        return [self._finding(
            record, "SPIR-V module",
            f"SPIR-V {major}.{minor}, generator {generator >> 16}:{generator & 0xFFFF}, id bound {bound:,}; "
            f"{len(entries)} entry point(s): {', '.join(entries[:10]) or 'none'}; {bindings} binding decoration(s) in "
            f"{len(sets)} descriptor set(s).",
        )]

    def _dxbc(self, record: FileRecord, data: bytes) -> list[Finding]:
        if len(data) < 32:
            return []
        count = struct.unpack_from("<I", data, 28)[0]
        chunks = []
        for index in range(min(count, 64)):
            offset_position = 32 + index * 4
            if offset_position + 4 > len(data):
                break
            offset = struct.unpack_from("<I", data, offset_position)[0]
            if offset + 8 <= len(data):
                chunks.append((data[offset:offset + 4].decode("ascii", "replace"), offset))
        kind = model = ""
        for name, offset in chunks:
            if name in {"DXIL", "SHEX", "SHDR"} and offset + 12 <= len(data):
                program = struct.unpack_from("<I", data, offset + 8)[0]
                shader_kind = program >> 16
                kind = _DXIL_KINDS.get(shader_kind, str(shader_kind)) if name == "DXIL" else {
                    0: "pixel", 1: "vertex", 2: "geometry", 3: "hull", 4: "domain", 5: "compute"}.get(shader_kind, "")
                model = f"{(program >> 4) & 0xF}.{program & 0xF}"
                break
        code_facts.emit_fact("shader", "DXBC/DXIL", stage=kind or "unknown", entries=1 if kind else 0, bindings=0)
        return [self._finding(
            record, "Compiled Direct3D shader",
            f"DXBC container with {len(chunks)} chunk(s) ({', '.join(name for name, _ in chunks[:12])})"
            + (f"; {kind} shader model {model}" if kind else "") + ".",
        )]
