"""tools/wheel_architecture.py: the native modules a cross-compiled wheel must hold."""
from __future__ import annotations

import importlib.util
import platform
import struct
import zipfile
from pathlib import Path

import pytest

import project_discovery
from project_discovery.engine import native

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("wheel_architecture", ROOT / "tools" / "wheel_architecture.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


def _elf(machine: int) -> bytes:
    return b"\x7fELF\x02\x01" + bytes(12) + struct.pack("<H", machine) + bytes(40)


def _pe(machine: int) -> bytes:
    header = bytearray(0x80)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", header, 0x44, machine)
    return bytes(header)


def _macho(cpu: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + bytes(24)


def _universal(*cpus: int) -> bytes:
    return b"\xca\xfe\xba\xbe" + struct.pack(">I", len(cpus)) + b"".join(
        struct.pack(">IIIII", cpu, 0, 0, 0, 0) for cpu in cpus)


def test_executable_headers_name_their_architecture():
    assert tool.architectures(_elf(0x3E)) == {"x86_64"} and tool.architectures(_elf(0xB7)) == {"arm64"}
    assert tool.architectures(_pe(0x8664)) == {"x86_64"} and tool.architectures(_pe(0xAA64)) == {"arm64"}
    assert tool.architectures(_macho(0x0100000C)) == {"arm64"}
    assert tool.architectures(_universal(0x01000007, 0x0100000C)) == {"x86_64", "arm64"}
    assert tool.architectures(b"not an executable") == set() and tool.architectures(b"MZ") == set()


def _wheel(path: Path, members: dict[str, bytes]) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return str(path)


def test_a_wheel_must_hold_every_native_module_for_the_expected_architecture(tmp_path: Path, capsys):
    arm = {f"project_discovery/{module}.cpython-313-aarch64-linux-gnu.so": _elf(0xB7) for module in tool.MODULES}
    wheel = _wheel(tmp_path / "arm.whl", {**arm, "project_discovery/__init__.py": b""})
    assert tool.check(wheel, "aarch64") == [] and tool.main([wheel, "--expect", "ARM64"]) == 0
    assert "built for arm64" in capsys.readouterr().out
    assert tool.check(wheel, "x86_64") == [f"{module} is built for arm64, not x86_64" for module in sorted(tool.MODULES)]
    partial = _wheel(tmp_path / "partial.whl", {name: data for name, data in arm.items() if "_walker" not in name})
    assert tool.check(partial, "arm64") == ["_walker is missing (its build failed or was skipped)"]
    assert tool.main([partial, "--expect", "arm64"]) == 1
    universal = _wheel(tmp_path / "universal.whl", {f"project_discovery/{module}.cpython-313-darwin.so":
                                                    _universal(0x01000007, 0x0100000C) for module in tool.MODULES})
    assert tool.check(universal, "x86_64") == tool.check(universal, "arm64") == []


@pytest.mark.skipif(not (native.native_available() and native.signature_backend_available()
                         and native.rust_walker_available()), reason="the native modules are not all built")
def test_the_modules_built_here_are_for_this_machine(tmp_path: Path):
    package = Path(project_discovery.__file__).parent
    built = {f"project_discovery/{path.name}": path.read_bytes()
             for path in package.iterdir() if path.suffix in {".so", ".pyd"} and path.name.startswith("_")}
    machine = tool.ALIASES.get(platform.machine().lower())
    if machine is None:
        pytest.skip(f"no expectation for {platform.machine()}")
    assert tool.check(_wheel(tmp_path / "here.whl", built), machine) == []
