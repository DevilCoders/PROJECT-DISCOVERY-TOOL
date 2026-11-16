"""Check that a wheel holds every native module, built for the expected architecture.

    python tools/wheel_architecture.py wheelhouse/*.whl --expect arm64

The C, C++ and Rust extensions are optional builds, so a cross-compile that fails for one of
them still produces a wheel, without it. This reads each extension's executable header (ELF,
Mach-O, PE) and fails when a module is missing or built for another architecture.
"""
from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from pathlib import PurePosixPath

MODULES = ("_native", "_native_cpp", "_walker")
ALIASES = {"x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}
_ELF = {0x03: "x86", 0x28: "arm", 0x3E: "x86_64", 0xB7: "arm64"}
_MACHO = {7: "x86", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "arm64"}
_PE = {0x014C: "x86", 0x01C4: "arm", 0x8664: "x86_64", 0xAA64: "arm64"}


def architectures(data: bytes) -> set[str]:
    """The architectures an executable image is built for (several for a universal Mach-O)."""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        (machine,) = struct.unpack_from("<H" if data[5] == 1 else ">H", data, 18)
        return {_ELF.get(machine, f"elf:{machine:#x}")}
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") and len(data) >= 8:  # Mach-O, little-endian
        (cpu,) = struct.unpack_from("<I", data, 4)
        return {_MACHO.get(cpu, f"mach-o:{cpu:#x}")}
    if data[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8:  # universal Mach-O: big-endian fat_arch entries
        (count,) = struct.unpack_from(">I", data, 4)
        found = set()
        for index in range(min(count, 16)):
            if len(data) >= 12 + 20 * index:
                (cpu,) = struct.unpack_from(">I", data, 8 + 20 * index)
                found.add(_MACHO.get(cpu, f"mach-o:{cpu:#x}"))
        return found
    if data[:2] == b"MZ" and len(data) >= 0x40:
        (offset,) = struct.unpack_from("<I", data, 0x3C)
        if data[offset:offset + 4] == b"PE\0\0" and len(data) >= offset + 6:
            (machine,) = struct.unpack_from("<H", data, offset + 4)
            return {_PE.get(machine, f"pe:{machine:#x}")}
    return set()


def check(wheel: str, expected: str) -> list[str]:
    """What is wrong with the wheel's native modules: missing, or not built for ``expected``."""
    want = ALIASES[expected.lower()]
    found: dict[str, set[str]] = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            path = PurePosixPath(name)
            if path.suffix in {".so", ".pyd"} and path.parent.name == "project_discovery":
                found[path.name.split(".", 1)[0]] = architectures(archive.read(name))
    problems = [f"{module} is missing (its build failed or was skipped)" for module in MODULES if module not in found]
    problems += [f"{module} is built for {', '.join(sorted(arches)) or 'an unknown format'}, not {want}"
                 for module, arches in sorted(found.items()) if want not in arches]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a wheel's native modules and their architecture.")
    parser.add_argument("wheels", nargs="+")
    parser.add_argument("--expect", required=True, choices=sorted(ALIASES, key=str.lower) + ["ARM64", "AMD64"])
    arguments = parser.parse_args(argv)
    failed = False
    for wheel in arguments.wheels:
        problems = check(wheel, arguments.expect)
        print(f"{wheel}: " + ("; ".join(problems) if problems else
                              f"{', '.join(MODULES)} built for {ALIASES[arguments.expect.lower()]}"))
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
