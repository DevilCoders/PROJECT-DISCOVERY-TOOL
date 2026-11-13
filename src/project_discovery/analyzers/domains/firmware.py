"""Firmware images, binary metadata and firmware build systems.

Binary formats are identified by their headers, read through bounded verified streams:

* **ELF** (executables, shared objects, kernel modules, bare-metal firmware): class,
  byte order, machine, type, entry point, load segments, stripped/debug state, build ID,
  compiler notes and, for Linux binaries, hardening (NX stack, PIE, RELRO, stack
  protector, FORTIFY, RPATH, writable-and-executable segments).
* **Intel HEX** and **Motorola S-record**: address ranges, data size, entry point and
  record checksums. **UF2**: block count, family IDs (RP2040, nRF52, SAMD, ESP32...)
  and target ranges.
* **Device tree blobs** (and FIT images), **U-Boot uImage**, **Android boot images**,
  **ESP32 application images** (with the embedded app descriptor), SquashFS, UBI, JFFS2,
  cramfs, ext2/3/4, TRX and compressed blobs; raw images are checked for a Cortex-M
  vector table and their entropy is measured. Version strings of well-known components
  (U-Boot, Linux, BusyBox, OpenSSL, FreeRTOS, Zephyr, ESP-IDF, Dropbear) are listed.

Firmware build inputs: Yocto/BitBake recipes and configuration (``debug-tweaks`` and
empty root passwords), Buildroot defconfigs, OpenWrt feeds and ESP-IDF partition tables.
"""
from __future__ import annotations

import math
import re
import struct
from collections import Counter
from pathlib import Path, PurePosixPath

from ...core.limits import AnalyzerLimits, over_limit
from ...core.source_utils import SourceBudgetExceeded, open_verified_binary, read_text_bounded
from ...intelligence import facts as code_facts
from ...inventory.signatures import family_of
from ...models import FileRecord, Finding
from ..base import Analyzer

MAX_HEADER_BYTES = 1024 * 1024
MAX_TABLE_BYTES = 4 * 1024 * 1024
MAX_TEXT_IMAGE_BYTES = 64 * 1024 * 1024
MAX_STRING_SCAN_BYTES = 8 * 1024 * 1024
MAX_UF2_BLOCKS = 65_536
_ELF_MACHINES = {
    2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S/390", 40: "ARM", 42: "SuperH",
    43: "SPARCv9", 50: "IA-64", 62: "x86-64", 83: "AVR", 92: "OpenRISC", 94: "Xtensa", 105: "MSP430",
    164: "Hexagon", 183: "AArch64", 190: "CUDA", 243: "RISC-V", 247: "BPF", 258: "LoongArch",
}
_ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump"}
_BARE_METAL = frozenset({"ARM", "RISC-V", "Xtensa", "AVR", "MSP430", "AArch64"})
_UF2_FAMILIES = {
    0xE48BFF56: "RP2040", 0xE48BFF57: "RP2350 (absolute)", 0xE48BFF59: "RP2350 ARM secure",
    0xE48BFF5A: "RP2350 RISC-V", 0xE48BFF5B: "RP2350 ARM non-secure", 0xADA52840: "nRF52840",
    0x1B57745F: "nRF52", 0x621E937A: "nRF52833", 0x68ED2B88: "SAMD21", 0x55114460: "SAMD51",
    0x57755A57: "STM32F4", 0x5EE21072: "STM32F1", 0x6B846188: "STM32F3", 0x53B80F00: "STM32F7",
    0x6DB66082: "STM32H7", 0x00FF6919: "STM32L4", 0xBFDD4EEE: "ESP32-S2", 0xC47E5767: "ESP32-S3",
    0xD42BA06C: "ESP32-C3", 0x2B88D29C: "ESP32-C2", 0x332726F6: "ESP32-H2", 0x540DDF62: "ESP32-C6",
    0x1C5F21B0: "ESP32", 0x16573617: "ATmega32", 0x4FB2D5BD: "i.MX RT10xx", 0x2ABC77EC: "LPC55",
}
_UIMAGE_OS = {1: "OpenBSD", 2: "NetBSD", 3: "FreeBSD", 5: "Linux", 17: "U-Boot", 20: "RTEMS", 23: "OpenRTOS",
              25: "TEE", 26: "OpenSBI", 27: "EFI"}
_UIMAGE_ARCH = {1: "Alpha", 2: "ARM", 3: "x86", 5: "MIPS", 6: "MIPS64", 7: "PowerPC", 15: "SuperH", 20: "AVR32",
                21: "Blackfin", 22: "AArch64", 25: "Xtensa", 26: "RISC-V", 27: "ARC", 28: "x86-64"}
_UIMAGE_TYPE = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi-file", 5: "firmware", 6: "script",
                7: "filesystem", 8: "flattened device tree", 9: "Kirkwood boot", 10: "U-Boot environment"}
_UIMAGE_COMPRESSION = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
_SQUASHFS_COMPRESSION = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
_COMPONENT_STRINGS = (
    ("U-Boot", re.compile(rb"U-Boot (\d{4}\.\d{2}(?:[-.][\w.+-]{1,24}+)?)")),
    ("Linux kernel", re.compile(rb"Linux version (\d{1,2}\.\d{1,3}\.\d{1,4}[\w.+-]{0,40}+)")),
    ("BusyBox", re.compile(rb"BusyBox v(\d{1,2}\.\d{1,3}\.\d{1,3})")),
    ("OpenSSL", re.compile(rb"OpenSSL (\d\.\d{1,2}\.\d{1,2}[a-z]?)")),
    ("FreeRTOS", re.compile(rb"FreeRTOS(?: Kernel)? V(\d{1,2}\.\d{1,2}\.\d{1,2})")),
    ("Zephyr", re.compile(rb"Zephyr OS (?:build )?v?(\d{1,2}\.\d{1,2}\.\d{1,2})")),
    ("ESP-IDF", re.compile(rb"(?:ESP-IDF |IDF_VER=?)v?(\d\.\d{1,2}(?:\.\d{1,2})?(?:-[\w.]{1,20}+)?)")),
    ("Dropbear", re.compile(rb"dropbear_(\d{4}\.\d{1,3})")),
    ("mbed TLS", re.compile(rb"[Mm]bed ?TLS (\d\.\d{1,2}\.\d{1,2})")),
    ("lwIP", re.compile(rb"lwIP/(\d\.\d{1,2}\.\d{1,2})")),
)
_COMPONENT_HINT = re.compile(rb"U-Boot |Linux version |BusyBox v|OpenSSL \d|FreeRTOS|Zephyr OS|ESP-IDF|IDF_VER|"
                             rb"dropbear_|bed ?TLS |lwIP/")
_ENTROPY_SAMPLE = 64 * 1024
# Containers handled elsewhere (archives, media, documents, models, datasets): not firmware
# even as .bin, such as a pytorch_model.bin.
_NOT_FIRMWARE_TYPES = (
    "archive/", "image/", "audio/", "video/", "document/", "font/", "database/", "dataset/", "ml-model/",
    "data/", "vcs/", "crypto/", "3d-model/", "game-asset/", "bytecode/", "package/", "email/", "core-dump/",
    "library/static",
)
_BINARY_EXTENSIONS = frozenset({
    ".elf", ".axf", ".bin", ".img", ".fw", ".rom", ".dtb", ".dtbo", ".itb", ".uimage", ".ub", ".trx", ".chk",
    ".ota", ".squashfs", ".sqsh", ".ubi", ".jffs2", ".cramfs", ".ext4", ".ext2", ".uf2", ".hex", ".ihex", ".ihx",
    ".srec", ".s19", ".s28", ".s37", ".mot",
})
_YOCTO_SETTING = re.compile(r"(?m)^[ \t]*+([A-Z][A-Z0-9_]{1,60}+)(?::[\w-]{1,40}+)?[ \t]*+(?:\?\?=|\?=|:=|\+=|=\+|\.=|=)"
                            r"[ \t]*+\"([^\"\r\n]{0,2000}+)\"")
_BR2_SETTING = re.compile(r"(?m)^(BR2_[A-Z0-9_]{1,120}+)=([^\r\n]{0,300}+)")
_FEED = re.compile(r"(?m)^[ \t]*+src-(\w{2,10}+)[ \t]++(\S{1,80}+)[ \t]++(\S{1,300}+)")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(count / length * math.log2(count / length) for count in counts.values())


def _ranges(spans: list[tuple[int, int]], limit: int = 8) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged[:limit]]


def _describe_ranges(spans: list[tuple[int, int]]) -> str:
    return ", ".join(f"{start:#010x}-{end - 1:#010x}" for start, end in spans) or "none"


def _kind(record: FileRecord) -> str | None:
    posix = record.path.replace("\\", "/")
    name = PurePosixPath(posix).name
    lower = name.lower()
    suffix = PurePosixPath(lower).suffix
    # Every ELF and MZ (PE, DOS, EFI) file, and firmware and filesystem images by signature.
    if family_of(record.file_type) in ("elf", "mz") or suffix == ".efi":
        return "binary"
    if record.file_type.startswith(("firmware/", "filesystem/")) or (record.signature or "").startswith("firmware/"):
        return "binary"
    if suffix in _BINARY_EXTENSIONS and not record.file_type.startswith(_NOT_FIRMWARE_TYPES):
        return "binary"
    # mkimage and kernel builds name images without an extension (uImage, zImage, Image);
    # _binary identifies them by their magic.
    if lower in {"uimage", "zimage", "bzimage", "image", "fitimage", "vmlinuz"} and record.file_type.startswith("binary"):
        return "binary"
    if lower in {"partitions.csv", "partition_table.csv"} or (lower.startswith("partitions") and suffix == ".csv"):
        return "partitions"
    if suffix in {".bb", ".bbappend", ".bbclass"}:
        return "yocto_recipe"
    if lower in {"local.conf", "bblayers.conf", "layer.conf", "auto.conf", "site.conf"} and "/conf/" in f"/{posix}":
        return "yocto_conf"
    if lower.endswith("_defconfig") or lower == ".config" and "buildroot" in posix.lower():
        return "defconfig"
    if lower in {"feeds.conf", "feeds.conf.default"}:
        return "openwrt_feeds"
    return None


class FirmwareAnalyzer(Analyzer):
    name = "firmware"
    limits = AnalyzerLimits(
        MAX_TEXT_IMAGE_BYTES,
        "sampled",
        {"header_sample_bytes": MAX_HEADER_BYTES, "table_bytes": MAX_TABLE_BYTES, "string_scan_bytes": MAX_STRING_SCAN_BYTES, "uf2_blocks": MAX_UF2_BLOCKS},
        outcome="Partial header results; an over-budget build file is skipped and the limit recorded",
    )
    version = "1.0.0"
    description = ("Firmware images and binaries (ELF, HEX, S-record, UF2, DTB/FIT, uImage, Android boot, ESP32, "
                   "filesystems) and firmware build systems (Yocto, Buildroot, OpenWrt, ESP-IDF partitions).")
    domains = ("firmware",)

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and record.content_skipped_reason is None and _kind(record) is not None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        kind = _kind(record)
        try:
            if kind == "binary":
                return self._binary(path, record)
            if over_limit(record.size_bytes, MAX_TABLE_BYTES):
                return []
            text = read_text_bounded(path, MAX_TABLE_BYTES, errors="replace",
                                     expected_identity=record.analysis_identity)
        except (OSError, SourceBudgetExceeded, struct.error):
            return []
        return getattr(self, f"_{kind}")(record, text)

    def _finding(self, record: FileRecord, title: str, detail: str, *, severity: str = "INFO",
                 confidence: str = "CONFIRMED", recommendation: str | None = None) -> Finding:
        return Finding("firmware", f"{title}: {record.path}", detail, confidence=confidence,
                       evidence=[record.path], analyzer=self.name, severity=severity,
                       recommendation=recommendation)

    # -- binary dispatch -------------------------------------------------------------
    def _binary(self, path: Path, record: FileRecord) -> list[Finding]:
        lower = record.path.lower()
        with open_verified_binary(path, record.analysis_identity) as stream:
            head = stream.read(4096)
            if head.startswith(b"\x7fELF"):
                return self._elf(stream, record, head)
            # By name, or by the content signature the inventory verified (any name).
            hex_records = lower.endswith((".hex", ".ihex", ".ihx")) or record.signature == "firmware/intel-hex"
            if hex_records and head.lstrip()[:1] == b":":
                return self._intel_hex(stream, record, head)
            s_records = lower.endswith((".srec", ".s19", ".s28", ".s37", ".mot")) or record.signature == "firmware/srec"
            if s_records and head.lstrip()[:1] == b"S":
                return self._srecord(stream, record, head)
            if len(head) >= 512 and struct.unpack_from("<II", head, 0) == (0x0A324655, 0x9E5D5157):
                return self._uf2(stream, record, head)
            if head.startswith(b"MZ"):
                return self._pe(stream, record, head)
            stream.seek(0)
            sample = stream.read(MAX_STRING_SCAN_BYTES)
        return self._image(record, sample)

    # -- ELF ----------------------------------------------------------------------------
    def _elf(self, stream, record: FileRecord, head: bytes) -> list[Finding]:
        if len(head) < 52 or head[4] not in (1, 2) or head[5] not in (1, 2):
            return []
        is64, endian = head[4] == 2, "<" if head[5] == 1 else ">"
        if is64:
            if len(head) < 64:
                return []
            (e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack_from(endian + "HHIQQQIHHHHHH", head, 16)
        else:
            (e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum,
             e_shstrndx) = struct.unpack_from(endian + "HHIIIIIHHHHHH", head, 16)
        machine = _ELF_MACHINES.get(e_machine, f"machine {e_machine}")
        kind = _ELF_TYPES.get(e_type, f"type {e_type}")

        def read(offset: int, size: int) -> bytes:
            if offset < 0 or size <= 0 or offset >= record.size_bytes:
                return b""
            stream.seek(offset)
            return stream.read(min(size, MAX_TABLE_BYTES))

        segments = []
        if e_phoff and 0 < e_phentsize <= 128:
            table = read(e_phoff, min(e_phnum, 512) * e_phentsize)
            for index in range(len(table) // e_phentsize):
                entry = table[index * e_phentsize:(index + 1) * e_phentsize]
                if is64 and len(entry) >= 56:
                    p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(endian + "IIQQQQQQ", entry)
                elif not is64 and len(entry) >= 32:
                    p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(endian + "IIIIIIII", entry)
                else:
                    continue
                segments.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
        sections: dict[str, tuple[int, int, int]] = {}
        if e_shoff and 0 < e_shentsize <= 128 and e_shnum:
            table = read(e_shoff, min(e_shnum, 8192) * e_shentsize)
            headers = []
            for index in range(len(table) // e_shentsize):
                entry = table[index * e_shentsize:(index + 1) * e_shentsize]
                if is64 and len(entry) >= 64:
                    name, s_type, _, _, s_offset, s_size = struct.unpack_from(endian + "IIQQQQ", entry)
                elif not is64 and len(entry) >= 40:
                    name, s_type, _, _, s_offset, s_size = struct.unpack_from(endian + "IIIIII", entry)
                else:
                    continue
                headers.append((name, s_type, s_offset, s_size))
            if 0 <= e_shstrndx < len(headers):
                _, _, names_offset, names_size = headers[e_shstrndx]
                names = read(names_offset, min(names_size, MAX_HEADER_BYTES))
                for name, s_type, s_offset, s_size in headers:
                    end = names.find(b"\x00", name)
                    label = names[name:end if end != -1 else None].decode("ascii", "replace") if name < len(names) else ""
                    if label and label not in sections:
                        sections[label] = (s_type, s_offset, s_size)
        interpreter = ""
        for p_type, _, p_offset, _, p_filesz, _ in segments:
            if p_type == 3:
                interpreter = read(p_offset, min(p_filesz, 256)).rstrip(b"\x00").decode("ascii", "replace")
        dynamic = any(p_type == 2 for p_type, *_ in segments)
        stripped = ".symtab" not in sections
        debug = any(name.startswith((".debug_info", ".zdebug_info")) for name in sections)
        build_id = ""
        if ".note.gnu.build-id" in sections:
            _, offset, size = sections[".note.gnu.build-id"]
            note = read(offset, min(size, 256))
            if len(note) >= 16:
                namesz, descsz, _ = struct.unpack_from(endian + "III", note)
                start = 12 + ((namesz + 3) & ~3)
                build_id = note[start:start + descsz].hex()
        compiler = ""
        if ".comment" in sections:
            _, offset, size = sections[".comment"]
            comment = read(offset, min(size, 4096))
            compiler = "; ".join(sorted({part.decode("ascii", "replace").strip() for part in comment.split(b"\x00")
                                         if part.strip()}))[:300]
        linux = bool(interpreter) or dynamic or e_type == 3
        bare_metal = e_type == 2 and not linux and machine in _BARE_METAL
        module = e_type == 1 and ".modinfo" in sections
        hardening = self._elf_hardening(read, sections, segments, endian, is64, e_type, interpreter) if linux else {}
        loads = [(vaddr, vaddr + memsz, flags) for p_type, flags, _, vaddr, _, memsz in segments if p_type == 1 and memsz]
        writable_executable = [vaddr for vaddr, _, flags in loads if flags & 0x1 and flags & 0x2]
        role = ("bare-metal firmware" if bare_metal else "Linux kernel module" if module
                else "core dump" if e_type == 4 else f"Linux {kind}" if linux else kind)
        code_facts.emit_fact(
            "elf_binary", machine, role=role, bits=64 if is64 else 32, stripped=int(stripped), debug=int(debug),
            **{key: int(value) for key, value in hardening.items() if isinstance(value, bool)},
        )
        findings: list[Finding] = []
        if bare_metal or module or record.path.lower().endswith((".elf", ".axf")):
            details = [f"{'64' if is64 else '32'}-bit {'little' if endian == '<' else 'big'}-endian {machine} {role}",
                       f"entry {e_entry:#x}"]
            if loads:
                details.append("load segments " + ", ".join(
                    f"{start:#x}-{end - 1:#x} ({'R' if flags & 4 else ''}{'W' if flags & 2 else ''}"
                    f"{'X' if flags & 1 else ''})" for start, end, flags in loads[:8]))
            vector = next((name for name in (".isr_vector", ".vectors", ".vector_table", ".intvec") if name in sections), "")
            if vector:
                details.append(f"vector table section {vector}")
            details.append("stripped" if stripped else "symbols present")
            if debug:
                details.append("debug information present")
            if build_id:
                details.append(f"build ID {build_id}")
            if compiler:
                details.append(f"compiled by {compiler}")
            if bare_metal:
                stream.seek(0)
                components = self._components(stream.read(MAX_STRING_SCAN_BYTES))
                for component, version in components:
                    code_facts.emit_fact("firmware_component", component, version=version)
                if components:
                    details.append("contains " + ", ".join(f"{name} {version}" for name, version in components))
            findings.append(self._finding(record, "Firmware image (ELF)", "; ".join(details) + "."))
        if e_type == 4:
            findings.append(self._finding(
                record, "Core dump", f"{machine} process core dump. Core dumps contain process memory, which can "
                "include credentials and keys.", severity="LOW",
                recommendation="Remove core dumps from the repository and exclude them in .gitignore.",
            ))
        if writable_executable:
            findings.append(self._finding(
                record, "Writable and executable segment",
                f"Load segment(s) at {', '.join(hex(item) for item in writable_executable[:6])} are both writable and "
                "executable, so memory corruption can be turned directly into code execution.",
                severity="MEDIUM" if linux else "LOW",
                recommendation="Link with separate code and data segments (W^X); check the linker script.",
            ))
        if linux and hardening.get("executable_stack"):
            findings.append(self._finding(
                record, "Executable stack",
                "The PT_GNU_STACK segment is executable (or missing), so stack buffer overflows can run injected code.",
                severity="MEDIUM", recommendation="Link with -z noexecstack and remove assembly that requests an executable stack.",
            ))
        if debug and bare_metal and not record.path.lower().endswith((".elf", ".axf")):
            findings.append(self._finding(
                record, "Debug information in a firmware binary",
                "The image carries DWARF debug information, which discloses source structure to anyone who extracts it.",
                severity="LOW",
            ))
        return findings

    def _pe(self, stream, record: FileRecord, head: bytes) -> list[Finding]:
        if len(head) < 64:
            return []
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        if offset > MAX_HEADER_BYTES:
            return []
        stream.seek(offset)
        header = stream.read(24 + 96)
        if len(header) < 24 + 72 or header[:4] != b"PE\x00\x00":
            return []
        machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", header, 4)
        magic = struct.unpack_from("<H", header, 24)[0]
        if magic not in (0x10B, 0x20B):
            return []
        subsystem, dll_flags = struct.unpack_from("<HH", header, 24 + 68)
        names = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2",
                 0x5032: "RISC-V 32", 0x5064: "RISC-V 64", 0xEBC: "EFI byte code"}
        architecture = names.get(machine, f"machine {machine:#x}")
        efi = subsystem in {10, 11, 12, 13}
        role = {1: "native driver", 2: "GUI application", 3: "console application", 10: "EFI application",
                11: "EFI boot-service driver", 12: "EFI runtime driver", 13: "EFI ROM"}.get(subsystem, "binary")
        if characteristics & 0x2000 and not efi:
            role = "DLL"
        flags = {"aslr": bool(dll_flags & 0x40), "high_entropy_aslr": bool(dll_flags & 0x20),
                 "nx": bool(dll_flags & 0x100), "cfg": bool(dll_flags & 0x4000), "no_seh": bool(dll_flags & 0x400)}
        code_facts.emit_fact("pe_binary", architecture, role=role, bits=64 if magic == 0x20B else 32,
                             **{key: int(value) for key, value in flags.items()})
        if not efi:
            return []
        return [self._finding(
            record, "UEFI firmware image",
            f"{architecture} {role} with {sections} section(s); "
            f"{'NX-compatible' if flags['nx'] else 'not NX-compatible'}, "
            f"{'relocatable (ASLR)' if flags['aslr'] else 'fixed base'}.",
        )]

    @staticmethod
    def _elf_hardening(read, sections, segments, endian, is64, e_type, interpreter) -> dict:
        stack = next((flags for p_type, flags, *_ in segments if p_type == 0x6474E551), None)
        relro = any(p_type == 0x6474E552 for p_type, *_ in segments)
        bind_now = False
        rpath = False
        if ".dynamic" in sections:
            _, offset, size = sections[".dynamic"]
            data = read(offset, min(size, 256 * 1024))
            step = 16 if is64 else 8
            form = endian + ("qQ" if is64 else "iI")
            for index in range(len(data) // step):
                tag, value = struct.unpack_from(form, data, index * step)
                if tag == 0:
                    break
                if tag == 24 or (tag == 30 and value & 0x8) or (tag == 0x6FFFFFFB and value & 0x1):
                    bind_now = True
                if tag in {15, 29}:
                    rpath = True
        strings = b""
        if ".dynstr" in sections:
            _, offset, size = sections[".dynstr"]
            strings = read(offset, min(size, MAX_TABLE_BYTES))
        return {
            "nx": stack is not None and not stack & 0x1,
            "executable_stack": stack is None and bool(interpreter) or (stack is not None and bool(stack & 0x1)),
            "pie": e_type == 3 and bool(interpreter),
            "relro": relro, "full_relro": relro and bind_now,
            "canary": b"__stack_chk_fail\x00" in strings or b"__stack_chk_guard\x00" in strings,
            "fortify": bool(re.search(rb"__\w{2,30}?_chk\x00", strings)), "rpath": rpath,
        }

    # -- text images ----------------------------------------------------------------------
    def _lines(self, stream, head: bytes) -> list[bytes]:
        data = head + stream.read(MAX_TEXT_IMAGE_BYTES - len(head))
        return data.splitlines()

    def _intel_hex(self, stream, record: FileRecord, head: bytes) -> list[Finding]:
        base, spans, size, errors, entry, end_seen, records = 0, [], 0, 0, None, False, 0
        for raw in self._lines(stream, head):
            line = raw.strip()
            if not line:
                continue
            records += 1
            if not line.startswith(b":"):
                errors += 1
                continue
            try:
                data = bytes.fromhex(line[1:].decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                errors += 1
                continue
            if len(data) < 5 or len(data) != data[0] + 5 or sum(data) & 0xFF:
                errors += 1
                continue
            count, address, kind, payload = data[0], (data[1] << 8) | data[2], data[3], data[4:-1]
            if kind == 0:
                spans.append((base + address, base + address + count))
                size += count
            elif kind == 1:
                end_seen = True
                break
            elif kind == 2 and len(payload) == 2:
                base = ((payload[0] << 8) | payload[1]) << 4
            elif kind == 4 and len(payload) == 2:
                base = ((payload[0] << 8) | payload[1]) << 16
            elif kind in (3, 5) and len(payload) == 4:
                entry = int.from_bytes(payload, "big")
        return self._text_image(record, "Intel HEX", records, spans, size, errors, entry, end_seen)

    def _srecord(self, stream, record: FileRecord, head: bytes) -> list[Finding]:
        spans, size, errors, entry, end_seen, records, header = [], 0, 0, None, False, 0, ""
        widths = {"1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2, "0": 2}
        for raw in self._lines(stream, head):
            line = raw.strip()
            if not line:
                continue
            records += 1
            kind = chr(line[1]) if len(line) > 1 and line[:1] == b"S" else ""
            try:
                data = bytes.fromhex(line[2:].decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                errors += 1
                continue
            width = widths.get(kind)
            if width is None or len(data) < width + 2 or len(data) != data[0] + 1 or (sum(data[:-1]) & 0xFF) ^ 0xFF != data[-1]:
                errors += 1
                continue
            address = int.from_bytes(data[1:1 + width], "big")
            payload = data[1 + width:-1]
            if kind in "123":
                spans.append((address, address + len(payload)))
                size += len(payload)
            elif kind == "0":
                header = payload.decode("ascii", "replace").strip("\x00 ")[:60]
            elif kind in "789":
                entry, end_seen = address, True
        findings = self._text_image(record, "Motorola S-record", records, spans, size, errors, entry, end_seen)
        if header and findings:
            findings[0].detail = findings[0].detail.rstrip(".") + f"; header \"{header}\"."
        return findings

    def _text_image(self, record, label, records, spans, size, errors, entry, end_seen) -> list[Finding]:
        if not records:
            return []
        merged = _ranges(spans)
        code_facts.emit_fact("firmware_image", label, size=size, ranges=len(merged))
        findings = [self._finding(
            record, f"{label} firmware image",
            f"{records:,} record(s); {size:,} data bytes in {_describe_ranges(merged)}"
            + (f"; entry point {entry:#x}" if entry is not None else "") + ".",
        )]
        if errors:
            findings.append(self._finding(
                record, f"Corrupt {label} records",
                f"{errors:,} record(s) fail their checksum or format check; programming this image would write "
                "wrong data.", severity="LOW",
            ))
        if not end_seen:
            findings.append(self._finding(
                record, f"{label} image without end record",
                "The file has no end-of-file/termination record, which usually means it was truncated.",
                severity="LOW", confidence="INFERRED",
            ))
        return findings

    def _uf2(self, stream, record: FileRecord, head: bytes) -> list[Finding]:
        stream.seek(0)
        families: Counter = Counter()
        spans, blocks, bad = [], 0, 0
        while blocks < MAX_UF2_BLOCKS:
            block = stream.read(512)
            if len(block) < 512:
                break
            blocks += 1
            magic0, magic1, flags, address, payload_size, _, _, family = struct.unpack_from("<IIIIIIII", block)
            if (magic0, magic1) != (0x0A324655, 0x9E5D5157) or struct.unpack_from("<I", block, 508)[0] != 0x0AB16F30:
                bad += 1
                continue
            if flags & 0x1:
                continue  # not for the main flash
            if flags & 0x2000:
                families[_UF2_FAMILIES.get(family, f"{family:#010x}")] += 1
            spans.append((address, address + min(payload_size, 476)))
        merged = _ranges(spans)
        for family in families:
            code_facts.emit_fact("embedded_target", family, source="uf2")
        code_facts.emit_fact("firmware_image", "UF2", blocks=blocks)
        findings = [self._finding(
            record, "UF2 firmware image",
            f"{blocks:,} block(s) for {', '.join(f'{name} ({count})' for name, count in families.most_common()) or 'no family ID'}; "
            f"target {_describe_ranges(merged)}.",
        )]
        if bad:
            findings.append(self._finding(record, "Corrupt UF2 blocks", f"{bad:,} block(s) have invalid magic numbers.",
                                          severity="LOW"))
        return findings

    # -- raw images ----------------------------------------------------------------------
    def _image(self, record: FileRecord, sample: bytes) -> list[Finding]:
        if len(sample) < 64:
            return []
        findings: list[Finding] = []
        detail, label = self._container(sample)
        if label is None and record.path.lower().endswith((".bin", ".img", ".fw", ".rom")):
            detail, label = self._cortex_m(sample)
        entropy = _entropy(sample[:_ENTROPY_SAMPLE])
        components = self._components(sample)
        for component, version in components:
            code_facts.emit_fact("firmware_component", component, version=version)
        if label is None and not components:
            if entropy >= 7.95 and record.size_bytes >= 4096:
                code_facts.emit_fact("firmware_image", "high-entropy", size=record.size_bytes)
                return [self._finding(
                    record, "Encrypted or compressed binary",
                    f"Entropy {entropy:.2f} bits/byte with no known header: the content is encrypted, compressed or "
                    "random, so it cannot be inspected further.", confidence="INFERRED",
                )]
            return []
        code_facts.emit_fact("firmware_image", label or "binary", size=record.size_bytes)
        text = (detail or "Binary image") + f"; entropy {entropy:.2f} bits/byte"
        if components:
            text += "; contains " + ", ".join(f"{name} {version}" for name, version in components[:10])
        findings.append(self._finding(record, label or "Firmware binary", text + ".",
                                      confidence="CONFIRMED" if label and label != "Cortex-M firmware image" else "INFERRED"))
        return findings

    @staticmethod
    def _components(data: bytes) -> list[tuple[str, str]]:
        if not _COMPONENT_HINT.search(data):
            return []
        found = []
        for name, pattern in _COMPONENT_STRINGS:
            match = pattern.search(data)
            if match:
                found.append((name, match.group(1).decode("ascii", "replace")))
        return found

    def _container(self, data: bytes) -> tuple[str | None, str | None]:
        if data[:4] == b"\xd0\x0d\xfe\xed":
            return self._dtb(data)
        if data[:4] == b"\x27\x05\x19\x56" and len(data) >= 64:
            _, _, _, size, load, entry, _, os_id, arch, image_type, compression = struct.unpack_from(">IIIIIIIBBBB", data)
            name = data[32:64].split(b"\x00", 1)[0].decode("ascii", "replace")
            return (f"U-Boot image \"{name}\": {_UIMAGE_TYPE.get(image_type, image_type)} for "
                    f"{_UIMAGE_OS.get(os_id, os_id)}/{_UIMAGE_ARCH.get(arch, arch)}, "
                    f"{_UIMAGE_COMPRESSION.get(compression, compression)} compression, {size:,} bytes, "
                    f"load {load:#x}, entry {entry:#x}", "U-Boot uImage")
        if data[:8] == b"ANDROID!" and len(data) >= 64:
            version = struct.unpack_from("<I", data, 40)[0]
            if version >= 3:
                kernel, ramdisk = struct.unpack_from("<II", data, 8)
                return (f"Android boot image v{version}: kernel {kernel:,} bytes, ramdisk {ramdisk:,} bytes",
                        "Android boot image")
            kernel, _, ramdisk, _, _, _, _, page = struct.unpack_from("<IIIIIIII", data, 8)
            name = data[48:64].split(b"\x00", 1)[0].decode("ascii", "replace")
            return (f"Android boot image v{version} \"{name}\": kernel {kernel:,} bytes, ramdisk {ramdisk:,} bytes, "
                    f"page size {page}", "Android boot image")
        if data[:4] in (b"hsqs", b"sqsh") and len(data) >= 48:
            endian = "<" if data[:4] == b"hsqs" else ">"
            inodes, _, block_size, _, compression, _, _, _, major, minor = struct.unpack_from(endian + "IIIIHHHHHH", data, 4)
            used = struct.unpack_from(endian + "Q", data, 40)[0]
            return (f"SquashFS {major}.{minor} filesystem: {inodes:,} inodes, {block_size:,}-byte blocks, "
                    f"{_SQUASHFS_COMPRESSION.get(compression, compression)} compression, {used:,} bytes used",
                    "SquashFS image")
        if data[:4] == b"UBI#":
            return "UBI volume image (erase-count header)", "UBI image"
        if data[:2] in (b"\x85\x19", b"\x19\x85"):
            return "JFFS2 filesystem", "JFFS2 image"
        if data[:4] in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
            return "cramfs filesystem", "cramfs image"
        if len(data) >= 1082 and data[1080:1082] == b"\x53\xef":
            blocks, = struct.unpack_from("<I", data, 1028)
            label = data[1144:1160].split(b"\x00", 1)[0].decode("ascii", "replace")
            return f"ext2/3/4 filesystem \"{label}\" with {blocks:,} blocks", "ext filesystem image"
        if data[:4] == b"HDR0":
            return "Broadcom TRX firmware container", "TRX image"
        if data[0] == 0xE9 and 1 <= data[1] <= 16 and len(data) >= 288:
            magic, secure_version = struct.unpack_from("<II", data, 32)
            if magic == 0xABCD5432:
                version = data[48:80].split(b"\x00", 1)[0].decode("ascii", "replace")
                project = data[80:112].split(b"\x00", 1)[0].decode("ascii", "replace")
                idf = data[144:176].split(b"\x00", 1)[0].decode("ascii", "replace")
                return (f"ESP32 application \"{project}\" version {version}, built with ESP-IDF {idf}, "
                        f"{data[1]} segment(s), secure version {secure_version}", "ESP32 application image")
            return f"ESP32/ESP8266 image with {data[1]} segment(s)", "ESP image"
        for magic, name in ((b"\x1f\x8b", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"\x5d\x00\x00", "LZMA"),
                            (b"\x28\xb5\x2f\xfd", "zstd"), (b"\x04\x22\x4d\x18", "LZ4"), (b"\x89LZO", "LZO")):
            if data.startswith(magic):
                return f"{name}-compressed blob", f"{name} compressed image"
        return None, None

    def _dtb(self, data: bytes) -> tuple[str, str]:
        if len(data) < 40:
            return "Device tree blob (truncated header)", "Device tree blob"
        _, total, struct_offset, strings_offset, _, version, _, _, strings_size, struct_size = struct.unpack_from(">IIIIIIIIII", data)
        block = data[struct_offset:struct_offset + min(struct_size, len(data))]
        strings = data[strings_offset:strings_offset + strings_size]
        position, depth, nodes, model, compatible, images_depth, image_count = 0, 0, 0, "", "", 0, 0
        tokens = 0
        while position + 4 <= len(block) and tokens < 1_000_000:
            tokens += 1
            token = struct.unpack_from(">I", block, position)[0]
            position += 4
            if token == 1:
                end = block.find(b"\x00", position)
                if end == -1:
                    break
                name = block[position:end]
                depth += 1
                nodes += 1
                if depth == 2 and name == b"images":
                    images_depth = 2
                elif images_depth and depth == images_depth + 1:
                    image_count += 1
                position = (end + 4) & ~3
            elif token == 2:
                if images_depth and depth == images_depth:
                    images_depth = 0
                depth -= 1
            elif token == 3:
                if position + 8 > len(block):
                    break
                length, name_offset = struct.unpack_from(">II", block, position)
                position += 8
                value = block[position:position + length]
                position = (position + length + 3) & ~3
                if depth == 1:
                    end = strings.find(b"\x00", name_offset)
                    prop = strings[name_offset:end if end != -1 else None]
                    if prop == b"model":
                        model = value.rstrip(b"\x00").decode("ascii", "replace")[:120]
                    elif prop == b"compatible":
                        compatible = ", ".join(part.decode("ascii", "replace") for part in value.split(b"\x00") if part)[:200]
            elif token == 4:
                continue
            else:
                break
        if model:
            code_facts.emit_fact("embedded_target", model, source="dtb")
        kind = "FIT image" if image_count else "Device tree blob"
        detail = (f"{kind} (version {version}, {total:,} bytes, {nodes:,} nodes)"
                  + (f", model \"{model}\"" if model else "") + (f", compatible {compatible}" if compatible else "")
                  + (f", {image_count} image(s)" if image_count else ""))
        return detail, kind

    @staticmethod
    def _cortex_m(data: bytes) -> tuple[str | None, str | None]:
        if len(data) < 64:
            return None, None
        stack, reset, nmi, hard_fault = struct.unpack_from("<IIII", data)
        ram = 0x10000000 <= stack <= 0x10100000 or 0x1FFE0000 <= stack <= 0x20400000 or 0x20000000 <= stack <= 0x24000000
        flash_ranges = ((0x00000000, 0x00400000), (0x08000000, 0x08400000), (0x10000000, 0x11000000),
                        (0x00200000, 0x00300000), (0x60000000, 0x60800000))

        def handler(value: int) -> bool:
            return value & 1 == 1 and any(start <= value < end for start, end in flash_ranges)

        if ram and stack & 0x3 == 0 and handler(reset) and (handler(nmi) or nmi == 0) and (handler(hard_fault) or hard_fault == 0):
            return (f"Raw Cortex-M image: initial stack pointer {stack:#010x}, reset handler {reset - 1:#010x} (Thumb)",
                    "Cortex-M firmware image")
        return None, None

    # -- build systems ---------------------------------------------------------------------
    def _partitions(self, record: FileRecord, text: str) -> list[Finding]:
        rows = []
        for line in text.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            fields = [field.strip() for field in stripped.split(",")]
            if len(fields) >= 3 and fields[1] in {"app", "data"} or (len(fields) >= 3 and fields[1].startswith("0x")):
                rows.append(fields + [""] * (6 - len(fields)))
        if not rows:
            return []
        ota = sum(1 for row in rows if row[2].startswith("ota_"))
        encrypted = sum(1 for row in rows if "encrypted" in row[5])
        described = "; ".join(f"{row[0]} ({row[1]}/{row[2]}{', ' + row[4] if row[4] else ''})" for row in rows[:16])
        findings = [self._finding(
            record, "ESP-IDF partition table",
            f"{len(rows)} partition(s): {described}. "
            + (f"OTA update slots: {ota}." if ota else "No OTA slots: firmware can only be updated over a wired connection.")
            + (f" {encrypted} partition(s) flagged encrypted." if encrypted else ""),
        )]
        if ota == 1:
            findings.append(self._finding(
                record, "Single OTA slot",
                "Only one OTA application slot exists, so a failed update has no fallback image.", severity="LOW",
                confidence="INFERRED", recommendation="Define ota_0 and ota_1 so updates can roll back.",
            ))
        return findings

    def _yocto_recipe(self, record: FileRecord, text: str) -> list[Finding]:
        settings: dict[str, str] = {}
        for key, value in _YOCTO_SETTING.findall(text):
            settings[key] = (settings.get(key, "") + " " + value).strip() if key in settings else value
        name = PurePosixPath(record.path.replace("\\", "/")).stem
        fetches = [item.split(";", 1)[0] for item in settings.get("SRC_URI", "").split() if "://" in item]
        code_facts.emit_fact("yocto_recipe", name.split("_", 1)[0], license=settings.get("LICENSE", "")[:80],
                             fetches=len(fetches))
        findings = []
        insecure = [uri for uri in fetches if uri.startswith(("http://", "ftp://", "git://"))
                    and "protocol=https" not in settings.get("SRC_URI", "") and "protocol=ssh" not in settings.get("SRC_URI", "")]
        if insecure:
            findings.append(self._finding(
                record, "Recipe fetches sources without transport security",
                f"SRC_URI uses unencrypted transports ({', '.join(insecure[:5])}); without a checksum or pinned "
                "SRCREV a network attacker can substitute the sources.", severity="LOW",
                recommendation="Use https:// or ;protocol=https and keep SRC_URI checksums.",
            ))
        if "${AUTOREV}" in settings.get("SRCREV", "") or re.search(r"(?m)^[ \t]*+SRCREV\w*+[ \t]*+\??=[ \t]*+\"\$\{AUTOREV\}\"", text):
            findings.append(self._finding(
                record, "Unpinned source revision",
                "SRCREV is ${AUTOREV}, so every build fetches the newest commit and images are not reproducible.",
                severity="LOW", recommendation="Pin SRCREV to a commit hash for release builds.",
            ))
        return findings

    def _yocto_conf(self, record: FileRecord, text: str) -> list[Finding]:
        settings: dict[str, str] = {}
        for key, value in _YOCTO_SETTING.findall(text):
            settings[key] = (settings.get(key, "") + " " + value).strip()
        findings = []
        machine, distro = settings.get("MACHINE", ""), settings.get("DISTRO", "")
        series = next((value for key, value in settings.items() if key.startswith("LAYERSERIES_COMPAT")), "")
        if machine:
            code_facts.emit_fact("embedded_target", machine, source="yocto")
        parts = [f"MACHINE {machine}" if machine else "", f"DISTRO {distro}" if distro else "",
                 f"compatible with {series}" if series else "",
                 f"collections {settings['BBFILE_COLLECTIONS']}" if settings.get("BBFILE_COLLECTIONS") else ""]
        if any(parts):
            findings.append(self._finding(record, "Yocto configuration", "; ".join(part for part in parts if part) + "."))
        features = " ".join(settings.get(key, "") for key in ("EXTRA_IMAGE_FEATURES", "IMAGE_FEATURES"))
        risky = [feature for feature in ("debug-tweaks", "empty-root-password", "allow-empty-password",
                                         "allow-root-login", "post-install-logging") if feature in features.split()]
        if risky:
            findings.append(self._finding(
                record, "Development image features enabled",
                f"Image features {', '.join(risky)} are set: images built with them allow root login without a "
                "password.", severity="MEDIUM",
                recommendation="Remove debug-tweaks and empty-password features from production image configurations.",
            ))
        return findings

    def _defconfig(self, record: FileRecord, text: str) -> list[Finding]:
        settings = dict(_BR2_SETTING.findall(text))
        if not settings:
            kernel = len(re.findall(r"(?m)^CONFIG_[A-Z0-9_]{1,120}+=", text))
            if not kernel:
                return []
            return [self._finding(record, "Kernel or bootloader defconfig", f"{kernel:,} configuration option(s) set.")]
        architecture = next((key[4:] for key, value in settings.items()
                             if value == "y" and key in {"BR2_arm", "BR2_aarch64", "BR2_x86_64", "BR2_i386", "BR2_mips",
                                                         "BR2_mipsel", "BR2_riscv", "BR2_powerpc", "BR2_xtensa"}), "")
        packages = sum(1 for key, value in settings.items() if key.startswith("BR2_PACKAGE_") and value == "y")
        findings = [self._finding(
            record, "Buildroot configuration",
            f"Architecture {architecture or 'unspecified'}; {packages:,} package(s) selected"
            + (f"; kernel {settings['BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE'].strip(chr(34))}"
               if settings.get("BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE") else "") + ".",
        )]
        password = settings.get("BR2_TARGET_GENERIC_ROOT_PASSWD")
        if password is not None and password.strip() in {'""', ""} and settings.get("BR2_TARGET_ENABLE_ROOT_LOGIN", "y") == "y":
            findings.append(self._finding(
                record, "Empty root password",
                "BR2_TARGET_GENERIC_ROOT_PASSWD is empty while root login is enabled, so images accept root logins "
                "without a password.", severity="MEDIUM",
                recommendation="Set a root password hash or disable root login (BR2_TARGET_ENABLE_ROOT_LOGIN=n).",
            ))
        return findings

    def _openwrt_feeds(self, record: FileRecord, text: str) -> list[Finding]:
        feeds = _FEED.findall(text)
        if not feeds:
            return []
        insecure = [name for kind, name, url in feeds if url.startswith(("http://", "git://"))]
        findings = [self._finding(record, "OpenWrt package feeds",
                                  f"{len(feeds)} feed(s): " + ", ".join(f"{name} ({kind})" for kind, name, _ in feeds[:12]) + ".")]
        if insecure:
            findings.append(self._finding(
                record, "Package feed without transport security",
                f"Feed(s) {', '.join(insecure)} are fetched over an unencrypted transport.", severity="LOW",
            ))
        return findings
