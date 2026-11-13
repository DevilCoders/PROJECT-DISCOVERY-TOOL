"""File signatures (magic bytes) and MIME types, kept apart from what a file name suggests.

``detect(sample)`` names a file's format from its leading bytes alone. A table of magic-byte
rules (``RULES``) proposes candidates in order; the C++ classifier compiles the same table
from the generated ``native/cpp/pdt_signature_rules.h`` and is used only while its digest
matches this catalog. A validator per format family then checks the header and reads the
subtype: ELF and Mach-O file types, PE DLLs, EFI images and .NET assemblies, ZIP packages
(Office Open XML, OpenDocument, EPUB, JAR, APK, PyTorch and others), ISO base media brands,
RIFF, EBML and Ogg codecs, OLE compound documents, MPEG audio frames, tar header checksums
and ISO 9660 and UDF volume descriptors. A candidate its validator rejects lets the next
rule match. Text formats (scripts, PostScript, RTF, SVG, PEM, Intel HEX, S-records, Git LFS
pointers) are recognized only in samples that are text.

``name_type(path)`` says what the name suggests, from a separate catalog, and ``classify``
combines the two: ``file_type`` is the verified format, ``text``, ``binary/unknown`` or
``empty``, and comes from the name only when the content was not read.
"""
from __future__ import annotations

import bisect
import hashlib
import math
import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from ..catalog.languages import is_source_path, is_textual_path
from ..core.source_utils import text_encoding
from ..engine import native as _native

# Bytes read from the start of every file. 4 KiB reaches the OOXML part names, the ext2/3/4
# superblock, GPT headers and HDF5 user blocks that 512 bytes do not, for the same read.
SAMPLE_BYTES = 4096
# A stored inventory classified with another catalog version is not resumed.
CATALOG_VERSION = 1

ISO_DESCRIPTOR_OFFSET = 32768  # sector 16: the ISO 9660 / UDF volume recognition area
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


@dataclass(frozen=True, slots=True)
class Kind:
    """A format: report label (``category/format``), MIME type and container family."""

    label: str
    mime: str
    family: str
    text: bool = False  # a text format: file_type stays "text"


@dataclass(frozen=True, slots=True)
class Signature:
    """A verified format, with a description of what the header says."""

    kind: Kind
    detail: str | None = None
    declared_mime: str | None = None  # a MIME type the content declares (OpenDocument)

    @property
    def label(self) -> str:
        return self.kind.label

    @property
    def mime(self) -> str:
        return self.declared_mime or self.kind.mime

    @property
    def family(self) -> str:
        return self.kind.family


Check = Callable[["Rule", bytes, "int | None", Mapping[int, bytes]], "Signature | None"]


@dataclass(frozen=True, slots=True)
class Rule:
    """Every (offset, bytes) test must match; ``check`` then validates the header."""

    kind: Kind
    tests: tuple[tuple[int, bytes], ...]
    check: Check | None = None
    binary: bool = False  # rejected when the sample is text (printable magic numbers)


@dataclass(frozen=True, slots=True)
class NameType:
    """What a name suggests, and the signature labels, families or "text" that confirm it."""

    label: str
    accepts: frozenset[str]
    strict: bool = False  # the format always starts with a signature the catalog checks


@dataclass(frozen=True, slots=True)
class Classification:
    file_type: str
    type_source: str  # "signature", "content" or "name"
    signature: Signature | None = None
    detail: str | None = None
    mime_type: str | None = None
    name_type: str | None = None
    mismatch: bool = False


KINDS: dict[str, Kind] = {}


def _kind(label: str, mime: str, family: str | None = None, *, text: bool = False) -> Kind:
    kind = Kind(label, mime, family or label.split("/", 1)[1], text)
    if KINDS.setdefault(label, kind) != kind:
        raise ValueError(f"conflicting definitions of the {label} signature")
    return KINDS[label]


def family_of(label: str | None) -> str | None:
    """The container family of a signature label ("zip" for a .docx), or None."""
    kind = KINDS.get(label or "")
    return None if kind is None else kind.family


def _le(data: bytes, offset: int, width: int) -> int:
    return int.from_bytes(data[offset:offset + width], "little")


def _be(data: bytes, offset: int, width: int) -> int:
    return int.from_bytes(data[offset:offset + width], "big")


# ---------------------------------------------------------------------------------------
# Text and binary samples

# Control bytes that do not occur in text: NUL to BEL, SO to SUB, FS to US and DEL. Tab,
# line breaks, form feed, backspace and escape (terminal colors in logs) do.
_BINARY_CONTROLS = bytes((*range(0x00, 0x08), *range(0x0E, 0x1B), *range(0x1C, 0x20), 0x7F))
_BINARY_CONTROL_CHARACTERS = frozenset(chr(value) for value in _BINARY_CONTROLS)


def looks_textual(sample: bytes) -> bool:
    """Whether a sample is text whatever the file is called.

    Text is a UTF-16/32 byte-order mark, NUL-interleaved UTF-16 that decodes to text, a
    sample without NUL bytes that decodes as UTF-8 (a character cut at the sample end is
    allowed), or one in a legacy 8-bit encoding: no NUL and at most 1% control bytes.
    """
    if not sample:
        return False
    encoding = text_encoding(sample)
    if encoding in ("utf-16", "utf-32"):
        return True
    if encoding in ("utf-16-le", "utf-16-be"):
        text = sample[:len(sample) // 2 * 2].decode(encoding, errors="replace")
        controls = sum(character in _BINARY_CONTROL_CHARACTERS for character in text)
        return controls * 100 <= len(text)
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 3 and exc.reason == "unexpected end of data":
            return True
    return (len(sample) - len(sample.translate(None, _BINARY_CONTROLS))) * 100 <= len(sample)


def _entropy(sample: bytes) -> float:
    length = len(sample)
    return -sum(count / length * math.log2(count / length) for count in Counter(sample).values())


# ---------------------------------------------------------------------------------------
# Executables, libraries and bytecode

_ELF_OBJECT = _kind("object/elf", "application/x-object", "elf")
_ELF_EXECUTABLE = _kind("executable/elf", "application/x-executable", "elf")
_ELF_LIBRARY = _kind("library/elf", "application/x-sharedlib", "elf")
_ELF_CORE = _kind("core-dump/elf", "application/x-core", "elf")
_ELF_MACHINES = {
    2: "SPARC", 3: "x86", 4: "Motorola 68000", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 22: "S/390",
    40: "ARM", 42: "SuperH", 43: "SPARC V9", 50: "IA-64", 62: "x86-64", 83: "AVR", 92: "OpenRISC",
    94: "Xtensa", 105: "MSP430", 164: "Hexagon", 183: "AArch64", 190: "CUDA", 243: "RISC-V", 247: "BPF",
    258: "LoongArch",
}


def _elf(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    if len(sample) < 20 or sample[4] not in (1, 2) or sample[5] not in (1, 2):
        return Signature(_ELF_EXECUTABLE, "ELF file with an invalid or truncated header")
    bits = 32 if sample[4] == 1 else 64
    order = "little" if sample[5] == 1 else "big"

    def field(offset: int, width: int) -> int:
        return int.from_bytes(sample[offset:offset + width], order)

    machine = field(18, 2)
    header = f"ELF {bits}-bit {'LSB' if order == 'little' else 'MSB'}"
    arch = _ELF_MACHINES.get(machine, f"machine {machine}")
    file_type = field(16, 2)
    if file_type == 1:
        return Signature(_ELF_OBJECT, f"{header} relocatable object, {arch}")
    if file_type == 2:
        return Signature(_ELF_EXECUTABLE, f"{header} executable, {arch}")
    if file_type == 3:
        # A position-independent executable is ET_DYN like a library; only executables
        # name a program interpreter (PT_INTERP).
        if _elf_interpreter(sample, bits, field):
            return Signature(
                _ELF_EXECUTABLE, f"{header} position-independent executable, {arch}",
                "application/x-pie-executable",
            )
        return Signature(_ELF_LIBRARY, f"{header} shared object, {arch}")
    if file_type == 4:
        return Signature(_ELF_CORE, f"{header} core file, {arch}")
    return Signature(_ELF_EXECUTABLE, f"{header} file of type {file_type:#x}, {arch}")


def _elf_interpreter(sample: bytes, bits: int, field: Callable[[int, int], int]) -> bool:
    if len(sample) < (46 if bits == 32 else 58):
        return False
    if bits == 32:
        offset, width, count = field(28, 4), field(42, 2), field(44, 2)
    else:
        offset, width, count = field(32, 8), field(54, 2), field(56, 2)
    if width < 8:
        return False
    for index in range(min(count, 64)):
        entry = offset + index * width
        if entry + 4 > len(sample):
            return False
        if field(entry, 4) == 3:  # PT_INTERP
            return True
    return False


_PE_EXECUTABLE = _kind("executable/pe", "application/vnd.microsoft.portable-executable", "mz")
_PE_LIBRARY = _kind("library/pe", "application/vnd.microsoft.portable-executable", "mz")
_EFI = _kind("firmware/efi", "application/efi", "mz")
_DOS = _kind("executable/dos", "application/x-dosexec", "mz")
_PE_MACHINES = {
    0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2", 0xAA64: "ARM64", 0xA641: "ARM64EC",
    0xA64E: "ARM64X", 0x200: "IA-64", 0xEBC: "EFI byte code", 0x5032: "RISC-V 32-bit",
    0x5064: "RISC-V 64-bit", 0x6232: "LoongArch 32-bit", 0x6264: "LoongArch 64-bit", 0x1F0: "PowerPC",
    0x166: "MIPS",
}
_PE_SUBSYSTEMS = {
    1: "native", 2: "GUI", 3: "console", 5: "OS/2 console", 7: "POSIX console", 9: "Windows CE",
    10: "EFI application", 11: "EFI boot service driver", 12: "EFI runtime driver", 13: "EFI ROM",
    14: "Xbox", 16: "Windows boot application",
}
_DOS_EXTENDED = {
    b"NE": "NE executable (16-bit Windows or OS/2)",
    b"LE": "LE executable (VxD driver or DOS extender)",
    b"LX": "LX executable (OS/2)",
}


def _mz(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    header = _le(sample, 0x3C, 4) if len(sample) >= 64 else 0
    if header >= 0x40 and header + 24 <= len(sample) and sample[header:header + 4] == b"PE\0\0":
        return _pe(sample, header)
    if header >= 0x40 and sample[header:header + 2] in _DOS_EXTENDED:
        return Signature(_DOS, _DOS_EXTENDED[sample[header:header + 2]])
    # A plain MS-DOS executable: bytes on the last page, page count and header paragraphs.
    if len(sample) < 28:
        return None
    last, pages, paragraphs = _le(sample, 2, 2), _le(sample, 4, 2), _le(sample, 8, 2)
    if last >= 512 or not pages or not paragraphs or paragraphs * 16 > pages * 512:
        return None
    if header >= len(sample) and header >= 0x40 and (size is None or header + 4 <= size):
        return Signature(_DOS, f"MZ executable; its extended header at offset {header} is past the sample")
    return Signature(_DOS, "MS-DOS executable")


def _pe(sample: bytes, header: int) -> Signature:
    machine, characteristics = _le(sample, header + 4, 2), _le(sample, header + 22, 2)
    arch = _PE_MACHINES.get(machine, f"machine {machine:#06x}")
    optional = header + 24
    magic = _le(sample, optional, 2) if optional + 2 <= len(sample) else 0
    flavor = {0x10B: "PE32", 0x20B: "PE32+", 0x107: "PE ROM"}.get(magic, "PE")
    subsystem = None
    dotnet = False
    if magic in (0x10B, 0x20B):
        if optional + 70 <= len(sample):
            subsystem = _le(sample, optional + 68, 2)
        directories = optional + (96 if magic == 0x10B else 112)
        # Data directory 14 is the CLR runtime header of a .NET assembly.
        if directories + 15 * 8 <= len(sample) and _le(sample, directories - 4, 4) > 14:
            clr = directories + 14 * 8
            dotnet = bool(_le(sample, clr, 4) and _le(sample, clr + 4, 4))
    suffix = ", .NET assembly" if dotnet else ""
    if subsystem in (10, 11, 12, 13):
        return Signature(_EFI, f"{flavor} {_PE_SUBSYSTEMS[subsystem]}, {arch}")
    if characteristics & 0x2000:  # IMAGE_FILE_DLL
        return Signature(_PE_LIBRARY, f"{flavor} DLL, {arch}{suffix}")
    role = f"executable ({_PE_SUBSYSTEMS[subsystem]})" if subsystem in _PE_SUBSYSTEMS else "executable"
    return Signature(_PE_EXECUTABLE, f"{flavor} {role}, {arch}{suffix}")


_MACHO = {
    category: _kind(f"{category}/mach-o", "application/x-mach-binary", "mach-o")
    for category in ("executable", "library", "object", "core-dump")
}
_MACHO_UNIVERSAL = _kind("executable/mach-o-universal", "application/x-mach-binary", "mach-o")
_JAVA_CLASS = _kind("bytecode/java-class", "application/java-vm", "java-class")
_MACHO_TYPES = {
    1: ("object", "relocatable object"), 2: ("executable", "executable"),
    3: ("library", "fixed VM shared library"), 4: ("core-dump", "core file"),
    5: ("executable", "preloaded executable"), 6: ("library", "dynamic library"),
    7: ("executable", "dynamic linker"), 8: ("library", "bundle"), 9: ("library", "dynamic library stub"),
    10: ("object", "debug symbols"), 11: ("library", "kernel extension"), 12: ("executable", "file set"),
}
_MACHO_CPUS = {
    7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64", 0x0200000C: "ARM64_32",
    18: "PowerPC", 0x01000012: "PowerPC64",
}


def _macho(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    big = sample[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
    bits = 64 if sample[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 32
    if len(sample) < 16:
        return Signature(_MACHO["executable"], "Mach-O file with a truncated header")
    read = _be if big else _le
    cpu, file_type = read(sample, 4, 4), read(sample, 12, 4)
    category, description = _MACHO_TYPES.get(file_type, ("executable", f"file of type {file_type}"))
    return Signature(_MACHO[category], f"Mach-O {bits}-bit {description}, {_MACHO_CPUS.get(cpu, f'CPU type {cpu:#x}')}")


def _cafebabe(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    """A Mach-O universal binary (few architectures) or a Java class (major version 45+)."""
    if len(sample) < 8:
        return None
    count = _be(sample, 4, 4)
    fat64 = sample[3] == 0xBF
    if fat64 or 0 < count < 30:
        width = 32 if fat64 else 20
        cpus = [
            _MACHO_CPUS.get(_be(sample, 8 + index * width, 4), "unknown CPU")
            for index in range(min(count, 8)) if 8 + index * width + 4 <= len(sample)
        ]
        listed = f": {', '.join(cpus)}" if cpus else ""
        return Signature(_MACHO_UNIVERSAL, f"Mach-O universal binary with {count} architecture(s){listed}")
    major, minor = _be(sample, 6, 2), _be(sample, 4, 2)
    if 45 <= major <= 120:
        release = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4"}.get(major, str(major - 44))
        return Signature(_JAVA_CLASS, f"Java class file, version {major}.{minor} (Java {release})")
    return None


_DEX = _kind("bytecode/dex", "application/octet-stream", "dex")


def _dex(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    version = sample[4:7]
    if len(sample) < 8 or not version.isdigit() or sample[7] != 0:
        return None
    optimized = "optimized " if sample[2:3] == b"y" else ""
    return Signature(_DEX, f"{optimized}Dalvik executable, version {version.decode('ascii')}")


def _version_field(offset: int, width: int, allowed: tuple[int, ...], big: bool = False, describe: str | None = None) -> Check:
    """A check that a version number in the header is one the format defines."""

    def check(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
        if len(sample) < offset + width:
            return None
        value = (_be if big else _le)(sample, offset, width)
        if value not in allowed:
            return None
        return Signature(rule.kind, describe.format(value) if describe else None)

    return check


def _swf(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 8 or not 1 <= sample[3] <= 60:
        return None
    length = _le(sample, 4, 4)
    if sample[:1] == b"F" and size is not None and length != size:
        return None
    if length < 8:
        return None
    compression = {b"F": "uncompressed", b"C": "zlib-compressed", b"Z": "LZMA-compressed"}[sample[:1]]
    return Signature(rule.kind, f"Flash movie, version {sample[3]}, {compression}")


def _pyc(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 8:
        return None
    magic = _le(sample, 0, 2)
    if 3000 <= magic < 4000:
        # Python 3.7+ headers carry flags (0, 1 or 3) where older ones had a timestamp.
        if magic >= 3390 and _le(sample, 4, 4) not in (0, 1, 3):
            return None
        return Signature(rule.kind, f"Python 3 bytecode, magic number {magic}")
    if magic in (62161, 62211):  # Python 2.6 and 2.7; their headers carry a timestamp
        return Signature(rule.kind, f"Python 2 bytecode, magic number {magic}")
    return None


# ---------------------------------------------------------------------------------------
# Archives, packages and compression

_ZIP = _kind("archive/zip", "application/zip", "zip")
_JAR = _kind("archive/jar", "application/java-archive", "zip")
_WAR = _kind("archive/war", "application/java-archive", "zip")
_APK = _kind("package/apk", "application/vnd.android.package-archive", "zip")
_AAR = _kind("package/aar", "application/zip", "zip")
_IPA = _kind("package/ipa", "application/x-ios-app", "zip")
_WHEEL = _kind("package/wheel", "application/x-wheel+zip", "zip")
_NUPKG = _kind("package/nupkg", "application/zip", "zip")
_VSIX = _kind("package/vsix", "application/zip", "zip")
_MSIX = _kind("package/msix", "application/msix", "zip")
_DOCX = _kind("document/docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "zip")
_XLSX = _kind("document/xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "zip")
_PPTX = _kind("document/pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "zip")
_VSDX = _kind("document/vsdx", "application/vnd.ms-visio.drawing.main+xml", "zip")
_OOXML = _kind("document/ooxml", "application/zip", "zip")
_XPS = _kind("document/xps", "application/vnd.ms-xpsdocument", "zip")
_EPUB = _kind("document/epub", "application/epub+zip", "zip")
_ODF = {
    "text": _kind("document/odt", "application/vnd.oasis.opendocument.text", "zip"),
    "spreadsheet": _kind("document/ods", "application/vnd.oasis.opendocument.spreadsheet", "zip"),
    "presentation": _kind("document/odp", "application/vnd.oasis.opendocument.presentation", "zip"),
    "graphics": _kind("document/odg", "application/vnd.oasis.opendocument.graphics", "zip"),
}
_ODF_OTHER = _kind("document/odf", "application/zip", "zip")
# OpenDocument types a package may declare; anything else is a plain ZIP (the declared MIME
# type is content, and only these become metrics keys).
_ODF_TYPES = frozenset({
    "text", "text-template", "text-master", "text-web", "spreadsheet", "spreadsheet-template",
    "presentation", "presentation-template", "graphics", "graphics-template", "chart", "chart-template",
    "formula", "formula-template", "database", "image", "image-template",
})
_PYTORCH = _kind("ml-model/pytorch", "application/zip", "zip")
_NPZ = _kind("dataset/npz", "application/zip", "zip")


def _zip_entries(sample: bytes) -> list[tuple[bytes, int, int, int]]:
    """(name, method, compressed size, data offset) of the local headers in the sample."""
    entries: list[tuple[bytes, int, int, int]] = []
    offset = 0
    while offset + 30 <= len(sample) and sample[offset:offset + 4] == b"PK\x03\x04" and len(entries) < 64:
        flags, method = _le(sample, offset + 6, 2), _le(sample, offset + 8, 2)
        compressed = _le(sample, offset + 18, 4)
        name_length, extra_length = _le(sample, offset + 26, 2), _le(sample, offset + 28, 2)
        name = sample[offset + 30:offset + 30 + name_length]
        if len(name) < name_length:
            break
        data = offset + 30 + name_length + extra_length
        entries.append((name, method, compressed, data))
        if flags & 0x08 or compressed == 0xFFFFFFFF:
            break  # the sizes follow the data, or are in a ZIP64 field: the next header is not locatable
        offset = data + compressed
    return entries


def _zip(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    if not sample.startswith(b"PK\x03\x04"):
        return Signature(_ZIP, "empty ZIP archive" if sample.startswith(b"PK\x05\x06") else "spanned ZIP archive")
    entries = _zip_entries(sample)
    if entries and entries[0][0] == b"mimetype" and entries[0][1] == 0:
        _, _, length, data = entries[0]
        declared = sample[data:data + length] if length <= 128 else b""
        if declared == b"application/epub+zip":
            return Signature(_EPUB, "EPUB e-book")
        prefix = b"application/vnd.oasis.opendocument."
        if declared.startswith(prefix) and declared[len(prefix):].decode("ascii", "replace") in _ODF_TYPES:
            subtype = declared[len(prefix):].decode("ascii")
            kind = _ODF.get(subtype)
            if kind is not None:
                return Signature(kind, f"OpenDocument {subtype}")
            base = _ODF.get(subtype.split("-", 1)[0], _ODF_OTHER)
            return Signature(base, f"OpenDocument {subtype}", declared.decode("ascii"))
    names = [name.lower() for name, *_ in entries]
    present = set(names)

    def any_prefix(prefix: bytes) -> bool:
        return any(name.startswith(prefix) for name in names)

    if present & {b"androidmanifest.xml", b"classes.dex", b"resources.arsc"}:
        if b"classes.jar" in present:
            return Signature(_AAR, "Android library")
        return Signature(_APK, "Android application package")
    if any_prefix(b"payload/") and any(b".app/" in name for name in names):
        return Signature(_IPA, "iOS application archive")
    if present & {b"appxmanifest.xml", b"appxblockmap.xml"}:
        return Signature(_MSIX, "MSIX or AppX package")
    if present & {b"[content_types].xml", b"_rels/.rels"}:
        for prefix, kind, description in (
            (b"word/", _DOCX, "Word document"), (b"xl/", _XLSX, "Excel workbook"),
            (b"ppt/", _PPTX, "PowerPoint presentation"), (b"visio/", _VSDX, "Visio drawing"),
        ):
            if any_prefix(prefix):
                return Signature(kind, f"Office Open XML {description}")
        if any(name.endswith(b".nuspec") for name in names):
            return Signature(_NUPKG, "NuGet package")
        if b"extension.vsixmanifest" in present:
            return Signature(_VSIX, "Visual Studio extension")
        if any_prefix(b"documents/") or b"fixeddocumentsequence.fdseq" in present:
            return Signature(_XPS, "XPS document")
        return Signature(_OOXML, "Office Open XML package; its document part is past the sample")
    if b"meta-inf/manifest.mf" in present or (names and names[0] == b"meta-inf/"):
        if any_prefix(b"web-inf/"):
            return Signature(_WAR, "Java web application archive")
        return Signature(_JAR, "Java archive")
    if any(name == b"data.pkl" or name.endswith((b"/data.pkl", b"/constants.pkl")) for name in names):
        return Signature(_PYTORCH, "PyTorch model or tensors (ZIP serialization)")
    if names and all(name.endswith(b".npy") for name in names):
        return Signature(_NPZ, "NumPy array archive")
    if any(b".dist-info/" in name for name in names):
        return Signature(_WHEEL, "Python wheel")
    return Signature(_ZIP)


def _gzip(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if len(sample) >= 10 and not sample[3] & 0xE0 else None


def _bzip2(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 4 or sample[3:4] not in b"123456789":
        return None
    block = sample[4:10]
    if len(sample) >= 10 and block not in (b"\x31\x41\x59\x26\x53\x59", b"\x17\x72\x45\x38\x50\x90"):
        return None
    return Signature(rule.kind, f"bzip2, {sample[3] - 0x30}00 kB blocks")


def _compress(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if len(sample) >= 3 and 9 <= sample[2] & 0x1F <= 16 else None


def _rar(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if sample[6:7] == b"\x00":
        return Signature(rule.kind, "RAR 4")
    if sample[6:8] == b"\x01\x00":
        return Signature(rule.kind, "RAR 5")
    return None


def _lzma(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 13:
        return None
    dictionary, length = _le(sample, 1, 4), _le(sample, 5, 8)
    power = dictionary & (dictionary - 1) == 0 and 1 << 12 <= dictionary <= 1 << 30
    return Signature(rule.kind) if power and (length == 2**64 - 1 or length < 1 << 42) else None


def _arj(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if len(sample) >= 11 and 1 <= _le(sample, 2, 2) <= 2600 and sample[10] == 2 else None


def _lha(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 7 or sample[5:6] not in b"01234567d" or sample[6:7] != b"-":
        return None
    return Signature(rule.kind, f"LHA -lh{sample[5:6].decode('ascii')}- compression")


def _zstd_skippable(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind, "starts with a skippable frame") if sample[0] & 0xF0 == 0x50 else None


_STATIC_LIBRARY = _kind("library/static", "application/x-archive", "ar")
_DEB = _kind("archive/deb", "application/vnd.debian.binary-package", "ar")


def _ar(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    member = sample[8:24].rstrip(b" ")
    if member.startswith(b"debian-binary"):
        return Signature(_DEB, "Debian package")
    if member in (b"/", b"//", b"/SYM64/", b"__.SYMDEF", b"__.SYMDEF SORTED", b"__.SYMDEF_64"):
        return Signature(_STATIC_LIBRARY, "static library with a symbol table")
    if member.endswith((b".o/", b".o", b".obj/", b".obj")):
        return Signature(_STATIC_LIBRARY, "static library")
    return Signature(rule.kind)


def _cpio(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if sample[:6] == b"070707":
        return Signature(rule.kind, "portable ASCII (odc)") if re.fullmatch(rb"[0-7]{70}", sample[6:76]) else None
    if not re.fullmatch(rb"[0-9A-Fa-f]{104}", sample[6:110]):
        return None
    return Signature(rule.kind, "SVR4 with CRC" if sample[5:6] == b"2" else "SVR4 (newc)")


_TAR = _kind("archive/tar", "application/x-tar", "tar")


def _tar(sample: bytes) -> Signature | None:
    """A tar header, validated by its checksum (V7 archives have no magic number)."""
    if len(sample) < 512:
        return None
    header = sample[:512]
    digits = header[148:156].strip(b" \0")
    if not digits or not all(0x30 <= value <= 0x37 for value in digits):
        return None
    expected = int(digits, 8)
    unsigned = sum(header[:148]) + 8 * 0x20 + sum(header[156:])
    if expected != unsigned:
        high = sum(1 for value in header[:148] + header[156:] if value >= 0x80)
        if expected != unsigned - 256 * high:  # old implementations summed signed chars
            return None
    if header[257:265] == b"ustar\x0000":
        return Signature(_TAR, "POSIX tar (ustar)")
    if header[257:265] == b"ustar  \x00":
        return Signature(_TAR, "GNU tar")
    if header[257:262] == b"ustar":
        return Signature(_TAR, "tar (ustar)")
    if not header[0] or not all(0x30 <= value <= 0x37 or value in (0x20, 0) for value in header[124:136]):
        return None
    return Signature(_TAR, "V7 tar")


# ---------------------------------------------------------------------------------------
# Documents

_PDF = _kind("document/pdf", "application/pdf", "pdf")


def _pdf(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    match = re.search(rb"%PDF-(\d\.\d)", sample[:16])
    return Signature(_PDF, f"PDF {match.group(1).decode('ascii')}" if match else None)


_OLE = _kind("document/ole", "application/x-ole-storage", "ole")
_DOC = _kind("document/doc", "application/msword", "ole")
_XLS = _kind("document/xls", "application/vnd.ms-excel", "ole")
_PPT = _kind("document/ppt", "application/vnd.ms-powerpoint", "ole")
_VSD = _kind("document/vsd", "application/vnd.visio", "ole")
_MSG = _kind("email/msg", "application/vnd.ms-outlook", "ole")
_MSI = _kind("package/msi", "application/x-msi", "ole")
_OFFICE_ENCRYPTED = _kind("document/office-encrypted", "application/x-ole-storage", "ole")
_MSI_CLSIDS = {
    "000c1084-0000-0000-c000-000000000046": "Windows Installer package",
    "000c1086-0000-0000-c000-000000000046": "Windows Installer patch",
    "000c1082-0000-0000-c000-000000000046": "Windows Installer transform",
}
OLE_DIRECTORY_PROBE_BYTES = 4096


def ole_directory(sample: bytes) -> tuple[int, int] | None:
    """(offset, sector size) of an OLE compound file's first directory sector."""
    if len(sample) < 512 or not sample.startswith(_OLE_MAGIC):
        return None
    shift = _le(sample, 30, 2)
    if shift not in (9, 12):
        return None
    first = _le(sample, 48, 4)
    if first >= 0xFFFFFFFA:
        return None
    return (first + 1) << shift, 1 << shift


def _clsid(data: bytes) -> str | None:
    if len(data) != 16:
        return None
    return f"{_le(data, 0, 4):08x}-{_le(data, 4, 2):04x}-{_le(data, 6, 2):04x}-{data[8:10].hex()}-{data[10:16].hex()}"


def _ole(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    location = ole_directory(sample)
    if location is None:
        return Signature(_OLE, "OLE compound file")
    start, sector = location
    window = max(sector, OLE_DIRECTORY_PROBE_BYTES)
    directory = sample[start:start + window] if start + sector <= len(sample) else probes.get(start, b"")
    names: set[str] = set()
    root = None
    for offset in range(0, len(directory) - 127, 128):
        length = _le(directory, offset + 64, 2)
        if 2 <= length <= 64 and not length % 2:
            names.add(directory[offset:offset + length - 2].decode("utf-16-le", "replace"))
        if offset == 0 and directory[offset + 66] == 5:  # the root storage
            root = _clsid(directory[offset + 80:offset + 96])
    if root in _MSI_CLSIDS:
        return Signature(_MSI, _MSI_CLSIDS[root])
    if "EncryptedPackage" in names:
        return Signature(_OFFICE_ENCRYPTED, "encrypted Office document")
    for stream, kind, description in (
        ("WordDocument", _DOC, "Word 97-2003 document"), ("Workbook", _XLS, "Excel 97-2003 workbook"),
        ("Book", _XLS, "Excel 5.0/95 workbook"), ("PowerPoint Document", _PPT, "PowerPoint 97-2003 presentation"),
        ("VisioDocument", _VSD, "Visio 2003-2010 drawing"),
    ):
        if stream in names:
            return Signature(kind, description)
    if any(name.startswith(("__substg1.0_", "__nameid_version1.0")) for name in names):
        return Signature(_MSG, "Outlook message")
    return Signature(_OLE, "OLE compound file" if directory else "OLE compound file; its directory is past the sample")


# ---------------------------------------------------------------------------------------
# Images, audio, video and fonts

def _bmp(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 18 or _le(sample, 6, 4) != 0 or _le(sample, 14, 4) not in (12, 16, 40, 52, 56, 64, 108, 124):
        return None
    return Signature(rule.kind)


def _ico(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 22:
        return None
    count = _le(sample, 4, 2)
    if not 1 <= count <= 255 or sample[9] != 0 or _le(sample, 10, 2) > 1 or _le(sample, 18, 4) < 6 + 16 * count:
        return None
    return Signature(rule.kind, f"icon with {count} image(s)")


_JP2_BRANDS = {
    b"jp2 ": (_kind("image/jp2", "image/jp2", "jpeg2000"), "JPEG 2000 image"),
    b"jpx ": (_kind("image/jpx", "image/jpx", "jpeg2000"), "JPEG 2000 extended image"),
    b"jpm ": (_kind("image/jpm", "image/jpm", "jpeg2000"), "JPEG 2000 compound image"),
    b"mjp2": (_kind("video/mj2", "video/mj2", "jpeg2000"), "Motion JPEG 2000"),
}


def _jp2(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    kind, description = _JP2_BRANDS.get(sample[20:24] if sample[16:20] == b"ftyp" else b"", _JP2_BRANDS[b"jp2 "])
    return Signature(kind, description)


def _pnm(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if not re.match(rb"P[456]\s+(?:#[^\n]{0,200}\n\s*)*\d{1,6}\s+(?:#[^\n]{0,200}\n\s*)*\d{1,6}\s", sample):
        return None
    return Signature(rule.kind)


def _sfnt(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 12:
        return None
    tables, search_range = _be(sample, 4, 2), _be(sample, 6, 2)
    if not 1 <= tables <= 80 or search_range != 16 * (1 << (tables.bit_length() - 1)):
        return None
    return Signature(rule.kind, f"{tables} tables")


def _woff(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if sample[4:8] in (b"\x00\x01\x00\x00", b"OTTO", b"true") else None


def _ttc(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if sample[4:8] in (b"\x00\x01\x00\x00", b"\x00\x02\x00\x00") else None


_MP3 = _kind("audio/mpeg", "audio/mpeg", "mpeg-audio")
_AAC = _kind("audio/aac", "audio/aac", "aac")
_FLAC = _kind("audio/flac", "audio/flac", "flac")
_BITRATES = {
    (3, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),  # MPEG-1 Layer III
    (3, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),  # MPEG-1 Layer II
}
_LOW_BITRATES = (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160)  # MPEG-2 and 2.5
_SAMPLE_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}


def _mpeg_frame(sample: bytes, offset: int = 0) -> tuple[str, int] | None:
    """(description, frame length) of an MPEG audio Layer II/III frame header."""
    header = sample[offset:offset + 4]
    if len(header) < 4 or header[0] != 0xFF or header[1] & 0xE0 != 0xE0:
        return None
    version, layer = (header[1] >> 3) & 3, (header[1] >> 1) & 3  # layer: 1 = III, 2 = II
    bitrate_index, rate_index = header[2] >> 4, (header[2] >> 2) & 3
    # Reserved version, Layer I (FF FE is also a UTF-16 byte-order mark) and reserved fields.
    if version == 1 or layer not in (1, 2) or bitrate_index in (0, 15) or rate_index == 3:
        return None
    layer_number = 4 - layer
    bitrate = (_BITRATES.get((version, layer_number)) or _LOW_BITRATES)[bitrate_index]
    rate = _SAMPLE_RATES[version][rate_index]
    factor = 72 if layer_number == 3 and version != 3 else 144
    length = factor * bitrate * 1000 // rate + ((header[2] >> 1) & 1)
    name = {3: "MPEG-1", 2: "MPEG-2", 0: "MPEG-2.5"}[version]
    return f"{name} Layer {'III' if layer_number == 3 else 'II'}, {bitrate} kbit/s, {rate} Hz", length


def _adts(sample: bytes, offset: int = 0) -> int | None:
    """The frame length of an AAC ADTS header."""
    header = sample[offset:offset + 7]
    if len(header) < 7 or header[0] != 0xFF or header[1] & 0xF6 != 0xF0 or (header[2] >> 2) & 0xF > 12:
        return None
    length = ((header[3] & 3) << 11) | (header[4] << 3) | (header[5] >> 5)
    return length if length >= 7 else None


def _mpeg_audio(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    """MPEG audio or ADTS AAC from frame sync, confirmed by the next frame when sampled."""
    frame = _mpeg_frame(sample)
    if frame is not None:
        description, length = frame
        if length + 4 <= len(sample) and _mpeg_frame(sample, length) is None:
            return None
        return Signature(_MP3, description)
    length = _adts(sample)
    if length is None or (length + 7 <= len(sample) and _adts(sample, length) is None):
        return None
    return Signature(_AAC, "AAC (ADTS)")


def _id3(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 10 or sample[3] not in (2, 3, 4) or sample[4] == 0xFF or any(value & 0x80 for value in sample[6:10]):
        return None
    end = 10 + ((sample[6] << 21) | (sample[7] << 14) | (sample[8] << 7) | sample[9])
    tag = f"ID3v2.{sample[3]} tag"
    if sample[end:end + 4] == b"fLaC":
        return Signature(_FLAC, f"FLAC with an {tag}")
    if _adts(sample, end) is not None:
        return Signature(_AAC, f"AAC (ADTS) with an {tag}")
    return Signature(_MP3, f"MPEG audio with an {tag}")


def _flac(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if len(sample) >= 8 and not sample[4] & 0x7F and sample[5:8] == b"\x00\x00\x22" else None


_OGG_AUDIO = _kind("audio/ogg", "audio/ogg", "ogg")
_OGG_VIDEO = _kind("video/ogg", "video/ogg", "ogg")
_OGG_CODECS = (
    (b"\x01vorbis", _OGG_AUDIO, "Vorbis"), (b"OpusHead", _OGG_AUDIO, "Opus"), (b"\x7fFLAC", _OGG_AUDIO, "FLAC"),
    (b"Speex   ", _OGG_AUDIO, "Speex"), (b"\x80theora", _OGG_VIDEO, "Theora"), (b"fishead\x00", _OGG_VIDEO, "skeleton"),
    (b"\x01video\x00\x00\x00", _OGG_VIDEO, "OGM video"),
)


def _ogg(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 28 or sample[4] != 0:
        return None
    packet = 27 + sample[26]
    for prefix, kind, codec in _OGG_CODECS:
        if sample[packet:packet + len(prefix)] == prefix:
            return Signature(kind, f"Ogg {codec}")
    return Signature(_OGG_AUDIO, "Ogg container", "application/ogg")


def _au(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if len(sample) >= 16 and _be(sample, 4, 4) >= 24 and 1 <= _be(sample, 12, 4) <= 27 else None


_MP4 = _kind("video/mp4", "video/mp4", "iso-bmff")
_QUICKTIME = _kind("video/quicktime", "video/quicktime", "iso-bmff")
_M4A = _kind("audio/mp4", "audio/mp4", "iso-bmff")
_3GP = _kind("video/3gpp", "video/3gpp", "iso-bmff")
_3G2 = _kind("video/3gpp2", "video/3gpp2", "iso-bmff")
_HEIC = _kind("image/heic", "image/heic", "iso-bmff")
_HEIC_SEQUENCE = _kind("image/heic-sequence", "image/heic-sequence", "iso-bmff")
_HEIF = _kind("image/heif", "image/heif", "iso-bmff")
_HEIF_SEQUENCE = _kind("image/heif-sequence", "image/heif-sequence", "iso-bmff")
_AVIF = _kind("image/avif", "image/avif", "iso-bmff")
_CR3 = _kind("image/x-canon-cr3", "image/x-canon-cr3", "iso-bmff")
_BRANDS: dict[bytes, tuple[Kind, str, str | None]] = {
    b"qt  ": (_QUICKTIME, "QuickTime movie", None),
    b"M4A ": (_M4A, "MPEG-4 audio", None), b"M4B ": (_M4A, "MPEG-4 audiobook", None),
    b"M4P ": (_M4A, "protected MPEG-4 audio", None),
    **{brand: (_MP4, "M4V video", "video/x-m4v") for brand in (b"M4V ", b"M4VH", b"M4VP")},
    **{brand: (_3GP, "3GPP media", None) for brand in (b"3gp4", b"3gp5", b"3gp6", b"3gp7", b"3gs7", b"3ge6", b"3ge7", b"3gg6")},
    **{brand: (_3G2, "3GPP2 media", None) for brand in (b"3g2a", b"3g2b", b"3g2c")},
    **{brand: (_HEIC, "HEIC image", None) for brand in (b"heic", b"heix", b"heim", b"heis")},
    **{brand: (_HEIC_SEQUENCE, "HEIC image sequence", None) for brand in (b"hevc", b"hevx", b"hevm", b"hevs")},
    b"mif1": (_HEIF, "HEIF image", None), b"msf1": (_HEIF_SEQUENCE, "HEIF image sequence", None),
    b"avif": (_AVIF, "AVIF image", None), b"avis": (_AVIF, "AVIF image sequence", None),
    b"crx ": (_CR3, "Canon CR3 raw image", None),
    b"f4v ": (_MP4, "Flash MP4 video", "video/x-f4v"),
    b"mjp2": (_JP2_BRANDS[b"mjp2"][0], "Motion JPEG 2000", None),
}
_BRAND_TEXT = re.compile(rb"[A-Za-z0-9 ._+-]{4}")


def _ftyp(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    """ISO base media (MP4, QuickTime, HEIF, AVIF, 3GP...) by the ftyp box brands."""
    if len(sample) < 16:
        return None
    box, major = _be(sample, 0, 4), sample[8:12]
    if box < 16 or not _BRAND_TEXT.fullmatch(major):
        return None
    compatible = {sample[offset:offset + 4] for offset in range(16, min(box, len(sample), 256) - 3, 4)}
    if major in (b"mif1", b"msf1"):
        sequence = major == b"msf1"
        if compatible & {b"avif", b"avis"}:
            major = b"avis" if sequence else b"avif"
        elif compatible & {b"heic", b"heix", b"hevc", b"hevx"}:
            major = b"hevc" if sequence else b"heic"
    entry = _BRANDS.get(major)
    if entry is None:
        return Signature(_MP4, f"ISO base media file, major brand '{major.decode('ascii').strip()}'")
    kind, description, mime = entry
    return Signature(kind, description, mime)


def _quicktime_atom(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    box = _be(sample, 0, 4)
    if box in (0, 1) or (8 <= box and (size is None or box <= size)):
        return Signature(_QUICKTIME, "QuickTime movie")
    return None


_MATROSKA = _kind("video/x-matroska", "video/x-matroska", "ebml")
_WEBM = _kind("video/webm", "video/webm", "ebml")


def _ebml(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    position = sample.find(b"\x42\x82", 4, 64)  # the DocType element
    if position != -1 and position + 3 <= len(sample) and sample[position + 2] & 0x80:
        doctype = sample[position + 3:position + 3 + (sample[position + 2] & 0x7F)]
        if doctype == b"webm":
            return Signature(_WEBM, "WebM")
        if doctype == b"matroska":
            return Signature(_MATROSKA, "Matroska")
        if re.fullmatch(rb"[A-Za-z0-9_.-]{1,32}", doctype):
            return Signature(_MATROSKA, f"EBML document type '{doctype.decode('ascii')}'")
    return Signature(_MATROSKA, "EBML (Matroska family)")


def _transport_stream(stride: int, first: int) -> Check:
    def check(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
        if any(sample[offset] != 0x47 for offset in range(first, len(sample), stride)):
            return None
        return Signature(rule.kind, "MPEG-2 transport stream" if first == 0 else "BDAV MPEG-2 transport stream")

    return check


def _realmedia(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    return Signature(rule.kind) if len(sample) >= 8 and _be(sample, 4, 4) >= 10 else None


# ---------------------------------------------------------------------------------------
# Databases, datasets and machine-learning models

def _safetensors(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    length = _le(sample, 0, 8)
    if not 2 <= length <= 100 * 1024 * 1024 or (size is not None and 8 + length > size):
        return None
    if sample[9:10] not in (b'"', b" ", b"\n", b"\r", b"\t", b"}"):
        return None
    if b'"dtype"' not in sample and b'"__metadata__"' not in sample and sample[8:10] != b"{}":
        return None
    return Signature(rule.kind, f"safetensors, {length:,}-byte header")


_PICKLE = _kind("data/pickle", "application/octet-stream", "pickle")
_PYTORCH_LEGACY = _kind("ml-model/pytorch-legacy", "application/octet-stream", "pickle")
# The pickled magic number that legacy (pre-1.6) torch.save files begin with.
_TORCH_LEGACY_MAGIC = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19"
_PICKLE_OPENERS = frozenset(b"}])(cqKMJNXU\x88\x89\x8aG\x8c")


def _pickle(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if sample.startswith(_TORCH_LEGACY_MAGIC):
        return Signature(_PYTORCH_LEGACY, "legacy PyTorch serialization (pickle)")
    if len(sample) < 3 or sample[1] not in (2, 3, 4, 5):
        return None
    if sample[1] >= 4 and sample[2] != 0x95 or sample[1] < 4 and sample[2] not in _PICKLE_OPENERS:
        return None
    return Signature(_PICKLE, f"Python pickle, protocol {sample[1]}")


# ---------------------------------------------------------------------------------------
# Firmware, filesystems and disk images

_ISO = _kind("disk-image/iso9660", "application/x-iso9660-image", "iso9660")
_UDF = _kind("disk-image/udf", "application/octet-stream", "udf")
_MBR = _kind("disk-image/mbr", "application/x-raw-disk-image", "partitioned")
_GPT = _kind("disk-image/gpt", "application/x-raw-disk-image", "partitioned")
_FAT = _kind("filesystem/fat", "application/octet-stream", "fat")
_NTFS = _kind("filesystem/ntfs", "application/octet-stream", "ntfs")
_EXFAT = _kind("filesystem/exfat", "application/octet-stream", "exfat")
_EXT = {name: _kind(f"filesystem/{name}", "application/octet-stream", "ext") for name in ("ext2", "ext3", "ext4")}


def _volume_descriptor(probes: Mapping[int, bytes], hybrid: str = "") -> Signature | None:
    data = probes.get(ISO_DESCRIPTOR_OFFSET, b"")
    if data[1:6] == b"CD001" and data[:1] in (b"\x00", b"\x01", b"\x02", b"\x03", b"\xff"):
        return Signature(_ISO, f"ISO 9660 image{hybrid}")
    if data[1:6] in (b"BEA01", b"NSR02", b"NSR03"):
        return Signature(_UDF, f"UDF image{hybrid}")
    return None


def _gpt(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature:
    return _volume_descriptor(probes, " (hybrid, GPT)") or Signature(_GPT, "GUID partition table")


def _boot_sector(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if sample[3:11] == b"NTFS    ":
        return Signature(_NTFS, "NTFS volume")
    if sample[3:11] == b"EXFAT   ":
        return Signature(_EXFAT, "exFAT volume")
    if sample[:1] in (b"\xeb", b"\xe9"):
        for offset, name in ((82, b"FAT32   "), (54, b"FAT16   "), (54, b"FAT12   "), (54, b"FAT     ")):
            if sample[offset:offset + 8] == name:
                return Signature(_FAT, f"{name.decode('ascii').strip()} volume")
    iso = _volume_descriptor(probes, " (hybrid, MBR)")
    if iso is not None:
        return iso
    entries = [sample[offset:offset + 16] for offset in range(446, 510, 16)]
    if all(entry[0] in (0, 0x80) for entry in entries) and any(entry[4] for entry in entries):
        return Signature(_MBR, "MBR partition table")
    return None


def _ext(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    base = 1024
    if len(sample) < base + 104 or not _le(sample, base, 4) or not _le(sample, base + 4, 4):
        return None
    if _le(sample, base + 24, 4) > 6 or _le(sample, base + 76, 4) > 1:
        return None
    compat, incompat, ro_compat = _le(sample, base + 92, 4), _le(sample, base + 96, 4), _le(sample, base + 100, 4)
    if incompat & (0x40 | 0x80 | 0x200) or ro_compat & (0x8 | 0x10 | 0x20 | 0x40 | 0x400):
        name = "ext4"
    elif compat & 0x4:
        name = "ext3"
    else:
        name = "ext2"
    return Signature(_EXT[name], f"{name} filesystem")


def _dtb(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 28 or _be(sample, 4, 4) < 40:
        return None
    version, compatible = _be(sample, 20, 4), _be(sample, 24, 4)
    return Signature(rule.kind, f"device tree blob, version {version}") if 1 <= version <= 17 and compatible <= version else None


def _jffs2(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    node = (_le if sample[:1] == b"\x85" else _be)(sample, 2, 2)
    return Signature(rule.kind) if node in (0xE001, 0xE002, 0x2003, 0x2004, 0x2006, 0xE008, 0xE009) else None


def _squashfs(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if len(sample) < 32:
        return None
    major = (_le if sample[:4] == b"hsqs" else _be)(sample, 28, 2)
    return Signature(rule.kind, f"SquashFS {major}") if major in (1, 2, 3, 4) else None


def _xfs(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    block = _be(sample, 4, 4)
    return Signature(rule.kind) if 512 <= block <= 65536 and not block & (block - 1) else None


def _luks(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    version = _be(sample, 6, 2)
    return Signature(rule.kind, f"LUKS{version} encrypted volume") if version in (1, 2) else None


# ---------------------------------------------------------------------------------------
# Text formats (recognized in samples that are text)

_SCRIPTS = {
    name: _kind(f"script/{name}", mime, "script", text=True)
    for name, mime in (
        ("shell", "text/x-shellscript"), ("python", "text/x-python"), ("perl", "text/x-perl"),
        ("ruby", "text/x-ruby"), ("javascript", "text/javascript"), ("php", "application/x-httpd-php"),
        ("lua", "text/x-lua"), ("r", "text/x-r"), ("powershell", "text/plain"), ("awk", "text/x-awk"),
        ("tcl", "text/x-tcl"), ("other", "text/plain"),
    )
}
_INTERPRETERS = {
    **dict.fromkeys(("sh", "bash", "dash", "ash", "ksh", "mksh", "zsh", "fish", "busybox"), "shell"),
    **dict.fromkeys(("python", "pypy"), "python"), "perl": "perl", "ruby": "ruby",
    **dict.fromkeys(("node", "nodejs", "deno", "bun"), "javascript"), "php": "php",
    **dict.fromkeys(("lua", "luajit"), "lua"), "rscript": "r", **dict.fromkeys(("pwsh", "powershell"), "powershell"),
    **dict.fromkeys(("awk", "gawk", "mawk", "nawk"), "awk"), **dict.fromkeys(("tclsh", "wish"), "tcl"),
}
_LFS = _kind("vcs/git-lfs-pointer", "text/plain", "git-lfs", text=True)
_PEM = _kind("crypto/pem", "application/x-pem-file", "pem", text=True)
_PUTTY = _kind("crypto/putty-key", "text/plain", "putty", text=True)
_POSTSCRIPT = _kind("document/postscript", "application/postscript", "postscript", text=True)
_RTF = _kind("document/rtf", "application/rtf", "rtf", text=True)
_SVG = _kind("image/svg", "image/svg+xml", "svg", text=True)
_INTEL_HEX = _kind("firmware/intel-hex", "text/plain", "intel-hex", text=True)
_SREC = _kind("firmware/srec", "text/plain", "srec", text=True)
_SHEBANG = re.compile(r"#![ \t]*+(\S{1,200})([^\r\n]{0,300})")
_PEM_BEGIN = re.compile(r"\s{0,64}-----BEGIN ([A-Z0-9 ]{1,48})-----")
# The root element of an SVG document, optionally namespace-prefixed.
_SVG_ROOT = re.compile(r"<(?:[A-Za-z_][\w.-]{0,32}:)?svg[\s>/]")
_SVG_PROLOG_ITEMS = 20
_HEX_RECORD = re.compile(r":[0-9A-Fa-f]{10,520}")
_SREC_RECORD = re.compile(r"S[0-35-9][0-9A-Fa-f]{6,520}")


def _script(line: str) -> Signature | None:
    match = _SHEBANG.match(line)
    if not match:
        return None
    name = match.group(1).rsplit("/", 1)[-1]
    if name == "env":
        arguments = [token for token in match.group(2).split() if not token.startswith("-") and "=" not in token]
        if not arguments:
            return Signature(_SCRIPTS["other"], "#! env")
        name = arguments[0].rsplit("/", 1)[-1]
    # python3.12 -> python; rstrip, not a regex: [\d.]+$ is quadratic on long digit runs.
    family = _INTERPRETERS.get(name.lower().rstrip("0123456789."), "other")
    interpreter = re.sub(r"[^\w.+-]", "?", name)[:40]  # content: only name characters are kept
    return Signature(_SCRIPTS[family], f"#! {interpreter}")


def _starts_with_svg(text: str) -> bool:
    """Whether the first element after the prolog (an XML declaration, comments, a doctype,
    processing instructions) is an <svg> root.

    Scanned rather than matched: a regex with a repeated comment group lets each comment run
    past its own --> to a later one, which backtracks exponentially on text full of comments.
    """
    position = 0
    for _ in range(_SVG_PROLOG_ITEMS + 1):
        position = len(text) - len(text[position:].lstrip())
        if text.startswith("<!--", position):
            end, skip = text.find("-->", position + 4), 3
        elif text.startswith("<?", position):
            end, skip = text.find("?>", position + 2), 2
        elif text.startswith(("<!DOCTYPE", "<!doctype"), position):
            end, skip = text.find(">", position), 1
        else:
            return _SVG_ROOT.match(text, position) is not None
        if end == -1:
            return False
        position = end + skip
    return False


def _hex_records(lines: list[str]) -> bool:
    for line in lines:
        if not _HEX_RECORD.fullmatch(line) or len(line) % 2 != 1:
            return False
        data = bytes.fromhex(line[1:])
        if len(data) != data[0] + 5 or sum(data) & 0xFF or data[3] > 5:
            return False
    return True


def _srec_records(lines: list[str]) -> bool:
    for line in lines:
        if not _SREC_RECORD.fullmatch(line) or len(line) % 2:
            return False
        data = bytes.fromhex(line[2:])
        if len(data) != data[0] + 1 or sum(data) & 0xFF != 0xFF:
            return False
    return True


def detect_text(sample: bytes, size: int | None = None) -> Signature | None:
    """The text format of a sample that is text: script, PEM, PostScript, SVG, HEX..."""
    encoding = text_encoding(sample)
    text = sample.decode("utf-8" if encoding == "utf-8" else encoding, errors="replace").lstrip("﻿")
    if text.startswith(("version https://git-lfs.github.com/spec/v1", "version https://hawser.github.com/spec/v1")):
        if "\noid sha256:" in text and "\nsize " in text and (size is None or size < 1024):
            return Signature(_LFS, "Git LFS pointer")
    if text.startswith("#!"):
        return _script(text[:512])
    if text.startswith("%!PS"):
        first = text.split("\n", 1)[0]
        return Signature(_POSTSCRIPT, "Encapsulated PostScript" if "EPSF" in first else "PostScript")
    if text.startswith("{\\rtf"):
        return Signature(_RTF, "Rich Text Format")
    if text.startswith("PuTTY-User-Key-File-"):
        return Signature(_PUTTY, "PuTTY private key")
    pem = _PEM_BEGIN.match(text)
    if pem:
        return Signature(_PEM, f"PEM {pem.group(1)}")
    if "<" in text[:512] and _starts_with_svg(text):
        return Signature(_SVG, "SVG image")
    # Firmware records: the complete lines of the sample, at most four, must all check out.
    first = text.lstrip()[:1]
    if first not in (":", "S"):
        return None
    lines = text.splitlines()
    if len(sample) == SAMPLE_BYTES and not text.endswith(("\n", "\r")):
        lines = lines[:-1]
    lines = [line.strip() for line in lines if line.strip()][:4]
    if lines and first == ":" and _hex_records(lines):
        return Signature(_INTEL_HEX, "Intel HEX records")
    if lines and first == "S" and _srec_records(lines):
        return Signature(_SREC, "Motorola S-records")
    return None


# ---------------------------------------------------------------------------------------
# The rule table

def _rule(label: str, mime: str, *tests: tuple[int, bytes], family: str | None = None,
          check: Check | None = None, binary: bool = False) -> Rule:
    return Rule(_kind(label, mime, family), tuple(tests), check, binary)


def _accept(rule: Rule, sample: bytes, size: int | None, probes: Mapping[int, bytes]) -> Signature | None:
    if rule.binary and looks_textual(sample):
        return None
    return Signature(rule.kind) if rule.check is None else rule.check(rule, sample, size, probes)


_HDF5 = b"\x89HDF\r\n\x1a\n"
_X = "application/octet-stream"

# Rules whose tests all start past offset 0 come last: they are candidates for every sample.
RULES: tuple[Rule, ...] = (
    # Executables, libraries and bytecode
    _rule("executable/elf", "application/x-executable", (0, b"\x7fELF"), family="elf", check=_elf),
    _rule("executable/pe", "application/vnd.microsoft.portable-executable", (0, b"MZ"), family="mz", check=_mz),
    *(_rule("executable/mach-o", "application/x-mach-binary", (0, magic), check=_macho)
      for magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")),
    _rule("executable/mach-o-universal", "application/x-mach-binary", (0, b"\xca\xfe\xba\xbe"), family="mach-o", check=_cafebabe),
    _rule("executable/mach-o-universal", "application/x-mach-binary", (0, b"\xca\xfe\xba\xbf"), family="mach-o", check=_cafebabe),
    _rule("bytecode/dex", _X, (0, b"dex\n"), check=_dex),
    _rule("bytecode/dex", _X, (0, b"dey\n"), check=_dex),
    _rule("bytecode/wasm", "application/wasm", (0, b"\x00asm"),
          check=_version_field(4, 4, (1,), describe="WebAssembly module, version {}")),
    _rule("bytecode/lua", "application/x-lua-bytecode", (0, b"\x1bLua")),
    _rule("bytecode/llvm-bitcode", _X, (0, b"BC\xc0\xde")),
    _rule("bytecode/llvm-bitcode", _X, (0, b"\xde\xc0\x17\x0b")),
    _rule("bytecode/spir-v", _X, (0, b"\x03\x02\x23\x07")),
    _rule("bytecode/spir-v", _X, (0, b"\x07\x23\x02\x03")),
    *(_rule("bytecode/swf", "application/vnd.adobe.flash.movie", (0, magic), check=_swf, binary=True)
      for magic in (b"FWS", b"CWS", b"ZWS")),
    # Archives, packages and compression
    *(_rule("archive/zip", "application/zip", (0, magic), check=_zip) for magic in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    _rule("archive/gzip", "application/gzip", (0, b"\x1f\x8b\x08"), check=_gzip),
    _rule("archive/bzip2", "application/x-bzip2", (0, b"BZh"), check=_bzip2),
    _rule("archive/xz", "application/x-xz", (0, b"\xfd7zXZ\x00")),
    _rule("archive/zstandard", "application/zstd", (0, b"\x28\xb5\x2f\xfd")),
    _rule("archive/lz4", "application/x-lz4", (0, b"\x04\x22\x4d\x18")),
    _rule("archive/lz4", "application/x-lz4", (0, b"\x02\x21\x4c\x18")),
    _rule("archive/lzip", "application/x-lzip", (0, b"LZIP"), check=_version_field(4, 1, (0, 1))),
    _rule("archive/lzop", "application/x-lzop", (0, b"\x89LZO\x00\r\n\x1a\n")),
    _rule("archive/unix-compress", "application/x-compress", (0, b"\x1f\x9d"), family="compress", check=_compress),
    _rule("archive/7z", "application/x-7z-compressed", (0, b"7z\xbc\xaf\x27\x1c")),
    _rule("archive/rar", "application/vnd.rar", (0, b"Rar!\x1a\x07"), check=_rar),
    _rule("archive/cab", "application/vnd.ms-cab-compressed", (0, b"MSCF\x00\x00\x00\x00")),
    _rule("archive/installshield-cab", _X, (0, b"ISc(")),
    _rule("archive/ar", "application/x-archive", (0, b"!<arch>\n"), check=_ar),
    _rule("library/static", "application/x-archive", (0, b"!<thin>\n"), family="ar"),
    _rule("archive/rpm", "application/x-rpm", (0, b"\xed\xab\xee\xdb"), check=_version_field(4, 1, (3, 4))),
    *(_rule("archive/cpio", "application/x-cpio", (0, magic), check=_cpio) for magic in (b"070701", b"070702", b"070707")),
    _rule("archive/xar", "application/x-xar", (0, b"xar!"), check=_version_field(4, 2, (28,), big=True)),
    _rule("archive/wim", "application/x-ms-wim", (0, b"MSWIM\x00\x00\x00")),
    _rule("archive/arj", "application/x-arj", (0, b"\x60\xea"), check=_arj),
    _rule("archive/lzma", "application/x-lzma", (0, b"\x5d\x00\x00"), check=_lzma),
    _rule("package/crx", "application/x-chrome-extension", (0, b"Cr24"), check=_version_field(4, 4, (2, 3))),
    # Documents
    _rule("document/pdf", "application/pdf", (0, b"%PDF-"), check=_pdf),
    _rule("document/pdf", "application/pdf", (0, b"\xef\xbb\xbf%PDF-"), check=_pdf),
    _rule("document/ole", "application/x-ole-storage", (0, _OLE_MAGIC), check=_ole),
    _rule("document/djvu", "image/vnd.djvu", (0, b"AT&TFORM"), (12, b"DJV")),
    _rule("document/chm", "application/vnd.ms-htmlhelp", (0, b"ITSF"), check=_version_field(4, 4, (2, 3))),
    # Images
    _rule("image/png", "image/png", (0, b"\x89PNG\r\n\x1a\n")),
    _rule("image/jpeg", "image/jpeg", (0, b"\xff\xd8\xff")),
    _rule("image/jp2", "image/jp2", (0, b"\xff\x4f\xff\x51"), family="jpeg2000"),
    _rule("image/jxl", "image/jxl", (0, b"\xff\x0a")),
    _rule("image/jxl", "image/jxl", (0, b"\x00\x00\x00\x0cJXL \r\n\x87\n")),
    _rule("image/jp2", "image/jp2", (0, b"\x00\x00\x00\x0cjP  \r\n\x87\n"), family="jpeg2000", check=_jp2),
    _rule("image/gif", "image/gif", (0, b"GIF87a")),
    _rule("image/gif", "image/gif", (0, b"GIF89a")),
    _rule("image/bmp", "image/bmp", (0, b"BM"), check=_bmp),
    _rule("image/x-canon-cr2", "image/x-canon-cr2", (0, b"II*\x00"), (8, b"CR"), family="tiff"),
    _rule("image/x-olympus-orf", "image/x-olympus-orf", (0, b"IIRO"), family="tiff"),
    _rule("image/x-olympus-orf", "image/x-olympus-orf", (0, b"IIRS"), family="tiff"),
    _rule("image/x-panasonic-rw2", "image/x-panasonic-rw2", (0, b"IIU\x00"), family="tiff"),
    *(_rule("image/tiff", "image/tiff", (0, magic)) for magic in (b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")),
    _rule("image/webp", "image/webp", (0, b"RIFF"), (8, b"WEBP"), family="riff"),
    _rule("image/vnd.microsoft.icon", "image/vnd.microsoft.icon", (0, b"\x00\x00\x01\x00"), family="ico", check=_ico),
    _rule("image/vnd.adobe.photoshop", "image/vnd.adobe.photoshop", (0, b"8BPS"), family="psd",
          check=_version_field(4, 2, (1, 2), big=True)),
    _rule("image/qoi", "image/qoi", (0, b"qoif")),
    _rule("image/x-exr", "image/x-exr", (0, b"\x76\x2f\x31\x01"), family="exr"),
    _rule("image/vnd.ms-dds", "image/vnd.ms-dds", (0, b"DDS "), family="dds"),
    _rule("image/ktx", "image/ktx", (0, b"\xabKTX 11\xbb\r\n\x1a\n")),
    _rule("image/ktx2", "image/ktx2", (0, b"\xabKTX 20\xbb\r\n\x1a\n")),
    _rule("image/vnd.radiance", "image/vnd.radiance", (0, b"#?RADIANCE"), family="radiance"),
    _rule("image/vnd.radiance", "image/vnd.radiance", (0, b"#?RGBE"), family="radiance"),
    _rule("image/x-xcf", "image/x-xcf", (0, b"gimp xcf "), family="xcf"),
    _rule("image/icns", "image/icns", (0, b"icns")),
    _rule("image/wmf", "image/wmf", (0, b"\xd7\xcd\xc6\x9a")),
    _rule("image/emf", "image/emf", (0, b"\x01\x00\x00\x00"), (40, b" EMF")),
    *(_rule(f"image/x-portable-{name}", f"image/x-portable-{name}", (0, magic), family="pnm", check=_pnm, binary=True)
      for magic, name in ((b"P4", "bitmap"), (b"P5", "graymap"), (b"P6", "pixmap"))),
    # Audio and video
    _rule("audio/wav", "audio/wav", (0, b"RIFF"), (8, b"WAVE"), family="riff"),
    _rule("audio/wav", "audio/wav", (0, b"RF64"), (8, b"WAVE"), family="riff"),
    _rule("audio/wav", "audio/wav", (0, b"RIFX"), (8, b"WAVE"), family="riff"),
    _rule("video/x-msvideo", "video/x-msvideo", (0, b"RIFF"), (8, b"AVI "), family="riff"),
    _rule("audio/midi", "audio/midi", (0, b"RIFF"), (8, b"RMID"), family="midi"),
    _rule("audio/aiff", "audio/aiff", (0, b"FORM"), (8, b"AIFF")),
    _rule("audio/aiff", "audio/aiff", (0, b"FORM"), (8, b"AIFC")),
    _rule("audio/mpeg", "audio/mpeg", (0, b"ID3"), family="mpeg-audio", check=_id3),
    _rule("audio/flac", "audio/flac", (0, b"fLaC"), check=_flac),
    _rule("audio/ogg", "audio/ogg", (0, b"OggS"), check=_ogg),
    _rule("audio/midi", "audio/midi", (0, b"MThd"), (4, b"\x00\x00\x00\x06")),
    _rule("audio/basic", "audio/basic", (0, b".snd"), family="au", check=_au),
    _rule("audio/amr-wb", "audio/amr-wb", (0, b"#!AMR-WB\n"), family="amr"),
    _rule("audio/amr", "audio/amr", (0, b"#!AMR\n")),
    _rule("audio/x-ape", "audio/x-ape", (0, b"MAC "), family="ape", binary=True),
    _rule("audio/x-wavpack", "audio/x-wavpack", (0, b"wvpk"), family="wavpack"),
    _rule("audio/x-caf", "audio/x-caf", (0, b"caff"), (4, b"\x00\x01"), family="caf"),
    _rule("audio/x-dsf", "audio/x-dsf", (0, b"DSD "), (4, b"\x1c\x00\x00\x00\x00\x00\x00\x00"), family="dsf"),
    _rule("video/x-matroska", "video/x-matroska", (0, b"\x1a\x45\xdf\xa3"), family="ebml", check=_ebml),
    _rule("video/x-flv", "video/x-flv", (0, b"FLV\x01"), family="flv"),
    _rule("video/mpeg", "video/mpeg", (0, b"\x00\x00\x01\xba")),
    _rule("video/mpeg", "video/mpeg", (0, b"\x00\x00\x01\xb3")),
    _rule("video/x-ms-asf", "video/x-ms-asf", (0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"),
          family="asf"),
    _rule("video/realmedia", "application/vnd.rn-realmedia", (0, b".RMF"), check=_realmedia),
    _rule("video/mxf", "application/mxf", (0, b"\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02\x01\x01\x02")),
    _rule("video/mp2t", "video/mp2t", (0, b"G"), (188, b"G"), (376, b"G"), check=_transport_stream(188, 0)),
    # Fonts
    _rule("font/woff", "font/woff", (0, b"wOFF"), check=_woff),
    _rule("font/woff2", "font/woff2", (0, b"wOF2"), check=_woff),
    _rule("font/otf", "font/otf", (0, b"OTTO"), family="sfnt", check=_sfnt),
    _rule("font/ttf", "font/ttf", (0, b"\x00\x01\x00\x00"), family="sfnt", check=_sfnt),
    _rule("font/ttf", "font/ttf", (0, b"true"), family="sfnt", check=_sfnt),
    _rule("font/collection", "font/collection", (0, b"ttcf"), family="sfnt", check=_ttc),
    _rule("font/type1", "application/x-font-type1", (0, b"\x80\x01"), (6, b"%!PS-AdobeFont")),
    # Databases and datasets
    _rule("database/sqlite", "application/vnd.sqlite3", (0, b"SQLite format 3\x00")),
    _rule("database/sqlite-wal", _X, (0, b"\x37\x7f\x06\x82")),
    _rule("database/sqlite-wal", _X, (0, b"\x37\x7f\x06\x83")),
    _rule("dataset/matlab", "application/x-matlab-data", (0, b"MATLAB 7.3 MAT-file")),
    _rule("dataset/matlab", "application/x-matlab-data", (0, b"MATLAB 5.0 MAT-file")),
    _rule("dataset/hdf5", "application/x-hdf5", (0, _HDF5)),
    _rule("dataset/hdf4", "application/x-hdf", (0, b"\x0e\x03\x13\x01")),
    _rule("dataset/npy", _X, (0, b"\x93NUMPY"),
          check=_version_field(6, 1, (1, 2, 3), describe="NumPy array, format version {}")),
    _rule("dataset/parquet", "application/vnd.apache.parquet", (0, b"PAR1"), binary=True),
    _rule("dataset/arrow", "application/vnd.apache.arrow.file", (0, b"ARROW1\x00\x00")),
    _rule("dataset/feather", _X, (0, b"FEA1"), binary=True),
    _rule("dataset/avro", _X, (0, b"Obj\x01")),
    _rule("dataset/orc", _X, (0, b"ORC"), binary=True),
    *(_rule("dataset/netcdf", "application/x-netcdf", (0, magic)) for magic in (b"CDF\x01", b"CDF\x02", b"CDF\x05")),
    _rule("dataset/fits", "application/fits", (0, b"SIMPLE  =")),
    # Machine-learning models
    _rule("ml-model/gguf", _X, (0, b"GGUF"), check=_version_field(4, 4, (1, 2, 3), describe="GGUF version {}")),
    *(_rule("ml-model/ggml", _X, (0, magic)) for magic in (b"lmgg", b"fmgg", b"tjgg")),
    # Firmware, filesystems and disk images
    _rule("firmware/uimage", _X, (0, b"\x27\x05\x19\x56")),
    _rule("firmware/device-tree", _X, (0, b"\xd0\x0d\xfe\xed"), check=_dtb),
    _rule("firmware/android-boot", _X, (0, b"ANDROID!")),
    _rule("firmware/android-vendor-boot", _X, (0, b"VNDRBOOT")),
    _rule("firmware/uf2", _X, (0, b"UF2\n"), (4, b"\x57\x51\x5d\x9e")),
    _rule("firmware/trx", _X, (0, b"HDR0"), binary=True),
    _rule("disk-image/android-sparse", _X, (0, b"\x3a\xff\x26\xed")),
    _rule("filesystem/squashfs", "application/vnd.squashfs", (0, b"hsqs"), check=_squashfs),
    _rule("filesystem/squashfs", "application/vnd.squashfs", (0, b"sqsh"), check=_squashfs),
    _rule("filesystem/cramfs", _X, (0, b"\x45\x3d\xcd\x28")),
    _rule("filesystem/cramfs", _X, (0, b"\x28\xcd\x3d\x45")),
    _rule("filesystem/romfs", _X, (0, b"-rom1fs-")),
    _rule("filesystem/ubi", _X, (0, b"UBI#"), check=_version_field(4, 1, (1,))),
    _rule("filesystem/ubifs", _X, (0, b"\x31\x18\x10\x06")),
    _rule("filesystem/jffs2", _X, (0, b"\x85\x19"), check=_jffs2),
    _rule("filesystem/jffs2", _X, (0, b"\x19\x85"), check=_jffs2),
    _rule("filesystem/xfs", _X, (0, b"XFSB"), check=_xfs),
    _rule("disk-image/qcow2", "application/x-qemu-disk", (0, b"QFI\xfb"), check=_version_field(4, 4, (1, 2, 3), big=True)),
    _rule("disk-image/vmdk", "application/x-vmdk", (0, b"KDMV"), check=_version_field(4, 4, (1, 2, 3))),
    _rule("disk-image/vhdx", "application/x-vhdx-disk", (0, b"vhdxfile")),
    _rule("disk-image/vhd", "application/x-vhd-disk", (0, b"conectix")),
    _rule("disk-image/luks", _X, (0, b"LUKS\xba\xbe"), check=_luks),
    # Data, version control and key stores
    _rule("vcs/git-pack", _X, (0, b"PACK"), check=_version_field(4, 4, (2, 3), big=True)),
    _rule("vcs/git-index", _X, (0, b"DIRC"), check=_version_field(4, 4, (2, 3, 4), big=True)),
    _rule("vcs/git-pack-index", _X, (0, b"\xfftOc"), check=_version_field(4, 4, (2,), big=True)),
    _rule("vcs/git-commit-graph", _X, (0, b"CGPH"), check=_version_field(4, 1, (1, 2))),
    _rule("vcs/git-multi-pack-index", _X, (0, b"MIDX"), check=_version_field(4, 1, (1,))),
    _rule("data/java-serialized", "application/x-java-serialized-object", (0, b"\xac\xed\x00\x05")),
    _rule("data/plist", "application/x-bplist", (0, b"bplist00")),
    _rule("data/cbor", "application/cbor", (0, b"\xd9\xd9\xf7")),
    _rule("data/windows-registry", _X, (0, b"regf"), binary=True),
    _rule("data/windows-event-log", _X, (0, b"ElfFile\x00")),
    _rule("data/windows-shortcut", "application/x-ms-shortcut", (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00")),
    *(_rule("data/pcap", "application/vnd.tcpdump.pcap", (0, magic))
      for magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")),
    _rule("data/pcapng", "application/x-pcapng", (0, b"\x0a\x0d\x0d\x0a"), (8, b"\x1a\x2b\x3c\x4d")),
    _rule("data/pcapng", "application/x-pcapng", (0, b"\x0a\x0d\x0d\x0a"), (8, b"\x4d\x3c\x2b\x1a")),
    _rule("core-dump/minidump", _X, (0, b"MDMP"), (4, b"\x93\xa7")),
    _rule("crypto/java-keystore", "application/x-java-keystore", (0, b"\xfe\xed\xfe\xed")),
    _rule("crypto/java-jce-keystore", "application/x-java-jce-keystore", (0, b"\xce\xce\xce\xce"), family="java-keystore"),
    _rule("crypto/keepass", "application/x-keepass2", (0, b"\x03\xd9\xa2\x9a"), (4, b"\x67\xfb\x4b\xb5")),
    _rule("crypto/keepass", "application/x-keepass2", (0, b"\x03\xd9\xa2\x9a"), (4, b"\x65\xfb\x4b\xb5")),
    # 3D models and game assets
    _rule("3d-model/gltf-binary", "model/gltf-binary", (0, b"glTF"), family="gltf", check=_version_field(4, 4, (1, 2))),
    _rule("3d-model/fbx", _X, (0, b"Kaydara FBX Binary  \x00")),
    _rule("3d-model/blend", "application/x-blender", (0, b"BLENDER"),
          check=lambda rule, sample, size, probes: Signature(rule.kind) if sample[7:8] in (b"-", b"_") else None),
    _rule("3d-model/usd", _X, (0, b"PXR-USDC")),
    _rule("game-asset/unity-bundle", _X, (0, b"UnityFS\x00")),
    _rule("game-asset/unreal-package", _X, (0, b"\xc1\x83\x2a\x9e")),
    _rule("game-asset/godot-pack", _X, (0, b"GDPC"), check=_version_field(4, 4, (0, 1, 2, 3))),
    # Weak magic numbers, after the rules that share their first bytes
    _rule("data/pickle", _X, (0, b"\x80"), family="pickle", check=_pickle),
    _rule("audio/mpeg", "audio/mpeg", (0, b"\xff"), family="mpeg-audio", check=_mpeg_audio),
    # Tests that start past offset 0
    _rule("video/mp4", "video/mp4", (4, b"ftyp"), family="iso-bmff", check=_ftyp),
    *(_rule("video/quicktime", "video/quicktime", (4, atom), family="iso-bmff", check=_quicktime_atom)
      for atom in (b"moov", b"mdat", b"wide", b"pnot")),
    _rule("video/mp2t", "video/mp2t", (4, b"G"), (196, b"G"), (388, b"G"), check=_transport_stream(192, 4)),
    _rule("ml-model/tflite", _X, (4, b"TFL3")),
    _rule("database/access", "application/x-msaccess", (4, b"Standard Jet DB")),
    _rule("database/access", "application/x-msaccess", (4, b"Standard ACE DB")),
    _rule("database/duckdb", _X, (8, b"DUCK")),
    _rule("crypto/gpg-keybox", _X, (8, b"KBXf")),
    *(_rule("database/berkeley-db", _X, (12, magic))
      for magic in (b"\x61\x15\x06\x00", b"\x00\x06\x15\x61", b"\x62\x31\x05\x00", b"\x00\x05\x31\x62")),
    _rule("database/lmdb", _X, (16, b"\xde\xc0\xef\xbe")),
    _rule("document/mobi", "application/x-mobipocket-ebook", (60, b"BOOKMOBI")),
    _rule("disk-image/vdi", "application/x-virtualbox-vdi", (64, b"\x7f\x10\xda\xbe")),
    _rule("disk-image/gpt", "application/x-raw-disk-image", (512, b"EFI PART"), family="partitioned", check=_gpt),
    *(_rule("dataset/hdf5", "application/x-hdf5", (offset, _HDF5)) for offset in (512, 1024, 2048)),
    _rule("disk-image/mbr", "application/x-raw-disk-image", (510, b"\x55\xaa"), family="partitioned", check=_boot_sector),
    _rule("filesystem/erofs", _X, (1024, b"\xe2\xe1\xf5\xe0")),
    _rule("filesystem/f2fs", _X, (1024, b"\x10\x20\xf5\xf2")),
    _rule("filesystem/ext2", _X, (1080, b"\x53\xef"), family="ext", check=_ext),
    _rule("archive/lha", "application/x-lha", (2, b"-lh"), check=_lha),
    _rule("archive/zstandard", "application/zstd", (1, b"\x2a\x4d\x18"), check=_zstd_skippable),
    _rule("ml-model/safetensors", _X, (8, b"{"), check=_safetensors),
    _rule("bytecode/python", "application/x-python-bytecode", (2, b"\r\n"), family="pyc", check=_pyc),
)

RULES_DIGEST = hashlib.sha256("\n".join(
    rule.kind.label + " " + " ".join(f"{offset}:{data.hex()}" for offset, data in rule.tests) for rule in RULES
).encode("ascii")).hexdigest()


def _first_byte(rule: Rule) -> int | None:
    for offset, data in rule.tests:
        if offset == 0:
            return data[0]
    return None


# The rules each first byte can match, in table order (the C++ classifier scans them all).
_CANDIDATES: tuple[tuple[int, ...], ...] = tuple(
    tuple(index for index, rule in enumerate(RULES) if _first_byte(rule) in (None, value)) for value in range(256)
)
_CPP_CURRENT = _native.signature_rules_digest() == RULES_DIGEST


def cpp_rules_current() -> bool:
    """Whether the compiled C++ classifier holds this catalog's rule table."""
    return _CPP_CURRENT


def match_rule(sample: bytes, start: int = 0) -> int | None:
    """The index of the first rule from ``start`` whose bytes the sample matches."""
    if not sample:
        return None
    if _CPP_CURRENT:
        return _native.match_signature_rule(sample, start)
    return python_match_rule(sample, start)


def python_match_rule(sample: bytes, start: int = 0) -> int | None:
    """The portable matcher; the C++ classifier returns the same index."""
    if not sample:
        return None
    candidates = _CANDIDATES[sample[0]]
    for position in range(bisect.bisect_left(candidates, start), len(candidates)):
        index = candidates[position]
        if all(sample[offset:offset + len(data)] == data for offset, data in RULES[index].tests):
            return index
    return None


def probe_offsets(sample: bytes, size: int | None) -> tuple[tuple[int, int], ...]:
    """Further (offset, length) reads a sample needs: an ISO 9660/UDF volume descriptor
    (all-zero system areas and hybrid images) and an OLE directory past the sample."""
    probes: list[tuple[int, int]] = []
    if size is not None and size >= ISO_DESCRIPTOR_OFFSET + 8 and (
        not sample.strip(b"\x00") or sample[510:512] == b"\x55\xaa"
    ):
        probes.append((ISO_DESCRIPTOR_OFFSET, 8))
    directory = ole_directory(sample)
    if directory is not None:
        start, sector = directory
        if start + sector > len(sample) and start <= 1 << 26 and (size is None or start + sector <= size):
            probes.append((start, max(sector, OLE_DIRECTORY_PROBE_BYTES)))
    return tuple(probes)


def content_probes(content: bytes) -> dict[int, bytes]:
    """The probes of a file whose whole content is in memory (no-download scans)."""
    return {
        offset: content[offset:offset + length]
        for offset, length in probe_offsets(content[:SAMPLE_BYTES], len(content))
    }


def detect(sample: bytes, size: int | None = None, probes: Mapping[int, bytes] | None = None) -> Signature | None:
    """The binary format of a sample from its magic bytes, or None (text formats excluded)."""
    if not sample:
        return None
    probes = probes or {}
    tar = _tar(sample)
    if tar is not None:
        return tar
    start = 0
    while (index := match_rule(sample, start)) is not None:
        signature = _accept(RULES[index], sample, size, probes)
        if signature is not None:
            return signature
        start = index + 1
    return _volume_descriptor(probes)


# ---------------------------------------------------------------------------------------
# What names suggest

_NAME_TYPES: dict[str, NameType] = {}
_COMPOUND_NAME_TYPES: list[tuple[str, NameType]] = []


def _names(label: str, accepts: tuple[str, ...] | str, *suffixes: str, strict: bool = False) -> None:
    entry = NameType(label, frozenset((accepts,) if isinstance(accepts, str) else accepts), strict)
    for suffix in suffixes:
        if suffix.count(".") > 1:
            _COMPOUND_NAME_TYPES.append((suffix, entry))
        else:
            _NAME_TYPES[suffix] = entry


_ZIP_FAMILY = "zip"
_names("archive/zip", _ZIP_FAMILY, ".zip", strict=True)
_names("archive/jar", _ZIP_FAMILY, ".jar", ".war", ".ear", strict=True)
_names("package/apk", _ZIP_FAMILY, ".apk", ".aab", ".xapk", strict=True)
_names("package/aar", _ZIP_FAMILY, ".aar", strict=True)
_names("package/ipa", _ZIP_FAMILY, ".ipa", strict=True)
_names("package/wheel", _ZIP_FAMILY, ".whl", ".egg", strict=True)
_names("package/nupkg", _ZIP_FAMILY, ".nupkg", ".snupkg", strict=True)
_names("package/vsix", _ZIP_FAMILY, ".vsix", strict=True)
_names("package/xpi", _ZIP_FAMILY, ".xpi", strict=True)
_names("package/msix", _ZIP_FAMILY, ".msix", ".appx", ".msixbundle", ".appxbundle", strict=True)
_names("package/ipk", ("ar", "gzip", "tar"), ".ipk")
_names("document/docx", _ZIP_FAMILY, ".docx", ".docm", ".dotx", ".dotm", strict=True)
_names("document/xlsx", _ZIP_FAMILY, ".xlsx", ".xlsm", ".xltx", ".xltm", strict=True)
_names("document/pptx", _ZIP_FAMILY, ".pptx", ".pptm", ".potx", ".ppsx", strict=True)
_names("document/vsdx", _ZIP_FAMILY, ".vsdx", strict=True)
_names("document/odt", _ZIP_FAMILY, ".odt", ".ott", strict=True)
_names("document/ods", _ZIP_FAMILY, ".ods", ".ots", strict=True)
_names("document/odp", _ZIP_FAMILY, ".odp", ".otp", strict=True)
_names("document/odg", _ZIP_FAMILY, ".odg", ".otg", strict=True)
_names("document/odf", _ZIP_FAMILY, ".odf", ".odc", ".odb", strict=True)
_names("document/epub", _ZIP_FAMILY, ".epub", strict=True)
_names("document/xps", _ZIP_FAMILY, ".xps", ".oxps", strict=True)
_names("document/doc", "ole", ".doc", ".dot")
_names("document/xls", "ole", ".xls", ".xlt")
_names("document/ppt", "ole", ".ppt", ".pps", ".pot")
_names("document/vsd", "ole", ".vsd")
_names("email/msg", "ole", ".msg")
_names("package/msi", "ole", ".msi", ".msp", ".mst", strict=True)
_names("document/pdf", "pdf", ".pdf", strict=True)
_names("document/rtf", ("rtf", "text"), ".rtf")
_names("document/postscript", ("postscript", "text"), ".ps", ".eps")
_names("document/mobi", "mobi", ".mobi", ".azw")
_names("document/djvu", "djvu", ".djvu", ".djv")
_names("document/chm", "chm", ".chm")
_names("archive/gzip", "gzip", ".gz", ".svgz", strict=True)
_names("archive/tar+gzip", "gzip", ".tgz", ".tar.gz", strict=True)
_names("archive/bzip2", "bzip2", ".bz2", strict=True)
_names("archive/tar+bzip2", "bzip2", ".tbz2", ".tbz", ".tar.bz2", strict=True)
_names("archive/xz", "xz", ".xz", strict=True)
_names("archive/tar+xz", "xz", ".txz", ".tar.xz", strict=True)
_names("archive/zstandard", "zstandard", ".zst", strict=True)
_names("archive/tar+zstandard", "zstandard", ".tzst", ".tar.zst", strict=True)
_names("archive/lz4", "lz4", ".lz4", ".tar.lz4")
_names("archive/lzip", "lzip", ".lz", ".tar.lz")
_names("archive/lzma", "lzma", ".lzma", ".tlz", ".tar.lzma")
_names("archive/lzop", "lzop", ".lzo")
_names("archive/unix-compress", "compress", ".z", ".tar.z")
_names("archive/7z", "7z", ".7z", strict=True)
_names("archive/rar", "rar", ".rar", strict=True)
_names("archive/cab", ("cab", "installshield-cab"), ".cab")
_names("archive/tar", "tar", ".tar")
_names("archive/cpio", "cpio", ".cpio")
_names("archive/deb", "ar", ".deb", ".udeb", ".ipk", strict=True)
_names("archive/rpm", "rpm", ".rpm", strict=True)
_names("archive/xar", "xar", ".xar", ".pkg")
_names("archive/wim", "wim", ".wim", ".esd", ".swm")
_names("archive/arj", "arj", ".arj")
_names("archive/lha", "lha", ".lzh", ".lha")
_names("package/crx", "crx", ".crx")
_names("disk-image/iso", ("iso9660", "udf"), ".iso")
_names("disk-image/dmg", (), ".dmg")
_names("disk-image/qcow2", "qcow2", ".qcow2", ".qcow")
_names("disk-image/vmdk", ("vmdk", "text"), ".vmdk")
_names("disk-image/vhd", ("vhd", "vhdx"), ".vhd", ".vhdx")
_names("disk-image/vdi", "vdi", ".vdi")
_names("executable/pe", "mz", ".exe", ".scr", ".sys", ".drv", strict=True)
_names("firmware/efi", "mz", ".efi", strict=True)
_names("library/pe", "mz", ".dll", ".ocx", ".cpl", ".mui", strict=True)
# A .so may be a GNU ld script (libc.so), which is text.
_names("library/elf", ("elf", "text"), ".so", strict=True)
_names("object/elf", "elf", ".ko", strict=True)
_names("executable/elf", "elf", ".elf", ".axf", ".prx", strict=True)
_names("object/native", ("elf", "mach-o"), ".o")
_names("library/static", "ar", ".a", ".lib")
_names("library/mach-o", "mach-o", ".dylib", strict=True)
_names("bytecode/java-class", "java-class", ".class", strict=True)
_names("bytecode/dex", "dex", ".dex", ".odex", strict=True)
_names("bytecode/wasm", "wasm", ".wasm", strict=True)
_names("bytecode/python", "pyc", ".pyc", ".pyo", strict=True)
_names("bytecode/lua", "lua", ".luac")
_names("bytecode/spir-v", "spir-v", ".spv")
_names("bytecode/swf", "swf", ".swf")
_names("image/png", "png", ".png", ".apng", strict=True)
_names("image/jpeg", "jpeg", ".jpg", ".jpeg", ".jpe", ".jfif", strict=True)
_names("image/gif", "gif", ".gif", strict=True)
_names("image/bmp", "bmp", ".bmp", ".dib")
_names("image/tiff", "tiff", ".tif", ".tiff", ".dng", ".nef", ".arw", ".cr2", ".orf", ".rw2")
_names("image/webp", "image/webp", ".webp", strict=True)
_names("image/vnd.microsoft.icon", "ico", ".ico")
_names("image/vnd.adobe.photoshop", "psd", ".psd", ".psb")
_names("image/heif", ("image/heic", "image/heic-sequence", "image/heif", "image/heif-sequence"),
       ".heic", ".heif", ".heics", ".heifs")
_names("image/avif", "image/avif", ".avif")
_names("image/x-canon-cr3", "image/x-canon-cr3", ".cr3")
_names("image/jp2", "jpeg2000", ".jp2", ".j2k", ".j2c", ".jpf", ".jpx", ".jpm")
_names("image/jxl", "jxl", ".jxl")
_names("image/qoi", "qoi", ".qoi")
_names("image/x-exr", "exr", ".exr")
_names("image/vnd.ms-dds", "dds", ".dds")
_names("image/ktx", ("ktx", "ktx2"), ".ktx", ".ktx2")
# Radiance images, or ENVI and Analyze headers (text or binary).
_names("image/vnd.radiance", ("radiance", "text"), ".hdr")
_names("image/x-xcf", "xcf", ".xcf")
_names("image/icns", "icns", ".icns")
_names("image/wmf", ("wmf", "emf"), ".wmf", ".emf")
_names("image/x-portable-anymap", ("pnm", "text"), ".pbm", ".pgm", ".ppm", ".pnm")
_names("image/svg", ("svg", "text"), ".svg")
_names("audio/wav", "audio/wav", ".wav", ".wave", ".rf64")
_names("audio/mpeg", "mpeg-audio", ".mp3", ".mp2")
_names("audio/aac", "aac", ".aac", ".adts")
_names("audio/flac", "flac", ".flac", strict=True)
_names("audio/ogg", "ogg", ".ogg", ".oga", ".opus", ".spx", ".ogx", strict=True)
_names("video/ogg", "ogg", ".ogv", strict=True)
_names("audio/mp4", "iso-bmff", ".m4a", ".m4b", ".m4p")
_names("audio/aiff", "aiff", ".aif", ".aiff", ".aifc")
_names("audio/midi", "midi", ".mid", ".midi", ".rmi")
_names("audio/basic", "au", ".au", ".snd")
_names("audio/amr", "amr", ".amr", ".awb")
_names("audio/x-ape", "ape", ".ape")
_names("audio/x-wavpack", "wavpack", ".wv")
_names("audio/x-caf", "caf", ".caf")
_names("audio/x-dsf", "dsf", ".dsf")
_names("video/mp4", "iso-bmff", ".mp4", ".m4v", ".mov", ".qt", ".3gp", ".3g2", ".f4v")
_names("video/x-matroska", "ebml", ".mkv", ".mka", ".mks", ".mk3d", ".webm", strict=True)
_names("video/x-msvideo", "video/x-msvideo", ".avi", strict=True)
_names("video/x-flv", "flv", ".flv")
_names("video/mpeg", "mpeg", ".mpg", ".mpeg", ".m1v", ".m2v", ".vob")
_names("video/mp2t", "mp2t", ".m2ts", ".mts")
_names("video/x-ms-asf", "asf", ".asf", ".wmv", ".wma")
_names("video/realmedia", "realmedia", ".rm", ".rmvb")
_names("video/mxf", "mxf", ".mxf")
_names("font/ttf", "sfnt", ".ttf", strict=True)
_names("font/otf", "sfnt", ".otf", strict=True)
_names("font/collection", "sfnt", ".ttc", ".otc", strict=True)
_names("font/woff", "woff", ".woff", strict=True)
_names("font/woff2", "woff2", ".woff2", strict=True)
_names("font/type1", "type1", ".pfb")
_names("database/sqlite", "sqlite", ".sqlite", ".sqlite3", ".db3", strict=True)
_names("database/duckdb", "duckdb", ".duckdb")
_names("database/access", ("access", "lmdb"), ".mdb", ".accdb")
_names("dataset/hdf5", ("hdf5", "hdf4"), ".h5", ".hdf5", ".he5", ".hdf", ".h4")
_names("dataset/npy", "npy", ".npy", strict=True)
_names("dataset/npz", _ZIP_FAMILY, ".npz", strict=True)
_names("dataset/parquet", "parquet", ".parquet", strict=True)
_names("dataset/arrow", ("arrow", "feather"), ".arrow", ".feather")
_names("dataset/avro", "avro", ".avro")
_names("dataset/orc", "orc", ".orc")
_names("dataset/netcdf", ("netcdf", "hdf5"), ".nc", ".nc4", ".cdf")
_names("dataset/fits", "fits", ".fits", ".fit", ".fts")
_names("dataset/matlab", "matlab", ".mat")
_names("data/pickle", ("pickle", "ml-model/pytorch-legacy"), ".pkl", ".pickle")
_names("ml-model/safetensors", "safetensors", ".safetensors", strict=True)
_names("ml-model/gguf", ("gguf", "ggml"), ".gguf", ".ggml")
_names("ml-model/pytorch", (_ZIP_FAMILY, "pickle"), ".pt", ".pth")
_names("ml-model/tflite", "tflite", ".tflite")
_names("ml-model/keras", (_ZIP_FAMILY, "hdf5"), ".keras")
_names("ml-model/onnx", (), ".onnx")
_names("firmware/uimage", "uimage", ".uimage", ".ub")
_names("firmware/device-tree", "device-tree", ".dtb", ".dtbo", ".itb", strict=True)
_names("firmware/uf2", "uf2", ".uf2", strict=True)
_names("firmware/trx", "trx", ".trx")
_names("firmware/intel-hex", ("intel-hex", "text"), ".hex", ".ihex", ".ihx")
_names("firmware/srec", ("srec", "text"), ".srec", ".s19", ".s28", ".s37", ".mot")
_names("filesystem/squashfs", "squashfs", ".squashfs", ".sqsh", ".sfs")
_names("filesystem/ubi", ("ubi", "ubifs"), ".ubi", ".ubifs")
_names("filesystem/jffs2", "jffs2", ".jffs2")
_names("filesystem/cramfs", "cramfs", ".cramfs")
_names("filesystem/ext", "ext", ".ext2", ".ext3", ".ext4")
_names("vcs/git-pack", "git-pack", ".pack")
_names("data/plist", ("plist", "text"), ".plist")
_names("data/pcap", ("pcap", "pcapng"), ".pcap", ".pcapng")
_names("data/windows-shortcut", "windows-shortcut", ".lnk")
_names("data/windows-event-log", "windows-event-log", ".evtx")
_names("core-dump/minidump", "minidump", ".dmp", ".mdmp")
_names("crypto/java-keystore", "java-keystore", ".jks", ".jceks")
_names("crypto/keepass", "keepass", ".kdbx", ".kdb")
_names("crypto/pem", ("pem", "text"), ".pem")
_names("3d-model/gltf-binary", "gltf", ".glb")
_names("3d-model/fbx", ("fbx", "text"), ".fbx")
_names("3d-model/blend", "blend", ".blend")
_names("3d-model/usd", ("usd", "text", _ZIP_FAMILY), ".usd", ".usdc", ".usdz")
_names("game-asset/unity-bundle", "unity-bundle", ".unity3d")
_names("game-asset/unreal-package", "unreal-package", ".uasset", ".umap")
_names("game-asset/godot-pack", "godot-pack", ".pck")
# Names that are source as well as a binary format: TypeScript or an MPEG transport stream.
_names("source", ("text", "video/mp2t"), ".ts")
_COMPOUND_NAME_TYPES.sort(key=lambda item: -len(item[0]))
_SOURCE = NameType("source", frozenset({"text"}))
_TEXT = NameType("text", frozenset({"text"}))
_SHARED_OBJECT = _NAME_TYPES[".so"]
_VERSIONED_SHARED_OBJECT = re.compile(r"\.so(?:\.\d+)+$")


def name_type(path: str) -> NameType | None:
    """What a file's name or extension suggests, independently of its content."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix, entry in _COMPOUND_NAME_TYPES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return entry
    dot = name.rfind(".")
    if dot > 0:
        entry = _NAME_TYPES.get(name[dot:])
        if entry is not None:
            return entry
    if _VERSIONED_SHARED_OBJECT.search(name):
        return _SHARED_OBJECT
    if is_source_path(path):
        return _SOURCE
    if is_textual_path(path):
        return _TEXT
    return None


# ---------------------------------------------------------------------------------------
# Classification

def _mismatch(name: NameType | None, signature: Signature | None, file_type: str) -> bool:
    """Whether the name and the content disagree (a Git LFS pointer stands for its file)."""
    if name is None or (signature is not None and signature.kind is _LFS):
        return False
    accepts = name.accepts
    if signature is not None and (signature.label in accepts or signature.family in accepts):
        return False
    if file_type == "text":
        return "text" not in accepts
    if signature is not None:
        return True
    # Binary content without a known signature.
    return accepts == {"text"} or name.strict


def classify(sample: bytes | None, path: str, *, size: int | None = None,
             probes: Mapping[int, bytes] | None = None) -> Classification:
    """The file type of a content sample, or of the name alone when ``sample`` is None."""
    name = name_type(path)
    suggested = None if name is None else name.label
    if sample is None:
        return Classification(suggested or "unclassified", "name", name_type=suggested)
    signature = detect(sample, size, probes)
    if signature is not None:
        return Classification(
            signature.label, "signature", signature, signature.detail, signature.mime, suggested,
            _mismatch(name, signature, signature.label),
        )
    if not sample:
        return Classification("empty", "content", None, None, "inode/x-empty", suggested)
    if looks_textual(sample):
        text = detect_text(sample, size)
        return Classification(
            "text", "content", text, None if text is None else text.detail,
            "text/plain" if text is None else text.mime, suggested, _mismatch(name, text, "text"),
        )
    entropy = _entropy(sample)
    note = " (compressed or encrypted data)" if entropy >= 7.5 else ""
    return Classification(
        "binary/unknown", "content", None, f"no known signature; sample entropy {entropy:.1f} bits/byte{note}",
        "application/octet-stream", suggested, _mismatch(name, None, "binary/unknown"),
    )


def classify_content(content: bytes, path: str) -> Classification:
    """The classification of a file whose whole content is in memory."""
    return classify(content[:SAMPLE_BYTES], path, size=len(content), probes=content_probes(content))


def apply_classification(record, classification: Classification) -> None:
    """Store a classification in a FileRecord."""
    record.file_type = classification.file_type
    record.type_source = classification.type_source
    record.signature = None if classification.signature is None else classification.signature.label
    record.type_detail = classification.detail
    record.mime_type = classification.mime_type
    record.name_type = classification.name_type
    record.type_mismatch = classification.mismatch


def count_classification(stats, record) -> None:
    """Count a file record's type, MIME type, type source and name/content mismatch."""
    stats[f"file_type:{record.file_type}"] += 1
    if record.type_source:
        stats[f"type_source:{record.type_source}"] += 1
    if record.mime_type:
        stats[f"mime_type:{record.mime_type}"] += 1
    if record.type_mismatch:
        stats["type_mismatch_count"] += 1
        stats[f"type_mismatch:{record.name_type} → {record.file_type}"] += 1
    if record.signature == _LFS.label:
        stats["git_lfs_pointer_count"] += 1


def render_cpp_rules() -> str:
    """native/cpp/pdt_signature_rules.h: the rule table for the C++ classifier."""
    lines = [
        "// Generated from src/project_discovery/inventory/signatures.py by",
        "// `python tools/signature_rules.py --write`. Do not edit: a test fails when this",
        "// table and the Python catalog differ.",
        "",
    ]
    for index, rule in enumerate(RULES):
        for number, (_, data) in enumerate(rule.tests):
            values = ", ".join(f"0x{value:02x}" for value in data)
            lines.append(f"const unsigned char kRule{index}Bytes{number}[] = {{{values}}};")
        tests = ", ".join(
            f"{{{offset}, kRule{index}Bytes{number}, {len(data)}}}" for number, (offset, data) in enumerate(rule.tests)
        )
        lines.append(f"const Test kRule{index}Tests[] = {{{tests}}};")
    lines.append("")
    lines.append("const Rule kRules[] = {")
    lines.extend(f'    {{"{rule.kind.label}", kRule{index}Tests, {len(rule.tests)}}},' for index, rule in enumerate(RULES))
    lines.append("};")
    lines.append(f"const std::size_t kRuleCount = {len(RULES)};")
    lines.append(f'const char kRulesDigest[] = "{RULES_DIGEST}";')
    return "\n".join(lines) + "\n"
