"""File signatures and MIME types: per-format fixtures, names, mismatches, probes and scans."""
from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import pickle
import random
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from project_discovery.inventory import signatures
from project_discovery.inventory.signatures import (
    RULES,
    SAMPLE_BYTES,
    classify,
    classify_content,
    looks_textual,
    name_type,
    python_match_rule,
)


# ---------------------------------------------------------------------------------------
# Fixture builders

def _zip(*entries: tuple[str, str], stored_first: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index, (name, data) in enumerate(entries):
            method = zipfile.ZIP_STORED if stored_first and index == 0 else zipfile.ZIP_DEFLATED
            archive.writestr(name, data, compress_type=method)
    return buffer.getvalue()


def _elf(file_type: int, *, interpreter: bool = False, bits: int = 64, big: bool = False, machine: int = 62) -> bytes:
    order = ">" if big else "<"
    ident = b"\x7fELF" + bytes((2 if bits == 64 else 1, 2 if big else 1, 1)) + b"\0" * 9
    program_type = struct.pack(order + "I", 3 if interpreter else 1)
    if bits == 64:
        header = ident + struct.pack(order + "HHIQQQIHHHHHH", file_type, machine, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
        return header + program_type + b"\0" * 52
    header = ident + struct.pack(order + "HHIIIIIHHHHHH", file_type, machine, 1, 0, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    return header + program_type + b"\0" * 28


def _pe(*, characteristics: int = 0x0022, subsystem: int = 3, magic: int = 0x20B, machine: int = 0x8664,
        clr: bool = False) -> bytes:
    dos = bytearray(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\0" * 50)
    dos[0x3C:0x40] = struct.pack("<I", 0x80)
    dos += b"\0" * (0x80 - len(dos))
    size = 240 if magic == 0x20B else 224
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, size, characteristics)
    optional = bytearray(size)
    optional[0:2] = struct.pack("<H", magic)
    optional[68:70] = struct.pack("<H", subsystem)
    directories = 112 if magic == 0x20B else 96
    optional[directories - 4:directories] = struct.pack("<I", 16)
    if clr:
        optional[directories + 14 * 8:directories + 14 * 8 + 8] = struct.pack("<II", 0x2008, 0x48)
    return bytes(dos) + coff + bytes(optional)


def _macho(file_type: int, cpu: int = 0x0100000C) -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIII", cpu, 0, file_type, 0, 0, 0) + b"\0" * 4


def _ftyp(major: bytes, *compatible: bytes) -> bytes:
    return struct.pack(">I", 16 + 4 * len(compatible)) + b"ftyp" + major + b"\0\0\0\0" + b"".join(compatible)


def _ole(*streams: str, clsid: bytes = b"\0" * 16, directory_sector: int = 0) -> bytes:
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    header[26:28] = struct.pack("<H", 3)
    header[28:30] = b"\xfe\xff"
    header[30:32] = struct.pack("<H", 9)
    header[48:52] = struct.pack("<I", directory_sector)

    def entry(name: str, kind: int, identifier: bytes = b"\0" * 16) -> bytes:
        data = bytearray(128)
        encoded = (name + "\0").encode("utf-16-le")
        data[0:len(encoded)] = encoded
        data[64:66] = struct.pack("<H", len(encoded))
        data[66] = kind
        data[80:96] = identifier
        return bytes(data)

    directory = entry("Root Entry", 5, clsid) + b"".join(entry(name, 2) for name in streams)
    directory += b"\0" * (-len(directory) % 512)
    return bytes(header) + b"\0" * (512 * directory_sector) + directory


def _tar(format_: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=format_) as archive:
        member = tarfile.TarInfo("notes/readme.txt")
        member.size = 5
        archive.addfile(member, io.BytesIO(b"hello"))
    return buffer.getvalue()


def _v7_tar() -> bytes:
    data = bytearray(_tar(tarfile.USTAR_FORMAT))
    data[257:265] = b"\0" * 8  # no magic or version
    data[148:156] = b" " * 8
    data[148:156] = f"{sum(data[:512]):06o}\0 ".encode("ascii")
    return bytes(data)


def _boot_sector(*, fat: bytes | None = None, partition: bool = False) -> bytearray:
    sector = bytearray(512)
    if fat is not None:
        sector[0:3] = b"\xeb\x3c\x90"
        sector[54:62] = fat
    if partition:
        sector[446] = 0x80
        sector[450] = 0x83
    sector[510:512] = b"\x55\xaa"
    return sector


def _ext(compat: int = 0, incompat: int = 0) -> bytes:
    data = bytearray(2048)
    base = 1024
    data[base:base + 8] = struct.pack("<II", 128, 1024)
    data[base + 24:base + 28] = struct.pack("<I", 2)
    data[1080:1082] = b"\x53\xef"
    data[base + 76:base + 80] = struct.pack("<I", 1)
    data[base + 92:base + 104] = struct.pack("<III", compat, incompat, 0)
    return bytes(data)


def _adts(length: int = 200) -> bytes:
    header = bytes((0xFF, 0xF1, 0x50, 0x80 | ((length >> 11) & 3), (length >> 3) & 0xFF, ((length & 7) << 5) | 0x1F, 0xFC))
    return header + b"\0" * (length - 7)


def _hex_line(address: int, record_type: int, payload: bytes) -> str:
    data = bytes((len(payload), address >> 8, address & 0xFF, record_type)) + payload
    return ":" + (data + bytes(((-sum(data)) & 0xFF,))).hex().upper()


def _srec_line(address: int, payload: bytes) -> str:
    data = bytes((len(payload) + 3, address >> 8, address & 0xFF)) + payload
    return "S1" + (data + bytes((0xFF - (sum(data) & 0xFF),))).hex().upper()


_OGG_PAGE = b"OggS\x00\x02" + b"\0" * 20 + b"\x01\x1e"
_MSI_CLSID = bytes.fromhex("84100c0000000000c000000000000046")  # {000C1084-0000-0000-C000-000000000046}

# (file name, content, expected label, expected MIME type, a word the detail contains)
FIXTURES: list[tuple[str, bytes, str, str, str | None]] = [
    # Executables, libraries and bytecode
    ("app", _elf(2), "executable/elf", "application/x-executable", "executable, x86-64"),
    ("pie", _elf(3, interpreter=True), "executable/elf", "application/x-pie-executable", "position-independent"),
    ("libz.so.1", _elf(3), "library/elf", "application/x-sharedlib", "shared object"),
    ("main.o", _elf(1, bits=32, machine=40), "object/elf", "application/x-object", "32-bit LSB relocatable object, ARM"),
    ("core", _elf(4, big=True, machine=21), "core-dump/elf", "application/x-core", "MSB core file, PowerPC64"),
    ("tool.exe", _pe(), "executable/pe", "application/vnd.microsoft.portable-executable", "PE32+ executable (console)"),
    ("lib.dll", _pe(characteristics=0x2022), "library/pe", "application/vnd.microsoft.portable-executable", "DLL"),
    ("Managed.dll", _pe(characteristics=0x2022, magic=0x10B, machine=0x14C, clr=True), "library/pe",
     "application/vnd.microsoft.portable-executable", "PE32 DLL, x86, .NET assembly"),
    ("BOOTX64.EFI", _pe(subsystem=10), "firmware/efi", "application/efi", "EFI application"),
    ("old.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00" + b"\0" * 60, "executable/dos", "application/x-dosexec", "MS-DOS"),
    ("tool", _macho(2), "executable/mach-o", "application/x-mach-binary", "64-bit executable, ARM64"),
    ("libx.dylib", _macho(6, 0x01000007), "library/mach-o", "application/x-mach-binary", "dynamic library, x86-64"),
    ("x.o", _macho(1), "object/mach-o", "application/x-mach-binary", "relocatable object"),
    ("universal", b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + struct.pack(">IIIII", 0x01000007, 3, 4096, 9, 12)
     + struct.pack(">IIIII", 0x0100000C, 0, 16384, 9, 14), "executable/mach-o-universal", "application/x-mach-binary",
     "2 architecture(s): x86-64, ARM64"),
    ("Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\0" * 24, "bytecode/java-class", "application/java-vm",
     "Java 21"),
    ("classes.dex", b"dex\n035\x00" + b"\0" * 24, "bytecode/dex", "application/octet-stream", "version 035"),
    ("app.wasm", b"\x00asm\x01\x00\x00\x00", "bytecode/wasm", "application/wasm", "version 1"),
    ("x.pyc", struct.pack("<H", 3531) + b"\r\n" + b"\0" * 12 + b"\xe3" + b"\0" * 20, "bytecode/python",
     "application/x-python-bytecode", "magic number 3531"),
    ("x.luac", b"\x1bLuaT\x00", "bytecode/lua", "application/x-lua-bytecode", None),
    ("shader.spv", b"\x03\x02\x23\x07\x00\x00\x01\x00", "bytecode/spir-v", "application/octet-stream", None),
    ("movie.swf", b"FWS\x0a" + struct.pack("<I", 24) + b"\x78\x00\x05\x5f\x00\x00\x0f\xa0\x00\x00\x18\x01\x00\x00\x00\x00",
     "bytecode/swf",
     "application/vnd.adobe.flash.movie", "version 10"),
    # Archives, packages and compression
    ("a.zip", _zip(("readme.txt", "hello")), "archive/zip", "application/zip", None),
    ("empty.zip", b"PK\x05\x06" + b"\0" * 18, "archive/zip", "application/zip", "empty ZIP"),
    ("lib.jar", _zip(("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")), "archive/jar", "application/java-archive",
     "Java archive"),
    ("app.war", _zip(("META-INF/MANIFEST.MF", "M"), ("WEB-INF/web.xml", "<w/>")), "archive/war",
     "application/java-archive", "web application"),
    ("app.apk", _zip(("AndroidManifest.xml", "x"), ("classes.dex", "y")), "package/apk",
     "application/vnd.android.package-archive", "Android application"),
    ("lib.aar", _zip(("AndroidManifest.xml", "x"), ("classes.jar", "y")), "package/aar", "application/zip",
     "Android library"),
    ("App.ipa", _zip(("Payload/App.app/Info.plist", "x")), "package/ipa", "application/x-ios-app", "iOS"),
    ("pkg-1.0-py3-none-any.whl", _zip(("pkg/__init__.py", ""), ("pkg-1.0.dist-info/METADATA", "x")), "package/wheel",
     "application/x-wheel+zip", "wheel"),
    ("pkg.nupkg", _zip(("_rels/.rels", "x"), ("pkg.nuspec", "x"), ("[Content_Types].xml", "x")), "package/nupkg",
     "application/zip", "NuGet"),
    ("app.msix", _zip(("AppxManifest.xml", "x")), "package/msix", "application/msix", "MSIX"),
    ("a.docx", _zip(("[Content_Types].xml", "x"), ("_rels/.rels", "x"), ("word/document.xml", "x")), "document/docx",
     "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word"),
    ("a.xlsx", _zip(("[Content_Types].xml", "x"), ("xl/workbook.xml", "x")), "document/xlsx",
     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel"),
    ("a.pptx", _zip(("[Content_Types].xml", "x"), ("ppt/presentation.xml", "x")), "document/pptx",
     "application/vnd.openxmlformats-officedocument.presentationml.presentation", "PowerPoint"),
    ("a.docm", _zip(("[Content_Types].xml", "x"), ("docProps/app.xml", "x")), "document/ooxml", "application/zip",
     "past the sample"),
    ("a.odt", _zip(("mimetype", "application/vnd.oasis.opendocument.text"), ("content.xml", "x"), stored_first=True),
     "document/odt", "application/vnd.oasis.opendocument.text", "OpenDocument text"),
    ("a.ods", _zip(("mimetype", "application/vnd.oasis.opendocument.spreadsheet"), stored_first=True),
     "document/ods", "application/vnd.oasis.opendocument.spreadsheet", None),
    ("a.ott", _zip(("mimetype", "application/vnd.oasis.opendocument.text-template"), stored_first=True),
     "document/odt", "application/vnd.oasis.opendocument.text-template", "text-template"),
    ("book.epub", _zip(("mimetype", "application/epub+zip"), ("META-INF/container.xml", "x"), stored_first=True),
     "document/epub", "application/epub+zip", "EPUB"),
    ("model.pt", _zip(("archive/data.pkl", "x"), ("archive/version", "3")), "ml-model/pytorch", "application/zip",
     "PyTorch"),
    ("arrays.npz", _zip(("a.npy", "x"), ("b.npy", "y")), "dataset/npz", "application/zip", "NumPy"),
    ("a.gz", gzip.compress(b"hello"), "archive/gzip", "application/gzip", None),
    ("a.bz2", bz2.compress(b"hello"), "archive/bzip2", "application/x-bzip2", "900 kB"),
    ("a.xz", lzma.compress(b"hello"), "archive/xz", "application/x-xz", None),
    ("a.lzma", lzma.compress(b"hello", format=lzma.FORMAT_ALONE), "archive/lzma", "application/x-lzma", None),
    ("a.zst", b"\x28\xb5\x2f\xfd\x20\x05\x29\x00\x00hello", "archive/zstandard", "application/zstd", None),
    ("seekable.zst", b"\x5e\x2a\x4d\x18\x04\x00\x00\x00abcd", "archive/zstandard", "application/zstd", "skippable"),
    ("a.lz4", b"\x04\x22\x4d\x18\x64\x40\xa7", "archive/lz4", "application/x-lz4", None),
    ("a.7z", b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\0" * 24, "archive/7z", "application/x-7z-compressed", None),
    ("a.rar", b"Rar!\x1a\x07\x01\x00" + b"\0" * 8, "archive/rar", "application/vnd.rar", "RAR 5"),
    ("old.rar", b"Rar!\x1a\x07\x00" + b"\0" * 8, "archive/rar", "application/vnd.rar", "RAR 4"),
    ("a.cab", b"MSCF\0\0\0\0" + b"\0" * 28, "archive/cab", "application/vnd.ms-cab-compressed", None),
    ("a.deb", b"!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n", "archive/deb",
     "application/vnd.debian.binary-package", "Debian"),
    ("libm.a", b"!<arch>\n/               0           0     0     0       4         `\n\0\0\0\0", "library/static",
     "application/x-archive", "symbol table"),
    ("a.rpm", b"\xed\xab\xee\xdb\x03\x00" + b"\0" * 90, "archive/rpm", "application/x-rpm", None),
    ("a.cpio", b"070701" + b"0" * 104 + b"name\0", "archive/cpio", "application/x-cpio", "newc"),
    ("odc.cpio", b"070707" + b"0" * 70 + b"name\0", "archive/cpio", "application/x-cpio", "odc"),
    ("a.tar", _tar(tarfile.USTAR_FORMAT), "archive/tar", "application/x-tar", "POSIX tar"),
    ("gnu.tar", _tar(tarfile.GNU_FORMAT), "archive/tar", "application/x-tar", "GNU tar"),
    ("v7.tar", _v7_tar(), "archive/tar", "application/x-tar", "V7 tar"),
    ("a.xar", b"xar!" + struct.pack(">HH", 28, 1) + b"\0" * 20, "archive/xar", "application/x-xar", None),
    ("a.Z", b"\x1f\x9d\x90hello", "archive/unix-compress", "application/x-compress", None),
    ("a.crx", b"Cr24" + struct.pack("<I", 3) + b"\0" * 8, "package/crx", "application/x-chrome-extension", None),
    # Documents
    ("a.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n", "document/pdf", "application/pdf", "PDF 1.7"),
    ("bom.pdf", b"\xef\xbb\xbf%PDF-1.4\n", "document/pdf", "application/pdf", "PDF 1.4"),
    ("a.doc", _ole("WordDocument", "1Table"), "document/doc", "application/msword", "Word 97-2003"),
    ("a.xls", _ole("Workbook"), "document/xls", "application/vnd.ms-excel", "Excel 97-2003"),
    ("a.ppt", _ole("PowerPoint Document"), "document/ppt", "application/vnd.ms-powerpoint", None),
    ("a.msg", _ole("__substg1.0_0037001F"), "email/msg", "application/vnd.ms-outlook", "Outlook"),
    ("setup.msi", _ole("SummaryInformation", clsid=_MSI_CLSID), "package/msi", "application/x-msi",
     "Windows Installer package"),
    ("secret.docx", _ole("EncryptionInfo", "EncryptedPackage"), "document/office-encrypted",
     "application/x-ole-storage", "encrypted"),
    ("thumbs.db", _ole("Catalog"), "document/ole", "application/x-ole-storage", "OLE compound file"),
    ("a.chm", b"ITSF\x03\x00\x00\x00" + b"\0" * 24, "document/chm", "application/vnd.ms-htmlhelp", None),
    # Images
    ("a.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "image/png", "image/png", None),
    ("a.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF", "image/jpeg", "image/jpeg", None),
    ("a.gif", b"GIF89a\x01\x00\x01\x00", "image/gif", "image/gif", None),
    ("a.bmp", b"BM" + struct.pack("<IHHII", 1000, 0, 0, 54, 40) + b"\0" * 36, "image/bmp", "image/bmp", None),
    ("a.tif", b"II*\x00\x08\x00\x00\x00", "image/tiff", "image/tiff", None),
    ("a.cr2", b"II*\x00\x10\x00\x00\x00CR\x02\x00", "image/x-canon-cr2", "image/x-canon-cr2", None),
    ("a.webp", b"RIFF" + struct.pack("<I", 100) + b"WEBPVP8 ", "image/webp", "image/webp", None),
    ("a.ico", b"\x00\x00\x01\x00\x01\x00" + bytes((16, 16, 0, 0)) + struct.pack("<HHII", 1, 32, 1128, 22),
     "image/vnd.microsoft.icon", "image/vnd.microsoft.icon", "1 image"),
    ("a.psd", b"8BPS\x00\x01" + b"\0" * 20, "image/vnd.adobe.photoshop", "image/vnd.adobe.photoshop", None),
    ("a.heic", _ftyp(b"heic", b"mif1", b"heic"), "image/heic", "image/heic", "HEIC"),
    ("a.avif", _ftyp(b"avif", b"avif", b"mif1"), "image/avif", "image/avif", "AVIF"),
    ("mif.avif", _ftyp(b"mif1", b"avif", b"miaf"), "image/avif", "image/avif", None),
    ("a.jp2", b"\x00\x00\x00\x0cjP  \r\n\x87\n" + struct.pack(">I", 20) + b"ftypjp2 \0\0\0\0jp2 ", "image/jp2",
     "image/jp2", "JPEG 2000"),
    ("a.jxl", b"\xff\x0a\xfa\x7f", "image/jxl", "image/jxl", None),
    ("a.exr", b"\x76\x2f\x31\x01\x02\x00\x00\x00", "image/x-exr", "image/x-exr", None),
    ("a.ppm", b"P6\n# comment\n640 480\n255\n" + bytes(range(256)), "image/x-portable-pixmap",
     "image/x-portable-pixmap", None),
    # Audio and video
    ("a.wav", b"RIFF" + struct.pack("<I", 36) + b"WAVEfmt ", "audio/wav", "audio/wav", None),
    ("a.mp3", (b"\xff\xfb\x90\x64" + b"\0" * 413) * 3, "audio/mpeg", "audio/mpeg", "MPEG-1 Layer III, 128 kbit/s"),
    ("tagged.mp3", b"ID3\x04\x00\x00\x00\x00\x00\x0a" + b"\0" * 10 + b"\xff\xfb\x90\x64", "audio/mpeg", "audio/mpeg",
     "ID3v2.4"),
    ("a.aac", _adts() * 3, "audio/aac", "audio/aac", "ADTS"),
    ("a.flac", b"fLaC\x00\x00\x00\x22" + b"\0" * 34, "audio/flac", "audio/flac", None),
    ("a.ogg", _OGG_PAGE + b"\x01vorbis" + b"\0" * 22, "audio/ogg", "audio/ogg", "Vorbis"),
    ("a.opus", _OGG_PAGE + b"OpusHead\x01\x02", "audio/ogg", "audio/ogg", "Opus"),
    ("a.ogv", _OGG_PAGE + b"\x80theora\x03\x02", "video/ogg", "video/ogg", "Theora"),
    ("a.mid", b"MThd\x00\x00\x00\x06\x00\x01\x00\x02\x01\xe0", "audio/midi", "audio/midi", None),
    ("a.aiff", b"FORM" + struct.pack(">I", 100) + b"AIFFCOMM", "audio/aiff", "audio/aiff", None),
    ("a.mp4", _ftyp(b"isom", b"isom", b"iso2", b"mp41"), "video/mp4", "video/mp4", "major brand 'isom'"),
    ("a.mov", _ftyp(b"qt  ", b"qt  "), "video/quicktime", "video/quicktime", "QuickTime"),
    ("old.mov", struct.pack(">I", 64) + b"moov" + b"\0" * 56, "video/quicktime", "video/quicktime", None),
    ("a.m4a", _ftyp(b"M4A ", b"M4A ", b"mp42"), "audio/mp4", "audio/mp4", None),
    ("a.3gp", _ftyp(b"3gp5", b"3gp5"), "video/3gpp", "video/3gpp", None),
    ("a.mkv", b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\x82\x88matroska", "video/x-matroska", "video/x-matroska",
     "Matroska"),
    ("a.webm", b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\x82\x84webm", "video/webm", "video/webm", "WebM"),
    ("a.avi", b"RIFF" + struct.pack("<I", 100) + b"AVI LIST", "video/x-msvideo", "video/x-msvideo", None),
    ("a.flv", b"FLV\x01\x05\x00\x00\x00\x09", "video/x-flv", "video/x-flv", None),
    ("a.mpg", b"\x00\x00\x01\xba\x44\x00\x04\x00", "video/mpeg", "video/mpeg", None),
    ("a.ts", (b"G\x40\x00\x10" + b"\xff" * 184) * 22, "video/mp2t", "video/mp2t", "transport stream"),
    # Fonts
    ("a.ttf", b"\x00\x01\x00\x00" + struct.pack(">HHHH", 10, 128, 3, 32), "font/ttf", "font/ttf", "10 tables"),
    ("a.otf", b"OTTO" + struct.pack(">HHHH", 12, 128, 3, 64), "font/otf", "font/otf", None),
    ("a.woff", b"wOFF\x00\x01\x00\x00" + b"\0" * 8, "font/woff", "font/woff", None),
    ("a.woff2", b"wOF2OTTO" + b"\0" * 8, "font/woff2", "font/woff2", None),
    # Databases, datasets and machine-learning models
    ("a.sqlite", b"SQLite format 3\x00\x10\x00", "database/sqlite", "application/vnd.sqlite3", None),
    ("a.h5", b"\x89HDF\r\n\x1a\n\x00\x00", "dataset/hdf5", "application/x-hdf5", None),
    ("block.h5", b"user block " * 40 + b"\0" * 72 + b"\x89HDF\r\n\x1a\n\x00\x00", "dataset/hdf5",
     "application/x-hdf5", None),
    ("a.npy", b"\x93NUMPY\x01\x00v\x00{'descr': '<f4'}", "dataset/npy", "application/octet-stream", "format version 1"),
    ("a.parquet", b"PAR1\x15\x00\x15\x1c\x15\x1c\x2c\x15\x02\x00", "dataset/parquet", "application/vnd.apache.parquet",
     None),
    ("a.arrow", b"ARROW1\x00\x00\xff\xff\xff\xff", "dataset/arrow", "application/vnd.apache.arrow.file", None),
    ("a.nc", b"CDF\x01\x00\x00\x00\x00", "dataset/netcdf", "application/x-netcdf", None),
    ("a.fits", b"SIMPLE  =                    T / conforms to FITS standard", "dataset/fits", "application/fits", None),
    ("a.mat", b"MATLAB 5.0 MAT-file, Platform: GLNXA64" + b" " * 80, "dataset/matlab", "application/x-matlab-data",
     None),
    ("a.safetensors", struct.pack("<Q", 60) + b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}    ' + b"\0" * 4,
     "ml-model/safetensors", "application/octet-stream", "60-byte header"),
    ("a.gguf", b"GGUF" + struct.pack("<I", 3) + b"\0" * 16, "ml-model/gguf", "application/octet-stream", "version 3"),
    ("legacy.pt", signatures._TORCH_LEGACY_MAGIC + b".\x80\x02M\xe9\x03.", "ml-model/pytorch-legacy",
     "application/octet-stream", "legacy PyTorch"),
    ("a.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=4), "data/pickle", "application/octet-stream", "protocol 4"),
    ("p2.pkl", pickle.dumps({"weights": [1, 2, 3]}, protocol=2), "data/pickle", "application/octet-stream", "protocol 2"),
    ("a.tflite", b"\x1c\x00\x00\x00TFL3\x00\x00\x00\x00", "ml-model/tflite", "application/octet-stream", None),
    # Firmware, filesystems and disk images
    ("uImage", b"\x27\x05\x19\x56" + b"\0" * 60, "firmware/uimage", "application/octet-stream", None),
    ("a.dtb", b"\xd0\x0d\xfe\xed" + struct.pack(">IIIIII", 1000, 56, 200, 40, 17, 16), "firmware/device-tree",
     "application/octet-stream", "version 17"),
    ("boot.img", b"ANDROID!" + b"\0" * 40, "firmware/android-boot", "application/octet-stream", None),
    ("a.uf2", b"UF2\n\x57\x51\x5d\x9e" + b"\0" * 24, "firmware/uf2", "application/octet-stream", None),
    ("rootfs.squashfs", b"hsqs" + b"\0" * 24 + struct.pack("<H", 4) + b"\0" * 66, "filesystem/squashfs",
     "application/vnd.squashfs", "SquashFS 4"),
    ("disk.ext4", _ext(compat=0x4, incompat=0x40), "filesystem/ext4", "application/octet-stream", "ext4"),
    ("disk.ext3", _ext(compat=0x4), "filesystem/ext3", "application/octet-stream", "ext3"),
    ("fat.img", bytes(_boot_sector(fat=b"FAT16   ")), "filesystem/fat", "application/octet-stream", "FAT16"),
    ("disk.img", bytes(_boot_sector(partition=True)), "disk-image/mbr", "application/x-raw-disk-image", "MBR"),
    ("gpt.img", bytes(_boot_sector(partition=True)) + b"EFI PART" + b"\0" * 84, "disk-image/gpt",
     "application/x-raw-disk-image", "GUID partition table"),
    ("a.qcow2", b"QFI\xfb\x00\x00\x00\x03" + b"\0" * 64, "disk-image/qcow2", "application/x-qemu-disk", None),
    ("a.vmdk", b"KDMV\x01\x00\x00\x00" + b"\0" * 64, "disk-image/vmdk", "application/x-vmdk", None),
    ("a.luks", b"LUKS\xba\xbe\x00\x02" + b"\0" * 64, "disk-image/luks", "application/octet-stream", "LUKS2"),
    # Data, version control, key stores and 3D models
    ("a.pcap", b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\0" * 16, "data/pcap", "application/vnd.tcpdump.pcap", None),
    ("a.pcapng", b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x4d\x3c\x2b\x1a" + b"\0" * 16, "data/pcapng",
     "application/x-pcapng", None),
    ("a.ser", b"\xac\xed\x00\x05sr\x00\x04Test", "data/java-serialized", "application/x-java-serialized-object", None),
    ("a.plist", b"bplist00\xd1\x01\x02", "data/plist", "application/x-bplist", None),
    ("pack-1.pack", b"PACK\x00\x00\x00\x02\x00\x00\x00\x03", "vcs/git-pack", "application/octet-stream", None),
    ("index", b"DIRC\x00\x00\x00\x02\x00\x00\x00\x01", "vcs/git-index", "application/octet-stream", None),
    ("a.jks", b"\xfe\xed\xfe\xed\x00\x00\x00\x02", "crypto/java-keystore", "application/x-java-keystore", None),
    ("a.kdbx", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00", "crypto/keepass", "application/x-keepass2", None),
    ("a.glb", b"glTF\x02\x00\x00\x00" + b"\0" * 12, "3d-model/gltf-binary", "model/gltf-binary", None),
]

# (file name, content, signature label, MIME type, detail)
TEXT_FIXTURES: list[tuple[str, bytes, str, str, str]] = [
    ("build", b"#!/bin/sh\nset -e\n", "script/shell", "text/x-shellscript", "#! sh"),
    ("tool", b"#!/usr/bin/env -S python3 -u\nprint(1)\n", "script/python", "text/x-python", "#! python3"),
    ("serve", b"#!/usr/bin/env node\nconsole.log(1)\n", "script/javascript", "text/javascript", "#! node"),
    ("model.bin", b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 1234\n",
     "vcs/git-lfs-pointer", "text/plain", "Git LFS pointer"),
    ("id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n", "crypto/pem", "application/x-pem-file",
     "PEM OPENSSH PRIVATE KEY"),
    ("figure.eps", b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\n", "document/postscript",
     "application/postscript", "Encapsulated PostScript"),
    ("a.rtf", b"{\\rtf1\\ansi\\deff0 Hello}", "document/rtf", "application/rtf", "Rich Text Format"),
    ("logo.svg", b'<?xml version="1.0"?>\n<!-- logo -->\n<svg xmlns="http://www.w3.org/2000/svg"/>', "image/svg",
     "image/svg+xml", "SVG image"),
    ("firmware.hex", (_hex_line(0x0100, 0, bytes(range(16))) + "\n" + _hex_line(0, 1, b"") + "\n").encode("ascii"),
     "firmware/intel-hex", "text/plain", "Intel HEX"),
    ("firmware.s19", (_srec_line(0x0000, b"\x28\x5f\x24\x5f") + "\n" + _srec_line(0x0010, b"\x22\x12") + "\n").encode(),
     "firmware/srec", "text/plain", "S-records"),
]


@pytest.mark.parametrize(("name", "content", "label", "mime", "detail"), FIXTURES, ids=[item[0] for item in FIXTURES])
def test_binary_formats_are_identified_from_their_content(name, content, label, mime, detail):
    result = classify_content(content, name)
    assert (result.file_type, result.type_source, result.mime_type) == (label, "signature", mime)
    assert result.signature is not None and result.signature.label == label
    if detail is not None:
        assert detail in (result.detail or "")
    # The verdict does not depend on the name: the same bytes under another name match too.
    assert classify_content(content, "renamed.dat").file_type == label


@pytest.mark.parametrize(("name", "content", "label", "mime", "detail"), TEXT_FIXTURES,
                         ids=[item[0] for item in TEXT_FIXTURES])
def test_text_formats_keep_the_text_type_and_record_their_format(name, content, label, mime, detail):
    result = classify_content(content, name)
    assert (result.file_type, result.type_source, result.mime_type) == ("text", "content", mime)
    assert result.signature.label == label and detail in result.detail


def test_svg_roots_are_found_after_the_prolog_in_linear_time():
    import time

    from project_discovery.inventory.signatures import _starts_with_svg

    assert _starts_with_svg('<?xml version="1.0"?>\n<!-- a -->\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN">\n<svg>')
    assert _starts_with_svg('  <svg:svg xmlns:svg="http://www.w3.org/2000/svg"/>')
    # A byte-order mark is removed before the prolog is read.
    bom_svg = b"\xef\xbb\xbf<svg xmlns='http://www.w3.org/2000/svg'/>"
    assert classify_content(bom_svg, "icon.svg").signature.label == "image/svg"
    assert _starts_with_svg("<?xml-stylesheet href='a.css'?><svg\nwidth='1'>")
    assert not _starts_with_svg("<html><svg></svg></html>")  # SVG inside another root
    assert not _starts_with_svg("<svgx>") and not _starts_with_svg("<!-- unterminated <svg>")
    # Regression: a regex with a repeated comment group took exponential time here (each
    # comment could run on to a later -->), which hung the regex-complexity test.
    started = time.perf_counter()
    assert not _starts_with_svg("<!-- a --> " * 2000 + "<html>")
    assert not _starts_with_svg("<!-- -->" * 20 + "<!-- --><svg>")  # more prolog items than read
    assert time.perf_counter() - started < 0.5


def test_content_without_a_signature_is_text_binary_or_empty():
    latin1 = "Grüße aus Köln, naïve café\n".encode("latin-1") * 20
    utf16 = "a UTF-16 file written by Windows PowerShell\r\n".encode("utf-16-le") * 4
    assert classify_content(latin1, "notes").file_type == "text"
    assert classify_content(utf16, "out.log").file_type == "text"
    assert classify_content(b"\xff\xfe" + utf16, "out.log").file_type == "text"
    assert classify_content(b"", "empty.py").file_type == "empty"
    assert classify_content(b"", "empty.py").mime_type == "inode/x-empty"
    noise = random.Random(7).randbytes(SAMPLE_BYTES)
    unknown = classify_content(noise, "blob")
    assert (unknown.file_type, unknown.mime_type) == ("binary/unknown", "application/octet-stream")
    assert "compressed or encrypted" in unknown.detail
    structured = classify_content(b"\x01\x00\x02\x00" * 300, "table.bin")
    assert structured.file_type == "binary/unknown" and "compressed" not in structured.detail


def test_looks_textual_accepts_legacy_encodings_and_rejects_control_data():
    assert looks_textual("plain ASCII".encode())
    assert looks_textual("Größe".encode("utf-8")[:-1])  # a character cut at the sample end
    assert looks_textual("Größe und Gewicht".encode("cp1252"))
    assert not looks_textual(b"text\x00with a NUL")
    # Valid UTF-8 counts as text even with control characters (^A-delimited data files are
    # text); an 8-bit sample needs almost none.
    assert looks_textual(b"field\x01value\x01" * 20)
    assert not looks_textual("é".encode("latin-1") + bytes(range(1, 32)) * 8)
    # NUL-interleaved bytes that decode to control characters are not UTF-16 text.
    assert not looks_textual(bytes(value for code in range(1, 30) for value in (code, 0)) * 4)
    assert looks_textual("UTF-16 without a byte-order mark".encode("utf-16-le"))


def test_a_rejected_candidate_lets_later_rules_match():
    # A safetensors header length whose low bytes read as a pickle opcode, MPEG frame sync
    # or "MZ" made the first candidate the only one tried.
    header = b'{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    for length in (0x280, 0x2FF, 0x5A4D):
        content = struct.pack("<Q", length) + header + b" " * (length - len(header)) + b"\0" * 4
        assert content[:1] in (b"\x80", b"\xff", b"M")
        assert classify_content(content, "model.safetensors").file_type == "ml-model/safetensors"
    # Text that starts like a magic number stays text.
    for text in (b"BMW cars\n", b"MZ is a prefix\n", b"true\n", b"ID3 tags are\n", b"CWS is short for\n"):
        assert classify_content(text, "notes.txt").file_type == "text"


def test_iso_images_are_found_through_the_volume_descriptor_probe():
    image = b"\0" * 32768 + b"\x01CD001\x01\x00" + b"\0" * 2040
    assert signatures.probe_offsets(image[:SAMPLE_BYTES], len(image)) == ((32768, 8),)
    result = classify_content(image, "disc.iso")
    assert (result.file_type, result.detail, result.mismatch) == ("disk-image/iso9660", "ISO 9660 image", False)
    hybrid = bytes(_boot_sector(partition=True)) + b"\0" * (32768 - 512) + b"\x01CD001\x01\x00" + b"\0" * 8
    assert classify_content(hybrid, "live.iso").detail == "ISO 9660 image (hybrid, MBR)"
    udf = b"\0" * 32768 + b"\x00BEA01\x01\x00" + b"\0" * 8
    assert classify_content(udf, "movie.iso").file_type == "disk-image/udf"
    # Without the probe (too small for one), an all-zero file has no signature.
    assert classify_content(b"\0" * 8192, "zeros.bin").file_type == "binary/unknown"


def test_ole_directories_past_the_sample_are_read_through_a_probe():
    document = _ole("WordDocument", directory_sector=10)
    start, sector = signatures.ole_directory(document[:SAMPLE_BYTES])
    assert start == 11 * 512 > SAMPLE_BYTES
    assert signatures.probe_offsets(document[:SAMPLE_BYTES], len(document)) == ((start, signatures.OLE_DIRECTORY_PROBE_BYTES),)
    assert classify_content(document, "report.doc").file_type == "document/doc"
    # Without the probe the container is still recognized, with no subtype.
    sample_only = classify(document[:SAMPLE_BYTES], "report.doc", size=len(document))
    assert (sample_only.file_type, sample_only.detail) == (
        "document/ole", "OLE compound file; its directory is past the sample",
    )


def test_names_suggest_types_independently_of_the_content():
    assert name_type("dist/app.tar.gz").label == "archive/tar+gzip"
    assert name_type("lib/libssl.so.3").label == "library/elf"
    assert name_type("lib/LIBSSL.SO").label == "library/elf"
    assert name_type("src/main.py").label == "source"
    assert name_type("README.md").label == "text"
    assert name_type("bin/tool") is None and name_type("LICENSE") is None
    assert name_type("C:\\data\\photo.JPG").label == "image/jpeg"
    # Names in --inventory-only scans: the type comes from the name, and says so.
    named = classify(None, "photo.png")
    assert (named.file_type, named.type_source, named.mime_type, named.signature) == ("image/png", "name", None, None)
    assert classify(None, "notes").file_type == "unclassified"


@pytest.mark.parametrize(("name", "content", "mismatch"), [
    ("photo.png", _elf(2), True),  # an executable disguised as an image
    ("download.zip", b"<!DOCTYPE html><html><body>Not found</body></html>", True),  # an error page saved as a ZIP
    ("data.json", b"\x1f\x8b\x08\x00" + b"\0" * 30, True),  # compressed, named as text
    ("weights.json", b"\x00\x01\x02\x03" * 64, True),  # binary content, text name
    ("photo.png", bytes(range(256)) * 2, True),  # the PNG signature is missing
    ("song.mp3", bytes(range(256)) * 2, False),  # MP3 frames need not start the file
    ("image.png", b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"b" * 64 + b"\nsize 9\n", False),
    ("libc.so", b"/* GNU ld script */\nGROUP ( /lib/libc.so.6 )\n", False),  # a linker script
    ("report.docx", _zip(("[Content_Types].xml", "x"), ("word/document.xml", "x")), False),
    ("bundle.jar", _zip(("readme.txt", "x")), False),  # a ZIP without a manifest is still a JAR's container
    ("clip.ts", (b"G\x40\x00\x10" + b"\xff" * 184) * 22, False),  # a transport stream, not TypeScript
    ("app.ts", b"export const x = 1;\n", False),
    ("empty.png", b"", False),
])
def test_names_and_contents_that_disagree_are_flagged(name, content, mismatch):
    assert classify_content(content, name).mismatch is mismatch


def test_the_python_matcher_agrees_with_the_compiled_classifier():
    native = pytest.importorskip("project_discovery._native_cpp")
    if not signatures.cpp_rules_current():
        pytest.skip("the C++ classifier was built from another catalog; rebuild it")
    samples = [content for _, content, *_ in FIXTURES + TEXT_FIXTURES]
    rng = random.Random(11)
    samples += [rng.randbytes(rng.randrange(0, 2200)) for _ in range(500)]
    for rule in rng.sample(RULES, 60):  # random bytes that pass a rule's tests
        data = bytearray(rng.randbytes(1200 + max(offset + len(bytes_) for offset, bytes_ in rule.tests)))
        for offset, bytes_ in rule.tests:
            data[offset:offset + len(bytes_)] = bytes_
        samples.append(bytes(data))
    for sample in samples:
        for length in sorted({0, 1, 2, 4, 8, 16, 64, 511, 1100, len(sample)}):
            truncated = sample[:length]
            start = 0
            while True:
                expected = python_match_rule(truncated, start)
                assert native.match_rule(truncated, start) == expected
                if expected is None:
                    break
                start = expected + 1


def test_every_rule_is_well_formed_and_labels_have_one_mime_type():
    for rule in RULES:
        assert rule.tests and all(isinstance(offset, int) and offset >= 0 and data for offset, data in rule.tests)
        assert "/" in rule.kind.label and rule.kind.mime and rule.kind.family
    assert len(signatures.KINDS) >= 150
    assert all(signatures.family_of(kind.label) == kind.family for kind in signatures.KINDS.values())


# ---------------------------------------------------------------------------------------
# Scans

def _walkers(monkeypatch):
    from project_discovery.inventory import scanner

    yield "native"
    monkeypatch.setattr(scanner, "native_create_walker", lambda *_args, **_kwargs: None)
    yield "python"


def _project(root: Path) -> Path:
    root.mkdir()
    (root / "libz.so").write_bytes(_elf(3))
    (root / "photo.png").write_bytes(_elf(2))
    (root / "model.safetensors").write_bytes(
        b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"c" * 64 + b"\nsize 1234\n"
    )
    (root / "report.doc").write_bytes(_ole("WordDocument", directory_sector=10))
    (root / "disc.iso").write_bytes(b"\0" * 32768 + b"\x01CD001\x01\x00" + b"\0" * 2040)
    (root / "notes.txt").write_bytes("Grüße\n".encode("latin-1"))
    (root / "empty.py").write_bytes(b"")
    (root / "run").write_bytes(b"#!/bin/bash\necho hi\n")
    return root


def test_both_walkers_record_signatures_mime_types_and_mismatches(tmp_path: Path, monkeypatch):
    from project_discovery.inventory.scanner import discover_inventory

    project = _project(tmp_path / "project")
    seen = []
    for _ in _walkers(monkeypatch):
        files, *_, stats = discover_inventory(project)
        records = {record.path: record for record in files}
        summary = {
            path: (record.file_type, record.type_source, record.signature, record.mime_type, record.name_type,
                   record.type_mismatch)
            for path, record in records.items()
        }
        assert summary == {
            "libz.so": ("library/elf", "signature", "library/elf", "application/x-sharedlib", "library/elf", False),
            "photo.png": ("executable/elf", "signature", "executable/elf", "application/x-executable", "image/png", True),
            "model.safetensors": ("text", "content", "vcs/git-lfs-pointer", "text/plain", "ml-model/safetensors", False),
            "report.doc": ("document/doc", "signature", "document/doc", "application/msword", "document/doc", False),
            "disc.iso": ("disk-image/iso9660", "signature", "disk-image/iso9660", "application/x-iso9660-image",
                         "disk-image/iso", False),
            "notes.txt": ("text", "content", None, "text/plain", "text", False),
            "empty.py": ("empty", "content", None, "inode/x-empty", "source", False),
            "run": ("text", "content", "script/shell", "text/x-shellscript", None, False),
        }
        assert records["libz.so"].type_detail == "ELF 64-bit LSB shared object, x86-64"
        assert stats["type_mismatch_count"] == 1 and stats["type_mismatch:image/png → executable/elf"] == 1
        assert stats["git_lfs_pointer_count"] == 1
        assert stats["type_source:signature"] == 4 and stats["type_source:content"] == 4
        seen.append(summary)
    assert seen[0] == seen[1]


def test_scan_reports_carry_type_sources_mime_types_and_mismatches(tmp_path: Path):
    from project_discovery.cli import run_scan

    project = _project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json", "markdown"}, 128, quiet=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    metrics = report["metrics"]
    assert metrics["type_sources"] == {"signature": 4, "content": 4}
    assert metrics["mime_types"]["text/plain"] == 2 and metrics["mime_types"]["application/msword"] == 1
    assert metrics["type_mismatches"] == {"count": 1, "pairs": {"image/png → executable/elf": 1}}
    assert metrics["git_lfs_pointer_count"] == 1
    photo = next(item for item in report["files"] if item["path"] == "photo.png")
    assert (photo["signature"], photo["name_type"], photo["type_mismatch"]) == ("executable/elf", "image/png", True)
    markdown = (output / "discovery-report.md").read_text(encoding="utf-8")
    assert "- File types determined by: signature 4, content 4" in markdown
    assert "- Name/content mismatches: 1 (image/png → executable/elf 1)" in markdown
    assert "- Git LFS pointers: 1 (content not in the tree)" in markdown
    assert "- photo.png: the name suggests image/png, the content is executable/elf (ELF 64-bit LSB executable, x86-64)" in markdown


def test_inventory_only_scans_classify_by_name_and_say_so(tmp_path: Path):
    from project_discovery.cli import run_scan

    project = _project(tmp_path / "project")
    output = tmp_path / "out"
    assert run_scan(project, output, {"json"}, 128, quiet=True, inventory_only=True) == 0
    report = json.loads((output / "discovery-report.json").read_text(encoding="utf-8"))
    photo = next(item for item in report["files"] if item["path"] == "photo.png")
    assert (photo["file_type"], photo["type_source"], photo["signature"], photo["mime_type"]) == (
        "image/png", "name", None, None,
    )
    assert report["metrics"]["type_sources"] == {"name": 8}
    assert report["metrics"]["type_mismatches"]["count"] == 0


def test_an_inventory_from_another_catalog_version_is_not_resumed(tmp_path: Path, monkeypatch):
    from project_discovery import cli
    from project_discovery.inventory.scanner import inventory_options
    from project_discovery.inventory.store import InventoryStore

    options = inventory_options(
        read_signatures=True, skip_oversized=False, max_file_bytes=1, excluded_names=set(), excluded_paths=set(),
    )
    path = tmp_path / "inventory.sqlite3"
    with InventoryStore(path) as store:
        store.checkpoint({
            "root": str(tmp_path), "traversal_finished": True, "inventory_status": "complete",
            "inventory_options": {**options, "signature_catalog": signatures.CATALOG_VERSION - 1},
            "walk_stats": {"entry_count": 3},
        })
    assert cli._resumable_walk_stats(path, tmp_path, options) is None
    with InventoryStore(path) as store:
        store.checkpoint({"inventory_options": options})
    assert cli._resumable_walk_stats(path, tmp_path, options) == {"entry_count": 3}


@pytest.mark.skipif(os.name == "nt", reason="the probe test needs a sparse POSIX file to stay fast")
def test_probes_read_far_offsets_of_large_files_without_reading_the_rest(tmp_path: Path):
    from project_discovery.inventory.scanner import _classify_file

    path = tmp_path / "large.iso"
    with path.open("wb") as stream:
        stream.seek(32768)
        stream.write(b"\x01CD001\x01\x00")
        stream.truncate(1 << 30)  # a sparse 1 GiB file
    classification, _ = _classify_file(path, "large.iso", path.stat())
    assert classification.file_type == "disk-image/iso9660"
