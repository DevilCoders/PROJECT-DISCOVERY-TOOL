"""Ownership, platform attributes and opt-in security metadata of inventory entries.

Every inventory record carries the POSIX owner and group IDs (None on Windows, which has no
numeric IDs) and the names of the entry's platform attributes: the Windows
``FILE_ATTRIBUTE_*`` bits, or the macOS file flags (``st_flags``). With
``--security-metadata`` a record also carries the owner and group SIDs and the DACL of the
Windows security descriptor, or the POSIX access and default ACLs on Linux. Nothing here
follows a link, reads file contents or recalls an offline file.
"""
from __future__ import annotations

import errno
import functools
import os
import struct
import sys
from typing import Any

# Windows FILE_ATTRIBUTE_* bits, named as the constant without its prefix, in lower case.
_WINDOWS_ATTRIBUTES = (
    (0x1, "readonly"), (0x2, "hidden"), (0x4, "system"), (0x20, "archive"), (0x40, "device"),
    (0x100, "temporary"), (0x200, "sparse_file"), (0x400, "reparse_point"),
    (0x800, "compressed"), (0x1000, "offline"), (0x2000, "not_content_indexed"),
    (0x4000, "encrypted"), (0x8000, "integrity_stream"), (0x10000, "virtual"),
    (0x20000, "no_scrub_data"), (0x40000, "recall_on_open"), (0x80000, "pinned"),
    (0x100000, "unpinned"), (0x400000, "recall_on_data_access"),
    (0x20000000, "strictly_sequential"),
)
# The record type already says these: DIRECTORY, and NORMAL ("no other attribute is set").
_WINDOWS_IMPLIED = 0x10 | 0x80
# macOS file flags (chflags(2)), named as the <sys/stat.h> constant in lower case.
_MACOS_FLAGS = (
    (0x1, "uf_nodump"), (0x2, "uf_immutable"), (0x4, "uf_append"), (0x8, "uf_opaque"),
    (0x20, "uf_compressed"), (0x40, "uf_tracked"), (0x80, "uf_datavault"),
    (0x8000, "uf_hidden"), (0x10000, "sf_archived"), (0x20000, "sf_immutable"),
    (0x40000, "sf_append"), (0x80000, "sf_restricted"), (0x100000, "sf_nounlink"),
    (0x800000, "sf_firmlink"), (0x40000000, "sf_dataless"),
)
_TABLES = {"win32": _WINDOWS_ATTRIBUTES, "darwin": _MACOS_FLAGS}


def attribute_names(bits: int | None, platform: str | None = None) -> list[str]:
    """Names of the set Windows attribute bits (``win32``) or macOS file flags (``darwin``).

    Other platforms record no attributes. A set bit without a name is kept as its
    hexadecimal value, so no bit is lost.
    """
    if not bits:
        return []
    return list(_names(int(bits), sys.platform if platform is None else platform))


@functools.lru_cache(maxsize=1024)
def _names(bits: int, platform: str) -> tuple[str, ...]:
    table = _TABLES.get(platform)
    if table is None:
        return ()
    if platform == "win32":
        bits &= ~_WINDOWS_IMPLIED
    names = [name for bit, name in table if bits & bit]
    unnamed = bits & ~functools.reduce(lambda mask, item: mask | item[0], table, 0)
    names.extend(f"0x{1 << shift:08x}" for shift in range(unnamed.bit_length()) if unnamed >> shift & 1)
    return tuple(names)


# Windows reparse tags (IO_REPARSE_TAG_*), named as the constant without its prefix.
_REPARSE_TAGS = {
    0xA0000003: "mount_point", 0xC0000004: "hsm", 0x80000006: "hsm2", 0x80000007: "sis",
    0x80000008: "wim", 0x80000009: "csv", 0x8000000A: "dfs", 0xA000000C: "symlink",
    0x80000012: "dfsr", 0x80000013: "dedup", 0x80000014: "nfs", 0x80000015: "file_placeholder",
    0x80000017: "wof", 0x80000018: "wci", 0x90001018: "wci_1", 0xA0000019: "global_reparse",
    0x8000001B: "appexeclink", 0x9000001C: "projfs", 0xA000001D: "lx_symlink",
    0x8000001E: "storage_sync", 0xA000001F: "wci_tombstone", 0x80000020: "unhandled",
    0x80000021: "onedrive", 0xA0000022: "projfs_tombstone", 0x80000023: "af_unix",
    0x80000024: "lx_fifo", 0x80000025: "lx_chr", 0x80000026: "lx_blk", 0xA0000027: "wci_link",
    0xA0001027: "wci_link_1", 0xA0000028: "dataless_cim",
}
# Cloud Files placeholders: IO_REPARSE_TAG_CLOUD with a provider variant in bits 12-15.
_CLOUD_TAG, _CLOUD_VARIANTS = 0x9000001A, 0x0000F000
# Reparse points that are special files, not regular ones: AF_UNIX sockets, and the FIFOs
# and device nodes WSL creates on NTFS. Both walkers would otherwise report regular files.
WINDOWS_SPECIAL_TAGS = {
    0x80000023: "socket", 0x80000024: "fifo", 0x80000025: "character_device", 0x80000026: "block_device",
}


def reparse_tag_name(tag: int | None) -> str | None:
    """The name of a Windows reparse tag ("mount_point" for a junction), or its hexadecimal value."""
    if not tag:
        return None
    if tag & ~_CLOUD_VARIANTS == _CLOUD_TAG:
        return "cloud"
    return _REPARSE_TAGS.get(tag, f"0x{tag:08x}")


def device_numbers(rdev: int | None) -> tuple[int | None, int | None]:
    """(major, minor) of a block or character device number, in the platform's encoding."""
    if rdev is None or not hasattr(os, "major"):
        return None, None
    return os.major(rdev), os.minor(rdev)


def stat_ownership(info: os.stat_result) -> tuple[int | None, int | None, list[str]]:
    """(uid, gid, attribute names) of a no-follow stat result, as the Rust walker reports them."""
    if os.name == "nt":
        return None, None, attribute_names(getattr(info, "st_file_attributes", 0), "win32")
    flags = getattr(info, "st_flags", 0) if sys.platform == "darwin" else 0
    return info.st_uid, info.st_gid, attribute_names(flags)


def security_supported() -> bool:
    """Whether --security-metadata can read this platform's security metadata."""
    return os.name == "nt" or sys.platform.startswith("linux")


def read_security(path: str, kind: str) -> dict[str, Any]:
    """The security metadata of one entry, read without following a link.

    ``kind`` is the record kind ("file", "directory", "symlink" or a special entry type).
    Windows: ``owner_sid``, ``group_sid`` and ``dacl`` (None when the descriptor has no
    DACL, which grants everyone full access). Linux: ``posix_acl`` and, for directories,
    ``posix_default_acl``, each None when the entry has no such ACL. A read that fails
    gives ``{"error": "..."}``.
    """
    try:
        if os.name == "nt":
            return _windows_security(path)
        if sys.platform.startswith("linux"):
            return _linux_security(path, kind)
    except (OSError, ValueError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {"error": f"security metadata is not read on {sys.platform}"}


def has_explicit_acl(security: dict[str, Any] | None) -> bool:
    """Whether an entry has access rules of its own: explicit DACL entries, or a POSIX ACL."""
    if not security or "error" in security:
        return False
    dacl = security.get("dacl")
    if isinstance(dacl, dict) and dacl.get("explicit_entries"):
        return True
    return bool(security.get("posix_acl") or security.get("posix_default_acl"))


# Linux POSIX ACLs (the system.posix_acl_access/default extended attributes).
_ACL_TAGS = {
    0x01: ("user", False), 0x02: ("user", True), 0x04: ("group", False),
    0x08: ("group", True), 0x10: ("mask", False), 0x20: ("other", False),
}
_NO_ACL = frozenset(
    code for code in (getattr(errno, "ENODATA", None), errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", None))
    if code is not None
)


def parse_posix_acl(value: bytes) -> list[str]:
    """The entries of a POSIX ACL attribute value, in getfacl's text form with numeric IDs."""
    if len(value) < 4 or (len(value) - 4) % 8:
        raise ValueError(f"malformed POSIX ACL of {len(value)} bytes")
    (version,) = struct.unpack_from("<I", value)
    if version != 2:
        raise ValueError(f"unsupported POSIX ACL version {version}")
    entries = []
    for tag, permissions, identifier in struct.iter_unpack("<HHI", value[4:]):
        if tag not in _ACL_TAGS:
            raise ValueError(f"unknown POSIX ACL entry tag 0x{tag:x}")
        name, qualified = _ACL_TAGS[tag]
        rights = "".join(letter if permissions & bit else "-" for bit, letter in ((4, "r"), (2, "w"), (1, "x")))
        entries.append(f"{name}:{identifier if qualified else ''}:{rights}")
    return entries


def _posix_acl(path: str, name: str) -> list[str] | None:
    try:
        value = os.getxattr(path, name, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in _NO_ACL:  # no such ACL, or a filesystem without ACL support
            return None
        raise
    return parse_posix_acl(value)


def _linux_security(path: str, kind: str) -> dict[str, Any]:
    if kind == "symlink":
        return {"posix_acl": None}  # Linux keeps no ACL on a link itself
    result: dict[str, Any] = {"posix_acl": _posix_acl(path, "system.posix_acl_access")}
    if kind == "directory":
        result["posix_default_acl"] = _posix_acl(path, "system.posix_acl_default")
    return result


# Windows security descriptors, read through a handle opened for READ_CONTROL only.
_READ_CONTROL = 0x00020000
_FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
_OPEN_EXISTING = 3
# Directories, the link itself instead of its target, and no recall of offline data.
_OPEN_FLAGS = 0x02000000 | 0x00200000 | 0x00100000
_SE_FILE_OBJECT = 1
_OWNER_GROUP_DACL = 0x1 | 0x2 | 0x4
_SE_DACL_PROTECTED = 0x1000
_ACL_SIZE_INFORMATION = 2
_INHERITED_ACE = 0x10
_ACE_TYPES = (
    "allow", "deny", "audit", "alarm", "compound_allow", "allow_object", "deny_object",
    "audit_object", "alarm_object", "allow_callback", "deny_callback", "allow_callback_object",
    "deny_callback_object", "audit_callback", "alarm_callback", "audit_callback_object",
    "alarm_callback_object", "mandatory_label", "resource_attribute", "scoped_policy_id",
    "process_trust_label", "access_filter",
)
# Object ACEs keep a flags word and up to two GUIDs between the access mask and the SID.
_OBJECT_ACE_TYPES = frozenset({5, 6, 7, 8, 11, 12, 15, 16})
_COMPOUND_ACE = 4
_ACE_FLAGS = (
    (0x1, "object_inherit"), (0x2, "container_inherit"), (0x4, "no_propagate_inherit"),
    (0x8, "inherit_only"), (0x20, "critical"), (0x40, "successful_access"), (0x80, "failed_access"),
)


@functools.cache
def _windows_api():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.POINTER(ctypes.c_void_p)

    def bind(library, name, restype, *argtypes):
        function = getattr(library, name)
        function.restype, function.argtypes = restype, argtypes
        return function

    class AceHeader(ctypes.Structure):
        _fields_ = (("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort))

    class AclSizeInformation(ctypes.Structure):
        _fields_ = (("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD))

    return {
        "ctypes": ctypes,
        "AceHeader": AceHeader,
        "AclSizeInformation": AclSizeInformation,
        "invalid_handle": ctypes.c_void_p(-1).value,
        "CreateFileW": bind(
            kernel32, "CreateFileW", wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ),
        "CloseHandle": bind(kernel32, "CloseHandle", wintypes.BOOL, wintypes.HANDLE),
        "LocalFree": bind(kernel32, "LocalFree", ctypes.c_void_p, ctypes.c_void_p),
        "GetSecurityInfo": bind(
            advapi32, "GetSecurityInfo", wintypes.DWORD, wintypes.HANDLE, ctypes.c_int,
            wintypes.DWORD, pointer, pointer, pointer, pointer, pointer,
        ),
        "GetSecurityDescriptorControl": bind(
            advapi32, "GetSecurityDescriptorControl", wintypes.BOOL, ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD),
        ),
        "GetAclInformation": bind(
            advapi32, "GetAclInformation", wintypes.BOOL, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_int,
        ),
        "GetAce": bind(advapi32, "GetAce", wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, pointer),
        "IsValidSid": bind(advapi32, "IsValidSid", wintypes.BOOL, ctypes.c_void_p),
        "GetLengthSid": bind(advapi32, "GetLengthSid", wintypes.DWORD, ctypes.c_void_p),
        "ConvertSidToStringSidW": bind(advapi32, "ConvertSidToStringSidW", wintypes.BOOL, ctypes.c_void_p, pointer),
    }


def _extended_path(path: str) -> str:
    """An absolute Windows path in \\\\?\\ form: no length limit, and no name rewriting."""
    path = path.replace("/", "\\")
    if path.startswith(("\\\\?\\", "\\\\.\\")):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def _windows_security(path: str) -> dict[str, Any]:
    api = _windows_api()
    ctypes = api["ctypes"]
    handle = api["CreateFileW"](
        _extended_path(path), _READ_CONTROL, _FILE_SHARE_ALL, None, _OPEN_EXISTING, _OPEN_FLAGS, None,
    )
    if handle is None or handle == api["invalid_handle"]:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        owner, group, dacl, descriptor = (ctypes.c_void_p() for _ in range(4))
        status = api["GetSecurityInfo"](
            handle, _SE_FILE_OBJECT, _OWNER_GROUP_DACL, ctypes.byref(owner), ctypes.byref(group),
            ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )
        if status:
            raise ctypes.WinError(status)
        try:
            control, revision = ctypes.c_ushort(), ctypes.c_ulong()
            if not api["GetSecurityDescriptorControl"](descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise ctypes.WinError(ctypes.get_last_error())
            return {
                "owner_sid": _sid_text(api, owner.value),
                "group_sid": _sid_text(api, group.value),
                "dacl": _dacl(api, dacl.value, bool(control.value & _SE_DACL_PROTECTED)) if dacl.value else None,
            }
        finally:
            api["LocalFree"](descriptor)
    finally:
        api["CloseHandle"](handle)


def _sid_text(api, address: int | None, limit: int | None = None) -> str | None:
    """The S-1-... form of the SID at an address, or None when it is absent or invalid."""
    if not address or not api["IsValidSid"](address):
        return None
    if limit is not None and api["GetLengthSid"](address) > limit:
        return None
    ctypes = api["ctypes"]
    text = ctypes.c_void_p()
    if not api["ConvertSidToStringSidW"](address, ctypes.byref(text)):
        return None
    try:
        return ctypes.wstring_at(text.value)
    finally:
        api["LocalFree"](text)


def _dacl(api, acl: int, protected: bool) -> dict[str, Any]:
    ctypes = api["ctypes"]
    info = api["AclSizeInformation"]()
    if not api["GetAclInformation"](acl, ctypes.byref(info), ctypes.sizeof(info), _ACL_SIZE_INFORMATION):
        raise ctypes.WinError(ctypes.get_last_error())
    explicit, inherited = [], 0
    for index in range(info.AceCount):
        ace = ctypes.c_void_p()
        if not api["GetAce"](acl, index, ctypes.byref(ace)):
            raise ctypes.WinError(ctypes.get_last_error())
        header = api["AceHeader"].from_address(ace.value)
        if header.AceFlags & _INHERITED_ACE:
            inherited += 1
        else:
            explicit.append(_ace(api, ace.value, header))
    # protected: inheritance from the parent is disabled for this entry.
    return {"protected": protected, "explicit_entries": explicit, "inherited_entry_count": inherited}


def _ace(api, address: int, header) -> dict[str, Any]:
    ctypes = api["ctypes"]
    kind, size = header.AceType, header.AceSize
    mask = ctypes.c_uint32.from_address(address + 4).value if size >= 8 else None
    offset = 8
    if kind in _OBJECT_ACE_TYPES and size >= 12:
        present = ctypes.c_uint32.from_address(address + 8).value
        offset = 12 + 16 * bool(present & 0x1) + 16 * bool(present & 0x2)
    sid = None
    if kind != _COMPOUND_ACE and offset + 8 <= size:
        sid = _sid_text(api, address + offset, size - offset)
    return {
        "type": _ACE_TYPES[kind] if kind < len(_ACE_TYPES) else f"type_{kind}",
        "sid": sid,
        "access_mask": mask,
        "flags": [name for bit, name in _ACE_FLAGS if header.AceFlags & bit],
    }
