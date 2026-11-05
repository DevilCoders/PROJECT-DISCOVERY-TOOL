"""Safe, deterministic filesystem inventory with no-follow symlink semantics."""
from __future__ import annotations

import hashlib
import os
import stat
from collections import Counter
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from .language_catalog import detect_language, is_source_path, is_textual_path
from .native_backend import count_byte as native_count_byte
from .native_backend import detect_signature as native_detect_signature
from .native_backend import create_walker as native_create_walker
from .inventory_store import InventoryStore, StoredFileRecords, StoredRecordSequence
from .models import (
    DirectoryRecord,
    FileRecord,
    SpecialEntryRecord,
    SymlinkRecord,
)
from .source_utils import FileIdentity, as_identity, identity_matches, stat_identity

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_REPARSE_TAG_NAME_SURROGATE = 0x20000000

# Kept as a compatibility constant. No directory is excluded by default.
DEFAULT_IGNORES: set[str] = set()

_DEVELOPMENT_MARKERS = {
    ".cache", ".cargo", ".gradle", ".m2", ".ivy2", ".coursier", ".npm",
    ".pnpm-store", ".yarn", ".venv", ".tox", ".nox", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".next", ".nuxt", ".svelte-kit",
    ".angular", ".parcel-cache", ".turbo", ".vite", ".webpack",
    ".nyc_output", ".fuff", ".fuzz", ".fuzzing", ".idea", ".vscode",
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "packages", "target", "build", "dist", "out", "coverage", "htmlcov",
    "venv", "env", "site-packages", "third_party", "third-party",
    "bazel-out", "bazel-bin", "bazel-testlogs", "Pods", "Carthage",
    "DerivedData", "gradle", "maven", "go", "pkg", "obj", "bin",
    "__pycache__", "_build", "_opam", "_site", "artifacts", "generated",
    "generated_code", "gen", "tmp", "temp", "cache", "caches",
    "fuzz", "corpus", "corpora", "crashers", "seeds",
}
_SIZE_BUCKETS = (
    (1024, "under_1_kib"),
    (1024 * 1024, "1_kib_to_1_mib"),
    (10 * 1024 * 1024, "1_to_10_mib"),
    (100 * 1024 * 1024, "10_to_100_mib"),
)


def sha256_file(
    path: Path,
    chunk_size: int = 1024 * 1024,
    expected_info: os.stat_result | None = None,
) -> str:
    """Hash a regular file through a verified no-follow descriptor with bounded memory."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    before = expected_info if expected_info is not None else path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError(f"refusing to hash non-regular entry: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"entry changed to a non-regular file: {path}")
        if not identity_matches(stat_identity(before), stat_identity(opened)):
            raise OSError(f"file identity changed before hashing: {path}")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _size_bucket(size: int) -> str:
    for boundary, label in _SIZE_BUCKETS:
        if size < boundary:
            return label
    return "over_100_mib"


def _is_hidden(name: str, info: os.stat_result) -> bool:
    """Recognize dot-hidden entries and the Windows FILE_ATTRIBUTE_HIDDEN bit."""
    if name.startswith("."):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & 0x2)


def _is_link_like(info: os.stat_result) -> bool:
    """Symlinks plus Windows junctions/mount points, which os.lstat reports as directories."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_tag = getattr(info, "st_reparse_tag", 0)
    return bool(
        attributes & _FILE_ATTRIBUTE_REPARSE_POINT
        and reparse_tag & _REPARSE_TAG_NAME_SURROGATE
    )


def _read_verified_sample(
    path: Path,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> tuple[bytes, FileIdentity]:
    """Read 512 bytes from a verified descriptor; return them with the opened identity."""
    # os.stat_result is itself a tuple subclass; only plain tuples are walker identities.
    walker_stat = isinstance(expected_info, os.stat_result)
    before = expected_info if walker_stat else path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError(f"refusing signature read from non-regular entry: {path}")
    observed_identity = stat_identity(before)
    expected_identity = (
        observed_identity if expected_info is None or walker_stat
        else as_identity(expected_info)
    )
    if not identity_matches(expected_identity, observed_identity):
        raise OSError(f"file identity changed before signature read: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"entry changed to a non-regular file: {path}")
        opened_identity = stat_identity(opened)
        if not (
            identity_matches(observed_identity, opened_identity)
            and identity_matches(expected_identity, opened_identity)
        ):
            raise OSError(f"file identity changed during signature read: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read(512), opened_identity
    finally:
        os.close(descriptor)


def _read_signature_sample(
    path: Path,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> bytes:
    """Read 512 bytes from a verified descriptor matching walker metadata."""
    return _read_verified_sample(path, expected_info)[0]


def _classify_head(head: bytes, relative_path: str) -> str | None:
    """Classify common binary formats from a bounded signature sample."""
    if not head:
        return None
    native_type = native_detect_signature(head)
    if native_type:
        return native_type

    # Portable fallback signature catalog.
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "archive/zip"
    if head.startswith(b"\x1f\x8b"):
        return "archive/gzip"
    if head.startswith(b"BZh"):
        return "archive/bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "archive/xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "archive/zstandard"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "archive/7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "archive/rar"
    if head.startswith(b"MSCF"):
        return "archive/cab"
    if head.startswith(b"!<arch>"):
        return "archive/ar"
    if head.startswith(b"\xed\xab\xee\xdb"):
        return "archive/rpm"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "archive/tar"

    # Documents, executable formats, databases and media.
    if head.startswith(b"%PDF-"):
        return "document/pdf"
    if head.startswith(b"\x7fELF"):
        return "executable/elf"
    if head.startswith(b"MZ"):
        return "executable/pe"
    if head[:4] in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    }:
        return "executable/mach-o-or-fat"
    if head.startswith(b"SQLite format 3\x00"):
        return "database/sqlite"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"BM"):
        return "image/bmp"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "audio/wav"
    if head.startswith(b"ID3") or head[:2] in {b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"}:
        return "audio/mpeg"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "video/mp4"
    if head.startswith(b"wOFF"):
        return "font/woff"
    if head.startswith(b"wOF2"):
        return "font/woff2"
    if head.startswith(b"OTTO"):
        return "font/otf"
    if head.startswith(b"\x00\x01\x00\x00"):
        return "font/ttf"

    # TAR and package formats with extension-specific signatures/containers.
    lower = relative_path.lower()
    if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "archive/tar-or-compressed-tar"
    if lower.endswith(".deb") and head.startswith(b"!<arch>"):
        return "archive/deb"
    if lower.endswith(".iso"):
        return "archive/iso-detected-by-extension"
    if native_count_byte(head, 0) > 0:
        return "binary/unknown"
    return None


def _signature_type(
    path: Path,
    relative_path: str,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> str | None:
    """Classify common binary formats from a bounded, no-follow signature sample."""
    try:
        head = _read_signature_sample(path, expected_info)
    except OSError:
        return None
    return _classify_head(head, relative_path)


def _classify_file(
    path: Path,
    relative_path: str,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> tuple[str, FileIdentity | None]:
    """Return the file type and the descriptor-verified identity observed while sampling."""
    try:
        head, opened_identity = _read_verified_sample(path, expected_info)
    except OSError:
        head, opened_identity = b"", None
    signature = _classify_head(head, relative_path)
    if signature:
        return signature, opened_identity
    if is_source_path(relative_path):
        return "source", opened_identity
    if is_textual_path(relative_path):
        return "text", opened_identity
    return "binary/unclassified", opened_identity


def _file_type(
    path: Path,
    relative_path: str,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> str:
    return _classify_file(path, relative_path, expected_info)[0]



def _symlink_scope(root: Path, link_path: Path, target: str) -> str:
    """Classify a symlink target lexically without resolving or stat-following it."""
    try:
        candidate = Path(target)
        if not candidate.is_absolute():
            candidate = link_path.parent / candidate
        normalized_root = os.path.normcase(os.path.abspath(os.path.normpath(str(root))))
        normalized_target = os.path.normcase(os.path.abspath(os.path.normpath(str(candidate))))
        common = os.path.commonpath((normalized_root, normalized_target))
        return "internal" if common == normalized_root else "external"
    except ValueError:
        # Different Windows drives or filesystem roots are necessarily external.
        return "external"
    except OSError:
        return "unknown"


def _normalise_exclusions(ignores: set[str] | None) -> tuple[set[str], set[str]]:
    names: set[str] = set()
    paths: set[str] = set()
    for raw in ignores or ():
        value = raw.replace("\\", "/").strip("/")
        if not value:
            continue
        if "/" in value:
            paths.add(value.casefold())
        else:
            names.add(value.casefold())
    return names, paths


def _exclusion_match(
    relative_path: str, name: str, excluded_names: set[str], excluded_paths: set[str],
) -> str | None:
    if name.casefold() in excluded_names:
        return f"explicit --exclude-dir name: {name}"
    if relative_path.casefold() in excluded_paths:
        return f"explicit --exclude-dir path: {relative_path}"
    return None


def discover_files(
    root: Path,
    *,
    max_file_bytes: int = 128 * 1024 * 1024,
    ignores: set[str] | None = None,
    skip_oversized: bool = False,
) -> tuple[list[FileRecord], dict[str, int]]:
    """Compatibility file iterator; no implicit ignore list or global size skip."""
    files, _, _, _, stats = discover_inventory(
        root,
        max_file_bytes=max_file_bytes,
        skip_oversized=skip_oversized,
        ignores=ignores,
    )
    return files, stats



def _discover_with_rust(
    root: Path,
    excluded_names: set[str],
    excluded_paths: set[str],
    max_file_bytes: int,
    skip_oversized: bool,
    directories_by_path: dict[str, DirectoryRecord],
    files: list[FileRecord],
    symlinks: list[SymlinkRecord],
    special_entries: list[SpecialEntryRecord],
    stats: Counter[str],
    store: InventoryStore | None = None,
) -> bool:
    """Consume the optional Rust directory iterator; return False if unavailable."""
    try:
        walker = native_create_walker(root, excluded_names, excluded_paths)
    except OSError as exc:
        message = f"{type(exc).__name__}: {exc}"
        if store is None:
            directories_by_path["."].error = message
        else:
            store.adjust_directory(".", error=message)
        stats["walk_errors"] += 1
        return True
    if walker is None:
        return False
    for relative, kind, size, mode, mtime_ns, hidden, target, error, depth, device_id, inode_id, ctime_ns in walker:
        # The walker returns lossless OS strings with native separators. A backslash is
        # a legal POSIX file-name character, so only Windows separators are rewritten.
        if os.sep == "\\":
            relative = relative.replace("\\", "/")
        if kind == "directory_error":
            message = error or "Directory read failed"
            if store is None:
                record = directories_by_path.get(relative)
                if record is not None:
                    record.error = message
            else:
                store.adjust_directory(relative, error=message)
            stats["walk_errors"] += 1
            continue
        stats["entry_count"] += 1
        parent = PurePosixPath(relative).parent.as_posix() or "."
        if store is None:
            parent_record = directories_by_path.get(parent)
            if parent_record is not None:
                parent_record.direct_child_count += 1
        else:
            store.adjust_directory(parent, direct_child_delta=1)
        if hidden:
            stats["hidden_entry_count"] += 1
        if kind == "entry_error":
            stats["entry_errors"] += 1
            entry_record = FileRecord(
                relative, 0, Path(relative).suffix.lower(), "Unknown",
                error=error or "Entry metadata unavailable", is_hidden=hidden,
            )
            if store is None:
                files.append(entry_record)
            else:
                store.append("file", entry_record)
                _update_file_ancestor_totals(relative, 0, store)
            continue
        if kind == "symlink":
            scope = _symlink_scope(root, root / relative, target)
            link_record = SymlinkRecord(
                relative, target, scope, target_state="unverified",
                is_hidden=hidden, permissions=mode,
            )
            if store is None:
                symlinks.append(link_record)
            else:
                store.append("symlink", link_record)
            stats["symlink_count"] += 1
            stats[f"symlink_scope:{scope}"] += 1
            continue
        if kind == "directory":
            name = PurePosixPath(relative).name
            marker = name.casefold() if name.casefold() in _DEVELOPMENT_MARKERS else None
            exclusion = _exclusion_match(relative, name, excluded_names, excluded_paths)
            record = DirectoryRecord(
                relative, depth, is_hidden=hidden, permissions=mode,
                development_marker=marker, pruned=exclusion is not None,
                prune_reason=exclusion, error=error,
            )
            if store is None:
                directories_by_path[relative] = record
            else:
                store.append("directory", record)
            if marker:
                stats["development_directory_count"] += 1
                stats[f"development_dir:{marker}"] += 1
            if exclusion:
                stats["pruned_directory_count"] += 1
                stats[f"pruned_dir:{name.casefold()}"] += 1
            if error:
                stats["walk_errors"] += 1
            continue
        if kind == "file":
            path = root / relative
            file_identity = (
                device_id, inode_id, size, mtime_ns, ctime_ns,
            ) if device_id is not None and inode_id is not None else None
            file_type, opened_identity = _classify_file(path, relative, file_identity)
            language = detect_language(relative)
            record = FileRecord(
                relative, size, Path(relative).suffix.lower(), language,
                file_type=file_type, size_bucket=_size_bucket(size),
                is_hidden=hidden, permissions=mode, mtime_ns=mtime_ns,
                # Prefer the descriptor-verified identity; the Windows walker
                # cannot report a file ID itself.
                analysis_identity=opened_identity or file_identity,
            )
            if size > max_file_bytes and skip_oversized:
                record.content_skipped_reason = (
                    f"Explicit --skip: exceeds {max_file_bytes} bytes"
                )
                stats["oversized_content_skipped"] += 1
            if store is None:
                files.append(record)
            else:
                store.append("file", record)
                _update_file_ancestor_totals(relative, size, store)
            stats["total_bytes"] += size
            stats[f"file_type:{file_type}"] += 1
            stats[f"size_bucket:{record.size_bucket}"] += 1
            stats[f"language:{language}"] += 1
            continue
        special_record = SpecialEntryRecord(
            relative, kind, is_hidden=hidden, permissions=mode, size_bytes=size,
        )
        if store is None:
            special_entries.append(special_record)
        else:
            store.append("special", special_record)
        stats["special_entry_count"] += 1
        stats[f"special_type:{kind}"] += 1
    return True



def _update_file_ancestor_totals(
    relative_path: str,
    size_bytes: int,
    store: InventoryStore,
) -> None:
    """Update directory aggregates incrementally without retaining directory objects."""
    parent = PurePosixPath(relative_path).parent
    while True:
        key = parent.as_posix() or "."
        store.adjust_directory(key, file_count_delta=1, total_bytes_delta=size_bytes)
        if key == ".":
            break
        parent = parent.parent


def discover_inventory(
    root: Path,
    *,
    max_file_bytes: int = 128 * 1024 * 1024,
    skip_oversized: bool = False,
    ignores: set[str] | None = None,
    store: InventoryStore | None = None,
) -> tuple[
    Sequence[FileRecord],
    Sequence[DirectoryRecord],
    Sequence[SymlinkRecord],
    Sequence[SpecialEntryRecord],
    dict[str, int],
]:
    """Inventory all entries by default; only explicit excludes prune subtrees.

    The traversal never follows symlinks. With a store, file, directory, symlink and
    special-entry records are persisted in bounded batches and returned through lazy
    SQLite-backed sequences. Directory counters and errors are updated incrementally
    in SQLite; only the active Python fallback iterator stack remains depth-bounded in
    memory. Analyzer findings and report aggregation still have separate memory gates.
    """
    root = root.expanduser().absolute()
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode):
        raise ValueError("The scan root itself is a symlink; pass its real directory path explicitly.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be >= 1")

    excluded_names, excluded_paths = _normalise_exclusions(ignores)
    stats: Counter[str] = Counter()
    try:
        root_info = root.stat()
        root_mode = stat.S_IMODE(root_info.st_mode)
        root_hidden = _is_hidden(root.name, root_info) if root.name else False
    except OSError:
        root_mode, root_hidden = None, False
    if store is not None:
        store.clear()
        stats["inventory_store_enabled"] = 1
        store.checkpoint({"inventory_status": "running", "root": str(root)})
    root_directory = DirectoryRecord(".", 0, permissions=root_mode, is_hidden=root_hidden)
    directories_by_path: dict[str, DirectoryRecord] = {}
    if store is None:
        directories_by_path["."] = root_directory
    else:
        store.append("directory", root_directory)
    files: list[FileRecord] = []
    symlinks: list[SymlinkRecord] = []
    special_entries: list[SpecialEntryRecord] = []
    used_rust = _discover_with_rust(
        root, excluded_names, excluded_paths, max_file_bytes, skip_oversized,
        directories_by_path, files, symlinks, special_entries, stats, store,
    )
    scandir_stack = []
    if not used_rust:
        try:
            root_iterator = os.scandir(root)
        except OSError as exc:
            message = f"{type(exc).__name__}: {exc}"
            if store is None:
                root_directory.error = message
            else:
                store.adjust_directory(".", error=message)
            stats["walk_errors"] += 1
        else:
            scandir_stack.append((root, ".", 0, root_directory, root_iterator))

    # Keep only active directory iterators on the Python fallback stack. This is
    # O(depth), not O(number of sibling directories) for high-fan-out trees.
    while scandir_stack:
        current, relative_dir, depth, directory_record, entries = scandir_stack[-1]
        try:
            entry = next(entries)
        except StopIteration:
            entries.close()
            scandir_stack.pop()
            continue
        except OSError as exc:
            message = f"{type(exc).__name__}: {exc}"
            directory_record.error = message
            if store is not None:
                store.adjust_directory(relative_dir, error=message)
            stats["walk_errors"] += 1
            entries.close()
            scandir_stack.pop()
            continue
        relative = entry.name if relative_dir == "." else f"{relative_dir}/{entry.name}"
        stats["entry_count"] += 1
        if store is None:
            directory_record.direct_child_count += 1
        else:
            store.adjust_directory(relative_dir, direct_child_delta=1)
        try:
            info = entry.stat(follow_symlinks=False)
            hidden = _is_hidden(entry.name, info)
            if hidden:
                stats["hidden_entry_count"] += 1

            if _is_link_like(info):
                try:
                    target = os.readlink(entry.path)
                    scope = _symlink_scope(root, Path(entry.path), target)
                except OSError:
                    target, scope = "", "unknown"
                link_record = SymlinkRecord(
                    relative, target, scope, target_state="unverified", is_hidden=hidden,
                    permissions=stat.S_IMODE(info.st_mode),
                )
                if store is None:
                    symlinks.append(link_record)
                else:
                    store.append("symlink", link_record)
                stats["symlink_count"] += 1
                stats[f"symlink_scope:{scope}"] += 1
                continue

            if stat.S_ISDIR(info.st_mode):
                marker = entry.name.casefold() if entry.name.casefold() in _DEVELOPMENT_MARKERS else None
                exclusion = _exclusion_match(
                    relative, entry.name, excluded_names, excluded_paths,
                )
                record = DirectoryRecord(
                    relative,
                    depth + 1,
                    is_hidden=hidden,
                    permissions=stat.S_IMODE(info.st_mode),
                    development_marker=marker,
                    pruned=exclusion is not None,
                    prune_reason=exclusion,
                )
                if store is None:
                    directories_by_path[relative] = record
                else:
                    store.append("directory", record)
                if marker:
                    stats["development_directory_count"] += 1
                    stats[f"development_dir:{marker}"] += 1
                if exclusion:
                    stats["pruned_directory_count"] += 1
                    stats[f"pruned_dir:{entry.name.casefold()}"] += 1
                else:
                    try:
                        child_iterator = os.scandir(entry.path)
                    except OSError as exc:
                        message = f"{type(exc).__name__}: {exc}"
                        record.error = message
                        if store is not None:
                            store.adjust_directory(relative, error=message)
                        stats["walk_errors"] += 1
                    else:
                        scandir_stack.append((
                            Path(entry.path), relative, depth + 1,
                            record, child_iterator,
                        ))
                continue

            if stat.S_ISREG(info.st_mode):
                size = info.st_size
                file_type, opened_identity = _classify_file(Path(entry.path), relative, info)
                language = detect_language(relative)
                file_record = FileRecord(
                    relative,
                    size,
                    Path(entry.name).suffix.lower(),
                    language,
                    file_type=file_type,
                    size_bucket=_size_bucket(size),
                    is_hidden=hidden,
                    permissions=stat.S_IMODE(info.st_mode),
                    mtime_ns=info.st_mtime_ns,
                    analysis_identity=opened_identity or stat_identity(info),
                )
                if size > max_file_bytes and skip_oversized:
                    file_record.content_skipped_reason = (
                        f"Explicit --skip: exceeds {max_file_bytes} bytes"
                    )
                    stats["oversized_content_skipped"] += 1
                if store is None:
                    files.append(file_record)
                else:
                    store.append("file", file_record)
                    _update_file_ancestor_totals(relative, size, store)
                stats["total_bytes"] += size
                stats[f"file_type:{file_type}"] += 1
                stats[f"size_bucket:{file_record.size_bucket}"] += 1
                stats[f"language:{language}"] += 1
                continue

            if stat.S_ISFIFO(info.st_mode):
                kind = "fifo"
            elif stat.S_ISSOCK(info.st_mode):
                kind = "socket"
            elif stat.S_ISBLK(info.st_mode):
                kind = "block_device"
            elif stat.S_ISCHR(info.st_mode):
                kind = "character_device"
            else:
                kind = "unknown_special"
            special_record = SpecialEntryRecord(
                relative,
                kind,
                is_hidden=hidden,
                permissions=stat.S_IMODE(info.st_mode),
                size_bytes=getattr(info, "st_size", 0),
            )
            if store is None:
                special_entries.append(special_record)
            else:
                store.append("special", special_record)
            stats["special_entry_count"] += 1
            stats[f"special_type:{kind}"] += 1
        except OSError as exc:
            stats["entry_errors"] += 1
            error_record = FileRecord(
                relative, 0, Path(entry.name).suffix.lower(), "Unknown",
                error=f"{type(exc).__name__}: {exc}",
                is_hidden=entry.name.startswith("."),
            )
            if store is None:
                files.append(error_record)
            else:
                store.append("file", error_record)
                _update_file_ancestor_totals(relative, 0, store)

    # The no-store compatibility path still aggregates from its in-memory file list.
    if store is None:
        for file_record in files:
            parent = PurePosixPath(file_record.path).parent
            while True:
                key = parent.as_posix() or "."
                record = directories_by_path.get(key)
                if record is not None:
                    record.file_count += 1
                    record.total_bytes += file_record.size_bytes
                if key == ".":
                    break
                parent = parent.parent

    if store is not None:
        # Directory records and aggregate deltas are persisted as traversal proceeds.
        store.flush()
        walk_errors = stats.get("walk_errors", 0)
        entry_errors = stats.get("entry_errors", 0)
        store.checkpoint({
            "inventory_status": "complete" if not (walk_errors or entry_errors) else "partial",
            "traversal_finished": True,
            "root": str(root),
            "record_counts": {
                "file": store.count("file"),
                "directory": store.count("directory"),
                "symlink": store.count("symlink"),
                "special": store.count("special"),
            },
            "walk_errors": walk_errors,
            "entry_errors": entry_errors,
        })
        stats["inventory_store_record_count"] = sum(store.counts().values())
        stats["inventory_store_integrity_ok"] = int(store.integrity_check() == "ok")
        stats["inventory_store_partial"] = int(bool(walk_errors or entry_errors))
        # Persisted so `pdt scan --resume` can report the original traversal statistics.
        store.set_metadata("walk_stats", dict(stats))

    # With a store, file records are read lazily from SQLite in deterministic
    # case-folded path order. The in-memory fallback retains its compatibility sort.
    if store is None:
        files.sort(key=lambda item: (item.path.casefold(), item.path))
        symlinks.sort(key=lambda item: (item.path.casefold(), item.path))
        special_entries.sort(key=lambda item: (item.path.casefold(), item.path))
    else:
        files = StoredFileRecords(store.path)
        symlinks = StoredRecordSequence(store.path, "symlink", SymlinkRecord)
        special_entries = StoredRecordSequence(
            store.path, "special", SpecialEntryRecord,
        )
    if store is None:
        directories = list(directories_by_path.values())
        directories.sort(key=lambda item: (item.depth, item.path.casefold(), item.path))
    else:
        directories = StoredRecordSequence(store.path, "directory", DirectoryRecord)
    return files, directories, symlinks, special_entries, dict(stats)
