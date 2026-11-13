"""Safe, deterministic filesystem inventory with no-follow symlink semantics."""
from __future__ import annotations

import hashlib
import os
import posixpath
import stat
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath

from ..catalog.languages import detect_language
from ..core.source_utils import (
    FileIdentity, as_identity, identity_matches, open_regular_descriptor, stat_identity,
)
from ..engine.native import create_walker as native_create_walker
from ..models import DirectoryRecord, FileRecord, SpecialEntryRecord, SymlinkRecord
from .entry_metadata import (
    WINDOWS_SPECIAL_TAGS,
    attribute_names,
    device_numbers,
    has_explicit_acl,
    read_security,
    reparse_tag_name,
    security_supported,
    stat_ownership,
)
from .links import classify_links, local_flavor, memory_lookup, root_components, store_lookup, stored_links
from .markers import CATALOG_VERSION as MARKER_CATALOG_VERSION
from .markers import (
    Marker,
    TreeScope,
    apply_marker,
    count_marker,
    detect_marker,
    profile_match,
    tree_scope,
    validate_tree_mode,
)
from .signatures import (
    CATALOG_VERSION,
    SAMPLE_BYTES,
    Classification,
    apply_classification,
    count_classification,
    probe_offsets,
)
from .signatures import classify as classify_sample
from .store import InventoryStore, StoredFileRecords, StoredRecordSequence

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_REPARSE_TAG_NAME_SURROGATE = 0x20000000

# Kept as a compatibility constant. No directory is excluded by default.
DEFAULT_IGNORES: set[str] = set()

def development_marker(name: str, has_entry: Callable[[str], bool] | None = None) -> str | None:
    """The marker catalog key of a directory name, or None (inventory.markers has the rest)."""
    marker = detect_marker(name, has_entry)
    return None if marker is None else marker.key


def _on_disk(directory: str) -> Callable[[str], bool]:
    """Whether a directory on disk holds an entry (lexists: a link is evidence, never followed)."""
    return lambda relative: os.path.lexists(os.path.join(directory, relative))


def _directory_marker(name: str, directory: str, parent: str) -> Marker | None:
    """The marker of a directory on disk, confirmed by entries inside it or beside it."""
    return detect_marker(name, _on_disk(directory), _on_disk(parent))


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
    descriptor, opened = open_regular_descriptor(path)
    try:
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


def _mode(info: os.stat_result) -> int | None:
    """POSIX permission bits; None on Windows, as the Rust walker reports.

    Windows has no permission bits: Python derives 0o666/0o444/0o777 from the read-only
    attribute, so the two backends (and the root record) disagreed for one tree.
    """
    return None if os.name == "nt" else stat.S_IMODE(info.st_mode)


def _is_hidden(name: str, info: os.stat_result) -> bool:
    """Recognize dot-hidden entries and the Windows FILE_ATTRIBUTE_HIDDEN bit."""
    if name.startswith("."):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & 0x2)


def _lstat_reparse_tag(path: str) -> int | None:
    """The reparse tag of a Windows reparse point, read without following it."""
    try:
        return getattr(os.lstat(path), "st_reparse_tag", None) or None
    except OSError:
        return None


def _special_kind(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISCHR(mode):
        return "character_device"
    return "unknown_special"


def _record_metadata(record, path: str, kind: str, stats: Counter[str], security: bool) -> None:
    """Count a record's attributes; with --security-metadata, read its security metadata."""
    for name in record.attributes:
        stats[f"attribute:{name}"] += 1
    if record.reparse_tag:
        stats[f"reparse_tag:{record.reparse_tag}"] += 1
    if security:
        record.security = read_security(path, kind)
        stats["security_metadata_entries"] += 1
        if "error" in record.security:
            stats["security_metadata_errors"] += 1
        elif has_explicit_acl(record.security):
            stats["security_explicit_acl_entries"] += 1


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
    probes: dict[int, bytes] | None = None,
) -> tuple[bytes, FileIdentity]:
    """Read the signature sample from a verified descriptor; return it with the opened identity.

    The sample is the first SAMPLE_BYTES; ``probes`` receives the further reads the sample
    needs (an ISO 9660 volume descriptor, an OLE directory), from the same descriptor.
    """
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
    descriptor, opened = open_regular_descriptor(path)
    try:
        opened_identity = stat_identity(opened)
        if not (
            identity_matches(observed_identity, opened_identity)
            and identity_matches(expected_identity, opened_identity)
        ):
            raise OSError(f"file identity changed during signature read: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            sample = stream.read(SAMPLE_BYTES)
            if probes is not None:
                for offset, length in probe_offsets(sample, opened.st_size):
                    stream.seek(offset)
                    probes[offset] = stream.read(length)
            return sample, opened_identity
    finally:
        os.close(descriptor)


def _read_signature_sample(
    path: Path,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> bytes:
    """Read the signature sample from a verified descriptor matching walker metadata."""
    return _read_verified_sample(path, expected_info)[0]


def _classify_file(
    path: Path,
    relative_path: str,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> tuple[Classification, FileIdentity | None]:
    """The file's classification and the descriptor-verified identity observed while sampling.

    The type comes from the content: a catalogued signature, text (including text formats
    such as scripts), binary without a known signature, or empty. A file that cannot be
    read is classified by its name (type_source "name"); what the name suggests is
    recorded either way, apart from the content's type.
    """
    probes: dict[int, bytes] = {}
    try:
        sample, opened_identity = _read_verified_sample(path, expected_info, probes)
    except OSError:
        return classify_sample(None, relative_path), None
    # The size of the opened file (identities are device, inode, size, mtime, ctime).
    size = opened_identity[2] if opened_identity is not None else None
    return classify_sample(sample, relative_path, size=size, probes=probes), opened_identity


def _classify_name_only(
    path: Path,
    relative_path: str,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> tuple[Classification, FileIdentity | None]:
    """The file type from its name alone; nothing is opened (inventory-only scans)."""
    return classify_sample(None, relative_path), None


def _file_type(
    path: Path,
    relative_path: str,
    expected_info: os.stat_result | FileIdentity | None = None,
) -> str:
    return _classify_file(path, relative_path, expected_info)[0].file_type



def _user_form_target(target: str) -> str:
    """A Windows link target without the ``\\\\?\\`` prefix ``os.readlink`` keeps.

    Junction and absolute-symlink targets read as ``\\\\?\\C:\\proj\\src`` or
    ``\\\\?\\UNC\\server\\share``; the Rust walker reports ``C:\\proj\\src`` and
    ``\\\\server\\share``. Without this, scope checks against the root saw another drive.
    """
    if target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + target[len("\\\\?\\UNC\\"):]
    if target.startswith("\\\\?\\"):
        return target[len("\\\\?\\"):]
    return target


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


def _relative_to_root(value: str, root: Path) -> str | None:
    """An absolute ``value`` as a POSIX path relative to ``root``, or None outside it.

    The lexical path is tried first, then the resolved one (a path through a symlinked
    parent, or a Windows short name, still names a directory inside the root).
    """
    for candidate in (os.path.abspath(value), os.path.realpath(value)):
        try:
            relative = os.path.relpath(candidate, root).replace("\\", "/")
        except ValueError:  # another Windows drive
            continue
        if relative != ".." and not relative.startswith("../"):
            return relative
    return None


def normalize_exclusions(
    ignores: set[str] | None, root: Path | None = None,
) -> tuple[set[str], set[str]]:
    """--exclude-dir values as casefolded (names, root-relative paths).

    A bare name (``node_modules``) prunes every directory of that name. A value with a
    separator (``web/src``), a ``./`` prefix (``./web``) or an absolute path inside ``root``
    names one directory relative to the root; ``.`` and ``..`` segments are collapsed
    lexically. A value that can never match raises ValueError: one outside the root, the
    root itself, or an absolute path when there is no local root (a remote scan).
    """
    names: set[str] = set()
    paths: set[str] = set()
    for raw in ignores or ():
        value = raw.strip()
        if not value:
            continue
        text = value.replace("\\", "/")
        anchored = text.startswith("./")
        if text.startswith("/") or os.path.isabs(value):
            if root is None:
                raise ValueError(
                    f"--exclude-dir {raw}: an absolute path needs a local scan root; "
                    "give the directory relative to the repository root"
                )
            relative = _relative_to_root(value, root)
            if relative is None:
                raise ValueError(f"--exclude-dir {raw} is outside the scan root {root}")
            text, anchored = relative, True
        normalized = posixpath.normpath(text)
        if normalized in {"", "."}:
            raise ValueError(f"--exclude-dir {raw} names the scan root itself, which cannot be pruned")
        if normalized == ".." or normalized.startswith("../"):
            raise ValueError(f"--exclude-dir {raw} is outside the scan root")
        if anchored or "/" in normalized:
            paths.add(normalized.casefold())
        else:
            names.add(normalized.casefold())
    return names, paths


_normalise_exclusions = normalize_exclusions  # the name earlier releases used


def unused_exclusions(stats, excluded_names: set[str], excluded_paths: set[str]) -> list[str]:
    """The --exclude-dir values that pruned no directory, spelled as names or ./paths."""
    return [
        name for name in sorted(excluded_names) if not stats.get(f"exclusion_used:name:{name}")
    ] + [
        f"./{path}" for path in sorted(excluded_paths) if not stats.get(f"exclusion_used:path:{path}")
    ]


def inventory_options(
    *, read_signatures: bool, skip_oversized: bool, max_file_bytes: int,
    excluded_names: set[str], excluded_paths: set[str], security_metadata: bool = False,
    exclude_profiles: frozenset[str] | set[str] = frozenset(), development_trees: str = "deep",
) -> dict:
    """The options that shape a stored inventory; --resume continues only an identical one."""
    return {
        "read_signatures": bool(read_signatures),
        "skip_oversized": bool(skip_oversized),
        "max_file_bytes": int(max_file_bytes) if skip_oversized else None,
        "exclude_names": sorted(excluded_names),
        "exclude_paths": sorted(excluded_paths),
        "exclude_profiles": sorted(exclude_profiles),
        "development_trees": development_trees,
        "security_metadata": bool(security_metadata),
        # File types and markers from another catalog version would mix with this one's.
        "signature_catalog": CATALOG_VERSION,
        "marker_catalog": MARKER_CATALOG_VERSION,
    }


def _exclusion_match(
    relative_path: str, name: str, excluded_names: set[str], excluded_paths: set[str],
    marker: Marker | None = None, profiles: frozenset[str] | set[str] = frozenset(),
) -> tuple[str, str] | None:
    """The --exclude-dir value or --exclude-profile a directory matches, as (stats key, prune reason)."""
    folded = name.casefold()
    if folded in excluded_names:
        return f"exclusion_used:name:{folded}", f"explicit --exclude-dir name: {name}"
    folded_path = relative_path.casefold()
    if folded_path in excluded_paths:
        return f"exclusion_used:path:{folded_path}", f"explicit --exclude-dir path: {relative_path}"
    return profile_match(marker, profiles) if profiles else None


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
    classify=None,
    security_metadata: bool = False,
    profiles: frozenset[str] = frozenset(),
    development_trees: str = "deep",
) -> bool:
    """Consume the optional Rust directory iterator; return False if unavailable."""
    scopes: dict[str, TreeScope] = {}  # directories inside an inventory or directory-only tree
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
    for item in walker:
        relative, kind, size, mode, mtime_ns, hidden, target, error, depth, device_id, inode_id, ctime_ns = item[:12]
        # Owner uid, group gid and the Windows attribute or macOS flag bits.
        uid, gid, attribute_bits = item[12:15] if len(item) >= 15 else (None, None, None)
        device_number = item[15] if len(item) >= 16 else None
        # The walker returns lossless OS strings with native separators. A backslash is
        # a legal POSIX file-name character, so only Windows separators are rewritten.
        if os.sep == "\\":
            relative = relative.replace("\\", "/")
        # The Rust walker reports hidden=false for entries it could not stat; a dot name is
        # hidden either way, as in the fallback walker.
        hidden = bool(hidden) or relative.rsplit("/", 1)[-1].startswith(".")
        reparse_tag = None
        if os.name == "nt" and attribute_bits and attribute_bits & _FILE_ATTRIBUTE_REPARSE_POINT:
            # The walker cannot read the tag itself; reparse points are rare.
            reparse_tag = _lstat_reparse_tag(os.path.join(root, relative))
            if kind == "file":
                kind = WINDOWS_SPECIAL_TAGS.get(reparse_tag, kind)
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
        tree = scopes.get(parent)
        if tree is not None and tree.mode == "directory-only" and kind != "directory":
            _unrecorded_entry(relative, size, kind, store, directories_by_path, stats)
            continue
        if kind == "symlink":
            if error:
                # The target could not be read: the link is inventoried, its target is not.
                target, scope, state = "", "unknown", "unreadable"
                stats["entry_errors"] += 1
            else:
                scope, state = _symlink_scope(root, root / relative, target), "unverified"
            link_record = SymlinkRecord(
                relative, target, scope, target_state=state,
                is_hidden=hidden, permissions=mode,
                uid=uid, gid=gid, attributes=attribute_names(attribute_bits),
                mtime_ns=mtime_ns, reparse_tag=reparse_tag_name(reparse_tag),
            )
            _record_metadata(link_record, os.path.join(root, relative), kind, stats, security_metadata)
            if store is None:
                symlinks.append(link_record)
            else:
                store.append("symlink", link_record)
            stats["symlink_count"] += 1
            stats[f"symlink_scope:{scope}"] += 1
            continue
        if kind == "directory":
            name = PurePosixPath(relative).name
            marker = _directory_marker(name, os.path.join(root, relative), os.path.join(root, parent))
            match = _exclusion_match(relative, name, excluded_names, excluded_paths, marker, profiles)
            exclusion = match[1] if match else None
            record = DirectoryRecord(
                relative, depth, is_hidden=hidden, permissions=mode,
                pruned=exclusion is not None, prune_reason=exclusion, error=error,
                uid=uid, gid=gid, attributes=attribute_names(attribute_bits),
                mtime_ns=mtime_ns, reparse_tag=reparse_tag_name(reparse_tag),
            )
            apply_marker(record, marker)
            if not match:
                _enter_scope(record, tree_scope(development_trees, tree, marker, relative), scopes, stats)
            _record_metadata(record, os.path.join(root, relative), kind, stats, security_metadata)
            if store is None:
                directories_by_path[relative] = record
            else:
                store.append("directory", record)
            count_marker(stats, marker)
            if match:
                stats["pruned_directory_count"] += 1
                stats[f"pruned_dir:{name.casefold()}"] += 1
                stats[match[0]] += 1
                # Recorded as pruned here, so the walker must not descend into it either.
                skip = getattr(walker, "skip_directory", None)
                if skip is not None:
                    skip()
            if error:
                stats["walk_errors"] += 1
            continue
        if kind == "file":
            path = root / relative
            file_identity = (
                device_id, inode_id, size, mtime_ns, ctime_ns,
            ) if device_id is not None and inode_id is not None else None
            # Inside an inventory-mode development tree no content is read, not even a sample.
            reader = _classify_name_only if tree is not None else (classify or _classify_file)
            classification, opened_identity = reader(path, relative, file_identity)
            language = detect_language(relative)
            record = FileRecord(
                relative, size, Path(relative).suffix.lower(), language,
                size_bucket=_size_bucket(size),
                is_hidden=hidden, permissions=mode, mtime_ns=mtime_ns,
                uid=uid, gid=gid, attributes=attribute_names(attribute_bits),
                reparse_tag=reparse_tag_name(reparse_tag),
                # Prefer the descriptor-verified identity; the Windows walker
                # cannot report a file ID itself.
                analysis_identity=opened_identity or file_identity,
            )
            apply_classification(record, classification)
            _record_metadata(record, str(path), kind, stats, security_metadata)
            if tree is not None:
                record.content_skipped_reason = tree.reason
                stats["development_tree_unread_files"] += 1
            elif size > max_file_bytes and skip_oversized:
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
            count_classification(stats, record)
            stats[f"size_bucket:{record.size_bucket}"] += 1
            stats[f"language:{language}"] += 1
            continue
        major, minor = device_numbers(device_number)
        special_record = SpecialEntryRecord(
            relative, kind, is_hidden=hidden, permissions=mode, size_bytes=size,
            uid=uid, gid=gid, attributes=attribute_names(attribute_bits),
            mtime_ns=mtime_ns, device_major=major, device_minor=minor,
            reparse_tag=reparse_tag_name(reparse_tag),
        )
        _record_metadata(special_record, os.path.join(root, relative), kind, stats, security_metadata)
        if store is None:
            special_entries.append(special_record)
        else:
            store.append("special", special_record)
        stats["special_entry_count"] += 1
        stats[f"special_type:{kind}"] += 1
    return True



def _unrecorded_entry(
    relative_path: str, size_bytes: int, kind: str, store: InventoryStore | None,
    directories_by_path: dict[str, DirectoryRecord], stats: Counter[str],
) -> None:
    """Count an entry of a directory-only development tree in the totals, without a record."""
    if kind != "file":
        stats["development_tree_unrecorded_entries"] += 1
        return
    stats["total_bytes"] += size_bytes
    stats["development_tree_unrecorded_files"] += 1
    stats["development_tree_unrecorded_bytes"] += size_bytes
    if store is not None:
        _update_file_ancestor_totals(relative_path, size_bytes, store)
        return
    # The no-store path aggregates from its file list at the end, which these files are not in.
    parent = PurePosixPath(relative_path).parent
    while True:
        key = parent.as_posix() or "."
        record = directories_by_path.get(key)
        if record is not None:
            record.file_count += 1
            record.total_bytes += size_bytes
        if key == ".":
            break
        parent = parent.parent


def _enter_scope(
    record: DirectoryRecord, scope: TreeScope | None, scopes: dict[str, TreeScope], stats: Counter[str],
) -> None:
    """Remember a directory's development-tree scope for its entries, before it is stored."""
    if scope is None:
        return
    scopes[record.path] = scope
    if scope.root == record.path:
        stats["development_tree_count"] += 1
    if scope.mode == "directory-only":
        record.contents_recorded = False


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
    read_signatures: bool = True,
    security_metadata: bool = False,
    exclude_profiles: frozenset[str] = frozenset(),
    development_trees: str = "deep",
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

    Every record carries its owner and group IDs and platform attributes;
    ``security_metadata`` also reads each entry's ACLs (see ``entry_metadata``).
    ``exclude_profiles`` prunes the confirmed and distinctively named development trees of
    those --exclude-profile presets (see ``markers``); ``development_trees`` (deep, inventory
    or directory-only) decides what is recorded and read inside the other such trees.
    """
    if security_metadata and not security_supported():
        raise ValueError("--security-metadata reads Windows security descriptors and Linux POSIX ACLs only")
    root = root.expanduser().absolute()
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode):
        raise ValueError("The scan root itself is a symlink; pass its real directory path explicitly.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"The scan root is not a directory: {root}")
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be >= 1")
    validate_tree_mode(development_trees)

    excluded_names, excluded_paths = normalize_exclusions(ignores, root)
    stats: Counter[str] = Counter()
    try:
        root_info = root.stat()
        root_mode = _mode(root_info)
        root_hidden = _is_hidden(root.name, root_info) if root.name else False
        root_uid, root_gid, root_attributes = stat_ownership(root_info)
        root_mtime, root_tag = root_info.st_mtime_ns, getattr(root_info, "st_reparse_tag", None)
    except OSError:
        root_mode, root_hidden = None, False
        root_uid, root_gid, root_attributes = None, None, []
        root_mtime = root_tag = None
    if store is not None:
        store.clear()
        stats["inventory_store_enabled"] = 1
        store.checkpoint({
            "inventory_status": "running", "root": str(root),
            # What --resume compares: an inventory made with other options cannot be continued.
            "inventory_options": inventory_options(
                read_signatures=read_signatures, skip_oversized=skip_oversized,
                max_file_bytes=max_file_bytes,
                excluded_names=excluded_names, excluded_paths=excluded_paths,
                security_metadata=security_metadata, exclude_profiles=exclude_profiles,
                development_trees=development_trees,
            ),
        })
    root_directory = DirectoryRecord(
        ".", 0, permissions=root_mode, is_hidden=root_hidden,
        uid=root_uid, gid=root_gid, attributes=root_attributes,
        mtime_ns=root_mtime, reparse_tag=reparse_tag_name(root_tag),
    )
    _record_metadata(root_directory, str(root), "directory", stats, security_metadata)
    directories_by_path: dict[str, DirectoryRecord] = {}
    if store is None:
        directories_by_path["."] = root_directory
    else:
        store.append("directory", root_directory)
    files: list[FileRecord] = []
    symlinks: list[SymlinkRecord] = []
    special_entries: list[SpecialEntryRecord] = []
    # read_signatures=False (inventory-only): no file is opened, not even for the
    # signature sample, so file types come from names alone.
    classify = _classify_file if read_signatures else _classify_name_only
    used_rust = _discover_with_rust(
        root, excluded_names, excluded_paths, max_file_bytes, skip_oversized,
        directories_by_path, files, symlinks, special_entries, stats, store, classify,
        security_metadata, exclude_profiles, development_trees,
    )
    scopes: dict[str, TreeScope] = {}  # directories inside an inventory or directory-only tree
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
            uid, gid, attributes = stat_ownership(info)
            reparse_tag = getattr(info, "st_reparse_tag", None) or None  # Windows only
            tag_name = reparse_tag_name(reparse_tag)
            if hidden:
                stats["hidden_entry_count"] += 1
            tree = scopes.get(relative_dir)
            directory_only = tree is not None and tree.mode == "directory-only"

            if _is_link_like(info):
                if directory_only:
                    _unrecorded_entry(relative, 0, "symlink", store, directories_by_path, stats)
                    continue
                try:
                    target = _user_form_target(os.readlink(entry.path))
                except (OSError, ValueError):
                    # ValueError: a name-surrogate reparse point that CPython does not read
                    # as a link, such as a WSL (LX) symlink on NTFS.
                    target = None
                if target is None:
                    target, scope, state = "", "unknown", "unreadable"
                    stats["entry_errors"] += 1
                else:
                    scope, state = _symlink_scope(root, Path(entry.path), target), "unverified"
                link_record = SymlinkRecord(
                    relative, target, scope, target_state=state, is_hidden=hidden,
                    permissions=_mode(info), uid=uid, gid=gid, attributes=attributes,
                    mtime_ns=info.st_mtime_ns, reparse_tag=tag_name,
                )
                _record_metadata(link_record, entry.path, "symlink", stats, security_metadata)
                if store is None:
                    symlinks.append(link_record)
                else:
                    store.append("symlink", link_record)
                stats["symlink_count"] += 1
                stats[f"symlink_scope:{scope}"] += 1
                continue

            # A Windows AF_UNIX socket or WSL FIFO or device node reads as a regular file.
            windows_special = WINDOWS_SPECIAL_TAGS.get(reparse_tag) if reparse_tag else None
            if stat.S_ISDIR(info.st_mode) and windows_special is None:
                marker = _directory_marker(entry.name, entry.path, str(current))
                match = _exclusion_match(
                    relative, entry.name, excluded_names, excluded_paths, marker, exclude_profiles,
                )
                exclusion = match[1] if match else None
                record = DirectoryRecord(
                    relative,
                    depth + 1,
                    is_hidden=hidden,
                    permissions=_mode(info),
                    pruned=exclusion is not None,
                    prune_reason=exclusion,
                    uid=uid,
                    gid=gid,
                    attributes=attributes,
                    mtime_ns=info.st_mtime_ns,
                    reparse_tag=tag_name,
                )
                apply_marker(record, marker)
                if not match:
                    _enter_scope(record, tree_scope(development_trees, tree, marker, relative), scopes, stats)
                _record_metadata(record, entry.path, "directory", stats, security_metadata)
                if store is None:
                    directories_by_path[relative] = record
                else:
                    store.append("directory", record)
                count_marker(stats, marker)
                if match:
                    stats["pruned_directory_count"] += 1
                    stats[f"pruned_dir:{entry.name.casefold()}"] += 1
                    stats[match[0]] += 1
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

            if stat.S_ISREG(info.st_mode) and windows_special is None:
                size = info.st_size
                if directory_only:
                    _unrecorded_entry(relative, size, "file", store, directories_by_path, stats)
                    continue
                # Inside an inventory-mode development tree no content is read, not even a sample.
                reader = _classify_name_only if tree is not None else classify
                classification, opened_identity = reader(Path(entry.path), relative, info)
                language = detect_language(relative)
                file_record = FileRecord(
                    relative,
                    size,
                    Path(entry.name).suffix.lower(),
                    language,
                    size_bucket=_size_bucket(size),
                    is_hidden=hidden,
                    permissions=_mode(info),
                    mtime_ns=info.st_mtime_ns,
                    uid=uid,
                    gid=gid,
                    attributes=attributes,
                    reparse_tag=tag_name,
                    analysis_identity=opened_identity or stat_identity(info),
                )
                apply_classification(file_record, classification)
                _record_metadata(file_record, entry.path, "file", stats, security_metadata)
                if tree is not None:
                    file_record.content_skipped_reason = tree.reason
                    stats["development_tree_unread_files"] += 1
                elif size > max_file_bytes and skip_oversized:
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
                count_classification(stats, file_record)
                stats[f"size_bucket:{file_record.size_bucket}"] += 1
                stats[f"language:{language}"] += 1
                continue

            kind = windows_special or _special_kind(info.st_mode)
            if directory_only:
                _unrecorded_entry(relative, 0, kind, store, directories_by_path, stats)
                continue
            major, minor = (None, None) if windows_special else device_numbers(
                getattr(info, "st_rdev", None) if kind in {"block_device", "character_device"} else None
            )
            special_record = SpecialEntryRecord(
                relative,
                kind,
                is_hidden=hidden,
                permissions=_mode(info),
                size_bytes=getattr(info, "st_size", 0),
                uid=uid,
                gid=gid,
                attributes=attributes,
                mtime_ns=info.st_mtime_ns,
                device_major=major,
                device_minor=minor,
                reparse_tag=tag_name,
            )
            _record_metadata(special_record, entry.path, kind, stats, security_metadata)
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

    # Every link's target is resolved against the finished inventory, never the filesystem.
    flavor = local_flavor(str(root))
    root_parts = root_components(str(root), flavor)
    if store is None:
        lookup = memory_lookup(
            [("directory", record) for record in directories_by_path.values()]
            + [("file", record) for record in files] + [("symlink", record) for record in symlinks]
            + [("special", record) for record in special_entries],
            flavor.fold,
        )
        classify_links(symlinks, lookup, flavor, root_parts, stats)
    else:
        store.flush()
        classify_links(
            stored_links(store), store_lookup(store, flavor.fold), flavor, root_parts, stats,
            save=lambda record: store.append("symlink", record),
        )

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
