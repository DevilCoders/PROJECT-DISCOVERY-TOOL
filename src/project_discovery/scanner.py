"""Safe, deterministic filesystem inventory. Never follows symlinks."""
import hashlib
import os
from collections import Counter
from pathlib import Path, PurePosixPath

from .language_catalog import detect_language
from .models import DirectoryRecord, FileRecord, SymlinkRecord

DEFAULT_IGNORES = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "node_modules", "vendor", "dist", "build",
    ".next", ".nuxt", "coverage", ".tox",
}


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_files(
    root: Path, *, max_file_bytes: int, ignores: set[str] | None = None
) -> tuple[list[FileRecord], dict[str, int]]:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    ignored = DEFAULT_IGNORES | (ignores or set())
    records: list[FileRecord] = []
    stats: Counter[str] = Counter()

    def onerror(_: OSError) -> None:
        stats["walk_errors"] += 1

    for current, dirs, names in os.walk(
        root, topdown=True, followlinks=False, onerror=onerror
    ):
        dirs[:] = sorted(
            name for name in dirs
            if name not in ignored and not (Path(current) / name).is_symlink()
        )
        for name in sorted(names):
            path = Path(current) / name
            try:
                if path.is_symlink() or not path.is_file():
                    stats["skipped_special"] += 1
                    continue
                size = path.stat().st_size
                extension = path.suffix.lower()
                language = detect_language(path.relative_to(root).as_posix())
                record = FileRecord(
                    path.relative_to(root).as_posix(), size, extension, language
                )
                if size > max_file_bytes:
                    record.error = f"Content analysis skipped: exceeds {max_file_bytes} bytes"
                    stats["oversized"] += 1
                records.append(record)
                stats["total_bytes"] += size
                stats[f"language:{language}"] += 1
            except OSError as exc:
                stats["file_errors"] += 1
                records.append(FileRecord(
                    path.relative_to(root).as_posix(), 0, path.suffix.lower(),
                    "Unknown", error=str(exc),
                ))
    return records, dict(stats)



_DEVELOPMENT_MARKERS = {
    "src", "source", "tests", "test", "spec", "specs", "docs", "documentation",
    "examples", "benchmarks", "scripts", "tools", "build", "dist", "target",
    "vendor", "infra", "infrastructure", "deploy", "deployment", "migrations",
    "migration", "assets", "models", "datasets", "notebooks", "robot", "robots",
    "firmware", "hardware", "shaders", "scenes", "packages", "apps", "services",
    "modules", "plugins", "extensions", "config", "configs",
}


def _size_bucket(size: int) -> str:
    if size < 1024:
        return "under_1_kib"
    if size < 1024 * 1024:
        return "1_kib_to_1_mib"
    if size < 10 * 1024 * 1024:
        return "1_to_10_mib"
    if size < 100 * 1024 * 1024:
        return "10_to_100_mib"
    return "over_100_mib"


def _file_type(relative_path: str) -> str:
    from .language_catalog import is_source_path, is_textual_path

    if is_source_path(relative_path):
        return "source"
    if is_textual_path(relative_path):
        return "text"
    return "binary_or_unclassified"


def discover_inventory(
    root: Path,
    *,
    max_file_bytes: int,
    skip_oversized: bool = False,
    ignores: set[str] | None = None,
) -> tuple[list[FileRecord], list[DirectoryRecord], list[SymlinkRecord], dict[str, int]]:
    """Inventory files, directories and symlinks without following links.

    Large files remain part of the inventory by default. Content skipping is an
    explicit opt-in so a caller cannot silently lose coverage of a project.
    """
    import stat

    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be >= 1")

    ignored = DEFAULT_IGNORES | (ignores or set())
    stats: Counter[str] = Counter()
    directories_by_path: dict[str, DirectoryRecord] = {
        ".": DirectoryRecord(
            ".", 0, permissions=stat.S_IMODE(root.stat().st_mode), is_hidden=False,
        )
    }
    files: list[FileRecord] = []
    symlinks: list[SymlinkRecord] = []
    pending: list[tuple[Path, str, int]] = [(root, ".", 0)]

    while pending:
        current, relative_dir, depth = pending.pop()
        directory_record = directories_by_path[relative_dir]
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            directory_record.error = str(exc)
            stats["walk_errors"] += 1
            continue

        for entry in entries:
            relative = (
                entry.name if relative_dir == "."
                else f"{relative_dir}/{entry.name}"
            )
            stats["entry_count"] += 1
            hidden = entry.name.startswith(".")
            if hidden:
                stats["hidden_entry_count"] += 1
            directory_record.direct_child_count += 1

            try:
                if entry.is_symlink():
                    try:
                        target = os.readlink(entry.path)
                        resolved = (Path(entry.path).parent / target).resolve(strict=False)
                        if not resolved.exists():
                            scope = "broken"
                        elif resolved == root or root in resolved.parents:
                            scope = "internal"
                        else:
                            scope = "external"
                        mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                    except OSError:
                        target, scope, mode = "", "unknown", None
                    symlinks.append(SymlinkRecord(
                        relative, target, scope, is_hidden=hidden, permissions=mode,
                    ))
                    continue

                if entry.is_dir(follow_symlinks=False):
                    marker = entry.name.lower() if entry.name.lower() in _DEVELOPMENT_MARKERS else None
                    try:
                        mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
                    except OSError:
                        mode = None
                    record = DirectoryRecord(
                        relative, depth + 1, is_hidden=hidden,
                        permissions=mode, development_marker=marker,
                        pruned=entry.name in ignored,
                    )
                    directories_by_path[relative] = record
                    if marker:
                        stats["development_directory_count"] += 1
                        stats[f"development_dir:{marker}"] += 1
                    if not record.pruned:
                        pending.append((Path(entry.path), relative, depth + 1))
                    continue

                if not entry.is_file(follow_symlinks=False):
                    stats["skipped_special"] += 1
                    continue

                info = entry.stat(follow_symlinks=False)
                size = info.st_size
                language = detect_language(relative)
                file_record = FileRecord(
                    relative,
                    size,
                    Path(entry.name).suffix.lower(),
                    language,
                    file_type=_file_type(relative),
                    size_bucket=_size_bucket(size),
                    is_hidden=hidden,
                    permissions=stat.S_IMODE(info.st_mode),
                    mtime_ns=info.st_mtime_ns,
                )
                if size > max_file_bytes and skip_oversized:
                    file_record.content_skipped_reason = (
                        f"Explicit --skip-oversized-content: exceeds {max_file_bytes} bytes"
                    )
                    stats["oversized_content_skipped"] += 1
                files.append(file_record)
                stats["total_bytes"] += size
                stats[f"file_type:{file_record.file_type}"] += 1
                stats[f"size_bucket:{file_record.size_bucket}"] += 1
                stats[f"language:{language}"] += 1
            except OSError as exc:
                stats["file_errors"] += 1
                files.append(FileRecord(
                    relative, 0, Path(entry.name).suffix.lower(), "Unknown",
                    error=str(exc), is_hidden=hidden,
                ))

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

    return (
        sorted(files, key=lambda item: item.path),
        sorted(directories_by_path.values(), key=lambda item: (item.depth, item.path)),
        sorted(symlinks, key=lambda item: item.path),
        dict(stats),
    )
