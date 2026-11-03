"""Safe, deterministic filesystem inventory. Never follows symlinks."""
import hashlib
import os
from collections import Counter
from pathlib import Path

from .language_catalog import detect_language
from .models import FileRecord

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
