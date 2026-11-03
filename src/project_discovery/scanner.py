"""Safe, deterministic filesystem inventory. Never follows symlinks."""
import hashlib
import os
from collections import Counter
from pathlib import Path
from .models import FileRecord

DEFAULT_IGNORES = {".git",".hg",".svn",".venv","venv","__pycache__",".pytest_cache",
                   ".mypy_cache",".ruff_cache","node_modules","vendor","dist","build",
                   ".next",".nuxt","coverage",".tox"}
LANGUAGES = {".py":"Python",".pyi":"Python",".js":"JavaScript",".jsx":"JavaScript",
 ".ts":"TypeScript",".tsx":"TypeScript",".rs":"Rust",".go":"Go",".c":"C",".h":"C/C++ Header",
 ".cpp":"C++",".cc":"C++",".hpp":"C++ Header",".java":"Java",".kt":"Kotlin",
 ".swift":"Swift",".cs":"C#",".rb":"Ruby",".php":"PHP",".sh":"Shell",".bash":"Shell",
 ".ps1":"PowerShell",".html":"HTML",".css":"CSS",".scss":"SCSS",".json":"JSON",
 ".yaml":"YAML",".yml":"YAML",".toml":"TOML",".xml":"XML",".sql":"SQL",
 ".md":"Markdown",".rst":"reStructuredText",".txt":"Text",".pdf":"PDF",".docx":"Word",
 ".ipynb":"Jupyter Notebook"}

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def discover_files(root: Path, *, max_file_bytes: int,
                   ignores: set[str] | None = None) -> tuple[list[FileRecord], dict[str, int]]:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    ignored = DEFAULT_IGNORES | (ignores or set())
    records: list[FileRecord] = []
    stats: Counter[str] = Counter()
    def onerror(_: OSError) -> None:
        stats["walk_errors"] += 1
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        dirs[:] = sorted(n for n in dirs if n not in ignored and not (Path(current) / n).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            try:
                if path.is_symlink() or not path.is_file():
                    stats["skipped_special"] += 1
                    continue
                size = path.stat().st_size
                ext = path.suffix.lower()
                rec = FileRecord(path.relative_to(root).as_posix(), size, ext,
                                 LANGUAGES.get(ext, "Other"))
                if size > max_file_bytes:
                    rec.error = f"Content analysis skipped: exceeds {max_file_bytes} bytes"
                    stats["oversized"] += 1
                records.append(rec)
                stats["total_bytes"] += size
                stats[f"language:{rec.language}"] += 1
            except OSError as exc:
                stats["file_errors"] += 1
                records.append(FileRecord(path.relative_to(root).as_posix(), 0,
                                          path.suffix.lower(), "Unknown", error=str(exc)))
    return records, dict(stats)
