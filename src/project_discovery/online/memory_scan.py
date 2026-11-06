"""No-download online mode: analyze a remote repository from its provider API, in memory.

The repository is never cloned, archived or written to disk. The commit's tree listing
becomes PDT's inventory; file contents are fetched on demand, held in memory only while
the built-in analyzers read them (through the same verified-read prefetch path that local
scans use), and then discarded. PDT's own outputs (reports, the inventory database with
findings and code facts) are written to the report directory as in every other mode.

Budgets bound the work per repository: content requests, total bytes, bytes per file,
files and API requests. Anything not fetched because of a budget, a rate limit or a
network error stays in the inventory with a content-skipped reason and is reported as an
UNKNOWN coverage gap, so the scan is never presented as complete when it is not.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator

from ..analysis_engine import FileOutcome, _run_analyzers
from ..code_facts import collecting_facts
from ..inventory_store import InventoryStore, StoredFileRecords, StoredRecordSequence
from ..language_catalog import detect_language, is_source_path, is_textual_path
from ..lockfiles import LOCKFILE_NAMES, MAX_LOCKFILE_BYTES
from ..models import DirectoryRecord, FileRecord, SpecialEntryRecord, SymlinkRecord
from ..python_graph import MAX_GRAPH_AST_FILE_BYTES, parse_python_imports
from ..remote import RemoteTarget
from ..scanner import _DEVELOPMENT_MARKERS, _classify_head, _size_bucket
from ..source_utils import prefetched_content
from .credentials import ApiCredential, resolve_credential
from .http import DEFAULT_TIMEOUT, HttpClient, NetworkError
from .providers import (
    CLIENTS, ProviderError, RequestBudget, ResolvedRevision, TreeEntry, api_provider_for,
    default_api_url, split_repository, symlink_scope,
)

DEFAULT_API_MAX_FILES = 20_000
DEFAULT_API_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_API_MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_API_MAX_REQUESTS = 15_000
DEFAULT_API_WORKERS = 8
# Lockfile texts kept in memory for the online vulnerability lookup after analysis.
MAX_KEPT_LOCKFILE_BYTES = 256 * 1024 * 1024
MAX_SYMLINK_TARGET_BYTES = 4096


@dataclass(frozen=True)
class ApiLimits:
    max_files: int = DEFAULT_API_MAX_FILES
    max_bytes: int = DEFAULT_API_MAX_BYTES
    max_file_bytes: int = DEFAULT_API_MAX_FILE_BYTES
    max_requests: int = DEFAULT_API_MAX_REQUESTS
    workers: int = DEFAULT_API_WORKERS

    def __post_init__(self) -> None:
        if min(self.max_files, self.max_bytes, self.max_file_bytes, self.max_requests) < 1:
            raise ValueError("no-download budgets must be positive")
        if not 1 <= self.workers <= 32:
            raise ValueError("no-download workers must be between 1 and 32")


@dataclass(frozen=True)
class NoDownloadOptions:
    provider: str = "auto"
    api_url: str | None = None
    use_credential_helper: bool = False
    timeout: float = DEFAULT_TIMEOUT
    ca_bundle: Path | None = None
    limits: ApiLimits = ApiLimits()


def _virtual_root(identity: str) -> Path:
    """A path namespace for in-memory files that cannot exist on disk.

    On POSIX it lies below /dev/null (a file, so nothing can be created beneath it). On
    Windows it is an unpredictable name in the per-user temporary directory that is never
    created. Analyzer reads of these paths are served from memory by the prefetch layer.
    """
    name = f"pdt-no-download-{identity}-{secrets.token_hex(6)}"
    if os.name == "nt":
        return Path(tempfile.gettempdir()) / name
    return Path("/dev/null") / name


class NoDownloadSource:
    """One remote repository read through its provider API for a single scan."""

    def __init__(self, target: RemoteTarget, options: NoDownloadOptions) -> None:
        if target.vcs != "git":
            raise ProviderError(
                f"No-download mode reads Git hosting provider APIs; {target.vcs} repositories "
                "need the download mode."
            )
        self.target = target
        self.options = options
        self.limits = options.limits
        self.host, self.repository = split_repository(target.clone_url)
        self.provider = api_provider_for(target.provider, options.provider)
        self.api_url = options.api_url or default_api_url(self.provider, self.host)
        self.credential: ApiCredential | None = resolve_credential(
            self.provider, self.host, use_helper=options.use_credential_helper,
        )
        self.http = HttpClient(ca_bundle=options.ca_bundle, timeout=options.timeout)
        self.budget = RequestBudget(self.limits.max_requests)
        self.client = CLIENTS[self.provider](
            self.http, api_url=self.api_url, repository=self.repository, host=self.host,
            credential=self.credential, budget=self.budget,
        )
        self.virtual_root = _virtual_root(target.identity)
        self.revision: ResolvedRevision | None = None
        self.entries: dict[str, TreeEntry] = {}
        self.lockfiles: dict[str, str] = {}
        self.python_imports: dict[str, tuple] = {}
        self._kept_lockfile_bytes = 0
        self._lock = threading.Lock()
        self._stop_reason: str | None = None
        self.counters: Counter[str] = Counter()
        self.skipped: dict[str, list[str]] = {}
        self.started = time.monotonic()
        self.acquired_at = datetime.now(timezone.utc).isoformat()
        self.metadata: dict[str, Any] = {}
        self.excluded_plugins: list[str] = []

    @staticmethod
    def size_bucket(size: int) -> str:
        return _size_bucket(size)

    @staticmethod
    def ancestors(path: str) -> Iterator[str]:
        parent = PurePosixPath(path).parent
        while True:
            key = parent.as_posix() or "."
            yield key
            if key == ".":
                return
            parent = parent.parent

    # ------------------------------------------------------------------
    def open(self) -> dict[str, Any]:
        """Resolve the ref to a commit (fatal errors raise ProviderError/NetworkError)."""
        self.revision = self.client.resolve(self.target.ref)
        self.metadata = {
            "mode": "remote",
            "acquisition": "api",
            "vcs": "git",
            "provider": self.target.provider,
            "api_provider": self.client.name,
            "api_url": self.api_url,
            "url": self.target.clone_url,
            "repository": self.target.repository_name,
            "identity": self.target.identity,
            "ref": self.target.ref,
            "revision": self.revision.revision,
            "branch": self.revision.branch,
            "default_branch": self.revision.default_branch,
            "private": self.revision.private,
            "transport": "https" if self.api_url.startswith("https://") else "http",
            "transport_insecure": not self.api_url.startswith("https://"),
            "credential_source": self.credential.source if self.credential else None,
            "acquired_at": self.acquired_at,
            "history_complete": False,
            "written_to_disk": False,
            "limits": {
                "max_files": self.limits.max_files, "max_bytes": self.limits.max_bytes,
                "max_file_bytes": self.limits.max_file_bytes, "max_requests": self.limits.max_requests,
            },
            "coverage": [], "coverage_gaps": [], "warnings": [],
        }
        return self.metadata

    # ------------------------------------------------------------------
    def build_inventory(self, store: InventoryStore, *, ignores: set[str] | None = None,
                        max_file_bytes: int, skip_oversized: bool):
        """Persist the commit tree as PDT inventory records (no content is read)."""
        assert self.revision is not None, "open() must be called first"
        entries, truncated = self.client.tree(self.revision)
        excluded = {item.replace("\\", "/").strip("/").casefold() for item in ignores or () if item.strip("/")}
        stats: Counter[str] = Counter()
        store.clear()
        stats["inventory_store_enabled"] = 1
        store.checkpoint({"inventory_status": "running", "root": str(self.virtual_root)})
        store.append("directory", DirectoryRecord(".", 0))
        directories: dict[str, DirectoryRecord] = {}
        invalid = 0
        pruned_prefixes: list[str] = []

        def pruned(path: str) -> bool:
            return any(path == prefix or path.startswith(prefix + "/") for prefix in pruned_prefixes)

        def ensure_directory(path: str) -> None:
            if path in {"", "."} or path in directories:
                return
            parent = PurePosixPath(path).parent.as_posix()
            ensure_directory(parent if parent != "." else "")
            name = PurePosixPath(path).name
            exclusion = None
            if name.casefold() in excluded or path.casefold() in excluded:
                exclusion = f"explicit --exclude-dir: {path}"
            marker = name.casefold() if name.casefold() in _DEVELOPMENT_MARKERS else None
            record = DirectoryRecord(
                path, path.count("/") + 1, is_hidden=name.startswith("."),
                development_marker=marker, pruned=exclusion is not None, prune_reason=exclusion,
            )
            directories[path] = record
            store.append("directory", record)
            store.adjust_directory(parent if parent not in {"", "."} else ".", direct_child_delta=1)
            stats["entry_count"] += 1
            if record.is_hidden:
                stats["hidden_entry_count"] += 1
            if marker:
                stats["development_directory_count"] += 1
                stats[f"development_dir:{marker}"] += 1
            if exclusion:
                stats["pruned_directory_count"] += 1
                pruned_prefixes.append(path)

        for entry in sorted(entries, key=lambda item: (item.path.casefold(), item.path)):
            if entry.kind == "invalid":
                invalid += 1
                continue
            parent = PurePosixPath(entry.path).parent.as_posix()
            if parent not in {".", ""}:
                ensure_directory(parent)
                if pruned(parent):
                    continue
            if entry.kind in {"directory", "submodule"}:
                ensure_directory(entry.path)
                if entry.kind == "submodule":
                    stats["submodule_count"] += 1
                continue
            self.entries[entry.path] = entry
            name = PurePosixPath(entry.path).name
            hidden = name.startswith(".")
            stats["entry_count"] += 1
            if hidden:
                stats["hidden_entry_count"] += 1
            store.adjust_directory(parent if parent not in {"", "."} else ".", direct_child_delta=1)
            if entry.kind == "symlink":
                target = self._symlink_target(entry)
                scope = symlink_scope(entry.path, target) if target else "unknown"
                store.append("symlink", SymlinkRecord(
                    entry.path, target or "", scope, target_state="unverified", is_hidden=hidden,
                    permissions=0o777,
                ))
                stats["symlink_count"] += 1
                stats[f"symlink_scope:{scope}"] += 1
                continue
            size = entry.size if entry.size is not None else 0
            file_type = "source" if is_source_path(entry.path) else "text" if is_textual_path(entry.path) else "binary/unclassified"
            record = FileRecord(
                entry.path, size, PurePosixPath(name).suffix.lower(), detect_language(entry.path),
                file_type=file_type, size_bucket=_size_bucket(size), is_hidden=hidden,
                permissions=0o755 if entry.executable else 0o644,
            )
            if size > max_file_bytes and skip_oversized:
                record.content_skipped_reason = f"Explicit --skip: exceeds {max_file_bytes} bytes"
                stats["oversized_content_skipped"] += 1
            store.append("file", record)
            ancestor = PurePosixPath(entry.path).parent
            while True:
                key = ancestor.as_posix() or "."
                store.adjust_directory(key, file_count_delta=1, total_bytes_delta=size)
                if key == ".":
                    break
                ancestor = ancestor.parent
            stats["total_bytes"] += size
            stats[f"size_bucket:{record.size_bucket}"] += 1
            stats[f"language:{record.language}"] += 1
        store.flush()
        store.checkpoint({
            "inventory_status": "partial" if truncated or invalid else "complete",
            "traversal_finished": True,
            "root": str(self.virtual_root),
            "record_counts": {kind: store.count(kind) for kind in ("file", "directory", "symlink", "special")},
        })
        stats["inventory_store_record_count"] = sum(store.counts().values())
        stats["inventory_store_integrity_ok"] = int(store.integrity_check() == "ok")
        stats["inventory_store_partial"] = int(bool(truncated or invalid))
        store.set_metadata("walk_stats", dict(stats))
        self.counters["tree_entries"] = len(entries)
        self.counters["invalid_tree_paths"] = invalid
        self.counters["tree_truncated"] = int(truncated)
        self.counters["submodules"] = stats.get("submodule_count", 0)
        self.walk_stats = stats
        return (
            StoredFileRecords(store.path),
            StoredRecordSequence(store.path, "directory", DirectoryRecord),
            StoredRecordSequence(store.path, "symlink", SymlinkRecord),
            StoredRecordSequence(store.path, "special", SpecialEntryRecord),
            stats,
        )

    def _symlink_target(self, entry: TreeEntry) -> str | None:
        try:
            data = self.client.read(entry, self.revision, MAX_SYMLINK_TARGET_BYTES)
        except NetworkError as exc:
            self._note_skip(f"symlink target not read ({exc.kind})", entry.path)
            return None
        self.counters["symlink_requests"] += 1
        return data.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    def _note_skip(self, reason: str, path: str) -> None:
        with self._lock:
            self.skipped.setdefault(reason, []).append(path)

    def _reserve(self, record: FileRecord) -> str | None:
        """Apply the file, byte and per-file budgets before a content request."""
        with self._lock:
            if self._stop_reason:
                return self._stop_reason
            if self.counters["content_requests"] >= self.limits.max_files:
                return f"no-download file budget of {self.limits.max_files:,} files reached"
            entry = self.entries.get(record.path)
            size = entry.size if entry and entry.size is not None else None
            if size is not None and size > self.limits.max_file_bytes:
                return f"exceeds the no-download per-file budget of {self.limits.max_file_bytes:,} bytes"
            if self.counters["bytes_fetched"] + (size or 0) > self.limits.max_bytes:
                return f"no-download byte budget of {self.limits.max_bytes:,} bytes reached"
            self.counters["content_requests"] += 1
            return None

    def _fetch(self, record: FileRecord) -> tuple[bytes | None, str | None]:
        reason = self._reserve(record)
        if reason is not None:
            return None, reason
        entry = self.entries[record.path]
        try:
            data = self.client.read(entry, self.revision, self.limits.max_file_bytes)
        except NetworkError as exc:
            if exc.kind == "too_large":
                return None, f"exceeds the no-download per-file budget of {self.limits.max_file_bytes:,} bytes"
            if exc.kind in {"rate_limit", "budget"}:
                with self._lock:
                    when = ""
                    if exc.retry_after is not None:
                        when = f"; resets in about {int(exc.retry_after):,} s"
                    self._stop_reason = (
                        "provider API rate limit exhausted" + when if exc.kind == "rate_limit"
                        else str(exc)
                    )
                return None, self._stop_reason
            return None, f"content request failed ({exc.kind}: {exc})"
        with self._lock:
            self.counters["bytes_fetched"] += len(data)
            self.counters["files_fetched"] += 1
        return data, None

    def analyze_records(
        self, records, analyzers, locks, *,
        record_callback: Callable[[FileRecord, FileOutcome | None, str | None, int], None],
    ) -> None:
        """Fetch and analyze each eligible record with bounded parallelism.

        Results are handed to ``record_callback(record, outcome, skip_reason, fetched_size)``
        in the calling thread and in submission order, so the caller alone writes to the
        scan databases. At most ``2 * workers`` file contents are held in memory at once.
        """
        workers = self.limits.workers

        def work(record: FileRecord):
            content, reason = self._fetch(record)
            if content is None:
                return record, None, reason, 0
            path = self.virtual_root / record.path
            signature = _classify_head(content[:512], record.path)
            if signature:
                record.file_type = signature
            outcome = FileOutcome(digest=hashlib.sha256(content).hexdigest())
            with prefetched_content(path, content, None), collecting_facts() as facts:
                _run_analyzers(analyzers, locks, record, path, outcome)
                if record.extension in {".py", ".pyi"} and len(content) <= MAX_GRAPH_AST_FILE_BYTES:
                    self.python_imports[record.path] = parse_python_imports(self.virtual_root, record)
            outcome.facts = facts or None
            if PurePosixPath(record.path).name.lower() in LOCKFILE_NAMES and len(content) <= MAX_LOCKFILE_BYTES:
                with self._lock:
                    if self._kept_lockfile_bytes + len(content) <= MAX_KEPT_LOCKFILE_BYTES:
                        self._kept_lockfile_bytes += len(content)
                        self.lockfiles[record.path] = content.decode("utf-8", errors="replace")
            return record, outcome, None, len(content)

        pending: deque = deque()
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="pdt-no-download") as pool:
            for record in records:
                pending.append(pool.submit(work, record))
                while len(pending) >= workers * 2:
                    record_callback(*pending.popleft().result())
            while pending:
                record_callback(*pending.popleft().result())

    def lockfile_text(self, path: str) -> str:
        text = self.lockfiles.get(path)
        if text is None:
            raise OSError("lockfile content was not fetched in no-download mode")
        return text

    # ------------------------------------------------------------------
    def finalize(self) -> dict[str, Any]:
        """Record coverage, request use and timing; returns the source metadata."""
        coverage = []

        def add(kind: str, count: int, detail: str, incomplete: bool) -> None:
            if count:
                coverage.append({"kind": kind, "count": count, "detail": detail, "incomplete": incomplete})

        add("tree_truncated", self.counters["tree_truncated"],
            "The provider returned a truncated tree listing; some paths are missing from the inventory.", True)
        add("paths_not_materialized", self.counters["invalid_tree_paths"],
            f"{self.counters['invalid_tree_paths']:,} tree path(s) were malformed or unsafe and were not inventoried.", True)
        for reason, paths in sorted(self.skipped.items()):
            add("content_not_fetched", len(paths),
                f"{len(paths):,} file(s) were inventoried but their content was not fetched: {reason}.", True)
        add("git_submodules_not_fetched", self.counters["submodules"],
            f"{self.counters['submodules']:,} Git submodule(s) were inventoried but not fetched.", False)
        add("plugins_not_run", len(self.excluded_plugins),
            f"{len(self.excluded_plugins):,} third-party plugin(s) were not run ({', '.join(self.excluded_plugins)}): "
            "sandboxed plugins need a file copy on disk, which no-download mode never writes.", True)
        self.metadata.update({
            "coverage": coverage,
            "coverage_gaps": [item["detail"] for item in coverage if item["incomplete"]],
            "warnings": [item["detail"] for item in coverage]
            + ["The repository was read through the provider API in memory; nothing was written to disk."],
            "acquisition_seconds": round(time.monotonic() - self.started, 3),
            "tree_entries": self.counters["tree_entries"],
            "files_fetched": self.counters["files_fetched"],
            "bytes_fetched": self.counters["bytes_fetched"],
            "content_requests": self.counters["content_requests"],
            "api_requests": self.budget.used,
            "api_request_budget": self.budget.limit,
            "requests": self.http.statistics(),
        })
        return self.metadata

    def record_skip(self, record: FileRecord, reason: str) -> None:
        self._note_skip(reason, record.path)


def iter_skip_reasons(source: NoDownloadSource) -> Iterator[tuple[str, int]]:
    for reason, paths in source.skipped.items():
        yield reason, len(paths)
