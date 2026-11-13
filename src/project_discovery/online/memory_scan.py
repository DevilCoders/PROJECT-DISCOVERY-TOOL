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
import re
import secrets
import tempfile
import threading
import time
import urllib.parse
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator

from ..analyzers.dependencies.lockfile_parsers import LOCKFILE_NAMES, MAX_LOCKFILE_BYTES
from ..catalog.languages import detect_language, is_source_path, is_textual_path
from ..core.source_utils import prefetched_content
from ..engine.executor import FileOutcome, _run_analyzers
from ..intelligence.facts import collecting_facts
from ..intelligence.python_graph import MAX_GRAPH_AST_FILE_BYTES, parse_python_imports
from ..inventory.scanner import (
    _classify_head, _exclusion_match, _size_bucket, development_marker, normalize_exclusions,
)
from ..inventory.store import InventoryStore, StoredFileRecords, StoredRecordSequence
from ..models import DirectoryRecord, FileRecord, SpecialEntryRecord, SymlinkRecord
from .credentials import ApiCredential, resolve_credential
from .http import DEFAULT_TIMEOUT, HttpClient, NetworkError
from .providers import (
    CLIENTS,
    ProviderError,
    RequestBudget,
    ResolvedRevision,
    TreeEntry,
    api_provider_for,
    provider_for_host,
    server_api_url,
    default_api_url,
    split_repository,
    symlink_scope,
)
from .repositories import RemoteTarget

DEFAULT_API_MAX_FILES = 20_000
DEFAULT_API_MAX_BYTES = 512 * 1024 * 1024
DEFAULT_API_MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_API_MAX_REQUESTS = 15_000
DEFAULT_API_WORKERS = 8
# Lockfile texts kept in memory for the online vulnerability lookup after analysis.
MAX_KEPT_LOCKFILE_BYTES = 256 * 1024 * 1024
MAX_SYMLINK_TARGET_BYTES = 4096
# A skip reason with this prefix is the user's --skip, not a no-download coverage gap.
SKIP_OPTION_REASON = "Explicit --skip: "


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
    # --no-download-plugins: sandboxed plugins run on a transient copy of each file, staged
    # in the plugin host's private folder under the output and deleted after the call.
    plugins: bool = False


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
        self.provider = provider_for_host(
            api_provider_for(target.provider, options.provider), self.host, options.provider,
        )
        self.api_url = options.api_url or (
            server_api_url(self.host, self.repository) if self.provider == "bitbucket-server"
            and not os.environ.get("PDT_API_URL_" + re.sub(r"[^A-Z0-9]", "_", self.host.upper()))
            else default_api_url(self.provider, self.host)
        )
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
        self._api_host = urllib.parse.urlsplit(self.api_url).hostname or "the provider API"
        self.revision: ResolvedRevision | None = None
        self.entries: dict[str, TreeEntry] = {}
        self.lockfiles: dict[str, str] = {}
        self.python_imports: dict[str, tuple] = {}
        self._kept_lockfile_bytes = 0
        self._lock = threading.Lock()
        # Byte-budget accounting: reservations of reads in flight plus bytes already used.
        self._budget_changed = threading.Condition(self._lock)
        self._reserved_bytes = 0
        self._in_flight = 0
        self._skip_bytes: int | None = None
        self._stop_reason: str | None = None
        self._stop_kind: str | None = None
        self._listing_cause: str | None = None
        self.counters: Counter[str] = Counter()
        self.skipped: dict[str, list[str]] = {}
        self.started = time.monotonic()
        self.acquired_at = datetime.now(timezone.utc).isoformat()
        self.metadata: dict[str, Any] = {}
        self.excluded_plugins: list[str] = []
        self.staged_plugins: list[str] = []

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
        # A file whose size the listing lacks (GitLab) is checked against --skip when read.
        self._skip_bytes = max_file_bytes if skip_oversized else None
        entries, truncated, listing_error = self.client.listing(self.revision)
        if listing_error is not None:
            # Content requests would hit the same exhausted limit: stop them now.
            self._listing_cause = self._stop_for(listing_error)
        # The same spellings and matching as a local walk; an absolute path is a usage error.
        excluded_names, excluded_paths = normalize_exclusions(ignores)
        # Corroborates generic development-tree names (go/pkg/mod, env/pyvenv.cfg).
        listed = {entry.path for entry in entries}
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
            match = _exclusion_match(path, name, excluded_names, excluded_paths)
            exclusion = match[1] if match else None
            marker = development_marker(name, lambda relative: f"{path}/{relative}" in listed)
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
            if match:
                stats["pruned_directory_count"] += 1
                stats[f"pruned_dir:{name.casefold()}"] += 1
                stats[match[0]] += 1
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
            # GitLab's tree listing has no sizes. Such a file keeps size 0 in the unknown
            # bucket, out of the totals, until its content arrives (see listed_size).
            size = entry.size if entry.size is not None else 0
            file_type = "source" if is_source_path(entry.path) else "text" if is_textual_path(entry.path) else "binary/unclassified"
            record = FileRecord(
                entry.path, size, PurePosixPath(name).suffix.lower(), detect_language(entry.path),
                file_type=file_type,
                size_bucket=_size_bucket(size) if entry.size is not None else "unknown",
                is_hidden=hidden, permissions=0o755 if entry.executable else 0o644,
            )
            if entry.size is None:
                stats["size_unknown_count"] += 1
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
        self.counters["sizes_unknown"] = stats.get("size_unknown_count", 0)
        self.walk_stats = stats
        return (
            StoredFileRecords(store.path),
            StoredRecordSequence(store.path, "directory", DirectoryRecord),
            StoredRecordSequence(store.path, "symlink", SymlinkRecord),
            StoredRecordSequence(store.path, "special", SpecialEntryRecord),
            stats,
        )

    def _symlink_target(self, entry: TreeEntry) -> str | None:
        with self._lock:
            stopped = self._stop_kind
        if stopped is not None:
            self._note_skip(f"symlink target not read ({stopped})", entry.path)
            return None
        try:
            data = self.client.read(entry, self.revision, MAX_SYMLINK_TARGET_BYTES)
        except NetworkError as exc:
            if exc.kind in {"rate_limit", "budget"}:
                self._stop_for(exc)
            self._note_skip(f"symlink target not read ({exc.kind})", entry.path)
            return None
        self.counters["symlink_requests"] += 1
        return data.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    def _note_skip(self, reason: str, path: str) -> None:
        with self._lock:
            self.skipped.setdefault(reason, []).append(path)

    def listed_size(self, path: str) -> int | None:
        """The size the provider's tree listing gave for ``path``; None when it gave none."""
        entry = self.entries.get(path)
        return entry.size if entry is not None else None

    def _reserve(self, record: FileRecord) -> tuple[str | None, int]:
        """Apply the file, byte and per-file budgets before a content request.

        Returns (refusal reason, bytes reserved). The byte budget counts the reservations
        of reads in flight, so parallel reads cannot overshoot it together. A size the
        listing lacks reserves what the read may return: the per-file budget, or the
        rest of the byte budget when less remains. When reads in flight hold the budget,
        this waits for them to release what they did not use instead of refusing.
        """
        entry = self.entries.get(record.path)
        size = entry.size if entry and entry.size is not None else None
        with self._budget_changed:
            while True:
                if self._stop_reason:
                    return self._stop_reason, 0
                if self.counters["content_requests"] >= self.limits.max_files:
                    return f"no-download file budget of {self.limits.max_files:,} files reached", 0
                if size is not None and size > self.limits.max_file_bytes:
                    return f"exceeds the no-download per-file budget of {self.limits.max_file_bytes:,} bytes", 0
                available = self.limits.max_bytes - self._reserved_bytes
                if (size if size is not None else 1) <= available:
                    break
                if not self._in_flight:
                    return f"no-download byte budget of {self.limits.max_bytes:,} bytes reached", 0
                self._budget_changed.wait()
            reservation = size if size is not None else min(self.limits.max_file_bytes, available)
            self._reserved_bytes += reservation
            self._in_flight += 1
            self.counters["content_requests"] += 1
            return None, reservation

    def _stop_for(self, exc: NetworkError) -> str:
        """Stop all later requests: the rate limit or the request budget is exhausted."""
        with self._lock:
            if self._stop_reason is None:
                when = ""
                if exc.retry_after is not None:
                    when = f"; resets in about {int(exc.retry_after):,} s"
                self._stop_reason = (
                    "provider API rate limit exhausted" + when if exc.kind == "rate_limit"
                    else str(exc)
                )
                self._stop_kind = exc.kind
            return self._stop_reason

    def _settle(self, reservation: int, used: int) -> None:
        """Release the unused part of a read's reservation and wake waiting reads."""
        with self._budget_changed:
            self._reserved_bytes -= reservation - used
            self._in_flight -= 1
            self._budget_changed.notify_all()

    def _fetch(self, record: FileRecord) -> tuple[bytes | None, str | None]:
        reason, reservation = self._reserve(record)
        if reason is not None:
            return None, reason
        entry = self.entries[record.path]
        cap = self.limits.max_file_bytes
        cap_reason = f"exceeds the no-download per-file budget of {self.limits.max_file_bytes:,} bytes"
        if entry.size is None:
            # The read may return no more than it reserved, and --skip, which could not be
            # decided from the listing, is decided from the bytes as they arrive.
            if reservation < cap:
                cap, cap_reason = reservation, f"no-download byte budget of {self.limits.max_bytes:,} bytes reached"
            if self._skip_bytes is not None and self._skip_bytes < cap:
                cap, cap_reason = self._skip_bytes, f"{SKIP_OPTION_REASON}exceeds {self._skip_bytes} bytes"
        used = 0
        try:
            data = self.client.read(entry, self.revision, cap)
            used = len(data)
        except NetworkError as exc:
            if exc.kind == "too_large":
                # What a refused response transferred counts against the byte budget, so
                # oversized files of unknown size cannot exceed it. A Content-Length above
                # the cap refuses it before any body byte is read.
                used = cap if exc.received is None else min(cap, exc.received)
                with self._lock:
                    self.counters["bytes_discarded"] += used
                return None, cap_reason
            if exc.kind in {"rate_limit", "budget"}:
                return None, self._stop_for(exc)
            # The cause without the file's path: one coverage gap per cause, with samples.
            cause = f"HTTP {exc.status}" if exc.status else exc.kind
            return None, f"content request failed ({cause} from {self._api_host})"
        finally:
            self._settle(reservation, used)
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

        def add(kind: str, count: int, detail: str, incomplete: bool, samples=None) -> None:
            if count:
                item = {"kind": kind, "count": count, "detail": detail, "incomplete": incomplete}
                if samples:
                    item["samples"] = samples
                coverage.append(item)

        add("tree_truncated", self.counters["tree_truncated"],
            (f"The tree listing stopped early ({self._listing_cause}); some paths are missing from the inventory."
             if self._listing_cause else
             "The provider returned a truncated tree listing; some paths are missing from the inventory."), True)
        add("paths_not_materialized", self.counters["invalid_tree_paths"],
            f"{self.counters['invalid_tree_paths']:,} tree path(s) were malformed or unsafe and were not inventoried.", True)
        for reason, paths in sorted(self.skipped.items()):
            add("content_not_fetched", len(paths),
                f"{len(paths):,} file(s) were inventoried but their content was not fetched: {reason}.", True,
                samples=sorted(paths)[:20])
        add("sizes_unknown", self.counters["sizes_unknown"],
            f"{self.counters['sizes_unknown']:,} file(s) have no size in the provider's tree listing and "
            "were not fetched; size totals and buckets leave them out (bucket 'unknown').", False)
        add("git_submodules_not_fetched", self.counters["submodules"],
            f"{self.counters['submodules']:,} Git submodule(s) were inventoried but not fetched.", False)
        add("plugins_not_run", len(self.excluded_plugins),
            f"{len(self.excluded_plugins):,} third-party plugin(s) were not run ({', '.join(self.excluded_plugins)}): "
            "sandboxed plugins need a file copy on disk, which no-download mode writes only with "
            "--no-download-plugins.", True)
        if self.staged_plugins:
            self.metadata["written_to_disk"] = True
            self.metadata["disk_writes"] = "transient plugin staging under OUTPUT/.pdt-cache/plugins"
        self.metadata.update({
            "coverage": coverage,
            "coverage_gaps": [item["detail"] for item in coverage if item["incomplete"]],
            "warnings": [item["detail"] for item in coverage]
            + ([
                f"{len(self.staged_plugins):,} third-party plugin(s) ran ({', '.join(self.staged_plugins)}) "
                "with --no-download-plugins: each file they analyzed was copied into the plugin host's private "
                "folder under the output for that call and deleted after it."
            ] if self.staged_plugins else [])
            + ["The repository was read through the provider API in memory; " + (
                "only the transient copies for third-party plugins were written to disk."
                if self.staged_plugins else "nothing was written to disk."
            )],
            "acquisition_seconds": round(time.monotonic() - self.started, 3),
            "tree_entries": self.counters["tree_entries"],
            "files_fetched": self.counters["files_fetched"],
            "bytes_fetched": self.counters["bytes_fetched"],
            "bytes_discarded": self.counters["bytes_discarded"],
            "content_requests": self.counters["content_requests"],
            "api_requests": self.budget.used,
            "api_request_budget": self.budget.limit,
            "requests": self.http.statistics(),
        })
        return self.metadata

    def record_skip(self, record: FileRecord, reason: str) -> None:
        self._note_skip(reason, record.path)

    def size_learned(self) -> None:
        """One file whose listing lacked a size was fetched, so its size is now known."""
        with self._lock:
            self.counters["sizes_unknown"] -= 1


def iter_skip_reasons(source: NoDownloadSource) -> Iterator[tuple[str, int]]:
    for reason, paths in source.skipped.items():
        yield reason, len(paths)
