"""Source-reading helpers that honor language declarations and redact report excerpts."""
from __future__ import annotations

import ast
import io
import os
import re
import stat
import threading
import tokenize
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from .secret_patterns import ANY_TOKEN

FileIdentity =tuple[int | None, int | None, int | None, int | None, int | None]

# Windows stat semantics differ between path- and handle-based calls: DirEntry.stat()
# reports zero st_dev/st_ino, and st_ctime is the creation time from lstat() but may be
# the metadata-change time from fstat() on Python 3.12+. Those fields are reported as
# unknown on Windows instead of producing false "identity changed" refusals.
_WINDOWS = os.name == "nt"


def normalize_identity(identity: FileIdentity | None) -> FileIdentity | None:
    """Drop identity fields that the current platform cannot compare reliably."""
    if identity is None:
        return None
    device, inode, size, mtime_ns, ctime_ns = identity
    if _WINDOWS:
        if not device and not inode:
            device = inode = None
        ctime_ns = None
    return (device, inode, size, mtime_ns, ctime_ns)


def stat_identity(info: os.stat_result) -> FileIdentity:
    """Return the comparable (device, inode, size, mtime_ns, ctime_ns) identity of a stat."""
    return normalize_identity((
        getattr(info, "st_dev", None),
        getattr(info, "st_ino", None),
        getattr(info, "st_size", None),
        getattr(info, "st_mtime_ns", None),
        getattr(info, "st_ctime_ns", None),
    ))


def as_identity(value: os.stat_result | FileIdentity | None) -> FileIdentity | None:
    """Coerce a stat result or a five-field identity tuple into a normalized identity."""
    if value is None:
        return None
    # os.stat_result is a tuple subclass, so it must be recognized before plain tuples;
    # zipping its ten positional fields against an identity compares unrelated values.
    if isinstance(value, os.stat_result):
        return stat_identity(value)
    if len(value) != 5:
        raise ValueError("file identity must contain exactly five fields")
    return normalize_identity(tuple(value))


def identity_matches(
    expected: os.stat_result | FileIdentity | None,
    actual: os.stat_result | FileIdentity | None,
) -> bool:
    """Compare two identities, skipping fields that either side could not report."""
    expected, actual = as_identity(expected), as_identity(actual)
    if expected is None or actual is None:
        return True
    return all(
        wanted is None or observed is None or wanted == observed
        for wanted, observed in zip(expected, actual, strict=True)
    )


_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)(["']?[A-Za-z0-9_]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key|account[_-]?key|shared[_-]?access[_-]?key|sas[_-]?token|private[_-]?key|database[_-]?url|connection[_-]?string|credential|refresh[_-]?token|aws_secret_access_key)[A-Za-z0-9_]*["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
)
_IDENTITY_ASSIGNMENT = re.compile(
    r"""(?ix)(["']?[A-Za-z0-9_]*(?:first_?name|given_?name|middle_?name|last_?name|family_?name|surname|user_?name|login_?name|account_?name|email|e_mail|email_?address|phone|telephone|mobile|cell_?number|street_?address|postal_?address|home_?address|date_?of_?birth|birth_?date|dob|ssn|social_?security|passport_?number|national_?id)[A-Za-z0-9_]*["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
)
_CREDENTIAL_URL = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s/]+(@)")
_AUTHORIZATION_HEADER = re.compile(
    r"(?i)\bauthorization\s*[:=]\s*(?:(?:bearer|basic)\s+)?[^,\r\n;]+"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[A-Za-z0-9-]{16,}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{12,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|"
    r"sk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"hf_[A-Za-z0-9]{24,}|npm_[A-Za-z0-9]{24,}|pypi-[A-Za-z0-9_-]{30,})\b"
)
_PRIVATE_KEY_BODY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*", re.I)
# PEM payload lines are base64-only; redact them conservatively even when a finding
# excerpt contains the body line but not the BEGIN marker.
_PRIVATE_KEY_MATERIAL_LINE = re.compile(r"(?m)^([ \t]*)[A-Za-z0-9+/]{32,}={0,2}([ \t]*)$")


def redact_source_excerpt(source_line: str, *, max_chars: int = 400) -> str:
    """Return a bounded source line with credentials and direct identifiers removed."""
    value = source_line.rstrip("\r\n")
    value = _PRIVATE_KEY_BODY.sub("[REDACTED PRIVATE KEY MATERIAL]", value)
    value = _PRIVATE_KEY_MATERIAL_LINE.sub(r"\1[REDACTED PRIVATE KEY MATERIAL]\2", value)
    value = _AUTHORIZATION_HEADER.sub("Authorization: [REDACTED]", value)
    value = _SECRET_ASSIGNMENT.sub(r'\1"[REDACTED]"', value)
    value = _IDENTITY_ASSIGNMENT.sub(r'\1"[REDACTED]"', value)
    value = _CREDENTIAL_URL.sub(r"\1[REDACTED]\2", value)
    # The shared registry guarantees every detected format is also redacted.
    value = ANY_TOKEN.sub("[REDACTED_TOKEN]", value)
    value = _TOKEN.sub("[REDACTED_TOKEN]", value)
    value = _EMAIL.sub("[REDACTED_EMAIL]", value)
    if len(value) > max_chars:
        value = value[:max_chars] + " … [truncated]"
    return value


_prefetch = threading.local()
_parsed = threading.local()


def parse_python(source: str, filename: str = "<unknown>") -> ast.AST:
    """``ast.parse`` with a one-entry per-thread memo so analyzers of a file share a tree.

    Several analyzers parse the same module back to back; the tree (or the parse error)
    is reused when the source text is identical. Callers must treat trees as read-only.
    """
    cached = getattr(_parsed, "entry", None)
    if cached is not None and (cached[0] is source or cached[0] == source):
        result = cached[1]
    else:
        try:
            result = ast.parse(source, filename=filename)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            result = exc
        _parsed.entry = (source, result)
    if isinstance(result, BaseException):
        # Raise a fresh instance so repeated failures do not chain tracebacks.
        raise type(result)(*result.args)
    return result


def _prefetch_key(path: Path) -> str:
    return os.path.normcase(os.fspath(path))


@contextmanager
def prefetched_content(path: Path, data: bytes, identity: FileIdentity | None) -> Iterator[None]:
    """Serve this thread's verified reads of ``path`` from ``data`` (read-once analysis).

    ``data`` must itself have been read through ``open_verified_binary``; the caller
    re-verifies the file after analysis, so the identity guarantees are unchanged.
    """
    previous = getattr(_prefetch, "entry", None)
    _prefetch.entry = (_prefetch_key(path), identity, data)
    try:
        yield
    finally:
        _prefetch.entry = previous


@contextmanager
def open_verified_binary(
    path: Path,
    expected_identity: FileIdentity | None = None,
) -> Iterator[BinaryIO]:
    """Open a regular file without following symlinks and verify its scan-time identity.

    The identity tuple is (device, inode, size, mtime_ns, ctime_ns). Missing
    platform fields are represented by None and are not compared. O_NOFOLLOW
    is requested where the operating system provides it; fstat comparison is
    still performed on platforms that do not expose that flag.
    """
    path = Path(path)
    entry = getattr(_prefetch, "entry", None)
    if (
        entry is not None
        and entry[0] == _prefetch_key(path)
        and identity_matches(expected_identity, entry[1])
    ):
        # BufferedReader keeps peek()/readline()/seek() semantics of a real file.
        with io.BufferedReader(io.BytesIO(entry[2])) as stream:
            yield stream
        return
    observed = path.lstat()
    if not stat.S_ISREG(observed.st_mode):
        raise OSError(f"refusing to read non-regular or symlink entry: {path}")
    observed_identity = stat_identity(observed)
    if not identity_matches(expected_identity, observed_identity):
        raise OSError(f"file identity changed since inventory: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"entry changed to a non-regular file: {path}")
        opened_identity = stat_identity(opened)
        if not identity_matches(observed_identity, opened_identity):
            raise OSError(f"file identity changed while opening: {path}")
        if not identity_matches(expected_identity, opened_identity):
            raise OSError(f"file identity changed since inventory: {path}")
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        try:
            yield stream
        finally:
            stream.close()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def open_verified_text(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
    expected_identity: FileIdentity | None = None,
):
    """Yield a text wrapper over a descriptor-verified file without reopening its path."""
    with open_verified_binary(path, expected_identity) as binary:
        text_stream = io.TextIOWrapper(binary, encoding=encoding, errors=errors)
        try:
            yield text_stream
        finally:
            # The outer context owns the binary descriptor.
            text_stream.detach()


def read_python_source(
    path: Path,
    *,
    expected_identity: FileIdentity | None = None,
) -> str:
    """Read Python source using PEP 263 encoding-cookie detection and pinned identity."""
    with open_verified_binary(path, expected_identity) as raw:
        raw_source = raw.read()
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_source).readline)
    return raw_source.decode(encoding)


class SourceBudgetExceeded(ValueError):
    """Raised when a source file exceeds a parser's bounded read budget."""


def read_python_source_bounded(
    path: Path,
    max_bytes: int,
    *,
    expected_identity: FileIdentity | None = None,
) -> str:
    """Read at most max_bytes + 1 through a verified descriptor and honor PEP 263."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    with open_verified_binary(path, expected_identity) as stream:
        raw_source = stream.read(max_bytes + 1)
    if len(raw_source) > max_bytes:
        raise SourceBudgetExceeded(
            f"source grew beyond the {max_bytes:,}-byte parser budget while being read"
        )
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_source).readline)
    return raw_source.decode(encoding)


def read_bytes_bounded(
    path: Path,
    max_bytes: int,
    *,
    expected_identity: FileIdentity | None = None,
) -> bytes:
    """Read a binary artifact through a verified descriptor with a max_bytes + 1 budget."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    with open_verified_binary(path, expected_identity) as stream:
        raw_content = stream.read(max_bytes + 1)
    if len(raw_content) > max_bytes:
        raise SourceBudgetExceeded(
            f"content grew beyond the {max_bytes:,}-byte analyzer budget while being read"
        )
    return raw_content


def read_text_bounded(
    path: Path,
    max_bytes: int,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
    expected_identity: FileIdentity | None = None,
) -> str:
    """Read a text artifact through a verified descriptor and enforce its byte budget."""
    return read_bytes_bounded(
        path, max_bytes, expected_identity=expected_identity,
    ).decode(encoding, errors=errors)

