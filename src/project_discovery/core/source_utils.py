"""Source-reading helpers that honor language declarations and redact report excerpts."""
from __future__ import annotations

import ast
import bisect
import configparser
import io
import os
import re
import stat
import threading
import tokenize
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from .limits import count_read, limit_reached
from .secret_patterns import ANY_TOKEN, ASSIGNMENT_OPERATOR, CREDENTIAL_KEYWORDS

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


_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def open_regular_descriptor(path: Path | str) -> tuple[int, os.stat_result]:
    """Open a regular file for reading without following a link or waiting on a FIFO.

    Returns the descriptor and its fstat. A path checked as a regular file can be replaced
    by a FIFO or a device before it is opened, and a plain open() of a FIFO waits for a
    writer forever (no budget can interrupt a blocked system call). O_NONBLOCK makes that
    open return at once; the descriptor must then be a regular file, and is made blocking
    again (regular-file reads never wait on the flag anyway).
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | _NONBLOCK
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"entry changed to a non-regular file: {path}")
        if _NONBLOCK:
            os.set_blocking(descriptor, True)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def keyed_identifier(keywords: str) -> str:
    """Regex source for a whole identifier (letters, digits, ``_``, ``-``) containing a keyword.

    The lookahead finds the keyword and the possessive body consumes the identifier without
    backtracking, so matching stays linear even on megabyte-long identifier runs. The
    unbounded ``[A-Za-z0-9_]*(?:keyword)[A-Za-z0-9_]*`` form it replaces was cubic on
    untrusted input such as ``tokentoken...``.
    """
    return rf"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*?(?:{keywords}))[A-Za-z0-9_-]++"


# Every key the secret scanner reports (CREDENTIAL_KEYWORDS) plus names only redacted, with
# the scanner's own operators (typed defaults, :=, =>), so no detected syntax leaves its
# value behind: "password :=" once lost only the operator and kept the literal.
_ASSIGNED_VALUE = r"""("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)(["']?"""
    + keyed_identifier(
        CREDENTIAL_KEYWORDS
        + r"|pwd|account[_-]?key|shared[_-]?access[_-]?key|sas[_-]?token|private[_-]?key"
        r"|database[_-]?url|connection[_-]?string|credential"
    )
    + ASSIGNMENT_OPERATOR + ")" + _ASSIGNED_VALUE
)
_IDENTITY_ASSIGNMENT = re.compile(
    r"""(?i)(["']?"""
    + keyed_identifier(
        r"first_?name|given_?name|forename|middle_?name|last_?name|family_?name|surname|user_?name"
        r"|login_?name|account_?name|email|e_mail|email_?address|mail_?address|phone|telephone|mobile"
        r"|cell_?number|street_?address|postal_?address|home_?address|date_?of_?birth"
        r"|birth_?date|dob|ssn|social_?security|passport_?number|national_?id"
    )
    + ASSIGNMENT_OPERATOR + ")" + _ASSIGNED_VALUE
)
_CREDENTIAL_URL = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]{0,31}://[^:/@\s]+:)[^@\s/]+(@)")
# A quoted or subscripted header key ("Authorization": "Bearer ...", headers['authorization']
# = ...) as well as Authorization: Basic ...
_AUTHORIZATION_HEADER = re.compile(
    r"""(?i)(\bauthorization["']?\]?[ \t]*[:=][ \t]*["']?)(?:(?:bearer|basic|token)[ \t]+)?[^,\r\n;"']+"""
)
# RFC 5321 limits: 64-character local part, 253-character domain.
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}\b")
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


# C0 and C1 control characters except tab and newline. Escape sequences (ESC), carriage
# returns and backspaces in scanned text could rewrite or spoof an operator's terminal.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def neutralize_controls(text: str) -> str:
    """Replace terminal control characters with U+FFFD; tab and newline are kept.

    CRLF line ends become LF first, so text read from Windows files is not marked.
    """
    if not _CONTROL_CHARACTERS.search(text):
        return text
    return _CONTROL_CHARACTERS.sub("�", text.replace("\r\n", "\n"))


def redact_source_excerpt(source_line: str, *, max_chars: int = 400) -> str:
    """Return a bounded source line with credentials and direct identifiers removed."""
    value = source_line.rstrip("\r\n")
    value = _PRIVATE_KEY_BODY.sub("[REDACTED PRIVATE KEY MATERIAL]", value)
    value = _PRIVATE_KEY_MATERIAL_LINE.sub(r"\1[REDACTED PRIVATE KEY MATERIAL]\2", value)
    value = _AUTHORIZATION_HEADER.sub(r"\1[REDACTED]", value)
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


def _quotes_content(exc: BaseException) -> bool:
    return isinstance(exc, configparser.Error) or hasattr(exc, "problem_mark")


def describe_error(exc: BaseException) -> str:
    """``Type: message`` for an analysis failure, quoting nothing from the scanned file.

    configparser and YAML messages quote the offending line or value (a password on a
    line without ``=``, the raw value that failed interpolation, a YAML snippet), so for
    those only the parser's description and the position are kept. Every other message is
    redacted like a source excerpt.
    """
    cause = exc.__cause__ if exc.__cause__ is not None and _quotes_content(exc.__cause__) else exc
    name = type(cause).__name__
    mark = getattr(cause, "problem_mark", None) or getattr(cause, "context_mark", None)
    if hasattr(cause, "problem_mark") or hasattr(cause, "context_mark"):  # yaml.MarkedYAMLError
        problem = getattr(cause, "problem", None) or getattr(cause, "context", None) or "invalid YAML"
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if hasattr(mark, "line") else ""
        return redact_source_excerpt(f"{name}: {problem}{where}")
    if isinstance(cause, configparser.Error):
        parts = []
        if getattr(cause, "section", None):
            parts.append(f"section {cause.section!r}")
        if getattr(cause, "option", None):
            parts.append(f"option {cause.option!r}")
        if getattr(cause, "lineno", None):
            parts.append(f"line {cause.lineno}")
        errors = getattr(cause, "errors", None)
        if errors:
            lines = ", ".join(str(number) for number, _ in errors[:5])
            parts.append(f"line {lines}" if len(errors) == 1 else f"lines {lines}" + (", ..." if len(errors) > 5 else ""))
        return redact_source_excerpt(f"{name}" + (f" ({'; '.join(parts)})" if parts else ""))
    return redact_source_excerpt(f"{name}: {exc}")


_BOMS = (
    (b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"),
)


def text_encoding(sample: bytes) -> str:
    """The codec of a text file from its first bytes.

    UTF-8 unless a byte-order mark or NUL-interleaved ASCII marks UTF-16 or UTF-32. Windows
    PowerShell 5.1 writes UTF-16LE for ``>`` and ``Out-File``; read as UTF-8, such a file
    has a NUL between every character, no pattern matches, and it looked clean.
    """
    for bom, codec in _BOMS:
        if sample.startswith(bom):
            return codec
    head = sample[:4096]
    half = len(head) // 2
    if half >= 8:
        even, odd = head[0::2].count(0), head[1::2].count(0)
        if odd > 0.4 * half and even < 0.05 * half:
            return "utf-16-le"
        if even > 0.4 * half and odd < 0.05 * half:
            return "utf-16-be"
    return "utf-8"


def utf8_stream(stream: BinaryIO, limit: int) -> tuple[BinaryIO, bool]:
    """``stream`` itself for UTF-8 text, or UTF-16/32 text transcoded to UTF-8 in memory.

    Returns the stream to read and whether more than ``limit`` bytes were available (the
    transcoded copy then holds only the first ``limit``). Line numbers are unchanged.
    """
    head = stream.read(4096)
    encoding = text_encoding(head)
    if encoding in ("utf-8", "utf-8-sig"):
        if stream.seekable():
            stream.seek(0)
            return stream, False
        rest = stream.read(max(0, limit + 1 - len(head)))
        data = head + rest
        return io.BytesIO(data[:limit]), len(data) > limit
    data = head + stream.read(max(0, limit + 1 - len(head)))
    return io.BytesIO(data[:limit].decode(encoding, errors="replace").encode("utf-8")), len(data) > limit


_NEWLINE = re.compile("\n")


class LineIndex:
    """1-based line numbers of offsets in one text, by bisecting its newline offsets.

    ``text.count("\\n", 0, offset)`` for every match is linear per match, so a dense file
    (a schema dump with one statement per line) cost minutes; the index is one pass over
    the text, built on first use, and each lookup is logarithmic.
    """

    __slots__ = ("_text", "_newlines")

    def __init__(self, text: str) -> None:
        self._text = text
        self._newlines: list[int] | None = None

    def line(self, offset: int) -> int:
        if self._newlines is None:
            self._newlines = [match.start() for match in _NEWLINE.finditer(self._text)]
        return bisect.bisect_left(self._newlines, offset) + 1


_prefetch = threading.local()
_parsed = threading.local()


# A syntax tree costs about 100-200 times its source in memory: a 5.6 MB generated module
# took 1.2 GB. Larger modules are reported instead of parsed.
MAX_PYTHON_SYNTAX_TREE_CHARS = 4 * 1024 * 1024
MAX_PYTHON_SYNTAX_TREE_LINES = 100_000


class PythonSourceTooLarge(MemoryError):
    """A Python module exceeds the syntax-tree budget (reported, never parsed)."""


def parse_python(source: str, filename: str = "<unknown>") -> ast.AST:
    """``ast.parse`` with a one-entry per-thread memo so analyzers of a file share a tree.

    Several analyzers parse the same module back to back; the tree (or the parse error)
    is reused when the source text is identical. Callers must treat trees as read-only.
    Modules beyond MAX_PYTHON_SYNTAX_TREE_CHARS or _LINES raise PythonSourceTooLarge.
    """
    cached = getattr(_parsed, "entry", None)
    if cached is not None and (cached[0] is source or cached[0] == source):
        result = cached[1]
    else:
        lines = source.count("\n") + 1
        if len(source) > MAX_PYTHON_SYNTAX_TREE_CHARS or lines > MAX_PYTHON_SYNTAX_TREE_LINES:
            result = PythonSourceTooLarge(
                f"{len(source):,} characters and {lines:,} lines exceed the Python syntax-tree budget "
                f"({MAX_PYTHON_SYNTAX_TREE_CHARS:,} characters, {MAX_PYTHON_SYNTAX_TREE_LINES:,} lines)"
            )
        else:
            try:
                result = ast.parse(source, filename=filename)
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                result = exc
        _parsed.entry = (source, result)
    if isinstance(result, BaseException):
        if isinstance(result, PythonSourceTooLarge):
            # Each analyzer that asked for the tree reached the limit, also from the memo.
            if len(source) > MAX_PYTHON_SYNTAX_TREE_CHARS:
                limit_reached("chars", MAX_PYTHON_SYNTAX_TREE_CHARS, len(source))
            else:
                limit_reached("lines", MAX_PYTHON_SYNTAX_TREE_LINES, source.count("\n") + 1)
        # Raise a fresh instance so repeated failures do not chain tracebacks.
        raise type(result)(*result.args)
    return result


def _prefetch_key(path: Path) -> str:
    return os.path.normcase(os.fspath(path))


class _CountingRaw(io.RawIOBase):
    """A raw stream that adds the bytes read through it to the running analyzer call."""

    mode = "rb"

    def __init__(self, raw) -> None:
        super().__init__()
        self._raw = raw

    @property
    def name(self):
        return self._raw.name

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int | None:
        count = self._raw.readinto(buffer)
        if count:
            count_read(count)
        return count

    def readall(self) -> bytes:
        data = self._raw.read()  # FileIO reads the rest in one call, BytesIO returns it
        count_read(len(data))
        return data

    def seekable(self) -> bool:
        return self._raw.seekable()

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._raw.seek(offset, whence)

    def tell(self) -> int:
        return self._raw.tell()

    def fileno(self) -> int:
        return self._raw.fileno()

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            finally:
                super().close()


def _stream_size(stream) -> int | None:
    """The size of a verified stream's file or buffer, for a limit record."""
    try:
        return os.fstat(stream.fileno()).st_size
    except (OSError, ValueError):  # io.UnsupportedOperation is both
        pass
    try:
        return stream.seek(0, io.SEEK_END)
    except (OSError, ValueError):
        return None


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
        # BufferedReader keeps peek()/readline()/seek() semantics of a real file; the
        # counting raw stream accounts what the analyzer reads.
        with io.BufferedReader(_CountingRaw(io.BytesIO(entry[2]))) as stream:
            yield stream
        return
    observed = path.lstat()
    if not stat.S_ISREG(observed.st_mode):
        raise OSError(f"refusing to read non-regular or symlink entry: {path}")
    observed_identity = stat_identity(observed)
    if not identity_matches(expected_identity, observed_identity):
        raise OSError(f"file identity changed since inventory: {path}")
    descriptor, opened = open_regular_descriptor(path)
    try:
        opened_identity = stat_identity(opened)
        if not identity_matches(observed_identity, opened_identity):
            raise OSError(f"file identity changed while opening: {path}")
        if not identity_matches(expected_identity, opened_identity):
            raise OSError(f"file identity changed since inventory: {path}")
        raw = io.FileIO(descriptor, "r", closefd=True)
        descriptor = -1
        stream = io.BufferedReader(_CountingRaw(raw))
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
            limit_reached("bytes", max_bytes, _stream_size(stream) or len(raw_source))
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
            limit_reached("bytes", max_bytes, _stream_size(stream) or len(raw_content))
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

