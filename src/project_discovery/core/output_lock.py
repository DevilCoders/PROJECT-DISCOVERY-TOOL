"""One PDT scan per output directory at a time.

A second scan into an output directory whose scan is still running used to clear and refill
the shared inventory database under the first, and both wrote reports that mixed two roots.
The lock is an operating-system file lock, so a scan that dies (a crash, a kill) releases it
and no stale lock remains.
"""
from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path
from typing import Iterator

# The lock covers one byte far past the owner note (Windows locks byte ranges, and a buffered
# read of the note asks for a whole block), so other processes can still read the note.
_LOCK_OFFSET = 1 << 30


class OutputInUse(ValueError):
    """Another PDT process is writing to the same output directory."""


def _lock(handle) -> bool:
    if os.name == "nt":
        import msvcrt

        handle.seek(_LOCK_OFFSET)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(handle) -> None:
    with contextlib.suppress(OSError):
        if os.name == "nt":
            import msvcrt

            handle.seek(_LOCK_OFFSET)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def output_lock(output: Path) -> Iterator[None]:
    """Hold ``OUTPUT/.pdt-cache/scan.lock`` for the scan; raise OutputInUse when it is held."""
    cache = output / ".pdt-cache"
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / "scan.lock"
    with open(path, "a+b") as handle:
        if not _lock(handle):
            try:
                os.lseek(handle.fileno(), 0, os.SEEK_SET)
                owner = os.read(handle.fileno(), 200).decode("utf-8", "replace").strip()
            except OSError:
                owner = ""
            raise OutputInUse(
                f"Another PDT scan is writing to {output} ({owner or 'owner unknown'}). "
                "Wait for it to finish or choose another --output."
            )
        try:
            handle.seek(0)
            handle.truncate()
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            handle.write(f"process {os.getpid()}, started {stamp}\n".encode())
            handle.flush()
            yield
        finally:
            _unlock(handle)
