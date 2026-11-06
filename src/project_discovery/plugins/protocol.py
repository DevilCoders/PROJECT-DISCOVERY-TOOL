"""Wire format shared by PDT and its isolated plugin hosts.

Every message is one frame: a 4-byte big-endian length followed by that many bytes of
UTF-8 JSON. JSON is data only, so nothing a plugin sends can execute in PDT (unlike
pickle). Hosts never receive file contents over the pipe; they read a private staged
copy of each file instead.
"""
from __future__ import annotations

import json
from typing import Any, Callable

# A response larger than this is a protocol violation and ends the host process.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
# PDT's own requests are small (file records and staged paths).
MAX_REQUEST_BYTES = 64 * 1024 * 1024
# Findings beyond this per file are dropped and the truncation is reported.
MAX_FINDINGS_PER_FILE = 5000
HEADER_BYTES = 4


class ProtocolError(ValueError):
    """A frame was truncated, oversized or not a JSON object."""


def encode_frame(message: dict[str, Any]) -> bytes:
    """Serialize one message; lone surrogates from undecodable file names are escaped."""
    payload = json.dumps(
        message, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ).encode("ascii")
    return len(payload).to_bytes(HEADER_BYTES, "big") + payload


def read_frame(read: Callable[[int], bytes], max_bytes: int) -> dict[str, Any] | None:
    """Read one frame with ``read(n)``; return None at a clean end of stream."""
    header = read(HEADER_BYTES)
    if not header:
        return None
    if len(header) != HEADER_BYTES:
        raise ProtocolError("truncated frame header")
    size = int.from_bytes(header, "big")
    if size > max_bytes:
        raise ProtocolError(f"frame of {size:,} bytes exceeds the {max_bytes:,}-byte limit")
    payload = read(size)
    if len(payload) != size:
        raise ProtocolError("truncated frame payload")
    try:
        message = json.loads(payload)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError(f"frame is not valid JSON: {type(exc).__name__}") from exc
    if not isinstance(message, dict):
        raise ProtocolError("frame is not a JSON object")
    return message
