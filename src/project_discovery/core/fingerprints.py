"""Keyed fingerprints of secret values (``pdt scan --fingerprint-key FILE``).

A secret finding never carries its value. With a key configured, it carries
``fingerprint: hmac-sha256:<16 hex digits>``, an HMAC-SHA256 of the value under the operator's
key. The same value gives the same fingerprint in every file, scan and repository scanned with
that key, so a reused secret can be followed across them. Without the key the fingerprint
cannot be reversed or checked against a guess: a plain hash of a short password could be
brute-forced, a keyed one cannot. Neither the key nor the value is written anywhere. The report
names the key by an identifier derived from it (``key_id``), which says whether two reports
used the same key.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

MIN_KEY_BYTES = 16
MAX_KEY_BYTES = 4096
FINGERPRINT_ENV = "PDT_FINGERPRINT_KEY"
_state: dict[str, bytes | None] = {"key": None}


def load_fingerprint_key(path: Path | None = None, environ: dict | None = None) -> tuple[bytes, str] | None:
    """(key, source) from a key file or the ``PDT_FINGERPRINT_KEY`` environment variable, or None
    when neither is given; ValueError for a key too short to resist guessing."""
    if path is not None:
        data = Path(path).expanduser().read_bytes()[:MAX_KEY_BYTES + 1]
        source = "file"
    else:
        value = (environ if environ is not None else os.environ).get(FINGERPRINT_ENV, "")
        if not value:
            return None
        data, source = value.encode("utf-8"), "environment"
    key = data.strip()
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"the fingerprint key must be at least {MIN_KEY_BYTES} bytes")
    if len(key) > MAX_KEY_BYTES:
        raise ValueError(f"the fingerprint key must be at most {MAX_KEY_BYTES} bytes")
    return key, source


def configure_fingerprint_key(key: bytes | None) -> None:
    """Set the key for this process (the scan's coordinator and each worker)."""
    _state["key"] = key or None


def configured_fingerprint_key() -> bytes | None:
    return _state["key"]


def key_id(key: bytes | None = None) -> str | None:
    """An identifier of the key that reveals nothing about it: two reports with the same
    ``key_id`` used the same key."""
    key = key if key is not None else _state["key"]
    return hmac.new(key, b"pdt fingerprint key id", hashlib.sha256).hexdigest()[:12] if key else None


def fingerprint(value: str) -> str | None:
    """``hmac-sha256:<16 hex>`` of a secret value under the configured key, or None without one."""
    key = _state["key"]
    if not key or not value:
        return None
    return "hmac-sha256:" + hmac.new(key, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:16]
