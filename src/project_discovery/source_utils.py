"""Source-reading helpers that honor language-specific encoding declarations."""
from __future__ import annotations

import tokenize
from pathlib import Path


def read_python_source(path: Path) -> str:
    """Read Python source using PEP 263 encoding-cookie detection."""
    with tokenize.open(path) as stream:
        return stream.read()
