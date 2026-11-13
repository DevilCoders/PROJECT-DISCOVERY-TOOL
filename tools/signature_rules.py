"""Generate native/cpp/pdt_signature_rules.h, the C++ classifier's rule table.

    python tools/signature_rules.py            # print the table
    python tools/signature_rules.py --write    # rewrite the committed header
    python tools/signature_rules.py --check    # exit 1 when the header is stale

The table is generated from the Python catalog (src/project_discovery/inventory/
signatures.py), never edited by hand; tests/engine/test_native_backend.py fails when it is
out of date, and a C++ build from a stale table is not used (its digest differs).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "native" / "cpp" / "pdt_signature_rules.h"

try:
    import project_discovery  # noqa: F401
except ImportError:  # a checkout without an installed package
    sys.path.insert(0, str(ROOT / "src"))

from project_discovery.inventory.signatures import render_cpp_rules  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="rewrite native/cpp/pdt_signature_rules.h")
    mode.add_argument("--check", action="store_true", help="exit 1 when the committed header is stale")
    options = parser.parse_args(argv)
    table = render_cpp_rules()
    if options.write:
        HEADER.write_bytes(table.encode("utf-8"))
        return 0
    if options.check:
        current = HEADER.read_bytes().decode("utf-8") if HEADER.is_file() else ""
        if current != table:
            print(f"{HEADER.relative_to(ROOT)} is stale: run python tools/signature_rules.py --write")
            return 1
        return 0
    sys.stdout.write(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
