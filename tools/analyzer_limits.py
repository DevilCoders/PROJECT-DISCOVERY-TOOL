"""Generate the per-analyzer limit table in docs/architecture/ANALYZER_RESOURCE_BUDGETS.md.

    python tools/analyzer_limits.py            # print the table
    python tools/analyzer_limits.py --write    # rewrite it in the committed document
    python tools/analyzer_limits.py --check    # exit 1 when the document is stale

The table comes from the ``limits`` each built-in analyzer declares (core.limits), the
values the analyzers apply, so it is never edited by hand; tests/test_documentation.py
fails when it is out of date.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "architecture" / "ANALYZER_RESOURCE_BUDGETS.md"
BEGIN = "<!-- BEGIN GENERATED LIMITS: python tools/analyzer_limits.py --write -->"
END = "<!-- END GENERATED LIMITS -->"

try:
    import project_discovery  # noqa: F401
except ImportError:  # a checkout without an installed package
    sys.path.insert(0, str(ROOT / "src"))

from project_discovery.analyzers import builtin_analyzers  # noqa: E402
from project_discovery.analyzers.dependencies.vulnerabilities import LocalVulnerabilityAnalyzer  # noqa: E402
from project_discovery.core.limits import READS  # noqa: E402
from project_discovery.reporting.writers import cap_text, size_text  # noqa: E402


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def render_table() -> str:
    """The generated block: one row per built-in analyzer, then the read modes."""
    analyzers = [(item.name, item.limits) for item in builtin_analyzers()]
    analyzers.append((LocalVulnerabilityAnalyzer.name, LocalVulnerabilityAnalyzer.limits))
    lines = [
        BEGIN,
        "",
        "| Analyzer | Reads | Per-file budget | Other limits | At the limit |",
        "|---|---|---:|---|---|",
    ]
    for name, limits in sorted(analyzers):
        if limits is None:
            raise SystemExit(f"{name} declares no limits")
        budget = size_text(limits.file_bytes) if limits.file_bytes else "—"
        caps = "; ".join(cap_text(key, value) for key, value in limits.caps.items()) or "—"
        lines.append(f"| `{name}` | {limits.reads} | {budget} | {_cell(caps)} | {_cell(limits.outcome) or '—'} |")
    lines += ["", "Read modes:", ""]
    lines += [f"- `{mode}`: {text}." for mode, text in READS.items()]
    lines += ["", END]
    return "\n".join(lines)


def render(document: str) -> str:
    """The document with its generated block replaced."""
    start, end = document.find(BEGIN), document.find(END)
    if start < 0 or end < start:
        raise SystemExit(f"{DOCUMENT.relative_to(ROOT)} has no generated block ({BEGIN} ... {END})")
    return document[:start] + render_table() + document[end + len(END):]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="rewrite the committed document")
    group.add_argument("--check", action="store_true", help="exit 1 when the document is stale")
    args = parser.parse_args()
    current = DOCUMENT.read_bytes().decode("utf-8")
    text = render(current)
    if args.write:
        DOCUMENT.write_bytes(text.encode("utf-8"))
        return 0
    if args.check:
        if current != text:
            print(f"{DOCUMENT.relative_to(ROOT)} is stale: run python tools/analyzer_limits.py --write")
            return 1
        return 0
    print(render_table())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
