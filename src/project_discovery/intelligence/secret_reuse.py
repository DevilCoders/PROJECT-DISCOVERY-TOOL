"""Secret values found in more than one place (a code index pass).

With ``--fingerprint-key``, every secret finding carries a keyed fingerprint of its value
(core.fingerprints). The same fingerprint in two places is the same secret, so rotating it
means changing every one of them, and a leak of one exposes the others. The pass reports each
fingerprint seen in two or more places, with those places and never the value.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from ..models import Finding

MAX_FINGERPRINTS = 200
MAX_LOCATIONS = 50


def secret_reuse(context: Any) -> tuple[dict, list[Finding]]:
    places: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for name, path, detail in context.db.execute(
            "SELECT name, path, detail FROM code_facts WHERE kind = 'secret_fingerprint' ORDER BY name, path"):
        try:
            values = json.loads(detail)
        except ValueError:
            continue
        if len(places[name]) < 1000:
            places[name].append((path, int(values.get("line") or 0), str(values.get("pattern") or "")))
    repeated = sorted(((name, sorted(set(items))) for name, items in places.items() if len(set(items)) > 1),
                      key=lambda entry: (-len(entry[1]), entry[0]))
    findings = []
    for name, items in repeated[:MAX_FINGERPRINTS]:
        files = sorted({path for path, _, _ in items})
        findings.append(Finding(
            "security", f"Secret value repeated in {len(items):,} places",
            f"The same secret value (keyed fingerprint {name}) appears {len(items):,} times in {len(files):,} "
            "file(s). Rotating it means changing every place, and a leak of any one exposes the others. The "
            "fingerprint is keyed: it cannot be reversed or checked against a guessed value without the key.",
            confidence="INFERRED", analyzer="secret-reuse", severity="MEDIUM",
            evidence=[f"fingerprint: {name}", *(f"{path}:{line} ({pattern})" for path, line, pattern in items[:MAX_LOCATIONS])],
        ))
    return {"fingerprints": len(places), "repeated": len(repeated),
            "reported": min(len(repeated), MAX_FINGERPRINTS)}, findings
