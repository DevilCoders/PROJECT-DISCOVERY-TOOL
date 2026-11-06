"""CVSS v2 and v3.x base-score calculation from vector strings.

OSV records carry severity as CVSS vectors rather than numbers. Scores are computed with
the published FIRST formulas; CVSS v4 vectors require the MacroVector lookup tables and are
reported as unscorable (None) rather than approximated.
"""
from __future__ import annotations

import math

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_V2_WEIGHTS = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}


def _metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        key, separator, value = part.partition(":")
        if separator:
            metrics[key] = value
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest one-decimal number >= value, float-error safe."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    metrics = _metrics(vector)
    if not metrics.get("CVSS", "").startswith("3"):
        return None
    try:
        scope = metrics["S"]
        weights = {key: _V3_WEIGHTS[key][metrics[key]] for key in _V3_WEIGHTS}
        privileges = _V3_PRIVILEGES[scope][metrics["PR"]]
    except KeyError:
        return None
    iss = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges * weights["UI"]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def cvss2_base_score(vector: str) -> float | None:
    metrics = _metrics(vector.removeprefix("(").removesuffix(")"))
    try:
        weights = {key: _V2_WEIGHTS[key][metrics[key]] for key in _V2_WEIGHTS}
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"]))
    exploitability = 20 * weights["AV"] * weights["AC"] * weights["Au"]
    factor = 0 if impact == 0 else 1.176
    return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * factor, 1)


def base_score(score_type: str, value: str | float | int) -> float | None:
    """Score an OSV severity entry; numeric scores pass through, vectors are computed."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    kind = score_type.upper()
    if kind == "CVSS_V3" or text.startswith("CVSS:3"):
        return cvss3_base_score(text)
    if kind == "CVSS_V2" or ("Au:" in text and "AV:" in text):
        return cvss2_base_score(text)
    return None


def qualitative_severity(score: float) -> str:
    """Map a CVSS base score onto PDT's severity scale (CVSS v3 qualitative bands)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"
