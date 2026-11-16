"""Triage files: the operator's offline decisions about vulnerability findings.

``pdt scan --triage FILE`` reads a TOML file of decisions. Each ``[[decision]]`` names an
advisory ID or one of its aliases. It can narrow that to a package (and ecosystem), a version
and a lockfile. It states what was decided and why, and until when:

    [[decision]]
    advisory = "GHSA-35jh-r3h4-6jhm"      # or a CVE alias
    package = "lodash"                    # optional, with ecosystem = "npm" if needed
    version = "4.17.20"                   # optional
    lockfile = "web/package-lock.json"    # optional
    status = "accepted"                   # accepted, false_positive or mitigated
    reason = "Templates are constants; no request data reaches _.template."
    expires = 2027-01-31                  # required for accepted risks
    reviewer = "appsec"                   # optional

An active decision turns the findings it matches into INFO findings. They keep their evidence
and carry the decision, its rationale and its expiry. A decision that has expired leaves the
finding as it was and says the decision lapsed. The most specific decision wins: lockfile,
then package and version, then package, then the advisory alone.
"""
from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .database import normalize_package_name
from .versions import compare_versions

MAX_TRIAGE_BYTES = 8 * 1024 * 1024
MAX_DECISIONS = 100_000
STATUSES = {"accepted": "Accepted risk", "false_positive": "False positive", "mitigated": "Mitigated"}
_TEXT_LIMIT = 500


@dataclass(frozen=True, slots=True)
class TriageDecision:
    key: str  # "file.toml#3": where the decision is, for the report
    advisory: str
    status: str
    reason: str
    expires: date | None = None
    ecosystem: str = ""
    package: str = ""
    version: str = ""
    lockfile: str = ""
    reviewer: str = ""

    def expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today


@dataclass(frozen=True, slots=True)
class TriageDecisions:
    decisions: tuple[TriageDecision, ...]
    names: tuple[str, ...]
    today: date
    sha256: str  # of the files and the date (expiry depends on it): --resume compares it

    def describe(self) -> dict[str, Any]:
        expired = sum(decision.expired(self.today) for decision in self.decisions)
        return {"documents": list(self.names), "decisions": len(self.decisions), "expired": expired,
                "as_of": self.today.isoformat(), "sha256": self.sha256}


def _text(value: Any, field: str, where: str, *, required: bool = False) -> str:
    if value is None or value == "":
        if required:
            raise ValueError(f"{where}: {field} is required")
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{where}: {field} must be a string")
    text = " ".join("".join(char if char.isprintable() else " " for char in value).split())
    return text[:_TEXT_LIMIT]


def _expiry(value: Any, where: str) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ValueError(f"{where}: expires must be a date (YYYY-MM-DD)") from exc
    raise ValueError(f"{where}: expires must be a date (YYYY-MM-DD)")


def parse_triage(document: dict[str, Any], source: str) -> list[TriageDecision]:
    """The decisions of a parsed triage file; ValueError names the entry at fault."""
    entries = document.get("decision")
    if not isinstance(entries, list):
        raise ValueError(f"{source}: no [[decision]] entries")
    decisions = []
    for index, entry in enumerate(entries, 1):
        where = f"{source}: decision {index}"
        if not isinstance(entry, dict):
            raise ValueError(f"{where}: not a table")
        unknown = set(entry) - {"advisory", "ecosystem", "package", "version", "lockfile", "status", "reason",
                                "expires", "reviewer"}
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
        status = _text(entry.get("status"), "status", where, required=True)
        if status not in STATUSES:
            raise ValueError(f"{where}: status must be one of {', '.join(STATUSES)}")
        expires = _expiry(entry.get("expires"), where)
        if status == "accepted" and expires is None:
            raise ValueError(f"{where}: an accepted risk needs an expires date")
        decisions.append(TriageDecision(
            key=f"{source}#{index}", advisory=_text(entry.get("advisory"), "advisory", where, required=True).upper(),
            status=status, reason=_text(entry.get("reason"), "reason", where, required=True), expires=expires,
            ecosystem=_text(entry.get("ecosystem"), "ecosystem", where),
            package=_text(entry.get("package"), "package", where),
            version=_text(entry.get("version"), "version", where),
            lockfile=_text(entry.get("lockfile"), "lockfile", where).replace("\\", "/").removeprefix("./"),
            reviewer=_text(entry.get("reviewer"), "reviewer", where),
        ))
    return decisions


def load_triage(paths: Iterable[Path], *, today: date | None = None) -> TriageDecisions:
    """Read triage files; ValueError names a file or decision that is not valid."""
    today = today or datetime.now(timezone.utc).date()
    decisions: list[TriageDecision] = []
    names: list[str] = []
    digest = hashlib.sha256(today.isoformat().encode())
    for path in paths:
        path = Path(path).expanduser()
        try:
            if path.stat().st_size > MAX_TRIAGE_BYTES:
                raise ValueError(f"--triage {path}: larger than {MAX_TRIAGE_BYTES // (1024 * 1024)} MiB")
            data = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"--triage {path}: {exc.strerror or exc}") from exc
        digest.update(hashlib.sha256(data).digest())
        try:
            document = tomllib.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"--triage {path}: not a TOML file ({exc})") from exc
        decisions += parse_triage(document, path.name)
        names.append(path.name)
        if len(decisions) > MAX_DECISIONS:
            raise ValueError(f"--triage: more than {MAX_DECISIONS:,} decisions")
    return TriageDecisions(tuple(decisions), tuple(names), today, digest.hexdigest())


def triage_decision(decisions: Iterable[TriageDecision], identifiers: Iterable[str], ecosystem: str, name: str,
                    version: str, lockfile: str) -> TriageDecision | None:
    """The decision that applies to a finding: about one of its advisory IDs or aliases and
    about its lockfile, package and version (the most specific wins; on a tie, the later one)."""
    wanted = {identifier.upper() for identifier in identifiers}
    base = ecosystem.partition(":")[0].casefold()
    best: tuple[int, TriageDecision] | None = None
    for decision in decisions:
        if decision.advisory not in wanted:
            continue
        rank = 0
        if decision.ecosystem:
            if decision.ecosystem.partition(":")[0].casefold() != base:
                continue
        if decision.package:
            if normalize_package_name(ecosystem, decision.package) != normalize_package_name(ecosystem, name):
                continue
            rank += 2
        if decision.version:
            if decision.version != version and compare_versions(decision.version, version, ecosystem) != 0:
                continue
            rank += 1
        if decision.lockfile:
            if decision.lockfile != lockfile.replace("\\", "/"):
                continue
            rank += 4
        if best is None or rank >= best[0]:
            best = (rank, decision)
    return best[1] if best else None
