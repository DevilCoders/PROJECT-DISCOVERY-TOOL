"""Shared, serialization-friendly domain models."""
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Confidence = Literal["CONFIRMED", "INFERRED", "UNKNOWN"]

@dataclass(slots=True)
class Finding:
    category: str
    title: str
    detail: str
    confidence: Confidence = "CONFIRMED"
    evidence: list[str] = field(default_factory=list)
    analyzer: str = "core"
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class FileRecord:
    path: str
    size_bytes: int
    extension: str
    language: str
    sha256: str | None = None
    analyzed: bool = False
    error: str | None = None
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class ScanResult:
    root: str
    started_at: str
    finished_at: str
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    analyzer_names: list[str] = field(default_factory=list)
    def to_dict(self) -> dict[str, Any]:
        return {"schema_version":"1.0","root":self.root,"started_at":self.started_at,
                "finished_at":self.finished_at,"files":[x.to_dict() for x in self.files],
                "findings":[x.to_dict() for x in self.findings],"metrics":self.metrics,
                "errors":self.errors,"analyzers":self.analyzer_names}
