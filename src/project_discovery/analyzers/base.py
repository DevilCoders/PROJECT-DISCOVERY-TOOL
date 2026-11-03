"""Public analyzer plugin contract."""
from abc import ABC, abstractmethod
from pathlib import Path
from ..models import FileRecord, Finding

class Analyzer(ABC):
    name = "unnamed"
    @abstractmethod
    def supports(self, record: FileRecord) -> bool: ...
    @abstractmethod
    def analyze(self, path: Path, record: FileRecord) -> list[Finding]: ...
