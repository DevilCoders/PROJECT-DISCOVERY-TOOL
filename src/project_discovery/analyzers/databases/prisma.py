"""Prisma ORM schema inventory."""
from __future__ import annotations

import bisect
import re
from pathlib import Path

from ...core.source_utils import LineIndex, describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_HEADER = re.compile(r"(?m)^[ \t]*(model|enum|datasource|generator)[ \t]+([A-Za-z_][A-Za-z0-9_]*+)\s*\{")
_CLOSE = re.compile(r"(?m)^[ \t]*\}")


def _blocks(content: str):
    """(kind, name, body start, body end, header start) of each block, in linear time.

    A block ends at the first later line that starts with ``}``. The single regex
    ``^model X {(.*?)^}`` scanned to the end of the file from every unclosed header.
    """
    closes = [match.start() for match in _CLOSE.finditer(content)]
    position = 0
    for header in _HEADER.finditer(content):
        if header.start() < position:
            continue  # inside the previous block
        index = bisect.bisect_left(closes, header.end())
        if index == len(closes):
            break
        yield header.group(1), header.group(2), header.end(), closes[index], header.start()
        position = closes[index]
# Any indentation, tabs included.
_FIELD = re.compile(r"(?m)^[ \t]++([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[\])?(?:\?)?")
_PROVIDER = re.compile(r'(?m)^[ \t]*provider\s*=\s*"([^"]+)"')


class PrismaSchemaAnalyzer(Analyzer):
    """Extract Prisma models, enums, datasource providers and model relations."""

    name = "prisma-schema"
    domains = ("orm", "databases_sql",)

    def supports(self, record: FileRecord) -> bool:
        return record.extension == ".prisma" and record.error is None

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            content = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "database",
                f"Prisma schema read error: {record.path}",
                describe_error(exc),
                confidence="UNKNOWN", severity="LOW",
                evidence=[record.path],
                analyzer=self.name,
            )]

        blocks = list(_blocks(content))
        models = {name for kind, name, *_ in blocks if kind == "model"}
        lines = LineIndex(content)
        model_fields: dict[str, int] = {}
        relations: list[tuple[str, str, str, int]] = []
        evidence: list[str] = []
        enums = []
        for kind, name, body_start, body_end, start in blocks:
            line = lines.line(start)
            if kind == "model":
                fields = []
                for field_match in _FIELD.finditer(content, body_start, body_end):
                    field_name, field_type = field_match.groups()
                    fields.append((field_name, field_type))
                    if field_type in models and field_type != name:
                        relations.append((name, field_name, field_type, lines.line(field_match.start(1))))
                model_fields[name] = len(fields)
                evidence.append(f"{record.path}:{line} model {name} ({len(fields)} fields)")
            elif kind == "enum":
                enums.append(name)
                evidence.append(f"{record.path}:{line} enum {name}")
            else:
                evidence.append(f"{record.path}:{line} {kind} {name}")

        # Only a datasource's provider names a database (a generator's names a client).
        providers = [
            match.group(1)
            for kind, _, body_start, body_end, _ in blocks if kind == "datasource"
            for match in _PROVIDER.finditer(content, body_start, body_end)
        ]
        details = [
            f"{len(models)} models",
            f"{len(enums)} enums",
            f"{sum(model_fields.values())} model fields",
            f"{len(relations)} model relations",
        ]
        if providers:
            details.append("datasource providers: " + ", ".join(sorted(set(providers))))
        if not blocks:
            return [Finding(
                "database",
                f"Prisma schema contains no recognized blocks: {record.path}",
                "No model, enum, datasource or generator block was recognized.",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]
        evidence.extend(
            f"{record.path}:{line} relation {source}.{field} -> {target}"
            for source, field, target, line in relations
        )
        return [Finding(
            "database",
            f"Prisma ORM schema: {record.path}",
            "Detected " + "; ".join(details) + ". This is a source schema inventory, "
            "not proof of the deployed database state.",
            confidence="CONFIRMED",
            evidence=evidence[:200] or [record.path],
            analyzer=self.name,
        )]
