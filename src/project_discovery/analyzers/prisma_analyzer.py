"""Prisma ORM schema inventory."""
from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..models import FileRecord, Finding
from ..source_utils import read_text_bounded


_BLOCK = re.compile(
    r"(?ms)^\s*(model|enum|datasource|generator)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)^\s*\}"
)
_FIELD = re.compile(r"(?m)^\s{2,}([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[\])?(?:\?)?")
_PROVIDER = re.compile(r'(?m)^\s*provider\s*=\s*"([^"]+)"')


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
                f"{type(exc).__name__}: {exc}",
                confidence="UNKNOWN",
                evidence=[record.path],
                analyzer=self.name,
            )]

        blocks = list(_BLOCK.finditer(content))
        models = {match.group(2) for match in blocks if match.group(1) == "model"}
        model_fields: dict[str, int] = {}
        relations: list[tuple[str, str, str, int]] = []
        evidence: list[str] = []
        enums = []
        for match in blocks:
            kind, name, body = match.groups()
            line = content.count("\n", 0, match.start()) + 1
            if kind == "model":
                fields = []
                for field_match in _FIELD.finditer(body):
                    field_name, field_type = field_match.groups()
                    fields.append((field_name, field_type))
                    if field_type in models and field_type != name:
                        field_line = line + body.count("\n", 0, field_match.start()) + 1
                        relations.append((name, field_name, field_type, field_line))
                model_fields[name] = len(fields)
                evidence.append(f"{record.path}:{line} model {name} ({len(fields)} fields)")
            elif kind == "enum":
                enums.append(name)
                evidence.append(f"{record.path}:{line} enum {name}")
            else:
                evidence.append(f"{record.path}:{line} {kind} {name}")

        providers = _PROVIDER.findall(content)
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
