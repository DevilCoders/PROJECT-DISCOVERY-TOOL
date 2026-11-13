"""Static coverage artifact reader for common language ecosystems."""
from __future__ import annotations

import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ...core.limits import AnalyzerLimits, over_limit
from ...core.safe_parsers import safe_xml_fromstring
from ...core.source_utils import SourceBudgetExceeded, describe_error, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_MAX_COVERAGE_ARTIFACT_BYTES = 64 * 1024 * 1024


_COVERAGE_NAMES = {
    "coverage.xml", "cobertura.xml", "jacoco.xml", "clover.xml", "opencover.xml",
    "coverage.json", "coverage-final.json", "coverage-summary.json",
    "lcov.info", "coverage.lcov", "coverage.out",
}


def _ratio(covered: int, total: int) -> str:
    return "n/a" if total <= 0 else f"{covered}/{total} ({covered * 100.0 / total:.1f}%)"


def _format_summary(values: dict[str, tuple[int, int]]) -> str:
    return "; ".join(
        f"{name}: {_ratio(covered, total)}"
        for name, (covered, total) in values.items() if total or covered
    )


def _json_summary(data: Any, filename: str) -> dict[str, tuple[int, int]] | None:
    if not isinstance(data, dict):
        return None
    total = data.get("total")
    if isinstance(total, dict):
        result = {}
        for key in ("lines", "statements", "functions", "branches"):
            item = total.get(key)
            if isinstance(item, dict):
                covered, count = item.get("covered"), item.get("total")
                if isinstance(covered, (int, float)) and isinstance(count, (int, float)):
                    result[key] = (int(covered), int(count))
        if result:
            return result

    files = data.get("files")
    if isinstance(files, dict):
        totals = {"lines": [0, 0], "branches": [0, 0]}
        for item in files.values():
            summary = item.get("summary", {}) if isinstance(item, dict) else {}
            if not isinstance(summary, dict):
                continue
            for target, covered_key, total_key in (
                ("lines", "covered_lines", "num_statements"),
                ("branches", "covered_branches", "num_branches"),
            ):
                covered, count = summary.get(covered_key), summary.get(total_key)
                if isinstance(covered, (int, float)) and isinstance(count, (int, float)):
                    totals[target][0] += int(covered)
                    totals[target][1] += int(count)
        result = {key: (value[0], value[1]) for key, value in totals.items() if value[1]}
        if result:
            return result

    if filename == "coverage-final.json":
        totals = {"statements": [0, 0], "functions": [0, 0], "branches": [0, 0]}
        for item in data.values():
            if not isinstance(item, dict):
                continue
            for key, target in (("s", "statements"), ("f", "functions")):
                counters = item.get(key)
                if isinstance(counters, dict):
                    totals[target][1] += len(counters)
                    totals[target][0] += sum(
                        1 for value in counters.values()
                        if isinstance(value, (int, float)) and value > 0
                    )
            counters = item.get("b")
            if isinstance(counters, dict):
                for values in counters.values():
                    if isinstance(values, list):
                        totals["branches"][1] += len(values)
                        totals["branches"][0] += sum(
                            1 for value in values
                            if isinstance(value, (int, float)) and value > 0
                        )
        result = {key: (value[0], value[1]) for key, value in totals.items() if value[1]}
        return result or None
    return None


def _xml_summary(root: ET.Element) -> dict[str, tuple[int, int]] | None:
    tag = root.tag.rsplit("}", 1)[-1].lower()
    if tag == "coverage" and "lines-valid" in root.attrib:
        result = {
            "lines": (
                int(root.attrib.get("lines-covered", 0)),
                int(root.attrib.get("lines-valid", 0)),
            )
        }
        if "branches-valid" in root.attrib:
            result["branches"] = (
                int(root.attrib.get("branches-covered", 0)),
                int(root.attrib.get("branches-valid", 0)),
            )
        return result

    if tag == "report":
        counters = {}
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1].lower() == "counter":
                kind = element.attrib.get("type", "").upper()
                if kind in {"LINE", "BRANCH", "METHOD"}:
                    covered = int(element.attrib.get("covered", 0))
                    missed = int(element.attrib.get("missed", 0))
                    label = {"LINE": "lines", "BRANCH": "branches", "METHOD": "methods"}[kind]
                    counters[label] = (covered, covered + missed)  # the report's own counter comes last
        if counters:
            return counters

    # Clover: php-code-coverage writes <metrics> for every class and file before the
    # project's own, so the first <metrics> in document order is one class, not the project.
    project = root.find("project")
    if root.tag == "coverage" and project is not None:
        metrics = project.find("metrics")
        files = list(project.iter("file"))
        elements = [metrics] if metrics is not None else [
            item for item in (file.find("metrics") for file in files) if item is not None
        ]
        result: dict[str, tuple[int, int]] = {}
        for key, covered_key in (
            ("statements", "coveredstatements"),
            ("conditionals", "coveredconditionals"),
            ("methods", "coveredmethods"),
        ):
            total = sum(int(element.attrib.get(key, 0)) for element in elements)
            covered = sum(int(element.attrib.get(covered_key, 0)) for element in elements)
            if total:
                result[key] = (covered, total)
        if result:
            return result

    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1].lower()
        if local == "summary":
            result = {}
            total = int(element.attrib.get("numSequencePoints", 0))
            covered = int(element.attrib.get("visitedSequencePoints", 0))
            if total:
                result["lines"] = (covered, total)
            total = int(element.attrib.get("numBranchPoints", 0))
            covered = int(element.attrib.get("visitedBranchPoints", 0))
            if total:
                result["branches"] = (covered, total)
            total = int(element.attrib.get("numMethods", 0))
            covered = int(element.attrib.get("visitedMethods", 0))
            if total:
                result["methods"] = (covered, total)
            if result:
                return result
        if local == "metrics":
            result = {}
            for key, covered_key in (
                ("statements", "coveredstatements"),
                ("conditionals", "coveredconditionals"),
                ("methods", "coveredmethods"),
            ):
                total = int(element.attrib.get(key, 0))
                covered = int(element.attrib.get(covered_key, 0))
                if total:
                    result[key] = (covered, total)
            if result:
                return result
    return None


def _lcov_summary(source: str) -> dict[str, tuple[int, int]] | None:
    totals = {"lines": [0, 0], "branches": [0, 0], "functions": [0, 0]}
    for line in io.StringIO(source, newline=None):
        for prefix, key, index in (
            ("LF:", "lines", 1), ("LH:", "lines", 0),
            ("BRF:", "branches", 1), ("BRH:", "branches", 0),
            ("FNF:", "functions", 1), ("FNH:", "functions", 0),
        ):
            if line.startswith(prefix):
                totals[key][index] += int(line[len(prefix):])
                break
    result = {key: (value[0], value[1]) for key, value in totals.items() if value[1]}
    return result or None


def _go_profile_summary(source: str) -> dict[str, tuple[int, int]] | None:
    # go test -coverpkg lists a block once per test binary; a block counts once and is
    # covered when any binary ran it.
    blocks: dict[str, tuple[int, bool]] = {}
    pattern = re.compile(r"^(\S+:\d+\.\d+,\d+\.\d+)\s+(\d+)\s+(\d+)\s*$")
    for line in io.StringIO(source, newline=None):
        match = pattern.match(line.strip())
        if match:
            block, statements, count = match.group(1), int(match.group(2)), int(match.group(3))
            known = blocks.get(block)
            blocks[block] = (statements, count > 0 or (known is not None and known[1]))
    total = sum(statements for statements, _ in blocks.values())
    covered = sum(statements for statements, hit in blocks.values() if hit)
    return {"statements": (covered, total)} if total else None


class CoverageArtifactAnalyzer(Analyzer):
    """Read LCOV, Cobertura, JaCoCo, Clover, OpenCover, Go and Istanbul artifacts."""

    name = "coverage-artifacts"
    limits = AnalyzerLimits(
        _MAX_COVERAGE_ARTIFACT_BYTES,
        "whole",
        outcome="UNKNOWN finding on oversize, growth, read or parse failure",
    )
    domains = ("coverage",)
    languages = ("Python", "JavaScript", "TypeScript", "Go", "Java", "C#", "C/C++")

    def supports(self, record: FileRecord) -> bool:
        return record.error is None and (
            Path(record.path).name.lower() in _COVERAGE_NAMES
            or Path(record.path).suffix.lower() == ".lcov"
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        if over_limit(record.size_bytes, _MAX_COVERAGE_ARTIFACT_BYTES):
            return [Finding(
                "coverage", f"Coverage artifact resource limit: {record.path}",
                f"File size {record.size_bytes:,} bytes exceeds the coverage parser's "
                f"{_MAX_COVERAGE_ARTIFACT_BYTES:,}-byte content budget.",
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        try:
            source = read_text_bounded(
                path, _MAX_COVERAGE_ARTIFACT_BYTES,
                expected_identity=record.analysis_identity,
            )
            name = Path(record.path).name.lower()
            if name in {"lcov.info", "coverage.lcov"} or path.suffix.lower() == ".lcov":
                summary, format_name = _lcov_summary(source), "LCOV"
            elif name == "coverage.out":
                summary, format_name = _go_profile_summary(source), "Go cover profile"
            elif name.endswith(".json"):
                summary = _json_summary(json.loads(source), name)
                format_name = "Istanbul/coverage JSON"
            else:
                summary = _xml_summary(safe_xml_fromstring(source))
                format_name = "XML coverage report"
        except SourceBudgetExceeded as exc:
            return [Finding(
                "coverage", f"Coverage artifact resource limit: {record.path}", str(exc),
                confidence="UNKNOWN", evidence=[record.path],
                analyzer=self.name, severity="LOW",
            )]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ET.ParseError, ValueError, RecursionError, MemoryError) as exc:
            return [Finding(
                "coverage", f"Coverage report parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if not summary:
            return [Finding(
                "coverage", f"Unrecognized coverage report: {record.path}",
                "The artifact name was recognized, but no supported coverage counters "
                "could be extracted.",
                confidence="UNKNOWN", evidence=[record.path], analyzer=self.name, severity="LOW",
            )]
        return [Finding(
            "coverage", f"{format_name}: {record.path}",
            f"Parsed recorded coverage counters: {_format_summary(summary)}. These values "
            "describe the coverage artifact as generated; PDT does not verify the test run, "
            "source revision, instrumentation completeness or current code-to-test mapping.",
            confidence="CONFIRMED",
            evidence=[record.path] + [
                f"{name}: {covered}/{total}"
                for name, (covered, total) in summary.items()
            ],
            analyzer=self.name,
        )]
