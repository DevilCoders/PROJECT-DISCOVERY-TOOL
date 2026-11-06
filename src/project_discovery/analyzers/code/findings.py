"""Shared helpers for analyzers built on the code model."""
from __future__ import annotations

import bisect
import re

from ...intelligence.model import FileModel
from ...models import CodeEvidence, Finding

MAX_LOCATIONS = 25
MAX_CODE_LINES = 5
_LOOP_KEYWORD = re.compile(r"(?<![\w$.])(for|while|foreach|loop)\b")


def code_finding(
    model: FileModel, category: str, title: str, detail: str, lines, *, analyzer: str,
    severity: str = "LOW", confidence: str = "INFERRED", impact: str | None = None,
    recommendation: str | None = None,
) -> Finding:
    """One finding per file and issue kind, listing every location (bounded)."""
    lines = sorted(set(lines))
    if len(lines) > MAX_LOCATIONS:
        detail += f" {len(lines):,} locations; the first {MAX_LOCATIONS} are listed."
    return Finding(
        category, f"{title}: {model.path}", detail, confidence=confidence,
        evidence=[f"{model.path}:{line}" for line in lines[:MAX_LOCATIONS]],
        analyzer=analyzer, severity=severity,
        code_evidence=[CodeEvidence(line, model.line_text(line)) for line in lines[:MAX_CODE_LINES]],
        impact=impact, recommendation=recommendation,
    )


def loop_bodies(model: FileModel) -> list[tuple[int, int]]:
    """[start, end) brace bodies of for/while/foreach/loop statements in a lexical model."""
    from ...intelligence.model.lexical import _body_after

    clean, braces, parens = model.clean, model.braces, model.parens
    bodies = []
    for match in _LOOP_KEYWORD.finditer(clean):
        position = match.end()
        following = clean[position:position + 50].lstrip()
        if following.startswith("("):
            paren = clean.find("(", position)
            close = parens.get(paren)
            if close is None:
                continue
            body = _body_after(clean, close + 1, braces)
        else:
            # Go/Rust/Swift loops have no parentheses (Go's ``for i := 0; i < n; i++ {``
            # even has semicolons); their body opens on the same line.
            line_end = clean.find("\n", position)
            brace = clean.find("{", position, line_end if line_end != -1 else len(clean))
            body = (brace, braces[brace]) if brace != -1 and brace in braces else None
        if body is not None:
            bodies.append(body)
    return sorted(set(bodies))


class Intervals:
    """Nested [start, end) intervals answering depth and containment by offset."""

    def __init__(self, intervals: list[tuple[int, int]]) -> None:
        self.intervals = sorted(intervals)
        self.starts = [start for start, _ in self.intervals]

    def depth(self, offset: int) -> int:
        index = bisect.bisect_right(self.starts, offset)
        return sum(1 for start, end in self.intervals[:index] if start < offset < end)

    def contains(self, offset: int) -> bool:
        index = bisect.bisect_right(self.starts, offset) - 1
        while index >= 0:
            start, end = self.intervals[index]
            if start < offset < end:
                return True
            index -= 1
        return False

    def deepest(self) -> list[tuple[int, int, int]]:
        """(start, end, depth) for every interval, depth 1 for outermost."""
        stack: list[int] = []
        result = []
        for start, end in self.intervals:
            while stack and stack[-1] <= start:
                stack.pop()
            stack.append(end)
            result.append((start, end, len(stack)))
        return result
