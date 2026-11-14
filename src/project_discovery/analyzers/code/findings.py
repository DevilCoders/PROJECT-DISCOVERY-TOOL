"""Shared helpers for analyzers built on the code model."""
from __future__ import annotations

import bisect
import re

from ...intelligence.model import FileModel
from ...models import CodeEvidence, Finding

MAX_LOCATIONS = 25
MAX_CODE_LINES = 5
_LOOP_KEYWORD = re.compile(r"(?<![\w$.])(for|while|foreach|loop)\b")
_RUST_IMPL = re.compile(r"(?<![\w$])impl\b")


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
    from ...intelligence.model.lexical import LEXICAL_LANGUAGES, _body_after, _statement_prefix

    clean, braces, parens = model.clean, model.braces, model.parens
    rust = LEXICAL_LANGUAGES.get(model.language) == "rust"
    bodies = []
    for match in _LOOP_KEYWORD.finditer(clean):
        position = match.end()
        following = clean[position:position + 50].lstrip()
        if rust and match.group(1) == "for" and (
            following.startswith("<") or _RUST_IMPL.search(_statement_prefix(clean, match.start()))
        ):
            continue  # ``impl Trait for Type {`` and ``for<'a>`` bounds are not loops
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
    """[start, end) intervals (loop bodies, lock regions) answering containment by offset."""

    def __init__(self, intervals: list[tuple[int, int]]) -> None:
        self.intervals = sorted(intervals)
        # The union of the open intervals (start, end), merged where they overlap: one
        # binary search answers containment. Walking back through every earlier interval
        # cost O(loops) per call, minutes on large generated sources.
        merged: list[list[int]] = []
        for start, end in self.intervals:
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self._starts = [start for start, _ in merged]
        self._ends = [end for _, end in merged]

    def contains(self, offset: int) -> bool:
        """Whether ``offset`` lies strictly inside one of the intervals."""
        index = bisect.bisect_left(self._starts, offset) - 1
        return index >= 0 and offset < self._ends[index]

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
