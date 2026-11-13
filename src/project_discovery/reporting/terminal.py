"""The live scan display: one row per scan phase, drawn from the scan's ScanProgress.

On a terminal it redraws in place a few times a second; redirected to a file or a pipe it
prints the final rows once, when it stops, with no control sequences. Paths never appear
in it, only counts, so nothing a scanned tree contains reaches the terminal through it.
"""
from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.live import Live
from rich.progress_bar import ProgressBar
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from ..engine.progress import ScanProgress
from .writers import duration_text, phase_text, size_text

_STATE_STYLES = {"done": "green", "skipped": "dim", "waiting": "dim", "running": "cyan"}


class PhaseDisplay:
    """A Rich Live view of a ScanProgress, started and stopped around the scan's phases."""

    def __init__(self, console: Console, progress: ScanProgress, *, refresh_per_second: float = 4) -> None:
        self._console = console
        self._progress = progress
        self._refresh = refresh_per_second
        self._live: Live | None = None
        self._spinner = Spinner("dots", style="cyan")

    def start(self) -> None:
        if self._live is None and not self._console.quiet:
            self._live = Live(console=self._console, get_renderable=self.render,
                              refresh_per_second=self._refresh, transient=False)
            self._live.start()

    def stop(self) -> None:
        """Draw the final rows and stop; a second call does nothing."""
        live, self._live = self._live, None
        if live is not None:
            live.stop()

    def __enter__(self) -> PhaseDisplay:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    def render(self) -> Table:
        table = Table.grid(padding=(0, 1))
        table.add_column(no_wrap=True)  # state
        table.add_column(no_wrap=True)  # phase
        table.add_column()  # progress bar and what the phase has done
        table.add_column(justify="right", no_wrap=True)  # time
        for item in self._progress.snapshot():
            state = item["state"]
            mark = self._spinner if state == "running" else Text(
                {"done": "done", "skipped": "skip"}.get(state, "...."), style=_STATE_STYLES[state])
            detail: Table | Text = Text(self._detail(item), style=_STATE_STYLES[state])
            total = item.get("total")
            if item["phase"] in {"analysis", "archives"} and total and state in {"running", "done"}:
                cell = Table.grid(padding=(0, 1))
                cell.add_column(no_wrap=True)
                cell.add_column()
                cell.add_row(ProgressBar(total=total, completed=min(item["done"], total), width=16), detail)
                detail = cell
            table.add_row(mark, Text(item["label"], style="bold" if state == "running" else ""), detail,
                          Text(duration_text(item["seconds"] if state != "running" else item.get("elapsed"))))
        return table

    @staticmethod
    def _detail(item: dict[str, Any]) -> str:
        state = item["state"]
        if state == "waiting":
            return "waiting"
        text = phase_text(item)
        if state != "running":
            return text
        elapsed = item.get("elapsed") or 0
        if item["phase"] == "hashing" and elapsed >= 1 and item.get("bytes"):
            text += f" ({size_text(item['bytes'] / elapsed)}/s)"
        total, done = item.get("total"), item["done"]
        if item["phase"] == "analysis" and total and 0 < done < total and elapsed >= 2:
            text += f" (about {duration_text(elapsed * (total - done) / done)} left)"
        if item.get("current_step"):
            text += f" (now: {item['current_step'].replace('_', ' ')})"
        return text
