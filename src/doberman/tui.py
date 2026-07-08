"""Decision-transparency TUI: browse the redacted decision log with a "why" panel.

A small Textual app over :func:`doberman.explain.explain_decision`. It reads
only the already-redacted rows from :func:`doberman.storage.log.read_decisions`
and displays exactly those values - it never opens a raw file, a raw payload,
or any data source beyond that redacted row.

Row-derived strings (and any LLM narrator output) are always rendered as plain
text — table cells go through :class:`rich.text.Text` and the explanation panel
has Rich markup disabled — so a crafted value like ``[red]PASS[/]`` in a stored
row can never restyle or spoof what this browser shows.

The deterministic template explanation renders immediately (it is pure/fast);
an optional Claude-Haiku enrichment (opt-in, see ``doberman.explain``) then
runs debounced in a background thread worker so a slow/network LLM call (up to
a 10s timeout) can never freeze the UI, and skimming rows cannot fire one
request per keypress. Enriched text is cached per ``action_id`` (rows are
immutable history), so a row is narrated at most once per app run.

This module is only ever imported lazily from the ``tui`` CLI command (never
at module scope elsewhere), so `import doberman` and the rest of the CLI keep
working with ``textual`` not installed. It must never import ``doberman.proxy``
(policy-core decoupling, see CLAUDE.md §9 / import-linter).
"""

from __future__ import annotations

import json

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Static
from textual.worker import get_current_worker

from doberman.explain import explain_decision, template_explanation
from doberman.storage.log import read_decisions

_EMPTY_PLACEHOLDER = "(no decisions recorded yet)"
_COLUMNS = ("ts", "verdict", "action_type", "target_path_class", "reason codes")
#: Debounce before the (possibly network-bound) enrichment worker starts, so
#: holding an arrow key skims rows without firing a request per keypress.
_EXPLAIN_DEBOUNCE_S = 0.3


def _reason_codes_text(row: dict) -> str:
    try:
        codes = json.loads(row.get("reason_codes_json") or "[]")
    except (TypeError, ValueError):
        codes = []
    if not isinstance(codes, list) or not codes:
        return "-"
    # str() each item: a tampered/corrupt row (e.g. `[1]` or `[{}]`) must render
    # as junk text, never crash the browser.
    return ", ".join(str(code) for code in codes)


def _row_key(row: dict) -> str:
    return str(row.get("action_id") or id(row))


class DecisionExplainerApp(App[None]):
    """Browse the redacted decision log; show `explain_decision` for the selected row."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "reload", "Reload"),
    ]

    CSS = """
    #decisions {
        height: 2fr;
    }
    #explanation {
        height: 1fr;
        border: solid $accent;
        padding: 1;
    }
    """

    def __init__(self, repo_root: str) -> None:
        super().__init__()
        self._repo_root = repo_root
        self._rows: list[dict] = []
        self._current_key: str | None = None
        self._explain_cache: dict[str, str] = {}
        self._explain_timer = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield DataTable(id="decisions")
            # markup=False: the "why" text embeds row-derived strings — render
            # them literally, never as Rich markup.
            yield Static(_EMPTY_PLACEHOLDER, id="explanation", markup=False)
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#decisions", DataTable)
        table.add_columns(*_COLUMNS)
        table.cursor_type = "row"
        await self._load_rows()

    async def action_reload(self) -> None:
        await self._load_rows()

    async def _load_rows(self) -> None:
        # The app already runs inside Textual's event loop - await directly (asyncio.run
        # here would raise "cannot be called from a running event loop").
        self._rows = await read_decisions(self._repo_root)
        table = self.query_one("#decisions", DataTable)
        table.clear()
        explanation = self.query_one("#explanation", Static)
        if not self._rows:
            self._current_key = None
            explanation.update(_EMPTY_PLACEHOLDER)
            return
        for row in self._rows:
            # Text() cells render literally — no Rich-markup interpretation of
            # row-derived strings.
            table.add_row(
                Text(str(row.get("ts") or "-")),
                Text(str(row.get("final_verdict") or "-")),
                Text(str(row.get("action_type") or "-")),
                Text(str(row.get("target_path_class") or "-")),
                Text(_reason_codes_text(row)),
            )
        table.move_cursor(row=0)
        self._show_explanation(0)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row is None:
            return
        self._show_explanation(event.cursor_row)

    def _show_explanation(self, index: int) -> None:
        if index < 0 or index >= len(self._rows):
            return
        row = self._rows[index]
        key = _row_key(row)
        self._current_key = key
        panel = self.query_one("#explanation", Static)
        cached = self._explain_cache.get(key)
        if cached is not None:
            panel.update(cached)
            return
        # Show the fast deterministic template immediately; the debounced worker
        # below may upgrade it in place if opt-in LLM enrichment is enabled.
        panel.update(template_explanation(row))
        if self._explain_timer is not None:
            self._explain_timer.stop()
        self._explain_timer = self.set_timer(_EXPLAIN_DEBOUNCE_S, lambda: self._explain_worker(row))

    @work(thread=True, exclusive=True, group="explain")
    def _explain_worker(self, row: dict) -> None:
        worker = get_current_worker()
        key = _row_key(row)
        try:
            text = explain_decision(row)
        except Exception:  # noqa: BLE001 — the TUI must never crash on a narrator failure
            return
        if worker.is_cancelled:
            return

        def _apply() -> None:
            # Runs on the UI thread: re-check the selection so a slow (opt-in)
            # LLM call can never overwrite a newer row's panel with stale text.
            self._explain_cache[key] = text
            if self._current_key == key:
                self.query_one("#explanation", Static).update(text)

        try:
            self.call_from_thread(_apply)
        except Exception:  # noqa: BLE001, S110 — app may have exited mid-flight; never crash on it
            return


def run_tui(repo_root: str) -> None:
    """Launch the decision-transparency TUI. Entry point for `doberman tui`."""
    DecisionExplainerApp(repo_root).run()
