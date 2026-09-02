"""Decision-transparency TUI: browse the redacted decision log with a "why" panel.

A small Textual app over :func:`doberman.explain.explain_decision_with_source`. It
reads only the already-redacted rows from :func:`doberman.storage.log.read_decisions`
and displays exactly those values - it never opens a raw file, a raw payload, or
any data source beyond that redacted row.

Row-derived strings (and any LLM narrator output) are always rendered as plain
text — table cells go through :class:`rich.text.Text` and every panel/screen has
Rich markup disabled — so a crafted value like ``[red]PASS[/]`` in a stored row
can never restyle or spoof what this browser shows. Verdict colors come from the
single shared palette in :mod:`doberman.render` (``verdict_rich_style``), never a
private copy, so this browser and ``doberman log`` can never drift apart. Every
cell/panel string this module renders is ASCII-only (the CLI must stay
cp1252-safe on Windows) — verdict glyphs, the target-class ellipsis, and every
literal string here avoid non-ASCII punctuation on purpose.

The load is bounded (``--last``, default 500) and runs in a background async
worker so a large decision log can never freeze the first paint; a
``LoadingIndicator`` covers the gap. The deterministic template explanation
renders immediately (it is pure/fast); an optional Claude-Haiku enrichment
(opt-in, see ``doberman.explain``) then runs debounced in a background thread
worker so a slow/network LLM call (up to a 10s timeout) can never freeze the UI,
and skimming rows cannot fire one request per keypress. Enriched text is cached
per ``action_id`` (rows are immutable history), so a row is narrated at most once
per app run.

This module is only ever imported lazily from the ``tui`` CLI command (never at
module scope elsewhere), so `import doberman` and the rest of the CLI keep
working with ``textual`` not installed. It must never import ``doberman.proxy``
(policy-core decoupling, see CLAUDE.md §9 / import-linter).
"""

from __future__ import annotations

import json
from datetime import datetime

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, LoadingIndicator, Static
from textual.worker import Worker, get_current_worker

import doberman.render as render
from doberman.explain import (
    explain_decision_with_source,
    llm_enrichment_enabled,
    template_explanation,
)
from doberman.models import Verdict
from doberman.storage.db import db_path
from doberman.storage.log import read_decisions

#: Column order + header labels, all plain words (never the raw schema name).
_HEADERS: tuple[str, ...] = ("verdict", "time", "risk", "auth", "action", "target", "why")
#: Fixed content width per column, sized so the whole table fits an 80-column
#: terminal without horizontal scroll (undiscoverable at 80x24 - see the design
#: critique). Target class and reason codes ("why") are the two columns this
#: browser is willing to shorten with a trailing "..."; the full value for both
#: always remains reachable in the why panel / full-screen why screen.
_WIDTHS: dict[str, int] = {
    "verdict": 7,
    "time": 8,
    "risk": 8,
    "auth": 9,
    "action": 12,
    "target": 12,
    "why": 8,
}
#: ASCII-only verdict glyphs (no Unicode - the CLI must stay cp1252-safe on
#: Windows). The glyph alone carries meaning even if color is unavailable.
_VERDICT_GLYPHS: dict[str, str] = {"BLOCK": "X", "AUTH": "?", "PASS": "."}

_MSG_NO_ROWS = "Doberman is running here but hasn't decided anything yet."
_MSG_NO_MATCH = "(no rows match the filter)"

#: Provenance stamps for the top of the why panel (ADR-style honesty about
#: where the text came from - never silently upgrade/replace without saying so).
_PROV_TEMPLATE = "source: offline template"
_PROV_LLM = "source: LLM narration (metadata only)"
_PROV_PENDING = "narrating..."
_PROV_FALLBACK = "LLM unavailable - showing template"

#: Debounce before the (possibly network-bound) enrichment worker starts, so
#: holding an arrow key skims rows without firing a request per keypress.
_EXPLAIN_DEBOUNCE_S = 0.3


def _truncate(text: str, width: int) -> str:
    """Shorten ``text`` to ``width`` with a trailing "...", never silently longer.

    ASCII-only ellipsis (three periods, not U+2026) - see the module docstring.
    """
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _parse_ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _time_cell(row: dict) -> str:
    ts = _parse_ts(row.get("ts"))
    return ts.strftime("%H:%M:%S") if ts else "-"


def _date_str(row: dict) -> str:
    ts = _parse_ts(row.get("ts"))
    return ts.strftime("%Y-%m-%d") if ts else ""


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


def _verdict_cell(verdict_str: str) -> Text:
    glyph = _VERDICT_GLYPHS.get(verdict_str, "?")
    label = _truncate(f"{glyph} {verdict_str}", _WIDTHS["verdict"])
    try:
        style = render.verdict_rich_style(Verdict(verdict_str))
    except ValueError:
        style = ""  # corrupt/future verdict value: render plain, never crash
    return Text(label, style=style)


def _row_cells(row: dict) -> tuple[Text, ...]:
    verdict_str = str(row.get("final_verdict") or "-")
    return (
        _verdict_cell(verdict_str),
        Text(_time_cell(row)),
        Text(_truncate(str(row.get("risk") or "-"), _WIDTHS["risk"])),
        Text(_truncate(str(row.get("auth_result") or "-"), _WIDTHS["auth"])),
        Text(_truncate(str(row.get("action_type") or "-"), _WIDTHS["action"])),
        Text(_truncate(str(row.get("target_path_class") or "-"), _WIDTHS["target"])),
        Text(_truncate(_reason_codes_text(row), _WIDTHS["why"])),
    )


class _DecisionTable(DataTable):
    """A `DataTable` whose Home/End jump to the first/last row.

    The base class's Home/End only move the *horizontal* viewport for a
    ``cursor_type="row"`` table (there is no "leftmost column" to seek to when
    there's only a row cursor) - not useful for browsing hundreds of rows. This
    override jumps the cursor instead, and un-hides the two bindings (the base
    class ships them with ``show=False``) so they earn a spot in the footer.
    """

    BINDINGS = [
        Binding("home", "scroll_home", "first", show=True),
        Binding("end", "scroll_end", "last", show=True),
    ]

    def action_scroll_home(self) -> None:
        if self.cursor_type == "row" and self.row_count:
            self.move_cursor(row=0)
        else:
            super().action_scroll_home()

    def action_scroll_end(self) -> None:
        if self.cursor_type == "row" and self.row_count:
            self.move_cursor(row=self.row_count - 1)
        else:
            super().action_scroll_end()


class WhyScreen(Screen[None]):
    """Full-screen "why": the complete explanation, every reason code, the action id."""

    BINDINGS = [
        Binding("escape", "close", "close"),
        Binding("q", "close", "close", show=False),
    ]

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="why-scroll"):
            yield Static(self._text, id="why-text", markup=False)
        yield Footer()

    def action_close(self) -> None:
        self.app.pop_screen()


class HelpScreen(Screen[None]):
    """`?`: every keybinding this app has, in plain words."""

    BINDINGS = [
        Binding("escape", "close", "close"),
        Binding("q", "close", "close", show=False),
    ]

    _TEXT = (
        "Doberman decision log - keyboard reference\n"
        "\n"
        "q            quit\n"
        "r            reload\n"
        "?            this help screen\n"
        "/            filter rows (substring match on verdict, target, reason codes)\n"
        "escape       clear the filter, or close this screen / the why screen\n"
        "tab          move focus between the table and the why panel\n"
        "enter, w     open the full-screen why panel for the selected row\n"
        "b            jump to the next BLOCK\n"
        "B            jump to the previous BLOCK\n"
        "a            jump to the next AUTH\n"
        "y            copy the selected action id to the clipboard\n"
        "home         jump to the first row\n"
        "end          jump to the last row\n"
    )

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="help-scroll"):
            yield Static(self._TEXT, id="help-text", markup=False)
        yield Footer()

    def action_close(self) -> None:
        self.app.pop_screen()


class DecisionExplainerApp(App[None]):
    """Browse the redacted decision log; show `explain_decision` for the selected row."""

    TITLE = "Doberman decision log"

    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("r", "reload", "reload"),
        Binding("question_mark", "help", "help"),
        Binding("/", "filter", "filter"),
        Binding("escape", "clear_filter", "clear filter", show=False),
        Binding("b", "next_block", "next BLOCK"),
        Binding("B", "prev_block", "prev BLOCK"),
        Binding("a", "next_auth", "next AUTH"),
        Binding("y", "copy_action_id", "copy id"),
        Binding("w", "open_why", "why"),
        Binding("enter", "open_why", "why", show=False),
    ]

    CSS = """
    #date-bar {
        height: 1;
        color: $text-muted;
        padding: 0 1;
    }
    #loading {
        height: 1;
    }
    #decisions {
        height: 2fr;
    }
    #filter {
        dock: bottom;
    }
    #explanation-scroll {
        height: 1fr;
        border: solid $accent;
    }
    #explanation {
        padding: 1;
    }
    """

    def __init__(self, repo_root: str, *, last: int = 500) -> None:
        super().__init__()
        self._repo_root = repo_root
        self._last = max(0, last)
        self._rows: list[dict] = []
        self._visible_rows: list[dict] = []
        self._current_key: str | None = None
        self._explain_cache: dict[str, str] = {}
        self._explain_timer = None
        self._load_worker: Worker[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="date-bar")
        yield LoadingIndicator(id="loading")
        with Vertical():
            yield _DecisionTable(
                id="decisions", cursor_type="row", cursor_foreground_priority="renderable"
            )
            yield Input(placeholder="filter (verdict / target / reason codes)", id="filter")
            # markup=False: the "why" text embeds row-derived strings - render
            # them literally, never as Rich markup.
            with VerticalScroll(id="explanation-scroll"):
                yield Static("", id="explanation", markup=False)
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#decisions", _DecisionTable)
        for header in _HEADERS:
            table.add_column(header, width=_WIDTHS[header], key=header)
        self.query_one("#filter", Input).display = False
        self.query_one("#loading", LoadingIndicator).display = False
        self._update_subtitle()
        self._load_worker = self._load_rows()

    async def wait_loaded(self) -> None:
        """Test helper: wait for the current (or most recently started) load."""
        if self._load_worker is not None:
            await self._load_worker.wait()

    # --- loading -----------------------------------------------------------

    @work(exclusive=True)
    async def _load_rows(self) -> None:
        loading = self.query_one("#loading", LoadingIndicator)
        loading.display = True
        try:
            path = db_path(self._repo_root)
            if not path.exists():
                self._rows = []
                self._reset_to_empty(
                    f"No decision log at {path}. Run Doberman here first, or pass --path."
                )
                return
            rows = await read_decisions(self._repo_root, limit=self._last)
            self._rows = rows
            if not rows:
                self._reset_to_empty(_MSG_NO_ROWS)
                return
            self._apply_filter()
        finally:
            loading.display = False

    def _reset_to_empty(self, message: str) -> None:
        self._visible_rows = []
        self.query_one("#decisions", _DecisionTable).clear()
        self._current_key = None
        self._update_date_bar(None)
        self._set_panel(message)
        self._update_subtitle()

    def action_reload(self) -> None:
        self._load_worker = self._load_rows()

    # --- filter --------------------------------------------------------------

    def action_filter(self) -> None:
        filter_input = self.query_one("#filter", Input)
        filter_input.display = True
        filter_input.focus()

    def action_clear_filter(self) -> None:
        filter_input = self.query_one("#filter", Input)
        filter_input.value = ""
        filter_input.display = False
        self._apply_filter()
        self.query_one("#decisions", _DecisionTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self._apply_filter()

    def _row_matches(self, row: dict, text: str) -> bool:
        haystacks = (
            str(row.get("final_verdict") or ""),
            str(row.get("target_path_class") or ""),
            _reason_codes_text(row),
        )
        return any(text in haystack.lower() for haystack in haystacks)

    def _apply_filter(self) -> None:
        text = self.query_one("#filter", Input).value.strip().lower()
        if not text:
            self._visible_rows = list(self._rows)
        else:
            self._visible_rows = [r for r in self._rows if self._row_matches(r, text)]
        self._rebuild_table()
        self._update_subtitle()

    def _rebuild_table(self) -> None:
        table = self.query_one("#decisions", _DecisionTable)
        table.clear()
        if not self._visible_rows:
            self._current_key = None
            self._update_date_bar(None)
            if self._rows:  # data exists, the filter just excluded all of it
                self._set_panel(_MSG_NO_MATCH)
            return
        for row in self._visible_rows:
            table.add_row(*_row_cells(row), key=_row_key(row))
        table.move_cursor(row=0)
        self._show_explanation(0)

    def _update_subtitle(self) -> None:
        self.sub_title = (
            f"{self._repo_root} - showing {len(self._visible_rows)} of {len(self._rows)}"
        )

    # --- selection / why panel ------------------------------------------------

    def _set_panel(self, text: str) -> None:
        self.query_one("#explanation", Static).update(text)

    def _update_date_bar(self, row: dict | None) -> None:
        self.query_one("#date-bar", Static).update(_date_str(row) if row else "")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.cursor_row is None:
            return
        self._show_explanation(event.cursor_row)

    def _show_explanation(self, index: int) -> None:
        if index < 0 or index >= len(self._visible_rows):
            return
        row = self._visible_rows[index]
        key = _row_key(row)
        self._current_key = key
        self._update_date_bar(row)
        cached = self._explain_cache.get(key)
        if cached is not None:
            self._set_panel(cached)
            return
        body = template_explanation(row)
        if not llm_enrichment_enabled():
            # Nothing to enrich with - never schedule a worker that would only
            # ever return the same template text.
            text = f"{_PROV_TEMPLATE}\n\n{body}"
            self._explain_cache[key] = text
            self._set_panel(text)
            return
        self._set_panel(f"{_PROV_PENDING}\n\n{body}")
        if self._explain_timer is not None:
            self._explain_timer.stop()
        self._explain_timer = self.set_timer(_EXPLAIN_DEBOUNCE_S, lambda: self._explain_worker(row))

    @work(thread=True, exclusive=True, group="explain")
    def _explain_worker(self, row: dict) -> None:
        worker = get_current_worker()
        key = _row_key(row)
        try:
            text, source = explain_decision_with_source(row)
        except Exception:  # noqa: BLE001 — the TUI must never crash on a narrator failure
            return
        if worker.is_cancelled:
            return
        provenance = _PROV_LLM if source == "llm" else _PROV_FALLBACK
        full = f"{provenance}\n\n{text}"

        def _apply() -> None:
            # Runs on the UI thread: re-check the selection so a slow (opt-in)
            # LLM call can never overwrite a newer row's panel with stale text.
            self._explain_cache[key] = full
            if self._current_key == key:
                self._set_panel(full)

        try:
            self.call_from_thread(_apply)
        except Exception:  # noqa: BLE001, S110 — app may have exited mid-flight; never crash on it
            return

    def _full_why_text(self, row: dict) -> str:
        key = _row_key(row)
        cached = self._explain_cache.get(key)
        body = cached if cached is not None else f"{_PROV_TEMPLATE}\n\n{template_explanation(row)}"
        action_id = row.get("action_id") or "-"
        return f"{body}\n\nreason codes: {_reason_codes_text(row)}\naction id: {action_id}"

    def _open_why_screen(self) -> None:
        cursor_row = self.query_one("#decisions", _DecisionTable).cursor_row
        if cursor_row is None or cursor_row < 0 or cursor_row >= len(self._visible_rows):
            return
        row = self._visible_rows[cursor_row]
        self.push_screen(WhyScreen(self._full_why_text(row)))

    def action_open_why(self) -> None:
        self._open_why_screen()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # DataTable's own "enter" binding fires `select_cursor`, which posts
        # this message - it never reaches our App-level "enter" binding while
        # the table is focused, so hook the same behavior here too.
        self._open_why_screen()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    # --- next/prev BLOCK, next AUTH, copy id ----------------------------------

    def _cursor_index(self) -> int | None:
        cursor_row = self.query_one("#decisions", _DecisionTable).cursor_row
        return cursor_row if cursor_row is not None and cursor_row >= 0 else None

    def _next_matching(self, *, verdict: str, forward: bool) -> None:
        rows = self._visible_rows
        total = len(rows)
        if total == 0:
            return
        start = self._cursor_index()
        start = start if start is not None else (0 if forward else total - 1)
        step = 1 if forward else -1
        for offset in range(1, total + 1):
            index = (start + offset * step) % total
            if rows[index].get("final_verdict") == verdict:
                self.query_one("#decisions", _DecisionTable).move_cursor(row=index)
                return

    def action_next_block(self) -> None:
        self._next_matching(verdict=Verdict.BLOCK.value, forward=True)

    def action_prev_block(self) -> None:
        self._next_matching(verdict=Verdict.BLOCK.value, forward=False)

    def action_next_auth(self) -> None:
        self._next_matching(verdict=Verdict.AUTH.value, forward=True)

    def action_copy_action_id(self) -> None:
        index = self._cursor_index()
        if index is None or index >= len(self._visible_rows):
            return
        action_id = str(self._visible_rows[index].get("action_id") or "")
        if not action_id:
            return
        self.copy_to_clipboard(action_id)
        self.notify(f"copied {action_id}")


def run_tui(repo_root: str, *, last: int = 500) -> None:
    """Launch the decision-transparency TUI. Entry point for `doberman tui`."""
    DecisionExplainerApp(repo_root, last=last).run()
