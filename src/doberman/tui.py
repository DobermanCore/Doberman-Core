"""Decision-transparency TUI: browse the redacted decision log with a "why" panel.

A small Textual app over :func:`doberman.explain.explain_decision_with_source`. It
reads only the already-redacted rows from :func:`doberman.storage.log.read_decisions`
and displays exactly those values - it never opens a raw file, a raw payload, or
any data source beyond that redacted row.

Row-derived strings (and any LLM narrator output) are always rendered as plain
text — table cells go through :class:`rich.text.Text` and every panel/screen has
Rich markup disabled — so a crafted value like ``[red]PASS[/]`` in a stored row
can never restyle or spoof what this browser shows. Verdict/risk colors come
from the single shared palette in :mod:`doberman.render` (``verdict_rich_style``,
``risk_rich_style``), never a private copy, so this browser and ``doberman log``
can never drift apart. Every cell/panel string this module renders is
ASCII-only (the CLI must stay cp1252-safe on Windows) — verdict glyphs, the
target-class ellipsis, and every literal string here avoid non-ASCII
punctuation on purpose.

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
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, LoadingIndicator, Static
from textual.widgets.data_table import CellDoesNotExist
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
#: The leading "" is the 1-char cursor gutter (round 3 design critique item 2):
#: DataTable's own cursor-row background is too low-contrast on its own to
#: read as "selected" (measured 1.69:1) - an ASCII ">" in this column, kept in
#: sync with the cursor by ``_update_gutter``, makes the selection legible even
#: without color.
_HEADERS: tuple[str, ...] = ("", "verdict", "time", "risk", "auth", "action", "target", "why")
#: Minimum content width per column, sized so the whole table fits an 80-column
#: terminal without horizontal scroll (undiscoverable at 80x24 - see the design
#: critique). Target class and reason codes ("why") are the two columns this
#: browser is willing to shorten with a trailing "..." - and the two that grow
#: to absorb any width a wider terminal offers (see ``_widths_for``); the full
#: value for both always remains reachable in the why panel / full-screen why.
_WIDTHS: dict[str, int] = {
    "": 1,
    "verdict": 7,
    "time": 8,
    "risk": 8,
    "auth": 9,
    "action": 12,
    "target": 12,
    "why": 5,
}

#: `time` cell width once the loaded rows span more than one calendar day (see
#: ``_time_cell``/``_widths_for``) - "MM-DD HH:MM" instead of "HH:MM:SS".
_TIME_WIDTH_MULTI_DAY = 11
#: ASCII-only verdict glyphs (no Unicode - the CLI must stay cp1252-safe on
#: Windows). The glyph alone carries meaning even if color is unavailable.
#: AUTH is "!" rather than "?" - "?" is the app's own help-screen key, and a
#: glyph that collides with a keybinding is a trap, not a shortcut.
_VERDICT_GLYPHS: dict[str, str] = {"BLOCK": "X", "AUTH": "!", "PASS": "."}

#: Per-column cell padding DataTable adds around content (one space each side).
_CELL_PADDING = 2

#: Columns the table's own border consumes (one on each side) now that the
#: table and the why panel each get a visible `:focus` border (design critique
#: item 2) - subtracted from the width budget so 80 columns never triggers a
#: horizontal scrollbar the way an un-bordered width calculation would.
_BORDER_COLUMNS = 2


def _widths_for(terminal_width: int, *, multi_day: bool = False) -> dict[str, int]:
    """Column widths for ``terminal_width``: the minimums, plus spare width
    split between ``target`` (1/3) and ``why`` (2/3) - reason codes are what a
    reviewer scans for, so they get the larger share of any room a wide
    terminal offers. Never narrower than the minimums.

    ``multi_day`` widens ``time`` to fit "MM-DD HH:MM" (see ``_time_cell``),
    borrowing the difference back from ``why``'s minimum so the 80-column
    no-scroll budget still holds even for a multi-day log at 80 columns.
    """
    widths = dict(_WIDTHS)
    if multi_day:
        delta = _TIME_WIDTH_MULTI_DAY - widths["time"]
        widths["time"] = _TIME_WIDTH_MULTI_DAY
        widths["why"] = max(1, widths["why"] - delta)
    used = sum(widths.values()) + _CELL_PADDING * len(widths)
    spare = max(0, terminal_width - used - _BORDER_COLUMNS - 1)
    if spare:
        extra_target = spare // 3
        widths["target"] += extra_target
        widths["why"] += spare - extra_target
    return widths


_MSG_NO_ROWS = (
    "Doberman is running here but hasn't decided anything yet. Trigger a tool "
    "call from your agent, or run 'doberman demo --fast' here, then press r."
)
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

#: One-line legend for the ASCII verdict glyphs, shown in the date bar so the
#: glyph meaning is never something a user has to remember or look up in `?`.
_LEGEND = "X BLOCK  ! AUTH  . PASS"

#: "Next" lines: one accurate, actionable line per verdict appended to the why
#: text - what a human can actually do about this decision, using only real
#: `doberman` commands/files (verified against docs/CLI.md; never invented).
#: PASS gets none - there is nothing to act on.
_NEXT_BLOCK = (
    "Next: this is a hard block - only a policy or role change lets it through "
    "(`doberman mode` to adjust strength, `doberman review --yes` to save the "
    "recommended checklist, or edit .doberman/policies.yaml directly). "
    "Re-running the action will not change this verdict."
)
_NEXT_AUTH = (
    "Next: re-running the action will ask again; a pending approval also shows "
    "in `doberman dash`'s approve/deny queue."
)


def _next_step_line(verdict: str | None) -> str | None:
    if verdict == Verdict.BLOCK.value:
        return _NEXT_BLOCK
    if verdict == Verdict.AUTH.value:
        return _NEXT_AUTH
    return None


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


def _time_cell(row: dict, *, multi_day: bool = False) -> str:
    ts = _parse_ts(row.get("ts"))
    if not ts:
        return "-"
    return ts.strftime("%m-%d %H:%M") if multi_day else ts.strftime("%H:%M:%S")


def _spans_multiple_days(rows: list[dict]) -> bool:
    """Whether the loaded rows cover more than one calendar day - if so, the
    time column trades HH:MM:SS for a date-qualified MM-DD HH:MM (round 3
    design critique item 6)."""
    dates = {_date_str(row) for row in rows}
    dates.discard("")
    return len(dates) > 1


def _date_str(row: dict) -> str:
    ts = _parse_ts(row.get("ts"))
    return ts.strftime("%Y-%m-%d") if ts else ""


def _date_bar_text(row: dict | None) -> str:
    """The date bar's text: the selected row's date (if any) plus the verdict
    glyph legend, always present so the glyphs are self-explanatory."""
    date = _date_str(row) if row else ""
    return f"{date}  {_LEGEND}" if date else _LEGEND


def _shorten_home(path: Path) -> str:
    """Collapse ``path`` to a ``~``-relative form when it lives under the home
    directory, else return it unchanged. Cosmetic only - never changes what
    path is actually used."""
    home = Path.home()
    try:
        rel = path.relative_to(home)
    except ValueError:
        return str(path)
    return "~" if str(rel) == "." else str(Path("~") / rel)


#: Short (2-4 word) labels for reason codes whose plain word-replace still
#: reads awkwardly in the narrow "why" column - REASON_DESCRIPTIONS-style
#: (doberman.explain's own reason-code descriptions) but trimmed to table-cell
#: length. Anything not listed falls back to a humanized form of the code
#: itself (see ``_short_reason``) - this dict never has to stay perfectly in
#: sync with `ReasonCode` to be safe. Used ONLY for the table's "why" column;
#: the why panel/full-screen why always show the raw codes via
#: ``_reason_codes_text``, never these shortened labels.
_SHORT_REASON_LABELS: dict[str, str] = {
    "secret_exfiltration": "secret sent outbound",
    "sensitive_secret_access": "touched a secret file",
    "possible_high_entropy_secret": "possible secret",
    "sensitive_path_access": "sensitive path",
    "protected_path_blocked": "protected path",
    "unknown_external_destination": "unknown destination",
    "confidentiality_sensitive_destination": "sensitive destination",
    "irreversible_high_blast": "hard to undo, high impact",
    "lethal_trifecta": "lethal trifecta pattern",
    "artifact_digest_mismatch": "digest mismatch",
    "egress_broker_enforced": "egress broker enforced",
    "egress_blocked_by_mode": "blocked by paranoid mode",
    "anomalous_egress_velocity": "unusual egress velocity",
    "unusual_for_workflow": "unusual for this agent",
    "unusual_for_deployment": "unusual for this deployment",
}


def _short_reason(code: str) -> str:
    return _SHORT_REASON_LABELS.get(code, code.replace("_", " "))


def _parsed_reason_codes(row: dict) -> list:
    try:
        codes = json.loads(row.get("reason_codes_json") or "[]")
    except (TypeError, ValueError):
        return []
    return codes if isinstance(codes, list) else []


def _reason_codes_text(row: dict) -> str:
    codes = _parsed_reason_codes(row)
    if not codes:
        return "-"
    # str() each item: a tampered/corrupt row (e.g. `[1]` or `[{}]`) must render
    # as junk text, never crash the browser.
    return ", ".join(str(code) for code in codes)


def _reason_codes_words(row: dict) -> str:
    """Like :func:`_reason_codes_text` but each code passed through
    :func:`_short_reason` - the table's "why" column reads as words, not raw
    snake_case constants (round 3 design critique item 7). The why
    panel/full-screen why keep the raw codes via ``_reason_codes_text``."""
    codes = _parsed_reason_codes(row)
    if not codes:
        return "-"
    return ", ".join(_short_reason(str(code)) for code in codes)


def _row_key(row: dict) -> str:
    return str(row.get("action_id") or id(row))


def _verdict_cell(verdict_str: str) -> Text:
    glyph = _VERDICT_GLYPHS.get(verdict_str, "?")
    label = _truncate(f"{glyph} {verdict_str}", _WIDTHS["verdict"])
    try:
        style = render.verdict_rich_style(Verdict(verdict_str), chip=True)
    except ValueError:
        style = ""  # corrupt/future verdict value: render plain, never crash
    return Text(label, style=style)


def _row_cells(
    row: dict, widths: dict[str, int] | None = None, *, multi_day: bool = False
) -> tuple[Text, ...]:
    widths = widths or _WIDTHS
    verdict_str = str(row.get("final_verdict") or "-")
    risk_str = str(row.get("risk") or "-")
    return (
        # Gutter: blank by default - `_update_gutter` marks the cursor row
        # with ">" (round 3 design critique item 2).
        Text(""),
        _verdict_cell(verdict_str),
        Text(_time_cell(row, multi_day=multi_day)),
        Text(_truncate(risk_str, widths["risk"]), style=render.risk_rich_style(risk_str)),
        Text(
            _truncate(
                render.humanize_auth_result(row.get("auth_result"), short=True), widths["auth"]
            )
        ),
        Text(_truncate(str(row.get("action_type") or "-"), widths["action"])),
        Text(_truncate(str(row.get("target_path_class") or "-"), widths["target"])),
        Text(_truncate(_reason_codes_words(row), widths["why"])),
    )


def _why_header_line(row: dict) -> str:
    """First line of the full-screen why: the row's identity at a glance -
    verdict glyph, time, risk, action type, target class - so paging through
    BLOCK/AUTH rows with b/B/a never loses track of which row is on screen
    (round 3 design critique item 4)."""
    verdict_str = str(row.get("final_verdict") or "-")
    glyph = _VERDICT_GLYPHS.get(verdict_str, "?")
    time_str = _time_cell(row)
    risk_str = str(row.get("risk") or "-")
    action_str = str(row.get("action_type") or "-")
    target_str = str(row.get("target_path_class") or "-")
    return f"{glyph} {verdict_str}  {time_str}  {risk_str}  {action_str}  {target_str}"


class _DecisionTable(DataTable):
    """A `DataTable` whose Home/End jump to the first/last decision row.

    The base class's Home/End only move the *horizontal* viewport for a
    ``cursor_type="row"`` table (there is no "leftmost column" to seek to when
    there's only a row cursor) - not useful for browsing hundreds of rows. Both
    keys forward to the App's own ``goto_first``/``goto_last`` actions (the
    ``"app.<action>"`` binding namespace) rather than a local override, so
    Home/End mean the same thing - "jump to the first/last decision" - no
    matter which widget currently has focus (see ``_WhyPanel`` below and the
    design critique's "Home/End is a no-op from the why panel" finding). Both
    stay hidden (`show=False`): the App's own hidden bindings are what the `?`
    help screen documents, and a footer entry here would be redundant with it.
    """

    BINDINGS = [
        Binding("home", "app.goto_first", "first", show=False),
        Binding("end", "app.goto_last", "last", show=False),
    ]


class _WhyPanel(VerticalScroll):
    """The docked why panel - same Home/End forwarding as `_DecisionTable`.

    Without this override, `VerticalScroll`'s own inherited Home/End would
    scroll the panel itself (top/bottom) whenever it has focus, which is a
    no-op from the browsing perspective: Home/End are meant as "jump to the
    first/last decision", a meaning that must not depend on which widget the
    `tab` key most recently focused.
    """

    BINDINGS = [
        Binding("home", "app.goto_first", "first", show=False),
        Binding("end", "app.goto_last", "last", show=False),
    ]


class WhyScreen(ModalScreen[None]):
    """Full-screen "why": the complete explanation, every reason code, the
    action id, and a "Next" step. Modal so it dims the browser behind it, and
    stays in sync while open: `b`/`B`/`a` jump the table's cursor to the
    next/previous BLOCK or next AUTH the same way they do from the main
    browser, and re-render this screen's own text for the newly selected row -
    letting a reviewer page through every BLOCK without ever closing the panel.
    """

    BINDINGS = [
        Binding("escape", "close", "close", show=True),
        Binding("q", "close", "close", show=False),
        # show=True (round 3 design critique item 4): b/B/a work from inside
        # this screen (see `_jump`/module docstring above) so its own footer
        # should say so, not just the main browser's.
        Binding("b", "jump_block_next", "next BLOCK", show=True),
        Binding("B", "jump_block_prev", "prev BLOCK", show=True),
        Binding("a", "jump_auth_next", "next AUTH", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="why-scroll"):
            yield Static("", id="why-text", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        app: DecisionExplainerApp = self.app  # type: ignore[assignment]
        row = app.current_row()
        text = app.full_why_text(row) if row is not None else ""
        # The Static was constructed with markup=False (see compose) - it
        # embeds row-derived strings and must always render literally.
        self.query_one("#why-text", Static).update(text)

    def action_close(self) -> None:
        self.app.pop_screen()

    def _jump(self, *, verdict: str, forward: bool) -> None:
        app: DecisionExplainerApp = self.app  # type: ignore[assignment]
        if app.jump_to_verdict(verdict, forward=forward):
            self._refresh()

    def action_jump_block_next(self) -> None:
        self._jump(verdict=Verdict.BLOCK.value, forward=True)

    def action_jump_block_prev(self) -> None:
        self._jump(verdict=Verdict.BLOCK.value, forward=False)

    def action_jump_auth_next(self) -> None:
        self._jump(verdict=Verdict.AUTH.value, forward=True)


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
        "/            filter rows (Enter keeps it, Esc clears it) - matches verdict, target,\n"
        "             action, reason codes\n"
        "escape       clear an active filter (works from the table too, not just the filter\n"
        "             box), or close this screen / the why screen\n"
        "tab          move focus between the table and the why panel\n"
        "enter, w     open the full-screen why panel for the selected row\n"
        "b            jump to the next BLOCK (also works inside the why panel)\n"
        "B            jump to the previous BLOCK (also works inside the why panel)\n"
        "a            jump to the next AUTH (also works inside the why panel)\n"
        "y            copy the selected action id to the clipboard\n"
        "home         jump to the first row (works no matter which widget has focus)\n"
        "end          jump to the last row (works no matter which widget has focus)\n"
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
    # This app has no command palette of its own, and the default `^p palette`
    # footer entry docks over the right edge of the footer - at 80 columns it
    # visually overlaps the tail of "next AUTH" (design critique item 1).
    ENABLE_COMMAND_PALETTE = False

    # Ordered by importance so the footer reads usefully even when the
    # terminal is too narrow to show every binding (design critique item 1):
    # at 80 columns it must read at least "w why  / filter  b next BLOCK
    # ? help  q quit". `escape` is deliberately declared with show=True but
    # gated dynamically via `check_action` - it only appears while the filter
    # input has focus, so it is never a footer entry that does nothing.
    BINDINGS = [
        Binding("w", "open_why", "why", show=True),
        Binding("/", "filter", "filter", show=True),
        Binding("b", "next_block", "next BLOCK", show=True),
        Binding("question_mark", "help", "help", show=True),
        Binding("q", "quit", "quit", show=True),
        Binding("B", "prev_block", "prev BLOCK", show=True),
        Binding("a", "next_auth", "next AUTH", show=True),
        Binding("y", "copy_action_id", "copy id", show=True),
        Binding("r", "reload", "reload", show=True),
        Binding("escape", "clear_filter", "clear", show=True),
        Binding("enter", "open_why", "why", show=False),
        Binding("home", "goto_first", "first", show=False),
        Binding("end", "goto_last", "last", show=False),
    ]

    CSS = """
    /* A dark cursor row instead of Textual's blue: every foreground colour
       (PASS green, the plain risk/auth cells) keeps its contrast under the
       cursor; the BLOCK/AUTH/critical/high chips carry their own background. */
    DataTable > .datatable--cursor {
        background: #3a3a3a;
    }
    DataTable:focus > .datatable--cursor {
        background: #4a4a4a;
    }
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
        border: solid $panel;
    }
    #decisions:focus {
        border: solid $accent;
    }
    #filter {
        dock: bottom;
    }
    #explanation-scroll {
        height: 1fr;
        border: solid $panel;
    }
    #explanation-scroll:focus {
        border: solid $accent;
    }
    #explanation {
        padding: 1;
    }
    #next-line {
        height: 1;
        padding: 0 1;
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
        self._widths: dict[str, int] = dict(_WIDTHS)
        self._columns_ready = False
        self._multi_day = False
        self._gutter_row: int | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="date-bar")
        yield LoadingIndicator(id="loading")
        with Vertical():
            yield _DecisionTable(
                id="decisions",
                cursor_type="row",
                cursor_foreground_priority="renderable",
                cursor_background_priority="renderable",
            )
            yield Input(
                placeholder="filter (verdict / target / action / reason codes)", id="filter"
            )
            # markup=False: the "why" text embeds row-derived strings - render
            # them literally, never as Rich markup.
            with _WhyPanel(id="explanation-scroll"):
                yield Static("", id="explanation", markup=False)
            # Docked separately from the why panel body (round 3 design
            # critique item 3): a "Next" step must stay visible even when the
            # panel above needs to scroll for a long explanation.
            yield Static("", id="next-line", markup=False)
        yield Footer()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # `escape`/"clear" is shown while the filter input has focus (the
        # ordinary case), OR while a filter is ACTIVE from anywhere else -
        # e.g. the table - so a reviewer doesn't have to tab back to the
        # filter box just to dismiss it (round 3 design critique item 1).
        # False (not None) hides it outright rather than merely graying it
        # out - the exact "trap" the original design critique flagged.
        if action == "clear_filter":
            try:
                filter_input = self.query_one("#filter", Input)
            except Exception:  # noqa: BLE001 — defensive: nothing focused before mount
                return False
            if self.focused is filter_input:
                return True
            return bool(filter_input.value.strip())
        return True

    async def on_mount(self) -> None:
        table = self.query_one("#decisions", _DecisionTable)
        self._widths = _widths_for(self.size.width)
        for header in _HEADERS:
            table.add_column(header, width=self._widths[header], key=header)
        self._columns_ready = True
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
                    f"No decision log at {_shorten_home(path)}. "
                    "Press q to quit, then rerun with --path <repo>."
                )
                return
            rows = await read_decisions(self._repo_root, limit=self._last)
            self._rows = rows
            self._multi_day = _spans_multiple_days(rows)
            self._apply_widths(_widths_for(self.size.width, multi_day=self._multi_day))
            if not rows:
                self._reset_to_empty(_MSG_NO_ROWS)
                return
            self._apply_filter()
        finally:
            loading.display = False

    def _apply_widths(self, widths: dict[str, int]) -> bool:
        """Re-declare the table's columns at ``widths``. Returns whether
        anything changed - callers rebuild the row data only when it did."""
        if widths == self._widths:
            return False
        self._widths = widths
        table = self.query_one("#decisions", _DecisionTable)
        for header in _HEADERS:
            table.remove_column(header)
        for header in _HEADERS:
            table.add_column(header, width=widths[header], key=header)
        return True

    def on_resize(self) -> None:
        """Re-fit the columns: spare width goes to target/why, never a scrollbar."""
        if not self._columns_ready:
            # The first layout resize lands before on_mount adds the columns.
            return
        widths = _widths_for(self.size.width, multi_day=self._multi_day)
        if self._apply_widths(widths):
            self._rebuild_table()

    def _reset_to_empty(self, message: str) -> None:
        self._visible_rows = []
        self._multi_day = False
        self._gutter_row = None
        self._apply_widths(_widths_for(self.size.width, multi_day=False))
        self.query_one("#decisions", _DecisionTable).clear()
        self._current_key = None
        self._update_date_bar(None)
        self._update_next_line(None)
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

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter commits the already-applied filter (a documented "exit"
        # distinct from escape's "clear") and returns focus to the table -
        # the footer then reads normally again (round 3 design critique
        # item 1).
        if event.input.id == "filter":
            self.query_one("#decisions", _DecisionTable).focus()

    def _row_matches(self, row: dict, text: str) -> bool:
        haystacks = (
            str(row.get("final_verdict") or ""),
            str(row.get("target_path_class") or ""),
            str(row.get("action_type") or ""),
            # auth_result is deliberately NOT searched: "block" would otherwise
            # match every row whose auth outcome is "blocked", not the verdict.
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
        previous_key = self._current_key
        table.clear()
        self._gutter_row = None
        if not self._visible_rows:
            self._current_key = None
            self._update_date_bar(None)
            self._update_next_line(None)
            if self._rows:  # data exists, the filter just excluded all of it
                self._set_panel(_MSG_NO_MATCH)
            return
        for row in self._visible_rows:
            table.add_row(
                *_row_cells(row, self._widths, multi_day=self._multi_day), key=_row_key(row)
            )
        # Restore the previously selected row by key rather than snapping to
        # row 0 - a resize (or a filter edit that still matches it) must not
        # lose the reviewer's place (design critique item 10).
        restore_index = 0
        if previous_key is not None:
            for index, row in enumerate(self._visible_rows):
                if _row_key(row) == previous_key:
                    restore_index = index
                    break
        table.move_cursor(row=restore_index)
        self._show_explanation(restore_index)

    def _update_subtitle(self) -> None:
        # Count first: it must survive truncation at narrow widths, the path
        # is the part that's safe to lose (design critique item 9).
        total = len(self._rows)
        # If the load hit the `--last` cap, say so explicitly - "3 of 3" reads
        # as "that's everything" when it may not be (round 3 design critique
        # item 5).
        suffix = f" (last {total}; --last for more)" if self._last and total == self._last else ""
        self.sub_title = f"showing {len(self._visible_rows)} of {total}{suffix} - {self._repo_root}"

    # --- selection / why panel ------------------------------------------------

    def _set_panel(self, text: str) -> None:
        self.query_one("#explanation", Static).update(text)

    def _update_date_bar(self, row: dict | None) -> None:
        self.query_one("#date-bar", Static).update(_date_bar_text(row))

    def _update_next_line(self, row: dict | None) -> None:
        # Docked separately from the panel body (round 3 design critique item
        # 3) so it stays on screen even while the why panel itself scrolls.
        next_line = _next_step_line(row.get("final_verdict")) if row is not None else None
        self.query_one("#next-line", Static).update(next_line or "")

    def _update_gutter(self, index: int) -> None:
        # The 1-char cursor gutter (round 3 design critique item 2): clear the
        # previous mark (if any) and mark the new cursor row with ">" - kept
        # independent of Textual's own cursor-row background, which measured
        # too low-contrast on its own to read as "selected".
        table = self.query_one("#decisions", _DecisionTable)
        if self._gutter_row is not None and self._gutter_row != index:
            try:
                table.update_cell_at(Coordinate(self._gutter_row, 0), Text(""), update_width=False)
            except CellDoesNotExist:
                pass
        try:
            table.update_cell_at(Coordinate(index, 0), Text(">"), update_width=False)
        except CellDoesNotExist:
            return
        self._gutter_row = index

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
        self._update_next_line(row)
        self._update_gutter(index)
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
        except Exception:  # noqa: BLE001 — best-effort: fall back rather than
            # strand the panel on "narrating..." forever (design critique
            # item 4) - an unhandled raise here must read exactly like the
            # already-handled "LLM call failed" case, not hang silently.
            text, source = template_explanation(row), "template"
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

    def full_why_text(self, row: dict) -> str:
        """The complete why text for `row`: a row-identity header line, cached
        body, every reason code, the action id, and a "Next" step - what
        `WhyScreen` displays (round 3 design critique item 4: paging through
        rows with b/B/a must never lose track of which row is on screen)."""
        header = _why_header_line(row)
        key = _row_key(row)
        cached = self._explain_cache.get(key)
        body = cached if cached is not None else f"{_PROV_TEMPLATE}\n\n{template_explanation(row)}"
        action_id = row.get("action_id") or "-"
        text = (
            f"{header}\n\n{body}\n\nreason codes: {_reason_codes_text(row)}\naction id: {action_id}"
        )
        next_line = _next_step_line(row.get("final_verdict"))
        return f"{text}\n\n{next_line}" if next_line else text

    def current_row(self) -> dict | None:
        """The row currently under the table cursor, or `None` if there isn't one."""
        index = self._cursor_index()
        if index is None or index >= len(self._visible_rows):
            return None
        return self._visible_rows[index]

    def _open_why_screen(self) -> None:
        if self.current_row() is not None:
            self.push_screen(WhyScreen())

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

    def jump_to_verdict(self, verdict: str, *, forward: bool) -> bool:
        """Move the table cursor to the next/previous row whose verdict is
        `verdict` (wrapping around). Returns whether it moved, so a caller
        (e.g. `WhyScreen`) knows whether to re-render; notifies the user when
        nothing matches rather than silently doing nothing."""
        rows = self._visible_rows
        total = len(rows)
        if total:
            start = self._cursor_index()
            start = start if start is not None else (0 if forward else total - 1)
            step = 1 if forward else -1
            for offset in range(1, total + 1):
                index = (start + offset * step) % total
                if rows[index].get("final_verdict") == verdict:
                    self.query_one("#decisions", _DecisionTable).move_cursor(row=index)
                    return True
        self.notify(f"no {verdict} rows in view", markup=False)
        return False

    def action_next_block(self) -> None:
        self.jump_to_verdict(Verdict.BLOCK.value, forward=True)

    def action_prev_block(self) -> None:
        self.jump_to_verdict(Verdict.BLOCK.value, forward=False)

    def action_next_auth(self) -> None:
        self.jump_to_verdict(Verdict.AUTH.value, forward=True)

    def action_goto_first(self) -> None:
        self._jump_cursor(0)

    def action_goto_last(self) -> None:
        table = self.query_one("#decisions", _DecisionTable)
        if table.row_count:
            self._jump_cursor(table.row_count - 1)

    def _jump_cursor(self, index: int) -> None:
        table = self.query_one("#decisions", _DecisionTable)
        if table.row_count:
            table.move_cursor(row=index)

    def action_copy_action_id(self) -> None:
        index = self._cursor_index()
        if index is None or index >= len(self._visible_rows):
            return
        action_id = str(self._visible_rows[index].get("action_id") or "")
        if not action_id:
            return
        self.copy_to_clipboard(action_id)
        # markup=False: the id is row-derived text and must render literally.
        self.notify(f"copy requested: {action_id} (clipboard via terminal OSC 52)", markup=False)


def run_tui(repo_root: str, *, last: int = 500) -> None:
    """Launch the decision-transparency TUI. Entry point for `doberman tui`."""
    DecisionExplainerApp(repo_root, last=last).run()
