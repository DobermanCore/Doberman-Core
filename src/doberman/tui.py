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
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import DataTable, Footer, Header, Input, LoadingIndicator, Static
from textual.widgets._footer import FooterKey
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
#: critique). `why` (reason codes) is the one column that grows to absorb any
#: width `target` doesn't need (see ``_widths_for``). `target`'s value here is
#: a FLOOR, not a fixed size (round 7 design critique item 1 supersedes round
#: 5 item 3's fixed-6: a real `target` value like "backend/secrets/*.env" was
#: unreadable at 6/3 columns) - the actual column width is driven by the
#: loaded rows' longest visible target class, see ``_target_width_need``; the
#: full value for both `target` and `why` always remains reachable in the why
#: panel / full-screen why regardless of what the table cell shows.
_TARGET_WIDTH_FLOOR = 8
#: Cap on how wide `target` may grow even when the data wants more - past this
#: point the extra width serves one outlier value better than `why` serves
#: every row, and the full value is always still reachable in the why panel.
_TARGET_WIDTH_CAP = 24
_WHY_WIDTH_FLOOR = 8
_WIDTHS: dict[str, int] = {
    "": 1,
    "verdict": 7,
    "time": 8,
    "risk": 8,
    "auth": 7,
    "action": 10,
    "target": _TARGET_WIDTH_FLOOR,
    "why": _WHY_WIDTH_FLOOR,
}


def _target_width_need(rows: list[dict]) -> int:
    """The `target` column's content-driven width: the longest visible
    `target_path_class` among ``rows``, floored at ``_TARGET_WIDTH_FLOOR`` and
    capped at ``_TARGET_WIDTH_CAP`` (round 7 design critique item 1) - real
    values like "backend/secrets/*.env" need more than the old fixed 6, but
    one outlier-long value should never swallow the whole `why` budget.
    Vacuously the floor for an empty/not-yet-loaded ``rows`` - nothing to
    measure yet."""
    longest = max((len(str(row.get("target_path_class") or "")) for row in rows), default=0)
    return max(_TARGET_WIDTH_FLOOR, min(_TARGET_WIDTH_CAP, longest))


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
#: item 2), PLUS one for Textual's own vertical scrollbar (round 6 design
#: critique item 1: the scrollbar is 2 columns wide - `scrollbar-size-vertical`
#: - and only ONE of those 2 was ever reserved here; measured with 45 rows
#: loaded at 80 columns, the table's virtual width came out to 77 while its
#: scrollable content region (after border + scrollbar) was only 76, a
#: spurious 1-column horizontal scrollbar). `#decisions` also sets
#: `overflow-x: hidden` (see CSS) as a second, unconditional guarantee that no
#: horizontal scrollbar can ever appear even if this budget is ever wrong by a
#: column - subtracted from the width budget so 80 columns never triggers one
#: the way an un-bordered width calculation would.
_BORDER_COLUMNS = 3


def _widths_for(
    terminal_width: int,
    *,
    multi_day: bool = False,
    hide_target: bool = False,
    target_need: int = _TARGET_WIDTH_FLOOR,
) -> dict[str, int]:
    """Column widths for ``terminal_width``: every column starts at its
    floor, then ``target`` gets first claim on spare width - up to
    ``target_need`` (see :func:`_target_width_need`) - and whatever's left
    goes to ``why`` (round 7 design critique item 1 supersedes round 5 item
    3's fixed-6 `target`: a real `target_path_class` like
    "backend/secrets/*.env" was unreadable at 6, let alone the 3 it measured
    once `why` had already eaten the rest of the row). Never narrower than
    the floors, and ``target`` never grows past what the data actually needs
    even when more spare width is available - the extra always goes to
    ``why`` instead.

    ``target`` and ``why`` both keep at least their floor (8) at 80 terminal
    columns even with a long real `target` present - `target` gets whatever
    spare the floors leave over (up to ``target_need``), and `why` keeps its
    own floor regardless (round 6 design critique item 1 reserves one more
    column for Textual's own vertical scrollbar - see ``_BORDER_COLUMNS`` - a
    smaller cost than a spurious horizontal scrollbar).

    ``multi_day`` widens ``time`` to fit "MM-DD HH:MM" (see ``_time_cell``) -
    that extra width comes out of the same spare pool ``target``/``why``
    would otherwise share, never below either one's floor.

    ``hide_target=True`` (every loaded row's target is "-" - see
    :func:`_all_targets_missing`) drops the ``target`` key entirely BEFORE the
    spare-width math runs, so one column fewer consuming the budget
    automatically folds its reclaimed width (plus its own cell padding) into
    ``why`` - the caller is expected to also stop adding a ``target`` column
    to the table in that case.
    """
    widths = dict(_WIDTHS)
    if multi_day:
        widths["time"] = _TIME_WIDTH_MULTI_DAY
    if hide_target:
        widths.pop("target")
    used = sum(widths.values()) + _CELL_PADDING * len(widths)
    spare = max(0, terminal_width - used - _BORDER_COLUMNS - 1)
    if not hide_target:
        target_room = max(0, target_need - widths["target"])
        target_grow = min(spare, target_room)
        widths["target"] += target_grow
        spare -= target_grow
    widths["why"] += spare
    return widths


def _headers_for(*, hide_target: bool) -> tuple[str, ...]:
    """Column headers to actually declare on the table - ``_HEADERS`` minus
    ``target`` when every loaded row's target is "-" (round 5 design critique
    item 3)."""
    return tuple(h for h in _HEADERS if h != "target") if hide_target else _HEADERS


def _all_targets_missing(rows: list[dict]) -> bool:
    """Whether every one of ``rows`` has no ``target_path_class`` - if so, the
    column is pure dead weight (always "-") and is dropped entirely in favor
    of giving that width to ``why`` (round 5 design critique item 3). Vacuously
    ``False`` for an empty/not-yet-loaded ``rows`` - nothing to hide behind
    yet, and the column stays present until a real load says otherwise."""
    return bool(rows) and not any(row.get("target_path_class") for row in rows)


_MSG_NO_ROWS = (
    "Doberman is running here but hasn't decided anything yet. Trigger a tool "
    "call from your agent, or run 'doberman demo --fast' here, then press r."
)
_MSG_NO_MATCH = "(no rows match the filter - press esc to clear it)"

#: Actions that need at least one visible row to mean anything - `check_action`
#: hides all five from the footer (round 4 design critique item 3) rather than
#: leaving a binding that visibly does nothing when the table is empty.
_ROW_ACTIONS = frozenset({"open_why", "copy_action_id", "next_block", "prev_block", "next_auth"})

#: Provenance stamps for the why panel (ADR-style honesty about where the
#: text came from - never silently upgrade/replace without saying so). Now
#: rendered as a MUTED one-liner at the END of the panel (round 5 design
#: critique item 6: the explanation is the point, the source note is
#: supporting detail, not the headline).
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


def _panel_text(body: str, provenance: str, *, time_line: str | None = None) -> Text:
    """The docked why panel's content: an optional muted `time_line` (the
    row's absolute UTC instant + relative age, round 7 design critique item
    2) first, then `body` (the explanation/remedy), then a blank line, then
    `provenance` styled muted/dim (round 5 design critique item 6). Built
    from plain strings only - `body`/`provenance`/`time_line` are never
    re-parsed as markup (this constructs a `Text` directly, the same
    literal-rendering guarantee the module docstring promises), so a crafted
    stored value still can't restyle anything; the `dim` spans cover only the
    text we ourselves appended (the leading time line and the trailing
    provenance line), never `body`.
    """
    prefix = f"{time_line}\n\n" if time_line else ""
    combined = f"{prefix}{body}\n\n{provenance}"
    text = Text(combined)
    text.stylize("dim", len(combined) - len(provenance), len(combined))
    if time_line:
        text.stylize("dim", 0, len(time_line))
    return text


#: The literal prefix of every `render.next_step_line` remedy - bolded in the
#: docked "Next" line so it reads as the remedy, not more prose (round 5
#: design critique item 6).
_NEXT_LINE_PREFIX = "Next"


def _next_line_text(line: str) -> Text:
    text = Text(line)
    if line.startswith(_NEXT_LINE_PREFIX):
        # The AUTH/accent style (bold) - shared with the verdict palette so
        # this never keeps a second copy of the color choice.
        text.stylize(render.verdict_rich_style(Verdict.AUTH), 0, len(_NEXT_LINE_PREFIX))
    return text


def _truncate(text: str, width: int) -> str:
    """Shorten ``text`` to ``width`` with a trailing "...", never silently
    longer, and never a bare cut with no visible marker (round 7 design
    critique item 1): showing fewer than 4 real characters with nothing to
    say "this was cut" reads as complete when it isn't. In practice no column
    ever asks for a width this narrow - every column floor is >= 7 (see
    ``_WIDTHS``/``_target_width_need``) - so the ``width <= 3`` branch only
    guards a defensive/theoretical caller.

    ASCII-only ellipsis (three periods, not U+2026) - see the module docstring.
    """
    if len(text) <= width:
        return text
    if width <= 3:
        return "..."[:width]
    return text[: width - 3] + "..."


def _parse_ts(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _to_local(ts: datetime) -> datetime:
    """Convert an aware UTC timestamp to this machine's local zone (round 7
    design critique item 2: the table's `time` column and the date bar now
    show local time - the row's stored value stays UTC on disk, this is
    display-only). A naive value (a hand-built/legacy row missing its offset)
    is assumed already UTC - every real row is stamped with
    ``datetime.now(timezone.utc).isoformat()`` (see
    ``doberman.storage.log.build_record``), so this only guards a
    defensive/theoretical caller."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone()


def _time_cell(row: dict, *, multi_day: bool = False) -> str:
    ts = _parse_ts(row.get("ts"))
    if not ts:
        return "-"
    local = _to_local(ts)
    return local.strftime("%m-%d %H:%M") if multi_day else local.strftime("%H:%M:%S")


def _spans_multiple_days(rows: list[dict]) -> bool:
    """Whether the loaded rows cover more than one LOCAL calendar day - if so,
    the time column trades HH:MM:SS for a date-qualified MM-DD HH:MM (round 3
    design critique item 6; round 7 item 2: local, matching what the time
    column and date bar now actually display)."""
    dates = {_date_str(row) for row in rows}
    dates.discard("")
    return len(dates) > 1


def _date_str(row: dict) -> str:
    ts = _parse_ts(row.get("ts"))
    return _to_local(ts).strftime("%Y-%m-%d") if ts else ""


def _relative_age(delta: timedelta) -> str:
    """A coarse "2m"/"3h"/"5d" span for ``delta`` - never finer than a whole
    second, and never negative (a row from the future, e.g. clock skew,
    clamps to "0s" rather than printing a negative span)."""
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d"


def _abs_utc_and_age(row: dict, *, now: datetime | None = None) -> str:
    """ "2026-09-02 09:31:05 UTC (2m ago)" - the row's absolute UTC instant
    plus a coarse relative age (round 7 design critique item 2). Explicitly
    UTC-labeled: the table's own `time` column and the date bar now show
    LOCAL time, so the why panel/full-screen why header is the one place a
    reviewer can always find the unambiguous absolute instant, alongside how
    long ago it happened. ``now`` defaults to the real wall clock and exists
    only so a test can freeze it - production callers never pass it. Computed
    fresh each time a row is (re)selected, never on a live-updating timer."""
    ts = _parse_ts(row.get("ts"))
    if not ts:
        return "-"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S')} UTC ({_relative_age(now - ts)} ago)"


def _verdict_counts_text(rows: list[dict]) -> str:
    """ "22 BLOCK / 1 AUTH / 22 PASS" - a verdict breakdown over ``rows`` (round
    6 design critique item 4), always all three verdicts in this fixed order
    even when a count is zero, so a reviewer can see at a glance how many of
    the LOADED rows actually need attention without opening the filter."""
    counts = Counter(str(row.get("final_verdict")) for row in rows)
    return " / ".join(
        f"{counts.get(v.value, 0)} {v.value}" for v in (Verdict.BLOCK, Verdict.AUTH, Verdict.PASS)
    )


def _date_bar_text(row: dict | None) -> Text:
    """The date bar's text: the selected row's LOCAL date (if any), marked
    "(local)" (round 7 design critique item 2 - the table's own `time` column
    shows local time too, so this must never read as if it were UTC), plus
    the verdict glyph legend, always present so the glyphs are
    self-explanatory.

    Round 6 design critique item 8: the legend is what a reader actually
    needs to keep referring back to - muting it along with the date (the
    old plain-string content, styled uniformly by `#date-bar`'s CSS `color:
    $text-muted`) made the very thing meant to explain the glyphs the
    hardest part of the bar to read. Only the date (+ "(local)") is muted
    (`dim`, the same approximation of a muted tone `_panel_text` already
    uses); the legend renders at the widget's normal (`$text`) color - see
    the CSS, which no longer sets `color` on `#date-bar` itself.
    """
    date = _date_str(row) if row else ""
    if not date:
        return Text(_LEGEND)
    date_label = f"{date} (local)"
    combined = f"{date_label}  {_LEGEND}"
    text = Text(combined)
    text.stylize("dim", 0, len(date_label))
    return text


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


def _initial_landing_index(rows: list[dict]) -> int:
    """Where the cursor starts on a fresh load (round 6 design critique item
    5): the index of the NEWEST row that isn't PASS - rows come back
    newest-first (see ``read_decisions``), so this is just the first
    non-PASS row scanning from the top. Falls back to row 0 (every row is
    PASS, or there are no rows) - never raises on an empty list."""
    for index, row in enumerate(rows):
        if row.get("final_verdict") != Verdict.PASS.value:
            return index
    return 0


def _verdict_cell(verdict_str: str) -> Text:
    glyph = _VERDICT_GLYPHS.get(verdict_str, "?")
    label = _truncate(f"{glyph} {verdict_str}", _WIDTHS["verdict"])
    try:
        style = render.verdict_rich_style(Verdict(verdict_str), chip=True)
    except ValueError:
        style = ""  # corrupt/future verdict value: render plain, never crash
    return Text(label, style=style)


def _row_cells(
    row: dict,
    widths: dict[str, int] | None = None,
    *,
    multi_day: bool = False,
    hide_target: bool = False,
) -> tuple[Text, ...]:
    widths = widths or _WIDTHS
    verdict_str = str(row.get("final_verdict") or "-")
    risk_str = str(row.get("risk") or "-")
    cells: dict[str, Text] = {
        # Gutter: blank by default - `_update_gutter` marks the cursor row
        # with ">" (round 3 design critique item 2).
        "": Text(""),
        "verdict": _verdict_cell(verdict_str),
        "time": Text(_time_cell(row, multi_day=multi_day)),
        "risk": Text(_truncate(risk_str, widths["risk"]), style=render.risk_rich_style(risk_str)),
        "auth": Text(
            _truncate(
                render.humanize_auth_result(
                    row.get("auth_result"), short=True, verdict=verdict_str
                ),
                widths["auth"],
            )
        ),
        "action": Text(_truncate(str(row.get("action_type") or "-"), widths["action"])),
        "why": Text(_truncate(_reason_codes_words(row), widths["why"])),
    }
    if not hide_target:
        cells["target"] = Text(
            _truncate(str(row.get("target_path_class") or "-"), widths["target"])
        )
    return tuple(cells[header] for header in _headers_for(hide_target=hide_target))


def _why_header_line(row: dict, time_line: str) -> str:
    """First line of the full-screen why: the row's identity at a glance -
    verdict glyph, absolute UTC time + relative age, risk, action type,
    target class - so paging through BLOCK/AUTH rows with b/B/a never loses
    track of which row is on screen (round 3 design critique item 4). `time_line`
    is `_abs_utc_and_age(row)` (round 7 design critique item 2) - passed in
    rather than computed here so every caller shares one "now" per render."""
    verdict_str = str(row.get("final_verdict") or "-")
    glyph = _VERDICT_GLYPHS.get(verdict_str, "?")
    risk_str = str(row.get("risk") or "-")
    action_str = str(row.get("action_type") or "-")
    target_str = str(row.get("target_path_class") or "-")
    return f"{glyph} {verdict_str}  {time_line}  {risk_str}  {action_str}  {target_str}"


def _set_focus_title(widget: Widget, *, focused: bool) -> None:
    """Set/clear a widget's `[focus]` border title (round 5 design critique
    item 8). Always a `Text` object, never a plain str - `border_title`'s
    setter otherwise parses a str as Textual markup, and a literal
    "[focus]" would be swallowed as an (invalid, empty) markup tag rather
    than displayed."""
    widget.border_title = Text("[focus]") if focused else Text("")


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

    def on_focus(self) -> None:
        # A second, non-color cue that this pane has focus (round 5 design
        # critique item 8) - the border's own color-only change is invisible
        # under NO_COLOR/limited palettes. A message handler, deliberately
        # NOT `watch_has_focus`: overriding that reactive watcher (even as a
        # no-op) breaks Textual's own `:focus` CSS pseudo-class re-styling on
        # blur - some internal machinery keys off that exact method name.
        # `DecisionExplainerApp._sync_focus_titles` seeds the INITIAL state
        # (this handler never fires for the app's own auto-focus at startup).
        _set_focus_title(self, focused=True)

    def on_blur(self) -> None:
        _set_focus_title(self, focused=False)


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

    def on_focus(self) -> None:
        # Same second focus cue as `_DecisionTable` (round 5 design critique
        # item 8) - see its `on_focus` docstring for why this is a message
        # handler and not `watch_has_focus`.
        _set_focus_title(self, focused=True)

    def on_blur(self) -> None:
        _set_focus_title(self, focused=False)


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
        # round 4 design critique item 4: `y` works from inside this screen
        # too - copies the SAME row this screen is currently showing, by
        # delegating to the App's own action (single source of truth).
        Binding("y", "copy_action_id", "copy id", show=True),
        # round 7 design critique item 5: `?` works from inside the why
        # screen too - it opens the SAME help modal on top of it (escape pops
        # back to this screen, same as everywhere else).
        Binding("question_mark", "help", "help", show=True),
    ]

    #: The last text `_refresh` set, WITHOUT any scroll cue prepended - kept
    #: separately so `_refresh_scroll_cue` can recompute the cued/uncued
    #: version without stacking a duplicate cue on every resize.
    _why_base: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="why-scroll"):
            yield Static("", id="why-text", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()

    def on_resize(self) -> None:
        self._refresh_scroll_cue()

    def _refresh(self) -> None:
        app: DecisionExplainerApp = self.app  # type: ignore[assignment]
        row = app.current_row()
        self._why_base = app.full_why_text(row) if row is not None else ""
        self._refresh_scroll_cue()

    def _refresh_scroll_cue(self) -> None:
        # Same pattern as `HelpScreen._refresh_scroll_cue` (round 7 design
        # critique item 3): only earns the cue when the body actually
        # overflows the viewport, and as the FIRST line - a cue only visible
        # after already scrolling to the bottom never told anyone up front
        # that there was more to see. Measured SYNCHRONOUSLY via
        # `Static.get_content_height` (see
        # `DecisionExplainerApp._refresh_why_panel_scroll_cue`'s docstring
        # for why `virtual_size` alone is not reliable here: this screen's
        # content changes every time `b`/`B`/`a` jumps to a new row).
        scroll = self.query_one("#why-scroll", VerticalScroll)
        static = self.query_one("#why-text", Static)
        # The Static was constructed with markup=False (see compose) - it
        # embeds row-derived strings and must always render literally.
        static.update(self._why_base)
        width = static.content_size.width or scroll.size.width
        if not width or not scroll.size.height:
            return
        content_height = static.get_content_height(scroll.size, scroll.size, width)
        if content_height <= scroll.size.height:
            return
        static.update(f"{_HELP_SCROLL_CUE}\n\n{self._why_base}")

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

    def action_copy_action_id(self) -> None:
        self.app.action_copy_action_id()  # type: ignore[attr-defined]

    def action_help(self) -> None:
        # `HelpScreen` is itself a `ModalScreen`, so pushing it here works the
        # same way it does from the main browser - the modal chain truncates
        # at whichever modal is topmost, so this is only ever reachable while
        # `WhyScreen` (not `HelpScreen`) is on top; no double-push is possible.
        self.app.push_screen(HelpScreen())


#: Appended only when the help body doesn't fit the screen (see
#: `HelpScreen._refresh_scroll_cue`) - round 5 design critique item 5.
_HELP_SCROLL_CUE = "(scroll for more)"


class HelpScreen(ModalScreen[None]):
    """`?`: every keybinding this app has, in plain words.

    Modal (round 5 design critique item 4): a plain `Screen` still forwards
    keys it doesn't bind itself down to the App underneath, so `w`/`b`/`B`/`a`
    used to silently open/jump the main browser while this screen sat on top
    of it. As a `ModalScreen`, the app-level bindings for those keys are
    simply unreachable while this screen is the top of the stack - the
    App's `action_help`/`action_open_why`/etc. also guard explicitly (see
    `DecisionExplainerApp`), so the behavior doesn't depend on that Textual
    internal alone.
    """

    BINDINGS = [
        Binding("escape", "close", "close"),
        Binding("q", "close", "close", show=False),
    ]

    # round 4 design critique item 7: four short groups (every line <= 76
    # chars, so nothing wraps at 80 columns) instead of one long flat list.
    _TEXT = (
        "Doberman decision log - keyboard reference\n"
        "\n"
        "Navigate\n"
        "  tab          move focus between the table and the why panel\n"
        "  b / B        next / previous BLOCK (also inside the why screen)\n"
        "  a            next AUTH (also inside the why screen)\n"
        "  home / end   jump to the first / last row (any focused widget)\n"
        "\n"
        "Find\n"
        "  /            filter rows (enter keeps it, escape clears it) -\n"
        "               matches verdict, action, target, reason codes\n"
        "  escape       clear an active filter (works from the table too),\n"
        "               or close the why / help screen\n"
        "\n"
        "Read\n"
        "  enter, w     open the full-screen why panel for the selected row\n"
        "  y            copy the selected action id (also in the why screen)\n"
        "\n"
        "App\n"
        "  r            reload\n"
        "  ?            this help screen\n"
        "  q            quit; closes the why/help screen instead (same as\n"
        "               escape) whenever one is open\n"
    )

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="help-scroll"):
            yield Static(self._TEXT, id="help-text", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.call_after_refresh(self._refresh_scroll_cue)

    def on_resize(self) -> None:
        self._refresh_scroll_cue()

    def _refresh_scroll_cue(self) -> None:
        # Only earns the cue when the body actually overflows the viewport -
        # a fixed line would be a lie at a tall enough terminal (round 5
        # design critique item 5). As the FIRST line, not appended at the end
        # (round 6 design critique item 6): a cue only visible after already
        # scrolling to the bottom never told anyone up front that there was
        # more to see - the whole point of a scroll cue is to be seen BEFORE
        # scrolling.
        scroll = self.query_one("#help-scroll", VerticalScroll)
        overflows = scroll.virtual_size.height > scroll.size.height
        text = f"{_HELP_SCROLL_CUE}\n\n{self._TEXT}" if overflows else self._TEXT
        self.query_one("#help-text", Static).update(text)

    def action_close(self) -> None:
        self.app.pop_screen()


class _AdaptiveFooter(Footer):
    """The main browser's `Footer`, swapped while the filter `Input` has
    focus (round 6 design critique item 9): "/ filter" is hidden - `Input`
    consumes "/" itself as a character keystroke, so showing "/ filter" while
    already inside the filter box would suggest pressing it does something it
    does not (types a literal "/" into the search text instead) - and a
    synthetic "enter keep" entry takes its place, since `Input`'s OWN key
    handling submits the value on Enter (`on_input_submitted`) with no
    App-level binding of its own to hang a real footer entry off of. ("esc
    clear" needs no special-casing here - `check_action("clear_filter", ...)`
    already returns `True` while the filter has focus, see
    `DecisionExplainerApp.check_action`, so the real `escape` `FooterKey`
    already appears via the normal path below.)

    Round 7 design critique item 4 retires the round 5 narrow-width
    filtering this class used to also do: `B`/`a`/`y` are now permanently
    `show=False` in `DecisionExplainerApp.BINDINGS` (help-only - see `?`),
    and `r`/"reload" is now permanently `show=True` - so the footer's
    steady-state set (`w`/`/`/`b`/`?`/`q`/`r`) is the same fixed 6 at ANY
    width, with no narrow/wide distinction left to make here. It still hides
    every entry except `q`/"quit" while the app is below the minimum
    terminal size (`DecisionExplainerApp._too_small`) - deliberately here,
    not via `check_action`, the same reason the old narrow-width filtering
    lived here too: every OTHER key (`?` help included) must keep WORKING
    even while its footer entry is hidden - a confused reader on a too-small
    terminal can still reach `?`.
    """

    def _filter_focused(self) -> bool:
        try:
            return self.screen.focused is self.screen.query_one("#filter", Input)
        except Exception:  # noqa: BLE001 — defensive: nothing focused/mounted yet
            return False

    def compose(self) -> ComposeResult:
        too_small = getattr(self.app, "_too_small", False)
        filter_focused = self._filter_focused()
        for widget in super().compose():
            if too_small and isinstance(widget, FooterKey) and widget.action != "quit":
                continue
            if filter_focused and isinstance(widget, FooterKey) and widget.action == "filter":
                continue
            yield widget
        if filter_focused and not too_small:
            # Synthetic - not a real bound action (see the class docstring).
            # `key="enter"` still makes a click on it do the right thing:
            # `FooterKey.on_mouse_down` simulates that literal key, not the
            # (here empty) `action` string.
            yield FooterKey("enter", "enter", "keep", "")


#: Below this width/height, the app shows one honest line instead of a
#: DataTable/panels that can't lay out at that size (round 5 design critique
#: item 10). 76 = the sum of the column minimums (multi-day time) plus
#: DataTable's cell padding - measured, not a round number: at 60 columns the
#: table's virtual width is 68 and it scrolls sideways. 16 (round 6 design
#: critique item 3, raised from 12) = the smallest height at which the docked
#: why panel (`#explanation-scroll`, `min-height: 5` in CSS - 2 border rows +
#: 3 content rows) still shows at least 3 lines alongside the docked Next
#: line and a usable table - measured the same way, not a round number.
_MIN_TERMINAL_WIDTH = 76
_MIN_TERMINAL_HEIGHT = 16
_MSG_TOO_SMALL = (
    f"Terminal too small - resize to at least {_MIN_TERMINAL_WIDTH}x{_MIN_TERMINAL_HEIGHT}"
)


class DecisionExplainerApp(App[None]):
    """Browse the redacted decision log; show `explain_decision` for the selected row."""

    TITLE = "Doberman decision log"
    # This app has no command palette of its own, and the default `^p palette`
    # footer entry docks over the right edge of the footer - at 80 columns it
    # visually overlaps the tail of "next AUTH" (design critique item 1).
    ENABLE_COMMAND_PALETTE = False

    # round 7 design critique item 4: a fixed 6-entry footer at ANY width -
    # "w why  / filter  b next BLOCK  ? help  q quit  r reload" - never more,
    # never fewer (superseding round 5 item 2's narrow-width dropping of a
    # DIFFERENT four). `B`/`a`/`y` are keyboard-only now (`show=False`) -
    # still fully live, documented in `?` (`HelpScreen._TEXT`) and in the
    # `WhyScreen` modal's own footer, just never a main-browser footer entry.
    # `escape` is deliberately declared with show=True but gated dynamically
    # via `check_action` - it only appears while a filter is active, so it is
    # never a footer entry that does nothing.
    BINDINGS = [
        Binding("w", "open_why", "why", show=True),
        Binding("/", "filter", "filter", show=True),
        Binding("b", "next_block", "next BLOCK", show=True),
        Binding("question_mark", "help", "help", show=True),
        Binding("q", "quit", "quit", show=True),
        Binding("r", "reload", "reload", show=True),
        Binding("B", "prev_block", "prev BLOCK", show=False),
        Binding("a", "next_auth", "next AUTH", show=False),
        Binding("y", "copy_action_id", "copy id", show=False),
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
        /* round 6 design critique item 8: no uniform `color` here - the
           legend renders at the normal `$text` color, only the date itself
           is dimmed (see `_date_bar_text`'s `Text.stylize("dim", ...)`). */
        padding: 0 1;
    }
    #loading {
        height: 1;
    }
    #decisions {
        height: 2fr;
        border: solid $panel;
        /* round 6 design critique item 1: the width budget (see
           `_BORDER_COLUMNS`) is sized to fit, but this is an unconditional
           second guarantee - no horizontal scrollbar ever appears, no matter
           what. */
        overflow-x: hidden;
    }
    #decisions:focus {
        border: solid $accent;
    }
    #filter {
        dock: bottom;
    }
    #explanation-scroll {
        height: 1fr;
        min-height: 5;
        border: solid $panel;
    }
    #explanation-scroll:focus {
        border: solid $accent;
    }
    #explanation {
        padding: 1;
    }
    /* auto/max-height (round 4 design critique item 1): a fixed height: 1
       silently clipped the "Next" text to whatever fit on one line - it must
       always be fully visible instead, wrapping onto up to 3 lines. */
    #next-line {
        height: auto;
        max-height: 3;
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
        # (body, provenance) - kept separate so the docked panel can style the
        # provenance line as muted without re-parsing anything (item 6).
        self._explain_cache: dict[str, tuple[str, str]] = {}
        self._explain_timer = None
        self._load_worker: Worker[None] | None = None
        self._widths: dict[str, int] = dict(_WIDTHS)
        self._headers: tuple[str, ...] = _HEADERS
        self._columns_ready = False
        self._multi_day = False
        self._hide_target = False
        # The `target` column's content-driven width need (round 7 design
        # critique item 1) - recomputed from the loaded rows in `_load_rows`.
        self._target_need = _TARGET_WIDTH_FLOOR
        self._gutter_row: int | None = None
        self._too_small = False
        # The docked why panel's last content, WITHOUT any scroll cue
        # prepended (round 7 design critique item 3) - kept separately so
        # `_refresh_why_panel_scroll_cue` can recompute the cued/uncued
        # version without stacking a duplicate cue on every resize.
        self._panel_base: str | Text = ""

    def compose(self) -> ComposeResult:
        yield Header()
        # markup=False: the date bar embeds the selected row's date - render
        # it literally, same guarantee as every other row-derived Static.
        yield Static("", id="date-bar", markup=False)
        yield LoadingIndicator(id="loading")
        # Shown INSTEAD of "#body" below `_MIN_TERMINAL_WIDTH`x`_MIN_TERMINAL_HEIGHT`
        # (round 5 design critique item 10) - toggled by `_apply_size_gate`.
        too_small = Static(_MSG_TOO_SMALL, id="too-small", markup=False)
        too_small.display = False
        yield too_small
        with Vertical(id="body"):
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
        yield _AdaptiveFooter()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # round 7 design critique item 4: `next_auth`'s footer entry moved to
        # help-only (see `BINDINGS`), but the key must still be a genuine
        # no-op - not just a "no AUTH rows in view" notify every time - when
        # the LOADED window (`_rows`, not the current filter's
        # `_visible_rows`) has no AUTH row at all to ever jump to.
        if action == "next_auth" and not any(
            row.get("final_verdict") == Verdict.AUTH.value for row in self._rows
        ):
            return False
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
        # round 5 design critique item 9: with nothing loaded at all, there is
        # nothing to filter - hide the footer entry rather than offer a search
        # box over zero rows.
        if action == "filter" and not self._rows:
            return False
        # round 4 design critique item 3: with no rows to act on (nothing
        # loaded, or the filter matched zero rows) these five actions would be
        # dead keys - hide them from the footer instead of leaving a binding
        # that visibly does nothing when pressed.
        if action in _ROW_ACTIONS and not self._visible_rows:
            return False
        return True

    async def on_mount(self) -> None:
        self._apply_size_gate()
        table = self.query_one("#decisions", _DecisionTable)
        self._widths = _widths_for(self.size.width)
        self._headers = _HEADERS
        for header in _HEADERS:
            table.add_column(header, width=self._widths[header], key=header)
        self._columns_ready = True
        self.query_one("#filter", Input).display = False
        self.query_one("#loading", LoadingIndicator).display = False
        self._update_subtitle()
        # Seed the initial `[focus]` border title (round 5 design critique
        # item 8): the app's own default auto-focus at startup never posts a
        # Focus message, so `_DecisionTable`/`_WhyPanel`'s own `on_focus`
        # never fires for it - only a later `tab` does.
        for pane in (table, self.query_one("#explanation-scroll", _WhyPanel)):
            _set_focus_title(pane, focused=pane.has_focus)
        self._load_worker = self._load_rows()

    async def wait_loaded(self) -> None:
        """Test helper: wait for the current (or most recently started) load."""
        if self._load_worker is not None:
            await self._load_worker.wait()

    def _apply_size_gate(self) -> None:
        """Below `_MIN_TERMINAL_WIDTH`x`_MIN_TERMINAL_HEIGHT`, swap the whole
        body for one honest line instead of a DataTable/panels that can't lay
        out at that size (round 5 design critique item 10) - and (round 7
        item 4) hide every OTHER footer entry via `_AdaptiveFooter`, so the
        too-small notice's own footer only offers `q`/"quit" (every key stays
        live regardless - see that class's docstring)."""
        too_small = self.size.width < _MIN_TERMINAL_WIDTH or self.size.height < _MIN_TERMINAL_HEIGHT
        self._too_small = too_small
        self.query_one("#too-small", Static).display = too_small
        self.query_one("#body", Vertical).display = not too_small
        self.query_one("#date-bar", Static).display = not too_small
        self.refresh_bindings()

    # --- loading -----------------------------------------------------------

    @work(exclusive=True)
    async def _load_rows(self) -> None:
        loading = self.query_one("#loading", LoadingIndicator)
        loading.display = True
        try:
            path = db_path(self._repo_root)
            if not path.exists():
                self._rows = []
                self._hide_target = False
                self._target_need = _TARGET_WIDTH_FLOOR
                self._reset_to_empty(
                    f"No decision log at {_shorten_home(path)}. "
                    "Press q to quit, then rerun with --path <repo>. "
                    # round 6 design critique item 11: name the REAL first
                    # step - a missing decision log almost always means
                    # Doberman was never set up here at all, not just that
                    # `--path` pointed somewhere else.
                    "Run 'doberman setup' here to start guarding this repo."
                )
                return
            rows = await read_decisions(self._repo_root, limit=self._last)
            self._rows = rows
            self._multi_day = _spans_multiple_days(rows)
            self._hide_target = _all_targets_missing(rows)
            self._target_need = _target_width_need(rows)
            self._apply_widths(
                _widths_for(
                    self.size.width,
                    multi_day=self._multi_day,
                    hide_target=self._hide_target,
                    target_need=self._target_need,
                ),
                _headers_for(hide_target=self._hide_target),
            )
            if not rows:
                self._reset_to_empty(_MSG_NO_ROWS)
                return
            self._apply_filter()
        finally:
            loading.display = False

    def _apply_widths(self, widths: dict[str, int], headers: tuple[str, ...] | None = None) -> bool:
        """Re-declare the table's columns at ``widths``/``headers``. Returns
        whether anything changed - callers rebuild the row data only when it
        did. ``headers`` defaults to the current header set (a pure width
        change, e.g. a resize); it differs only when ``target`` is hidden or
        restored (round 5 design critique item 3)."""
        headers = headers if headers is not None else self._headers
        if widths == self._widths and headers == self._headers:
            return False
        table = self.query_one("#decisions", _DecisionTable)
        for header in self._headers:
            try:
                table.remove_column(header)
            except Exception:  # noqa: BLE001, S110 — defensive: header already gone
                pass
        for header in headers:
            table.add_column(header, width=widths[header], key=header)
        self._widths = widths
        self._headers = headers
        return True

    def on_resize(self) -> None:
        """Re-fit the columns: spare width goes to why, never a scrollbar.
        Also re-gates the too-small notice and re-evaluates which footer
        bindings fit (round 5 design critique items 2 + 10)."""
        self._apply_size_gate()
        if not self._columns_ready:
            # The first layout resize lands before on_mount adds the columns.
            return
        widths = _widths_for(
            self.size.width,
            multi_day=self._multi_day,
            hide_target=self._hide_target,
            target_need=self._target_need,
        )
        if self._apply_widths(widths, _headers_for(hide_target=self._hide_target)):
            self._rebuild_table()
        self.refresh_bindings()
        # A resize can flip the docked why panel's overflow state without any
        # new `_set_panel` call (round 7 design critique item 3).
        self._refresh_why_panel_scroll_cue()

    def _reset_to_empty(self, message: str) -> None:
        self._visible_rows = []
        self.refresh_bindings()  # see `_rebuild_table` - same footer-staleness fix
        self._multi_day = False
        self._hide_target = False
        self._target_need = _TARGET_WIDTH_FLOOR
        self._gutter_row = None
        self._apply_widths(
            _widths_for(self.size.width, multi_day=False, hide_target=False), _HEADERS
        )
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
        # `check_action` reads `self._visible_rows` (round 4 design critique
        # item 3) but the Footer/binding display only re-polls it on an
        # explicit nudge - without this, a load/filter that flips
        # rows-vs-no-rows would leave the footer showing stale bindings.
        self.refresh_bindings()
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
                *_row_cells(
                    row, self._widths, multi_day=self._multi_day, hide_target=self._hide_target
                ),
                key=_row_key(row),
            )
        # Restore the previously selected row by key rather than snapping to
        # row 0 - a resize (or a filter edit that still matches it) must not
        # lose the reviewer's place (design critique item 10). `previous_key`
        # is only ever `None` before anything has EVER been selected in this
        # app instance (see `_show_explanation`, which sets it) - i.e. this is
        # the very first table build after a fresh load, never a later filter
        # edit or resize - so that's the one moment `_initial_landing_index`
        # (round 6 design critique item 5) gets to land somewhere other than
        # row 0: on the newest BLOCK/AUTH row, so a reviewer opening the
        # browser doesn't have to scroll past a wall of PASS rows to find what
        # actually needs attention. `home` still goes to row 0 regardless
        # (`action_goto_first`), and a `previous_key` that no longer matches
        # any visible row (filtered out) still falls back to row 0, not this.
        restore_index = _initial_landing_index(self._visible_rows) if previous_key is None else 0
        if previous_key is not None:
            for index, row in enumerate(self._visible_rows):
                if _row_key(row) == previous_key:
                    restore_index = index
                    break
        table.move_cursor(row=restore_index, scroll=True)
        self._show_explanation(restore_index)

    def _update_subtitle(self) -> None:
        # Count first: it must survive truncation at narrow widths, the path
        # is the part that's safe to lose (design critique item 9).
        total = len(self._rows)
        # If the load hit the `--last` cap, say so explicitly - "3 of 3" reads
        # as "that's everything" when it may not be (round 3 design critique
        # item 5).
        suffix = f" (last {total}; --last for more)" if self._last and total == self._last else ""
        # Verdict breakdown (round 6 design critique item 4): over the LOADED
        # rows (`self._rows`), never the filtered `self._visible_rows` - the
        # filter narrows which rows are shown, not how many of each verdict
        # actually exist in the loaded window. Omitted entirely when nothing
        # is loaded - nothing to break down yet.
        counts = f" - {_verdict_counts_text(self._rows)}" if self._rows else ""
        self.sub_title = (
            f"showing {len(self._visible_rows)} of {total}{suffix}{counts} - {self._repo_root}"
        )

    # --- selection / why panel ------------------------------------------------

    def _set_panel(self, text: str | Text) -> None:
        self._panel_base = text
        self._refresh_why_panel_scroll_cue()

    def _refresh_why_panel_scroll_cue(self) -> None:
        """Prepend a muted `_HELP_SCROLL_CUE` as the docked why panel's first
        line whenever its content overflows the visible height - same pattern
        as `HelpScreen._refresh_scroll_cue` (round 7 design critique item 3),
        but re-run on every panel update (not just resize), since unlike the
        help screen's fixed text, this panel's content changes on every row
        selection/filter edit.

        Measures the overflow SYNCHRONOUSLY via `Static.get_content_height`
        (the content's own required height at its current render width)
        rather than reading the scroll container's `virtual_size` after a
        deferred `call_after_refresh` - `virtual_size` is a framework-derived
        property that can still reflect the PREVIOUS (possibly taller)
        content for one tick right after a rapid content swap, which showed
        up as a stuck stale cue under load once content had already gone
        back to something short.
        """
        try:
            scroll = self.query_one("#explanation-scroll", _WhyPanel)
            static = self.query_one("#explanation", Static)
        except Exception:  # noqa: BLE001 — defensive: not mounted yet
            return
        base = self._panel_base
        static.update(base)
        width = static.content_size.width or scroll.size.width
        height = scroll.size.height
        if not width or not height or base == "":
            return
        content_height = static.get_content_height(scroll.size, scroll.size, width)
        if content_height <= height:
            return
        cue = Text(_HELP_SCROLL_CUE, style="dim")
        combined: str | Text = (
            Text("\n\n").join([cue, base])
            if isinstance(base, Text)
            else f"{_HELP_SCROLL_CUE}\n\n{base}"
        )
        static.update(combined)

    def _update_date_bar(self, row: dict | None) -> None:
        # No legend when nothing is loaded at all - "nothing to filter"
        # applies here too (round 5 design critique item 9): the glyphs
        # aren't worth explaining for a browser with zero rows in it.
        text = _date_bar_text(row) if self._rows else ""
        self.query_one("#date-bar", Static).update(text)

    def _update_next_line(self, row: dict | None) -> None:
        # Docked separately from the panel body (round 3 design critique item
        # 3) so it stays on screen even while the why panel itself scrolls.
        # tui_hint stays True here (the default) - this IS the "press w for
        # detail" affordance; the full-screen why (`full_why_text`) is the
        # detail itself and must not repeat it (round 5 design critique item 1).
        next_line = render.next_step_line(row.get("final_verdict")) if row is not None else None
        widget = self.query_one("#next-line", Static)
        widget.update(_next_line_text(next_line) if next_line else "")

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
        # Computed once per selection (round 7 design critique item 2), not on
        # a live-updating timer - re-selecting the same row later recomputes a
        # fresh age, but simply leaving it on screen never ticks.
        time_line = _abs_utc_and_age(row)
        self._update_date_bar(row)
        self._update_next_line(row)
        self._update_gutter(index)
        cached = self._explain_cache.get(key)
        if cached is not None:
            body, provenance = cached
            self._set_panel(_panel_text(body, provenance, time_line=time_line))
            return
        body = template_explanation(row)
        if not llm_enrichment_enabled():
            # Nothing to enrich with - never schedule a worker that would only
            # ever return the same template text.
            self._explain_cache[key] = (body, _PROV_TEMPLATE)
            self._set_panel(_panel_text(body, _PROV_TEMPLATE, time_line=time_line))
            return
        self._set_panel(_panel_text(body, _PROV_PENDING, time_line=time_line))
        if self._explain_timer is not None:
            self._explain_timer.stop()
        self._explain_timer = self.set_timer(
            _EXPLAIN_DEBOUNCE_S, lambda: self._explain_worker(row, time_line)
        )

    @work(thread=True, exclusive=True, group="explain")
    def _explain_worker(self, row: dict, time_line: str) -> None:
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

        def _apply() -> None:
            # Runs on the UI thread: re-check the selection so a slow (opt-in)
            # LLM call can never overwrite a newer row's panel with stale text.
            # `time_line` is the one captured at selection time (round 7 item
            # 2), not recomputed here - the age must not drift just because
            # the LLM call took a few extra seconds.
            self._explain_cache[key] = (text, provenance)
            if self._current_key == key:
                self._set_panel(_panel_text(text, provenance, time_line=time_line))

        try:
            self.call_from_thread(_apply)
        except Exception:  # noqa: BLE001, S110 — app may have exited mid-flight; never crash on it
            return

    def full_why_text(self, row: dict) -> str:
        """The complete why text for `row`: a row-identity header line, cached
        body, every reason code, the action id, a muted provenance note, and a
        "Next" step - what `WhyScreen` displays (round 3 design critique item
        4: paging through rows with b/B/a must never lose track of which row
        is on screen; round 5 item 6: the explanation leads, the provenance
        note trails near the end, same as the docked panel)."""
        header = _why_header_line(row, _abs_utc_and_age(row))
        key = _row_key(row)
        cached = self._explain_cache.get(key)
        body, provenance = (
            cached if cached is not None else (template_explanation(row), _PROV_TEMPLATE)
        )
        action_id = row.get("action_id") or "-"
        text = (
            f"{header}\n\n{body}\n\n"
            f"reason codes: {_reason_codes_text(row)}\naction id: {action_id}\n\n{provenance}"
        )
        # tui_hint=False (round 5 design critique item 1): this full-screen
        # why IS the detail "press w for detail" points at - it must not tell
        # the reader to press w again to see itself.
        next_line = render.next_step_line(row.get("final_verdict"), tui_hint=False)
        return f"{text}\n\n{next_line}" if next_line else text

    def current_row(self) -> dict | None:
        """The row currently under the table cursor, or `None` if there isn't one."""
        index = self._cursor_index()
        if index is None or index >= len(self._visible_rows):
            return None
        return self._visible_rows[index]

    def _help_open(self) -> bool:
        """Whether a `HelpScreen` is the current top screen - `?`/`w`/`b`/`B`/
        `a` must all be inert while it's open (round 5 design critique item
        4). `HelpScreen` being a `ModalScreen` already makes these keys
        unreachable from the keyboard on their own (see its docstring); this
        guard makes the App's own actions defensive regardless of how they're
        invoked."""
        return isinstance(self.screen, HelpScreen)

    def _open_why_screen(self) -> None:
        if self.current_row() is not None:
            self.push_screen(WhyScreen())

    def action_open_why(self) -> None:
        if self._help_open():
            return
        self._open_why_screen()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # DataTable's own "enter" binding fires `select_cursor`, which posts
        # this message - it never reaches our App-level "enter" binding while
        # the table is focused, so hook the same behavior here too.
        self._open_why_screen()

    def action_help(self) -> None:
        if self._help_open():  # never stack a second HelpScreen
            return
        self.push_screen(HelpScreen())

    # --- next/prev BLOCK, next AUTH, copy id ----------------------------------

    def _cursor_index(self) -> int | None:
        cursor_row = self.query_one("#decisions", _DecisionTable).cursor_row
        return cursor_row if cursor_row is not None and cursor_row >= 0 else None

    def jump_to_verdict(self, verdict: str, *, forward: bool) -> bool:
        """Move the table cursor to the next/previous row whose verdict is
        `verdict` (wrapping around). Returns whether it moved, so a caller
        (e.g. `WhyScreen`) knows whether to re-render; notifies the user when
        nothing matches rather than silently doing nothing.

        ``scroll=True`` (round 6 design critique item 2, explicit here even
        though it's `move_cursor`'s own default): a jump this far from the
        current row is exactly the case that must never land off-screen."""
        rows = self._visible_rows
        total = len(rows)
        if total:
            start = self._cursor_index()
            start = start if start is not None else (0 if forward else total - 1)
            step = 1 if forward else -1
            for offset in range(1, total + 1):
                index = (start + offset * step) % total
                if rows[index].get("final_verdict") == verdict:
                    self.query_one("#decisions", _DecisionTable).move_cursor(row=index, scroll=True)
                    return True
        self.notify(f"no {verdict} rows in view", markup=False)
        return False

    def action_next_block(self) -> None:
        if self._help_open():
            return
        self.jump_to_verdict(Verdict.BLOCK.value, forward=True)

    def action_prev_block(self) -> None:
        if self._help_open():
            return
        self.jump_to_verdict(Verdict.BLOCK.value, forward=False)

    def action_next_auth(self) -> None:
        if self._help_open():
            return
        self.jump_to_verdict(Verdict.AUTH.value, forward=True)

    def action_goto_first(self) -> None:
        self._jump_cursor(0)

    def action_goto_last(self) -> None:
        table = self.query_one("#decisions", _DecisionTable)
        if table.row_count:
            self._jump_cursor(table.row_count - 1)

    def _jump_cursor(self, index: int) -> None:
        # scroll=True (round 6 design critique item 2, see `jump_to_verdict`):
        # home/end must keep the first/last row on screen too.
        table = self.query_one("#decisions", _DecisionTable)
        if table.row_count:
            table.move_cursor(row=index, scroll=True)

    def action_copy_action_id(self) -> None:
        index = self._cursor_index()
        if index is None or index >= len(self._visible_rows):
            return
        action_id = str(self._visible_rows[index].get("action_id") or "")
        if not action_id:
            return
        self.copy_to_clipboard(action_id)
        # markup=False: the id is row-derived text and must render literally.
        # round 4 design critique item 9: OSC 52 is the mechanism, not
        # something a reader needs named - just be honest that it's a request.
        message = f"copy requested: {action_id} - your terminal decides whether it lands"
        self.notify(message, markup=False)


def run_tui(repo_root: str, *, last: int = 500) -> None:
    """Launch the decision-transparency TUI. Entry point for `doberman tui`."""
    DecisionExplainerApp(repo_root, last=last).run()
