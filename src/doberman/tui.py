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
from textual.css.query import NoMatches
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
#: Absolute minimum `target` may shrink to (round 8 design critique item 2) -
#: below `_TARGET_WIDTH_FLOOR`, `target`'s STARTING width now shrinks toward
#: the data's real need instead of sitting pinned at the floor: when every
#: loaded value is genuinely short (".env", or missing - "-"), padding the
#: column out to 8 wastes width `why` could use instead. Real/longer values
#: are unaffected - they still start at the floor and grow from there (see
#: `_widths_for`).
_TARGET_WIDTH_MIN = 4
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
    `target_path_class` among ``rows``, floored at ``_TARGET_WIDTH_MIN`` (not
    ``_TARGET_WIDTH_FLOOR`` - round 8 design critique item 2 supersedes round
    7 item 1's fixed floor-of-8: an all-short column like ".env"/"-" must be
    able to report a real need as low as 4, so ``_widths_for`` can shrink
    `target`'s STARTING width to match instead of always paying for 8) and
    capped at ``_TARGET_WIDTH_CAP`` - real values like "backend/secrets/*.env"
    need more than the old fixed 6, but one outlier-long value should never
    swallow the whole `why` budget. Vacuously the FLOOR (not the min) for an
    empty/not-yet-loaded ``rows`` - nothing measured yet, so this keeps the
    old default-load behavior unchanged."""
    longest = max(
        (len(str(row.get("target_path_class") or "")) for row in rows),
        default=_TARGET_WIDTH_FLOOR,
    )
    return max(_TARGET_WIDTH_MIN, min(_TARGET_WIDTH_CAP, longest))


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


#: Below this terminal width, `risk` and `auth` drop out of the table
#: entirely (round 8 design critique item 2) - both are already restated in
#: the why panel/full-screen why, so at a narrow terminal they cost two whole
#: columns (+padding) that `target`/`why` need more.
_NARROW_COLUMNS_WIDTH = 100


def _widths_for(
    terminal_width: int,
    *,
    multi_day: bool = False,
    hide_target: bool = False,
    hide_risk_auth: bool = False,
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

    ``target``'s STARTING width (round 8 design critique item 2) is the
    SMALLER of ``_TARGET_WIDTH_FLOOR`` and ``target_need`` - a genuinely long
    value (need > floor) still starts at the floor and grows from there,
    unchanged from round 7; an all-short column (need < floor, e.g. every
    loaded value is ".env" or missing) starts BELOW the floor instead, at
    its real need (down to ``_TARGET_WIDTH_MIN``), donating the difference
    to ``why`` rather than padding `target` out to a width nothing needs.

    ``why`` keeps its own floor (8) regardless (round 6 design critique item
    1 reserves one more column for Textual's own vertical scrollbar - see
    ``_BORDER_COLUMNS`` - a smaller cost than a spurious horizontal
    scrollbar).

    ``multi_day`` widens ``time`` to fit "MM-DD HH:MM" (see ``_time_cell``) -
    that extra width comes out of the same spare pool ``target``/``why``
    would otherwise share, never below either one's floor.

    ``hide_target=True`` (every loaded row's target is "-" - see
    :func:`_all_targets_missing`) drops the ``target`` key entirely BEFORE the
    spare-width math runs, so one column fewer consuming the budget
    automatically folds its reclaimed width (plus its own cell padding) into
    ``why`` - the caller is expected to also stop adding a ``target`` column
    to the table in that case.

    ``hide_risk_auth=True`` (terminal narrower than ``_NARROW_COLUMNS_WIDTH``)
    likewise drops ``risk``/``auth`` entirely - both are restated in the why
    panel/full-screen why, so at a narrow width they cost more than they earn
    the caller is expected to also stop adding those columns (see
    ``_headers_for``).
    """
    widths = dict(_WIDTHS)
    if multi_day:
        widths["time"] = _TIME_WIDTH_MULTI_DAY
    if hide_risk_auth:
        widths.pop("risk", None)
        widths.pop("auth", None)
    if hide_target:
        widths.pop("target", None)
    else:
        widths["target"] = min(_TARGET_WIDTH_FLOOR, target_need)
    used = sum(widths.values()) + _CELL_PADDING * len(widths)
    spare = max(0, terminal_width - used - _BORDER_COLUMNS - 1)
    if not hide_target:
        target_room = max(0, target_need - widths["target"])
        target_grow = min(spare, target_room)
        widths["target"] += target_grow
        spare -= target_grow
    widths["why"] += spare
    return widths


def _headers_for(*, hide_target: bool, hide_risk_auth: bool = False) -> tuple[str, ...]:
    """Column headers to actually declare on the table - ``_HEADERS`` minus
    ``target`` when every loaded row's target is "-" (round 5 design critique
    item 3), minus ``risk``/``auth`` below ``_NARROW_COLUMNS_WIDTH`` (round 8
    design critique item 2) - both stay fully visible in the why panel/
    full-screen why, so hiding them from the table costs nothing a reviewer
    can't get one keystroke away."""
    drop = set()
    if hide_target:
        drop.add("target")
    if hide_risk_auth:
        drop.add("risk")
        drop.add("auth")
    return tuple(h for h in _HEADERS if h not in drop)


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


def _panel_text(body: str, provenance: str) -> Text:
    """The docked why panel's BODY content: `body` (the explanation/remedy)
    first, then a blank line, then `provenance` styled muted/dim (round 5
    design critique item 6). Round 8 design critique item 1 moves the
    absolute-time+age line OUT of this body and into `_WhyPanel.border_title`
    (see `DecisionExplainerApp._show_explanation`/`_WhyPanel.set_time_line`) -
    at a short terminal that line (plus the scroll cue, now in
    `border_subtitle` too) used to crowd the explanation itself below the
    fold, so the panel appeared to show only "(scroll for more)" and a
    timestamp. Built from a plain string only - `body`/`provenance` are never
    re-parsed as markup (this constructs a `Text` directly, the same
    literal-rendering guarantee the module docstring promises), so a crafted
    stored value still can't restyle anything; the `dim` span covers only the
    trailing provenance line we ourselves appended, never `body`.
    """
    combined = f"{body}\n\n{provenance}"
    text = Text(combined)
    text.stylize("dim", len(combined) - len(provenance), len(combined))
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
    hide_risk_auth: bool = False,
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
        "action": Text(_truncate(str(row.get("action_type") or "-"), widths["action"])),
        "why": Text(_truncate(_reason_codes_words(row), widths["why"])),
    }
    if not hide_risk_auth:
        cells["risk"] = Text(
            _truncate(risk_str, widths["risk"]), style=render.risk_rich_style(risk_str)
        )
        cells["auth"] = Text(
            _truncate(
                render.humanize_auth_result(
                    row.get("auth_result"), short=True, verdict=verdict_str
                ),
                widths["auth"],
            )
        )
    if not hide_target:
        cells["target"] = Text(
            _truncate(str(row.get("target_path_class") or "-"), widths["target"])
        )
    return tuple(
        cells[header]
        for header in _headers_for(hide_target=hide_target, hide_risk_auth=hide_risk_auth)
    )


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

    Round 8 design critique item 1: `border_title` carries the selected row's
    absolute-time+age line (set via `set_time_line`, itself called from
    `DecisionExplainerApp._show_explanation`), with the same `[focus]` cue
    `_DecisionTable` shows appended while this pane has focus - moved here
    OUT of the panel BODY, which used to prepend that line (and the scroll
    cue) ahead of the explanation itself, crowding it below the fold at a
    short terminal.
    """

    BINDINGS = [
        Binding("home", "app.goto_first", "first", show=False),
        Binding("end", "app.goto_last", "last", show=False),
    ]

    #: The current row's absolute-time+age line (or "" - nothing selected),
    #: kept on the widget itself so `on_focus`/`on_blur` can rebuild
    #: `border_title` (time line + "[focus]") without reaching into the app.
    _time_line: str = ""

    def set_time_line(self, time_line: str) -> None:
        self._time_line = time_line
        self._refresh_border_title(focused=self.has_focus)

    def _refresh_border_title(self, *, focused: bool) -> None:
        # `focused` is passed in explicitly (never read from `self.has_focus`
        # here) - same reason `_set_focus_title` takes it as a parameter: at
        # the exact moment `on_focus`/`on_blur` fires, `self.has_focus` is
        # not yet guaranteed to reflect the NEW state.
        suffix = " [focus]" if focused else ""
        if self._time_line:
            self.border_title = Text(f"{self._time_line}{suffix}")
        else:
            self.border_title = Text(suffix.strip())

    def on_focus(self) -> None:
        # Second focus cue (round 5 design critique item 8), folded into the
        # same border_title this panel now also uses for the time line.
        self._refresh_border_title(focused=True)

    def on_blur(self) -> None:
        self._refresh_border_title(focused=False)


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
        # round 8 design critique item 4: the arrow keys and page up/down
        # are DataTable's own built-in bindings (never App-level, so they
        # don't otherwise appear here) - listed for discoverability, not
        # because this app defines them itself.
        "  up / down         move the cursor one row\n"
        "  page up / down    move the cursor a page of rows at a time\n"
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

#: Below this many terminal rows, the vertical split swaps to favor the why
#: panel over the table (round 8 design critique item 1 - see
#: `DecisionExplainerApp._apply_why_split` and the `.compact-why` CSS): a
#: reviewer at a laptop-height terminal is here to read the explanation, not
#: to see a few more table rows. Comfortably above `_MIN_TERMINAL_HEIGHT`
#: (16) - the swap engages well before the too-small gate ever would.
_COMPACT_WHY_HEIGHT = 30

#: Inside the compact-why range, `#decisions` also gets an explicit
#: min-height floor (see `_apply_why_split`) so it never shrinks to
#: near-nothing just because the why panel now claims the bigger 2fr share -
#: but ONLY once the terminal is at least this tall. Below it (down to the
#: app's own absolute floor, `_MIN_TERMINAL_HEIGHT` = 16), that floor plus
#: `#explanation-scroll`'s own CSS `min-height: 5` already exceeds the whole
#: available body height, which broke Textual's layout outright (measured:
#: the panel's own box overflowed past the screen's height). At that tight
#: end the why panel's own floor - real explanation lines, the actual
#: priority there - wins instead; `#decisions` is simply allowed to shrink.
_DECISIONS_FLOOR_MIN_HEIGHT = 20
#: `#decisions`' own min-height once `_DECISIONS_FLOOR_MIN_HEIGHT` is met -
#: 6 visible content rows (1 DataTable header row + 5 data rows) + 2 border
#: rows.
_DECISIONS_MIN_HEIGHT_ROWS = 8


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
    /* Same slot/sizing as `#decisions` - round 8 design critique item 5:
       only one of the two is ever `display`ed at a time, so swapping between
       them never shifts the rest of the layout. */
    #empty-message {
        height: 2fr;
        border: solid $panel;
        padding: 1;
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
    /* round 8 design critique item 1: below `_COMPACT_WHY_HEIGHT` rows
       (`_apply_why_split` toggles this class on `#body`), the why panel gets
       the larger share of the split instead of the table - the explanation
       is the point. No explicit `min-height` here: at the absolute size
       floor (76x16) `#explanation-scroll`'s own `min-height: 5` already
       consumes most of the tight budget, and stacking a competing hard
       floor on `#decisions` too made the two mins jointly exceed the
       container - Textual's layout has no good answer for that (measured:
       the panel's box overflowed the screen's own height). At any size with
       real headroom (80x24 and up) the 1fr:2fr ratio alone already leaves
       the table comfortably more than 6 rows - see the round 8 pilot test. */
    .compact-why #decisions {
        height: 1fr;
    }
    .compact-why #empty-message {
        height: 1fr;
    }
    .compact-why #explanation-scroll {
        height: 2fr;
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
        # Below `_NARROW_COLUMNS_WIDTH` (round 8 design critique item 2) -
        # purely width-driven (unlike `_hide_target`), so it's set as soon as
        # the terminal size is known (`on_mount`/`on_resize`), not only after
        # a load completes.
        self._hide_risk_auth = False
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
            # Shown INSTEAD of "#decisions" (round 8 design critique item 5)
            # when there's nothing to show a table OF: no decision log, an
            # empty one, or a filter matching zero rows - occupies the same
            # layout slot rather than leaving a 0-row table on screen while
            # the message shows somewhere else. Toggled by
            # `_show_empty_message`/`_hide_empty_message`.
            empty_message = Static("", id="empty-message", markup=False)
            empty_message.display = False
            yield empty_message
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
        self._apply_why_split()
        table = self.query_one("#decisions", _DecisionTable)
        self._hide_risk_auth = self.size.width < _NARROW_COLUMNS_WIDTH
        self._widths = _widths_for(self.size.width, hide_risk_auth=self._hide_risk_auth)
        self._headers = _headers_for(hide_target=False, hide_risk_auth=self._hide_risk_auth)
        for header in self._headers:
            table.add_column(header, width=self._widths[header], key=header)
        self._columns_ready = True
        self.query_one("#filter", Input).display = False
        self.query_one("#loading", LoadingIndicator).display = False
        self._update_subtitle()
        # Seed the initial `[focus]` border title (round 5 design critique
        # item 8): the app's own default auto-focus at startup never posts a
        # Focus message, so `_DecisionTable`/`_WhyPanel`'s own `on_focus`
        # never fires for it - only a later `tab` does.
        _set_focus_title(table, focused=table.has_focus)
        # Seeds the WhyPanel's initial border_title too - same "on_focus never
        # fires for the app's own startup auto-focus" gap noted above.
        why_panel = self.query_one("#explanation-scroll", _WhyPanel)
        why_panel._refresh_border_title(focused=why_panel.has_focus)
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

    def _apply_why_split(self) -> None:
        """Below `_COMPACT_WHY_HEIGHT` rows, swap the vertical split so the
        why panel (not the table) gets the larger share (round 8 design
        critique item 1): a short terminal used to give the table 2fr and
        the why panel a cramped 1fr - backwards for what this app is FOR, a
        reviewer reading the explanation.

        `#decisions`/`#empty-message` also get an explicit min-height floor
        (set here in Python, not CSS - see `_DECISIONS_FLOOR_MIN_HEIGHT`'s
        docstring for why a STATIC CSS floor broke layout at the tightest
        terminal size) so the table doesn't shrink to near-nothing at a
        merely-short (not tiny) terminal - but only once there's actually
        room for it alongside the why panel's own floor.
        """
        body = self.query_one("#body", Vertical)
        table = self.query_one("#decisions", _DecisionTable)
        empty = self.query_one("#empty-message", Static)
        compact = self.size.height < _COMPACT_WHY_HEIGHT
        body.set_class(compact, "compact-why")
        min_height = (
            _DECISIONS_MIN_HEIGHT_ROWS
            if compact and self.size.height >= _DECISIONS_FLOOR_MIN_HEIGHT
            else 0
        )
        table.styles.min_height = min_height
        empty.styles.min_height = min_height

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
            self._hide_risk_auth = self.size.width < _NARROW_COLUMNS_WIDTH
            self._target_need = _target_width_need(rows)
            self._apply_widths(
                _widths_for(
                    self.size.width,
                    multi_day=self._multi_day,
                    hide_target=self._hide_target,
                    hide_risk_auth=self._hide_risk_auth,
                    target_need=self._target_need,
                ),
                _headers_for(hide_target=self._hide_target, hide_risk_auth=self._hide_risk_auth),
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
        change, e.g. a resize); it differs when ``target`` is hidden or
        restored (round 5 design critique item 3), or ``risk``/``auth`` cross
        the ``_NARROW_COLUMNS_WIDTH`` threshold (round 8 item 2)."""
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
        Also re-gates the too-small notice, re-applies the compact-why split
        (round 8 design critique item 1), and re-evaluates which footer
        bindings fit (round 5 design critique items 2 + 10)."""
        self._apply_size_gate()
        self._apply_why_split()
        if not self._columns_ready:
            # The first layout resize lands before on_mount adds the columns.
            return
        self._hide_risk_auth = self.size.width < _NARROW_COLUMNS_WIDTH
        widths = _widths_for(
            self.size.width,
            multi_day=self._multi_day,
            hide_target=self._hide_target,
            hide_risk_auth=self._hide_risk_auth,
            target_need=self._target_need,
        )
        headers = _headers_for(hide_target=self._hide_target, hide_risk_auth=self._hide_risk_auth)
        if self._apply_widths(widths, headers):
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
        self._hide_risk_auth = self.size.width < _NARROW_COLUMNS_WIDTH
        self._target_need = _TARGET_WIDTH_FLOOR
        self._gutter_row = None
        self._apply_widths(
            _widths_for(
                self.size.width,
                multi_day=False,
                hide_target=False,
                hide_risk_auth=self._hide_risk_auth,
            ),
            _headers_for(hide_target=False, hide_risk_auth=self._hide_risk_auth),
        )
        self.query_one("#decisions", _DecisionTable).clear()
        self._current_key = None
        self._update_date_bar(None)
        self._update_next_line(None)
        self._show_empty_message(message)
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
                self._show_empty_message(_MSG_NO_MATCH)
            return
        self._hide_empty_message()
        for row in self._visible_rows:
            table.add_row(
                *_row_cells(
                    row,
                    self._widths,
                    multi_day=self._multi_day,
                    hide_target=self._hide_target,
                    hide_risk_auth=self._hide_risk_auth,
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
        # round 8 design critique item 3: name which count is which - a bare
        # "showing 11 of 45" reads as "11 of 45 total" until the verdict
        # breakdown right after it is read as "45 loaded, 11 currently shown"
        # instead. "(filtered)" only appears while a filter is actually
        # ACTIVE (not merely whenever visible != total, which can't happen
        # any other way here, but the intent is "a filter narrowed this").
        try:
            filter_active = bool(self.query_one("#filter", Input).value.strip())
        except Exception:  # noqa: BLE001 — defensive: not mounted yet
            filter_active = False
        filtered_label = " (filtered)" if filter_active else ""
        # Verdict breakdown (round 6 design critique item 4): over the LOADED
        # rows (`self._rows`), never the filtered `self._visible_rows` - the
        # filter narrows which rows are shown, not how many of each verdict
        # actually exist in the loaded window. Omitted entirely when nothing
        # is loaded - nothing to break down yet. "loaded" (round 8 item 3)
        # makes that scope explicit rather than implied.
        counts = f" - {_verdict_counts_text(self._rows)} loaded" if self._rows else ""
        self.sub_title = (
            f"showing {len(self._visible_rows)} of {total}{filtered_label}"
            f"{suffix}{counts} - {self._repo_root}"
        )

    # --- selection / why panel ------------------------------------------------

    def _why_panel(self) -> _WhyPanel | None:
        """Best-effort `#explanation-scroll` accessor: `None` instead of
        raising `NoMatches` when the panel isn't (yet, or any longer)
        mounted. Root cause (the CI flake this guards against, reproduced
        locally): a mount-timing race, not a filter-driven swap - the very
        first `DataTable.RowHighlighted`, posted by the initial load's own
        `table.move_cursor()`, can be pumped through
        `on_data_table_row_highlighted` -> `_show_explanation` before every
        sibling widget composed alongside this one is queryable yet.
        `on_mount` itself is exempt (compose has already placed the panel by
        then); every other call site must no-op via this instead of
        crashing the app. `_update_date_bar`/`_update_next_line` guard the
        same race on their own sibling widgets (`#date-bar`/`#next-line`)
        the same way."""
        try:
            return self.query_one("#explanation-scroll", _WhyPanel)
        except NoMatches:
            return None

    def _set_panel(self, text: str | Text) -> None:
        self._panel_base = text
        self._refresh_why_panel_scroll_cue()

    def _refresh_why_panel_scroll_cue(self) -> None:
        """Set the docked why panel's `border_subtitle` to `_HELP_SCROLL_CUE`
        whenever its content overflows the visible height, else clear it -
        same overflow test as `HelpScreen._refresh_scroll_cue` (round 7
        design critique item 3), re-run on every panel update (not just
        resize), since unlike the help screen's fixed text, this panel's
        content changes on every row selection/filter edit. Round 8 design
        critique item 1 moves the cue from the panel BODY (prepended ahead of
        the explanation, crowding it below the fold at a short terminal) into
        `border_subtitle`, alongside the time line's move into `border_title`
        - the body now starts with the explanation itself, always.

        Measures the overflow SYNCHRONOUSLY via `Static.get_content_height`
        (the content's own required height at its current render width)
        rather than reading the scroll container's `virtual_size` after a
        deferred `call_after_refresh` - `virtual_size` is a framework-derived
        property that can still reflect the PREVIOUS (possibly taller)
        content for one tick right after a rapid content swap, which showed
        up as a stuck stale cue under load once content had already gone
        back to something short.
        """
        scroll = self._why_panel()
        if scroll is None:
            return
        try:
            static = self.query_one("#explanation", Static)
        except NoMatches:  # defensive: not mounted yet
            return
        base = self._panel_base
        static.update(base)
        width = static.content_size.width or scroll.size.width
        height = scroll.size.height
        if not width or not height or base == "":
            scroll.border_subtitle = Text("")
            return
        content_height = static.get_content_height(scroll.size, scroll.size, width)
        scroll.border_subtitle = Text(_HELP_SCROLL_CUE if content_height > height else "")

    def _show_empty_message(self, message: str) -> None:
        """Show `message` INSIDE the table's own area (round 8 design
        critique item 5): swap the DataTable out for `#empty-message`, a
        Static occupying the same layout slot, instead of leaving a 0-row
        table on screen (still drawing its border and header) while the
        message shows somewhere else entirely (the why panel below it) - two
        regions each separately saying "nothing here" read as a broken
        layout, not "no data". The why panel itself goes blank (nothing to
        explain) and loses its time-line border title.
        """
        # Same mount-timing race as `_why_panel`/`_update_gutter`: this can
        # run inside the initial load, before `#decisions`/`#empty-message`
        # are queryable yet - no-op the swap rather than crash the app.
        try:
            self.query_one("#decisions", _DecisionTable).display = False
            empty = self.query_one("#empty-message", Static)
        except NoMatches:
            return
        empty.update(message)
        empty.display = True
        why_panel = self._why_panel()
        if why_panel is not None:
            why_panel.set_time_line("")
        self._set_panel("")

    def _hide_empty_message(self) -> None:
        self.query_one("#empty-message", Static).display = False
        self.query_one("#decisions", _DecisionTable).display = True

    def _update_date_bar(self, row: dict | None) -> None:
        # No legend when nothing is loaded at all - "nothing to filter"
        # applies here too (round 5 design critique item 9): the glyphs
        # aren't worth explaining for a browser with zero rows in it.
        text = _date_bar_text(row) if self._rows else ""
        try:
            # Same mount-timing race as `_why_panel`: the initial
            # `move_cursor`'s `RowHighlighted` can be pumped through
            # `on_data_table_row_highlighted` before this sibling widget is
            # queryable - no-op rather than crash the app.
            self.query_one("#date-bar", Static).update(text)
        except NoMatches:
            pass

    def _update_next_line(self, row: dict | None) -> None:
        # Docked separately from the panel body (round 3 design critique item
        # 3) so it stays on screen even while the why panel itself scrolls.
        # tui_hint stays True here (the default) - this IS the "press w for
        # detail" affordance; the full-screen why (`full_why_text`) is the
        # detail itself and must not repeat it (round 5 design critique item 1).
        next_line = render.next_step_line(row.get("final_verdict")) if row is not None else None
        try:
            widget = self.query_one("#next-line", Static)  # same race, see `_update_date_bar`
        except NoMatches:
            return
        widget.update(_next_line_text(next_line) if next_line else "")

    def _update_gutter(self, index: int) -> None:
        # The 1-char cursor gutter (round 3 design critique item 2): clear the
        # previous mark (if any) and mark the new cursor row with ">" - kept
        # independent of Textual's own cursor-row background, which measured
        # too low-contrast on its own to read as "selected".
        try:
            # Same mount-timing race as `_why_panel`/`_update_date_bar`: this
            # fires from `on_data_table_row_highlighted`, a fresh query for
            # `#decisions` posted by that same table's own cursor move - it
            # can still lose the race before the table is queryable again.
            table = self.query_one("#decisions", _DecisionTable)
        except NoMatches:
            return
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
        # fresh age, but simply leaving it on screen never ticks. Round 8
        # design critique item 1: this now goes to the panel's border_title
        # (via `set_time_line`), not the panel body - see `_panel_text`.
        time_line = _abs_utc_and_age(row)
        why_panel = self._why_panel()
        if why_panel is not None:
            why_panel.set_time_line(time_line)
        self._update_date_bar(row)
        self._update_next_line(row)
        self._update_gutter(index)
        cached = self._explain_cache.get(key)
        if cached is not None:
            body, provenance = cached
            self._set_panel(_panel_text(body, provenance))
            return
        body = template_explanation(row)
        if not llm_enrichment_enabled():
            # Nothing to enrich with - never schedule a worker that would only
            # ever return the same template text.
            self._explain_cache[key] = (body, _PROV_TEMPLATE)
            self._set_panel(_panel_text(body, _PROV_TEMPLATE))
            return
        self._set_panel(_panel_text(body, _PROV_PENDING))
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

        def _apply() -> None:
            # Runs on the UI thread: re-check the selection so a slow (opt-in)
            # LLM call can never overwrite a newer row's panel with stale text.
            # The border's time line was already set synchronously at
            # selection time - nothing to redo here even for a delayed reply.
            self._explain_cache[key] = (text, provenance)
            if self._current_key == key:
                self._set_panel(_panel_text(text, provenance))

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
        current row is exactly the case that must never land off-screen.

        Round 8 design critique item 6: when the CURSOR ROW ITSELF is the
        only match (e.g. the single AUTH row in view, cursor already on it),
        the wraparound search lands right back on `start` - silently
        "jumping" the cursor to the row it's already on reads as success,
        not as "there is nothing else to jump to". That case notifies
        `no other {verdict} rows in view` and returns `False` instead of
        moving the cursor to itself.
        """
        rows = self._visible_rows
        total = len(rows)
        if total:
            start = self._cursor_index()
            actual_start = start if start is not None else (0 if forward else total - 1)
            step = 1 if forward else -1
            for offset in range(1, total + 1):
                index = (actual_start + offset * step) % total
                if rows[index].get("final_verdict") == verdict:
                    if start is not None and index == start:
                        self.notify(f"no other {verdict} rows in view", markup=False)
                        return False
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
