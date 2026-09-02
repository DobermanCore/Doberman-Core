"""Unit tests for the round-4 dashboard control-surface pass (design re-critique).

Ten fixes, each covered here (or, for the two that are purely visual/behavioral
in a real browser - the popover's actual light-dismiss/Tab-containment
behavior and the 390px filter-input height - by a manual Chrome verification
noted in the round-4 session log/changelog instead):

1. Feed rows expand by click/tap, not only Enter/Space; explanation is the
   row's primary (full-contrast) text, reason codes the secondary muted line,
   individually glossed with both `title` and a keyboard/touch-reachable "?"
   toggle - same hierarchy on the pending card.
2. Real roving `tabindex` (DOM focus) replaces `aria-activedescendant`; each
   row carries an accessible name.
3. A strictness downgrade needs the same arm-then-confirm gesture as Approve.
4. Gloss coverage 58/58 (see test_explain.py::test_every_reason_code_has_a_gloss).
5. Filter chips color by verdict; Deny's solid fill is neutral/tan, not red.
6. Mobile: the filter input doesn't stretch vertically, badges don't wrap
   internally, Clear filters reaches the 44px floor.
7. The mode popover is a light-dismiss "dialog" with Tab containment; a single
   Escape closes only the topmost open thing.
8. The shortcuts panel anchors under its trigger instead of the viewport corner.
9. "from:unknown" is dropped; dark `.detail` text clears 4.5:1.
"""

from starlette.testclient import TestClient

from doberman.dash.app import create_app

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret


def _index_html(tmp_path) -> str:
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.get("/")
    assert resp.status_code == 200
    return resp.text


# --------------------------------------------------------------------------
# 1. Click/tap expand + explanation-primary / reason-codes-secondary hierarchy
# --------------------------------------------------------------------------


def test_feed_row_with_an_explanation_is_click_expandable(tmp_path):
    html = _index_html(tmp_path)
    # Direct-child combinator as of round 5 (see test_dash_round5.py) - a bare
    # descendant selector also matched a feed row's nested .gloss-list <li>s.
    assert "#feed > li.has-explanation { cursor: pointer; }" in html
    assert 'li.classList.add("has-explanation");' in html
    assert 'li.setAttribute("aria-expanded", "false");' in html
    assert 'li.addEventListener("click", function () {' in html
    assert "setActiveFeedEntry(entry);" in html
    assert "toggleActiveFeedExplanation();" in html
    # Enter/Space (roving focus) toggles the same aria-expanded state.
    assert 'li.setAttribute("aria-expanded", expanded ? "true" : "false");' in html


def test_feed_explanation_is_primary_reason_codes_are_secondary(tmp_path):
    html = _index_html(tmp_path)
    # Primary: body face, full-contrast --fg (was --fg-2).
    start = html.index("#feed li .row-explanation {")
    end = html.index("}", start)
    assert "color: var(--fg);" in html[start:end]
    # Explanation is appended to the DOM before rowMain (secondary metadata +
    # reason codes), so it reads as the row's first/primary line.
    assert html.index("li.appendChild(explanationEl);") < html.index("li.appendChild(rowMain);")


def test_reason_codes_get_a_keyboard_and_touch_reachable_gloss_toggle(tmp_path):
    """title="..." only ever shows on :hover. Superseded in round 5 (see
    test_dash_round5.py) - the per-code "?" button was itself a Tab-focusable
    control inside a list that otherwise has none, so it's gone; a row with
    an explanation reuses its OWN expand toggle to reveal the same text as a
    muted list instead (buildGlossList), and pending cards just show it
    always (they're never collapsed)."""
    html = _index_html(tmp_path)
    assert 'toggle.className = "gloss-q";' not in html
    assert 'glossText.className = "gloss-text";' not in html
    assert "function buildGlossList(codes) {" in html


def test_pending_card_sentence_first_codes_second(tmp_path):
    html = _index_html(tmp_path)
    assert html.index('explanation.className = "row-explanation";') < html.index(
        'reasons.className = "reason-line";'
    )
    assert "appendReasonCodeSpans(reasons, row.reason_codes" in html
    start = html.index("#pending-list .row-explanation {")
    end = html.index("}", start)
    assert "color: var(--fg);" in html[start:end]


# --------------------------------------------------------------------------
# 2. Roving focus via real tabindex, not aria-activedescendant
# --------------------------------------------------------------------------


def test_feed_rows_use_real_roving_focus_not_activedescendant(tmp_path):
    html = _index_html(tmp_path)
    # The mechanism itself is gone (only mentioned in a comment explaining why).
    assert 'setAttribute("aria-activedescendant"' not in html
    assert 'removeAttribute("aria-activedescendant")' not in html
    assert "li.tabIndex = -1;" in html
    assert "activeFeedEntry.li.focus();" in html
    # The scroller hands focus to the active/first row when IT is the direct
    # focus target (Tab into the list), not on every row's own focus.
    assert 'feedEl.addEventListener("focus", function (e) {' in html
    assert "if (e.target !== feedEl) { return; }" in html


def test_feed_row_has_an_accessible_name(tmp_path):
    html = _index_html(tmp_path)
    assert 'li.setAttribute(\n            "aria-label",' in html
    assert 'row.verdict + " " + row.action_type + " " +' in html


# --------------------------------------------------------------------------
# 3. Downgrade is gated at least as hard as an approval
# --------------------------------------------------------------------------


def test_mode_downgrade_requires_arm_then_confirm(tmp_path):
    html = _index_html(tmp_path)
    assert "#mode-save-btn.danger { border-color: var(--block); color: var(--block); }" in html
    assert (
        'modeSaveBtn.textContent = direction === "lower" ? ("Lower to " + modeSelect.value)' in html
    )
    assert 'modeSaveBtn.textContent = "Confirm lower (" + remaining + ")";' in html
    # Round 5: the hint text is now composed in modeHintText() (a per-mode
    # factual consequence, see test_dash_round5.py), not a single literal
    # assignment - just check the gate still branches only on "lower".
    assert 'if (computeModeDirection() === "lower" && !modeArmed) {' in html
    assert 'text = "Raise: applies immediately.";' in html


# --------------------------------------------------------------------------
# 5. Verdict-colored filter chips; Deny's solid fill is neutral, not red
# --------------------------------------------------------------------------


def test_filter_chips_color_by_verdict(tmp_path):
    html = _index_html(tmp_path)
    assert (
        '.filter-chip[data-verdict="BLOCK"][aria-pressed="true"] {\n'
        "    background: var(--block-bg); border-color: var(--block); color: var(--block);\n  }"
    ) in html
    assert (
        '.filter-chip[data-verdict="AUTH"][aria-pressed="true"] {\n'
        "    background: var(--auth-bg); border-color: var(--auth); color: var(--auth);\n  }"
    ) in html
    assert (
        '.filter-chip[data-verdict="PASS"][aria-pressed="true"] {\n'
        "    background: var(--pass-bg); border-color: var(--pass); color: var(--pass);\n  }"
    ) in html


def test_deny_is_solid_but_neutral_tan_not_red(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "#pending-list button.deny { background: var(--tan); "
        "border: 1px solid var(--tan); color: var(--ink-0); }"
    ) in html
    assert (
        "#pending-list button.deny { background: var(--block); "
        "border: 1px solid var(--block); color: var(--ink-0); }"
    ) not in html


# --------------------------------------------------------------------------
# 6. Mobile fixes
# --------------------------------------------------------------------------


def test_feed_filter_does_not_stretch_vertically_in_the_column_toolbar(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("#feed-filter {\n      width: 100%;")
    end = html.index("}", start)
    assert "flex: none;" in html[start:end]


def test_mode_and_enforcement_badges_never_wrap_to_two_lines(tmp_path):
    html = _index_html(tmp_path)
    assert ".badge, .status-pill { white-space: nowrap; }" in html
    assert ".topbar-group { flex-wrap: wrap; row-gap: .4rem; }" in html


def test_clear_filters_reaches_the_44px_floor(tmp_path):
    html = _index_html(tmp_path)
    assert "#feed-clear-filters-btn { min-height: 44px; min-width: 44px; }" in html


# --------------------------------------------------------------------------
# 7. Popover: light dismiss, Tab containment, single-Escape priority
# --------------------------------------------------------------------------


def test_mode_form_is_a_light_dismiss_dialog(tmp_path):
    html = _index_html(tmp_path)
    # aria-modal="true" as of round 5 (test_dash_round5.py) - Tab is
    # genuinely contained while the popover is open, see the keydown
    # handler below.
    assert (
        '<div id="mode-form" hidden role="dialog" aria-modal="true" '
        'aria-labelledby="mode-form-title">'
    ) in html
    # Round 6: the title is now VISIBLE ("Security mode", see test_dash_round6.py)
    # instead of sr-only - the popover otherwise had no on-screen heading at all.
    assert '<p id="mode-form-title">Security mode</p>' in html
    assert 'document.addEventListener("click", function (e) {' in html
    assert "if (modeForm.contains(e.target) || e.target === modeEditBtn) { return; }" in html
    assert "attemptCloseModeForm();" in html


def test_mode_form_traps_tab_focus_while_open(tmp_path):
    html = _index_html(tmp_path)
    assert 'modeForm.addEventListener("keydown", function (e) {' in html
    assert 'if (e.key !== "Tab") { return; }' in html


def test_escape_closes_only_the_topmost_thing(tmp_path):
    html = _index_html(tmp_path)
    order = [
        # Round 5: Escape now calls attemptCloseModeForm (same dismiss
        # semantics as an outside click), not closeModeForm directly.
        "if (!modeForm.hidden) { attemptCloseModeForm(); return; }",
        "if (!shortcutsPanel.hidden) { closeShortcuts(); return; }",
        "if (document.activeElement === feedFilterInput) {",
    ]
    positions = [html.index(s) for s in order]
    assert positions == sorted(positions)


# --------------------------------------------------------------------------
# 8. Shortcuts panel anchors under its trigger
# --------------------------------------------------------------------------


def test_shortcuts_panel_anchors_under_its_trigger(tmp_path):
    html = _index_html(tmp_path)
    assert "function positionShortcutsPanel()" in html
    assert "positionShortcutsPanel();" in html
    # The viewport-corner default only applies <=640px now - not unconditionally.
    assert html.count("#shortcuts-panel { right: 1.25rem; bottom: 1.25rem; }") == 1
    assert "@media (max-width: 640px) {\n    #shortcuts-panel" in html


# --------------------------------------------------------------------------
# 9. Noise: dropped from:unknown (see test_dash_polish.py), dark contrast fix
# --------------------------------------------------------------------------


def test_dark_fg3_bumped_for_contrast(tmp_path):
    html = _index_html(tmp_path)
    # 64% measured 4.48:1 against the feed row's :hover background (--ink-2);
    # 66% clears the 4.5:1 floor with margin. Both the default (dark-first)
    # :root block and the explicit :root[data-theme="dark"] override moved.
    assert html.count("oklch(66% 0.006 55)") == 2
    assert "oklch(64% 0.006 55)" not in html
