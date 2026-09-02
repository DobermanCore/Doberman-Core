"""Unit tests for the round-6 dashboard control-surface pass (design re-critique,
31/40 -> fixes below). Covered here where the assertion is a served-HTML/JS
string check or an SSE-payload field; the real popover scrim/inert behavior,
the 390px topbar fold, both-theme contrast, and the live focus ring are
instead covered by a manual Chrome verification noted in the round-6 session
log/changelog.

1. The roving-focus ring on the active feed row actually renders (it was
   being cancelled by an equal-specificity `outline: none` rule).
2. Every BLOCK/AUTH feed row leads with a short, reason-first `headline`
   (see test_explain.py for the function itself); the collapsed row shows it,
   the expanded body swaps in the full explanation.
3. `template_explanation(row, with_reasons=False)` for the feed body - no
   duplicated "Reasons: ..." clause (the gloss list already carries them).
4. A blocked popover dismiss shakes (`.nudge`) and states a distinct hint.
5. Modal discipline: `inert` on the rest of the page, a scrim, a blocked
   outside click refocuses the popover.
6. The feed is `aria-live="off"`; a debounced summary announcement plus an
   `Announce new rows: on/off` toggle replace the old per-row announcements.
7. 390px topbar fold: brand/status/guard on one row, a joined posture badge.
8. Copy: single-word enforcement, distinct chip/pill shapes, a visible mode
   popover title + tail, `Shortcuts: off` dims the binding list.
9. A pending card crossing the 90s horizon announces once.
10. Two tabs: `refreshPending` on `visibilitychange`.
"""

import json

from starlette.testclient import TestClient

from doberman.dash.app import _feed_row, create_app

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret


def _index_html(tmp_path) -> str:
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.get("/")
    assert resp.status_code == 200
    return resp.text


def _row(**overrides) -> dict:
    row = {
        "id": 1,
        "ts": "2026-07-07T00:00:00+00:00",
        "agent_role": "cli",
        "action_type": "shell_exec",
        "target_path_class": None,
        "risk": "critical",
        "source_context": "user",
        "final_verdict": "BLOCK",
        "decided_layer": "objective",
        "reason_codes_json": json.dumps(["destructive_command"]),
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------
# 1. The roving-focus ring actually renders
# --------------------------------------------------------------------------


def test_no_focus_suppression_left_on_the_active_feed_row(tmp_path):
    html = _index_html(tmp_path)
    assert "li:focus { outline: none" not in html


def test_active_row_focus_ring_uses_the_highest_specificity_it_needs(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "#feed > li:focus-visible, #feed > li.active:focus {\n"
        "    outline: 2px solid var(--tan-hi); outline-offset: -2px;\n  }"
    ) in html


# --------------------------------------------------------------------------
# 2/3. Headline-first collapsed row; no duplicated reasons clause on expand
# --------------------------------------------------------------------------


def test_feed_row_headline_field_is_populated_for_block_and_empty_for_pass():
    block_row = _feed_row(_row(final_verdict="BLOCK"))
    assert block_row["headline"]
    assert "blocked" in block_row["headline"]

    pass_row = _feed_row(_row(final_verdict="PASS"))
    assert pass_row["headline"] == ""


def test_feed_row_explanation_omits_the_reasons_clause():
    row = _feed_row(_row(reason_codes_json=json.dumps(["destructive_command"])))
    assert "Reasons:" not in row["explanation"]
    assert "Doberman decided BLOCK" in row["explanation"]


def test_collapsed_row_shows_headline_expanded_shows_full_explanation(tmp_path):
    """Round 7: expanding no longer REPLACES the headline with the full
    sentence (a collapsed row must still show the fragment that told it
    apart from its neighbors) - the full sentence is now a separate,
    initially-hidden element appended right under the (always-visible)
    headline. See test_dash_round7.py for the fuller coverage."""
    html = _index_html(tmp_path)
    assert "explanationEl.textContent = row.headline || row.explanation;" in html
    assert 'explanationEl.dataset.headline = row.headline || "";' not in html
    assert 'fullEl.className = "row-explanation-full";' in html
    assert "fullEl.hidden = true;" in html
    start = html.index("function toggleActiveFeedExplanation() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert 'var fullEl = li.querySelector(".row-explanation-full");' in block
    assert "fullEl.hidden = !expanded;" in block


def test_headline_leads_the_accessible_name(tmp_path):
    html = _index_html(tmp_path)
    assert '(row.headline ? row.headline + ". " : "") +' in html


# --------------------------------------------------------------------------
# 4. Blocked popover dismiss: visible nudge + distinct hint
# --------------------------------------------------------------------------


def test_blocked_dismiss_nudges_and_states_a_distinct_hint(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "var MODE_FORM_BLOCKED_DISMISS_HINT =\n"
        '        "Unsaved change - use Cancel to discard or Save to apply";'
    ) in html
    assert "function nudgeModeForm() {" in html
    start = html.index("function attemptCloseModeForm() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "modeHintEl.textContent = MODE_FORM_BLOCKED_DISMISS_HINT;" in block
    assert "nudgeModeForm();" in block
    assert "#mode-form.nudge { animation: mode-form-nudge .3s ease-in-out; }" in html
    assert (
        "@media (prefers-reduced-motion: reduce) { #mode-form.nudge { animation: none; } }" in html
    )


# --------------------------------------------------------------------------
# 5. Modal discipline: inert + scrim + focus recovery on a blocked dismiss
# --------------------------------------------------------------------------


def test_mode_popover_inerts_the_rest_of_the_page_and_shows_a_scrim(tmp_path):
    html = _index_html(tmp_path)
    assert '<div id="mode-scrim" hidden></div>' in html
    start = html.index("function openModeForm() {")
    end = html.index("\n      }", start)
    open_block = html[start:end]
    assert "modeScrim.hidden = false;" in open_block
    assert "mainEl.inert = true;" in open_block
    assert "topbarRow1El.inert = true;" in open_block
    assert "topbarUtilityGroupEl.inert = true;" in open_block

    start = html.index("function closeModeForm() {")
    end = html.index("\n      }", start)
    close_block = html[start:end]
    assert "modeScrim.hidden = true;" in close_block
    assert "mainEl.inert = false;" in close_block


def test_blocked_outside_click_refocuses_the_popover_not_body(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('document.addEventListener("click", function (e) {')
    end = html.index("});", start)
    block = html[start:end]
    assert "var closed = attemptCloseModeForm();" in block
    assert "if (!closed) { modeSelect.focus(); }" in block


def test_mode_trigger_group_never_goes_inert(tmp_path):
    """#mode-edit-btn must stay reachable while the popover it opens is open
    (clicking it again is how you close it) - only the OTHER two topbar
    groups (brand/status/guard, theme/shortcuts) go inert, never the group
    #mode-edit-btn itself lives in."""
    html = _index_html(tmp_path)
    assert 'id="topbar-utility-group"' in html
    start = html.index("function openModeForm() {")
    end = html.index("\n      }", start)
    open_block = html[start:end]
    assert "modeEditBtn.inert" not in open_block


# --------------------------------------------------------------------------
# 6. Feed aria-live=off; debounced summary announcement + toggle
# --------------------------------------------------------------------------


def test_feed_is_aria_live_off_not_a_bare_log(tmp_path):
    html = _index_html(tmp_path)
    assert '<ul id="feed" role="log" aria-live="off" tabindex="0"' in html


def test_announce_toggle_persists_and_gates_the_summary(tmp_path):
    html = _index_html(tmp_path)
    assert (
        '<button type="button" id="feed-announce-toggle-btn" aria-pressed="true">'
        "Announce new rows: on</button>"
    ) in html
    assert 'var ANNOUNCE_FEED_KEY = "doberman-dash-announce-feed";' in html
    assert "function queueFeedArrivalAnnouncement(verdict) {" in html
    assert "if (!announceFeedEnabled()) { return; }" in html
    assert "queueFeedArrivalAnnouncement(row.verdict);" in html


def test_summary_announcement_format_and_debounce(tmp_path):
    html = _index_html(tmp_path)
    assert "var FEED_ANNOUNCE_DEBOUNCE_MS = 2000;" in html
    assert 'var VERDICT_ANNOUNCE_ORDER = ["BLOCK", "AUTH", "PASS"];' in html
    assert ('total + " new decision" + (total === 1 ? "" : "s") + ": " + parts.join(", ")') in html


# --------------------------------------------------------------------------
# 7. 390px topbar fold: one row, joined posture badge
# --------------------------------------------------------------------------


def test_brand_and_connection_guard_share_the_first_topbar_row(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('<div class="topbar-row1">')
    end = html.index('</div>\n    <div class="topbar-right">', start)
    row1 = html[start:end]
    assert 'class="brand"' in row1
    assert 'id="status"' in row1
    assert 'id="guard-status"' in row1


def test_posture_badge_is_actually_hidden_on_wide_screens(tmp_path):
    """Caught live in Chrome: `.badge`'s own `display: inline-flex` (an
    AUTHOR rule) overrides the `hidden` attribute's UA `display: none`
    outright regardless of specificity, so the badge rendered on a 1568px
    viewport despite carrying `hidden` - the same class of bug this file's
    other `[hidden]`-restatement comments describe elsewhere."""
    html = _index_html(tmp_path)
    start = html.index("#posture-badge { display: none; }")
    assert start != -1
    # Must appear BEFORE the <=640px media rule that shows it again, and at
    # ID-selector specificity (not folded into the shared `.badge` rule).
    media_pos = html.index("#posture-badge { display: inline-flex; }")
    assert start < media_pos


def test_posture_badge_joins_mode_and_enforcement_for_the_mobile_fold(tmp_path):
    html = _index_html(tmp_path)
    assert '<span class="badge badge-neutral" id="posture-badge" hidden>posture: -</span>' in html
    assert ('postureBadge.textContent = "posture: " + s.mode + " · " + enforcementWord;') in html
    media_start = html.rindex("@media (max-width: 640px) {")
    mode_pos = html.index(
        "#mode-badge, #enforcement-badge, #theme-toggle-btn { display: none; }", media_start
    )
    posture_pos = html.index("#posture-badge { display: inline-flex; }", media_start)
    assert media_start < mode_pos < posture_pos


# --------------------------------------------------------------------------
# 8. Copy + shape + popover title/tail + shortcuts dimming
# --------------------------------------------------------------------------


def test_enforcement_reads_a_single_word_with_the_pair_in_title(tmp_path):
    html = _index_html(tmp_path)
    assert 'enforce: "enforcing"' in html
    assert 'monitor: "monitoring"' in html
    assert 'enforcementBadge.textContent = "enforcement: " + enforcementWord;' in html
    assert 'enforcementBadge.title = ENFORCEMENT_TITLE[s.enforcement] || "";' in html


def test_connected_chip_and_guard_pill_are_visually_distinct_shapes(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("  .chip {")
    end = html.index("}", start)
    assert "border-radius: var(--r-sm);" in html[start:end]
    assert "border-radius: 999px" not in html[start:end]


def test_mode_form_title_is_visible_with_a_tail_pointing_at_its_trigger(tmp_path):
    html = _index_html(tmp_path)
    assert '<p id="mode-form-title">Security mode</p>' in html
    assert "#mode-form-title {" in html
    assert "#mode-form:not([hidden])::before {" in html


def test_shortcuts_off_dims_the_binding_list_and_marks_the_title(tmp_path):
    html = _index_html(tmp_path)
    assert '<dl id="shortcuts-dl">' in html
    assert '<p class="panel-title" id="shortcuts-panel-title">Shortcuts</p>' in html
    # Round 7: scoped to `.gated` rows only, not the whole list (see
    # test_dash_round7.py) - Up/Down/Enter/Space/Home/End are never gated.
    assert "#shortcuts-dl.dimmed dt.gated, #shortcuts-dl.dimmed dd.gated { opacity: .55; }" in html
    start = html.index("function renderShortcutsToggle() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert 'shortcutsPanelTitleEl.textContent = "Shortcuts" + (on ? "" : " (off)");' in block
    assert 'shortcutsDlEl.classList.toggle("dimmed", !on);' in block


def test_theme_toggle_moves_into_the_shortcuts_panel_on_narrow_screens(tmp_path):
    html = _index_html(tmp_path)
    assert (
        '<button type="button" id="panel-theme-toggle-btn">Switch to light theme</button>' in html
    )
    assert 'panelThemeToggleBtn.addEventListener("click", toggleTheme);' in html
    media_start = html.rindex("@media (max-width: 640px) {")
    assert html.index("#theme-toggle-btn { display: none; }", media_start) > media_start


# --------------------------------------------------------------------------
# 9. 90s horizon announcement, once
# --------------------------------------------------------------------------


def test_horizon_crossing_announces_exactly_once_per_card(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function tickCountdowns() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "if (!node.dataset.horizonAnnounced) {" in block
    assert 'node.dataset.horizonAnnounced = "1";' in block
    assert 'announce("Approval moved to your terminal.");' in block


# --------------------------------------------------------------------------
# 10. Two tabs: refreshPending on visibilitychange
# --------------------------------------------------------------------------


def test_visibilitychange_refreshes_pending_immediately(tmp_path):
    html = _index_html(tmp_path)
    assert 'document.addEventListener("visibilitychange", function () {' in html
    assert 'if (document.visibilityState === "visible") { refreshPending(); }' in html
