"""Unit tests for the round-5 dashboard control-surface pass (design re-critique,
28/40 -> fixes below). Covered here where the assertion is a served-HTML/JS
string check; the popover's real dismiss/Tab-containment behavior, the 390px
mobile fold, and both-theme contrast are covered instead by a manual Chrome
verification noted in the round-5 session log/changelog.

1. Search finds the text you can read: `searchText` includes the explanation
   and the glossed reason words, not just the raw codes.
2. The redundant per-code "?" toggle buttons are gone. A feed row with an
   explanation (or with only glossed reason codes) reuses its OWN
   click/tap/Enter/Space expand toggle to reveal the same text as a muted
   list (`buildGlossList`) - no separate button, so Tab past the feed never
   hits a per-row control. Pending cards are never collapsed, so they just
   render the list always.
3. `d` gets the same arm-then-confirm gesture as `a` ("Confirm deny (N)"),
   documented in the shortcuts panel; a `Shortcuts: on/off` toggle persists
   in localStorage (WCAG 2.1.4) and gates every single-character shortcut
   except Escape.
4. One dismiss semantics for the mode popover: Escape and an outside click
   both call `attemptCloseModeForm` - if a change is pending, both keep it
   open and surface "Unsaved change - Save or Cancel"; Cancel still discards
   unconditionally. `aria-modal="true"` now that Tab is genuinely contained.
5. The downgrade hint is legible (`--fs-2`, `--fg`, `--block` when lowering)
   and states a real, per-mode consequence derived from
   `doberman/policy/modes.py`'s thresholds.
6. The AUTH/pending card says what it can't show (a one-line privacy note),
   the countdown is downsized so the explanation sentence is the card's
   largest element, and the TOTP field gets a visible "6-digit code" label.
7. Stats are three labeled groups (decisions / verdicts / top reasons), not
   one run-on line; the calm guard pip is `--pass` (green), not `--tan`.
8. Mobile fold: the decisions/top-reasons stat groups and the big dashed
   pending-empty box collapse at <=640px.
9. (see test_explain.py for the plain-words layer sentence.)
10. `Clear filters` returns focus to `#feed`; Escape from the filter jumps to
    the feed's NEWEST row; `Copy details` confirms inline ("Copied", 1.2s)
    and announces, or shows a failure message instead of failing silently.
11. No em dash (U+2014) anywhere in the served shell - ASCII hyphen instead.
12. The stray ~11px span (`.gloss-q`'s `.9em` inside a 12px context) is gone
    along with the rest of the per-code toggle machinery.
13. The shortcuts panel gets an explicit wide-viewport CSS fallback anchor
    (belt-and-suspenders alongside the JS `positionShortcutsPanel`), so it
    never silently falls back to its own static DOM position.
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
# 1. Search matches the readable text, not just raw codes
# --------------------------------------------------------------------------


def test_search_text_includes_explanation_and_glossed_reason_words(tmp_path):
    html = _index_html(tmp_path)
    assert "var reasonGlosses = (row.reason_codes || []).map(function (code) {" in html
    assert 'return REASON_DESCRIPTIONS[code] || "";' in html
    start = html.index("searchText: (")
    end = html.index(").toLowerCase()", start)
    block = html[start:end]
    assert "reasonGlosses" in block
    assert "row.explanation" in block


# --------------------------------------------------------------------------
# 2. No per-code toggle buttons; the row itself is the (at most one) toggle
# --------------------------------------------------------------------------


def test_no_per_code_gloss_toggle_buttons_remain(tmp_path):
    html = _index_html(tmp_path)
    assert "gloss-q" not in html
    assert "gloss-text" not in html
    assert 'What does " + code + " mean?' not in html


def test_build_gloss_list_is_the_shared_expand_mechanism(tmp_path):
    html = _index_html(tmp_path)
    assert "function buildGlossList(codes) {" in html
    assert 'list.className = "gloss-list";' in html
    assert 'item.textContent = code + " - " + REASON_DESCRIPTIONS[code];' in html
    # A feed row is expandable when it has a headline, an explanation, OR a
    # gloss list (round 6 added `row.headline` to this OR-chain) - not only
    # an explanation any more.
    assert (
        "var expandable = Boolean(row.headline) || Boolean(row.explanation) || "
        "Boolean(glossListEl);"
    ) in html
    assert "if (expandable) {" in html
    # Pending cards render it unconditionally (never collapsed).
    assert "var pendingGlossList = buildGlossList(row.reason_codes);" in html
    assert "if (pendingGlossList) { li.appendChild(pendingGlossList); }" in html


def test_gloss_list_hidden_attribute_actually_hides_it(tmp_path):
    """Caught live in Chrome: an author `display` on the same element
    outranks the UA's `[hidden]` rule (the mode form and feed filter both
    had this bug already) - without an explicit override, a collapsed feed
    row's gloss list rendered unconditionally instead of staying hidden."""
    html = _index_html(tmp_path)
    assert ".gloss-list[hidden] { display: none; }" in html


def test_row_styling_is_scoped_to_direct_children_not_the_nested_gloss_list(tmp_path):
    """Caught live in Chrome: a pending card's (and a feed row's) own
    .gloss-list is a <ul> of <li> nested INSIDE the row/card <li> - a bare
    descendant selector (`#pending-list li`, `#feed li`) matched those too,
    so each gloss line rendered as its own bordered/shadowed/animated card
    (or inherited the feed row's padding/hover/focus/active treatment).
    Every selector that styles the row/card ELEMENT ITSELF (not a specific
    class descendant like .row-main/.detail, which the gloss <li> never
    carries) must use the direct-child combinator instead."""
    html = _index_html(tmp_path)
    assert "#pending-list > li {" in html
    assert "#pending-list > li.stale { opacity: .7; border-style: dashed; }" in html
    assert "#pending-list > li { animation: none; }" in html
    assert "#pending-list li {" not in html
    assert "#feed > li {" in html
    assert "#feed > li[hidden] { display: none; }" in html
    assert "#feed > li:last-child { border-bottom: none; }" in html
    assert "#feed > li:hover { background: var(--ink-2); }" in html
    assert "#feed > li.active {" in html
    # Round 6: the old `#feed > li:focus { outline: none; }` suppression is
    # gone (see test_dash_round6.py) - direct-child scoping now lives on its
    # replacement instead.
    assert "#feed > li:focus-visible, #feed > li.active:focus {" in html
    assert "#feed li {" not in html


def test_toggle_active_feed_explanation_also_reveals_the_gloss_list(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function toggleActiveFeedExplanation() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert 'li.querySelector(".gloss-list");' in block
    assert "glossListEl.hidden = !expanded;" in block


# --------------------------------------------------------------------------
# 3. Deny arm-then-confirm; shortcuts on/off toggle (WCAG 2.1.4)
# --------------------------------------------------------------------------


def test_deny_gets_the_same_arm_then_confirm_gesture_as_approve(tmp_path):
    html = _index_html(tmp_path)
    assert 'denyBtn.textContent = "Confirm deny (" + remaining + ")";' in html
    assert "var denyArmTimer = null;" in html
    assert "<dt>d</dt><dd>Arm Deny on the first pending item, then Enter to confirm</dd>" in html
    # The keyboard shortcut's "already armed -> just focus" branch is no
    # longer restricted to `a` only.
    assert 'if (actionBtn.dataset.armed === "1") { actionBtn.focus(); return; }' in html
    assert 'if (e.key === "a" && actionBtn.dataset.armed === "1")' not in html


def test_shortcuts_toggle_persists_in_localstorage_and_gates_bare_keys(tmp_path):
    html = _index_html(tmp_path)
    assert (
        '<button type="button" id="shortcuts-toggle-btn" aria-pressed="true">Shortcuts: on</button>'
        in html
    )
    assert 'var SHORTCUTS_ENABLED_KEY = "doberman-dash-shortcuts-enabled";' in html
    assert "window.localStorage.getItem(SHORTCUTS_ENABLED_KEY)" in html
    assert "window.localStorage.setItem(SHORTCUTS_ENABLED_KEY" in html
    assert "if (!shortcutsEnabled()) { return; }" in html
    # Escape's branch must come BEFORE the shortcutsEnabled() gate, so it
    # always works regardless of the toggle.
    escape_pos = html.index('if (e.key === "Escape") {')
    gate_pos = html.index("if (!shortcutsEnabled()) { return; }")
    assert escape_pos < gate_pos


# --------------------------------------------------------------------------
# 4. Unified popover dismiss semantics + aria-modal="true"
# --------------------------------------------------------------------------


def test_mode_form_dismiss_is_unified_escape_and_outside_click(tmp_path):
    html = _index_html(tmp_path)
    assert (
        '<div id="mode-form" hidden role="dialog" aria-modal="true" '
        'aria-labelledby="mode-form-title">'
    ) in html
    assert "function attemptCloseModeForm() {" in html
    assert "if (pendingModeChange()) {" in html
    # Both call sites use the shared function - not two divergent branches.
    assert "if (!modeForm.hidden) { attemptCloseModeForm(); return; }" in html
    click_start = html.index('document.addEventListener("click", function (e) {')
    click_end = html.index("});", click_start)
    assert "attemptCloseModeForm();" in html[click_start:click_end]


def test_unsaved_change_hint_appears_when_a_change_is_pending(tmp_path):
    html = _index_html(tmp_path)
    assert '"Unsaved change - Save or Cancel."' in html
    assert "function pendingModeChange() {" in html
    assert 'return modeArmed || computeModeDirection() !== "none";' in html


def test_cancel_still_discards_unconditionally(tmp_path):
    html = _index_html(tmp_path)
    assert 'modeCancelBtn.addEventListener("click", closeModeForm);' in html
    start = html.index("function closeModeForm() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "modeSelect.value = currentModeName;" in block


# --------------------------------------------------------------------------
# 5. Legible, factual downgrade hint
# --------------------------------------------------------------------------


def test_mode_hint_css_is_legible_and_marks_lowering(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "#mode-hint { flex-basis: 100%; margin: -.15rem 0 .2rem; "
        "color: var(--fg); font-size: var(--fs-2); }"
    ) in html
    assert "#mode-hint.lowering { color: var(--block); }" in html
    assert 'modeHintEl.classList.toggle("lowering", computeModeDirection() === "lower");' in html


def test_downgrade_consequence_is_derived_per_mode(tmp_path):
    html = _index_html(tmp_path)
    assert "var MODE_DOWNGRADE_CONSEQUENCE = {" in html
    # Factual per doberman/policy/modes.py's MODES (bulk_delete_threshold,
    # abnormality_threshold, escalate_* flags) - not a single generic string.
    assert "only flags bulk deletes at 100+ items" in html  # light
    assert "raises the bulk-delete threshold to 25 items" in html  # balanced
    assert "raises the bulk-delete threshold to 10 items" in html  # strict
    # paranoid is never a "lower" target (it's already the strictest), so it
    # needs no dict entry - only a prose mention (capitalized) inside strict's
    # sentence is expected.
    consequence_block = html.split("var MODE_DOWNGRADE_CONSEQUENCE = {")[1].split("};")[0]
    assert "paranoid:" not in consequence_block
    assert "hard blocks (secrets, destructive commands, protected paths) " in html
    assert "stay in force regardless of mode." in html


# --------------------------------------------------------------------------
# 6. The AUTH/pending card
# --------------------------------------------------------------------------


def test_pending_card_states_what_it_cannot_show(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "Doberman never shows the raw command here - see doberman log for the redacted record."
    ) in html
    assert 'privacyNote.className = "privacy-note";' in html


def test_countdown_is_downsized_explanation_is_the_largest_element(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("#pending-list .countdown {")
    end = html.index("}", start)
    countdown_block = html[start:end]
    assert "font-size: var(--fs-2)" in countdown_block
    assert "var(--fs-3)" not in countdown_block

    start = html.index("#pending-list .row-explanation {")
    end = html.index("}", start)
    explanation_block = html[start:end]
    assert "font-size: var(--fs-3)" in explanation_block
    assert "font-weight: 600" in explanation_block


def test_totp_field_gets_a_visible_six_digit_label(tmp_path):
    html = _index_html(tmp_path)
    assert 'totpLabel.className = "totp-label";' in html
    assert 'totpLabel.textContent = "6-digit code";' in html
    # Not sr-only any more, and no longer duplicated as an aria-label (the
    # visible <label for=...> now provides the accessible name).
    assert 'totpLabel.className = "sr-only";' not in html
    assert 'totpInput.setAttribute("aria-label", "TOTP code");' not in html


# --------------------------------------------------------------------------
# 7. Stats are three labeled groups; the calm guard pip is green
# --------------------------------------------------------------------------


def test_stats_render_as_three_labeled_groups(tmp_path):
    html = _index_html(tmp_path)
    assert 'makeStatGroup("stats-decisions", "decisions")' in html
    assert 'makeStatGroup("stats-verdicts", "verdicts")' in html
    assert 'makeStatGroup("stats-reasons", "top reasons")' in html
    assert ".stat-label {" in html


def test_calm_guard_pip_is_pass_green_not_tan(tmp_path):
    html = _index_html(tmp_path)
    assert ".status-pill.ok .pip { color: var(--pass); }" in html
    assert ".status-pill.ok .pip { color: var(--tan); }" not in html


# --------------------------------------------------------------------------
# 8. Mobile fold
# --------------------------------------------------------------------------


def test_mobile_fold_hides_decisions_and_reasons_stat_groups(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "@media (max-width: 640px) {\n    #stats-decisions, #stats-reasons { display: none; }\n  }"
        in html
    )


def test_mobile_pending_empty_is_a_single_line_not_a_dashed_box(tmp_path):
    html = _index_html(tmp_path)
    start = html.rindex("@media (max-width: 640px) {")
    end = html.index("}", html.index("#pending-empty {", start))
    block = html[start:end]
    assert "border: none" in block
    assert "text-align: left" in block


# --------------------------------------------------------------------------
# 10. Clear filters / Escape focus targets; Copy details feedback
# --------------------------------------------------------------------------


def test_clear_filters_returns_focus_to_the_feed(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('feedClearFiltersBtn.addEventListener("click", function () {')
    end = html.index("});", start)
    assert "feedEl.focus();" in html[start:end]


def test_escape_from_filter_focuses_the_newest_row(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("if (document.activeElement === feedFilterInput) {")
    end = html.index("}", html.index("applyFeedFilter();", start))
    block = html[start:end]
    assert "jumpActiveFeedEntry(true);" in block


def test_copy_details_confirms_inline_and_announces_or_reports_failure(tmp_path):
    html = _index_html(tmp_path)
    assert 'copyBtn.textContent = "Copied";' in html
    assert 'announce("Copied approval details to the clipboard.");' in html
    assert "copyResetTimer = setTimeout(function () {" in html
    assert "}, 1200);" in html
    assert 'errorEl.textContent = "Couldn\'t copy - select the text instead";' in html


# --------------------------------------------------------------------------
# 11. No em dash anywhere in the served shell
# --------------------------------------------------------------------------


def test_served_shell_has_no_em_dash(tmp_path):
    html = _index_html(tmp_path)
    assert "—" not in html


# --------------------------------------------------------------------------
# 13. Shortcuts panel: explicit wide-viewport CSS fallback anchor
# --------------------------------------------------------------------------


def test_shortcuts_panel_has_a_wide_viewport_css_fallback_anchor(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "@media (min-width: 641px) {\n    #shortcuts-panel { top: 4.5rem; right: 1.25rem; }\n  }"
        in html
    )
