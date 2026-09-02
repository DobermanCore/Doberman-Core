"""Unit tests for the round-7 (final) dashboard control-surface pass (design
re-critique, 33/40 -> fixes below). Covered here where the assertion is a
served-HTML/JS string check; the 390px iframe measurements (with and without
a synthetic pending card), both-theme contrast, and the sticky-topbar scroll
behavior are instead covered by a manual Chrome verification noted in the
round-7 session log/changelog.

1. Feed rows show a client-computed relative age ("3m ago", "yesterday
   11:00"), refreshed on a timer, with the absolute LOCAL time + the labeled
   UTC value in `title` - never an unlabeled clock. The stats line's
   "updated HH:MM:SS" line is now explicitly "(local)".
2. <=640px: the four verdict chips collapse into one `<select>`, and the
   text filter + "Announce new rows" toggle move behind a collapsible
   "Filters" disclosure (collapsed by default, `aria-expanded`).
3. `refreshModeHint()` never overwrites a blocked-dismiss hint mid-poll;
   the guard clears on Save, Cancel, or a new mode selection.
4. Expanding a feed row appends the full explanation UNDER the (still
   visible) headline instead of replacing it.
5. The topbar is `position: sticky` with a scroll-triggered hairline/shadow.
6. Placeholder contrast, `, ` reason-code separators, `Shortcuts: off`
   scoped to the single-key rows only, the shortcuts panel widens so Close
   shares a row with the toggles, and the truncation note names the
   dropped-row count.
7. The default verdict filter is "Needs attention" (BLOCK + AUTH), not
   "All" - persisted per browser, with a filter-aware empty-state copy.
8. `feed-count` moved next to the verdict control, body colour, `--fs-2`.
"""

import json

from starlette.testclient import TestClient

from doberman.dash.app import create_app

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
# 1. Relative age, refreshed on a timer, labeled absolute time in `title`
# --------------------------------------------------------------------------


def test_relative_age_buckets_cover_just_now_through_yesterday(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function formatRelativeAge(tsIso) {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert '"just now"' in block
    assert '"m ago"' in block
    assert '"h ago"' in block
    assert '"yesterday " + hm' in block


def test_feed_time_refreshes_every_30_seconds(tmp_path):
    html = _index_html(tmp_path)
    assert "var FEED_TIME_REFRESH_MS = 30000;" in html
    assert "setInterval(refreshFeedTimes, FEED_TIME_REFRESH_MS);" in html
    start = html.index("function refreshFeedTimes() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert '.querySelectorAll(".row-time[data-ts]")' in block
    assert "node.textContent = formatRelativeAge(node.dataset.ts);" in block


def test_stats_updated_line_is_explicitly_labeled_local(tmp_path):
    html = _index_html(tmp_path)
    assert '"updated " +' in html
    assert '" (local)";' in html


# --------------------------------------------------------------------------
# 2. Mobile chrome: chips -> <select>, filter input + announce -> disclosure
# --------------------------------------------------------------------------


def test_mobile_verdict_select_exists_alongside_the_chip_group(tmp_path):
    html = _index_html(tmp_path)
    assert '<select id="feed-verdict-select" aria-label="Filter by verdict">' in html
    assert '<option value="needs_attention">Needs attention</option>' in html
    assert '<option value="">All</option>' in html
    assert '<option value="BLOCK">BLOCK</option>' in html
    assert '<option value="AUTH">AUTH</option>' in html
    assert '<option value="PASS">PASS</option>' in html
    # Hidden at desktop widths, shown only <=640px.
    assert "#feed-verdict-select {\n    display: none;" in html
    assert "#feed-verdict-select { display: inline-block; }" in html


def test_filter_chip_group_hides_at_mobile_width(tmp_path):
    html = _index_html(tmp_path)
    assert ".filter-chip-group { display: none; }" in html


def test_filters_disclosure_collapsed_by_default_with_aria_expanded(tmp_path):
    html = _index_html(tmp_path)
    assert (
        '<button type="button" id="feed-filters-toggle-btn" aria-expanded="false" '
        'aria-controls="feed-filters-panel">Filters</button>' in html
    )
    assert '<div id="feed-filters-panel" hidden>' in html
    assert "function setFeedFiltersOpen(open) {" in html
    assert "feedFiltersPanel.hidden = !open;" in html
    assert 'feedFiltersToggleBtn.setAttribute("aria-expanded", open ? "true" : "false");' in html


def test_filters_panel_contains_the_text_filter_and_announce_toggle(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('<div id="feed-filters-panel" hidden>')
    end = html.index("</div>", start)
    block = html[start:end]
    assert 'id="feed-filter"' in block
    assert 'id="feed-announce-toggle-btn"' in block


# --------------------------------------------------------------------------
# 3. A blocked mode-form dismiss survives a background poll
# --------------------------------------------------------------------------


def test_refresh_mode_hint_short_circuits_while_dismiss_blocked(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function refreshModeHint() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "if (modeDismissBlocked) { return; }" in block


def test_dismiss_blocked_flag_set_on_block_and_cleared_on_save_cancel_select(tmp_path):
    html = _index_html(tmp_path)
    # Set when a dismiss is blocked.
    start = html.index("function attemptCloseModeForm() {")
    end = html.index("\n      }", start)
    assert "modeDismissBlocked = true;" in html[start:end]
    # Cleared on a new select change.
    start = html.index("function updateModeHint() {")
    end = html.index("\n      }", start)
    assert "modeDismissBlocked = false;" in html[start:end]
    # Cleared on Cancel (closeModeForm is also the successful-save auto-close path).
    start = html.index("function closeModeForm() {")
    end = html.index("\n      }", start)
    assert "modeDismissBlocked = false;" in html[start:end]
    # Cleared when Save actually submits.
    start = html.index("function submitModeChange() {")
    end = html.index("\n      }", start)
    assert "modeDismissBlocked = false;" in html[start:end]


# --------------------------------------------------------------------------
# 4. Expanding a feed row keeps the headline, appends the full sentence
# --------------------------------------------------------------------------


def test_expanding_appends_full_explanation_under_the_headline(tmp_path):
    html = _index_html(tmp_path)
    assert "explanationEl.textContent = row.headline || row.explanation;" in html
    assert 'fullEl.className = "row-explanation-full";' in html
    assert "fullEl.textContent = row.explanation;" in html
    assert "fullEl.hidden = true;" in html
    # The headline element's own text is never swapped on expand/collapse.
    assert "explanationEl.textContent = expanded" not in html


def test_row_explanation_full_css_hidden_until_expanded(tmp_path):
    html = _index_html(tmp_path)
    assert "#feed li .row-explanation-full[hidden] { display: none; }" in html


# --------------------------------------------------------------------------
# 5. Sticky topbar with a scroll-triggered hairline
# --------------------------------------------------------------------------


def test_topbar_is_sticky_below_the_popover_scrim_z_index(tmp_path):
    html = _index_html(tmp_path)
    start = html.index(".topbar {")
    end = html.index("\n  }", start)
    block = html[start:end]
    assert "position: sticky; top: 0; z-index: 10;" in block


def test_topbar_scrolled_class_toggled_by_a_scroll_listener(tmp_path):
    html = _index_html(tmp_path)
    assert ".topbar.scrolled {" in html
    assert 'topbarEl.classList.toggle("scrolled", window.scrollY > 0);' in html
    assert 'window.addEventListener("scroll", syncTopbarScrolled, { passive: true });' in html


# --------------------------------------------------------------------------
# 6. Placeholder contrast, reason-code separators, shortcuts gating/width,
#    truncation count
# --------------------------------------------------------------------------


def test_placeholder_uses_the_muted_contrast_token(tmp_path):
    html = _index_html(tmp_path)
    assert "::placeholder { color: var(--fg-3); opacity: 1; }" in html


def test_feed_reason_codes_use_comma_space_separator(tmp_path):
    html = _index_html(tmp_path)
    assert 'appendReasonCodeSpans(detail, row.reason_codes, ", ");' in html
    assert 'appendReasonCodeSpans(detail, row.reason_codes, ",");' not in html


def test_shortcuts_off_dims_only_the_gated_single_key_rows(tmp_path):
    html = _index_html(tmp_path)
    assert "#shortcuts-dl.dimmed dt.gated, #shortcuts-dl.dimmed dd.gated { opacity: .55; }" in html
    for key in ("/", "r", "a", "d", "?"):
        assert f'<dt class="gated">{key}</dt>' in html
    # Never gated: roving focus / expand keys.
    assert "<dt>&uarr; / &darr;</dt>" in html
    assert "<dt>Enter / Space</dt>" in html
    assert "<dt>Home / End</dt>" in html
    assert "<dt>Esc</dt>" in html


def test_shortcuts_panel_widens_at_desktop_so_close_shares_the_toggle_row(tmp_path):
    html = _index_html(tmp_path)
    assert "#shortcuts-panel { max-width: 27rem; }" in html
    assert ".panel-actions { flex-wrap: nowrap; }" in html


def test_truncation_note_names_the_dropped_row_count(tmp_path):
    html = _index_html(tmp_path)
    assert "var feedRowsDroppedCount = 0;" in html
    assert "feedRowsDroppedCount += 1;" in html
    assert (
        "feedTruncatedEl.textContent =\n"
        '              "older rows not shown (" + feedRowsDroppedCount + ") - see doberman log";'
        in html
    )


# --------------------------------------------------------------------------
# 7. Default verdict filter is "Needs attention" (BLOCK + AUTH), persisted
# --------------------------------------------------------------------------


def test_needs_attention_is_the_default_chip_and_select_option(tmp_path):
    html = _index_html(tmp_path)
    # Round 8: the chip also carries a `title` defining "Needs attention"
    # (see test_dash_round8.py) - matched here without depending on the exact
    # attribute text, just that it still immediately precedes the label.
    assert (
        '<button type="button" class="filter-chip" data-verdict="needs_attention" '
        'aria-pressed="true" title="BLOCK + AUTH - what Doberman stopped or escalated"'
        ">Needs attention</button>" in html
    )
    assert (
        '<button type="button" class="filter-chip" data-verdict="" '
        'aria-pressed="false">All</button>' in html
    )
    assert 'var DEFAULT_VERDICT_FILTER = "needs_attention";' in html


def test_verdict_filter_persists_via_localstorage(tmp_path):
    html = _index_html(tmp_path)
    assert 'var VERDICT_FILTER_KEY = "doberman-dash-feed-verdict-filter";' in html
    assert "function readStoredVerdictFilter() {" in html
    assert "function writeStoredVerdictFilter(value) {" in html
    assert "writeStoredVerdictFilter(verdict);" in html


def test_matches_filter_treats_needs_attention_as_block_or_auth(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function matchesFilter(entry) {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert 'activeVerdict === "needs_attention"' in block
    assert 'entry.verdict !== "BLOCK" && entry.verdict !== "AUTH"' in block


def test_attention_empty_copy_offers_to_show_all(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "No blocks or approvals yet - Doberman's watching quietly (show All to see passes)" in html
    )


def test_clear_filters_resets_to_the_default_not_raw_all(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function resetFeedFilters() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "setVerdictFilter(DEFAULT_VERDICT_FILTER);" in block


# --------------------------------------------------------------------------
# 8. `feed-count` legible feedback: body colour, --fs-2, next to the select
# --------------------------------------------------------------------------


def test_feed_count_uses_body_colour_and_fs_2(tmp_path):
    html = _index_html(tmp_path)
    assert "#feed-count { color: var(--fg); font-size: var(--fs-2); align-self: center; }" in html


def test_new_feed_rows_refresh_the_count_since_the_default_is_always_filtering(tmp_path):
    """The default filter (Needs attention) means `filtering` is true from the
    very first row - the count must update as rows stream in, not only when
    the user touches a filter control (which was fine when "All"/no filter
    was the default and the count legitimately stayed blank)."""
    html = _index_html(tmp_path)
    # The old direct per-row hidden assignment is gone in favor of the shared
    # recompute (applyFeedFilter re-derives `hidden` for every entry too).
    assert "feedEntries.push(entry);\n          li.hidden = !matchesFilter(entry);" not in html
    assert "feedEntries.push(entry);" in html
    push_idx = html.index("feedEntries.push(entry);")
    after_push = html[push_idx : push_idx + 700]
    assert "applyFeedFilter();" in after_push


def test_feed_count_sits_in_the_same_row_as_the_verdict_select(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('<div class="feed-toolbar-row1">')
    end = html.index("</div>", start)
    block = html[start:end]
    assert 'id="feed-verdict-select"' in block
    assert 'id="feed-count"' in block
    assert 'id="feed-filters-toggle-btn"' in block
