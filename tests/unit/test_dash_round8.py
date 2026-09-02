"""Unit tests for the round-8 (final, small) dashboard control-surface pass.

Covered here where the assertion is a served-HTML/JS/CSS string check; the
light-theme scrollbar/select rendering, the 390px no-inner-scroll layout, and
the live `r`/Escape/newest-row-on-load behavior are instead covered by a
manual Chrome verification noted in the round-8 session log/changelog.

1. The pending card's privacy note points at the channel that can actually
   answer (the terminal), not just at what the dashboard withholds.
2. `color-scheme` follows the manual theme (`data-theme="light"/"dark"`), not
   just the OS preference - the bare `:root` default is unchanged.
3. Stats windows are explicitly labeled (`verdicts (all time)`, `top reasons
   (all time)`, `secret/taint events (all time)`) so no two numbers on the
   card can be confused.
4. A single `--fs-4` focal number (pending count, else recent BLOCK count);
   `h2` moves up to `--fs-3` so headings outrank badges.
5. The `Needs attention` chip carries a `title`, repeated in the `?` panel.
6. Escape from a no-match filter focuses the first VISIBLE row (never the
   last), or the feed container with none visible.
7. `r` announces `Refreshed - N decisions, M pending`; a blocked mode-form
   dismiss appends its hint after the consequence sentence instead of
   replacing it.
8. The feed renders newest-first (prepended); truncation drops the oldest
   (now the last child); at <=640px `#feed` drops its inner scroller.
9. No-match copy says "these filters" once two filters are stacked; the
   theme toggle stays reachable at 390px via the `?` panel.
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
# 1. Privacy note points at the channel that can answer
# --------------------------------------------------------------------------


def test_privacy_note_points_at_the_terminal(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "The raw command stays in your terminal. Let this fall through (or press d) "
        "to review it there."
    ) in html
    assert "Doberman never shows the raw command here" not in html


# --------------------------------------------------------------------------
# 2. color-scheme follows the manual theme
# --------------------------------------------------------------------------


def test_color_scheme_follows_manual_theme(tmp_path):
    html = _index_html(tmp_path)
    # Bare :root default unchanged.
    assert "color-scheme: dark light;" in html
    light_start = html.index(':root[data-theme="light"] {')
    light_end = html.index("}", light_start)
    assert "color-scheme: light;" in html[light_start:light_end]
    dark_start = html.index(':root[data-theme="dark"] {')
    dark_end = html.index("}", dark_start)
    assert "color-scheme: dark;" in html[dark_start:dark_end]


# --------------------------------------------------------------------------
# 3. Stats windows are labeled so no two numbers can be confused
# --------------------------------------------------------------------------


def test_stats_groups_are_labeled_with_their_window(tmp_path):
    html = _index_html(tmp_path)
    assert 'makeStatGroup("stats-verdicts", "verdicts (all time)")' in html
    assert 'makeStatGroup("stats-reasons", "top reasons (all time)")' in html
    assert '" secret/taint events (all time)"' in html


# --------------------------------------------------------------------------
# 4. A single --fs-4 focal number; h2 outranks badges
# --------------------------------------------------------------------------


def test_h2_uses_fs_3_not_fs_1(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("h2 {")
    end = html.index("}", start)
    block = html[start:end]
    assert "font-size: var(--fs-3)" in block
    assert "var(--fs-1)" not in block


def test_focal_number_is_the_only_fs_4_reference(tmp_path):
    html = _index_html(tmp_path)
    assert "--fs-4: 1.25rem;" in html
    assert html.count("var(--fs-4)") == 1
    assert ".focal-number {" in html
    assert "font-size: var(--fs-4)" in html


def test_focal_number_prefers_pending_over_recent_block(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('focalGroup.id = "stats-focal";')
    end = html.index("statsEl.appendChild(focalGroup);", start)
    block = html[start:end]
    assert "if (lastPendingCountForFavicon > 0) {" in block
    assert 'focalLabel.textContent = "pending";' in block
    assert "s.recent_verdict_counts && s.recent_verdict_counts.BLOCK" in block
    assert 'focalLabel.textContent = "recent BLOCK";' in block


# --------------------------------------------------------------------------
# 5. "Needs attention" chip title, repeated in the "?" panel
# --------------------------------------------------------------------------


def test_needs_attention_chip_has_a_title_repeated_in_the_panel(tmp_path):
    html = _index_html(tmp_path)
    definition = "BLOCK + AUTH - what Doberman stopped or escalated"
    assert (
        '<button type="button" class="filter-chip" data-verdict="needs_attention" '
        f'aria-pressed="true" title="{definition}">Needs attention</button>'
    ) in html
    assert f'"Needs attention" = {definition}.' in html


# --------------------------------------------------------------------------
# 6. Escape from a no-match filter: first visible row, else the container
# --------------------------------------------------------------------------


def test_escape_from_no_match_focuses_first_visible_row_or_container(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("if (document.activeElement === feedFilterInput) {")
    end = html.index("return;", start)
    block = html[start:end]
    assert "if (visibleFeedEntries().length) {" in block
    assert "jumpActiveFeedEntry(false);" in block
    assert "setActiveFeedEntry(null);" in block
    assert "feedEl.focus();" in block


def test_visible_feed_entries_reversed_to_match_newest_first_dom(tmp_path):
    html = _index_html(tmp_path)
    assert (
        "return feedEntries.filter(function (entry) { return !entry.li.hidden; }).reverse();"
    ) in html


# --------------------------------------------------------------------------
# 7. `r` announces; blocked mode-form dismiss appends, doesn't replace
# --------------------------------------------------------------------------


def test_manual_refresh_announces_counts(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function manualRefresh() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "Promise.all([refreshStats(), refreshPending()]).then(function () {" in block
    assert '"Refreshed - " + (lastTotalDecisions != null ? lastTotalDecisions : 0) +' in block
    assert '" decisions, " + lastPendingCountForFavicon + " pending"' in block


def test_blocked_dismiss_appends_after_the_consequence_sentence(tmp_path):
    html = _index_html(tmp_path)
    assert "function modeConsequenceText() {" in html
    start = html.index("function attemptCloseModeForm() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "var consequence = modeConsequenceText();" in block
    assert (
        'modeHintEl.textContent = (consequence ? consequence + " " : "") +\n'
        '            MODE_FORM_BLOCKED_DISMISS_HINT + ".";'
    ) in block


# --------------------------------------------------------------------------
# 8. Newest-first feed (prepend), oldest truncated last, no mobile trap
# --------------------------------------------------------------------------


def test_feed_rows_are_prepended_not_appended(tmp_path):
    html = _index_html(tmp_path)
    assert "feedEl.insertBefore(li, feedEl.firstChild);" in html
    assert "feedEl.appendChild(li);" not in html


def test_truncation_drops_the_last_child_now_that_oldest_is_last(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("while (feedEl.children.length > MAX_FEED_ROWS) {")
    end = html.index("\n          }", start)
    block = html[start:end]
    assert "feedEntries.shift();" in block
    assert "feedEl.removeChild(feedEl.lastChild);" in block


def test_near_top_scroll_pin_replaces_near_bottom(tmp_path):
    html = _index_html(tmp_path)
    assert "var nearTop = feedEl.scrollTop < 4;" in html
    assert "if (nearTop) {\n            feedEl.scrollTop = 0;\n          }" in html
    assert "nearBottom" not in html


def test_mobile_feed_drops_its_inner_scroller(tmp_path):
    html = _index_html(tmp_path)
    media_start = html.rindex("@media (max-width: 640px) {")
    assert html.index("#feed { max-height: none; overflow-y: visible; }", media_start) > media_start


# --------------------------------------------------------------------------
# 9. Plural no-match copy once two filters stack; mobile theme toggle
# --------------------------------------------------------------------------


def test_no_match_copy_is_plural_when_two_filters_active(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("if (noMatch) {")
    end = html.index("\n        }", start)
    block = html[start:end]
    assert "var twoFiltersActive = Boolean(activeVerdict) && Boolean(activeQuery);" in block
    assert '"No decisions match these filters."' in block
    assert '"No decisions match this filter."' in block


def test_panel_theme_toggle_present_for_390px_reachability(tmp_path):
    html = _index_html(tmp_path)
    # Always in the DOM inside the "?" panel - CSS hides the standalone
    # topbar toggle at <=640px, but this one takes over regardless of width.
    assert '<button type="button" id="panel-theme-toggle-btn">Switch to light theme</button>' in html
