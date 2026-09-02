"""Unit tests for the round-9 (final, small) dashboard control-surface pass.

Covered here where the assertion is a served-HTML/JS/CSS string check; the
390px `#stats` height, the 1280x800 first-feed-row y, the chip's accessible
name, the announcer's no-re-announce behavior, and cross-theme rendering are
instead covered by a manual Chrome verification noted in the round-9 session
log/changelog.

1. The pending card's privacy note is now TRUE: `d` DENIES (blocks the
   action), it never sends it anywhere - the note no longer says "press d ...
   to review it there".
2. Mobile (<=640px) stats stay one scrollable line - `.stat-group` no longer
   wraps its own children into a stacked column.
3. One scroll: `#pending-empty` is a one-line note at every width (not just
   <=640px), and `#feed` carries no max-height/overflow-y at any width.
4. The "Needs attention" chip's title leads with its own visible label
   ("Needs attention: ..."), same for the enforcement badge's title
   ("enforcement: <word> - ...").
5. `renderConnection` tracks its own last-announced text, separate from the
   shared `announce()` dedupe, so an unrelated announcement landing in
   between two identical connection states can't force a re-announce.
6. The mode-form downgrade hint is two elements: `#mode-hint` (the
   requirement + threshold change, still block-colored) and the new
   `#mode-reassurance` (the "hard blocks stay in force" sentence, --fg-2).
7. Enter/click-to-expand scrolls the row into view AFTER it grows (next
   frame), not before.
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
# 1. Privacy note is now true: `d` denies, it never sends the action anywhere
# --------------------------------------------------------------------------


def test_privacy_note_no_longer_claims_press_d_reviews_it(tmp_path):
    html = _index_html(tmp_path)
    assert "press d" not in html
    start = html.index('privacyNote.className = "privacy-note";')
    end = html.index("li.appendChild(privacyNote);", start)
    block = html[start:end]
    assert "press d" not in block
    assert (
        '"The raw command stays in your terminal. To read it before " +\n'
        '            "deciding, leave this card alone - it moves there in "'
    ) in block


def test_d_is_documented_only_as_deny_in_the_shortcuts_panel(tmp_path):
    html = _index_html(tmp_path)
    start = html.index('<dt class="gated">d</dt>')
    end = html.index("</dd>", start)
    block = html[start:end]
    assert "Deny" in block
    assert "terminal" not in block.lower()


# --------------------------------------------------------------------------
# 2. Mobile stats stay one scrollable line
# --------------------------------------------------------------------------


def test_mobile_stat_group_does_not_wrap_its_own_children(tmp_path):
    html = _index_html(tmp_path)
    media_start = html.index("@media (max-width: 640px) {\n    #stats-decisions")
    media_end = html.index("\n  }", media_start)
    block = html[media_start:media_end]
    assert "#stats > * { flex: none; white-space: nowrap; }" in block


# --------------------------------------------------------------------------
# 3. One scroll: #pending-empty compact and #feed unbounded at every width
# --------------------------------------------------------------------------


def test_pending_empty_is_compact_unconditionally(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("#pending-empty {")
    end = html.index("}", start)
    block = html[start:end]
    assert "padding: .4rem 0; border: none; text-align: left; font-size: var(--fs-1);" in block
    # No longer a mobile-only override (test_dash_round5.py) - the compact
    # rule now applies at every width.
    media_start = html.rindex("@media (max-width: 640px) {")
    assert "#pending-empty {" not in html[media_start:]


def test_feed_has_no_max_height_at_any_width(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("#feed {")
    end = html.index("}", start)
    block = html[start:end]
    assert "max-height" not in block
    assert "overflow-y" not in block
    # No CSS declaration anywhere sets it any more (comments mentioning the
    # word are fine - no rule ever writes "max-height:" again).
    assert "max-height:" not in html


# --------------------------------------------------------------------------
# 4. Accessible name = visible label, chip titles lead with their own label
# --------------------------------------------------------------------------


def test_needs_attention_chip_title_leads_with_its_own_label(tmp_path):
    html = _index_html(tmp_path)
    assert ('title="Needs attention: BLOCK + AUTH - what Doberman stopped or escalated"') in html


def test_enforcement_badge_title_leads_with_its_own_label(tmp_path):
    html = _index_html(tmp_path)
    assert 'enforcementBadge.title = ENFORCEMENT_TITLE[s.enforcement] || "";' in html
    start = html.index("var ENFORCEMENT_TITLE = {")
    end = html.index("};", start)
    block = html[start:end]
    assert 'enforce: "enforcement: enforcing - ' in block
    assert 'monitor: "enforcement: monitoring - ' in block
    assert 'off: "enforcement: off - ' in block


# --------------------------------------------------------------------------
# 5. renderConnection tracks its own last-announced text
# --------------------------------------------------------------------------


def test_render_connection_tracks_its_own_last_announced_text(tmp_path):
    html = _index_html(tmp_path)
    assert "var lastConnectionText = null;" in html
    start = html.index("function renderConnection() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "if (text !== lastConnectionText) {" in block
    assert "lastConnectionText = text;" in block
    assert 'announce("Dashboard " + text + ".");' in block


# --------------------------------------------------------------------------
# 6. Mode downgrade hint is two elements: requirement (block) + reassurance (--fg-2)
# --------------------------------------------------------------------------


def test_mode_reassurance_is_its_own_element(tmp_path):
    html = _index_html(tmp_path)
    assert '<p id="mode-hint" aria-live="polite"></p>' in html
    assert '<p id="mode-reassurance"></p>' in html
    start = html.index("#mode-reassurance {")
    end = html.index("}", start)
    assert "color: var(--fg-2)" in html[start:end]


def test_mode_consequence_text_no_longer_includes_the_reassurance(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function modeConsequenceText() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "hard blocks" not in block.lower()


def test_mode_reassurance_text_carries_the_hard_blocks_sentence(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function modeReassuranceText() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert (
        '"Hard blocks (secrets, destructive commands, protected paths) '
        'stay in force regardless of mode."'
    ) in block
    assert 'computeModeDirection() === "lower"' in block


# --------------------------------------------------------------------------
# 7. Expand-then-scroll: scrollIntoView runs AFTER the row grows (next frame)
# --------------------------------------------------------------------------


def test_expand_scrolls_into_view_after_growth_next_frame(tmp_path):
    html = _index_html(tmp_path)
    start = html.index("function toggleActiveFeedExplanation() {")
    end = html.index("\n      }", start)
    block = html[start:end]
    assert "requestAnimationFrame(function () {" in block
    assert 'li.scrollIntoView({ block: "nearest" });' in block
    # The rAF callback must come AFTER hidden/aria-expanded are flipped, not before.
    assert block.index("glossListEl.hidden = !expanded;") < block.index("requestAnimationFrame")
