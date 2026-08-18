"""Unit tests for the D5 dashboard visual polish (badges, header, empty states).

D5 only touches the inline HTML/CSS/JS shell served by ``GET /`` - no new
endpoints, no change to auth, redaction, or decision-path behavior (those are
covered by the D1/D2/D3 test files and remain untouched here). These tests
assert the shell carries the new visual surface:

* verdict / risk / enforcement badge-class lookup tables (exact-substring
  matchable, so a future change to the mapping is caught here);
* a header bar that renders the current mode + enforcement dial from
  ``/api/stats``'s existing ``mode``/``enforcement`` fields;
* CSS-only empty-state markup for both the feed and the pending-approvals
  list (no JS toggling `style.display`);
* the dark-by-default palette formalized as CSS custom properties;
* the pending-card risk badge mirrors the terminal's
  ``[RISK: {risk.upper()}]`` convention (``src/doberman/auth/provider.py``).
"""

from starlette.testclient import TestClient

from doberman.dash.app import create_app

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret


def _index_html(tmp_path) -> str:
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.get("/")
    assert resp.status_code == 200
    return resp.text


def test_shell_still_never_leaks_the_token(tmp_path):
    assert _TOKEN not in _index_html(tmp_path)


def test_verdict_badge_classes_present(tmp_path):
    html = _index_html(tmp_path)
    assert 'PASS: "badge badge-pass"' in html
    assert 'AUTH: "badge badge-auth"' in html
    assert 'BLOCK: "badge badge-block"' in html


def test_risk_badge_classes_present(tmp_path):
    html = _index_html(tmp_path)
    assert 'low: "badge badge-risk-low"' in html
    assert 'medium: "badge badge-risk-medium"' in html
    assert 'high: "badge badge-risk-high"' in html
    assert 'critical: "badge badge-risk-critical"' in html


def test_enforcement_badge_classes_present(tmp_path):
    html = _index_html(tmp_path)
    assert 'enforce: "badge badge-pass"' in html
    assert 'monitor: "badge badge-auth"' in html
    assert 'off: "badge badge-block"' in html


def test_header_bar_renders_mode_and_enforcement(tmp_path):
    html = _index_html(tmp_path)
    assert 'id="mode-badge"' in html
    assert 'id="enforcement-badge"' in html
    # Populated from /api/stats's existing mode/enforcement fields client-side
    # - stats.py needed no changes for D5.
    assert "s.mode" in html
    assert "s.enforcement" in html


def test_feed_has_a_designed_empty_state(tmp_path):
    html = _index_html(tmp_path)
    assert 'id="feed-empty"' in html
    assert 'class="empty-state"' in html
    # CSS-only reveal via a sibling combinator - no JS toggles display here.
    assert "#feed:not(:empty)" in html


def test_pending_list_still_has_a_designed_empty_state(tmp_path):
    html = _index_html(tmp_path)
    assert 'id="pending-empty"' in html
    assert "#pending-list:not(:empty)" in html
    # The old JS-driven toggle is gone in favor of the same CSS pattern used
    # for the feed.
    assert "pendingEmpty" not in html


def test_dark_theme_is_the_default_via_css_custom_properties(tmp_path):
    html = _index_html(tmp_path)
    assert "color-scheme: dark light;" in html
    assert "--bg: #0b0d10;" in html
    assert "@media (prefers-color-scheme: light)" in html


def test_pending_card_mirrors_terminal_risk_badge_convention(tmp_path):
    html = _index_html(tmp_path)
    # Mirrors the terminal's "[RISK: {risk.upper()}]" convention (see
    # src/doberman/auth/provider.py) inside the dashboard's pending cards.
    assert '"RISK: " + (row.risk || "-").toUpperCase()' in html


def test_feed_and_pending_rows_still_use_textcontent_only(tmp_path):
    html = _index_html(tmp_path)
    # The no-innerHTML-assignment discipline must survive the restyle: every
    # row-derived field is still assigned via .textContent, never innerHTML.
    # (The word "innerHTML" legitimately appears in comments documenting this
    # discipline, so assert on the assignment form specifically.)
    assert ".innerHTML" not in html


def test_stats_refresh_on_an_interval_not_just_at_load(tmp_path):
    html = _index_html(tmp_path)
    # Counters must track the live feed instead of freezing at their
    # page-load values.
    assert "function refreshStats()" in html
    assert "setInterval(refreshStats, STATS_REFRESH_MS)" in html


def test_feed_timestamp_renders_compact_not_full_iso(tmp_path):
    html = _index_html(tmp_path)
    # HH:MM:SS sliced from the ISO string; the full timestamp stays available
    # in `doberman log` / the TUI.
    assert ".slice(11, 19)" in html
    assert '" @ " + row.ts;' not in html


def test_pending_list_is_not_rebuilt_when_the_queue_is_unchanged(tmp_path):
    """The 2s poll used to rebuild every card, destroying the focused TOTP input
    and any digits already typed. A queued approval is immutable once written, so
    an unchanged id set must short-circuit before the list is cleared."""
    html = _index_html(tmp_path)
    assert "lastPendingKey" in html
    assert 'var key = rows.map(function (row) { return row.id; }).join(",");' in html
    # The guard must come BEFORE the clear, or it does nothing.
    assert html.index("if (key === lastPendingKey) { return; }") < html.index(
        'pendingList.textContent = "";'
    )


def test_the_totp_field_is_masked(tmp_path):
    """It is a live second factor and this screen gets shared and recorded."""
    html = _index_html(tmp_path)
    assert 'totpInput.type = "password";' in html
    assert 'totpInput.type = "text";' not in html


def test_feed_row_renders_a_risk_badge(tmp_path):
    """A PASS row with no path class and no reason codes (e.g. shell_exec)
    used to render as bare noise ("PASS shell_exec — — @ ..."); the risk
    badge is the signal that always shows, even at "low"."""
    html = _index_html(tmp_path)
    assert "riskBadge.className = RISK_BADGE_CLASS[row.risk]" in html
    assert 'riskBadge.textContent = (row.risk || "-").toUpperCase();' in html


def test_feed_row_renders_source_context(tmp_path):
    html = _index_html(tmp_path)
    assert '" from:" + (row.source_context || "-") +' in html
