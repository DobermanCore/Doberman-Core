"""The dashboard's session token must survive a reload of its own tab.

The page strips the token out of the address bar on load (so it can't leak via
history, a referrer, or a screen share), which means a refresh re-fetches a URL
that no longer carries it. These tests pin the two halves that have to hold at
once: the token is recoverable for *this tab*, and it is still never left in the
URL, the HTML, or anywhere that outlives the tab.

Assertions are on the served markup because the logic is inline JS with no
browser in the test suite - so they guard the contract, not the runtime.
"""

import pytest
from starlette.testclient import TestClient

from doberman.dash.app import create_app

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret


@pytest.fixture()
def shell() -> str:
    with TestClient(create_app(_TOKEN)) as client:
        resp = client.get("/")
    assert resp.status_code == 200
    return resp.text


def test_token_is_stashed_and_read_back_for_a_reload(shell: str):
    assert "sessionStorage.setItem(TOKEN_KEY" in shell
    assert "sessionStorage.getItem(TOKEN_KEY" in shell


def test_token_is_still_stripped_from_the_url(shell: str):
    """The privacy property the stripping exists for must survive the fix."""
    assert 'params.delete("token")' in shell
    assert "window.history.replaceState" in shell


def test_token_never_outlives_the_tab(shell: str):
    """sessionStorage (per-tab, cleared on close), never localStorage - a
    dashboard token must not persist after the tab is gone."""
    assert "localStorage" not in shell


def test_shell_never_embeds_the_token_value(shell: str):
    assert _TOKEN not in shell


def test_a_rejected_token_is_dropped_and_explains_the_way_back(shell: str):
    """A stale token must not be retried silently on every reload, and the dead
    end has to name its own fix."""
    assert "removeItem(TOKEN_KEY)" in shell
    assert "err.status === 401" in shell
    assert "reopen the link printed by doberman dash" in shell
