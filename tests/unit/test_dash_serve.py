"""Unit tests for the D1 dashboard serving skeleton (``doberman.dash``).

D1 is the serving skeleton only: an app factory, bearer-token auth, and the
inline HTML shell (no feed/stats/approve-deny yet - those are later slices).
Covers:

* the lazy-import guarantee: importing ``doberman`` (and the CLI module)
  never pulls in ``doberman.dash`` or ``starlette``;
* API auth: missing token -> 401, wrong token -> 401, correct token -> 200;
* the HTML shell (``GET /``) is served without auth and carries no token
  value;
* the CLI ``dash`` command's friendly install-hint + non-zero exit when the
  optional 'dash' extra is missing;
* the serve entry point binds to 127.0.0.1 only (no real socket is bound).
"""

import subprocess
import sys

import pytest
from typer.testing import CliRunner

runner = CliRunner()


def test_importing_doberman_never_pulls_in_dash_or_starlette():
    # Run in a fresh interpreter: order-independent of every other test below,
    # which legitimately imports doberman.dash / starlette for the app tests.
    code = (
        "import sys; "
        "import doberman; "
        "import doberman.cli.main; "
        "assert 'doberman.dash' not in sys.modules; "
        "assert 'starlette' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)  # noqa: S603


# --------------------------------------------------------------------------
# Everything below imports doberman.dash / starlette directly - fine, this
# process is not the one the lazy-import guarantee above is checking.
# --------------------------------------------------------------------------

from starlette.testclient import TestClient  # noqa: E402

from doberman.dash import app as app_module  # noqa: E402
from doberman.dash.app import create_app  # noqa: E402

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app(_TOKEN))


def test_health_without_token_is_401(client: TestClient):
    resp = client.get("/api/health")
    assert resp.status_code == 401


def test_health_with_wrong_token_is_401(client: TestClient):
    resp = client.get("/api/health", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_health_with_malformed_auth_header_is_401(client: TestClient):
    # No "Bearer " prefix at all.
    resp = client.get("/api/health", headers={"Authorization": _TOKEN})
    assert resp.status_code == 401


def test_health_with_correct_token_is_200(client: TestClient):
    resp = client.get("/api/health", headers={"Authorization": f"Bearer {_TOKEN}"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_index_serves_html_shell_without_auth(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # The shell carries no data - in particular, never the token value.
    assert _TOKEN not in resp.text


def test_index_serves_the_brand_mark_inline(client: TestClient):
    """The header carries the real Doberman mark as an inline data URI: no static-file
    route to protect, no placeholder left behind, and the payload really is a PNG."""
    import base64

    resp = client.get("/")
    assert "%%DASH_MARK_PNG_B64%%" not in resp.text
    prefix = 'src="data:image/png;base64,'
    start = resp.text.index(prefix) + len(prefix)
    payload = resp.text[start : resp.text.index('"', start)]
    png_signature = bytes.fromhex("89504e470d0a1a0a")
    assert base64.b64decode(payload, validate=True).startswith(png_signature)


def test_index_feed_handler_keeps_stats_in_step(client: TestClient):
    """A new feed row schedules a (debounced) stats refresh, so the counters never sit
    up to STATS_REFRESH_MS behind the list. The JS ships inline in the shell, so the
    served page is the only place this wiring can be checked without a browser."""
    shell = client.get("/").text
    assert "function syncStatsSoon()" in shell
    decision_handler = shell[shell.index('source.addEventListener("decision"') :]
    assert "syncStatsSoon();" in decision_handler


def test_cli_dash_missing_extra_exits_nonzero_with_install_hint(monkeypatch):
    from doberman.cli.main import app as cli_app

    # Simulate the optional 'dash' extra not being installed: a None entry in
    # sys.modules makes any import of that dotted path raise ImportError.
    monkeypatch.setitem(sys.modules, "doberman.dash", None)

    result = runner.invoke(cli_app, ["dash"])

    assert result.exit_code != 0
    assert result.stderr.startswith("error: ")
    assert 'pip install "doberman-core[dash]"' in result.stderr


def test_dash_binds_localhost_only():
    from doberman.cli import main as cli_main

    # Assert the constant the `dash` command passes to uvicorn.run - never
    # actually bind a socket in a test.
    assert cli_main._DASH_HOST == "127.0.0.1"


def test_dash_disables_uvicorn_access_log(monkeypatch, tmp_path):
    # The single-use bearer token rides in the URL query string, so uvicorn's
    # default request access log would write it into a log line
    # (`GET /?token=<secret> ...`). The `dash` command must disable the access
    # log so the token never lands in a log. Never bind a real socket: capture
    # the uvicorn.run call and stub the heartbeat side effect.
    import uvicorn

    from doberman.cli.main import app as cli_app

    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda _app, **kwargs: captured.update(kwargs))
    monkeypatch.setattr("doberman.storage.heartbeat.touch_heartbeat", lambda _path: None)

    result = runner.invoke(cli_app, ["dash", "--port", "0", "--path", str(tmp_path)])

    assert result.exit_code == 0
    assert captured.get("access_log") is False


def test_shell_pending_arrivals_are_announced_once():
    """Arrivals reach a screen reader through ONE polite live region - the
    shared #announcer (updateGuardStatus announces "ALERT: N pending") - not a
    second aria-live on the list itself, which read every card twice."""
    shell = app_module._HTML_SHELL
    assert 'id="announcer" class="sr-only" aria-live="polite"' in shell
    assert '<ul id="pending-list"></ul>' in shell
    assert 'id="pending-list" aria-live' not in shell


def test_shell_totp_input_has_aria_label():
    assert 'totpInput.setAttribute("aria-label", "TOTP code")' in app_module._HTML_SHELL


def test_shell_approve_requires_arm_then_confirm():
    assert "Confirm approve" in app_module._HTML_SHELL
    assert "armTimer" in app_module._HTML_SHELL


def test_shell_has_no_side_stripe():
    assert "border-left: 3px" not in app_module._HTML_SHELL


def test_shell_light_mode_retunes_verdict_colors():
    # the light block must override the verdict tokens, not just bg/ink
    light = app_module._HTML_SHELL.split("prefers-color-scheme: light", 1)[1].split("}")[0]
    for var in ("--pass:", "--auth:", "--block:", "--neutral:"):
        assert var in light


def test_shell_titles_pending_count():
    assert "document.title = (rows.length" in app_module._HTML_SHELL


def test_shell_renders_pending_expiry():
    assert "expires " in app_module._HTML_SHELL


def test_shell_light_mode_verdict_colors_pass_wcag_aa_contrast():
    # Light-mode verdict badge text on 12% tint background must clear
    # WCAG AA 4.5:1 contrast ratio.
    light = app_module._HTML_SHELL.split("prefers-color-scheme: light", 1)[1].split("}")[0]
    assert "--pass: #116329;" in light
    assert "--auth: #7d5200;" in light
    assert "--block: #a40e26;" in light
    assert "--neutral: #424a53;" in light
