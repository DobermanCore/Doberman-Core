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


def test_cli_dash_missing_extra_exits_nonzero_with_install_hint(monkeypatch):
    from doberman.cli.main import app as cli_app

    # Simulate the optional 'dash' extra not being installed: a None entry in
    # sys.modules makes any import of that dotted path raise ImportError.
    monkeypatch.setitem(sys.modules, "doberman.dash", None)

    result = runner.invoke(cli_app, ["dash"])

    assert result.exit_code != 0
    assert 'pip install "doberman-core[dash]"' in result.stderr


def test_dash_binds_localhost_only():
    from doberman.cli import main as cli_main

    # Assert the constant the `dash` command passes to uvicorn.run - never
    # actually bind a socket in a test.
    assert cli_main._DASH_HOST == "127.0.0.1"


def test_shell_pending_list_is_polite_live_region():
    assert 'id="pending-list" aria-live="polite"' in app_module._HTML_SHELL


def test_shell_totp_input_has_aria_label():
    assert 'totpInput.setAttribute("aria-label", "TOTP code")' in app_module._HTML_SHELL


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
