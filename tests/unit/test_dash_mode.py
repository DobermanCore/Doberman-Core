"""Unit tests for D6 — changing the strictness mode from the dashboard.

``GET /api/mode`` / ``POST /api/mode`` route through the SAME chokepoint as
``doberman mode``/``doberman setup`` (:func:`doberman.policy.drift.
apply_mode_change`), so these tests focus on the HTTP-layer contract (auth,
field validation, status codes) and on the two invariants that must hold no
matter which caller reaches the gate:

* raising strictness is always frictionless (no code required, never denied);
* lowering strictness is denied without a valid possession factor, and the
  dash server never verifies that factor itself (mirrors ``/api/resolve`` -
  see ``test_dash_app_never_imports_totp`` in ``test_dash_approve_deny.py``).
"""

import asyncio

import pyotp
from starlette.testclient import TestClient

from doberman.auth import password, totp
from doberman.config import load_mode
from doberman.dash.app import create_app
from doberman.policy.drift import read_policy_changes

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret
_PASSWORD = "correct horse battery staple"  # noqa: S105 - synthetic test credential


def _client(root: str) -> TestClient:
    return TestClient(create_app(_TOKEN, root))


def _enrolled_totp_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def _headers() -> dict:
    return {"Authorization": f"Bearer {_TOKEN}"}


def _post_mode(client: TestClient, mode: str, code: str | None = None):
    body = {"mode": mode}
    if code is not None:
        body["code"] = code
    return client.post("/api/mode", headers=_headers(), json=body)


# --- auth matrix -------------------------------------------------------------


def test_get_mode_without_token_is_401(tmp_path):
    resp = _client(str(tmp_path)).get("/api/mode")
    assert resp.status_code == 401


def test_post_mode_without_token_is_401(tmp_path):
    resp = _client(str(tmp_path)).post("/api/mode", json={"mode": "strict"})
    assert resp.status_code == 401


def test_post_mode_with_wrong_token_is_401(tmp_path):
    resp = _client(str(tmp_path)).post(
        "/api/mode",
        headers={"Authorization": "Bearer wrong"},
        json={"mode": "strict"},
    )
    assert resp.status_code == 401


# --- GET: current mode + valid names -----------------------------------------


def test_get_mode_reports_current_mode_and_valid_names(tmp_path):
    root = str(tmp_path)
    resp = _client(root).get("/api/mode", headers=_headers())

    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "balanced"  # default, fresh repo
    assert set(body["modes"]) == {"light", "balanced", "strict", "paranoid"}


# --- raising: always frictionless --------------------------------------------


def test_raising_mode_applies_with_no_code_and_never_denied(tmp_path):
    root = str(tmp_path)
    client = _client(root)

    resp = _post_mode(client, "strict")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"mode": "strict"}
    assert load_mode(root) == "strict"
    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approval_method"] == "auto"
    assert rows[0]["approved"] == 1


def test_noop_mode_change_applies_with_no_gate_and_no_ledger_row(tmp_path):
    root = str(tmp_path)
    client = _client(root)

    resp = _post_mode(client, "balanced")  # already the default

    assert resp.status_code == 200, resp.text
    assert load_mode(root) == "balanced"
    assert asyncio.run(read_policy_changes(root)) == []


# --- lowering: gated behind a possession factor ------------------------------


def test_lowering_with_no_factor_enrolled_is_denied_and_unchanged(tmp_path):
    root = str(tmp_path)
    client = _client(root)

    resp = _post_mode(client, "light")

    assert resp.status_code == 403
    assert resp.json() == {"error": "mode change denied"}
    assert load_mode(root) == "balanced"  # unchanged
    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approval_method"] == "no_factor_enrolled"
    assert rows[0]["approved"] == 0


def test_lowering_with_no_code_supplied_is_denied(tmp_path):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    client = _client(root)

    resp = _post_mode(client, "light")  # no "code" in the body at all

    assert resp.status_code == 403
    assert load_mode(root) == "balanced"


def test_lowering_with_valid_totp_code_applies_and_persists(tmp_path):
    root = str(tmp_path)
    code = _enrolled_totp_code()
    client = _client(root)

    resp = _post_mode(client, "light", code=code)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"mode": "light"}
    assert load_mode(root) == "light"
    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approval_method"] == "two_factor"
    assert rows[0]["approved"] == 1


def test_lowering_with_wrong_totp_code_is_denied(tmp_path):
    root = str(tmp_path)
    _enrolled_totp_code()
    client = _client(root)

    resp = _post_mode(client, "light", code="000000")

    assert resp.status_code == 403
    assert load_mode(root) == "balanced"


def test_lowering_with_valid_password_applies_when_totp_not_enrolled(tmp_path):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    client = _client(root)

    resp = _post_mode(client, "light", code=_PASSWORD)

    assert resp.status_code == 200, resp.text
    assert load_mode(root) == "light"
    rows = asyncio.run(read_policy_changes(root))
    assert rows[0]["approval_method"] == "password"


def test_lowering_with_wrong_password_is_denied(tmp_path):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    client = _client(root)

    resp = _post_mode(client, "light", code="not the password")

    assert resp.status_code == 403
    assert load_mode(root) == "balanced"


# --- validation ----------------------------------------------------------------


def test_unknown_mode_name_is_400(tmp_path):
    root = str(tmp_path)
    resp = _post_mode(_client(root), "extreme")

    assert resp.status_code == 400
    assert "unknown security mode" in resp.json()["error"]
    assert load_mode(root) == "balanced"


def test_missing_mode_field_is_400(tmp_path):
    resp = _client(str(tmp_path)).post("/api/mode", headers=_headers(), json={})
    assert resp.status_code == 400


# --- redaction / structural guarantees -----------------------------------------


def test_dash_app_still_never_imports_totp():
    """The mode route must not weaken this existing D3 guarantee."""
    import doberman.dash.app as dash_app_module

    assert "totp" not in vars(dash_app_module)


def test_password_never_appears_in_the_response(tmp_path):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    resp = _post_mode(_client(root), "light", code=_PASSWORD)

    assert resp.status_code == 200
    assert _PASSWORD not in resp.text
