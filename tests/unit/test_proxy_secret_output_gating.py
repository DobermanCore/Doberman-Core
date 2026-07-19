"""parity-1: the pure-MCP proxy's output-scan secret gate.

The host-hook's ``PostToolUse`` scan (``doberman.hosthooks.claude_code.evaluate_post``)
hard-blocks a tool result carrying credential-like material before it reaches the
model. Until now ``decide_and_execute`` (``doberman.proxy.executor``) recorded
output taint (PR #118) but never ran that same gate, so a secret-bearing result
from a downstream MCP tool passed straight through. ``_scan_output_for_secrets``
closes that gap by re-running the RESULT text through the same
``ObjectiveGuardrail`` / ``doberman.engine.rules.secrets`` detection used
everywhere else — no duplicated detector.

These tests drive the REAL, unstubbed ``decide_and_execute`` end to end, the
same way ``test_proxy_taint_floor.py`` does, and prove the parity-1 properties:
a secret-bearing result is gated to BLOCK, the raw secret never appears in the
response text or in any persisted decision row, a benign result is unaffected,
and a broken scan fails closed instead of leaking the output.

``executor._safe_decide`` is stubbed to a deterministic PASS (imported from
``test_proxy_taint_floor``) so the pre-execution objective/subjective engine's
own scoring stays out of scope — only the POST-execution output-scan gate is
under test here.
"""

import json
from datetime import datetime, timezone

import pytest

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.models import ReasonCode
from doberman.proxy import executor
from doberman.proxy.executor import _safe_decide as _real_safe_decide
from doberman.storage.db import db_path
from doberman.storage.log import read_decisions
from tests.unit.test_proxy_taint_floor import _FakeSession, _ok_result, _pass_decision


# Re-declared (not imported) so this file's autouse fixture is unambiguously
# scoped here too — importing a fixture's *name* into another test module relies
# on pytest's module-namespace fixture discovery; defining it locally next to
# the tests it isolates is one line cheaper to verify by reading this file alone.
@pytest.fixture(autouse=True)
def _deterministic_baseline_decision(monkeypatch):
    monkeypatch.setattr(executor, "_safe_decide", lambda action, _ctx: _pass_decision(action))


_SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _write_role(repo_root):
    cfg = repo_root / ".doberman"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "role.yaml").write_text(
        'name: webdev\nallowed:\n  - "frontend/**"\nsuspicious:\n  - "backend/**"\n',
        encoding="utf-8",
    )


async def _rows() -> list[dict]:
    return await read_decisions(executor.REPO_ROOT)


async def test_secret_output_triggers_block_gate_without_leaking_secret():
    # The request itself is unremarkable (a plain local read) — only the
    # downstream RESULT carries the secret, so the pre-execution decision is a
    # clean PASS and the call is forwarded; the output-scan gate must then
    # intercept the RESPONSE before it reaches the model.
    session = _FakeSession({"fs_read": _ok_result(_SYNTHETIC_AWS_KEY)})

    result = await executor.decide_and_execute(session, "fs_read", {"path": "cfg.txt"})

    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert ReasonCode.sensitive_secret_access.value in result.content[0].text
    assert _SYNTHETIC_AWS_KEY not in result.content[0].text
    # The downstream WAS called — the gate blocks the RESPONSE, not the call.
    assert session.calls == [("fs_read", {"path": "cfg.txt"})]

    # Log parity: exactly one row — the synthetic BLOCK — not the original PASS
    # (mirrors the host-hook: a gated output produces one log entry, the block).
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "BLOCK"
    assert ReasonCode.sensitive_secret_access.value in rows[0]["reason_codes_json"]
    assert rows[0]["auth_result"] == "blocked"

    # The secret never appears in ANY persisted artifact: the parsed rows, nor
    # the raw db file bytes on disk.
    assert _SYNTHETIC_AWS_KEY not in json.dumps(rows)
    assert _SYNTHETIC_AWS_KEY.encode() not in db_path(executor.REPO_ROOT).read_bytes()


async def test_benign_output_flows_unchanged():
    session = _FakeSession({"fs_read": _ok_result("just an ordinary config value")})

    result = await executor.decide_and_execute(session, "fs_read", {"path": "cfg.txt"})

    assert not result.isError
    assert result.content[0].text == "just an ordinary config value"
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "PASS"


async def test_scan_exception_fails_closed(monkeypatch):
    # DEFAULT_OBJECTIVE.evaluate is only reached from inside the output scan in
    # this test (the pre-execution decision is stubbed via _safe_decide above),
    # so raising here isolates a broken SCAN — not a broken pre-decision.
    def _boom(*_args, **_kwargs):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(executor.DEFAULT_OBJECTIVE, "evaluate", _boom)
    session = _FakeSession({"fs_read": _ok_result("nothing secret-shaped here")})

    result = await executor.decide_and_execute(session, "fs_read", {"path": "cfg.txt"})

    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert ReasonCode.objective_guardrail_error.value in result.content[0].text
    # The downstream was still called; only the broken scan's response is gated.
    assert session.calls == [("fs_read", {"path": "cfg.txt"})]
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "BLOCK"
    assert ReasonCode.objective_guardrail_error.value in rows[0]["reason_codes_json"]


async def test_gated_output_still_consumes_a_single_use_elevation(
    monkeypatch, isolated_executor_repo_root
):
    """Grant spending tracks EXECUTION, not output cleanliness (coordinator
    review, PR #126): the single-use elevation that released a destructive
    forward must be spent even when the RESULT is gated to BLOCK for a
    secret — otherwise the same grant could release a second execution just
    because the first result happened to contain a secret.
    """
    _write_role(isolated_executor_repo_root)
    # Restore the REAL decision engine for this test: the role rule reading
    # ctx.grants (not a stub) is what proves whether the elevation still
    # covers the second call.
    monkeypatch.setattr(executor, "_safe_decide", _real_safe_decide)
    calls = {"n": 0}

    def approve_elev(decision, action, *, prompter=None, at=None):
        calls["n"] += 1
        return AuthResult(
            approved=True,
            tier=AuthTier.role_elevation,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    monkeypatch.setattr(executor, "run_auth_challenge", approve_elev)
    session = _FakeSession({"fs_delete": _ok_result(_SYNTHETIC_AWS_KEY)})

    # 1) destructive, out-of-scope path -> AUTH -> single-use elevation granted
    #    -> the call DOES execute, but the RESULT carries a secret -> gated.
    result = await executor.decide_and_execute(session, "fs_delete", {"path": "backend/api.ts"})
    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert _SYNTHETIC_AWS_KEY not in result.content[0].text
    assert session.calls == [("fs_delete", {"path": "backend/api.ts"})]
    assert calls["n"] == 1

    # 2) SAME destructive call again: if the grant were left unspent because
    #    the first output was gated, this would silently ride the same grant
    #    (no new challenge) and delete a second time for free. It must instead
    #    require a FRESH role-elevation challenge.
    result2 = await executor.decide_and_execute(session, "fs_delete", {"path": "backend/api.ts"})
    assert calls["n"] == 2, "the single-use grant was not consumed by the gated execution"
    assert result2.isError  # gated again (same secret-bearing response)
    assert session.calls == [
        ("fs_delete", {"path": "backend/api.ts"}),
        ("fs_delete", {"path": "backend/api.ts"}),
    ]
