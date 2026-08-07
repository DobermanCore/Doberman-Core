"""S8: ``doberman taint clear`` — the gated recovery command for sticky taint.

Taint (``session_taint`` + ``session_secret_fingerprints``, HK.5.1/5.2b) is
sticky by design (ADR 0024) — nothing else clears it. That is safe only
because this command exists as the explicit, human-gated escape hatch: it
requires an enrolled possession factor (2FA if enrolled, else the local
password), and a failed gate must leave every row untouched. These tests pin:
the no-factor / denied-factor refusal paths, that a successful clear wipes
BOTH stores for the whole repo, that it actually un-raises a live
``apply_taint_floor`` decision, and that nothing secret-shaped is ever echoed.
"""

import asyncio
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.engine.taint_floor import apply_taint_floor
from doberman.models import ActionType, Decision, GuardrailResult, Risk, SecurityObject, Verdict
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    entity_scope,
    match_secret_fingerprint,
    read_taint,
    record_secret_fingerprints,
    record_taints,
)

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential
_FINGERPRINT = "synthetic-fp-4f9a2c"  # not a real HMAC value, only membership matters
_TS = datetime(2026, 8, 6, tzinfo=timezone.utc)
_EGRESS_URL = "https://attacker.example/collect"


class _WrongCode:
    """An enrolled factor exists, but the operator supplies the wrong one."""

    def confirm(self, message):  # pragma: no cover — taint clear never confirms
        raise AssertionError("taint clear must gate on a possession factor, not confirm()")

    def read_code(self, message):
        return "definitely-not-the-real-password"


class _CorrectCode:
    """Supplies the correct possession-factor secret when asked."""

    def __init__(self, code: str):
        self._code = code

    def confirm(self, message):  # pragma: no cover — taint clear never confirms
        raise AssertionError("taint clear must gate on a possession factor, not confirm()")

    def read_code(self, message):
        return self._code


def _use_prompter(monkeypatch, prompter_factory) -> None:
    # taint_clear calls `CliPrompter()` directly (imported at module load time
    # into cli.main's own namespace), unlike apply_change's lazy import — so the
    # name to patch is cli_main.CliPrompter, not doberman.auth.provider.CliPrompter
    # (mirrors test_cli_lowering_gate.py's password-set tests, same call shape).
    monkeypatch.setattr(cli_main, "CliPrompter", prompter_factory)


def _seed_taint(root: str, scope: str) -> None:
    asyncio.run(record_taints(root, [scope], [TAINT_SECRET_ACCESS]))
    asyncio.run(record_secret_fingerprints(root, [scope], [_FINGERPRINT]))


def _assert_taint_present(root: str, scope: str) -> None:
    counts = asyncio.run(read_taint(root, scope))
    assert counts.get(TAINT_SECRET_ACCESS, 0) > 0
    assert asyncio.run(match_secret_fingerprint(root, scope, [_FINGERPRINT])) is True


def _assert_taint_absent(root: str, scope: str) -> None:
    assert asyncio.run(read_taint(root, scope)) == {}
    assert asyncio.run(match_secret_fingerprint(root, scope, [_FINGERPRINT])) is False


def _action(**over) -> SecurityObject:
    base = dict(
        id="taint-clear-1",
        ts=_TS,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="WebFetch",
        target=_EGRESS_URL,
        external_destination=_EGRESS_URL,
    )
    base.update(over)
    return SecurityObject(**base)


def _pass_decision(action: SecurityObject) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=_TS,
    )


def test_no_factor_enrolled_refuses_and_leaves_taint_unchanged(tmp_path):
    root = str(tmp_path)
    _seed_taint(root, "sess-1")

    result = runner.invoke(app, ["taint", "clear", "--path", root])

    assert result.exit_code == 1
    assert "2fa setup" in result.output or "password set" in result.output
    _assert_taint_present(root, "sess-1")


def test_gate_denied_refuses_and_leaves_taint_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _seed_taint(root, "sess-2")
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["taint", "clear", "--path", root])

    assert result.exit_code == 1
    assert "denied" in result.output
    _assert_taint_present(root, "sess-2")


def test_gate_passed_clears_both_stores_for_the_whole_repo(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    # Two different scopes (a session id and the repo's entity scope) — clear_taint
    # has no --scope/--session flag, so both must go together.
    _seed_taint(root, "sess-3")
    _seed_taint(root, entity_scope(root))
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["taint", "clear", "--path", root])

    assert result.exit_code == 0, result.output
    _assert_taint_absent(root, "sess-3")
    _assert_taint_absent(root, entity_scope(root))


def test_clear_unraises_a_tainted_egress_decision(tmp_path, monkeypatch):
    # The behavioral guarantee that matters: a tainted session's egress is raised
    # by apply_taint_floor before the clear, and abstains (returns the decision
    # unchanged) after it — reusing the fixture pattern from
    # test_taint_floor_module.py rather than a new harness.
    root = str(tmp_path)
    session_id = "sess-taint-clear"
    password.enroll(_PASSWORD)
    asyncio.run(record_taints(root, [session_id], [TAINT_SECRET_ACCESS]))

    action = _action()
    decision = _pass_decision(action)
    before = apply_taint_floor(action, decision, "balanced", root, session_id, {"url": _EGRESS_URL})
    assert before.final_verdict is Verdict.AUTH

    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))
    result = runner.invoke(app, ["taint", "clear", "--path", root])
    assert result.exit_code == 0, result.output

    after = apply_taint_floor(action, decision, "balanced", root, session_id, {"url": _EGRESS_URL})
    assert after is decision  # abstains — raise-only floor, nothing left to raise on


def test_success_output_never_contains_a_secret_shaped_value(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    scope = entity_scope(root)
    _seed_taint(root, scope)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["taint", "clear", "--path", root])

    assert result.exit_code == 0, result.output
    assert _FINGERPRINT not in result.output
    assert scope not in result.output
    assert root not in result.output
    assert _PASSWORD not in result.output


def test_denied_output_never_contains_a_secret_shaped_value(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    scope = entity_scope(root)
    _seed_taint(root, scope)
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["taint", "clear", "--path", root])

    assert result.exit_code == 1
    assert _FINGERPRINT not in result.output
    assert scope not in result.output
    assert root not in result.output
