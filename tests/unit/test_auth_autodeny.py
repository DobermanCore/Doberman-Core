"""DOBERMAN_AUTODENY_AUTH — the dev-only, deny-only headless switch (ADR 0074).

The env var must deny every AUTH challenge *before any approval channel opens*
and must never be able to approve — it is a fail-closed escape hatch for
unattended dev/test runs, not an auth bypass.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from doberman.auth.challenge import AUTODENY_ENV, AUTODENY_METHOD, run_auth_challenge
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)


class _MustNotBeConsulted:
    """A prompter that fails the test if any channel is opened."""

    def confirm(self, message: str) -> bool:
        raise AssertionError("prompter consulted despite autodeny")

    def read_code(self, message: str) -> str:
        raise AssertionError("prompter consulted despite autodeny")


class _AlwaysYes:
    def confirm(self, message: str) -> bool:
        return True

    def read_code(self, message: str) -> str:
        return "000000"


def _auth_decision_and_action() -> tuple[Decision, SecurityObject]:
    action = SecurityObject(
        id="autodeny-test-action",
        ts=datetime.now(timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=None,
        external_destination=None,
        source_context=SourceContext.unknown,
        raw_args_redacted={},
        metadata={},
    )
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.egress_requires_auth],
        explanation="test challenge",
    )
    decision = Decision(
        action_id=action.id,
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.egress_requires_auth],
        explanation="test challenge",
        decided_at=datetime.now(timezone.utc),
    )
    return decision, action


def test_autodeny_denies_without_opening_any_channel(monkeypatch):
    monkeypatch.setenv(AUTODENY_ENV, "1")
    decision, action = _auth_decision_and_action()

    result = run_auth_challenge(decision, action, prompter=_MustNotBeConsulted())

    assert result.approved is False
    assert result.method == AUTODENY_METHOD
    assert result.action_id == action.id


@pytest.mark.parametrize("value", ["true", "TRUE", "yes", " 1 "])
def test_autodeny_accepts_common_truthy_spellings(monkeypatch, value):
    monkeypatch.setenv(AUTODENY_ENV, value)
    decision, action = _auth_decision_and_action()

    result = run_auth_challenge(decision, action, prompter=_MustNotBeConsulted())

    assert result.approved is False
    assert result.method == AUTODENY_METHOD


@pytest.mark.parametrize("value", ["0", "false", "", "no"])
def test_non_truthy_values_leave_the_challenge_live(monkeypatch, value):
    # With the switch off (or nonsense), the normal challenge path runs — the
    # prompter IS consulted. An _AlwaysYes prompter approving proves we took
    # the real path, not the autodeny shortcut.
    monkeypatch.setenv(AUTODENY_ENV, value)
    decision, action = _auth_decision_and_action()

    result = run_auth_challenge(decision, action, prompter=_AlwaysYes())

    assert result.method != AUTODENY_METHOD


def test_autodeny_can_never_approve(monkeypatch):
    # The whole point: even a prompter that says yes to everything cannot
    # produce an approval while the switch is set, because no channel is ever
    # consulted. Deny-only by construction — not an auth bypass.
    monkeypatch.setenv(AUTODENY_ENV, "1")
    decision, action = _auth_decision_and_action()

    result = run_auth_challenge(decision, action, prompter=_AlwaysYes())

    assert result.approved is False
    assert result.method == AUTODENY_METHOD
