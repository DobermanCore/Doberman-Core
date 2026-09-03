"""C2 — blast-radius preview v1: AUTH attaches effects; TOCTOU re-blocks on drift."""

from datetime import datetime, timezone
from unittest.mock import Mock

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.models import ReasonCode
from doberman.proxy import executor
from doberman.storage.log import read_decisions

from .test_proxy_passthrough import proxied_session


def _approve():
    def challenge(
        decision,
        action,
        *,
        prompter=None,
        at=None,
        message_tone=None,
        repo_root=None,
        session_id=None,
    ):
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    return challenge


async def test_delete_class_auth_carries_a_populated_effect_set(
    monkeypatch, isolated_executor_repo_root
):
    target = isolated_executor_repo_root / "fixture"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")
    (target / "b.txt").write_text("x", encoding="utf-8")

    seen = {}

    def approve_and_capture(decision, action, **kwargs):
        # decision is the SAME object executor.py passes into run_auth_challenge
        # (mocked here) — the direct, unambiguous way to check what a real
        # prompter would see via current_challenge() without depending on
        # the real run_auth_challenge (which sets that contextvar) running.
        seen["effects"] = decision.effects
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    # Force AUTH regardless of the real rule's exact threshold — this test is
    # about the effects WIRING, not the destructive-command rule's own logic
    # (that rule is covered by tests/unit/test_rule_commands.py).
    from doberman.engine.decision_engine import StaticGuardrail
    from doberman.models import GuardrailResult, Risk, Verdict

    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.destructive_command],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", approve_and_capture)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "rm -rf fixture"})
    assert not result.isError
    assert seen["effects"] is not None
    assert seen["effects"].file_count == 2
    assert seen["effects"].dir_count == 1
    assert seen["effects"].capped is False


async def test_non_delete_auth_carries_no_effects_and_never_walks(
    monkeypatch, isolated_executor_repo_root
):
    from doberman.engine.decision_engine import StaticGuardrail
    from doberman.models import GuardrailResult, Risk, Verdict

    spy = Mock(side_effect=executor.compute_delete_effects)
    monkeypatch.setattr(executor, "compute_delete_effects", spy)
    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.sensitive_path_access],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", _approve())
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "ls -la"})
    assert not result.isError
    spy.assert_not_called()


async def test_toctou_reblocks_when_a_file_is_added_during_the_challenge(
    monkeypatch, isolated_executor_repo_root
):
    target = isolated_executor_repo_root / "fixture"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")

    def approve_but_race(decision, action, **kwargs):
        # Simulate the filesystem changing WHILE the (mocked) human is
        # looking at the challenge — before the approval is returned.
        (target / "b.txt").write_text("x", encoding="utf-8")
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    from doberman.engine.decision_engine import StaticGuardrail
    from doberman.models import GuardrailResult, Risk, Verdict

    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.destructive_command],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", approve_but_race)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "rm -rf fixture"})
    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert ReasonCode.effect_set_diverged.value in result.content[0].text
    assert fake.calls == []  # never forwarded

    rows = await read_decisions(executor.REPO_ROOT)
    assert rows[-1]["final_verdict"] == "BLOCK"
    assert ReasonCode.effect_set_diverged.value in rows[-1]["reason_codes_json"]


async def test_dynamic_delete_operand_never_reports_a_confirmed_count(
    monkeypatch, isolated_executor_repo_root
):
    # C2 Task 3 review: `$( )`/backtick/`${ }`/`$VAR` content in a delete
    # segment gets flattened away by walk_command (the substitution body
    # becomes its own sibling segment) — delete_class_operands then returns
    # an empty/partial operand list that must NEVER read as a confirmed
    # (possibly zero) blast radius.
    target = isolated_executor_repo_root / "real_dir"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")

    seen = {}

    def approve_and_capture(decision, action, **kwargs):
        # decision is the SAME object executor.py passes into run_auth_challenge
        # (mocked here) — the direct, unambiguous way to check what a real
        # prompter would see via current_challenge() without depending on
        # the real run_auth_challenge (which sets that contextvar) running.
        seen["effects"] = decision.effects
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    from doberman.engine.decision_engine import StaticGuardrail
    from doberman.models import GuardrailResult, Risk, Verdict

    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.destructive_command],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", approve_and_capture)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "rm -rf real_dir $(echo hidden)"})
    assert not result.isError
    assert seen["effects"] is not None
    assert seen["effects"].file_count is None
    assert seen["effects"].dir_count is None
    assert seen["effects"].capped is True


async def test_static_delete_operand_reports_a_confirmed_count(
    monkeypatch, isolated_executor_repo_root
):
    target = isolated_executor_repo_root / "real_dir"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")

    seen = {}

    def approve_and_capture(decision, action, **kwargs):
        # decision is the SAME object executor.py passes into run_auth_challenge
        # (mocked here) — the direct, unambiguous way to check what a real
        # prompter would see via current_challenge() without depending on
        # the real run_auth_challenge (which sets that contextvar) running.
        seen["effects"] = decision.effects
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    from doberman.engine.decision_engine import StaticGuardrail
    from doberman.models import GuardrailResult, Risk, Verdict

    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.destructive_command],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", approve_and_capture)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "rm -rf real_dir"})
    assert not result.isError
    assert seen["effects"] is not None
    assert seen["effects"].file_count == 1
    assert seen["effects"].dir_count == 1
    assert seen["effects"].capped is False
