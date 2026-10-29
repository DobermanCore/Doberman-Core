"""#515: decision stamps describe evaluation inputs, never later policy files."""

from datetime import datetime, timezone

import pytest
from mcp.types import CallToolResult, TextContent

from doberman import __version__
from doberman.auth.challenge import AuthResult, AuthTier
from doberman.config import save_policy
from doberman.engine.decision_engine import PASS_STUB
from doberman.hosthooks import claude_code, codex, cursor, openclaw, spine
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict
from doberman.policy.checklist import recommend_policy
from doberman.proxy import executor
from doberman.storage.log import read_decisions, record_decision
from doberman.storage.policy_catalogue import build_snapshot, policy_version, read_snapshot


def _version(doc, state="enforce", resolved=None):
    return policy_version(build_snapshot(doc, None, state, __version__, resolved_policy=resolved))


async def test_proxy_keeps_evaluated_policy_when_files_change_before_logging(tmp_path, monkeypatch):
    root = str(tmp_path)
    original = recommend_policy().with_mode("balanced")
    changed = original.with_mode("strict")
    save_policy(original, root)
    monkeypatch.setattr(executor, "REPO_ROOT", root)
    monkeypatch.setattr(executor, "DEFAULT_SUBJECTIVE", PASS_STUB)
    decide = executor._safe_decide

    def evaluate_then_change(action, ctx):
        result = decide(action, ctx)
        assert ctx.mode == "balanced"
        save_policy(changed, root)
        return result

    async def forward(*args):
        return CallToolResult(content=[TextContent(type="text", text="ok")])

    monkeypatch.setattr(executor, "_safe_decide", evaluate_then_change)
    monkeypatch.setattr(executor, "_forward", forward)
    result = await executor.decide_and_execute(None, "bash", {"command": "echo hello"})

    assert not result.isError
    (row,) = await read_decisions(root)
    assert row["policy_version"] == _version(original)
    assert row["policy_version"] != _version(changed)
    assert read_snapshot(root, row["policy_version"])["doc"]["mode"] == "balanced"


@pytest.mark.parametrize("initial_state", ["enforce", "monitor", "off"])
@pytest.mark.parametrize("outcome", ["denied", "pass", "block"])
async def test_proxy_auth_snapshots_follow_the_decision_being_logged(
    tmp_path, monkeypatch, outcome, initial_state
):
    root = str(tmp_path)
    original = recommend_policy().with_mode("balanced")
    refreshed = original.with_mode("strict").with_enforcement("off")
    later = original.with_mode("paranoid")
    save_policy(original, root)
    monkeypatch.setattr(executor, "REPO_ROOT", root)
    monkeypatch.setattr(executor, "DEFAULT_SUBJECTIVE", PASS_STUB)
    modes = []
    forwarded = []

    class Rule:
        def evaluate(self, action, ctx):
            modes.append(ctx.mode)
            if len(modes) == 1:
                return GuardrailResult(
                    verdict=Verdict.AUTH,
                    risk=Risk.medium,
                    reason_codes=[ReasonCode.egress_requires_auth],
                    explanation="Approval required",
                )
            # Mutate again DURING re-evaluation, before its result is logged.
            save_policy(later, root)
            return GuardrailResult(
                verdict=Verdict.BLOCK if outcome == "block" else Verdict.PASS,
                risk=Risk.high if outcome == "block" else Risk.low,
                reason_codes=[ReasonCode.unusual_for_workflow] if outcome == "block" else [],
                explanation="Re-evaluated policy",
            )

    def challenge(decision, action, **kwargs):
        save_policy(refreshed, root)
        return AuthResult(
            approved=outcome != "denied",
            tier=AuthTier.local_auth,
            method="denied" if outcome == "denied" else "confirm",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    async def forward(*args):
        forwarded.append(True)
        return CallToolResult(content=[], isError=False)

    async def resolved_enforcement(*args, **kwargs):
        return initial_state

    monkeypatch.setattr(executor, "effective_enforcement", resolved_enforcement)
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", Rule())
    monkeypatch.setattr(executor, "run_auth_challenge", challenge)
    monkeypatch.setattr(executor, "_forward", forward)
    result = await executor.decide_and_execute(None, "bash", {"command": "echo hello"})

    (row,) = await read_decisions(root)
    assert modes == (["balanced"] if outcome == "denied" else ["balanced", "strict"])
    assert row["policy_version"] == (
        _version(refreshed, "enforce") if outcome == "block" else _version(original, initial_state)
    )
    snapshot = read_snapshot(root, row["policy_version"])
    assert snapshot["enforcement_effective"] == ("enforce" if outcome == "block" else initial_state)
    if outcome == "block":
        assert snapshot["doc"]["enforcement"] == "off"
    assert row["final_verdict"] == ("BLOCK" if outcome == "block" else "AUTH")
    assert bool(forwarded) == (outcome == "pass")
    assert result.isError == (outcome != "pass")


@pytest.mark.parametrize("host", ["claude", "codex", "cursor", "openclaw"])
def test_host_adapters_keep_evaluated_snapshot_when_policy_changes(tmp_path, monkeypatch, host):
    import asyncio

    root = str(tmp_path)
    original = recommend_policy().with_mode("balanced")
    save_policy(original, root)
    decide = spine.decide

    def evaluate_then_change(*args):
        decision = decide(*args)
        save_policy(original.with_mode("strict"), root)
        return decision

    monkeypatch.setattr(spine, "decide", evaluate_then_change)
    payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": root}
    if host == "claude":
        assert (
            claude_code.evaluate_pre(payload)["hookSpecificOutput"]["permissionDecision"] == "deny"
        )
    elif host == "codex":
        assert codex.evaluate_pre(payload)["hookSpecificOutput"]["permissionDecision"] == "deny"
    elif host == "cursor":
        payload.update(hook_event_name="beforeShellExecution", command="rm -rf /")
        assert cursor.evaluate(payload)["permission"] == "deny"
    else:
        payload.update(tool_name="exec", params={"command": "rm -rf /"})
        assert openclaw.evaluate_before_tool_call(payload)["verdict"] == "block"

    (row,) = asyncio.run(read_decisions(root))
    assert row["policy_version"] == _version(original)


async def test_logging_without_evaluation_snapshot_never_reads_current_policy(
    tmp_path, monkeypatch
):
    from doberman.engine.decision_engine import decide
    from doberman.engine.objective import ObjectiveGuardrail
    from doberman.models import EvalContext
    from doberman.proxy.normalize import normalize
    from doberman.storage import policy_catalogue

    action = normalize("bash", {"command": "echo hello"}, {"repo_root": str(tmp_path)})
    decision = decide(action, ObjectiveGuardrail(), PASS_STUB, EvalContext())

    def unexpected_read(*args, **kwargs):
        pytest.fail("Decision logging must never reconstruct an evaluation snapshot")

    monkeypatch.setattr(policy_catalogue, "current_snapshot", unexpected_read)
    assert await record_decision(decision, action, repo_root=str(tmp_path))
    (row,) = await read_decisions(str(tmp_path))
    assert row["policy_version"] is None


@pytest.mark.parametrize("secret_output", [False, True])
def test_post_hook_keeps_snapshot_captured_before_scan(tmp_path, monkeypatch, secret_output):
    import asyncio

    root = str(tmp_path)
    original = recommend_policy().with_mode("balanced")
    save_policy(original, root)
    guardrail = claude_code.ObjectiveGuardrail

    class ChangingGuardrail(guardrail):
        def evaluate(self, action, ctx):
            result = super().evaluate(action, ctx)
            save_policy(original.with_mode("strict"), root)
            return result

    monkeypatch.setattr(claude_code, "ObjectiveGuardrail", ChangingGuardrail)
    output = "AKIAIOSFODNN7EXAMPLE" if secret_output else "hello"  # noqa: S105 — synthetic
    result = claude_code.evaluate_post(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "tool_response": output,
            "cwd": root,
        }
    )
    assert (result is not None) == secret_output
    (row,) = asyncio.run(read_decisions(root))
    assert row["policy_version"] == _version(original)


async def test_snapshot_capture_failure_preserves_proxy_decision(tmp_path, monkeypatch):
    from doberman.storage import policy_catalogue

    root = str(tmp_path)
    monkeypatch.setattr(executor, "REPO_ROOT", root)
    monkeypatch.setattr(executor, "DEFAULT_SUBJECTIVE", PASS_STUB)

    def broken_snapshot(*args, **kwargs):
        raise RuntimeError("snapshot unavailable")

    async def forward(*args):
        return CallToolResult(content=[], isError=False)

    monkeypatch.setattr(policy_catalogue, "build_snapshot", broken_snapshot)
    monkeypatch.setattr(executor, "_forward", forward)
    result = await executor.decide_and_execute(None, "bash", {"command": "echo hello"})
    assert not result.isError
    (row,) = await read_decisions(root)
    assert row["final_verdict"] == "PASS"
    assert row["policy_version"] is None


async def test_proxy_context_and_stamp_share_captured_resolved_policy(tmp_path, monkeypatch):
    root = str(tmp_path)
    doc = recommend_policy()
    save_policy(doc, root)
    source_file = tmp_path / "doberman.policy.yaml"
    source_file.write_text('blocked: ["target.txt"]\n')
    load = executor.load_evaluation_policy
    captured = []
    decide = executor._safe_decide

    def capture_then_change(*args, **kwargs):
        policy = load(*args, **kwargs)
        captured.append(policy)
        source_file.write_text('blocked: ["target.txt", "later.txt"]\n')
        return policy

    def check_context(action, ctx):
        assert ctx.metadata["resolved_policy"] is captured[0].resolved_policy
        assert ctx.metadata["resolved_policy"].blocked_globs == ("target.txt",)
        return decide(action, ctx)

    monkeypatch.setattr(executor, "REPO_ROOT", root)
    monkeypatch.setattr(executor, "load_evaluation_policy", capture_then_change)
    monkeypatch.setattr(executor, "_safe_decide", check_context)
    monkeypatch.setattr(executor, "DEFAULT_SUBJECTIVE", PASS_STUB)
    result = await executor.decide_and_execute(None, "file_write", {"path": "target.txt"})

    assert result.isError
    assert len(captured) == 1
    (row,) = await read_decisions(root)
    assert row["policy_version"] == _version(doc, resolved=captured[0].resolved_policy)
    snapshot = read_snapshot(root, row["policy_version"])
    assert snapshot["resolved_policy"]["blocked_globs"] == ["target.txt"]
    from doberman.storage.policy_catalogue import current_snapshot

    assert policy_version(current_snapshot(root)) != row["policy_version"]


def test_host_context_and_stamp_share_captured_resolved_policy(tmp_path, monkeypatch):
    import asyncio

    root = str(tmp_path)
    doc = recommend_policy()
    save_policy(doc, root)
    source_file = tmp_path / "doberman.policy.yaml"
    source_file.write_text('blocked: ["target.txt"]\n')
    load = spine.load_evaluation_policy
    captured = []
    decide = spine.decide

    def capture_then_change(*args, **kwargs):
        policy = load(*args, **kwargs)
        captured.append(policy)
        source_file.write_text('blocked: ["target.txt", "later.txt"]\n')
        return policy

    def check_context(action, objective, subjective, ctx):
        assert ctx.metadata["resolved_policy"] is captured[0].resolved_policy
        assert ctx.metadata["resolved_policy"].blocked_globs == ("target.txt",)
        return decide(action, objective, subjective, ctx)

    monkeypatch.setattr(spine, "load_evaluation_policy", capture_then_change)
    monkeypatch.setattr(spine, "decide", check_context)
    result = claude_code.evaluate_pre(
        {"tool_name": "Write", "tool_input": {"file_path": "target.txt"}, "cwd": root}
    )

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert len(captured) == 1
    (row,) = asyncio.run(read_decisions(root))
    assert row["policy_version"] == _version(doc, resolved=captured[0].resolved_policy)
    assert read_snapshot(root, row["policy_version"])["resolved_policy"]["blocked_globs"] == [
        "target.txt"
    ]


async def test_auth_recheck_captures_changed_resolved_policy(tmp_path, monkeypatch):
    root = str(tmp_path)
    doc = recommend_policy()
    save_policy(doc, root)
    source_file = tmp_path / "doberman.policy.yaml"
    source_file.write_text('sensitive: ["target.txt"]\n')
    load = executor.load_evaluation_policy
    captured = []

    def capture(*args, **kwargs):
        policy = load(*args, **kwargs)
        captured.append(policy)
        if len(captured) == 2:
            source_file.write_text('blocked: ["target.txt", "later.txt"]\n')
        return policy

    def challenge(decision, action, **kwargs):
        source_file.write_text('blocked: ["target.txt"]\n')
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="confirm",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    monkeypatch.setattr(executor, "REPO_ROOT", root)
    monkeypatch.setattr(executor, "load_evaluation_policy", capture)
    monkeypatch.setattr(executor, "run_auth_challenge", challenge)
    monkeypatch.setattr(executor, "DEFAULT_SUBJECTIVE", PASS_STUB)
    result = await executor.decide_and_execute(None, "file_write", {"path": "target.txt"})

    assert result.isError
    assert len(captured) == 2
    (row,) = await read_decisions(root)
    assert row["final_verdict"] == "BLOCK"
    assert row["policy_version"] == _version(doc, resolved=captured[1].resolved_policy)
    assert row["policy_version"] != _version(doc, resolved=captured[0].resolved_policy)
    assert read_snapshot(root, row["policy_version"])["resolved_policy"]["blocked_globs"] == [
        "target.txt"
    ]
