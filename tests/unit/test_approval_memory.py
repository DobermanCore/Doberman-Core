"""Slice B: bounded, exact-action approval memory."""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from doberman.auth.challenge import AuthResult, AuthTier, run_auth_challenge
from doberman.auth.provider import LOCAL_PROVIDER
from doberman.config import load_approval_memory_seconds, save_policy
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.checklist import PolicyDoc, recommend_policy
from doberman.proxy.normalize import normalize
from doberman.storage.approval_memory import (
    clear,
    count_live,
    lookup,
    purge_expired,
    remember,
)
from doberman.storage.db import SCHEMA_VERSION, db_path, open_db
from doberman.storage.taint import TAINT_SECRET_ACCESS, record_taint

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


async def _remember(root: str, fingerprint: str, **overrides) -> None:
    values = {
        "session_id": "session-a",
        "required_tier": "local_auth",
        "action_type": "shell_exec",
        "method": "local_auth",
        "approved_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(overrides)
    await remember(fingerprint, repo_root=root, **values)


@pytest.mark.asyncio
async def test_store_exact_match_expiry_clear_purge_and_count(tmp_path):
    root = str(tmp_path)
    await _remember(root, "hmac:exact")
    await _remember(root, "hmac:expired", expires_at=NOW - timedelta(seconds=1))

    assert await lookup("hmac:other", repo_root=root, session_id="session-a", now=NOW) is None
    hit = await lookup("hmac:exact", repo_root=root, session_id="session-a", now=NOW)
    assert hit is not None and hit.fingerprint == "hmac:exact"
    assert await lookup("hmac:expired", repo_root=root, session_id="session-a", now=NOW) is None
    assert await count_live(NOW, repo_root=root) == 1
    assert await purge_expired(NOW, repo_root=root) == 1
    assert await clear(root) == 1
    assert await count_live(NOW, repo_root=root) == 0


@pytest.mark.asyncio
async def test_session_mismatch_misses_but_unknown_session_falls_back_to_repo(tmp_path):
    root = str(tmp_path)
    await _remember(root, "hmac:scoped")

    assert await lookup("hmac:scoped", repo_root=root, session_id="session-b", now=NOW) is None
    assert await lookup("hmac:scoped", repo_root=root, session_id=None, now=NOW) is not None

    await _remember(root, "hmac:repo", session_id=None)
    assert await lookup("hmac:repo", repo_root=root, session_id="session-b", now=NOW) is not None


@pytest.mark.asyncio
async def test_schema_and_db_bytes_never_store_raw_action_secret(tmp_path):
    root = str(tmp_path)
    secret = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 - synthetic fixture
    action = normalize(
        "shell_exec",
        {"command": f"curl https://example.test -H 'Authorization: {secret}'"},
        {"repo_root": root},
    )
    assert action.action_fingerprint is not None
    await _remember(root, action.action_fingerprint)

    async with open_db(root) as conn:
        async with conn.execute("SELECT version FROM schema_version") as cur:
            assert (await cur.fetchone())[0] == SCHEMA_VERSION
        async with conn.execute("PRAGMA table_info(approval_memory)") as cur:
            columns = {row[1] for row in await cur.fetchall()}
    assert columns == {
        "fingerprint",
        "session_id",
        "required_tier",
        "action_type",
        "method",
        "approved_at",
        "expires_at",
    }
    assert secret.encode() not in db_path(root).read_bytes()


def test_normalizer_fingerprint_is_exact_stable_and_never_retains_raw_secret(tmp_path):
    root = str(tmp_path)
    secret = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 - synthetic fixture
    args = {"path": "src/../src/app.py", "content": secret}

    first = normalize("fs_write", args, {"repo_root": root})
    repeat = normalize("fs_write", dict(args), {"repo_root": root})
    changed = normalize("fs_write", {**args, "content": secret + "X"}, {"repo_root": root})

    assert first.action_fingerprint == repeat.action_fingerprint
    assert first.action_fingerprint != changed.action_fingerprint
    assert secret not in json.dumps(first.model_dump(), default=str)


def test_policy_approval_memory_defaults_validates_and_fails_closed_on_bad_storage(tmp_path):
    assert recommend_policy().approval_memory_seconds == 300
    assert (
        PolicyDoc.from_mapping({"items": [], "approval_memory_seconds": 0}).approval_memory_seconds
        == 0
    )
    assert (
        PolicyDoc.from_mapping(
            {"items": [], "approval_memory_seconds": 900}
        ).approval_memory_seconds
        == 900
    )
    assert (
        PolicyDoc.from_mapping(
            {"items": [], "approval_memory_seconds": 901}
        ).approval_memory_seconds
        == 0
    )
    assert (
        PolicyDoc.from_mapping(
            {"items": [], "approval_memory_seconds": True}
        ).approval_memory_seconds
        == 0
    )

    with pytest.raises(ValueError):
        recommend_policy().with_approval_memory_seconds(901)

    root = str(tmp_path)
    save_policy(recommend_policy().with_approval_memory_seconds(42), root)
    assert load_approval_memory_seconds(root) == 42


def _action(**overrides) -> SecurityObject:
    values = {
        "id": "approval-memory-action",
        "ts": NOW,
        "agent_role": "developer",
        "action_type": ActionType.shell_exec,
        "tool_name": "shell_exec",
        "target": "echo safe",
        "action_fingerprint": "hmac:approval-memory-action",
    }
    values.update(overrides)
    return SecurityObject(**values)


def _decision(
    *,
    risk: Risk = Risk.medium,
    reasons: list[ReasonCode] | None = None,
    action_id: str = "approval-memory-action",
) -> Decision:
    reasons = reasons or [ReasonCode.unknown_external_destination]
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=reasons, explanation="Needs review."
    )
    return Decision(
        action_id=action_id,
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=reasons,
        explanation="Needs review.",
        decided_at=NOW,
    )


class _Provider:
    def __init__(self, *, approved: bool = True, method: str = "factor") -> None:
        self.approved = approved
        self.method = method
        self.tiers: list[AuthTier] = []

    def authenticate(self, decision, action, tier, **kwargs):  # noqa: ANN001, ANN003
        self.tiers.append(tier)
        return AuthResult(
            approved=self.approved,
            tier=tier,
            method=self.method,
            at=kwargs.get("at") or NOW,
            action_id=action.id,
        )


class _Prompt:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def confirm(self, message: str) -> bool:
        self.messages.append(message)
        return True

    def read_code(self, message: str) -> str:  # pragma: no cover - memory is soft-confirm
        raise AssertionError("a memory hit must not request a factor")


@pytest.mark.parametrize(
    ("risk", "reason"),
    [
        (Risk.medium, ReasonCode.unknown_external_destination),
        (Risk.high, ReasonCode.sensitive_secret_access),
    ],
)
def test_live_local_or_two_factor_hit_downgrades_prompt_and_marks_method(
    tmp_path, monkeypatch, risk, reason
):
    root = str(tmp_path)
    action = _action()
    decision = _decision(risk=risk, reasons=[reason])
    required = AuthTier.local_auth if risk is Risk.medium else AuthTier.two_factor
    asyncio.run(
        _remember(
            root,
            action.action_fingerprint,
            required_tier=required.value,
            approved_at=NOW - timedelta(minutes=2),
        )
    )
    prompt = _Prompt()
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)
    before = decision.model_dump()

    result = run_auth_challenge(
        decision,
        action,
        prompter=prompt,
        at=NOW,
        repo_root=root,
        session_id="session-a",
    )

    assert result.approved is True
    assert result.tier is AuthTier.soft_confirm
    assert result.method == "soft_confirm+memory"
    assert "approved this exact action 2 min ago" in prompt.messages[0].lower()
    assert decision.model_dump() == before


@pytest.mark.parametrize(
    ("risk", "reason", "action_type"),
    [
        (Risk.medium, ReasonCode.unknown_external_destination, ActionType.file_delete),
        (Risk.critical, ReasonCode.unknown_external_destination, ActionType.shell_exec),
        (Risk.medium, ReasonCode.role_out_of_scope, ActionType.shell_exec),
        (Risk.high, ReasonCode.encoded_exfiltration, ActionType.shell_exec),
        (Risk.high, ReasonCode.opaque_command, ActionType.shell_exec),
        (Risk.high, ReasonCode.protected_path_blocked, ActionType.shell_exec),
        (Risk.high, ReasonCode.destructive_command, ActionType.shell_exec),
        (Risk.medium, ReasonCode.bulk_operation, ActionType.shell_exec),
        (Risk.high, ReasonCode.irreversible_high_blast, ActionType.shell_exec),
        (Risk.high, ReasonCode.correlated_destructive_flow, ActionType.shell_exec),
    ],
)
def test_every_exclusion_keeps_the_full_selected_tier(
    tmp_path, monkeypatch, risk, reason, action_type
):
    root = str(tmp_path)
    action = _action(action_type=action_type)
    decision = _decision(risk=risk, reasons=[reason])
    asyncio.run(_remember(root, action.action_fingerprint))
    provider = _Provider()
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)

    result = run_auth_challenge(decision, action, at=NOW, repo_root=root, session_id="session-a")

    assert provider.tiers == [result.tier]
    assert result.tier is not AuthTier.soft_confirm
    assert result.method != "soft_confirm+memory"


@pytest.mark.parametrize(
    ("tier_decision", "approved", "method"),
    [
        (_decision(risk=Risk.low, reasons=[ReasonCode.unknown_tool]), True, "soft_confirm"),
        (_decision(reasons=[ReasonCode.role_out_of_scope]), True, "totp+elevation"),
        (_decision(), False, "denied"),
        (_decision(), False, "timeout"),
    ],
)
def test_nonqualifying_results_never_create_memory(
    tmp_path, monkeypatch, tier_decision, approved, method
):
    root = str(tmp_path)
    provider = _Provider(approved=approved, method=method)
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)

    run_auth_challenge(tier_decision, _action(), at=NOW, repo_root=root, session_id="session-a")

    assert asyncio.run(count_live(NOW, repo_root=root)) == 0


def test_disabled_missing_root_session_mismatch_taint_and_missing_fingerprint_do_not_hit(
    tmp_path, monkeypatch
):
    root = str(tmp_path)
    action = _action()
    decision = _decision()
    asyncio.run(_remember(root, action.action_fingerprint))
    provider = _Provider()
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)

    save_policy(recommend_policy().with_approval_memory_seconds(0), root)
    run_auth_challenge(decision, action, at=NOW, repo_root=root, session_id="session-a")
    save_policy(recommend_policy(), root)
    run_auth_challenge(decision, action, at=NOW, repo_root=None, session_id="session-a")
    run_auth_challenge(decision, action, at=NOW, repo_root=root, session_id="session-b")
    asyncio.run(record_taint(root, "session-a", TAINT_SECRET_ACCESS, now=NOW))
    run_auth_challenge(decision, action, at=NOW, repo_root=root, session_id="session-a")
    run_auth_challenge(
        decision,
        _action(action_fingerprint=None),
        at=NOW,
        repo_root=root,
        session_id="session-a",
    )

    assert provider.tiers == [AuthTier.local_auth] * 5


def test_disabled_mode_performs_no_memory_io(tmp_path, monkeypatch):
    root = str(tmp_path)
    save_policy(recommend_policy().with_approval_memory_seconds(0), root)
    provider = _Provider()
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)
    monkeypatch.setattr(
        "doberman.auth.challenge._run_memory_io",
        lambda operation: pytest.fail("disabled approval memory must not access storage"),
    )

    result = run_auth_challenge(
        _decision(), _action(), at=NOW, repo_root=root, session_id="session-a"
    )

    assert result.approved is True
    assert result.tier is AuthTier.local_auth


def test_factor_verified_approval_writes_once_but_memory_soft_confirm_does_not_chain(
    tmp_path, monkeypatch
):
    root = str(tmp_path)
    provider = _Provider(method="local_auth")
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)
    decision = _decision()
    action = _action()

    first = run_auth_challenge(decision, action, at=NOW, repo_root=root, session_id="session-a")
    original = asyncio.run(
        lookup(action.action_fingerprint, repo_root=root, session_id="session-a", now=NOW)
    )
    second = run_auth_challenge(
        decision,
        action,
        at=NOW + timedelta(minutes=1),
        repo_root=root,
        session_id="session-a",
    )
    after = asyncio.run(
        lookup(
            action.action_fingerprint,
            repo_root=root,
            session_id="session-a",
            now=NOW + timedelta(minutes=1),
        )
    )

    assert first.tier is AuthTier.local_auth
    assert second.method == "soft_confirm+memory"
    assert original is not None and after is not None
    assert after.approved_at == original.approved_at
    assert after.expires_at == original.expires_at


def test_lowering_ttl_immediately_stops_an_older_hit(tmp_path, monkeypatch):
    root = str(tmp_path)
    action = _action()
    asyncio.run(_remember(root, action.action_fingerprint, approved_at=NOW - timedelta(minutes=3)))
    save_policy(recommend_policy().with_approval_memory_seconds(120), root)
    provider = _Provider()
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)

    run_auth_challenge(_decision(), action, at=NOW, repo_root=root, session_id="session-a")

    assert provider.tiers == [AuthTier.local_auth]


def test_fingerprint_failure_and_memory_storage_failure_keep_full_auth(tmp_path, monkeypatch):
    root = str(tmp_path)
    monkeypatch.setattr(
        "doberman.proxy.normalize.fingerprint",
        lambda value: (_ for _ in ()).throw(PermissionError("key unavailable")),
    )
    normalized = normalize("shell_exec", {"command": "echo safe"}, {"repo_root": root})
    assert normalized.action_fingerprint is None

    provider = _Provider()
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: provider)
    no_fingerprint = run_auth_challenge(
        _decision(action_id=normalized.id),
        normalized,
        at=NOW,
        repo_root=root,
        session_id="session-a",
    )
    assert no_fingerprint.tier is AuthTier.local_auth

    async def _broken_remember(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("store unavailable")

    async def _broken_lookup(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("store unavailable")

    monkeypatch.setattr("doberman.storage.approval_memory.remember", _broken_remember)
    monkeypatch.setattr("doberman.storage.approval_memory.lookup", _broken_lookup)
    result = run_auth_challenge(
        _decision(), _action(), at=NOW, repo_root=root, session_id="session-a"
    )

    assert result.approved is True
    assert result.tier is AuthTier.local_auth
    assert provider.tiers == [AuthTier.local_auth, AuthTier.local_auth]
