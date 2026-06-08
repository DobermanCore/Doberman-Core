"""Slice 7.4 — an active elevation satisfies a role AUTH (never a role BLOCK)."""

from datetime import datetime, timedelta, timezone

from doberman.auth.elevation import ElevationGrant
from doberman.engine.rules.role_boundary import RoleBoundaryRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.roles.roles import RoleDefinition

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)
_ROLE = RoleDefinition(
    name="webdev",
    allowed=("frontend/**",),
    suspicious=("backend/**",),
    blocked=("secrets/**",),
)


def _action(target, action_type=ActionType.file_write):
    return SecurityObject(
        id="a1",
        ts=_NOW,
        agent_role="webdev",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
    )


def _grant(scope):
    return ElevationGrant(
        id="g1",
        scope_glob=scope,
        task_id="t",
        granted_at=_NOW,
        expires_at=_NOW + timedelta(seconds=900),
    )


def _ctx(grants=()):
    return EvalContext(role=_ROLE, metadata={"repo_root": ".", "elevations": grants})


def test_out_of_scope_auths_without_elevation():
    result = RoleBoundaryRule().evaluate(_action("backend/api.ts"), _ctx())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.role_out_of_scope in result.reason_codes


def test_matching_elevation_satisfies_the_role_auth():
    ctx = _ctx((_grant("backend/api.ts"),))
    result = RoleBoundaryRule().evaluate(_action("backend/api.ts"), ctx)
    assert result.verdict is Verdict.PASS


def test_elevation_for_a_different_file_does_not_satisfy():
    ctx = _ctx((_grant("backend/other.ts"),))
    result = RoleBoundaryRule().evaluate(_action("backend/api.ts"), ctx)
    assert result.verdict is Verdict.AUTH


def test_elevation_never_lifts_a_role_block():
    # Even an elevation whose glob covers a BLOCKED path must not downgrade it.
    ctx = _ctx((_grant("secrets/key"),))
    result = RoleBoundaryRule().evaluate(_action("secrets/key"), ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.role_blocked_target in result.reason_codes
