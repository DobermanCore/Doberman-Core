"""Slice 4.4 — ordered PolicySource resolver + authority layering (the seam).

Covers: empty resolution; role→snapshot mapping; raise-only union across
sources (blocked wins on tie, order-independent); discovery of a registered
source via the entry-point registry; standalone behavior with nothing
registered; and that a higher-authority registered source outranks the role via
the PolicySourceRule.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine import registry
from doberman.engine.rules.policy_source import PolicySourceRule
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)
from doberman.policy.sources import (
    PolicySnapshot,
    ResolvedPolicy,
    RoleSource,
    StaticSource,
    resolve_policy,
)
from doberman.roles.roles import RoleDefinition


# --- fakes for entry-point discovery (no package install needed) -------------
class _FakeEntryPoint:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class _FakeEntryPoints:
    def __init__(self, by_group):
        self._by_group = by_group

    def select(self, *, group):
        return list(self._by_group.get(group, []))


@pytest.fixture
def patch_policy_sources(monkeypatch, enable_plugins):
    def _install(*sources):
        sources = list(sources)
        table = _FakeEntryPoints({registry.POLICY_SOURCE_GROUP: sources})
        monkeypatch.setattr(registry, "entry_points", lambda: table)
        names = [s.name for s in sources]
        if names:
            enable_plugins(*names)

    return _install


def _action(target, action_type=ActionType.file_write):
    return SecurityObject(
        id="ps-1",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="x",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
    )


# --- resolver ---------------------------------------------------------------
def test_no_sources_resolves_empty():
    rp = resolve_policy(discover=False)
    assert rp.is_empty


def test_role_source_maps_blocked_and_suspicious():
    role = RoleDefinition(name="r", blocked=["a/**"], suspicious=["b/**"])
    snap = RoleSource(role).snapshot()
    assert snap.blocked_globs == ("a/**",)
    assert snap.sensitive_globs == ("b/**",)


def test_blocked_wins_over_sensitive_on_tie():
    a = StaticSource("a", 0, PolicySnapshot(sensitive_globs=["x/**"]))
    b = StaticSource("b", 100, PolicySnapshot(blocked_globs=["x/**"]))
    rp = resolve_policy([a, b], discover=False)
    assert "x/**" in rp.blocked_globs
    assert "x/**" not in rp.sensitive_globs


def test_merge_is_order_independent_and_raise_only():
    a = StaticSource("a", 0, PolicySnapshot(sensitive_globs=["x/**"]))
    b = StaticSource("b", 100, PolicySnapshot(blocked_globs=["x/**"]))
    forward = resolve_policy([a, b], discover=False)
    backward = resolve_policy([b, a], discover=False)
    assert forward.blocked_globs == backward.blocked_globs
    assert forward.sensitive_globs == backward.sensitive_globs
    # A lower-authority source cannot remove a higher source's blocked: x stays blocked.
    assert "x/**" in forward.blocked_globs


def test_a_raising_source_is_skipped_not_crashed_on(caplog):
    # This loop now runs on every action (#147): a registered plugin's
    # snapshot() must never be able to take down the decision path -- it is
    # logged and skipped, and the OTHER sources still resolve normally.
    class _Boom(StaticSource):
        def snapshot(self):
            raise RuntimeError("boom")

    boom = _Boom("boom", 50, PolicySnapshot(blocked_globs=["never/seen/**"]))
    ok = StaticSource("ok", 0, PolicySnapshot(blocked_globs=["fine/**"]))

    import logging

    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        rp = resolve_policy([boom, ok], discover=False)

    assert rp.blocked_globs == ("fine/**",)
    assert "never/seen/**" not in rp.blocked_globs
    assert any("boom" in r.message for r in caplog.records)


def test_discovers_a_registered_source(patch_policy_sources):
    class _DiscoveredSource:
        name = "enterprise-hard-policy"
        authority = 100

        def snapshot(self):
            return PolicySnapshot(blocked_globs=["app/secret.txt"])

    patch_policy_sources(_FakeEntryPoint("ent", _DiscoveredSource))
    rp = resolve_policy(discover=True)
    assert "app/secret.txt" in rp.blocked_globs
    assert any(name == "enterprise-hard-policy" for name, _ in rp.contributors)


def test_standalone_when_nothing_registered(patch_policy_sources):
    patch_policy_sources()  # empty policy-source group
    local = StaticSource("local", 0, PolicySnapshot(blocked_globs=["only/local/**"]))
    rp = resolve_policy([local], discover=True)
    assert rp.blocked_globs == ("only/local/**",)


# --- rule -------------------------------------------------------------------
def test_rule_abstains_without_a_resolved_policy(tmp_path):
    ctx = EvalContext(metadata={"repo_root": str(tmp_path)})
    assert PolicySourceRule().evaluate(_action("a.txt"), ctx).verdict is Verdict.PASS


def test_rule_blocks_a_resolved_blocked_path(tmp_path):
    rp = ResolvedPolicy(blocked_globs=("app/secret.txt",))
    ctx = EvalContext(metadata={"repo_root": str(tmp_path), "resolved_policy": rp})
    result = PolicySourceRule().evaluate(_action("app/secret.txt"), ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.policy_source_blocked in result.reason_codes


def test_rule_auths_a_resolved_sensitive_path(tmp_path):
    rp = ResolvedPolicy(sensitive_globs=("app/config/**",))
    ctx = EvalContext(metadata={"repo_root": str(tmp_path), "resolved_policy": rp})
    result = PolicySourceRule().evaluate(_action("app/config/db.ini"), ctx)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.policy_source_sensitive in result.reason_codes


def test_high_authority_source_outranks_role(tmp_path, patch_policy_sources):
    # Role allows app/**; a registered higher-authority source blocks app/secret.txt.
    role = RoleDefinition(name="dev", allowed=["app/**"])

    class _HardPolicy:
        name = "org-hard-policy"
        authority = 100

        def snapshot(self):
            return PolicySnapshot(blocked_globs=["app/secret.txt"])

    patch_policy_sources(_FakeEntryPoint("org", _HardPolicy))
    rp = resolve_policy([RoleSource(role)], discover=True)
    ctx = EvalContext(metadata={"repo_root": str(tmp_path), "resolved_policy": rp})

    # The path the role would allow is blocked by the higher-authority source.
    blocked = PolicySourceRule().evaluate(_action("app/secret.txt"), ctx)
    assert blocked.verdict is Verdict.BLOCK
    # A sibling the source does not constrain is unaffected by the seam.
    assert PolicySourceRule().evaluate(_action("app/main.py"), ctx).verdict is Verdict.PASS


def test_other_typed_tool_with_path_argument_matches_file_write_verdict(tmp_path):
    # A tool that doesn't normalize to a path action type (e.g. an
    # unrecognized name) but whose raw arguments still carry a path-shaped
    # value must be classified exactly like file_write — the tool NAME is
    # caller-supplied, not a trust boundary (#519/#527).
    rp = ResolvedPolicy(blocked_globs=("app/secret.txt",))
    write_ctx = EvalContext(metadata={"repo_root": str(tmp_path), "resolved_policy": rp})
    write_result = PolicySourceRule().evaluate(_action("app/secret.txt"), write_ctx)

    other_action = _action("app/secret.txt", action_type=ActionType.other)
    other_ctx = EvalContext(
        metadata={
            "repo_root": str(tmp_path),
            "resolved_policy": rp,
            "raw_arguments": {"path": "app/secret.txt"},
        }
    )
    other_result = PolicySourceRule().evaluate(other_action, other_ctx)

    assert write_result.verdict is other_result.verdict is Verdict.BLOCK
    assert ReasonCode.policy_source_blocked in write_result.reason_codes
    assert ReasonCode.policy_source_blocked in other_result.reason_codes
