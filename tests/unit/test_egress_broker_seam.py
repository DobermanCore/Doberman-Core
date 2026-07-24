"""Feature RB, slice RB.1 — the EgressBroker seam: interface, registry, and
the fail-closed dormant default.

Every test here defends one property: today's shipped raise-only egress
behavior (EB.1 / v0.16.0) is UNCHANGED by RB.1. The seam is real — a
registered broker's ``enforcement_status``/``classify`` are genuinely called
— but DORMANT: no broker verdict (ABSENT, UNPROVEN, PROVEN, or one that
raises) may raise or lower ``ExternalDestinationRule``'s verdict. PASS
authority does not land until RB.4.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from doberman.egress.broker import (
    BrokerVerdict,
    ConnectionEvent,
    EgressBroker,
    EnforcementStatus,
    consult_broker,
)
from doberman.engine import registry
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules import destinations as destinations_module
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.proxy.executor import _default_objective_rules


@pytest.fixture(autouse=True)
def _reset_egress_broker_cache():
    """``discover_egress_brokers`` is memoized (RB.1-fix). Tests in this file
    monkeypatch ``entry_points`` per-test, so the cache must be cleared before
    (a stale hit would ignore the patch) and after (so it never leaks a
    test-only broker into a later test / module).
    """
    registry.discover_egress_brokers.cache_clear()
    yield
    registry.discover_egress_brokers.cache_clear()


def _egress_action(action_type=ActionType.shell_exec, **overrides):
    base = dict(
        id="rb1-1",
        ts=datetime(2026, 7, 24, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="shell_exec",
        target="curl https://github.com/x",
        external_destination="github.com",
    )
    base.update(overrides)
    return SecurityObject(**base)


# --- stub brokers --------------------------------------------------------------


class _AbsentBroker:
    def enforcement_status(self):
        return EnforcementStatus.ABSENT

    def classify(self, action):  # pragma: no cover — must never be called
        raise AssertionError("classify() must not be called when ABSENT")

    def connection_events(self, entity, window):  # pragma: no cover
        return []


class _UnprovenAllowlistedBroker:
    def enforcement_status(self):
        return EnforcementStatus.UNPROVEN

    def classify(self, action):
        return BrokerVerdict(allowlisted=True, will_enforce=True)

    def connection_events(self, entity, window):
        return []


class _ProvenAllowlistedBroker:
    def enforcement_status(self):
        return EnforcementStatus.PROVEN

    def classify(self, action):
        return BrokerVerdict(allowlisted=True, will_enforce=True)

    def connection_events(self, entity, window):
        return []


class _RaisingStatusBroker:
    def enforcement_status(self):
        raise RuntimeError("broker exploded")

    def classify(self, action):  # pragma: no cover — never reached
        raise AssertionError("classify() must not be called after a raising status check")

    def connection_events(self, entity, window):  # pragma: no cover
        return []


class _RaisingClassifyBroker:
    def enforcement_status(self):
        return EnforcementStatus.PROVEN

    def classify(self, action):
        raise RuntimeError("classify exploded")

    def connection_events(self, entity, window):
        return []


# --- 1. models + protocol shape -------------------------------------------------


def test_enforcement_status_has_exactly_three_members():
    assert {s.value for s in EnforcementStatus} == {"PROVEN", "UNPROVEN", "ABSENT"}


def test_broker_verdict_carries_no_actual_destination_field():
    verdict = BrokerVerdict(allowlisted=True, will_enforce=True)
    assert not hasattr(verdict, "actual_destination")
    assert verdict.reason_codes == []


def test_connection_event_is_redaction_shaped():
    event = ConnectionEvent(
        entity_id="ent-1", ts=datetime(2026, 7, 24, tzinfo=timezone.utc), host="github.com"
    )
    assert event.host == "github.com"
    assert event.bytes_sent == 0
    assert event.will_enforce is False


def test_stub_brokers_satisfy_the_protocol():
    assert isinstance(_ProvenAllowlistedBroker(), EgressBroker)
    assert isinstance(_AbsentBroker(), EgressBroker)
    assert not isinstance(object(), EgressBroker)


# --- 2. consult_broker — the fail-closed helper ---------------------------------


def test_consult_broker_with_no_broker_returns_none():
    assert consult_broker(None, _egress_action()) is None


def test_consult_broker_absent_status_returns_none_without_calling_classify():
    # _AbsentBroker.classify() raises AssertionError if ever called.
    assert consult_broker(_AbsentBroker(), _egress_action()) is None


def test_consult_broker_unproven_returns_none_even_when_allowlisted():
    assert consult_broker(_UnprovenAllowlistedBroker(), _egress_action()) is None


def test_consult_broker_proven_returns_the_verdict():
    verdict = consult_broker(_ProvenAllowlistedBroker(), _egress_action())
    assert verdict is not None
    assert verdict.allowlisted is True
    assert verdict.will_enforce is True


def test_consult_broker_raising_enforcement_status_is_treated_as_absent():
    assert consult_broker(_RaisingStatusBroker(), _egress_action()) is None


def test_consult_broker_raising_classify_is_treated_as_absent():
    assert consult_broker(_RaisingClassifyBroker(), _egress_action()) is None


# --- 3. registry discovery -------------------------------------------------------


class _FakeEntryPoint:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class _FakeEntryPoints:
    """Mimics importlib.metadata.entry_points() with a .select(group=...)."""

    def __init__(self, eps):
        self._eps = list(eps)

    def select(self, *, group):
        return list(self._eps) if group == registry.EGRESS_BROKER_GROUP else []


def test_discover_egress_brokers_empty_with_nothing_installed():
    assert registry.discover_egress_brokers() == []


def test_discover_egress_brokers_finds_shaped_and_skips_others(monkeypatch):
    instance = _ProvenAllowlistedBroker()
    table = _FakeEntryPoints(
        [_FakeEntryPoint("good", lambda: instance), _FakeEntryPoint("bad", lambda: 42)]
    )
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    assert registry.discover_egress_brokers() == [instance]


def test_discover_egress_brokers_isolates_import_failures(monkeypatch):
    def _bad_loader():
        raise ImportError("cannot import broker")

    table = _FakeEntryPoints([_FakeEntryPoint("bad", _bad_loader)])
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    assert registry.discover_egress_brokers() == []


def test_discover_egress_brokers_discovery_failure_does_not_crash(monkeypatch):
    def _boom():
        raise RuntimeError("metadata broken")

    monkeypatch.setattr(registry, "entry_points", _boom)
    assert registry.discover_egress_brokers() == []


# --- 4. decision-path wiring — the fail-closed heart ------------------------------


def test_no_broker_installed_egress_behavior_is_unchanged():
    # load_broker=False mirrors "nothing installed" without touching real
    # importlib.metadata state.
    rule = ExternalDestinationRule(load_broker=False)
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.egress_requires_auth in result.reason_codes


def test_absent_broker_changes_nothing():
    rule = ExternalDestinationRule(egress_broker=_AbsentBroker())
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.egress_requires_auth in result.reason_codes


def test_unproven_allowlisted_broker_still_auth_no_pass():
    # The fail-closed heart: UNPROVEN + allowlisted=True + will_enforce=True
    # must NOT grant a PASS.
    rule = ExternalDestinationRule(egress_broker=_UnprovenAllowlistedBroker())
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH


def test_raising_broker_is_treated_as_absent_and_does_not_crash():
    rule = ExternalDestinationRule(egress_broker=_RaisingStatusBroker())
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH


def test_proven_broker_still_grants_no_pass_in_rb1():
    # RB.1 ships PASS-authority dormant — even a PROVEN, allowlisted,
    # will-enforce broker changes nothing until RB.4.
    rule = ExternalDestinationRule(egress_broker=_ProvenAllowlistedBroker())
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH


def test_broker_wiring_also_covers_plain_network_requests():
    # network_request egress goes through a different branch of evaluate();
    # the dormant consultation (and its discard) must hold there too.
    rule = ExternalDestinationRule(egress_broker=_ProvenAllowlistedBroker())
    action = _egress_action(
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://not-a-trusted-host.example",
        external_destination="https://not-a-trusted-host.example",
    )
    result = rule.evaluate(action, EvalContext(mode="strict"))
    assert result.verdict is Verdict.AUTH


def test_default_construction_never_discovers_a_broker():
    # RB.1-fix: load_broker now defaults to False, so a bare construction
    # (what the host hooks do, once per tool call) never touches discovery
    # at all — not just "discovers nothing in this environment".
    rule = ExternalDestinationRule()
    assert rule._broker is None
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH


def test_opted_in_construction_discovers_no_broker_in_this_environment():
    # No `doberman.egress_brokers` plugin is installed here — the real
    # (unmocked) discovery path, when explicitly opted into, must also be a
    # no-op. Regression guard for the RB.1 dormant default.
    rule = ExternalDestinationRule(load_broker=True)
    result = rule.evaluate(_egress_action(), EvalContext())
    assert result.verdict is Verdict.AUTH


# --- 5. RB.1-fix — hook path never discovers, proxy path opts in ----------------


def test_hook_style_objective_guardrail_never_discovers_egress_brokers(monkeypatch):
    # ObjectiveGuardrail() is exactly how the host hooks (claude_code.py,
    # openclaw.py) build the guardrail — once per tool call, in a cold-start
    # CLI process. That must never trigger the entry-point scan.
    spy = MagicMock(wraps=destinations_module.discover_egress_brokers)
    monkeypatch.setattr(destinations_module, "discover_egress_brokers", spy)
    ObjectiveGuardrail()
    assert spy.call_count == 0


def test_proxy_opt_in_path_resolves_a_registered_broker(monkeypatch):
    # `_default_objective_rules()` is exactly what builds the proxy's
    # long-lived DEFAULT_OBJECTIVE singleton (doberman.proxy.executor) — it
    # must resolve a registered broker, unlike the hook path above.
    instance = _ProvenAllowlistedBroker()
    table = _FakeEntryPoints([_FakeEntryPoint("p", lambda: instance)])
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    rules = _default_objective_rules()
    destination_rules = [r for r in rules if isinstance(r, ExternalDestinationRule)]
    assert len(destination_rules) == 1
    assert destination_rules[0]._broker is instance
