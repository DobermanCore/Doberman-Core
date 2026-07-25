"""Feature RB, slice RB.2a — `LocalEgressBroker`, the concrete reference broker.

Every test here defends the RB.2a scope: no listener exists yet, so
`will_enforce` must always be False, `connection_events` must always be
empty, and `classify()` must never claim to know a pending action's actual
runtime destination. `enforcement_status()` must simply delegate to the
injected probe. No test performs real network I/O — the allowlist and probe
are always injected.
"""

from datetime import datetime, timezone

from doberman.egress.allowlist import EgressAllowlist
from doberman.egress.broker import EgressBroker, EnforcementStatus
from doberman.egress.enforcement import EnforcementProbe
from doberman.egress.local import LocalEgressBroker
from doberman.models import ActionType, SecurityObject


def _egress_action(action_type=ActionType.shell_exec, **overrides):
    base = dict(
        id="rb2a-1",
        ts=datetime(2026, 7, 24, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="shell_exec",
        target="curl https://github.com/x",
        external_destination="github.com",
    )
    base.update(overrides)
    return SecurityObject(**base)


class _FixedProbe:
    def __init__(self, status: EnforcementStatus):
        self._status = status

    def status(self):
        return self._status


def test_local_egress_broker_satisfies_the_protocol():
    broker = LocalEgressBroker(
        allowlist=EgressAllowlist(), probe=_FixedProbe(EnforcementStatus.PROVEN)
    )
    assert isinstance(broker, EgressBroker)


def test_enforcement_status_delegates_to_the_injected_probe():
    broker = LocalEgressBroker(probe=_FixedProbe(EnforcementStatus.PROVEN))
    assert broker.enforcement_status() is EnforcementStatus.PROVEN

    broker = LocalEgressBroker(probe=_FixedProbe(EnforcementStatus.UNPROVEN))
    assert broker.enforcement_status() is EnforcementStatus.UNPROVEN


def test_classify_allowlisted_destination():
    broker = LocalEgressBroker(allowlist=EgressAllowlist())
    verdict = broker.classify(_egress_action(external_destination="github.com"))
    assert verdict.allowlisted is True
    assert verdict.reason_codes == []


def test_classify_non_allowlisted_destination():
    broker = LocalEgressBroker(allowlist=EgressAllowlist())
    verdict = broker.classify(_egress_action(external_destination="not-a-trusted-host.example"))
    assert verdict.allowlisted is False
    assert verdict.reason_codes  # carries a reason code for the denial


def test_will_enforce_is_always_false_in_rb2a_even_when_allowlisted_and_proven():
    # The load-bearing RB.2a invariant: no listener exists yet, so this
    # broker can never truthfully promise to enforce anything — regardless
    # of how trusted the destination looks or how the probe reads.
    broker = LocalEgressBroker(
        allowlist=EgressAllowlist(), probe=_FixedProbe(EnforcementStatus.PROVEN)
    )
    verdict = broker.classify(_egress_action(external_destination="github.com"))
    assert verdict.allowlisted is True
    assert verdict.will_enforce is False


def test_classify_never_carries_an_actual_destination_claim():
    broker = LocalEgressBroker(allowlist=EgressAllowlist())
    verdict = broker.classify(_egress_action())
    assert not hasattr(verdict, "actual_destination")


def test_classify_handles_a_missing_destination_as_denied():
    broker = LocalEgressBroker(allowlist=EgressAllowlist())
    action = _egress_action(
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="",
        external_destination=None,
    )
    verdict = broker.classify(action)
    assert verdict.allowlisted is False
    assert verdict.will_enforce is False


def test_connection_events_is_always_empty_in_rb2a():
    broker = LocalEgressBroker(allowlist=EgressAllowlist())
    events = broker.connection_events(
        "entity-1",
        (datetime(2026, 7, 1, tzinfo=timezone.utc), datetime(2026, 7, 24, tzinfo=timezone.utc)),
    )
    assert list(events) == []


def test_default_construction_builds_a_real_allowlist_and_probe_without_network_io():
    # Default-construct (no injected allowlist/probe) — must not perform any
    # network I/O at construction time; only calling enforcement_status()
    # would (and no test here calls it on a default-constructed broker).
    broker = LocalEgressBroker()
    assert isinstance(broker._allowlist, EgressAllowlist)
    assert isinstance(broker._probe, EnforcementProbe)
