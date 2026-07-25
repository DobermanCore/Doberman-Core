"""Feature RB, slice RB.5 — mode-gated egress posture over the broker.

Paranoid mode escalates ``ExternalDestinationRule``'s usual AUTH to a hard
``BLOCK`` for a non-allowlisted egress destination — but ONLY when a broker
PROVEN to enforce egress (``consult_broker`` gates on ``EnforcementStatus.
PROVEN``) also attests it will itself drop that exact destination at the
socket (``will_enforce``). Without a broker, every mode — including paranoid
— is byte-for-byte unchanged from today (EB.1): there is nothing enforcing
the block, so a hard BLOCK would be a lie. Strictly raise-only: no mode may
turn today's AUTH into PASS, and RB.3's route-divergence raise / RB.4's
broker-backed PASS gate both survive untouched.
"""

from datetime import datetime, timezone

import pytest

from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EnforcementStatus
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


def _command_egress_action(**overrides) -> SecurityObject:
    base = dict(
        id="rb5-cmd-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target="curl https://internal-tool.example/upload",
        external_destination="internal-tool.example",
    )
    base.update(overrides)
    return SecurityObject(**base)


def _network_action(**overrides) -> SecurityObject:
    base = dict(
        id="rb5-net-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://unknown-saas.example/api",
        external_destination="unknown-saas.example",
    )
    base.update(overrides)
    return SecurityObject(**base)


def _ctx(mode: str = "balanced", **metadata) -> EvalContext:
    return EvalContext(mode=mode, metadata=metadata)


class _Broker:
    """Configurable fake ``EgressBroker`` — PROVEN by default."""

    def __init__(
        self,
        status: EnforcementStatus = EnforcementStatus.PROVEN,
        *,
        allowlisted: bool = False,
        will_enforce: bool = True,
        events=(),
    ) -> None:
        self._status = status
        self._allowlisted = allowlisted
        self._will_enforce = will_enforce
        self._events = tuple(events)

    def enforcement_status(self) -> EnforcementStatus:
        return self._status

    def classify(self, action) -> BrokerVerdict:
        return BrokerVerdict(allowlisted=self._allowlisted, will_enforce=self._will_enforce)

    def connection_events(self, entity, window):
        start, end = window
        return tuple(e for e in self._events if e.entity_id == entity and start <= e.ts <= end)


# --- the key fail-closed-but-honest test -----------------------------------


@pytest.mark.parametrize("mode", ["light", "balanced", "strict", "paranoid"])
def test_no_broker_every_mode_unchanged_from_today(mode):
    """With no broker registered, EVERY mode — including paranoid — behaves
    exactly as today: a hard BLOCK requires real enforcement backing it."""
    rule = ExternalDestinationRule()
    result = rule.evaluate(_network_action(), _ctx(mode=mode))
    assert result.verdict is not Verdict.BLOCK
    expected = Verdict.AUTH if mode in ("strict", "paranoid") else Verdict.PASS
    assert result.verdict is expected


# --- paranoid + enforcing broker + non-allowlisted -> BLOCK ----------------


def test_paranoid_enforcing_broker_non_allowlisted_blocks_network():
    broker = _Broker(allowlisted=False, will_enforce=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_network_action(), _ctx(mode="paranoid"))
    assert result.verdict is Verdict.BLOCK
    assert result.reason_codes == [ReasonCode.egress_blocked_by_mode]


def test_paranoid_enforcing_broker_non_allowlisted_blocks_command_egress():
    broker = _Broker(allowlisted=False, will_enforce=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_command_egress_action(), _ctx(mode="paranoid"))
    assert result.verdict is Verdict.BLOCK
    assert result.reason_codes == [ReasonCode.egress_blocked_by_mode]


def test_paranoid_broker_not_enforcing_this_destination_stays_auth():
    """allowlisted=False but will_enforce=False: the broker won't actually
    drop this one at the socket, so a BLOCK would be advisory, not truthful.
    """
    broker = _Broker(allowlisted=False, will_enforce=False)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_network_action(), _ctx(mode="paranoid"))
    assert result.verdict is Verdict.AUTH


# --- RB.4's broker-backed PASS path survives untouched ----------------------


def test_paranoid_enforcing_broker_allowlisted_still_passes():
    broker = _Broker(allowlisted=True, will_enforce=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_network_action(), _ctx(mode="paranoid"))
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == [ReasonCode.egress_broker_enforced]


# --- raise-only ceiling: only paranoid escalates to BLOCK -------------------


@pytest.mark.parametrize("mode", ["light", "balanced", "strict"])
def test_non_paranoid_modes_never_block_even_with_enforcing_broker(mode):
    broker = _Broker(allowlisted=False, will_enforce=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_network_action(), _ctx(mode=mode))
    assert result.verdict is not Verdict.BLOCK
    expected = Verdict.AUTH if mode == "strict" else Verdict.PASS
    assert result.verdict is expected


# --- RB.3 divergence still raises and still wins over any PASS -------------


def test_route_divergence_with_paranoid_never_passes():
    """Even under RB.5's paranoid posture, RB.3's retrospective divergence
    check still raises a would-be PASS to at least AUTH — never PASS."""
    events = (ConnectionEvent(entity_id="ent-1", ts=_NOW, host="divergent-host.example"),)
    broker = _Broker(allowlisted=True, will_enforce=True, events=events)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_network_action(), _ctx(mode="paranoid", entity_id="ent-1"))
    assert result.verdict is not Verdict.PASS
    assert ReasonCode.egress_route_divergence in result.reason_codes
