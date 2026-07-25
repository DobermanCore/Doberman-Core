"""Feature RB, slice RB.2a — the two-sided enforcement probe.

Every test here defends the two-sided fail-closed contract: a PROVEN verdict
requires BOTH a failed direct connection AND a successful broker-routed
connection. A failed direct connection alone (however it fails — refused,
timed out, or anything else) is never sufficient by itself, because a
dropped packet or a policy-blocked probe target look identical to real
enforcement from the outside. No test ever touches a real socket or sleeps:
the connector, the broker probe, and the clock are all injected.
"""

import socket

from doberman.egress.broker import EnforcementStatus
from doberman.egress.enforcement import EnforcementProbe


def _connector_returns(*, exc: BaseException | None = None):
    calls = {"count": 0}

    def _connector(host, port, timeout):
        calls["count"] += 1
        if exc is not None:
            raise exc

    return _connector, calls


def _prober_returns(*, exc: BaseException | None = None):
    calls = {"count": 0}

    def _prober():
        calls["count"] += 1
        if exc is not None:
            raise exc

    return _prober, calls


def _fake_clock(start: float = 0.0):
    state = {"now": start}

    def _clock():
        return state["now"]

    def _advance(seconds: float):
        state["now"] += seconds

    return _clock, _advance


def test_direct_fails_and_broker_succeeds_is_proven():
    connector, connector_calls = _connector_returns(exc=ConnectionRefusedError())
    broker_probe, broker_calls = _prober_returns()
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe)
    assert probe.status() is EnforcementStatus.PROVEN
    assert connector_calls["count"] == 1
    assert broker_calls["count"] == 1


def test_direct_succeeds_and_broker_succeeds_is_unproven():
    # A direct connection that succeeds proves egress is unconstrained,
    # regardless of what the broker probe says.
    connector, _ = _connector_returns()
    broker_probe, broker_calls = _prober_returns()
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe)
    assert probe.status() is EnforcementStatus.UNPROVEN
    # Short-circuits: the positive half is never even consulted once the
    # negative half already failed to hold.
    assert broker_calls["count"] == 0


def test_direct_fails_and_broker_fails_is_unproven():
    connector, _ = _connector_returns(exc=ConnectionRefusedError())
    broker_probe, broker_calls = _prober_returns(exc=RuntimeError("broker unreachable"))
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe)
    assert probe.status() is EnforcementStatus.UNPROVEN
    assert broker_calls["count"] == 1


def test_direct_fails_and_broker_probe_absent_is_unproven():
    # The RB.2a default: no listener exists, so no broker_probe is wired in.
    connector, _ = _connector_returns(exc=ConnectionRefusedError())
    probe = EnforcementProbe(connector=connector, broker_probe=None)
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_dropped_packets_alone_do_not_prove_enforcement():
    # A firewall that DROPs packets (the most common enterprise block)
    # produces a TimeoutError on direct connect -- indistinguishable from
    # real enforcement unless the positive half also holds. With no working
    # broker probe, this must never read as PROVEN.
    connector, _ = _connector_returns(exc=TimeoutError())
    probe = EnforcementProbe(connector=connector, broker_probe=None)
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_connection_refused_alone_does_not_prove_enforcement():
    # Many enterprises block 1.1.1.1 specifically by resolver/RST policy,
    # producing a ConnectionRefusedError on a machine whose egress is
    # otherwise completely unconstrained. With no working broker probe,
    # this must never read as PROVEN.
    connector, _ = _connector_returns(exc=ConnectionRefusedError())
    probe = EnforcementProbe(connector=connector, broker_probe=None)
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_unexpected_exception_in_direct_half_is_unproven_and_never_raises():
    connector, _ = _connector_returns(exc=RuntimeError("connector bug"))
    broker_probe, _ = _prober_returns()
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe)
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_unexpected_exception_in_broker_half_is_unproven_and_never_raises():
    connector, _ = _connector_returns(exc=ConnectionRefusedError())
    broker_probe, _ = _prober_returns(exc=ValueError("nonsense"))
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe)
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_status_never_raises_even_with_a_pathological_connector():
    def _boom(host, port, timeout):
        raise ValueError("nonsense")

    probe = EnforcementProbe(connector=_boom)
    # Must not raise.
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_probe_is_cached_within_the_ttl_not_invoked_per_call():
    connector, connector_calls = _connector_returns(exc=ConnectionRefusedError())
    broker_probe, broker_calls = _prober_returns()
    clock, advance = _fake_clock()
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe, clock=clock, ttl=300.0)

    assert probe.status() is EnforcementStatus.PROVEN
    assert probe.status() is EnforcementStatus.PROVEN
    assert probe.status() is EnforcementStatus.PROVEN
    assert connector_calls["count"] == 1  # only the first call actually probed
    assert broker_calls["count"] == 1

    advance(299.0)  # still inside the TTL window
    assert probe.status() is EnforcementStatus.PROVEN
    assert connector_calls["count"] == 1
    assert broker_calls["count"] == 1


def test_probe_re_runs_once_the_ttl_elapses():
    connector, connector_calls = _connector_returns(exc=ConnectionRefusedError())
    broker_probe, broker_calls = _prober_returns()
    clock, advance = _fake_clock()
    probe = EnforcementProbe(connector=connector, broker_probe=broker_probe, clock=clock, ttl=300.0)

    assert probe.status() is EnforcementStatus.PROVEN
    assert connector_calls["count"] == 1
    assert broker_calls["count"] == 1

    advance(300.0)  # exactly at (>=) the TTL boundary
    assert probe.status() is EnforcementStatus.PROVEN
    assert connector_calls["count"] == 2
    assert broker_calls["count"] == 2


def test_default_construction_performs_no_network_io(monkeypatch):
    # A caller that constructs EnforcementProbe() with no injected connector
    # must never reach the network -- socket.create_connection should never
    # even be called. The default connector fails closed instead.
    def _must_not_be_called(*args, **kwargs):
        raise AssertionError("EnforcementProbe touched the real network by default")

    monkeypatch.setattr(socket, "create_connection", _must_not_be_called)
    probe = EnforcementProbe()
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_probe_target_and_timeout_are_constructor_injectable():
    seen = {}

    def _connector(host, port, timeout):
        seen["host"], seen["port"], seen["timeout"] = host, port, timeout

    probe = EnforcementProbe(host="probe.example", port=9999, timeout=0.25, connector=_connector)
    probe.status()
    assert seen == {"host": "probe.example", "port": 9999, "timeout": 0.25}
