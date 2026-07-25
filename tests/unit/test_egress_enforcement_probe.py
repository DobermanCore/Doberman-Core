"""Feature RB, slice RB.2a — the active-negative-probe enforcement check.

Every test here defends the fail-closed contract: a direct connection that
SUCCEEDS means egress is not constrained (UNPROVEN); an explicit rejection
(ConnectionRefusedError/TimeoutError) means it appears constrained (PROVEN);
anything else — an unrelated OSError or a surprising bug — is ambiguous and
must fail closed to UNPROVEN. No test ever touches a real socket or sleeps:
the connector and the clock are both injected.
"""

from doberman.egress.broker import EnforcementStatus
from doberman.egress.enforcement import EnforcementProbe


def _connector_returns(*, exc: BaseException | None = None):
    calls = {"count": 0}

    def _connector(host, port, timeout):
        calls["count"] += 1
        if exc is not None:
            raise exc

    return _connector, calls


def _fake_clock(start: float = 0.0):
    state = {"now": start}

    def _clock():
        return state["now"]

    def _advance(seconds: float):
        state["now"] += seconds

    return _clock, _advance


def test_successful_direct_connection_is_unproven():
    connector, calls = _connector_returns()
    probe = EnforcementProbe(connector=connector)
    assert probe.status() is EnforcementStatus.UNPROVEN
    assert calls["count"] == 1


def test_connection_refused_is_proven():
    connector, calls = _connector_returns(exc=ConnectionRefusedError())
    probe = EnforcementProbe(connector=connector)
    assert probe.status() is EnforcementStatus.PROVEN
    assert calls["count"] == 1


def test_timeout_error_is_proven():
    connector, calls = _connector_returns(exc=TimeoutError())
    probe = EnforcementProbe(connector=connector)
    assert probe.status() is EnforcementStatus.PROVEN
    assert calls["count"] == 1


def test_generic_os_error_is_unproven_per_the_documented_rule():
    # A plain OSError (e.g. DNS resolution failure, network unreachable) is
    # ambiguous — it might mean the probe itself is misconfigured, not that
    # egress is actually constrained — so it fails closed to UNPROVEN, unlike
    # the definitive ConnectionRefusedError/TimeoutError cases above.
    connector, calls = _connector_returns(exc=OSError("network is unreachable"))
    probe = EnforcementProbe(connector=connector)
    assert probe.status() is EnforcementStatus.UNPROVEN
    assert calls["count"] == 1


def test_unexpected_exception_is_unproven_and_never_propagates():
    connector, calls = _connector_returns(exc=RuntimeError("connector bug"))
    probe = EnforcementProbe(connector=connector)
    assert probe.status() is EnforcementStatus.UNPROVEN
    assert calls["count"] == 1


def test_status_never_raises_even_with_a_pathological_connector():
    def _boom(host, port, timeout):
        raise ValueError("nonsense")

    probe = EnforcementProbe(connector=_boom)
    # Must not raise.
    assert probe.status() is EnforcementStatus.UNPROVEN


def test_probe_is_cached_within_the_ttl_not_invoked_per_call():
    connector, calls = _connector_returns(exc=ConnectionRefusedError())
    clock, advance = _fake_clock()
    probe = EnforcementProbe(connector=connector, clock=clock, ttl=300.0)

    assert probe.status() is EnforcementStatus.PROVEN
    assert probe.status() is EnforcementStatus.PROVEN
    assert probe.status() is EnforcementStatus.PROVEN
    assert calls["count"] == 1  # only the first call actually probed

    advance(299.0)  # still inside the TTL window
    assert probe.status() is EnforcementStatus.PROVEN
    assert calls["count"] == 1


def test_probe_re_runs_once_the_ttl_elapses():
    connector, calls = _connector_returns(exc=ConnectionRefusedError())
    clock, advance = _fake_clock()
    probe = EnforcementProbe(connector=connector, clock=clock, ttl=300.0)

    assert probe.status() is EnforcementStatus.PROVEN
    assert calls["count"] == 1

    advance(300.0)  # exactly at (>=) the TTL boundary
    assert probe.status() is EnforcementStatus.PROVEN
    assert calls["count"] == 2


def test_probe_target_and_timeout_are_constructor_injectable():
    seen = {}

    def _connector(host, port, timeout):
        seen["host"], seen["port"], seen["timeout"] = host, port, timeout

    probe = EnforcementProbe(host="probe.example", port=9999, timeout=0.25, connector=_connector)
    probe.status()
    assert seen == {"host": "probe.example", "port": 9999, "timeout": 0.25}
