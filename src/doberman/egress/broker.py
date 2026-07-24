"""The `EgressBroker` seam: interface, verdict/event models, and the
fail-closed consultation helper (Feature RB, slice RB.1).

PROSPECTIVE vs RETROSPECTIVE — read this before touching :meth:`EgressBroker.
classify`. A forward-proxy broker only learns an action's REAL destination at
connect time, which happens AFTER the tool-call decision this seam consults it
for. So :meth:`classify` can never return an ``actual_destination`` — it can
only answer a prospective question: *if this action proceeds, would its
declared destination be permitted, and will the broker itself ENFORCE that
constraint at the socket?* The corresponding retrospective question — what did
the action actually connect to — is answered later, out-of-band, by
:meth:`EgressBroker.connection_events`. This split is why ground-truth
reconciliation (RB.3) compares a *logged* connection against the original
decision after the fact; it is never a pre-flight check.

RB.1 wires this seam into the decision path but keeps it DORMANT: a broker is
consulted (so the machinery is real and testable), but the decision path
unconditionally discards the result. No broker verdict can raise or lower a
verdict until RB.4 (an allowlisted, enforced destination becomes eligible for
``PASS`` there — never before).
"""

import logging
from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from doberman.models import ReasonCode, SecurityObject

logger = logging.getLogger("doberman.egress.broker")


class EnforcementStatus(StrEnum):
    """How much a broker's promise to enforce egress can currently be trusted.

    Only ``PROVEN`` is ever eligible to back a decision (starting RB.4). A
    broker that cannot attest its own enforcement — or that raises answering
    the question — is treated identically to no broker at all.
    """

    #: The broker has attested (e.g. via a startup/health proof) that it is
    #: actually intercepting and will enforce egress for this deployment.
    PROVEN = "PROVEN"
    #: A broker is registered and reachable, but has not (yet) proven it is
    #: enforcing — e.g. still starting up, or attestation is unimplemented.
    UNPROVEN = "UNPROVEN"
    #: No broker is registered, reachable, or trustworthy right now.
    ABSENT = "ABSENT"


class BrokerVerdict(BaseModel):
    """A broker's PROSPECTIVE answer for one pending action (immutable).

    Deliberately carries no ``actual_destination`` — see the module docstring.
    ``allowlisted`` and ``will_enforce`` are the broker's own claims; the
    caller MUST NOT treat them as authoritative unless ``enforcement_status()``
    is separately confirmed ``PROVEN`` (RB.1 never does — dormant by design).
    """

    model_config = ConfigDict(frozen=True)

    #: Would the broker permit this action's declared destination through.
    allowlisted: bool
    #: Will the broker itself enforce that constraint at the socket if the
    #: action proceeds (as opposed to merely opining on it).
    will_enforce: bool
    reason_codes: list[ReasonCode] = Field(default_factory=list)


class ConnectionEvent(BaseModel):
    """One RETROSPECTIVE, redaction-safe record of an observed connection.

    Ground truth for reconciliation (RB.3): what the broker actually saw at
    the socket, after the fact. No payload/body data — host, coarse volume,
    and whether the broker itself enforced this connection.
    """

    model_config = ConfigDict(frozen=True)

    #: Keyed HMAC fingerprint of the entity, never a raw role/path string.
    entity_id: str = Field(min_length=1)
    ts: AwareDatetime  # forensic timestamp — naive datetimes are rejected
    host: str
    #: Coarse byte count only, never payload content. Non-negative.
    bytes_sent: int = Field(default=0, ge=0)
    #: Whether the broker actually enforced (vs merely observed) this connection.
    will_enforce: bool = False


@runtime_checkable
class EgressBroker(Protocol):
    """The contract a runtime egress broker implements.

    CAVEAT: ``isinstance(obj, EgressBroker)`` is structural-only (checks for
    the three method names, not their signatures) — the real gate is that
    :func:`consult_broker` validates every return value and isolates
    exceptions. A broker MUST NOT raise as its normal signaling path; any
    failure is treated identically to :attr:`EnforcementStatus.ABSENT`.
    """

    def enforcement_status(self) -> EnforcementStatus:
        """Report how trustworthy this broker's enforcement currently is."""
        ...

    def classify(self, action: SecurityObject) -> BrokerVerdict:
        """Prospective: would ``action``'s declared destination be permitted,
        and will the broker enforce that at the socket if it proceeds? Never
        claims to know the actual runtime destination of a pending action —
        see the module docstring.
        """
        ...

    def connection_events(
        self, entity: str, window: tuple[AwareDatetime, AwareDatetime]
    ) -> Sequence[ConnectionEvent]:
        """Retrospective: connections actually observed for ``entity`` in ``window``."""
        ...


def consult_broker(broker: EgressBroker | None, action: SecurityObject) -> BrokerVerdict | None:
    """Fail-closed consultation: a live verdict only when the broker is PROVEN.

    Returns ``None`` — never raises — when there is no broker, the broker's
    ``enforcement_status()`` is not ``PROVEN``, or either method raises or
    returns something malformed. Callers MUST treat a ``None`` and an AUTH
    verdict identically to no broker at all; RB.1 additionally discards a
    non-``None`` return outright (the seam is wired but dormant).
    """
    if broker is None:
        return None
    try:
        status = broker.enforcement_status()
    except Exception:  # noqa: BLE001 — a raising broker is treated as ABSENT
        logger.debug("egress broker raised checking enforcement_status; treating as ABSENT")
        return None
    if status is not EnforcementStatus.PROVEN:
        return None
    try:
        verdict = broker.classify(action)
    except Exception:  # noqa: BLE001 — a raising broker is treated as ABSENT
        logger.debug("egress broker raised in classify(); treating as ABSENT")
        return None
    if not isinstance(verdict, BrokerVerdict):
        logger.debug("egress broker returned a non-BrokerVerdict; treating as ABSENT")
        return None
    return verdict
