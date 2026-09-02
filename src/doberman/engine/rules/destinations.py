"""External-destination rule (Feature 3, slice 3.5).

Steps up authentication when an action sends data to a destination Doberman
does not recognize as trusted, or when a raw shell/package/git command visibly
egresses. Static command classification is raise-only: even a trusted-looking
host requires ``AUTH`` because parsing cannot prove the runtime socket.

Host classification is treated as adversarial. We extract the host from a
properly parsed URL (never substring-match the raw string) and:

* decode IDNA/punycode so ``xn--80ak6aa92e.com`` is compared as its unicode
  form and a homoglyph domain is **not** mistaken for a trusted one;
* reject ``user:pass@host`` credential-in-URL forms — the embedded-credential
  is itself a signal, and the real host is taken from after the ``@``;
* treat bare IP literals (and ``[::1]``) as **unknown** (never trusted) — a
  trusted *name* cannot be impersonated by an IP;
* match on the **registered domain** (host == trusted, or a dotted subdomain of
  it), so ``evil-github.com`` and ``github.com.evil.test`` are *not* trusted.

SECURITY: the explanation names only the classification, never the raw URL,
query parameters, or any embedded credential.
"""

import ipaddress
import logging
from collections.abc import Iterable, Sequence
from datetime import timedelta
from urllib.parse import urlsplit

from pydantic import AwareDatetime

from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EgressBroker, consult_broker
from doberman.egress.velocity import EgressVelocityTracker, VelocityThresholds
from doberman.engine.registry import discover_egress_brokers
from doberman.engine.rules.commands import command_line_from_arguments
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for

logger = logging.getLogger("doberman.engine.rules.destinations")

#: RB.3 — how far back a broker's observed connections are consulted for
#: ground-truth reconciliation. Bounded and cheap: reuses the broker's own
#: (already-bounded) event store; the rule holds no history of its own.
_RECONCILIATION_WINDOW = timedelta(minutes=15)

#: Destinations Doberman ships trusting. Overridable (F6 loads from policy).
#: Registered domains only — subdomains are matched structurally.
TRUSTED_HOSTS: tuple[str, ...] = (
    "registry.npmjs.org",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "files.pythonhosted.org",
    "pythonhosted.org",
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "objects.githubusercontent.com",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
    "go.dev",
    "proxy.golang.org",
    "sum.golang.org",
)


def _decode_host(host: str) -> str:
    """Lower-case and IDNA-decode a host (punycode → unicode) for comparison.

    Decoding means a homoglyph/punycode domain is compared as the unicode it
    actually resolves to, so it cannot masquerade as an ASCII trusted host.
    Falls back to the raw lower-cased host if decoding fails.
    """
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    try:
        # encode('ascii') ensures any non-ASCII (already-unicode homoglyph) is
        # surfaced rather than silently equal to ASCII; then decode punycode.
        return cleaned.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return cleaned


def _is_ip_literal(host: str) -> bool:
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _registered_match(host: str, trusted: Iterable[str]) -> bool:
    """True if ``host`` equals a trusted domain or is a dotted subdomain of one."""
    if not host:
        return False
    for domain in trusted:
        d = domain.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def _carries_command(action: SecurityObject, ctx: EvalContext | None = None) -> bool:
    """True for the command-bearing action types, OR when the raw arguments
    still compose a command line whatever the tool's declared type.

    A caller-supplied tool name is not a trust boundary (#519/#527): a
    command-shaped payload (``command``/``cmd``/``script``/``args``) under an
    unrecognized tool name must be classified as command egress exactly like
    the same payload under ``shell_exec``/``package_install``/``git_op``.

    ``ctx`` is optional: :class:`~doberman.egress.broker.EgressBroker.classify`
    (a third-party plugin protocol method, e.g. :class:`~doberman.egress.
    local.LocalEgressBroker`) only receives ``action`` and has no ``EvalContext``
    to consult — with no ``ctx``, this degrades to the action_type-only check
    (unchanged, prior behavior) rather than raising or widening the plugin
    contract.
    """
    if action.action_type in (
        ActionType.shell_exec,
        ActionType.package_install,
        ActionType.git_op,
    ):
        return True
    if ctx is None or action.action_type is ActionType.network_request:
        # A network action's destination IS its URL: an ``args`` list on a
        # fetch tool is request options, not a shell line, and treating it as
        # command egress would route the action through the command branch
        # (broker PASS site, "shell egress" AUTH) instead of the network
        # branch's embedded-credential / IP-literal checks.
        return False
    raw_arguments = ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
    if not isinstance(raw_arguments, dict):
        return False
    return command_line_from_arguments(raw_arguments) is not None


def _is_egress_classified(action: SecurityObject, ctx: EvalContext | None = None) -> bool:
    """True for the action types (or command-shaped payloads) this rule (and
    RB.3 reconciliation) classify."""
    return action.action_type is ActionType.network_request or _carries_command(action, ctx)


def _broker_grants_pass(verdict: BrokerVerdict | None) -> bool:
    """RB.4: true only when a PROVEN broker's verdict allowlists AND will
    enforce this exact destination.

    ``consult_broker`` already collapses everything short of that — no
    broker, ``UNPROVEN``/``ABSENT``, or a raising broker — to ``None`` (see
    ``doberman.egress.broker``), so a ``None`` here means "no signal,
    unchanged AUTH behavior." Both flags are required: an allowlisted
    destination the broker will NOT itself enforce (e.g. no proxy running)
    is still a bare claim, not proof, and must stay AUTH.
    """
    return verdict is not None and verdict.allowlisted and verdict.will_enforce


def _raise_for_divergence(result: GuardrailResult) -> GuardrailResult:
    """RB.3: attach ``egress_route_divergence`` and ensure at least ``AUTH``.

    Strictly raise-only — this only ever raises a ``PASS`` to ``AUTH``, or
    appends the reason code to an already-``AUTH``/``BLOCK`` result (RB.5's
    paranoid mode-gated hard block is the one case ``ExternalDestinationRule``
    itself returns ``BLOCK``). Never lowers a verdict/risk, never grants ``PASS``.
    """
    if result.verdict is Verdict.PASS:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.egress_route_divergence],
            explanation=(
                "This entity recently connected to a destination its static egress "
                "classification did not predict; authentication required."
            ),
        )
    return GuardrailResult(
        verdict=result.verdict,
        risk=result.risk,
        reason_codes=[*result.reason_codes, ReasonCode.egress_route_divergence],
        explanation=result.explanation,
    )


def _raise_for_velocity(result: GuardrailResult) -> GuardrailResult:
    """RB.6: attach ``anomalous_egress_velocity`` and ensure at least ``AUTH``.

    Strictly raise-only, same shape as :func:`_raise_for_divergence` — only
    ever raises a ``PASS`` to ``AUTH``, or appends the reason code to an
    already-``AUTH``/``BLOCK`` result. Never lowers a verdict/risk, never
    grants ``PASS``.
    """
    if result.verdict is Verdict.PASS:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.anomalous_egress_velocity],
            explanation=(
                "This entity's recent egress connections show anomalous velocity "
                "(burst, volume, or fan-out); authentication required."
            ),
        )
    return GuardrailResult(
        verdict=result.verdict,
        risk=result.risk,
        reason_codes=[*result.reason_codes, ReasonCode.anomalous_egress_velocity],
        explanation=result.explanation,
    )


def _extract_destination(action: SecurityObject, ctx: EvalContext | None = None) -> str | None:
    """The network or command-egress destination this rule classifies.

    ``ctx`` is optional — see :func:`_carries_command`; callers outside this
    rule (e.g. :class:`~doberman.egress.local.LocalEgressBroker.classify`,
    which only receives ``action``) get the unchanged, action_type-only
    behavior.
    """
    if action.action_type is ActionType.network_request:
        return action.external_destination or action.target
    if _carries_command(action, ctx):
        return action.external_destination
    # Domain tools still expose recipients to the secret/trifecta floors, but
    # destination-alone AUTH remains suppressed to avoid message-send spam.
    return None


def _parse_host(destination: str) -> tuple[str | None, bool]:
    """Return ``(decoded_host, had_embedded_credentials)`` from a destination.

    Handles bare ``host``/``host:port`` (no scheme) as well as full URLs. The
    host is taken from the authority *after* any ``user:pass@`` so a credential
    prefix cannot disguise the true host.
    """
    raw = destination.strip()
    # Give urlsplit a scheme to parse bare hosts consistently.
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parts = urlsplit(candidate if "://" in raw else f"http:{candidate}")
    except ValueError:
        return None, False
    had_credentials = "@" in (parts.netloc or "") and bool(parts.username or parts.password)
    host = parts.hostname  # already strips credentials and brackets for IPv6
    if not host:
        return None, had_credentials
    if _is_ip_literal(host):
        # Keep IP literals as-is (never IDNA-decoded); they are always unknown.
        return host.lower(), had_credentials
    return _decode_host(host), had_credentials


class ExternalDestinationRule:
    """Classify network destinations and raise static command egress to AUTH.

    RB.1: also consults a registered :class:`~doberman.egress.broker.
    EgressBroker` (if any) for every egress-classified action, via the
    fail-closed :func:`~doberman.egress.broker.consult_broker` helper.

    RB.4: the consulted verdict may now grant ``PASS`` in place of this
    rule's two "static parsing can't prove it" ``AUTH`` outcomes — command
    egress with a resolved host, and an unknown/untrusted network
    destination — but ONLY when :func:`_broker_grants_pass` holds (broker
    ``PROVEN``, and it both allowlists AND will itself enforce this exact
    destination at the socket). Every other static ``AUTH`` (an
    unresolvable/malformed host, embedded credentials, a raw IP literal, RB.3
    route divergence) is unaffected: a broker PASS never overrides those, and
    ``combine()`` downstream is raise-only, so this can never punch through a
    BLOCK/AUTH from any other rule (e.g. the secrets rule, the
    lethal-trifecta floor).

    RB.3: separately, :meth:`evaluate` also performs RETROSPECTIVE
    ground-truth reconciliation — never a pre-flight check of the pending
    action's own destination (a forward proxy only learns that at CONNECT
    time, after this decision). It asks the broker what this entity's
    connections actually showed a moment ago
    (:meth:`~doberman.egress.broker.EgressBroker.connection_events`) and, if
    any of them diverged from this rule's static host-trust classification,
    RAISES the verdict :meth:`evaluate` was already going to return. This is
    strictly raise-only: it can step a ``PASS`` up to ``AUTH`` and attach
    ``egress_route_divergence``, but it never lowers a verdict/risk and never
    grants ``PASS``. No broker, no entity id, or a broker whose
    ``connection_events`` raises → no signal → behavior identical to today.

    ``load_broker`` defaults to **False**. This rule is rebuilt from scratch
    on every :class:`~doberman.engine.objective.ObjectiveGuardrail`
    construction, and the host hooks (``doberman.hosthooks.claude_code`` /
    ``.openclaw``) construct a fresh ``ObjectiveGuardrail`` on **every tool
    call**, in a cold-start CLI process, on a path whose whole point is
    near-zero per-call cost. Defaulting broker discovery on there would add a
    full ``importlib.metadata.entry_points()`` scan to every tool call for a
    verdict RB.1 unconditionally discards. Only the long-lived proxy
    singleton (``doberman.proxy.executor.DEFAULT_OBJECTIVE``), built once per
    process, opts in explicitly with ``load_broker=True``. Do not flip this
    default back to ``True`` without re-solving the hook cold-start cost.
    """

    def __init__(
        self,
        trusted_hosts: Iterable[str] = TRUSTED_HOSTS,
        *,
        egress_broker: EgressBroker | None = None,
        load_broker: bool = False,
        velocity_thresholds: VelocityThresholds | None = None,
    ) -> None:
        self._trusted = tuple(h.lower() for h in trusted_hosts)
        self._velocity = EgressVelocityTracker(thresholds=velocity_thresholds)
        if egress_broker is not None:
            self._broker: EgressBroker | None = egress_broker
        elif load_broker:
            discovered = discover_egress_brokers()
            self._broker = discovered[0] if discovered else None
        else:
            self._broker = None

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        """Static classification, then RB.3/RB.6's raise-only retrospective
        checks.

        The static result (unchanged from RB.1) is computed first; ground-
        truth reconciliation and velocity anomalies only ever raise it — see
        the class docstring.
        """
        result = self._evaluate_static(action, ctx)
        if _is_egress_classified(action, ctx):
            if self._has_route_divergence(action, ctx):
                result = _raise_for_divergence(result)
            if self._has_velocity_anomaly(action, ctx):
                result = _raise_for_velocity(result)
        return result

    def _recent_broker_events(
        self, action: SecurityObject, ctx: EvalContext
    ) -> tuple[str, Sequence[ConnectionEvent], tuple[AwareDatetime, AwareDatetime]] | None:
        """Fail-closed fetch of this entity's broker-observed egress within
        the bounded reconciliation window.

        Returns ``None`` (no signal) when there is no broker, no entity id in
        ``ctx.metadata``, or the broker's ``connection_events`` raises.
        Shared by RB.3 and RB.6 so both stay byte-for-byte dormant without a
        broker.
        """
        if self._broker is None:
            return None
        entity = ctx.metadata.get("entity_id") if isinstance(ctx.metadata, dict) else None
        if not entity:
            return None
        end = action.ts
        start = end - _RECONCILIATION_WINDOW
        try:
            events = self._broker.connection_events(entity, (start, end))
        except Exception:  # noqa: BLE001 — a raising broker is no signal, never a crash
            logger.debug("egress broker raised in connection_events(); treating as no signal")
            return None
        return entity, events, (start, end)

    def _has_route_divergence(self, action: SecurityObject, ctx: EvalContext) -> bool:
        """RB.3: has this entity's broker-observed egress, within the bounded
        recent window, shown a host this rule's own static classification
        would not have trusted?

        RETROSPECTIVE only — never re-examines ``action``'s own destination
        (a forward proxy only learns that at CONNECT time, after this
        decision; see the module docstring in ``doberman.egress.broker``).
        Fail-closed to "no signal": no broker, no entity id, or a broker
        whose ``connection_events`` raises all return ``False`` — dormant
        without a broker means byte-for-byte unchanged behavior.
        """
        fetched = self._recent_broker_events(action, ctx)
        if fetched is None:
            return False
        _entity, events, _window = fetched
        return any(
            not _registered_match(_decode_host(event.host), self._trusted) for event in events
        )

    def _has_velocity_anomaly(self, action: SecurityObject, ctx: EvalContext) -> bool:
        """RB.6: has this entity's broker-observed egress, within the bounded
        recent window, tripped a burst/volume/fan-out velocity signal?

        RETROSPECTIVE only, same fail-closed shape as :meth:`_has_route_
        divergence`: no broker, no entity id, or a broker whose
        ``connection_events`` raises all return ``False`` — dormant without a
        broker means byte-for-byte unchanged behavior.
        """
        fetched = self._recent_broker_events(action, ctx)
        if fetched is None:
            return False
        entity, events, window = fetched
        return self._velocity.assess(entity, events, window) is not None

    def _evaluate_static(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        metadata = action.metadata if isinstance(action.metadata, dict) else {}
        command_egress = _carries_command(action, ctx)
        broker_verdict: BrokerVerdict | None = None
        if command_egress or action.action_type is ActionType.network_request:
            # RB.4: genuinely consulted now — may grant PASS below via
            # _broker_grants_pass, but ONLY at the two sites documented in the
            # class docstring. Everywhere else in this method behaves exactly
            # as before RB.4 (this local var is simply unused there).
            broker_verdict = consult_broker(self._broker, action)
        if metadata.get("egress_ambiguous"):
            return self._auth_egress(
                "Command egress could not be resolved to one runtime route; "
                "authentication required."
            )

        destination = _extract_destination(action, ctx)
        if not destination:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        host, had_credentials = _parse_host(destination)
        had_credentials = had_credentials or bool(metadata.get("egress_embedded_credentials"))

        # A malformed/absent host on a network/egress action is suspicious → AUTH.
        if host is None:
            if command_egress:
                return self._auth_egress(
                    "Command egress destination could not be resolved safely; "
                    "authentication required."
                )
            return self._auth_unknown(
                "Network destination could not be resolved to a known host; "
                "authentication required."
            )

        # A visible command destination can only raise risk. The parsed host is
        # not proof of the runtime socket, even when it looks trusted/read-only.
        if command_egress:
            if _broker_grants_pass(broker_verdict):
                return self._pass_broker_enforced()
            if self._mode_hard_blocks_egress(ctx, broker_verdict):
                return self._block_egress_mode()
            if (
                metadata.get("egress_implied_registry")
                and not had_credentials
                and not _is_ip_literal(host)
                and _registered_match(host, self._trusted)
                and not thresholds_for(
                    getattr(ctx, "mode", "balanced")
                ).escalate_unknown_destination
            ):
                # ADR 0075: a recognized package-manager fetch over its default
                # registry, with no redirect signal (normalize guarantees that).
                # Light/Balanced already PASS destination-alone signals for
                # UNKNOWN hosts; a trusted-registry route is strictly stronger.
                # Strict/Paranoid keep the AUTH below, and trimming the trusted
                # list in policy tightens this automatically.
                return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
            return self._auth_egress(
                "Shell, package, or git egress requires authentication because "
                "static parsing cannot prove the runtime route."
            )

        # Embedded credentials in the URL are a smell on their own → AUTH even
        # if the host turns out to be trusted (the credential should not be there).
        if had_credentials:
            return self._auth_unknown(
                "Destination URL embeds credentials in the authority; authentication required."
            )

        # IP literals are never trusted by name.
        if _is_ip_literal(host):
            return self._auth_unknown(
                "Network destination is a raw IP address (not a trusted host); "
                "authentication required."
            )

        if _registered_match(host, self._trusted):
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        # A plain unknown host steps up only when the mode says so. Light and
        # Balanced treat "not on the trusted list" as PASS — this AUTH fired on
        # every fetch to any host off the small registry allowlist and was the
        # top source of benign prompts. This is raise-only-safe: it only relaxes
        # the *destination-alone* signal in lighter modes; the sharper smells
        # above (embedded credentials, raw IPs, unresolvable hosts) still AUTH in
        # every mode, and a secret leaving to any host is still a hard block via
        # the secrets rule + raise-only combine. Strict/Paranoid still AUTH here.
        if not thresholds_for(getattr(ctx, "mode", "balanced")).escalate_unknown_destination:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        if _broker_grants_pass(broker_verdict):
            return self._pass_broker_enforced()

        if self._mode_hard_blocks_egress(ctx, broker_verdict):
            return self._block_egress_mode()

        return self._auth_unknown(
            "Network destination is not on the trusted list; authentication required."
        )

    def _auth_unknown(self, explanation: str) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.unknown_external_destination],
            explanation=explanation,
        )

    def _auth_egress(self, explanation: str) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.egress_requires_auth],
            explanation=explanation,
        )

    def _mode_hard_blocks_egress(
        self, ctx: EvalContext, broker_verdict: BrokerVerdict | None
    ) -> bool:
        """RB.5: Paranoid-only, and only when a broker PROVEN to enforce egress
        (``broker_verdict is not None`` — see :func:`consult_broker`) attests it
        will itself drop this exact destination at the socket. Mirrors
        :func:`_broker_grants_pass` with ``allowlisted`` flipped: same
        ``will_enforce`` requirement, so the BLOCK is truthful, not advisory.
        Dormant with no broker in every mode, including Paranoid (raise-only).
        """
        if broker_verdict is None or not broker_verdict.will_enforce:
            return False
        if broker_verdict.allowlisted:
            return False
        return thresholds_for(getattr(ctx, "mode", "balanced")).egress_hard_block

    def _block_egress_mode(self) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.high,
            reason_codes=[ReasonCode.egress_blocked_by_mode],
            explanation=(
                "Paranoid mode hard-blocks this destination because a proven egress "
                "broker will itself drop it at the socket."
            ),
        )

    def _pass_broker_enforced(self) -> GuardrailResult:
        """RB.4: reached only via :func:`_broker_grants_pass` — a PROVEN
        broker attested it allowlists AND will itself enforce this exact
        destination at the socket, so static parsing's inability to prove
        the runtime route is no longer the last word.
        """
        return GuardrailResult(
            verdict=Verdict.PASS,
            risk=Risk.low,
            reason_codes=[ReasonCode.egress_broker_enforced],
            explanation=(
                "A proven egress broker attests this destination is allowlisted and "
                "will enforce it at the socket; authentication is not required."
            ),
        )
