"""Smuggled-token channel detection (OOD token defense — objective rule).

The deterministic, near-zero-false-positive half of Doberman's out-of-distribution
token defense. It scans the strings an action carries — the un-redacted
``raw_arguments`` (in memory only, never logged), the target, the external
destination, and the tool name — for **hard** smuggling channels with no
legitimate use in tool traffic:

* Unicode Tag Block ASCII smuggling (the "ASCII Smuggler" channel),
* bidirectional control overrides (Trojan-Source class),
* variation-selector byte channels,
* noncharacter / unassigned codepoints,
* unpaired surrogates (a tag-block reassembly evasion),
* payloads that are entirely invisible.

(The probabilistic channels — homoglyph confusables, glitch-token fragments,
NFKC compatibility-form smuggling — are raise-only and handled by the subjective
detector in :mod:`doberman.engine.detectors.token_channels`, never here.)

Verdicts (mirrors the secret-leakage rule's posture):

* a hard channel **+ an external destination** → ``BLOCK (smuggled_token_channel)``
  — hidden instructions or data on their way out of the boundary,
* a hard channel staying **local** → ``AUTH (smuggled_token_channel)`` — step up,
  never PASS-on-doubt,
* nothing hard detected → abstain (``PASS``).

SECURITY / redaction: the decoded smuggled payload, the matched substring, and
the raw argument values are **never** placed in the explanation, a reason code,
or a log. The agent-visible explanation names the *channel class*, not the
payload. This is defense-in-depth and intentionally imperfect — it is not
marketed as airtight.
"""

import logging

from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.tokens import SCAN_MAX_CHARS, collect_scan_strings, scan_text

logger = logging.getLogger("doberman.engine.rules.token_channels")


def _has_external_destination(action: SecurityObject) -> bool:
    """Is this action sending data OUT to an external destination?"""
    if action.external_destination:
        return True
    return action.action_type in (ActionType.network_request, ActionType.git_op)


def _hard_channels(strings: list[str]) -> list[str]:
    """The distinct hard channel classes found across all strings (no payload)."""
    found: list[str] = []
    for text in strings:
        report = scan_text(text[:SCAN_MAX_CHARS])
        for channel in report.channels(severity="hard"):
            if channel not in found:
                found.append(channel)
    return found


class TokenChannelRule:
    """Block exfiltration of, and step up on, hard smuggled-token channels.

    Pure ``Guardrail``: reads the action + context, returns a verdict. Never
    mutates the action; never emits the decoded payload or a matched substring.
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        channels = _hard_channels(collect_scan_strings(action, ctx))
        if not channels:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        # Channel classes are safe to log (no payload); useful for forensics.
        logger.debug("smuggled-token channel(s) detected (action %s): %s", action.id, channels)

        if _has_external_destination(action):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.critical,
                reason_codes=[ReasonCode.smuggled_token_channel],
                explanation=(
                    "Action carries hidden/invisible token-smuggling channels and "
                    "targets an external destination; blocked to prevent smuggled "
                    "instructions or data from leaving the boundary."
                ),
            )
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.smuggled_token_channel],
            explanation=(
                "Action carries hidden/invisible token-smuggling channels; "
                "authentication required before proceeding."
            ),
        )
