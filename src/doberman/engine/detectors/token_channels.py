"""Probabilistic token-anomaly detection (OOD token defense — subjective detector).

The raise-only half of the out-of-distribution token defense. Where the
objective :class:`~doberman.engine.rules.token_channels.TokenChannelRule`
handles the deterministic, near-zero-false-positive *hard* channels (and may
BLOCK), this detector handles the **soft**, context-dependent signals that
warrant a step-up but not a hard block:

* ``mixed_script_confusable`` — homoglyph spoofing (a Cyrillic ``а`` in a Latin
  word),
* ``glitch_fragment``         — known under-trained ("glitch") token fragments,
* ``nfkc_delta``              — text that gains ASCII under NFKC normalization
  (compatibility-form smuggling),
* ``private_use`` / ``control_chars`` — out-of-distribution codepoints,
* a small (sub-threshold) run of zero-width characters.

It runs in the subjective guardrail, so by construction it can only **raise**
risk to ``AUTH`` — the execution rule clamps any subjective BLOCK to AUTH. It
never blocks and never lowers a verdict.

Optional statistical channel (opt-in, no core dependency): an adversarial-suffix
/ perplexity signal is genuinely useful but needs a real language model, which
core (local-first, stdlib-only) does not ship. A calibrated scorer can be
injected via ``perplexity_fn`` (a ``Callable[[str], float]`` returning a
``[0, 1]`` anomaly score); a built-in instance leaves it ``None``. A reference
model-backed implementation belongs in a separately-installed package (it would
register through the ``doberman.detectors`` entry point), not here — shipping a
character-statistics heuristic in its place would be security theater, since
such heuristics cannot separate adversarial suffixes from benign shell/SQL.

SECURITY / redaction: never emits the matched substring, the decoded payload,
or raw argument values — the explanation names the *signal class* only.
"""

import logging
from collections.abc import Callable

from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.tokens import SCAN_MAX_CHARS, GlitchFragmentStore, collect_scan_strings, scan_text

logger = logging.getLogger("doberman.engine.detectors.token_channels")


class TokenChannelDetector:
    """Raise-only detector for soft (probabilistic) token-channel anomalies.

    Pure ``Guardrail``: ``evaluate(action, ctx) -> GuardrailResult``. Built-in
    instances are constructed with no arguments (no perplexity model). Pass a
    ``glitch_store`` to supply a per-model fragment list, or a ``perplexity_fn``
    + ``perplexity_threshold`` to enable the opt-in statistical channel.
    """

    def __init__(
        self,
        *,
        glitch_store: GlitchFragmentStore | None = None,
        perplexity_fn: Callable[[str], float] | None = None,
        perplexity_threshold: float = 0.5,
    ) -> None:
        self._glitch = glitch_store or GlitchFragmentStore()
        self._perplexity_fn = perplexity_fn
        self._perplexity_threshold = perplexity_threshold

    def _soft_channels(self, strings: list[str]) -> list[str]:
        found: list[str] = []
        for text in strings:
            report = scan_text(text[:SCAN_MAX_CHARS], glitch_store=self._glitch)
            for channel in report.channels(severity="soft"):
                if channel not in found:
                    found.append(channel)
        return found

    def _perplexity_exceeded(self, strings: list[str]) -> bool:
        if self._perplexity_fn is None:
            return False
        for text in strings:
            try:
                score = self._perplexity_fn(text[:SCAN_MAX_CHARS])
            except Exception:  # noqa: BLE001 — an injected scorer must not crash the gate
                logger.warning("injected perplexity_fn raised; ignoring its signal")
                return False
            if isinstance(score, (int, float)) and score >= self._perplexity_threshold:
                return True
        return False

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        strings = collect_scan_strings(action, ctx)
        channels = self._soft_channels(strings)
        if self._perplexity_exceeded(strings):
            channels.append("perplexity")
        if not channels:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        logger.debug("soft token-anomaly signal(s) (action %s): %s", action.id, channels)
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.anomalous_token_pattern],
            explanation=(
                "Action carries probabilistic out-of-distribution token signals "
                "(e.g. homoglyph confusables or under-trained token fragments); "
                "authentication required before proceeding."
            ),
        )
