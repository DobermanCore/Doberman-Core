"""Slice TG3.1 — Tier 1 heuristic step-up (AUTH-only, BLOCK-incapable).

The deliberately looser recall net. Where Tier 0 is small and provable, Tier 1
casts wider but its only available verdict is **AUTH** — a false positive costs
one human tap, never a denied prompt. It is **structurally incapable of BLOCK**:
:func:`_flag` only ever produces AUTH, and the engine clamps any stray BLOCK.

Classes:

* ``embedded_instruction`` — agent-directed imperatives inside *pasted /
  tool-fetched* text (a document telling the agent what to do). Requires
  agent-directedness, not mere imperative mood, so tutorials don't trip it; and
  only fires for untrusted origins (a user directing the agent is the normal case).
* ``persona_override`` — "from now on you are …" / "pretend to be …" below Tier 0
  authority-override confidence.
* ``obfuscated_content`` — sub-threshold encoded runs, zero-width characters, and
  long hex-escape sequences.
* ``urgency_secrecy_framing`` — "don't tell the user", "do this quietly".
* ``stylometric_outlier`` (TG3.2) — the co-occurrence gate: steps up ONLY when
  the turn's style is an extreme outlier for this entity (hook-precomputed
  empirical-CDF p-value ≤ :data:`STYLE_EXTREME_P`) **and** the apparent intent
  touches a sensitive capability (credential / destructive / external-send).
  Style-weird alone is **tagged, never gated** — the tag rides as a reason code
  on a PASS result (people type differently tired/mobile/pasting; a device or
  language switch is baseline drift, not an attack). With no precomputed
  p-value (cold start, immature baseline, storage failure) the gate abstains.
"""

import math
import re

from doberman.engine.decision_engine import combine
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    TurnObject,
    Verdict,
)
from doberman.turngate.raw import RawSegment, raw_turn_from_ctx, style_pvalue_from_ctx

_MAX_SCAN_CHARS = 200_000
_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

#: A style p-value at or below this is an *extreme* outlier for the entity.
#: With the empirical (add-one) CDF this is roughly the rarest 1-in-50 turns —
#: and even then the gate fires only on sensitive apparent intent.
STYLE_EXTREME_P = 0.02

#: Agent-directed phrasing (not mere imperative mood) — embedded-instruction tell.
_AGENT_DIRECTED = re.compile(
    r"\b(you must|you should|you are required to|you will now|you need to|from now on,? you|"
    r"the assistant (must|should|will)|the ai (must|should|will)|assistant:|system:|"
    r"note (for|to) the (ai|assistant|model|llm)|ignore the user|do not tell the user|"
    r"instead of (helping|the user))\b",
    re.IGNORECASE,
)

_PERSONA_OVERRIDE = re.compile(
    r"\b(pretend (to be|you are|that you are)|you are now (a|an)\b|roleplay as|role-play as|"
    r"from now on you are|act like you are|you are no longer)\b",
    re.IGNORECASE,
)

_URGENCY_SECRECY = re.compile(
    r"\b(don'?t tell|do not tell|without telling|keep (this|it) (secret|quiet|between us)|"
    r"do (this|it) quietly|don'?t mention|do not mention|without (the user|anyone) knowing|"
    r"behind (the user'?s|their) back|don'?t let the user|so the user (won'?t|doesn'?t) (know|notice))\b",
    re.IGNORECASE,
)

#: A medium, token-shaped run below the Tier 0 carrier length (20–39 chars).
_MEDIUM_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{20,39}")
#: Zero-width / invisible code points used to smuggle hidden instructions.
_ZERO_WIDTH = re.compile("[​‌‍﻿⁠]")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_OBFUSCATION_ENTROPY = 3.7


def _shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _flag(reason: ReasonCode, label: str) -> GuardrailResult:
    """Build a Tier 1 result. AUTH-only by construction — never BLOCK."""
    return GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[reason],
        explanation=f"Turn flagged ({label}) — approve this turn before it reaches the model?",
    )


def _looks_obfuscated(text: str) -> bool:
    if _ZERO_WIDTH.search(text) or _HEX_ESCAPES.search(text):
        return True
    for token in _MEDIUM_TOKEN.findall(text):
        if any(ch.isdigit() for ch in token) and _shannon_entropy(token) >= _OBFUSCATION_ENTROPY:
            return True
    return False


def _stylometric_gate(turn: TurnObject, ctx: EvalContext) -> GuardrailResult:
    """The TG3.2 co-occurrence gate: extreme style outlier × sensitive intent.

    No precomputed p-value (cold start / immature baseline / failure) → abstain.
    Outlier without sensitive intent → **tag-and-pass**: a PASS result carrying
    ``stylometric_outlier`` as a reason code, which ``combine`` merges into the
    decision (visible in the audit log, and the TG3.3 handoff's raw material)
    without ever gating on style alone.
    """
    pvalue = style_pvalue_from_ctx(ctx)
    if pvalue is None or pvalue > STYLE_EXTREME_P:
        return _PASS
    if turn.apparent_intent.is_sensitive:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.stylometric_outlier],
            explanation=(
                "Prompt style is an extreme outlier for this entity AND the turn "
                f"appears to involve {turn.apparent_intent.value} — approve this "
                "turn before it reaches the model?"
            ),
        )
    return GuardrailResult(
        verdict=Verdict.PASS,
        risk=Risk.low,
        reason_codes=[ReasonCode.stylometric_outlier],
    )


def _scan_segment(segment: RawSegment) -> GuardrailResult:
    text = segment.text[:_MAX_SCAN_CHARS]
    worst = _PASS
    # Embedded instructions only matter from untrusted origins — a user directing
    # the agent (typed) is normal, a *document* directing it is the tell.
    if segment.origin.is_untrusted and _AGENT_DIRECTED.search(text):
        worst = combine(
            worst, _flag(ReasonCode.embedded_instruction, "embedded agent-directed instruction")
        )
    if _PERSONA_OVERRIDE.search(text):
        worst = combine(worst, _flag(ReasonCode.persona_override, "persona / role override"))
    if _URGENCY_SECRECY.search(text):
        worst = combine(
            worst, _flag(ReasonCode.urgency_secrecy_framing, "urgency + secrecy framing")
        )
    if _looks_obfuscated(text):
        worst = combine(
            worst,
            _flag(ReasonCode.obfuscated_content, "obfuscated / sub-threshold encoded content"),
        )
    return worst


class Tier1HeuristicGuardrail:
    """The AUTH-only Tier 1 turn guardrail (the recall layer).

    Runs the stylometric co-occurrence gate (off the hook-precomputed p-value in
    the context — no raw text needed), then scans each raw segment, reducing
    results raise-only; the only verdicts it can ever produce are PASS and AUTH.
    The text scan abstains (PASS) with no in-memory raw turn.
    """

    def evaluate(self, turn: TurnObject, ctx: EvalContext) -> GuardrailResult:
        worst = _stylometric_gate(turn, ctx)
        raw = raw_turn_from_ctx(ctx)
        if raw is None:
            return worst
        for segment in raw.segments:
            worst = combine(worst, _scan_segment(segment))
        # Structural guarantee: Tier 1 never hard-blocks (defensive — _flag only
        # makes AUTH, but a future edit must not silently gain BLOCK authority).
        if worst.verdict is Verdict.BLOCK:  # pragma: no cover — unreachable by construction
            return _flag(ReasonCode.turn_gate_error, "tier-1 clamp")
        return worst
