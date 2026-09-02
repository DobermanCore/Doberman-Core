"""A constrained, BYO-model shadow-adjudicator implementation (C6 spec, v1).

Implements the C6 contract from
``doberman-vault/Plans/2026-08-03-defenseclaw-derived-security-candidates-c1-c8-spec.md``
(lines 130-155): a per-category two-boolean (``unambiguous``, ``high_impact``)
judge output, mapped **deterministically in code** — never free text — to risk
(TT->CRITICAL, TF->HIGH, FT->MEDIUM, FF->LOW), and raise-only relative to the
deterministic result it shadows. v1 (this task) is SHADOW-ONLY and has NO
production caller.

OFFLINE / MEASUREMENT-ONLY (ADR 0028, ADR 0029): :class:`HaikuJudgeAdjudicator`
implements the :class:`doberman.engine.adjudicator.Adjudicator` Protocol and is
structurally usable as a shadow-seam plugin, but nothing in core wires it into
``decide()`` today — that is a separate, ADR-gated slice
(``doberman.engine.registry.discover_adjudicators`` has zero production callers).
The only consumer in this repo is the offline bench,
``tests.benchmarks.suites.judge_agreement``, which replays it over
``tests/corpus/detection_corpus.jsonl`` to measure whether an LLM judge adds any
lift over the deterministic rules on the class-only
:func:`doberman.engine.adjudicator.redacted_features` envelope.

Mirrors ``doberman.explain``'s proven three-way opt-in gate (``anthropic``
installed AND ``ANTHROPIC_API_KEY`` set AND an explicit env flag) and its lazy
``import anthropic`` (only reached after the gate passes, so the optional
``[judge]`` extra is completely inert with nothing set).

SECURITY: the request payload sent to the model is exactly the caller-supplied
``features`` mapping (a :func:`redacted_features` output), JSON-encoded — this
module never receives or forwards a ``SecurityObject``, a raw argument, or the
``current`` result's ``explanation``. Any parse failure (missing key, wrong
type, non-JSON, an exception, a timeout) makes ``adjudicate`` return ``None`` —
it must never raise into a caller and never emit a partial/guessed
``GuardrailResult``.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from collections.abc import Mapping
from typing import Any

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict

logger = logging.getLogger("doberman.judge")

_JUDGE_MODEL = "claude-haiku-4-5"
_JUDGE_MAX_TOKENS = 200
_JUDGE_TIMEOUT_S = 1.5

_JUDGE_SYSTEM_PROMPT = (
    "You are a narrow security classifier. You are given a REDACTED summary of "
    "one tool-call action: enum classes, reason codes, and counts only - never "
    "a path, command, argument, or secret. Reply with ONLY a single JSON object "
    'with exactly two boolean fields: "unambiguous" (true if the action\'s '
    "intent is clearly determinable from these classes alone) and "
    '"high_impact" (true if, assuming malicious intent, this action could '
    "cause significant harm). No prose, no markdown, no other fields."
)


def _judge_enabled() -> bool:
    """The three-way opt-in gate: installed + API key + explicit env flag."""
    if importlib.util.find_spec("anthropic") is None:
        return False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    return os.environ.get("DOBERMAN_JUDGE_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def judge_enabled() -> bool:
    """Public gate check - lets a caller (the offline bench) decide up front
    whether to even attempt a replay, without duplicating the gate logic."""
    return _judge_enabled()


def _recommend(unambiguous: bool, high_impact: bool, current: GuardrailResult) -> GuardrailResult:
    """Deterministic, EXHAUSTIVE two-boolean -> risk mapping, raise-only
    against ``current`` (C6 spec:
    ``doberman-vault/Plans/2026-08-03-defenseclaw-derived-security-candidates-c1-c8-spec.md``,
    lines 139/151). Every one of the four ``(unambiguous, high_impact)``
    pairs maps to a risk level — the judge never emits free-text severity and
    never abstains on a valid boolean pair (abstention, ``None``, is reserved
    for unavailability / gate-off / malformed model output — Task 2):

        (True,  True)  -> Risk.critical
        (True,  False) -> Risk.high
        (False, True)  -> Risk.medium
        (False, False) -> Risk.low

    RAISE-ONLY: the returned risk is ``max(current.risk, mapped_risk)``; the
    returned verdict is ``max(current.verdict, Verdict.AUTH)`` when the
    mapped risk is high/critical, else exactly ``current.verdict`` — neither
    axis is ever lower than ``current``'s. No new ``ReasonCode`` is added for
    this slice (out of scope): when the mapping actually raises something
    above ``current`` (either axis moved), the result carries
    ``ReasonCode.unclassified_action`` as the closest existing generic code
    for "a second opinion flagged this without a more specific built-in
    reason"; when nothing raises, ``current``'s own reason codes and
    explanation are carried through unchanged rather than replaced.
    """
    if unambiguous and high_impact:
        mapped_risk = Risk.critical
    elif unambiguous:
        mapped_risk = Risk.high
    elif high_impact:
        mapped_risk = Risk.medium
    else:
        mapped_risk = Risk.low

    result_risk = max_risk(current.risk, mapped_risk)
    result_verdict = (
        max_verdict(current.verdict, Verdict.AUTH)
        if mapped_risk in (Risk.high, Risk.critical)
        else current.verdict
    )

    if result_risk == current.risk and result_verdict == current.verdict:
        return current.model_copy(deep=True)
    explanation = "shadow: judge read this action as {} and {}".format(
        "unambiguous" if unambiguous else "ambiguous",
        "high-impact" if high_impact else "low-impact",
    )
    return GuardrailResult(
        verdict=result_verdict,
        risk=result_risk,
        reason_codes=[ReasonCode.unclassified_action],
        explanation=explanation,
    )


class HaikuJudgeAdjudicator:
    """Structural ``Adjudicator`` implementation backed by Claude Haiku.

    SHADOW-ONLY, OFFLINE-ONLY (see module docstring). ``adjudicate`` never
    raises into a caller. Network call handling (lazy import, hard timeout,
    response parsing) is added in the next task; for now the gate + Protocol
    shape land first so they can be tested in isolation.
    """

    def adjudicate(
        self, features: Mapping[str, Any], current: GuardrailResult
    ) -> GuardrailResult | None:
        if not _judge_enabled():
            return None
        raise NotImplementedError  # completed in Task 2
