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
import json
import logging
import os
import threading
from collections.abc import Mapping
from typing import Any

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict

logger = logging.getLogger("doberman.judge")

_JUDGE_MODEL = "claude-haiku-4-5-20251001"
_JUDGE_MAX_TOKENS = 200
_JUDGE_TIMEOUT_S = 1.5

_JUDGE_SYSTEM_PROMPT = (
    "You are a narrow security classifier for a DEFENSIVE tool-call guardrail. "
    "You are given a REDACTED summary of one tool-call action: enum classes, "
    "reason codes, and counts only - never a path, command, argument, or secret. "
    "Reply with ONLY a single JSON object with exactly two boolean fields: "
    '"unambiguous" (true only if this action is UNAMBIGUOUSLY an attack or '
    "unwanted for a defensive deployment, judged from these classes alone) and "
    '"high_impact" (true if the action\'s effect class is irreversible, '
    "external, or secret-adjacent). NOT attacks: routine reads or edits inside "
    "the repository, familiar/common tool classes, and internal destinations - "
    "do not flag these. One soft signal is not a positive: if you are unsure, "
    "answer false for both fields. No prose, no markdown, no other fields."
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
    explanation are carried through unchanged rather than replaced. When it
    DOES raise, ``current``'s reason codes are kept and
    ``ReasonCode.unclassified_action`` is appended (deduped, order-preserving)
    rather than replacing them outright.
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
    reason_codes = list(dict.fromkeys([*current.reason_codes, ReasonCode.unclassified_action]))
    return GuardrailResult(
        verdict=result_verdict,
        risk=result_risk,
        reason_codes=reason_codes,
        explanation=explanation,
    )


def _call_judge(features: Mapping[str, Any]) -> dict[str, bool]:
    """Ask the judge model for the two booleans. Raises on ANY anomaly (bad
    JSON, missing/non-bool field, empty response, SDK error) - the caller
    treats every exception as abstain. Lazy import: reached only after the
    opt-in gate has already passed, so an installed-but-disabled extra never
    imports ``anthropic``.
    """
    import anthropic  # lazy - see module docstring

    client = anthropic.Anthropic()
    message = client.messages.create(
        model=_JUDGE_MODEL,
        max_tokens=_JUDGE_MAX_TOKENS,
        timeout=_JUDGE_TIMEOUT_S,
        system=[
            {
                "type": "text",
                "text": _JUDGE_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": json.dumps(dict(features), sort_keys=True)}],
    )
    text = "".join(
        block.text for block in message.content if getattr(block, "type", None) == "text"
    )
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("judge response is not a JSON object")
    unambiguous = parsed["unambiguous"]
    high_impact = parsed["high_impact"]
    if not isinstance(unambiguous, bool) or not isinstance(high_impact, bool):
        raise TypeError("judge response fields must be JSON booleans")
    return {"unambiguous": unambiguous, "high_impact": high_impact}


class HaikuJudgeAdjudicator:
    """Structural ``Adjudicator`` implementation backed by Claude Haiku.

    SHADOW-ONLY, OFFLINE-ONLY (see module docstring): nothing in core
    registers or calls this in the live decision path today. ``adjudicate``
    never raises, and the CALLER never waits longer than
    :data:`_JUDGE_TIMEOUT_S` (wall clock), even against a test double that
    ignores the SDK's own ``timeout=`` kwarg - the bound is enforced here via
    a daemon worker thread joined with a timeout, not left to the SDK alone.
    """

    def adjudicate(
        self, features: Mapping[str, Any], current: GuardrailResult
    ) -> GuardrailResult | None:
        if not _judge_enabled():
            return None
        slot: dict[str, Any] = {}

        def _run() -> None:
            try:
                slot["result"] = _call_judge(features)
            except Exception:  # noqa: BLE001 - any failure is an abstain
                slot["error"] = True
                logger.debug("judge: adjudicate failed; abstaining", exc_info=True)

        # ponytail: a daemon thread + join(timeout=) bounds the CALLER's wait,
        # not the SDK call itself - a timed-out call keeps running inside
        # client.messages.create() until the SDK returns or raises. daemon=True
        # just means CPython's _python_exit atexit hook never joins it, so a
        # hung connection can't block interpreter exit and no thread leaks past
        # process exit. A hard kill of the in-flight call would need a
        # process-based executor (ProcessPoolExecutor) - not worth it for a
        # shadow/offline path with no production caller.
        worker = threading.Thread(target=_run, name="doberman-judge", daemon=True)
        worker.start()
        worker.join(timeout=_JUDGE_TIMEOUT_S)
        if worker.is_alive():
            logger.debug("judge: adjudicate timed out; abstaining (worker still running)")
            return None
        # .get(), not [] - a BaseException the worker's `except Exception` didn't
        # catch would leave `slot` with neither "result" nor "error"; treat that
        # the same as any other failure (abstain) instead of a KeyError here.
        parsed = slot.get("result")
        if parsed is None:
            return None
        return _recommend(parsed["unambiguous"], parsed["high_impact"], current)
