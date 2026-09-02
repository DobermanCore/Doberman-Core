"""C15 v1 — the offline judge-agreement bench (issue: is the judge worth wiring in?).

Replays `doberman.judge.HaikuJudgeAdjudicator` over the labeled
`tests/corpus/detection_corpus.jsonl` and reports, per `kind`, whether the
judge's recommendation agrees with the deterministic `ObjectiveGuardrail`'s
verdict direction (PASS vs. non-PASS), plus two specific numbers: the judge's
own false-raise rate on benign rows, and — the actual lift number — how often
it would raise on an attack row the rules missed (verdict PASS).

NOT wired into `tests.benchmarks.run` or `BUILTIN_ADAPTERS`: this is a
standalone, on-demand CLI, same "operator-supplied, opt-in" posture as the
AgentDojo suite, gated on an API key rather than an installed package.
`main()` requires ANTHROPIC_API_KEY + DOBERMAN_JUDGE_ENABLED=1 (the exact
gate `HaikuJudgeAdjudicator.adjudicate()` itself enforces) - with either
missing it prints a skip message and returns 0 without ever importing
`anthropic` or making a network call, so it stays CI-green with no
credentials (see tests/unit/test_judge.py).

`redacted_features()` carries no command, argument, path, or destination
text - only enum classes and counts. This bench therefore measures
class-level judgment only; it is structurally blind to natural-language
injection for the same reason the deterministic layer is, and never claims
otherwise (see docs/BENCHMARKS.md).
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

from doberman.engine.adjudicator import redacted_features
from doberman.engine.objective import ObjectiveGuardrail
from doberman.judge import HaikuJudgeAdjudicator, judge_enabled
from doberman.models import Verdict

from ..mapping import to_eval_context, to_security_object
from .corpus import CorpusRow, load_corpus


@dataclass(frozen=True)
class RowAgreement:
    """One row's rule verdict vs. the judge's recommendation (or abstain)."""

    row_id: str
    kind: str
    is_attack: bool
    rule_verdict: Verdict
    judge_verdict: Verdict | None  # None = the judge abstained


def replay(
    rows: list[CorpusRow], guardrail: ObjectiveGuardrail, judge: HaikuJudgeAdjudicator
) -> list[RowAgreement]:
    """Decide each row through the real objective guardrail, then ask the judge
    to recommend on the exact `redacted_features()` envelope that result
    produces - mirrors `corpus.py`'s `evaluate_corpus` for the mapping, but
    calls `ObjectiveGuardrail` directly rather than the full `decide()` (an
    adjudicator is only ever consulted against the objective result in
    production - see `decision_engine.py`'s `_shadow_for`)."""
    results: list[RowAgreement] = []
    for row in rows:
        action = row.to_candidate_action()
        security_object = to_security_object(f"judge:{row.id}", action)
        ctx = to_eval_context(action)
        rule_result = guardrail.evaluate(security_object, ctx)
        features = redacted_features(security_object, rule_result)
        recommendation = judge.adjudicate(features, rule_result)
        results.append(
            RowAgreement(
                row_id=row.id,
                kind=row.kind,
                is_attack=row.is_attack,
                rule_verdict=rule_result.verdict,
                judge_verdict=recommendation.verdict if recommendation else None,
            )
        )
    return results


def summarize(results: list[RowAgreement]) -> dict[str, Any]:
    """Per-`kind` agreement counts, benign false-raise rate, and the lift
    number (attack rows the rule missed that the judge would have raised)."""
    by_family: dict[str, dict[str, int]] = {}
    benign_would_raise = 0
    benign_total = 0
    lift_hits = 0
    rule_missed_total = 0
    abstained = 0

    for r in results:
        fam = by_family.setdefault(r.kind, {"n": 0, "agree": 0, "disagree": 0, "abstain": 0})
        fam["n"] += 1
        if r.judge_verdict is None:
            fam["abstain"] += 1
            abstained += 1
            continue
        rule_raised = r.rule_verdict is not Verdict.PASS
        judge_raised = r.judge_verdict is not Verdict.PASS
        if rule_raised == judge_raised:
            fam["agree"] += 1
        else:
            fam["disagree"] += 1
        if not r.is_attack:
            benign_total += 1
            if judge_raised:
                benign_would_raise += 1
        if r.is_attack and not rule_raised:
            rule_missed_total += 1
            if judge_raised:
                lift_hits += 1

    return {
        "n_rows": len(results),
        "n_abstained": abstained,
        "by_family": by_family,
        "benign_total": benign_total,
        "benign_would_raise": benign_would_raise,
        "benign_false_raise_rate": (benign_would_raise / benign_total if benign_total else None),
        "rule_missed_total": rule_missed_total,
        "lift_hits": lift_hits,
        "lift_on_rules_missed": (lift_hits / rule_missed_total if rule_missed_total else None),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    if not judge_enabled():
        print(
            "judge_agreement: ANTHROPIC_API_KEY / DOBERMAN_JUDGE_ENABLED not set "
            "(or `anthropic` not installed) - skipping. No live network call was made."
        )
        return 0
    rows = load_corpus()
    guardrail = ObjectiveGuardrail()
    judge = HaikuJudgeAdjudicator()
    results = replay(rows, guardrail, judge)
    report = summarize(results)
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
