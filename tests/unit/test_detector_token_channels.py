"""OOD token defense — subjective detector (TokenChannelDetector).

Covers: soft signals (homoglyph confusable, glitch fragment) raise to AUTH,
raise-only; benign → PASS; a hard-only channel is left to the objective rule
(detector abstains on it); the opt-in perplexity_fn injection escalates and a
raising scorer is isolated; a per-model glitch list is honored; and the detector
is wired into SubjectiveGuardrail as a built-in (escalates a soft-signal action).
"""

from datetime import datetime, timezone

from doberman.engine.detectors.token_channels import TokenChannelDetector
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)
from doberman.tokens import GlitchFragmentStore

CYRILLIC_A = chr(0x0430)


def _tag_smuggle(visible: str, hidden: str) -> str:
    return visible + "".join(chr(0xE0000 + ord(c)) for c in hidden)


def _action(*, tool="t", target=None, dest=None):
    return SecurityObject(
        id="dt-1",
        ts=datetime(2026, 6, 12, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name=tool,
        target=target,
        external_destination=dest,
    )


def _ctx(**raw_arguments):
    return EvalContext(metadata={"raw_arguments": raw_arguments})


def test_homoglyph_confusable_raises_to_auth():
    det = TokenChannelDetector()
    result = det.evaluate(_action(target="x.ts"), _ctx(content="visit p" + CYRILLIC_A + "ypal"))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.anomalous_token_pattern in result.reason_codes


def test_glitch_fragment_raises_to_auth():
    det = TokenChannelDetector()
    result = det.evaluate(_action(target="x.ts"), _ctx(content="print SolidGoldMagikarp"))
    assert result.verdict is Verdict.AUTH


def test_benign_passes():
    det = TokenChannelDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(content="const y = 2")).verdict is Verdict.PASS


def test_hard_only_channel_is_left_to_objective_rule():
    # A pure tag-block payload is a HARD channel with no soft signal — the
    # detector abstains (the objective rule owns the hard block / step-up).
    det = TokenChannelDetector()
    result = det.evaluate(_action(target="x.ts"), _ctx(content=_tag_smuggle("ok", "secret")))
    assert result.verdict is Verdict.PASS


def test_injected_perplexity_fn_escalates():
    det = TokenChannelDetector(perplexity_fn=lambda _t: 0.9, perplexity_threshold=0.5)
    # Even benign text escalates when the injected scorer reports high perplexity.
    result = det.evaluate(_action(target="x.ts"), _ctx(content="totally normal text"))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.anomalous_token_pattern in result.reason_codes


def test_injected_perplexity_fn_below_threshold_passes():
    det = TokenChannelDetector(perplexity_fn=lambda _t: 0.1, perplexity_threshold=0.5)
    assert det.evaluate(_action(target="x.ts"), _ctx(content="hi")).verdict is Verdict.PASS


def test_raising_perplexity_fn_is_isolated_not_fatal():
    def boom(_text):
        raise RuntimeError("model exploded")

    det = TokenChannelDetector(perplexity_fn=boom, perplexity_threshold=0.5)
    # The injected scorer's failure must not crash the detector or block; the
    # deterministic channels remain the load-bearing defense.
    assert det.evaluate(_action(target="x.ts"), _ctx(content="hi")).verdict is Verdict.PASS


def test_per_model_glitch_list_is_honored():
    store = GlitchFragmentStore(extra=[" zzGlitchToken"])
    det = TokenChannelDetector(glitch_store=store)
    result = det.evaluate(_action(target="x.ts"), _ctx(content="here is zzGlitchToken"))
    assert result.verdict is Verdict.AUTH


def test_builtin_detector_is_wired_into_subjective_guardrail():
    g = SubjectiveGuardrail(load_plugins=False)  # built-ins still load
    ctx = EvalContext(
        metadata={"abnormality": 0.0, "raw_arguments": {"content": "p" + CYRILLIC_A + "ypal"}}
    )
    assert g.evaluate(_action(target="login.ts"), ctx).verdict is Verdict.AUTH


def test_subjective_guardrail_can_disable_builtins():
    g = SubjectiveGuardrail(load_plugins=False, load_builtins=False)
    ctx = EvalContext(
        metadata={"abnormality": 0.0, "raw_arguments": {"content": "p" + CYRILLIC_A + "ypal"}}
    )
    # With built-ins off and a calm baseline, the same action passes.
    assert g.evaluate(_action(target="login.ts"), ctx).verdict is Verdict.PASS
