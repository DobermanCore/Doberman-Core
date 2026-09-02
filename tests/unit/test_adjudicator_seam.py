"""Adaptive-precision Phase 0 — the SHADOW-ONLY adjudication seam.

Every test here defends one security guarantee: an adjudicator may *observe* a
decision (on redacted features only) and record what it WOULD recommend, but it
can NEVER change ``final_verdict``/``final_risk``. The seam is fail-closed
(errors ignored), floor-untouchable (never consulted for a non-AUTH decision),
and redaction-safe (no raw secret/path/destination reaches the adjudicator).
"""

from datetime import datetime, timezone

import pytest

from doberman.engine import registry
from doberman.engine.adjudicator import (
    Adjudicator,
    LocalReferenceAdjudicator,
    redacted_features,
    run_shadow_adjudication,
)
from doberman.engine.decision_engine import decide
from doberman.models import (
    ActionType,
    Algebra,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.storage.db import open_db
from doberman.storage.log import record_shadow

CTX = EvalContext()
SECRET = "AKIA" + "IOSFODNN7EXAMPLE"  # synthetic AWS-shaped key, never a real one
RAW_PATH = "/home/user/project/.env.production"

# --- guardrail stubs --------------------------------------------------------


class Static:
    """A guardrail returning a fixed result (or raising, for the error paths)."""

    def __init__(self, outcome: GuardrailResult | Exception) -> None:
        self.outcome = outcome

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _r(verdict: Verdict, risk: Risk = Risk.medium) -> GuardrailResult:
    if verdict is Verdict.PASS:
        return GuardrailResult(verdict=verdict, risk=risk)
    return GuardrailResult(
        verdict=verdict,
        risk=risk,
        reason_codes=[ReasonCode.unknown_tool],
        explanation=f"{verdict}.",
    )


PASS_OBJ = Static(_r(Verdict.PASS))
AUTH_SUBJ = Static(_r(Verdict.AUTH))  # objective PASS + this → combined AUTH


def make_action(**over) -> SecurityObject:
    base = dict(
        id="adj-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/auth/session.ts",
        target_path_class="backend/auth/*.ts",
    )
    base.update(over)
    return SecurityObject(**base)


# --- adjudicator stubs ------------------------------------------------------


class AlwaysPass:
    def adjudicate(self, features, current):
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low, explanation="shadow benign")


class AlwaysBlock:
    def adjudicate(self, features, current):
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.unusual_for_deployment],
            explanation="shadow: anomalous",
        )


class Raising:
    def adjudicate(self, features, current):
        raise RuntimeError("adjudicator exploded")


class Garbage:
    def adjudicate(self, features, current):
        return "not-a-guardrail-result"


class Spy:
    def __init__(self) -> None:
        self.seen = None

    def adjudicate(self, features, current):
        self.seen = features
        return None


# --- 1. backward-compat -----------------------------------------------------


def test_backward_compat_no_adjudicators_arg_unchanged():
    # AUTH-producing decision, called the classic 4-arg way: shadow must be None
    # and the verdict identical to today.
    decision = decide(make_action(), PASS_OBJ, AUTH_SUBJ, CTX)
    assert decision.final_verdict is Verdict.AUTH
    assert decision.shadow is None
    # A PASS decision likewise carries no shadow.
    pass_decision = decide(make_action(), PASS_OBJ, Static(_r(Verdict.PASS)), CTX)
    assert pass_decision.final_verdict is Verdict.PASS
    assert pass_decision.shadow is None


# --- 2. shadow-only (the core guarantee) ------------------------------------


def test_shadow_pass_recommendation_never_moves_live_auth_verdict():
    decision = decide(make_action(), PASS_OBJ, AUTH_SUBJ, CTX, adjudicators=[AlwaysPass()])
    # Live verdict did NOT move — still AUTH.
    assert decision.final_verdict is Verdict.AUTH
    assert decision.final_risk is Risk.medium
    # The shadow annotation records what the adjudicator WOULD do.
    assert decision.shadow is not None
    assert decision.shadow.verdict is Verdict.PASS


# --- 3. fail-closed ---------------------------------------------------------


def test_raising_adjudicator_is_isolated_and_leaves_shadow_none():
    decision = decide(make_action(), PASS_OBJ, AUTH_SUBJ, CTX, adjudicators=[Raising()])
    assert decision.final_verdict is Verdict.AUTH  # unchanged
    assert decision.shadow is None  # error → ignored


def test_garbage_adjudicator_return_is_skipped():
    decision = decide(make_action(), PASS_OBJ, AUTH_SUBJ, CTX, adjudicators=[Garbage()])
    assert decision.final_verdict is Verdict.AUTH
    assert decision.shadow is None


# --- 4. floor-untouchable ---------------------------------------------------


def test_objective_block_floor_never_consults_adjudicator():
    # Objective BLOCK short-circuits: the adjudicator is not even looked at.
    decision = decide(
        make_action(), Static(_r(Verdict.BLOCK)), AUTH_SUBJ, CTX, adjudicators=[AlwaysPass()]
    )
    assert decision.final_verdict is Verdict.BLOCK
    assert decision.shadow is None


def test_shadow_block_recommendation_never_raises_the_live_auth_verdict():
    # Shadow-only in BOTH directions: even a BLOCK recommendation cannot raise
    # the live verdict in Phase 0.
    decision = decide(make_action(), PASS_OBJ, AUTH_SUBJ, CTX, adjudicators=[AlwaysBlock()])
    assert decision.final_verdict is Verdict.AUTH  # not raised to BLOCK
    assert decision.shadow is not None
    assert decision.shadow.verdict is Verdict.BLOCK


def test_pass_decision_never_consults_adjudicator():
    decision = decide(
        make_action(), PASS_OBJ, Static(_r(Verdict.PASS)), CTX, adjudicators=[AlwaysPass()]
    )
    assert decision.final_verdict is Verdict.PASS
    assert decision.shadow is None


# --- 5. redaction (critical) ------------------------------------------------


def test_adjudicator_never_sees_raw_secret_path_or_destination():
    spy = Spy()
    action = make_action(
        external_destination="https://evil.example.com/collect",
        payload_fingerprints=["hmac-abc123"],
        raw_args_redacted={"body": SECRET, "path": RAW_PATH},
        metadata={"raw_arguments": {"token": SECRET, "path": RAW_PATH}},
    )
    decision = decide(action, PASS_OBJ, AUTH_SUBJ, CTX, adjudicators=[spy])
    assert decision.final_verdict is Verdict.AUTH
    features = spy.seen
    assert features is not None
    text = repr(features)
    # The synthetic secret, the raw path, and the raw destination are all absent.
    assert SECRET not in text
    assert RAW_PATH not in text
    assert "evil.example.com" not in text
    # No raw-argument channels leak through as keys.
    assert "raw_arguments" not in features
    assert "raw_args_redacted" not in features
    assert "external_destination" not in features
    assert "explanation" not in features
    # Only the safe surface is present.
    assert features["has_external_destination"] is True
    assert features["fingerprint_count"] == 1
    assert features["target_path_class"] == "backend/auth/*.ts"


def test_redacted_features_allowlist_is_exactly_the_safe_keys():
    action = make_action(
        external_destination="https://x.example",
        payload_fingerprints=["fp1", "fp2"],
        raw_args_redacted={"secret": SECRET},
    )
    current = _r(Verdict.AUTH)
    features = redacted_features(action, current)
    assert set(features) == {
        "action_type",
        "tool_name",
        "target_path_class",
        "risk",
        "verdict",
        "reason_codes",
        "algebra",
        "has_external_destination",
        "fingerprint_count",
    }
    assert set(features["algebra"]) == {
        "capability",
        "target_class",
        "destination_class",
        "blast_radius",
        "provenance",
        "classification_confidence",
    }
    assert features["fingerprint_count"] == 2
    assert features["has_external_destination"] is True
    assert SECRET not in repr(features)


# --- 6. Decision validator intact -------------------------------------------


def test_decision_with_shadow_still_honors_final_never_weaker_than_objective():
    obj = _r(Verdict.AUTH)
    # A valid Decision with a PASS shadow on an AUTH decision constructs fine.
    good = Decision(
        action_id="d1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=obj,
        reason_codes=[ReasonCode.unknown_tool],
        explanation="auth.",
        decided_at=datetime.now(timezone.utc),
        shadow=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
    )
    assert good.shadow is not None and good.shadow.verdict is Verdict.PASS
    # Shadow does NOT disable the raise-only invariant: a final weaker than the
    # objective still fails, even with a shadow attached.
    with pytest.raises(ValueError, match="weaker than the objective"):
        Decision(
            action_id="d2",
            final_verdict=Verdict.PASS,
            final_risk=Risk.low,
            objective=GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.high,
                reason_codes=[ReasonCode.protected_path_blocked],
                explanation="blocked.",
            ),
            decided_at=datetime.now(timezone.utc),
            shadow=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        )


# --- 7. registry ------------------------------------------------------------


def test_discover_adjudicators_empty_with_nothing_installed():
    assert registry.discover_adjudicators() == []


def test_discover_adjudicators_finds_shaped_and_skips_others(monkeypatch, enable_plugins):
    class _FakeEP:
        def __init__(self, name, loader):
            self.name = name
            self._loader = loader

        def load(self):
            return self._loader()

    class _FakeEPs:
        def __init__(self, eps):
            self._eps = eps

        def select(self, *, group):
            return list(self._eps) if group == registry.ADJUDICATOR_GROUP else []

    instance = LocalReferenceAdjudicator()
    table = _FakeEPs([_FakeEP("good", lambda: instance), _FakeEP("bad", lambda: 42)])
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    enable_plugins("good", "bad")
    found = registry.discover_adjudicators()
    assert found == [instance]  # adjudicator-shaped kept; the int skipped


# --- LocalReferenceAdjudicator (the built-in reference) ---------------------


def test_local_reference_recommends_pass_only_on_benign_auth():
    ref = LocalReferenceAdjudicator()
    benign = redacted_features(
        make_action(
            algebra=Algebra(target_class=TargetClass.public, classification_confidence=0.9)
        ),
        _r(Verdict.AUTH),
    )
    assert ref.adjudicate(benign, _r(Verdict.AUTH)).verdict is Verdict.PASS
    # Abstains when it has an external destination, low confidence, or sensitive class.
    external = redacted_features(
        make_action(
            algebra=Algebra(target_class=TargetClass.public, classification_confidence=0.9),
            external_destination="https://x.example",
        ),
        _r(Verdict.AUTH),
    )
    assert ref.adjudicate(external, _r(Verdict.AUTH)) is None
    low_conf = redacted_features(
        make_action(
            algebra=Algebra(target_class=TargetClass.public, classification_confidence=0.5)
        ),
        _r(Verdict.AUTH),
    )
    assert ref.adjudicate(low_conf, _r(Verdict.AUTH)) is None


def test_run_shadow_adjudication_never_raises_and_returns_first():
    action = make_action()
    # Empty → None; raising first, then a real recommendation → returns the real one.
    assert run_shadow_adjudication([], action, _r(Verdict.AUTH)) is None
    rec = run_shadow_adjudication([Raising(), AlwaysPass()], action, _r(Verdict.AUTH))
    assert rec is not None and rec.verdict is Verdict.PASS


def test_stub_adjudicators_satisfy_the_protocol():
    assert isinstance(AlwaysPass(), Adjudicator)
    assert isinstance(LocalReferenceAdjudicator(), Adjudicator)
    assert not isinstance(object(), Adjudicator)


# --- 8. record_shadow (best-effort writer) ----------------------------------


def _shadow_decision() -> Decision:
    return Decision(
        action_id="adj-shadow-1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=_r(Verdict.AUTH),
        reason_codes=[ReasonCode.unknown_tool],
        explanation="auth.",
        decided_at=datetime.now(timezone.utc),
        shadow=GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.unusual_for_deployment],
            explanation="shadow: anomalous",
        ),
    )


async def test_record_shadow_writes_a_row_when_shadow_present(tmp_path):
    decision = _shadow_decision()
    await record_shadow(decision, make_action(), repo_root=str(tmp_path), entity_id="ent-hmac")
    async with open_db(str(tmp_path)) as conn:
        async with conn.execute(
            "SELECT action_id, live_verdict, shadow_verdict, shadow_reason_codes, entity_id "
            "FROM shadow_adjudications"
        ) as cur:
            rows = await cur.fetchall()
    assert len(rows) == 1
    action_id, live_v, shadow_v, codes, entity = rows[0]
    assert action_id == "adj-shadow-1"
    assert live_v == "AUTH"
    assert shadow_v == "BLOCK"
    assert codes == '["unusual_for_deployment"]'
    assert entity == "ent-hmac"


async def test_record_shadow_writes_nothing_when_shadow_absent(tmp_path):
    decision = Decision(
        action_id="no-shadow",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=_r(Verdict.PASS, Risk.low),
        decided_at=datetime.now(timezone.utc),
    )
    await record_shadow(decision, make_action(), repo_root=str(tmp_path))
    async with open_db(str(tmp_path)) as conn:
        async with conn.execute("SELECT COUNT(*) FROM shadow_adjudications") as cur:
            count = (await cur.fetchone())[0]
    assert count == 0


async def test_record_shadow_is_best_effort_on_bad_repo_root(tmp_path):
    # repo_root points at a FILE, so opening the DB under it fails — record_shadow
    # must swallow the error and never raise into the (already-made) decision.
    bad = tmp_path / "not_a_dir"
    bad.write_text("x")
    await record_shadow(_shadow_decision(), make_action(), repo_root=str(bad))  # must not raise
