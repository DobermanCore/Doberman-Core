"""Attack Success Rate (ASR) runner for the OOD / smuggled-token defense.

Runs the full corpus against the REAL TokenChannelRule + TokenChannelDetector
and produces a per-channel bypass-rate report.

REDACTION POLICY: The returned/printed report holds channel classes + counts
ONLY. The text field of each corpus item is NEVER logged, printed, or included
in any return value. Verdict objects and reason codes are metadata, never payload.

--- SOFT-CHANNEL ASR == 0.0: BASELINE, NOT ROBUSTNESS ---

The ``per_channel`` section of the report will show soft-channel ASR of 0.000
for known-signature channels (glitch_fragment, mixed_script_confusable,
whole_script_confusable, nfkc_delta).  This is a NO-REGRESSION BASELINE: the
corpus feeds the detector its own known signatures, so a tautological 0%
bypass is expected and correct.
It means the implementation is consistent, NOT that the defense is airtight.

The REAL adaptive red-team result is in the ``evasion`` section of the report:
those items use techniques that GENUINELY evade the deterministic detector.
The evasion ASR surfaces the documented deterministic-soft gap that the
enterprise perplexity detector (plan slice P2.4) is designed to close.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from doberman.engine.detectors.token_channels import TokenChannelDetector
from doberman.engine.rules.token_channels import TokenChannelRule
from doberman.models import ActionType, EvalContext, SecurityObject, Verdict

from .corpus import build_corpus

# Singletons — no side effects, safe to reuse
_RULE = TokenChannelRule()
_DETECTOR = TokenChannelDetector()


def _make_action(item_id: str) -> SecurityObject:
    """Build a SecurityObject with a local (non-external) destination.

    Using file_write so the rule's _has_external_destination() returns False,
    meaning a hard channel hit yields AUTH (not BLOCK). This is intentional:
    we test detection, not the BLOCK/AUTH split — the rule's verdict is AUTH
    either way when the channel is hard.

    For the purposes of ASR: any non-PASS verdict = CAUGHT.
    """
    return SecurityObject(
        id=item_id,
        ts=datetime(2026, 6, 14, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="write_file",
        target="output.txt",
        external_destination=None,
    )


def _make_ctx(text: str) -> EvalContext:
    """Build EvalContext with the attack text in raw_arguments (the real API path)."""
    return EvalContext(metadata={"raw_arguments": {"content": text}})


def _is_caught(rule_result: Any, det_result: Any) -> bool:
    """Return True if either the rule or detector raised above PASS."""
    return rule_result.verdict is not Verdict.PASS or det_result.verdict is not Verdict.PASS


def run_asr(seed: int = 1337) -> dict:
    """Run the red-team harness and return the ASR report.

    Returns a dict:
        {
            "per_channel": {
                "<channel_id>": {
                    "n":        int,
                    "caught":   int,
                    "bypassed": int,
                    "asr":      float,  # bypassed / n
                }
            },
            "evasion": {
                "<evasion_channel>": {
                    "n":        int,
                    "caught":   int,    # caught_by_deterministic (unexpected)
                    "bypassed": int,    # truly evaded (expected / documented gap)
                    "asr":      float,  # bypassed / n  (high = gap is real)
                }
            },
            "benign_fpr":   float,  # caught_benign / total_benign
            "totals": {
                "n":        int,
                "caught":   int,
                "bypassed": int,
            }
        }

    ``evasion`` items are reported SEPARATELY from ``per_channel`` because a high
    bypass rate in ``evasion`` is EXPECTED (it documents the gap), not a regression.
    A non-zero bypass rate in ``per_channel`` for hard channels IS a regression.

    The "text" field of corpus items is NEVER included in this return value.
    """
    corpus = build_corpus(seed=seed)

    # Accumulators: per channel, evasion, and benign
    per_channel: dict[str, dict[str, int]] = {}
    evasion: dict[str, dict[str, int]] = {}
    benign_total = 0
    benign_caught = 0
    total_n = 0
    total_caught = 0

    for item in corpus:
        channel = item["channel"]
        expected = item["expected"]
        text = item["text"]  # used only locally, never returned/logged

        action = _make_action(item["id"])
        ctx = _make_ctx(text)

        rule_result = _RULE.evaluate(action, ctx)
        det_result = _DETECTOR.evaluate(action, ctx)
        caught = _is_caught(rule_result, det_result)

        if expected == "benign":
            benign_total += 1
            if caught:
                benign_caught += 1
            # Do NOT count benign items in per-channel or totals
            continue

        if expected == "evasion":
            # Track evasion items separately — a high bypass rate here is
            # EXPECTED (documents the deterministic-soft gap), not a regression.
            if channel not in evasion:
                evasion[channel] = {"n": 0, "caught": 0, "bypassed": 0}
            evasion[channel]["n"] += 1
            if caught:
                evasion[channel]["caught"] += 1
            else:
                evasion[channel]["bypassed"] += 1
            # Do NOT count evasion items in per-channel or totals
            continue

        # For perplexity_only items: the deterministic scanner should NOT catch them.
        # We still record them under their channel to show ASR = 1.0 (all bypass).
        if channel not in per_channel:
            per_channel[channel] = {"n": 0, "caught": 0, "bypassed": 0}

        per_channel[channel]["n"] += 1
        total_n += 1
        if caught:
            per_channel[channel]["caught"] += 1
            total_caught += 1
        else:
            per_channel[channel]["bypassed"] += 1

    # Compute ASR per channel
    for stats in per_channel.values():
        n = stats["n"]
        stats["asr"] = stats["bypassed"] / n if n > 0 else 0.0

    # Compute ASR per evasion technique
    for stats in evasion.values():
        n = stats["n"]
        stats["asr"] = stats["bypassed"] / n if n > 0 else 0.0

    benign_fpr = benign_caught / benign_total if benign_total > 0 else 0.0

    return {
        "per_channel": per_channel,
        "evasion": evasion,
        "benign_fpr": benign_fpr,
        "totals": {
            "n": total_n,
            "caught": total_caught,
            "bypassed": total_n - total_caught,
        },
    }
