"""Decision transparency: turn a redacted decision-log row into a plain-language "why".

Two explanation modes, always with a safe default:

* :func:`template_explanation` - deterministic, offline, always available. Built from
  the redacted row alone (verdict, decided layer, reason codes) using the shared
  :class:`~doberman.models.ReasonCode` constants.
* :func:`_llm_explain` - an OPT-IN narrator (Claude Haiku) that rewords the same
  redacted metadata in plainer language. It never sees a raw path, argument, or
  secret, and it never influences the verdict - it explains a decision that has
  already been made.

Fail-safe by construction: LLM enrichment is only attempted when explicitly opted in
(``DOBERMAN_EXPLAIN_LLM`` + ``ANTHROPIC_API_KEY`` + ``anthropic`` installed), and any
failure (missing key, network error, timeout, bad response, whatever) falls back to
the template. This module never raises into a caller and never touches
``doberman.proxy`` (policy-core decoupling, see CLAUDE.md §9 / import-linter).
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os

from doberman.models import ReasonCode

logger = logging.getLogger("doberman.explain")

# Defensive allowlist: the ONLY columns of a `decisions` row that may ever reach the
# LLM. These are already redaction-safe (path CLASS only, HMAC fingerprints, enum
# values, ids) per doberman/storage/log.py's build_record(). Never widen this to a
# passthrough of arbitrary row keys.
REDACTED_FIELDS: tuple[str, ...] = (
    "ts",
    "action_id",
    "agent_role",
    "action_type",
    "target_path_class",
    "risk",
    "source_context",
    "final_verdict",
    "decided_layer",
    "reason_codes_json",
    "auth_required",
    "auth_result",
    "elevation_id",
    "entity_id",
    "session_id",
)

_LLM_MODEL = "claude-haiku-4-5-20251001"
_LLM_MAX_TOKENS = 300
_LLM_TIMEOUT_S = 10.0

_LLM_SYSTEM_PROMPT = (
    "You explain a security tool's ALREADY-MADE decision to a developer in plain "
    "language. You are given only redacted metadata - do not invent specifics you "
    "were not given, and never ask for more data."
)

# Human-readable descriptions for the ReasonCode constants (doberman/models.py).
# Anything not listed here (e.g. a future code) falls back to a humanized form of
# the code itself, so this dict never has to be kept perfectly in sync to be safe.
# Public (no leading underscore): doberman.dash.app reuses this exact dict to gloss
# reason codes with a title="..." tooltip client-side, rather than hand-duplicating
# a second copy of these descriptions in the served JS.
REASON_DESCRIPTIONS: dict[str, str] = {
    "normalization_failed": "the action could not be normalized into a well-formed request",
    "unknown_tool": "the tool was not recognized",
    "downstream_error": "the downstream service returned an error",
    "objective_guardrail_error": "the objective guardrail failed to evaluate cleanly",
    "subjective_guardrail_error": "the subjective guardrail failed to evaluate cleanly",
    "subjective_block_clamped": "a subjective-layer block was clamped to the objective floor",
    "secret_exfiltration": "the action appeared to send a known secret outbound",
    "sensitive_secret_access": "the action touched a file recognized as holding secrets",
    "possible_high_entropy_secret": "the payload looked like it might contain a high-entropy secret",
    "protected_path_blocked": "the target path is in a protected location",
    "sensitive_path_access": "the target path is sensitive",
    "destructive_command": "the command looked destructive (e.g. a recursive delete)",
    "bulk_operation": "the action affected an unusually large number of items at once",
    "opaque_command": "the command's effect could not be determined ahead of time",
    "unknown_external_destination": "the action targeted an external destination not on any allowlist",
    "encoded_exfiltration": "the payload looked like an encoded attempt to move data out",
    "rule_error": "a guardrail rule raised an error while evaluating",
    "role_blocked_target": "the agent's role is not permitted to touch this target",
    "role_out_of_scope": "the action is outside the agent role's declared scope",
    "policy_source_blocked": "the instruction's source is not permitted to trigger this action",
    "policy_source_sensitive": "the instruction's source is treated as sensitive",
    "unusual_for_workflow": "the action doesn't match the agent's usual behavior pattern",
    "unusual_for_deployment": "the action doesn't match this deployment's usual behavior pattern",
    "confidentiality_sensitive_destination": "the destination is confidentiality-sensitive",
    "irreversible_high_blast": "the action is hard to undo and would affect a lot if wrong",
    "lethal_trifecta": (
        "the action combines untrusted input, access to private data, and an external channel"
    ),
    "unclassified_action": "the action could not be classified by the subjective layer",
    "smuggled_token_channel": "the payload appeared to smuggle tokens through an unexpected channel",
    "anomalous_token_pattern": "the token pattern in the payload was anomalous",
    "multi_step_exfil": "this action is part of a multi-step pattern that looks like exfiltration",
    "confirmed_exfil": ("a secret read earlier in this session reappeared in an outbound payload"),
    "egress_route_divergence": (
        "this entity recently connected to a destination its static egress classification "
        "did not predict"
    ),
    "egress_broker_enforced": (
        "a proven egress broker attested this destination is allowlisted and will enforce it "
        "at the socket"
    ),
    "egress_blocked_by_mode": (
        "paranoid mode hard-blocks this destination because a proven egress broker will "
        "itself drop it at the socket"
    ),
    "anomalous_egress_velocity": (
        "this entity's recent egress connections show anomalous velocity (burst, volume, "
        "or fan-out)"
    ),
    "artifact_digest_mismatch": (
        "the fetched content's digest did not match its pinned expected digest"
    ),
    "proxy_handler_error": "an unexpected error escaped the proxy's tool-call handler",
    "environment_dump_command": (
        "the command reads or prints the process environment, a common carrier for secrets"
    ),
    "egress_requires_auth": "this destination requires authentication before the action can proceed",
    "tool_schema_changed": "the live tool's contract changed since it was first pinned",
    "pii_data_class_egress": (
        "the outbound payload contains checksum-valid personal or financial data bound for "
        "an external destination"
    ),
    "oversized_encoded_blob": (
        "the payload carries a large base64-encoded blob, a common shape for smuggling data out"
    ),
    "single_use_elevation_unclaimable": (
        "the one-time elevation covering this action was already spent or could not be claimed"
    ),
    "correlated_trifecta": (
        "this action, combined with earlier ones in the session, adds up to the "
        "lethal-trifecta pattern"
    ),
    "correlated_destructive_flow": (
        "this action, combined with earlier ones in the session, adds up to a destructive pattern"
    ),
    "turn_gate_error": "the pre-inference turn gate failed to evaluate cleanly",
    "instruction_nullification": (
        "the input matched an instruction-nullification pattern "
        '(e.g. "ignore your previous instructions")'
    ),
    "authority_override": (
        "the input matched an authority-override pattern (impersonation, mode-switch framing, "
        "or an ask to reveal the system prompt)"
    ),
    "secret_export": "the input asked for a credential, key, or token to be exported",
    "encoded_payload": "the input carried a long high-entropy encoded blob or a punycode host",
    "indirect_injection": (
        "the matched pattern was found in untrusted (pasted or tool-fetched) content, "
        "not the user's own words"
    ),
    "embedded_instruction": (
        "untrusted pasted or tool-fetched text contained an instruction directed at the agent"
    ),
    "persona_override": "the input tried to make the agent adopt a different persona or role",
    "obfuscated_content": (
        "the input contained sub-threshold encoded runs, zero-width characters, or long hex escapes"
    ),
    "urgency_secrecy_framing": (
        'the input used urgency or secrecy framing (e.g. "do this quietly, don\'t tell the user")'
    ),
    "stylometric_outlier": "the turn's writing style is an extreme outlier for this entity",
    "repeat_after_block": "this input resubmits a request that was already blocked",
    "turn_blocked_repeatedly": (
        "repeated resubmission of a blocked request locked this session out for the cooldown window"
    ),
}

# Fail at import time if a ReasonCode is ever added without a description - a
# silently-humanized fallback is fine at runtime, but we want a nudge in review.
_MISSING_REASON_DESCRIPTIONS = {rc.value for rc in ReasonCode} - set(REASON_DESCRIPTIONS)
if _MISSING_REASON_DESCRIPTIONS:  # pragma: no cover - reminder, not a hard failure
    logger.debug(
        "explain: no description for reason codes %s", sorted(_MISSING_REASON_DESCRIPTIONS)
    )


def build_explanation_payload(row: dict) -> dict:
    """Defensive allowlist projection of a decision row for the LLM.

    Pulls values ONLY by iterating :data:`REDACTED_FIELDS` - never by copying the
    row and stripping unwanted keys - so a stray/raw key on ``row`` (e.g. from a
    caller that merged in something it shouldn't have) can never leak through.
    """
    return {field: row[field] for field in REDACTED_FIELDS if field in row}


def _parse_reason_codes(reason_codes_json: object) -> list[str]:
    if not reason_codes_json:
        return []
    try:
        codes = json.loads(reason_codes_json)
    except (TypeError, ValueError):
        return []
    if not isinstance(codes, list):
        return []
    return [str(c) for c in codes]


def _describe_reason(code: str) -> str:
    return REASON_DESCRIPTIONS.get(code, code.replace("_", " "))


def _describe_layer(layer: str) -> str:
    """Plain-words gloss of ``decided_layer`` for the primary sentence.

    ``decided_layer`` is only ever ``"objective"`` or ``"combined"`` (see
    ``doberman.storage.log._decided_layer``) - "combined" means the
    subjective/behavioral-baseline guardrail also weighed in, never that it
    ran alone. The raw technical value stays available elsewhere on the row
    (and to any caller that wants it) - this is only the human-facing words.
    """
    if layer == "combined":
        return "the rules and the behaviour baseline"
    return "the rules"


def template_explanation(row: dict, *, with_reasons: bool = True) -> str:
    """Deterministic, offline "why" for a decision row. Always available, never raises.

    ``with_reasons=False`` omits the "Reasons: ..." clause (and its no-codes
    fallback sentence) entirely - for a caller that already renders the reason
    codes some other way (the dash feed's glossed ``gloss-list``, see
    ``doberman.dash.app._feed_row``) so the sentence isn't said twice.
    """
    role = row.get("agent_role") or "the agent"
    action_type = row.get("action_type") or "an action"
    target = row.get("target_path_class")
    verdict = row.get("final_verdict") or "UNKNOWN"
    layer = row.get("decided_layer") or "objective"
    reason_codes = _parse_reason_codes(row.get("reason_codes_json"))

    what = f"{role} attempted {action_type}"
    if target:
        what += f" on {target}"
    sentences = [
        f"{what}.",
        f"Doberman decided {verdict} after checking {_describe_layer(layer)}.",
    ]

    if with_reasons:
        if reason_codes:
            reasons_text = "; ".join(_describe_reason(c) for c in reason_codes)
            sentences.append(f"Reasons: {reasons_text}.")
        else:
            sentences.append("No specific reason codes were recorded for this decision.")

    if verdict == "AUTH":
        sentences.append(
            "Completing the authentication challenge (or an approved role elevation) "
            "would let this action proceed."
        )
        if row.get("auth_result") == "soft_confirm+memory":
            sentences.append("This action was approved via 5-minute memory (soft_confirm).")
    elif verdict == "BLOCK":
        sentences.append(
            "This was a hard block - it will only be allowed after a policy or role "
            "change, not by re-authenticating."
        )

    return " ".join(sentences)


#: Verdict -> the word :func:`headline` uses for what happened. Deliberately
#: short - the headline is a fragment, not a sentence (see `headline` below).
_HEADLINE_VERDICT_WORD: dict[str, str] = {
    "BLOCK": "blocked",
    "AUTH": "needs approval",
    "PASS": "allowed",
}

#: Reason code -> a short (<=4 word), plain-English fact for `headline()`.
#: `_headline_fact` walks the ROW's OWN reason-code list in ITS order and
#: takes the first one with an entry here, so the row's own ordering (in
#: practice, whichever rule fired most decisively) drives the headline even
#: when several codes fired together - this dict does not impose its own
#: ranking. A deliberate subset of REASON_DESCRIPTIONS (the common/
#: high-signal codes), not all of them - a code missing here falls back to a
#: humanized form of itself (see `_headline_fact`), so this never has to be
#: exhaustive to stay safe.
_HEADLINE_FACTS: dict[str, str] = {
    "secret_exfiltration": "Secret exfiltration attempt",
    "confirmed_exfil": "Confirmed secret exfiltration",
    "multi_step_exfil": "Multi-step exfiltration pattern",
    "sensitive_secret_access": "Secret file read",
    "possible_high_entropy_secret": "Possible secret in payload",
    "pii_data_class_egress": "Personal-data egress",
    "encoded_exfiltration": "Encoded exfiltration attempt",
    "smuggled_token_channel": "Smuggled token channel",
    "destructive_command": "Recursive delete",
    "protected_path_blocked": "Protected-path write",
    "sensitive_path_access": "Sensitive-path access",
    "bulk_operation": "Bulk operation",
    "irreversible_high_blast": "Hard-to-undo action",
    "lethal_trifecta": "Lethal-trifecta pattern",
    "correlated_trifecta": "Lethal-trifecta pattern",
    "correlated_destructive_flow": "Correlated destructive pattern",
    "unknown_external_destination": "External upload",
    "egress_blocked_by_mode": "Egress blocked by mode",
    "anomalous_egress_velocity": "Anomalous egress burst",
    "egress_route_divergence": "Unexpected egress route",
    "unusual_for_workflow": "Unusual-for-agent action",
    "unusual_for_deployment": "Unusual-for-deployment action",
    "stylometric_outlier": "Writing-style outlier",
    "role_blocked_target": "Role-restricted target",
    "role_out_of_scope": "Out-of-scope action",
    "policy_source_blocked": "Blocked instruction source",
    "policy_source_sensitive": "Sensitive instruction source",
    "instruction_nullification": "Instruction-nullification attempt",
    "authority_override": "Authority-override attempt",
    "indirect_injection": "Indirect prompt injection",
    "embedded_instruction": "Embedded untrusted instruction",
    "persona_override": "Persona-override attempt",
    "urgency_secrecy_framing": "Urgency/secrecy framing",
    "obfuscated_content": "Obfuscated content",
    "repeat_after_block": "Repeated blocked request",
    "turn_blocked_repeatedly": "Repeated-block lockout",
    "unknown_tool": "Unrecognized tool",
    "artifact_digest_mismatch": "Digest mismatch",
    "tool_schema_changed": "Tool contract changed",
    "environment_dump_command": "Environment dump",
    "single_use_elevation_unclaimable": "Elevation already spent",
}

#: Reason codes whose headline reads better with the TARGET PATH CLASS as the
#: trailing detail (``"... - .env class"``) rather than the action type - a
#: path-shaped fact is more specific than a bare action type on its own.
_HEADLINE_PATH_FOCUSED_CODES = frozenset(
    {
        "sensitive_secret_access",
        "protected_path_blocked",
        "sensitive_path_access",
        "possible_high_entropy_secret",
    }
)


def _headline_fact(reason_codes: list[str]) -> str | None:
    for code in reason_codes:
        fact = _HEADLINE_FACTS.get(code)
        if fact:
            return fact
    # No code in the priority table - fall back to humanizing the FIRST code
    # on the row (still reason-first, just not one we have a curated phrase
    # for) rather than silently saying nothing about why.
    for code in reason_codes:
        return code.replace("_", " ").capitalize()
    return None


def headline(row: dict) -> str:
    """A <=9-word, reason-first fragment for a feed row's COLLAPSED state.

    Distinguishes otherwise-identical BLOCK rows at a glance (the "why", not
    the full sentence) - e.g. "Recursive delete blocked - shell_exec" or
    "Secret file read blocked - .env class". Falls back to a generic "Action"
    fact when no reason codes are recorded. Never raises - unlike
    :func:`template_explanation`, this never even touches ``agent_role``, so
    a row missing every optional field still gets a plain fragment back.
    """
    reason_codes = _parse_reason_codes(row.get("reason_codes_json"))
    verdict = row.get("final_verdict") or "UNKNOWN"
    verdict_word = _HEADLINE_VERDICT_WORD.get(verdict, verdict.lower())
    action_type = row.get("action_type") or "action"
    target = row.get("target_path_class")

    path_focused = any(code in _HEADLINE_PATH_FOCUSED_CODES for code in reason_codes)
    tail = f"{target} class" if (path_focused and target) else action_type
    fact = _headline_fact(reason_codes) or "Action"

    return f"{fact} {verdict_word} - {tail}"


def _llm_enrichment_enabled() -> bool:
    """Resolve the opt-in gate: installed + API key + explicit env flag, all three."""
    if importlib.util.find_spec("anthropic") is None:
        return False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    return os.environ.get("DOBERMAN_EXPLAIN_LLM", "").strip().lower() in {"1", "true", "yes"}


def _llm_explain(payload: dict) -> str:
    """Ask Haiku to reword the redacted payload. Narrator only - never the verdict."""
    import anthropic  # lazy: only imported once the opt-in gate has already passed

    client = anthropic.Anthropic()
    message = client.messages.create(
        model=_LLM_MODEL,
        max_tokens=_LLM_MAX_TOKENS,
        timeout=_LLM_TIMEOUT_S,
        system=_LLM_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(payload, sort_keys=True)}],
    )
    text = "".join(
        block.text for block in message.content if getattr(block, "type", None) == "text"
    )
    if not text.strip():
        raise ValueError("empty LLM response")
    return text


def explain_decision(row: dict, *, use_llm: bool | None = None) -> str:
    """Plain-language "why" for a redacted decision row.

    ``use_llm`` can only *restrict*: ``False`` forces the offline template even
    when the env gate is on; ``True``/``None`` still require the full opt-in gate
    (:func:`_llm_enrichment_enabled` - dep installed AND key AND env flag), so a
    caller can never bypass the user's env opt-in programmatically. Any failure
    in the LLM path - missing dep, no key, network, timeout, bad response -
    falls back to :func:`template_explanation`; this function never raises.
    """
    enabled = use_llm is not False and _llm_enrichment_enabled()
    if not enabled:
        return template_explanation(row)

    try:
        return _llm_explain(build_explanation_payload(row))
    except Exception:  # noqa: BLE001 - LLM enrichment is best-effort, never fatal
        logger.debug("explain: LLM enrichment failed, falling back to template", exc_info=True)
        return template_explanation(row)
