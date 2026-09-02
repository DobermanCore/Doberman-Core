"""Decision transparency: turn a redacted decision-log row into a plain-language "why".

Two explanation modes, always with a safe default:

* :func:`template_explanation` — deterministic, offline, always available. Built from
  the redacted row alone (verdict, decided layer, reason codes) using the shared
  :class:`~doberman.models.ReasonCode` constants.
* :func:`_llm_explain` — an OPT-IN narrator (Claude Haiku) that rewords the same
  redacted metadata in plainer language. It never sees a raw path, argument, or
  secret, and it never influences the verdict — it explains a decision that has
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
    "language. You are given only redacted metadata — do not invent specifics you "
    "were not given, and never ask for more data."
)

# Human-readable descriptions for the ReasonCode constants (doberman/models.py).
# Anything not listed here (e.g. a future code) falls back to a humanized form of
# the code itself, so this dict never has to be kept perfectly in sync to be safe.
_REASON_DESCRIPTIONS: dict[str, str] = {
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
}

# Fail at import time if a ReasonCode is ever added without a description — a
# silently-humanized fallback is fine at runtime, but we want a nudge in review.
_MISSING_REASON_DESCRIPTIONS = {rc.value for rc in ReasonCode} - set(_REASON_DESCRIPTIONS)
if _MISSING_REASON_DESCRIPTIONS:  # pragma: no cover — reminder, not a hard failure
    logger.debug(
        "explain: no description for reason codes %s", sorted(_MISSING_REASON_DESCRIPTIONS)
    )

# Plain-words phrasing for `decided_layer` (see storage/log.py's `_decided_layer`:
# "objective" | "combined"). Anything unrecognized falls back to a humanized form
# of the raw value, same defensive pattern as `_describe_reason`.
_LAYER_DESCRIPTIONS: dict[str, str] = {
    "objective": "the objective guardrail layer",
    "combined": "the objective and subjective guardrail layers together",
}


def _describe_layer(layer: str) -> str:
    return _LAYER_DESCRIPTIONS.get(layer, layer.replace("_", " "))


def build_explanation_payload(row: dict) -> dict:
    """Defensive allowlist projection of a decision row for the LLM.

    Pulls values ONLY by iterating :data:`REDACTED_FIELDS` — never by copying the
    row and stripping unwanted keys — so a stray/raw key on ``row`` (e.g. from a
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
    return _REASON_DESCRIPTIONS.get(code, code.replace("_", " "))


def template_explanation(row: dict) -> str:
    """Deterministic, offline "why" for a decision row. Always available, never raises."""
    role = row.get("agent_role") or "the agent"
    action_type = row.get("action_type") or "an action"
    target = row.get("target_path_class")
    verdict = row.get("final_verdict") or "UNKNOWN"
    layer = row.get("decided_layer") or "objective"
    reason_codes = _parse_reason_codes(row.get("reason_codes_json"))

    what = f"{role} attempted {action_type}"
    if target:
        what += f" on {target}"
    layer_desc = _describe_layer(layer)
    sentences = [f"{what}.", f"{layer_desc[0].upper()}{layer_desc[1:]} decided {verdict}."]

    if reason_codes:
        reasons_text = "; ".join(_describe_reason(c) for c in reason_codes)
        sentences.append(f"Reasons: {reasons_text}.")
    elif verdict == "PASS":
        sentences.append(
            "Nothing was flagged: the action was checked against the built-in "
            "guardrails and found clean."
        )
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


def _llm_enrichment_enabled() -> bool:
    """Resolve the opt-in gate: installed + API key + explicit env flag, all three."""
    if importlib.util.find_spec("anthropic") is None:
        return False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    return os.environ.get("DOBERMAN_EXPLAIN_LLM", "").strip().lower() in {"1", "true", "yes"}


def _llm_explain(payload: dict) -> str:
    """Ask Haiku to reword the redacted payload. Narrator only — never the verdict."""
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


def llm_enrichment_enabled() -> bool:
    """Public check: would `explain_decision` attempt LLM enrichment right now?

    Same three-way gate as :func:`explain_decision` (dep installed AND key AND
    env flag) — exposed so a caller (the `tui` decision browser) can decide up
    front whether to even schedule an enrichment attempt, without duplicating
    the gate logic itself.
    """
    return _llm_enrichment_enabled()


def explain_decision_with_source(row: dict, *, use_llm: bool | None = None) -> tuple[str, str]:
    """Like :func:`explain_decision`, but also reports where the text came from.

    Returns ``(text, source)`` where ``source`` is ``"llm"`` (successfully
    narrated) or ``"template"`` (LLM disabled, or enabled but failed and fell
    back) — lets a caller distinguish "never attempted" from "attempted and
    fell back" for its own display, without this function ever raising.
    """
    enabled = use_llm is not False and _llm_enrichment_enabled()
    if not enabled:
        return template_explanation(row), "template"

    try:
        return _llm_explain(build_explanation_payload(row)), "llm"
    except Exception:  # noqa: BLE001 — LLM enrichment is best-effort, never fatal
        logger.debug("explain: LLM enrichment failed, falling back to template", exc_info=True)
        return template_explanation(row), "template"


def explain_decision(row: dict, *, use_llm: bool | None = None) -> str:
    """Plain-language "why" for a redacted decision row.

    ``use_llm`` can only *restrict*: ``False`` forces the offline template even
    when the env gate is on; ``True``/``None`` still require the full opt-in gate
    (:func:`_llm_enrichment_enabled` — dep installed AND key AND env flag), so a
    caller can never bypass the user's env opt-in programmatically. Any failure
    in the LLM path — missing dep, no key, network, timeout, bad response —
    falls back to :func:`template_explanation`; this function never raises.
    """
    text, _source = explain_decision_with_source(row, use_llm=use_llm)
    return text
