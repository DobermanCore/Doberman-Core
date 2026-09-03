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
    "raw_socket_channel": "the command opens a raw network socket or TLS client connection outside the normal HTTP tooling",
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
    "verification_bypass_flag": (
        "the git commit skips its pre-commit/pre-push hooks or signature check "
        "(--no-verify, -n, or --no-gpg-sign)"
    ),
    "test_file_removal": "a test file is being deleted or renamed, not just edited",
    "dependency_known_malicious": (
        "the package name in this install command is on a bundled known-malicious list"
    ),
    "dependency_name_typosquat": (
        "the package name in this install command is one character away from a popular "
        "package name and is not itself recognized (possible typosquat)"
    ),
}

# Fail at import time if a ReasonCode is ever added without a description - a
# silently-humanized fallback is fine at runtime, but we want a nudge in review.
_MISSING_REASON_DESCRIPTIONS = {rc.value for rc in ReasonCode} - set(REASON_DESCRIPTIONS)
if _MISSING_REASON_DESCRIPTIONS:  # pragma: no cover - reminder, not a hard failure
    logger.debug(
        "explain: no description for reason codes %s", sorted(_MISSING_REASON_DESCRIPTIONS)
    )

# Plain-words phrasing for `decided_layer` (see storage/log.py's `_decided_layer`:
# "objective" | "combined") for the trailing "(Checked by: ...)" sentence
# (round 6 design critique item 10 - was "(Decided by: the objective
# guardrail layer.)"/"...the objective and subjective guardrail layers
# together.)"; the technical layer-identity phrasing read as jargon next to
# the rest of the plain-language body, so this now says what was checked, in
# the same words `_layer_checked_clause` already uses for `first_sentence`).
# Anything unrecognized falls back to a humanized form of the raw value, same
# defensive pattern as `_describe_reason`.
_LAYER_CHECKED_BY: dict[str, str] = {
    "objective": "the rules",
    "combined": "the rules and the behaviour baseline",
}


def _describe_checked_by(layer: str) -> str:
    return _LAYER_CHECKED_BY.get(layer, layer.replace("_", " "))


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


def _layer_checked_clause(layer: str) -> str:
    """What Doberman checked, in plain words (round 4 design critique item 6):
    "checking the rules" for the objective layer alone, or "...and the
    behaviour baseline" once the subjective layer weighed in too (``layer ==
    "combined"``)."""
    if layer == "combined":
        return "checking the rules and the behaviour baseline"
    return "checking the rules"


def first_sentence(row: dict) -> str:
    """The one-line plain-language summary of a decision row: the verdict plus
    what was checked. Deliberately :func:`template_explanation`'s FIRST
    sentence (see below) - `doberman log --why` reuses this for a compact
    one-line "why" without repeating the reason codes `doberman log`'s own row
    already shows.
    """
    verdict = row.get("final_verdict") or "UNKNOWN"
    layer = row.get("decided_layer") or "objective"
    return f"Doberman decided {verdict} after {_layer_checked_clause(layer)}."


def _body_sentences(row: dict, *, with_reasons: bool = True) -> list[str]:
    """Every sentence of :func:`template_explanation` EXCEPT the trailing
    "(Checked by: ...)" one - shared by :func:`template_explanation` (which
    appends that sentence) and :func:`why_body` (which deliberately doesn't).

    ``with_reasons=False`` omits the "Reasons: ..." clause (and its no-codes /
    PASS fallback sentence) entirely - for a caller that already renders the
    reason codes some other way (the dash feed's glossed ``gloss-list``, see
    ``doberman.dash.app._feed_row``) so the sentence isn't said twice.
    """
    role = row.get("agent_role")
    # "unknown" is a real (not merely absent) `agent_role` value on some rows -
    # rendering it literally read as "unknown attempted shell_exec.", which
    # looks like a bug rather than a deliberate "we don't know" statement.
    if not role or role == "unknown":
        role = "An agent"  # capitalised: this sentence follows `first_sentence`
    action_type = row.get("action_type") or "an action"
    target = row.get("target_path_class")
    verdict = row.get("final_verdict") or "UNKNOWN"
    reason_codes = _parse_reason_codes(row.get("reason_codes_json"))

    what = f"{role} attempted {action_type}"
    if target:
        what += f" on {target}"

    # Plain-language summary leads - the verdict and what was checked - then
    # the attempted action, then (optionally) the reasons; the technical
    # layer identity lives in the trailing "(Checked by: ...)" sentence that
    # `template_explanation` appends.
    sentences = [first_sentence(row), f"{what}."]

    if with_reasons:
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

    return sentences


def template_explanation(row: dict, *, with_reasons: bool = True) -> str:
    """Deterministic, offline "why" for a decision row. Always available, never raises.

    ``with_reasons=False`` omits the "Reasons: ..." clause (see
    :func:`_body_sentences`) for a caller that renders the codes itself.
    """
    layer = row.get("decided_layer") or "objective"
    sentences = [
        *_body_sentences(row, with_reasons=with_reasons),
        f"(Checked by: {_describe_checked_by(layer)}.)",
    ]
    return " ".join(sentences)


def why_body(row: dict) -> str:
    """`template_explanation` minus the trailing "(Checked by: ...)" sentence -
    what `doberman log --why` prints under a BLOCK/AUTH row (round 6 design
    critique item 7). `doberman log`'s own row already shows the raw reason
    codes and the decided verdict, so the OLD one-line `first_sentence` alone
    ("Doberman decided BLOCK after checking the rules.") added nothing beyond
    what was already on screen; this adds the "what was attempted" and
    "Reasons: ..." sentences too, so `--why` earns its name.
    """
    return " ".join(_body_sentences(row))


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
    "raw_socket_channel": "Raw socket channel",
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
    "verification_bypass_flag": "Verification bypass",
    "test_file_removal": "Test file removal",
    "dependency_known_malicious": "Known-malicious package name",
    "dependency_name_typosquat": "Possible package typosquat",
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
    (:func:`_llm_enrichment_enabled` - dep installed AND key AND env flag), so a
    caller can never bypass the user's env opt-in programmatically. Any failure
    in the LLM path - missing dep, no key, network, timeout, bad response -
    falls back to :func:`template_explanation`; this function never raises.
    """
    text, _source = explain_decision_with_source(row, use_llm=use_llm)
    return text
