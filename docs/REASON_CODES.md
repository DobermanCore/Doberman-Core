# Reason codes

Every non-PASS Doberman decision can carry one or more `ReasonCode` values plus a human explanation.
Catalogue of all members of `ReasonCode` in `src/doberman/models.py`, with raise-site modules under `src/doberman/`.

**Total codes:** 51

| Code | Value | Group | Raised in | Meaning |
|------|-------|-------|-----------|---------|
| `normalization_failed` | `normalization_failed` | general | `engine/rules/normalization.py`, `proxy/normalize.py` | normalization failed (general) |
| `unknown_tool` | `unknown_tool` | general | _(reserved / enum only)_ | unknown tool (general) |
| `downstream_error` | `downstream_error` | general | `proxy/executor.py` | downstream error (general) |
| `objective_guardrail_error` | `objective_guardrail_error` | general | `engine/decision_engine.py`, `proxy/executor.py` | objective guardrail error (general) |
| `subjective_guardrail_error` | `subjective_guardrail_error` | general | `engine/decision_engine.py`, `engine/subjective.py` | subjective guardrail error (general) |
| `subjective_block_clamped` | `subjective_block_clamped` | general | `engine/decision_engine.py`, `policy/drift.py` | subjective block clamped (general) |
| `proxy_handler_error` | `proxy_handler_error` | never carries the exception's own message, only its class name. | `proxy/executor.py` | proxy handler error (never carries the exception's own message, only its class name.) |
| `secret_exfiltration` | `secret_exfiltration` | Feature 3 — objective guardrail (basic rules + plugin seam). | `engine/rules/secrets.py`, `hosthooks/claude_code.py`, `policy/modes.py`, `proxy/executor.py` | noqa: S105 — reason-code constant, not a secret |
| `sensitive_secret_access` | `sensitive_secret_access` | Feature 3 — objective guardrail (basic rules + plugin seam). | `auth/challenge.py`, `engine/rules/secrets.py`, `proxy/executor.py` | noqa: S105 — reason code, not a secret |
| `possible_high_entropy_secret` | `possible_high_entropy_secret` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `engine/rules/secrets.py` | noqa: S105 — reason code |
| `protected_path_blocked` | `protected_path_blocked` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `engine/rules/commands.py`, `engine/rules/paths.py`, `policy/modes.py` | protected path blocked (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `sensitive_path_access` | `sensitive_path_access` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `auth/challenge.py`, `engine/rules/paths.py`, `policy/drift.py` | sensitive path access (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `destructive_command` | `destructive_command` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `engine/rules/commands.py`, `policy/modes.py` | destructive command (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `bulk_operation` | `bulk_operation` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `auth/challenge.py`, `engine/rules/commands.py`, `policy/drift.py` | bulk operation (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `opaque_command` | `opaque_command` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `auth/challenge.py`, `engine/rules/commands.py` | opaque command (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `unknown_external_destination` | `unknown_external_destination` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `auth/challenge.py`, `egress/local.py`, `engine/rules/destinations.py` | unknown external destination (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `egress_requires_auth` | `egress_requires_auth` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `engine/rules/destinations.py` | egress requires auth (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `encoded_exfiltration` | `encoded_exfiltration` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `auth/challenge.py` | encoded exfiltration (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `rule_error` | `rule_error` | UUIDs / base64 fragments) instead of hard-blocking a benign read. | `engine/objective.py`, `engine/subjective.py` | rule error (UUIDs / base64 fragments) instead of hard-blocking a benign read.) |
| `role_blocked_target` | `role_blocked_target` | Feature 4 — agent role policy & boundaries (+ policy-source seam). | `engine/rules/role_boundary.py`, `policy/modes.py` | role blocked target (Feature 4 — agent role policy & boundaries (+ policy-source seam).) |
| `role_out_of_scope` | `role_out_of_scope` | Feature 4 — agent role policy & boundaries (+ policy-source seam). | `auth/challenge.py`, `engine/rules/role_boundary.py`, `policy/drift.py` | role out of scope (Feature 4 — agent role policy & boundaries (+ policy-source seam).) |
| `policy_source_blocked` | `policy_source_blocked` | Feature 4 — agent role policy & boundaries (+ policy-source seam). | `engine/rules/policy_source.py`, `policy/modes.py` | policy source blocked (Feature 4 — agent role policy & boundaries (+ policy-source seam).) |
| `policy_source_sensitive` | `policy_source_sensitive` | Feature 4 — agent role policy & boundaries (+ policy-source seam). | `auth/challenge.py`, `engine/rules/policy_source.py` | policy source sensitive (Feature 4 — agent role policy & boundaries (+ policy-source seam).) |
| `unusual_for_workflow` | `unusual_for_workflow` | Feature 9 — subjective guardrail & workflow baseline (+ detector seam). | `engine/subjective.py`, `policy/drift.py` | unusual for workflow (Feature 9 — subjective guardrail & workflow baseline (+ detector seam).) |
| `unusual_for_deployment` | `unusual_for_deployment` | Universal subjective layer (SL7) — three-axis scoring + trifecta floor. | `engine/subjective.py`, `policy/drift.py` | unusual for deployment (Universal subjective layer (SL7) — three-axis scoring + trifecta floor.) |
| `confidentiality_sensitive_destination` | `confidentiality_sensitive_destination` | Universal subjective layer (SL7) — three-axis scoring + trifecta floor. | `engine/subjective.py` | confidentiality sensitive destination (Universal subjective layer (SL7) — three-axis scoring + trifecta floor.) |
| `irreversible_high_blast` | `irreversible_high_blast` | Universal subjective layer (SL7) — three-axis scoring + trifecta floor. | `engine/subjective.py` | irreversible high blast (Universal subjective layer (SL7) — three-axis scoring + trifecta floor.) |
| `lethal_trifecta` | `lethal_trifecta` | Universal subjective layer (SL7) — three-axis scoring + trifecta floor. | `engine/decision_engine.py`, `engine/subjective.py`, `subjective/revealed.py` | lethal trifecta (Universal subjective layer (SL7) — three-axis scoring + trifecta floor.) |
| `unclassified_action` | `unclassified_action` | Universal subjective layer (SL7) — three-axis scoring + trifecta floor. | `engine/subjective.py`, `policy/drift.py` | unclassified action (Universal subjective layer (SL7) — three-axis scoring + trifecta floor.) |
| `smuggled_token_channel` | `smuggled_token_channel` | OOD / smuggled-token channel defense (objective rule + subjective detector). | `engine/rules/token_channels.py` | noqa: S105 — reason code, not a secret |
| `anomalous_token_pattern` | `anomalous_token_pattern` | OOD / smuggled-token channel defense (objective rule + subjective detector). | `engine/detectors/token_channels.py` | noqa: S105 — reason code, not a secret |
| `multi_step_exfil` | `multi_step_exfil` | HK.5 — host-hook containment: the cross-call (multi-step) exfiltration floor. | `engine/taint_floor.py`, `hosthooks/claude_code.py` | multi step exfil (HK.5 — host-hook containment: the cross-call (multi-step) exfiltration floor.) |
| `confirmed_exfil` | `confirmed_exfil` | fingerprint) in an outbound payload: a confirmed read-then-send exfiltration. | `engine/taint_floor.py`, `hosthooks/claude_code.py` | confirmed exfil (fingerprint) in an outbound payload: a confirmed read-then-send exfiltration.) |
| `turn_gate_error` | `turn_gate_error` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `engine/decision_engine.py`, `turngate/heuristics.py`, `turngate/hook.py` | turn gate error (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `instruction_nullification` | `instruction_nullification` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/repeat.py`, `turngate/signatures.py` | instruction nullification (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `authority_override` | `authority_override` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/repeat.py`, `turngate/signatures.py` | authority override (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `secret_export` | `secret_export` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/repeat.py`, `turngate/signatures.py` | noqa: S105 — reason-code constant, not a secret |
| `encoded_payload` | `encoded_payload` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/repeat.py`, `turngate/signatures.py` | encoded payload (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `indirect_injection` | `indirect_injection` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/repeat.py`, `turngate/signatures.py` | indirect injection (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `embedded_instruction` | `embedded_instruction` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/heuristics.py` | embedded instruction (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `persona_override` | `persona_override` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/heuristics.py` | persona override (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `obfuscated_content` | `obfuscated_content` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/heuristics.py` | obfuscated content (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `urgency_secrecy_framing` | `urgency_secrecy_framing` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/heuristics.py` | urgency secrecy framing (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `stylometric_outlier` | `stylometric_outlier` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/heuristics.py` | stylometric outlier (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `repeat_after_block` | `repeat_after_block` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/hook.py`, `turngate/repeat.py` | repeat after block (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `turn_blocked_repeatedly` | `turn_blocked_repeatedly` | Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these. | `turngate/repeat.py` | turn blocked repeatedly (Tier 1 (heuristic, AUTH-only). Every turn verdict carries one of these.) |
| `egress_route_divergence` | `egress_route_divergence` | never a pre-flight check of the pending action's own destination). | `engine/rules/destinations.py` | egress route divergence (never a pre-flight check of the pending action's own destination).) |
| `egress_broker_enforced` | `egress_broker_enforced` | other rule (secrets, trifecta floor, RB.3 divergence). | `engine/rules/destinations.py` | egress broker enforced (other rule (secrets, trifecta floor, RB.3 divergence).) |
| `egress_blocked_by_mode` | `egress_blocked_by_mode` | without a broker in every mode, including paranoid (raise-only; ADR 0021). | `engine/rules/destinations.py` | egress blocked by mode (without a broker in every mode, including paranoid (raise-only; ADR 0021).) |
| `anomalous_egress_velocity` | `anomalous_egress_velocity` | same shape as egress_route_divergence: no broker means no signal. | `engine/rules/destinations.py` | anomalous egress velocity (same shape as egress_route_divergence: no broker means no signal.) |
| `artifact_digest_mismatch` | `artifact_digest_mismatch` | post-result. | `proxy/executor.py` | artifact digest mismatch (post-result.) |

## Notes

- Prefer matching on the enum **name** in automation; values are stable strings.
- Evidence may be redacted; reason codes are the machine-stable half of explainability.
- When adding a `ReasonCode`, update this table in the same PR.
