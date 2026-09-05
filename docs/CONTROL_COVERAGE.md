# Control coverage: OWASP LLM Top 10 and NIST AI RMF

Doberman is a local action gate for coding agents, not a model-security product: it mediates every
tool call an agent makes and decides `PASS`/`AUTH`/`BLOCK` before it executes. It does not train,
fine-tune, sandbox, or evaluate the truthfulness of any model. This matrix maps that gate to the OWASP
Top 10 for LLM Applications (2025) and the NIST AI RMF 1.0, stating plainly which controls it
implements, which it partially supports, and which it does not address at all.

## How to read this

`partial` means defense-in-depth, never airtight. That's the same wording the [README](../README.md)
uses for its own secret detection: no single rule is a guarantee, and the "Honest limit" column
names the specific gap. `covered` means the mechanism exists and is tested, not that the risk
category is fully closed. Read the limit column for every row regardless of status. Nothing in this
document is a compliance attestation. It is an engineering summary of what ships today, grounded in
the [`ReasonCode`](REASON_CODES.md) enum and the rule/detector modules that raise each code.

## Table 1: OWASP Top 10 for LLM Applications (2025)

| # | Risk | Status | Doberman mechanism | Honest limit |
|---|---|---|---|---|
| LLM01:2025 | Prompt Injection | `partial` | Turn gate Tier 0 signatures (`instruction_nullification`, `authority_override`, `secret_export`, `encoded_payload`, `indirect_injection`; `src/doberman/turngate/signatures.py`) and Tier 1 heuristics (`embedded_instruction`, `persona_override`, `obfuscated_content`, `urgency_secrecy_framing`; `turngate/heuristics.py`) run pre-inference; every resulting tool call still passes the action gate regardless of how the model was steered. | [Turn gate](TURN_GATE.md)'s own guarantee is deliberately narrow ("no Tier‑0‑signature turn reaches the model"), not exhaustive. A paraphrased injection matching no signature or heuristic can still reach inference. The action gate is the real backstop. |
| LLM02:2025 | Sensitive Information Disclosure | `partial` | `SecretLeakageRule` (`secret_exfiltration` hard-block, `sensitive_secret_access`, `possible_high_entropy_secret`; `engine/rules/secrets.py`), `pii_data_class_egress` (`engine/rules/data_classes.py`), cross-call taint floor (`multi_step_exfil`, `confirmed_exfil`; `engine/taint_floor.py`), `untrusted_value_echo`, post-execution output secret scan. | The README's own "Known limitations" section documents concrete false-negative classes today: bare hex/UUID secrets with no credential-name context, oversized-blob evasion by splitting a payload, DNS-label exfiltration (smuggling data out disguised as DNS lookups) left uncovered. |
| LLM03:2025 | Supply Chain | `partial` | `DependencyAdmissionRule` (`dependency_known_malicious`, `dependency_name_typosquat`; `engine/rules/dependency_admission.py`); Doberman's own releases ship a CycloneDX SBOM (Software Bill of Materials, a list of the project's dependencies). | Name-only, offline, small bundled seed lists (69 popular names across five ecosystems, 10 known-malicious names, all of them npm); no lockfile, registry, or postinstall-script inspection; `npx`/`pipx run` fetch-and-run shapes are not parsed at all. |
| LLM04:2025 | Data and Model Poisoning | `not addressed` | None | Doberman has no visibility into training or fine-tuning data. Its "raise-only" defense against policy drift, meaning a change to the policy over time (`policy/drift.py`), protects Doberman's own policy configuration from being weakened. That's a different kind of poisoning, out of this risk's scope. |
| LLM05:2025 | Improper Output Handling | `covered` | Every action the agent's output drives is normalized into a `SecurityObject` and routed through the decision engine (`doberman.proxy`, `engine/decision_engine.py`) before it executes. A `BLOCK` verdict means the downstream tool records nothing, proven by `tests/integration/test_engine_blocks_reach_no_tool.py`. | Mediation is rule-based classification of the call, not sandboxed execution. A shape none of the objective rules recognize (an unlisted verb, a runtime-built path) can still pass. |
| LLM06:2025 | Excessive Agency | `partial` | `RoleBoundaryRule` (`role_blocked_target`, `role_out_of_scope`), tiered/time-limited/single-use elevation (`auth/challenge.py`), destructive- and bulk-operation gating (`destructive_command`, `bulk_operation`). | Role boundaries are opt-in and abstain entirely with no active role configured ([Authority tiers](AUTHORITY_TIERS.md)). Doberman gates the *use* of tools already granted. It does not reduce what an agent is provisioned with upstream. |
| LLM07:2025 | System Prompt Leakage | `partial` | Turn gate `authority_override` explicitly matches "authority-impersonation, jailbreak/mode-switch, or system-prompt-exfiltration" pattern shapes (`turngate/signatures.py`). | Tier 0 signature match only, deliberately narrow, evadable by rephrasing; no runtime redaction of the system prompt itself. |
| LLM08:2025 | Vector and Embedding Weaknesses | `not addressed` | None | Doberman has no visibility into embedding stores, RAG retrieval, or vector-database access. That's out of its layer entirely. |
| LLM09:2025 | Misinformation | `not addressed` | None | Doberman does not evaluate the truthfulness of model output. The shadow adjudicator (`engine/adjudicator.py`) is advisory-only and judges decision *risk*, never factual accuracy, and has no production caller today ([Authority tiers](AUTHORITY_TIERS.md) T3). |
| LLM10:2025 | Unbounded Consumption | `not addressed` | None | Doberman does not meter or rate-limit LLM inference calls, tokens, or API cost. `bulk_operation` and `anomalous_egress_velocity` bound destructive blast radius (how much damage one action could do) and bursts of egress (outbound network connections) respectively. That's a different concern, not model or API resource consumption. |

**Counts:** covered 1 · partial 5 · not addressed 4.

## Table 2: NIST AI RMF 1.0

Rows below are the subcategories Doberman meaningfully touches. Every other subcategory across all
four functions is untouched by design (see the note after the table).

| Subcategory | Status | Doberman mechanism | Honest limit |
|---|---|---|---|
| GOVERN 3.2 | `covered` | Role and policy-source boundaries define human-AI oversight roles (`RoleBoundaryRule`, `PolicySourceRule`; `role_blocked_target`, `policy_source_blocked`) plus tiered human authentication (`doberman.auth`). | Role/policy-source configuration is opt-in per deployment, not enforced by default. |
| GOVERN 6.2 | `covered` | Third-party rule/detector/audit-sink plugins are isolated: one that fails to import, fails to construct, or doesn't match the interface is logged and skipped, never crashes core ([Write a guardrail plugin](PLUGINS.md); `rule_error`). | Covers plugin *failure*, not a malicious-but-well-formed plugin. Containment there is that a plugin can only raise risk through `combine()`, never lower it. |
| GOVERN 1.2 | `partial` | Doberman's own prime directives (fail closed, raise-only, no secrets) are documented and CI-enforced against itself. | Governs Doberman's own build, not the deploying organization's broader AI risk policy. That's out of scope for a point tool. |
| MEASURE 2.6 | `covered` | The benchmark harness runs the real decision engine over a labeled detection corpus and CI gates on any regression in attack-bypass rate ([Benchmarks](BENCHMARKS.md)). | Corpus coverage is uneven. [Authority tiers](AUTHORITY_TIERS.md) documents a gap in benign delete-command false-positive (over-block) coverage specifically. |
| MEASURE 2.7 | `covered` | The same benchmark/corpus harness scores false-positive (over-block) rate alongside attack-bypass rate. | Offline, deterministic replay only; no live red-team feed. |
| MEASURE 2.13 | `covered` | The [parity matrix](PARITY.md) is generated from CI test results, never hand-edited; [Authority tiers](AUTHORITY_TIERS.md) is kept honest by `tests/unit/test_authority_tiers.py`; [`REASON_CODES.md`](REASON_CODES.md) cannot drift from the enum (`tests/unit/test_reason_codes_documented.py` fails the build otherwise). | These are internal TEVV artifacts about Doberman's own rule set, not a third-party audit. |
| MEASURE 2.10 | `partial` | `pii_data_class_egress` (checksum-valid card/IBAN/SSN detection) plus the secret-detection rules from LLM02 above. | Same entropy/shape false-negative classes documented in the README's "Known limitations." |
| MANAGE 1.3 | `covered` | Every non-`PASS` decision is a documented, categorized risk response (`PASS`/`AUTH`/`BLOCK`) carrying `reason_codes` plus a human `explanation` (`models.py`, [`REASON_CODES.md`](REASON_CODES.md)). | The response taxonomy is fixed to three verdicts; no formal risk-transfer or risk-acceptance workflow beyond a human's AUTH approval. |
| MANAGE 2.4 | `covered` | A `BLOCK` verdict stops a single action outright, and the control plane is self-protected. A mediated agent cannot disable its own leash. | Deactivates a *specific action*, not the agent itself; a human at the keyboard can still disable the hook (README "Known limitations"). |
| MANAGE 2.3 | `partial` | The subjective layer's raise-only score (`unusual_for_deployment`, `unusual_for_workflow`) and policy-drift auto-tightening respond to previously unseen risk shapes. | Structurally capped at `AUTH`, never `BLOCK` ([Authority tiers](AUTHORITY_TIERS.md) T2). An unknown risk is escalated to a human, not autonomously contained. |
| MANAGE 4.1 / 4.3 | `partial` | The local decision log, optional webhook/OTel audit sinks, and the dashboard give post-deployment visibility; [`SECURITY.md`](../SECURITY.md) defines a private vulnerability-reporting channel. | No formal incident-response or appeal workflow beyond re-submitting an action for a fresh AUTH decision. |

**Counts:** covered 7 · partial 4 · not addressed 0 (this table lists only touched subcategories).

**Untouched:** the entire MAP function (pre-deployment context, capability, and impact
characterization) is untouched. Doberman is installed after a coding agent already exists, not a
pre-deployment risk-mapping tool. Most of GOVERN (organization-level AI risk culture, accountability
structures, procurement beyond entry-point plugins) and every MEASURE/MANAGE subcategory not listed
above are also untouched.
