"""Core data models: the `SecurityObject` schema, verdicts, and reason codes.

This module is the central, shared vocabulary of Doberman. Every intercepted
tool call is normalized into a :class:`SecurityObject`; every guardrail answers
with a :class:`GuardrailResult`. Both are immutable so no later layer can
silently mutate risk or a verdict downward — changes happen by producing a
*new* object, never by editing in place (raise-only principle).
"""

from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from doberman.roles.roles import RoleDefinition


class ActionType(StrEnum):
    """What kind of action the agent is attempting."""

    file_read = "file_read"
    file_write = "file_write"
    file_delete = "file_delete"
    shell_exec = "shell_exec"
    network_request = "network_request"
    git_op = "git_op"
    package_install = "package_install"
    memory_write = "memory_write"
    final_output = "final_output"
    other = "other"


class SourceContext(StrEnum):
    """Where the instruction that led to this action came from."""

    user = "user"
    github_issue = "github_issue"
    readme = "readme"
    webpage = "webpage"
    email = "email"
    tool_output = "tool_output"
    unknown = "unknown"


class Risk(StrEnum):
    """Assessed risk level of an action."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Reversibility(StrEnum):
    """How easily the action's effects can be undone."""

    low = "low"
    medium = "medium"
    high = "high"


class Capability(StrEnum):
    """The abstract verb of an action (algebra dimension, closed enum)."""

    read = "read"
    mutate = "mutate"
    delete = "delete"
    send = "send"
    execute = "execute"
    grant = "grant"
    configure = "configure"
    other = "other"


class TargetClass(StrEnum):
    """Sensitivity tier of what the action touches — never a literal path/recipient."""

    public = "public"
    internal = "internal"
    sensitive = "sensitive"
    secret = "secret"  # noqa: S105 — sensitivity-tier constant, not a secret value
    unknown = "unknown"


class DestinationClass(StrEnum):
    """Where data goes (algebra dimension, closed enum)."""

    none = "none"
    internal = "internal"
    known_external = "known_external"
    unknown_external = "unknown_external"


class BlastRadius(StrEnum):
    """How many entities the action touches (algebra dimension, closed enum)."""

    single = "single"
    few = "few"
    many = "many"
    mass = "mass"
    unknown = "unknown"


class Provenance(StrEnum):
    """Whether the action traces to a trusted instruction or untrusted data."""

    trusted_instruction = "trusted_instruction"
    untrusted_data = "untrusted_data"
    mixed = "mixed"
    unknown = "unknown"


#: Version of the action-algebra vocabulary. Adding/changing a dimension is a
#: core schema change (bump this), never an adapter-level change.
ALGEBRA_VERSION = 1

# Severity orderings for the ordered algebra tiers. Used by the refine-only
# adapter clamp (an adapter may move a class UP these scales, never down) and
# by the ordinal feature encoding. ``unknown`` deliberately sits above the
# benign tiers — unclassified is treated as elevated, never as safe.
TARGET_CLASS_ORDER: dict[TargetClass, int] = {
    TargetClass.public: 0,
    TargetClass.internal: 1,
    TargetClass.unknown: 2,
    TargetClass.sensitive: 3,
    TargetClass.secret: 4,
}
DESTINATION_CLASS_ORDER: dict[DestinationClass, int] = {
    DestinationClass.none: 0,
    DestinationClass.internal: 1,
    DestinationClass.known_external: 2,
    DestinationClass.unknown_external: 3,
}
BLAST_RADIUS_ORDER: dict[BlastRadius, int] = {
    BlastRadius.single: 0,
    BlastRadius.few: 1,
    BlastRadius.unknown: 2,
    BlastRadius.many: 3,
    BlastRadius.mass: 4,
}
#: Higher = less trusted. An adapter may only ever move provenance toward MORE
#: untrusted — ``trusted_instruction`` can never be reached by refinement.
PROVENANCE_ORDER: dict[Provenance, int] = {
    Provenance.trusted_instruction: 0,
    Provenance.unknown: 1,
    Provenance.mixed: 2,
    Provenance.untrusted_data: 3,
}

if (  # pragma: no cover — same import-time guard as VERDICT_ORDER below
    set(TARGET_CLASS_ORDER) != set(TargetClass)
    or set(DESTINATION_CLASS_ORDER) != set(DestinationClass)
    or set(BLAST_RADIUS_ORDER) != set(BlastRadius)
    or set(PROVENANCE_ORDER) != set(Provenance)
):
    raise RuntimeError("algebra ORDER maps must cover every enum member")


class Algebra(BaseModel):
    """The universal action-abstraction (algebra) for one action — immutable.

    Every action reduces to this small, fixed, versioned vocabulary
    (:data:`ALGEBRA_VERSION`) so the subjective layer needs no per-application
    branching. Defaults are the CONSERVATIVE members: an uninspected action is
    ``unknown`` at zero confidence, which downstream layers treat as elevated
    sensitivity — never as benign. ``reversibility`` is not duplicated here; the
    algebra reads :attr:`SecurityObject.reversibility`.

    ``classification_confidence`` is load-bearing: low confidence routes the
    action through the conservative-default path (elevated sensitivity + a
    bounded novelty signal), and only a verified adapter may raise it.
    """

    model_config = ConfigDict(frozen=True)

    capability: Capability = Capability.other
    target_class: TargetClass = TargetClass.unknown
    destination_class: DestinationClass = DestinationClass.none
    blast_radius: BlastRadius = BlastRadius.unknown
    provenance: Provenance = Provenance.unknown
    classification_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class Verdict(StrEnum):
    """The decision for an action: pass through, authenticate, or block."""

    PASS = "PASS"  # noqa: S105 — verdict constant, not a password
    AUTH = "AUTH"
    BLOCK = "BLOCK"


# Severity orderings: combination may only ever move UP these scales
# (raise-only). Shared by the Decision consistency check below and the
# engine's combine().
VERDICT_ORDER: dict[Verdict, int] = {Verdict.PASS: 0, Verdict.AUTH: 1, Verdict.BLOCK: 2}
RISK_ORDER: dict[Risk, int] = {Risk.low: 0, Risk.medium: 1, Risk.high: 2, Risk.critical: 3}

# Fail at import time if an enum member is ever added without an ordering —
# a KeyError mid-decision would crash instead of failing closed.
if set(VERDICT_ORDER) != set(Verdict) or set(RISK_ORDER) != set(Risk):  # pragma: no cover
    raise RuntimeError("VERDICT_ORDER/RISK_ORDER must cover every enum member")


class ReasonCode(StrEnum):
    """Stable reason-code constants attached to every non-PASS decision.

    Start small; grow per feature. Codes are part of the explainability
    contract: every BLOCK/AUTH carries reason codes plus a human explanation.
    """

    normalization_failed = "normalization_failed"
    unknown_tool = "unknown_tool"
    downstream_error = "downstream_error"
    objective_guardrail_error = "objective_guardrail_error"
    subjective_guardrail_error = "subjective_guardrail_error"
    subjective_block_clamped = "subjective_block_clamped"

    # Feature 3 — objective guardrail (basic rules + plugin seam).
    secret_exfiltration = "secret_exfiltration"  # noqa: S105 — reason-code constant, not a secret
    sensitive_secret_access = "sensitive_secret_access"  # noqa: S105 — reason code, not a secret
    protected_path_blocked = "protected_path_blocked"
    sensitive_path_access = "sensitive_path_access"
    destructive_command = "destructive_command"
    bulk_operation = "bulk_operation"
    opaque_command = "opaque_command"
    unknown_external_destination = "unknown_external_destination"
    encoded_exfiltration = "encoded_exfiltration"
    rule_error = "rule_error"

    # Feature 4 — agent role policy & boundaries (+ policy-source seam).
    role_blocked_target = "role_blocked_target"
    role_out_of_scope = "role_out_of_scope"
    policy_source_blocked = "policy_source_blocked"
    policy_source_sensitive = "policy_source_sensitive"

    # Feature 9 — subjective guardrail & workflow baseline (+ detector seam).
    unusual_for_workflow = "unusual_for_workflow"

    # Universal subjective layer (SL7) — three-axis scoring + trifecta floor.
    unusual_for_deployment = "unusual_for_deployment"
    confidentiality_sensitive_destination = "confidentiality_sensitive_destination"
    irreversible_high_blast = "irreversible_high_blast"
    lethal_trifecta = "lethal_trifecta"
    unclassified_action = "unclassified_action"

    # OOD / smuggled-token channel defense (objective rule + subjective detector).
    smuggled_token_channel = "smuggled_token_channel"  # noqa: S105 — reason code, not a secret
    anomalous_token_pattern = "anomalous_token_pattern"  # noqa: S105 — reason code, not a secret


class GuardrailResult(BaseModel):
    """A single guardrail's answer for one action (immutable).

    Explainability contract: every non-PASS verdict must carry at least one
    stable :class:`ReasonCode` and a human-readable explanation.

    SECURITY: ``explanation`` is shown to the agent on AUTH/BLOCK. Guardrail
    authors MUST NOT embed raw argument values, file contents, secret
    material, or match excerpts in it — describe the rule, not the payload
    (e.g. "path is under a protected directory", never the path's contents).
    """

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    risk: Risk
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    explanation: str = ""

    @model_validator(mode="after")
    def _non_pass_must_be_explained(self) -> "GuardrailResult":
        if self.verdict is not Verdict.PASS:
            if not self.reason_codes:
                raise ValueError(f"a {self.verdict} verdict requires at least one reason code")
            if not self.explanation.strip():
                raise ValueError(f"a {self.verdict} verdict requires a human explanation")
        return self


class EvalContext(BaseModel):
    """Context handed to every guardrail evaluation (immutable).

    Carries the active agent role (F4) so the objective layer can escalate
    actions that cross the role's boundaries; later features add the security
    mode (F6) and the baseline handle (F9). ``role`` is ``None`` when no role
    is configured — role enforcement is opt-in and the role rule then abstains.

    NOTE: ``frozen=True`` is shallow — the ``metadata`` dict itself is
    mutable. Guardrails are pure functions by contract and MUST NOT mutate
    it; the engine treats any mutation as a guardrail bug.
    """

    model_config = ConfigDict(frozen=True)

    role: RoleDefinition | None = None
    #: Active security strength mode (F6): "light"/"balanced"/"strict"/"paranoid".
    #: Tunes step-up thresholds only; the hard-block floor is mode-independent.
    mode: str = "balanced"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityObject(BaseModel):
    """The normalized, redacted description of one intercepted action.

    Immutable (`frozen=True`) so no layer can mutate risk downward after
    creation. `raw_args_redacted` must only ever contain redacted values —
    raw secrets, full file contents, or unredacted prompts never enter this
    object.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    ts: AwareDatetime  # forensic timestamp — naive datetimes are rejected
    agent_role: str
    action_type: ActionType
    tool_name: str
    target: str | None = None
    target_path_class: str | None = None
    risk: Risk = Risk.low
    source_context: SourceContext = SourceContext.unknown
    reversibility: Reversibility = Reversibility.medium
    sensitive_asset: bool = False
    external_destination: str | None = None
    #: The universal action-algebra classification (SL1). Populated by the
    #: generic inference layer at normalize time; defaults to the conservative
    #: all-unknown / zero-confidence algebra when nothing has inferred it yet.
    algebra: Algebra = Field(default_factory=Algebra)
    payload_fingerprints: list[str] = Field(default_factory=list)
    # Values must already be redacted before entering the object; redaction is
    # enforced by normalize() and its tests, not by this type.
    raw_args_redacted: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """The engine's final, immutable answer for one action.

    This is the audit record's source of truth: it always carries the
    contributing guardrail results, and any non-PASS outcome must be
    explained (reason codes + human explanation). ``subjective`` is ``None``
    when the execution rule skipped it (objective short-circuit).

    Consistency invariant: ``final_verdict`` can never be WEAKER than the
    objective guardrail's verdict (objective is never overridden downward).
    It MAY be weaker than ``subjective.verdict`` — the execution rule clamps
    a non-allowlisted subjective BLOCK to AUTH by design.

    ``action_id`` must equal the ``SecurityObject.id`` of the action being
    decided (chain of custody for audit).
    """

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(min_length=1)
    final_verdict: Verdict
    final_risk: Risk
    objective: GuardrailResult
    subjective: GuardrailResult | None = None
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    explanation: str = ""
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def _non_pass_must_be_explained(self) -> "Decision":
        if self.final_verdict is not Verdict.PASS:
            if not self.reason_codes:
                raise ValueError(
                    f"a {self.final_verdict} decision requires at least one reason code"
                )
            if not self.explanation.strip():
                raise ValueError(f"a {self.final_verdict} decision requires a human explanation")
        return self

    @model_validator(mode="after")
    def _final_never_weaker_than_objective(self) -> "Decision":
        if VERDICT_ORDER[self.final_verdict] < VERDICT_ORDER[self.objective.verdict]:
            raise ValueError(
                f"final_verdict {self.final_verdict} is weaker than the objective "
                f"verdict {self.objective.verdict} — objective is never overridden downward"
            )
        if RISK_ORDER[self.final_risk] < RISK_ORDER[self.objective.risk]:
            raise ValueError(
                f"final_risk {self.final_risk} is lower than the objective "
                f"risk {self.objective.risk} — risk is never lowered"
            )
        return self


class CostKind(StrEnum):
    """What kind of resource consumption a :class:`CostEvent` meters."""

    tokens_in = "tokens_in"
    tokens_out = "tokens_out"
    tool_call = "tool_call"
    other = "other"


class CostEvent(BaseModel):
    """A redaction-safe record of resource consumption (token burn, tool calls).

    Cost observability is **advisory**, the third boundary's raw material: a
    ``CostEvent`` never rides the decision path and recording one can never
    alter a PASS/AUTH/BLOCK verdict. Like every other object here it is
    redaction-safe by construction — it holds **counts and coarse classes
    only**, never prompt/response text. ``model`` is a coarse label (e.g.
    ``"opus"``), and ``entity_id`` is a keyed HMAC fingerprint, never a raw
    role or path. Immutable (``frozen=True``) so a meter can never adjust a
    recorded cost downward after the fact.
    """

    model_config = ConfigDict(frozen=True)

    action_id: str = Field(min_length=1)
    ts: AwareDatetime  # forensic timestamp — naive datetimes are rejected
    kind: CostKind = CostKind.other
    #: Token count or call count. Non-negative — cost only ever accrues.
    units: int = Field(default=0, ge=0)
    #: Coarse model label only (e.g. "opus"); never request/response payload.
    model: str | None = None
    #: Keyed HMAC fingerprint of the entity, never a raw role/path string.
    entity_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
