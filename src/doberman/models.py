"""Core data models: the `SecurityObject` schema, verdicts, and reason codes.

This module is the central, shared vocabulary of Doberman. Every intercepted
tool call is normalized into a :class:`SecurityObject`; every guardrail answers
with a :class:`GuardrailResult`. Both are immutable so no later layer can
silently mutate risk or a verdict downward — changes happen by producing a
*new* object, never by editing in place (raise-only principle).
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


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


class Verdict(StrEnum):
    """The decision for an action: pass through, authenticate, or block."""

    PASS = "PASS"  # noqa: S105 — verdict constant, not a password
    AUTH = "AUTH"
    BLOCK = "BLOCK"


class ReasonCode(StrEnum):
    """Stable reason-code constants attached to every non-PASS decision.

    Start small; grow per feature. Codes are part of the explainability
    contract: every BLOCK/AUTH carries reason codes plus a human explanation.
    """

    normalization_failed = "normalization_failed"
    unknown_tool = "unknown_tool"
    downstream_error = "downstream_error"


class GuardrailResult(BaseModel):
    """A single guardrail's answer for one action (immutable)."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    risk: Risk
    reason_codes: list[str] = Field(default_factory=list)
    explanation: str = ""


class SecurityObject(BaseModel):
    """The normalized, redacted description of one intercepted action.

    Immutable (`frozen=True`) so no layer can mutate risk downward after
    creation. `raw_args_redacted` must only ever contain redacted values —
    raw secrets, full file contents, or unredacted prompts never enter this
    object.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    ts: datetime
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
    payload_fingerprints: list[str] = Field(default_factory=list)
    raw_args_redacted: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)
