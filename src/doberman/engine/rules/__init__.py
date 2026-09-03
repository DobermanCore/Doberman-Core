"""Built-in objective rules (Feature 3).

Each rule is a pure ``Guardrail`` — ``evaluate(action, ctx) -> GuardrailResult``
— that may only ever return PASS/AUTH/BLOCK. The :class:`~doberman.engine.objective.ObjectiveGuardrail`
runs every rule, isolates failures, and reduces the results raise-only via
``combine()``; no rule lowers another's verdict. Rules MUST NOT mutate the
frozen ``SecurityObject`` and MUST NOT put raw secrets, paths, or argument
values into any explanation — describe the rule, never the payload.

This package contains ONLY the basic, universally-safe rules. Advanced /
proprietary detection lives in the enterprise edition and attaches through the
entry-point registry (slice 3.8) — core never imports it.
"""

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.engine.rules.data_classes import PiiDataClassRule
from doberman.engine.rules.dependency_admission import DependencyAdmissionRule
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.engine.rules.normalization import NormalizationFailureRule
from doberman.engine.rules.paths import ProtectedPathRule
from doberman.engine.rules.policy_source import PolicySourceRule
from doberman.engine.rules.role_boundary import RoleBoundaryRule
from doberman.engine.rules.secrets import SecretLeakageRule
from doberman.engine.rules.token_channels import TokenChannelRule
from doberman.engine.rules.trifecta_floor import TrifectaFloorRule

#: The built-in rule set, in a stable order. ``ObjectiveGuardrail`` instantiates
#: these with their defaults; F6 will later override the policy lists. The role
#: and policy-source rules abstain unless the context supplies a role / resolved
#: policy, so they are inert until F4 wiring (or a registered source) is active.
BUILTIN_RULE_TYPES = (
    NormalizationFailureRule,
    SecretLeakageRule,
    ProtectedPathRule,
    DestructiveCommandRule,
    ExternalDestinationRule,
    DependencyAdmissionRule,
    RoleBoundaryRule,
    PolicySourceRule,
    TokenChannelRule,
    PiiDataClassRule,
    TrifectaFloorRule,
)

__all__ = [
    "BUILTIN_RULE_TYPES",
    "DependencyAdmissionRule",
    "DestructiveCommandRule",
    "ExternalDestinationRule",
    "NormalizationFailureRule",
    "PiiDataClassRule",
    "PolicySourceRule",
    "ProtectedPathRule",
    "RoleBoundaryRule",
    "SecretLeakageRule",
    "TokenChannelRule",
    "TrifectaFloorRule",
]
