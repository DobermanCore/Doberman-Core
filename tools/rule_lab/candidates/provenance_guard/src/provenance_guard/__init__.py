"""Rule-lab candidate: untrusted-provenance step-up for consequential actions.

Hypothesis
----------
On AgentDojo, the attacks that bypass the built-ins are injection-task actions
whose *provenance* is untrusted tool output (``source_context != user``) and whose
*effect* mutates state or sends data outward — yet they carry no secret and no
unknown-destination signal, so no built-in rule fires. Every legitimate
(user-task) action in the suite is ``source_context == user``. So stepping up
**consequential actions that originate from non-user provenance** to AUTH should
catch those bypasses with no benign friction.

Scope / honesty
---------------
This is intentionally MORE aggressive than core's current design: core treats
untrusted provenance as a signal only *in combination* (the lethal trifecta =
sensitive data + untrusted provenance + external destination), not on its own.
This candidate actions provenance alone. That is a real policy change — which is
why the rule-lab loop routes it to **human review**, never an autonomous merge.

In a real deployment, legitimate agentic workflows DO act on tool output (read a
file, then write based on it), so this rule WOULD add friction there; the clean
zero-FPR result on AgentDojo partly reflects that suite stamping benign actions
as ``user`` provenance. Treat the benchmark win as necessary-not-sufficient.

Raise-only: this rule only ever returns AUTH (a step-up) or abstains (PASS/low).
It can never lower another rule's verdict — the objective guardrail combines
raise-only.
"""

from __future__ import annotations

from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)

#: Provenances that did not originate from the (trusted) user. An action driven
#: by any of these may be carrying an injected instruction.
_UNTRUSTED: frozenset[SourceContext] = frozenset(
    {
        SourceContext.tool_output,
        SourceContext.webpage,
        SourceContext.email,
        SourceContext.github_issue,
        SourceContext.readme,
    }
)

#: Actions with a side effect worth confirming when their provenance is untrusted
#: (state mutation, deletion, egress, code/package execution).
_CONSEQUENTIAL: frozenset[ActionType] = frozenset(
    {
        ActionType.file_write,
        ActionType.file_delete,
        ActionType.network_request,
        ActionType.git_op,
        ActionType.package_install,
        ActionType.memory_write,
        ActionType.shell_exec,
    }
)

#: Abstention — no opinion; the engine keeps whatever other rules decided.
_ABSTAIN = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


class ProvenanceGuardRule:
    """Step up consequential actions whose provenance is not the trusted user."""

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        if action.source_context in _UNTRUSTED and action.action_type in _CONSEQUENTIAL:
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.unusual_for_workflow],
                # Names only the class of signal, never the payload.
                explanation=(
                    "Consequential action originates from untrusted (non-user) provenance; "
                    "confirm before it runs."
                ),
            )
        return _ABSTAIN
