"""Policy-source enforcement rule (Feature 4, slice 4.4).

Enforces a :class:`~doberman.policy.sources.ResolvedPolicy` — the merged result
of all registered policy sources (the seam by which an enterprise/org authority
can layer above the agent role). The resolved policy is handed in through
``ctx.metadata['resolved_policy']``; with none present (the default, no extra
sources installed) this rule abstains, so core behavior is unchanged.

Verdicts (raise-only):

* canonical target matches a resolved ``blocked`` glob → ``BLOCK (policy_source_blocked)``
* canonical target matches a resolved ``sensitive`` glob → ``AUTH (policy_source_sensitive)``
* otherwise abstain (``PASS``)

Because the resolved policy is itself raise-only across sources (a higher
authority can only tighten), a registered source can outrank the role here —
but nothing can ever loosen a constraint a higher-authority source set.
"""

import fnmatch

from doberman.canonical import canonicalize
from doberman.engine.rules.paths import RAW_PATH_KEYS_STRICT, raw_path_candidates
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.sources import ResolvedPolicy

_PATH_ACTION_TYPES = frozenset(
    {ActionType.file_read, ActionType.file_write, ActionType.file_delete}
)
_DEFAULT_ROOT = "."


def _candidate_paths(action: SecurityObject) -> list[str]:
    raw_paths = action.metadata.get("raw_paths") if isinstance(action.metadata, dict) else None
    if isinstance(raw_paths, (list, tuple)) and raw_paths:
        return [str(p) for p in raw_paths if isinstance(p, str) and p]
    if action.target:
        return [action.target]
    return []


def _matches_any(relposix: str, globs: tuple[str, ...]) -> bool:
    if not relposix:
        return False
    return any(fnmatch.fnmatch(relposix, pattern) for pattern in globs)


class PolicySourceRule:
    """Enforce a resolved, layered policy from registered policy sources."""

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        policy = ctx.metadata.get("resolved_policy") if isinstance(ctx.metadata, dict) else None
        if not isinstance(policy, ResolvedPolicy) or policy.is_empty:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        if action.action_type in _PATH_ACTION_TYPES:
            paths = _candidate_paths(action)
        else:
            # A tool whose declared type isn't path-shaped can still carry a
            # path-shaped raw argument (an unrecognized tool name, {"path":
            # ...}) — the tool NAME is caller-supplied and not a trust
            # boundary, so classify those candidates too rather than
            # abstaining (mirrors RoleBoundaryRule).
            raw_arguments = (
                ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
            )
            paths = (
                raw_path_candidates(raw_arguments, RAW_PATH_KEYS_STRICT)
                if isinstance(raw_arguments, dict)
                else []
            )
        if not paths:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        root = str(ctx.metadata.get("repo_root") or _DEFAULT_ROOT)

        worst = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        for raw_path in paths:
            result = self._evaluate_one(raw_path, root, policy)
            if _verdict_rank(result) > _verdict_rank(worst):
                worst = result
            if worst.verdict is Verdict.BLOCK:
                break
        return worst

    @staticmethod
    def _evaluate_one(raw_path: str, root: str, policy: ResolvedPolicy) -> GuardrailResult:
        canonical = canonicalize(raw_path, root=root)
        rel = canonical.relposix
        if _matches_any(rel, policy.blocked_globs):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.high,
                reason_codes=[ReasonCode.policy_source_blocked],
                explanation="Target is blocked by a higher-authority policy source.",
            )
        if _matches_any(rel, policy.sensitive_globs):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.policy_source_sensitive],
                explanation=(
                    "Target is sensitive under a higher-authority policy source; "
                    "authentication required."
                ),
            )
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _verdict_rank(result: GuardrailResult) -> int:
    from doberman.models import VERDICT_ORDER

    return VERDICT_ORDER[result.verdict]
