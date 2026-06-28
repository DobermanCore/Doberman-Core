"""Protected-path rule (Feature 3, slice 3.3).

Blocks writes/deletes/reads against paths that policy declares off-limits, and
steps up authentication on sensitive (but not forbidden) paths. The whole point
of this rule is that it matches the **canonical** form of the target — resolving
``..`` traversals, symlinks, and case differences via the one shared
:func:`doberman.canonical.canonicalize` helper — so an attacker cannot reach a
protected file by spelling it ``a/../.env`` or ``.ENV`` or through a symlink.

Verdicts:

* canonical path matches a **blocked** glob, or the path **escapes the repo
  root** → ``BLOCK (protected_path_blocked)``.
* canonical path matches a **sensitive** glob → ``AUTH (sensitive_path_access)``.
* otherwise this rule abstains (``PASS``).

For a batch action (a list of paths), the rule evaluates **every** path and
contributes the **worst** verdict — a single forbidden member blocks the batch.

SECURITY: the explanation names only the path *class* (a stable glob label),
never the raw path or its contents. An empty or ``**`` policy pattern is
rejected at construction so a misconfiguration can never make everything match
(blocked) or nothing match (sensitive); see :func:`_sanitize_globs`.
"""

import fnmatch
from collections.abc import Iterable, Sequence

from doberman.canonical import canonicalize
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

#: Paths that are NEVER allowed without going through the human-approved path.
#: Overridable (F6 will load these from policy); kept as a module constant so
#: tests and callers can supply their own.
DEFAULT_BLOCKED_GLOBS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "secrets/**",
    "**/secrets/**",
    "**/id_rsa*",
    "**/id_ed25519*",
    # Doberman's own control plane: the policy doc, the active role, and the DB
    # holding the append-only policy_changes ledger / decision log / baselines /
    # elevations. A proxied agent has no legitimate path here — Doberman writes
    # it via direct I/O, never through the proxy — and reaching it would bypass
    # the Feature 10 apply_change gate (policy rewrite, role expansion, ledger
    # wipe). Block any agent-proxied read/write/delete of it.
    ".doberman",
    ".doberman/**",
    "**/.doberman",
    "**/.doberman/**",
    # Doberman's host-harness control plane: the Claude Code hook config that
    # installs Doberman as PreToolUse/PostToolUse hooks (ADR 0022 = host-hook
    # architecture; ADR 0024 = this block). Editing the settings — or deleting
    # the whole `.claude/` dir — removes the hooks and disables enforcement at
    # the harness level ("fire the cop"): the same on-disk bypass `.doberman/`
    # closes (ADR 0011), extended to the host-hook config. Hard-block the
    # hook-install settings and the directory itself; the rest of `.claude/`
    # (project commands/agents) is AUTH (sensitive, below).
    # NOTE: this matches the path *target* of a file action — a Bash command that
    # writes the file (e.g. `echo > .claude/settings.json`, `sed -i`) or runs
    # `doberman uninstall-hooks` is NOT caught here; command-text scanning of the
    # control plane is tracked as HK.5.0b.
    ".claude",
    ".claude/settings.json",
    ".claude/settings.local.json",
    "**/.claude",
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
)

#: Paths that are sensitive: allowed, but only after authentication.
DEFAULT_SENSITIVE_GLOBS: tuple[str, ...] = (
    "backend/auth/**",
    "**/backend/auth/**",
    "infra/**",
    "**/infra/**",
    ".github/workflows/**",
    "**/.github/workflows/**",
    "migrations/**",
    "**/migrations/**",
    "**/*.tfstate",
    # The rest of the Claude Code control directory (commands, agents, MCP
    # config, etc.): not a hook-install file, but still harness configuration —
    # changing it warrants authentication. The settings.json files above are
    # hard-blocked (checked first); everything else under .claude/ → AUTH.
    ".claude/**",
    "**/.claude/**",
)

#: Used as the repo root when the context does not supply one. ".": the process
#: working directory — confinement still applies, escapes still flag.
_DEFAULT_ROOT = "."


def _sanitize_globs(globs: Iterable[str]) -> tuple[str, ...]:
    """Drop empty / whole-tree (``**``/``*``) patterns that would match anything.

    A blocked ``**`` would block every action; a sensitive ``**`` would AUTH
    every action. Either is almost certainly a policy mistake, and the safe
    response is to ignore the over-broad pattern rather than let it dominate.
    Concrete deny-lists stay intact.
    """
    cleaned = []
    for raw in globs:
        pattern = (raw or "").strip()
        if not pattern or pattern in {"*", "**", "**/*", "/**"}:
            continue
        cleaned.append(pattern.lower())  # canonical relposix is lower-cased
    return tuple(cleaned)


def _matches_any(relposix: str, globs: Sequence[str]) -> bool:
    if not relposix:
        return False
    return any(fnmatch.fnmatch(relposix, pattern) for pattern in globs)


def _candidate_paths(action: SecurityObject) -> list[str]:
    """Collect the path-like targets to evaluate (single target or a batch).

    Batch operations are surfaced by ``normalize`` via ``metadata['raw_paths']``
    when available; otherwise the single ``target`` is used. Non-path actions
    yield nothing (the rule abstains).
    """
    raw_paths = action.metadata.get("raw_paths") if isinstance(action.metadata, dict) else None
    if isinstance(raw_paths, (list, tuple)) and raw_paths:
        return [str(p) for p in raw_paths if isinstance(p, str) and p]
    if action.target:
        return [action.target]
    return []


class ProtectedPathRule:
    """Enforce blocked/sensitive path policy on canonicalized targets."""

    def __init__(
        self,
        blocked_globs: Iterable[str] = DEFAULT_BLOCKED_GLOBS,
        sensitive_globs: Iterable[str] = DEFAULT_SENSITIVE_GLOBS,
    ) -> None:
        self._blocked = _sanitize_globs(blocked_globs)
        self._sensitive = _sanitize_globs(sensitive_globs)

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        root = _DEFAULT_ROOT
        if isinstance(ctx.metadata, dict):
            root = str(ctx.metadata.get("repo_root") or _DEFAULT_ROOT)

        paths = _candidate_paths(action)
        if not paths:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        worst = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        for raw_path in paths:
            result = self._evaluate_one(raw_path, root)
            if _is_more_severe(result, worst):
                worst = result
            if worst.verdict is Verdict.BLOCK:
                break  # cannot get worse than a hard block
        return worst

    def _evaluate_one(self, raw_path: str, root: str) -> GuardrailResult:
        canonical = canonicalize(raw_path, root=root)

        # A path that resolves outside the repo root is out of scope and unsafe
        # to allow — block it (this also catches ".." escapes and odd symlinks).
        if canonical.escapes_root:
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.high,
                reason_codes=[ReasonCode.protected_path_blocked],
                explanation=(
                    "Target path resolves outside the repository boundary; "
                    "blocked (possible traversal or symlink escape)."
                ),
            )

        if _matches_any(canonical.relposix, self._blocked):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.high,
                reason_codes=[ReasonCode.protected_path_blocked],
                explanation="Target is a protected path; blocked by policy.",
            )

        if _matches_any(canonical.relposix, self._sensitive):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.sensitive_path_access],
                explanation=(
                    "Target is a sensitive path; authentication required before proceeding."
                ),
            )

        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _is_more_severe(candidate: GuardrailResult, current: GuardrailResult) -> bool:
    from doberman.models import VERDICT_ORDER

    return VERDICT_ORDER[candidate.verdict] > VERDICT_ORDER[current.verdict]
