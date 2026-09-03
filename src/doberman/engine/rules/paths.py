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
import re
from collections.abc import Iterable, Sequence

from doberman.canonical import canonicalize
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

#: Doberman's own control plane: its state dir (``.doberman/`` — policy doc,
#: active role, and the DB holding the append-only policy_changes ledger /
#: decision log / baselines / elevations; ADR 0011) and the Claude Code
#: host-hook install config (``.claude/settings*.json`` + the ``.claude`` dir
#: itself; ADR 0022 host-hook architecture / ADR 0024 this block), plus the
#: per-user auth state that backs every possession-factor gate (ADR 0065). Editing or
#: deleting either disables Doberman at the engine or harness level ("fire the
#: cop") and bypasses the Feature 10 apply_change gate; Doberman writes these via
#: direct I/O, never through the proxy, so any agent-proxied write/delete/read is
#: hard-blocked. **Shared with the command rule (HK.5.0b)** via
#: :func:`names_control_plane`, so a shell command that names one of these
#: (``echo > .claude/settings.json``, ``rm -rf .doberman``) is caught too — a
#: path-*target* rule alone misses a path hidden inside a command string.
CONTROL_PLANE_GLOBS: tuple[str, ...] = (
    ".doberman",
    ".doberman/**",
    "**/.doberman",
    "**/.doberman/**",
    ".claude",
    ".claude/settings.json",
    ".claude/settings.local.json",
    "**/.claude",
    "**/.claude/settings.json",
    "**/.claude/settings.local.json",
    # The Codex CLI control plane (W1.3): its hook config (both scopes),
    # ``config.toml`` (it configures hooks, trust, AND the sandbox), the ``.codex``
    # dir itself, and the plugin dirs that can carry plugin-bundled hooks. Editing
    # or deleting any of these lets the agent unhook, un-trust, or reconfigure its
    # own leash — so they are hard-blocked, mirroring the ``.claude`` split. The
    # rest of ``.codex/**`` is SENSITIVE (AUTH), below.
    ".codex",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".codex/plugins",
    ".codex/plugins/**",
    "**/.codex",
    "**/.codex/hooks.json",
    "**/.codex/config.toml",
    "**/.codex/plugins",
    "**/.codex/plugins/**",
    # The per-user auth state (``doberman.auth.totp`` / ``doberman.auth.password``):
    # the TOTP seed, its lockout counter, and the password hash. These live OUTSIDE
    # any repo (``%LOCALAPPDATA%``/``$XDG_CONFIG_HOME``/``~/.config`` + ``doberman/``)
    # precisely so they are never committed — which also puts them past
    # :func:`canonicalize`'s repo-root confinement, so the repo-relative globs above
    # can never reach them. Matched here against the RAW token instead (see
    # :func:`names_control_plane`), which is why these patterns are shaped like the
    # absolute path text rather than a relative one. Deleting the seed silently
    # un-enrols 2FA (every "TOTP if enrolled" gate degrades to confirm-only);
    # deleting the lockout file resets the brute-force counter; overwriting either
    # secret hands an attacker the factor itself. ADR 0065.
    "**/doberman/totp.secret",
    "**/doberman/totp.secret.*",
    "**/doberman/password.hash",
    "**/doberman/password.hash.*",
    # ...and the containing state dir, so a recursive delete of the whole directory
    # is caught too. Deliberately NOT a bare ``**/doberman`` — that would match any
    # checkout of this project (the repo itself is named ``doberman``) and block
    # ordinary work on it.
    "**/appdata/local/doberman",
    "**/appdata/local/doberman/**",
    "**/.config/doberman",
    "**/.config/doberman/**",
)

#: Paths that are NEVER allowed without going through the human-approved path.
#: Overridable (F6 will load these from policy); kept as a module constant so
#: tests and callers can supply their own. Includes the control plane above.
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
    *CONTROL_PLANE_GLOBS,
)

#: Continuous-integration / delivery pipeline definitions across the common
#: hosted and self-managed systems (not just GitHub Actions). A write here can
#: silently reconfigure the pipeline that builds, tests, signs, or deploys the
#: repo — an agent rewriting CI config to, say, exfiltrate a deploy secret or
#: disable a required check is exactly the high-leverage change that warrants a
#: human in the loop. These are SENSITIVE (AUTH), consistent with how GitHub
#: Actions workflows have always been treated; adding a system here only ever
#: adds step-ups (raise-only) and never loosens an existing verdict. Globs are
#: lower-cased to match the canonical (lower-cased) relposix, so ``Jenkinsfile``
#: is written ``jenkinsfile`` and still matches the real capitalized file.
CICD_CONFIG_GLOBS: tuple[str, ...] = (
    # GitHub Actions.
    ".github/workflows/**",
    "**/.github/workflows/**",
    # GitLab CI.
    ".gitlab-ci.yml",
    "**/.gitlab-ci.yml",
    # Jenkins (root or nested ``Jenkinsfile`` and its ``.suffix`` variants).
    "jenkinsfile",
    "**/jenkinsfile",
    "jenkinsfile.*",
    "**/jenkinsfile.*",
    # CircleCI.
    ".circleci/**",
    "**/.circleci/**",
    # Azure Pipelines.
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "**/azure-pipelines.yml",
    "**/azure-pipelines.yaml",
)

#: Repo governance + lint/type-check configuration whose silent edit can hide a
#: bad change from review (CODEOWNERS routing) or from CI (a loosened/disabled
#: lint or type rule). Path-class detection cannot tell a legitimate config
#: tune from a silencing one, so every MUTATION (write or delete) steps up to
#: AUTH (raise-only). Unlike CICD_CONFIG_GLOBS above, this set is deliberately
#: NOT folded into DEFAULT_SENSITIVE_GLOBS — agents read CODEOWNERS and lint
#: config constantly for routine lookups, and gating reads too would be an
#: approval-fatigue source with no security value (only a silent EDIT can hide
#: a bad change; a read reveals nothing an attacker couldn't already see).
#: ProtectedPathRule matches this set separately and only for
#: ProtectedPathRule.MUTATION_ACTION_TYPES — see its evaluate(). Deliberately
#: excludes pyproject.toml itself: it is edited constantly for routine
#: dependency bumps, and flagging the whole file for a [tool.ruff]-section-only
#: concern would need to read file content, which this rule never does — see
#: README's known-limitations.
VERIFICATION_CONFIG_GLOBS: tuple[str, ...] = (
    "codeowners",
    "**/codeowners",
    ".github/codeowners",
    "ruff.toml",
    ".ruff.toml",
    "**/ruff.toml",
    "mypy.ini",
    ".mypy.ini",
    "**/mypy.ini",
    ".eslintrc",
    ".eslintrc.*",
    "eslint.config.*",
    "**/.eslintrc*",
    "**/eslint.config.*",
    "**/.ruff.toml",
    "**/.mypy.ini",
)

#: Paths that are sensitive: allowed, but only after authentication.
#: VERIFICATION_CONFIG_GLOBS is deliberately NOT included here — it is
#: matched separately by ProtectedPathRule, scoped to mutation action types
#: only (see VERIFICATION_CONFIG_GLOBS' docstring above and
#: ProtectedPathRule.MUTATION_ACTION_TYPES). Every glob set in THIS tuple
#: stays action-type-agnostic: a read is just as informative as a write for
#: e.g. backend/auth/** or a CI/CD pipeline definition.
DEFAULT_SENSITIVE_GLOBS: tuple[str, ...] = (
    "backend/auth/**",
    "**/backend/auth/**",
    "infra/**",
    "**/infra/**",
    *CICD_CONFIG_GLOBS,
    "migrations/**",
    "**/migrations/**",
    "**/*.tfstate",
    # The rest of the Claude Code control directory (commands, agents, MCP
    # config, etc.): not a hook-install file, but still harness configuration —
    # changing it warrants authentication. The settings.json files above are
    # hard-blocked (checked first); everything else under .claude/ → AUTH.
    ".claude/**",
    "**/.claude/**",
    # The rest of the Codex control directory: harness configuration -> AUTH.
    # hooks.json / config.toml / the plugin dirs above are hard-blocked (checked
    # first); everything else under .codex/ warrants authentication.
    ".codex/**",
    "**/.codex/**",
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


_CONTROL_PLANE = _sanitize_globs(CONTROL_PLANE_GLOBS)

#: Test files/dirs across the common Python/JS/TS conventions. Deleting or
#: renaming one is a distinct signal from writing to one — the branch below
#: gates on ACTION TYPE, not this glob table, deliberately: adding these as a
#: sensitive glob would AUTH every ordinary test edit (constant traffic, would
#: blow the corpus FPR gate). No file-content reads: this catches a delete/
#: rename of a file that matches by name/path only — it cannot see a
#: pytest.mark.skip marker inserted into a KEPT test (see README).
TEST_FILE_GLOBS: tuple[str, ...] = (
    "test_*.py",
    "**/test_*.py",
    "*_test.py",
    "**/*_test.py",
    "tests/**",
    "**/tests/**",
    "**/*.test.[jt]s",
    "**/*.spec.[jt]s",
    "**/*.test.[jt]sx",
    "**/*.spec.[jt]sx",
    "**/*.test.mjs",
    "**/*.spec.mjs",
)

_TEST_FILE_PATTERNS = _sanitize_globs(TEST_FILE_GLOBS)

#: Heuristic for "this tool call is a rename/move". ActionType has no dedicated
#: rename member (normalize.py has no rename-verb -> ActionType mapping, and
#: subjective/infer.py's own Capability classifier already buckets
#: rename/move under the same "mutate" verb group as an ordinary write), so a
#: rename is recognized here by TOOL NAME instead. Known ceiling (documented in
#: README): a `git mv`/shell `mv` routes through DestructiveCommandRule, not
#: this path-target rule, and is invisible here; a rename tool that doesn't
#: name itself rename/move is also invisible here.
_RENAME_TOOL_HINT = re.compile(r"(?i)rename|move")


def _is_delete_or_rename(action_type: ActionType, tool_name: str) -> bool:
    if action_type is ActionType.file_delete:
        return True
    # The tool-name hint is a MUTATION signal, not an action-type-agnostic
    # one: a file_read whose tool merely happens to be named "rename_file"
    # (e.g. a dry-run/preview call) is not a rename in progress.
    return action_type in ProtectedPathRule.MUTATION_ACTION_TYPES and bool(
        _RENAME_TOOL_HINT.search(tool_name or "")
    )


def names_control_plane(raw_path: str, root: str = _DEFAULT_ROOT) -> bool:
    """True if a raw path token lands on Doberman's control plane.

    Used by the command rule (HK.5.0b) so a shell command that writes/deletes the
    control plane (``echo > .claude/settings.json``, ``rm -rf .doberman``,
    ``sed -i ... .doberman/policies.yaml``) is blocked — a path-*target* rule
    alone misses a path hidden inside a command string. Checks the raw token
    (catches absolute / ``~`` / Windows-separator paths) and the repo-root
    canonical form (catches ``..`` traversal back into the plane).

    Known limits — static shell analysis cannot resolve runtime semantics, so a
    control-plane path produced at runtime is NOT caught here (accepted defense-
    in-depth, tracked for HK.5.6; the OS file owner/mode and the file-target path
    rule are the backstops): a path built from a variable
    (``X=.doberman; rm -rf $X``), shell glob / brace expansion (``rm -rf .dober*``),
    or a scripting-interpreter payload (``python -c "...rmtree('.doberman')..."`` —
    ``python``/``node``/``perl`` are not shells, so the body is not scanned).
    """
    token = (raw_path or "").strip().strip("\"'").replace("\\", "/").lower()
    if not token:
        return False
    if _matches_any(token, _CONTROL_PLANE):
        return True
    canonical = canonicalize(raw_path, root=root)
    if canonical.escapes_root:
        return False
    return _matches_any(canonical.relposix, _CONTROL_PLANE)


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


#: Argument keys likely to carry a raw (un-redacted) path, checked in priority
#: order. Kept local rather than imported from ``doberman.proxy`` — the
#: policy core must not depend on the proxy adapter (import-linter contract).
_RAW_PATH_KEYS: tuple[str, ...] = ("path", "file", "filename", "target")

#: The unambiguous subset for tools whose declared type is NOT path-shaped:
#: ``target`` is a common name for a host/URL/command argument too
#: (``ping {"target": ...}``), so only the keys that always mean a filesystem
#: path are consulted there (role-boundary / policy-source rules).
RAW_PATH_KEYS_STRICT: tuple[str, ...] = ("path", "file", "filename")


def raw_path_candidates(raw_arguments: dict, keys: tuple[str, ...] = _RAW_PATH_KEYS) -> list[str]:
    """Extract path candidate(s) from raw (un-redacted) call arguments.

    SECURITY: ``normalize`` redacts any string argument over 256 chars (or
    secret-shaped) to ``"<redacted>"`` before it becomes ``action.target`` —
    so a >256-char traversal or a padded path that still resolves to a
    protected glob would canonicalize the harmless redaction marker instead
    of the real path. Matching against the raw value here closes that gap;
    the raw value is used ONLY for matching and must never be written back to
    the action, its metadata, or a log.

    Returns the first path-shaped key's value: a single string yields one
    candidate, a non-empty list/tuple of strings yields all of them (the
    batch case, e.g. a multi-file delete).

    Public (promoted from ``_raw_path_candidates``): also reused by the role-
    boundary and policy-source rules so a non-path-typed tool whose raw
    arguments still carry a path-shaped value is classified rather than
    abstained on just because the tool's declared type isn't path-shaped.
    """
    for key in keys:
        value = raw_arguments.get(key)
        if isinstance(value, str) and value:
            return [value]
        if isinstance(value, (list, tuple)) and value:
            candidates = [str(v) for v in value if isinstance(v, str) and v]
            if candidates:
                return candidates
    return []


class ProtectedPathRule:
    """Enforce blocked/sensitive path policy on canonicalized targets."""

    #: Action types treated as a mutation for glob sets that are scoped to
    #: mutations only (currently just ``mutation_sensitive_globs`` /
    #: VERIFICATION_CONFIG_GLOBS — see its docstring). Reads a governance/lint
    #: config file constantly for routine lookups carry no risk on their own;
    #: only a write or delete can silently hide a bad change. Every OTHER
    #: glob set on this rule (``blocked_globs``, ``sensitive_globs``) stays
    #: action-type-agnostic and is not gated by this set.
    MUTATION_ACTION_TYPES: frozenset[ActionType] = frozenset(
        {ActionType.file_write, ActionType.file_delete}
    )

    def __init__(
        self,
        blocked_globs: Iterable[str] = DEFAULT_BLOCKED_GLOBS,
        sensitive_globs: Iterable[str] = DEFAULT_SENSITIVE_GLOBS,
        mutation_sensitive_globs: Iterable[str] = VERIFICATION_CONFIG_GLOBS,
    ) -> None:
        self._blocked = _sanitize_globs(blocked_globs)
        self._sensitive = _sanitize_globs(sensitive_globs)
        self._mutation_sensitive = _sanitize_globs(mutation_sensitive_globs)

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        root = _DEFAULT_ROOT
        raw_arguments = None
        if isinstance(ctx.metadata, dict):
            root = str(ctx.metadata.get("repo_root") or _DEFAULT_ROOT)
            raw_arguments = ctx.metadata.get("raw_arguments")

        # Prefer the RAW (un-redacted) path for matching so a length-redacted
        # action.target ("<redacted>") cannot bypass confinement; fall back to
        # the (possibly redacted) action target when no raw path is available.
        paths = raw_path_candidates(raw_arguments) if isinstance(raw_arguments, dict) else []
        if not paths:
            paths = _candidate_paths(action)
        if not paths:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        is_mutation = action.action_type in self.MUTATION_ACTION_TYPES
        worst = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        for raw_path in paths:
            result = self._evaluate_one(
                raw_path, root, action.action_type, action.tool_name, is_mutation
            )
            if _is_more_severe(result, worst):
                worst = result
            if worst.verdict is Verdict.BLOCK:
                break  # cannot get worse than a hard block
        return worst

    def _evaluate_one(
        self,
        raw_path: str,
        root: str,
        action_type: ActionType,
        tool_name: str,
        is_mutation: bool,
    ) -> GuardrailResult:
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

        # Checked BEFORE the test-file branch below: a path can match both
        # (e.g. ".github/workflows/tests/ci.yml" matches "**/tests/**" too) —
        # a CI/CD-pipeline or other sensitive-path delete keeps its own stable
        # reason code, rather than being relabeled test_file_removal just
        # because "tests" happens to appear in the path.
        if _matches_any(canonical.relposix, self._sensitive):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.sensitive_path_access],
                explanation=(
                    "Target is a sensitive path; authentication required before proceeding."
                ),
            )

        if _is_delete_or_rename(action_type, tool_name) and _matches_any(
            canonical.relposix, _TEST_FILE_PATTERNS
        ):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.test_file_removal],
                explanation=(
                    "Target is a test file being deleted or renamed; "
                    "authentication required before proceeding."
                ),
            )

        if is_mutation and _matches_any(canonical.relposix, self._mutation_sensitive):
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
