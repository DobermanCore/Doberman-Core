"""Minimal custom Guardrail: step up writes to ``SECRETS_TODO.md``.

This is the worked example from issue #91. It intentionally mirrors the style of
``doberman.engine.rules.paths.ProtectedPathRule``:

* match the **canonical** basename (lower-cased, ``..``/symlink resolved);
* prefer the raw (un-redacted) path from ``ctx.metadata["raw_arguments"]`` when
  present, so a length-redacted ``action.target`` cannot bypass the check;
* return only ``PASS`` / ``AUTH`` / ``BLOCK`` shaped results (here: PASS or AUTH);
* never put the raw path, file contents, or any payload into ``explanation``.

Raise-only: this rule only ever abstains (PASS) or steps up (AUTH). The
objective guardrail combines results with ``combine()``, so a plugin cannot
lower another rule's verdict.
"""

from __future__ import annotations

from collections.abc import Mapping

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

#: Basename this tutorial rule cares about (matched against lower-cased
#: ``CanonicalPath.relposix``). Harmless demo marker, not a real secret store.
_MARKER_BASENAME = "secrets_todo.md"

#: Keys that may carry a raw path in un-redacted call arguments — same priority
#: order as the built-in path rule (kept local so this package does not import
#: ``doberman.proxy``).
_RAW_PATH_KEYS: tuple[str, ...] = ("path", "file", "filename", "target")

_DEFAULT_ROOT = "."


def _abstain() -> GuardrailResult:
    """Fresh PASS/low — no shared mutable result object for callers to alias."""
    return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _raw_path_candidates(raw_arguments: Mapping[str, object]) -> list[str]:
    """Extract path candidate(s) from raw call arguments (match only, never log)."""
    for key in _RAW_PATH_KEYS:
        value = raw_arguments.get(key)
        if isinstance(value, str) and value:
            return [value]
        if isinstance(value, (list, tuple)) and value:
            candidates = [str(v) for v in value if isinstance(v, str) and v]
            if candidates:
                return candidates
    return []


def _candidate_paths(action: SecurityObject) -> list[str]:
    """Fallback path candidates from the (possibly redacted) SecurityObject."""
    raw_paths = action.metadata.get("raw_paths") if isinstance(action.metadata, dict) else None
    if isinstance(raw_paths, (list, tuple)) and raw_paths:
        return [str(p) for p in raw_paths if isinstance(p, str) and p]
    if action.target:
        return [action.target]
    return []


def _paths_for(action: SecurityObject, ctx: EvalContext) -> list[str]:
    """Prefer raw_arguments paths, then the normalized action target."""
    raw_arguments = None
    if isinstance(ctx.metadata, dict):
        raw_arguments = ctx.metadata.get("raw_arguments")
    if isinstance(raw_arguments, dict):
        paths = _raw_path_candidates(raw_arguments)
        if paths:
            return paths
    return _candidate_paths(action)


def _repo_root(ctx: EvalContext) -> str:
    if isinstance(ctx.metadata, dict):
        return str(ctx.metadata.get("repo_root") or _DEFAULT_ROOT)
    return _DEFAULT_ROOT


def _basename_matches_marker(raw_path: str, root: str) -> bool:
    """True when the canonical basename is ``SECRETS_TODO.md`` (any case).

    Backslashes are normalized to forward slashes before canonicalization so a
    Windows-style path string still matches on POSIX hosts (agents sometimes
    emit ``notes\\SECRETS_TODO.md`` even when the engine runs on Linux).
    """
    # Mirror the control-plane helper in paths.py: normalize separators first.
    normalized = (raw_path or "").replace("\\", "/")
    canonical = canonicalize(normalized, root=root)
    # Escapes are the built-in path rule's job; this tutorial rule abstains so
    # it never invents a second, weaker confinement story.
    if canonical.escapes_root:
        return False
    # relposix is lower-cased and uses forward slashes.
    basename = canonical.relposix.rsplit("/", 1)[-1]
    return basename == _MARKER_BASENAME


class ExampleRule:
    """Step up authentication when writing a file named ``SECRETS_TODO.md``.

    Implements the :class:`~doberman.engine.decision_engine.Guardrail` protocol
    (one method: ``evaluate``). Registered via::

        [project.entry-points."doberman.rules"]
        example_rule = "example_plugin.rules:ExampleRule"
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        # Scope: only file writes. Reads of the marker file are not stepped up
        # by this tutorial rule (keep the demo obvious and minimal).
        if action.action_type is not ActionType.file_write:
            return _abstain()

        paths = _paths_for(action, ctx)
        if not paths:
            return _abstain()

        root = _repo_root(ctx)
        for raw_path in paths:
            if _basename_matches_marker(raw_path, root):
                return GuardrailResult(
                    verdict=Verdict.AUTH,
                    risk=Risk.medium,
                    reason_codes=[ReasonCode.sensitive_path_access],
                    # Names the *rule*, never the raw path or file contents.
                    explanation=(
                        "Write targets a secrets-todo marker file; "
                        "authentication required before proceeding."
                    ),
                )
        return _abstain()
